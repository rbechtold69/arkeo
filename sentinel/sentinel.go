package sentinel

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"sync"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/koding/websocketproxy"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/arkeonetwork/arkeo/common"
	"github.com/arkeonetwork/arkeo/sentinel/conf"
)

type Proxy struct {
	Metadata            Metadata
	Config              conf.Configuration
	MemStore            *MemStore
	ClaimStore          *ClaimStore
	ContractConfigStore *ContractConfigurationStore
	ProviderConfigStore *ProviderConfigurationStore
	logger              log.Logger
	proxies             map[string]*url.URL
	proxyMu             sync.RWMutex
	serviceIDs          map[string]int32
	authManager         *ArkeoAuthManager
	serviceMu           sync.RWMutex
}

func NewProxy(config conf.Configuration) (*Proxy, error) {
	logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout))

	if len(config.Services) == 0 {
		logger.Error("FATAL: Configuration file appears empty or did not load! No services found in config.Services.")
		return nil, fmt.Errorf("configuration YAML was not loaded: no services configured")
	}

	logger.Error("DEBUG:FUNCTION NewProxy")

	claimStore, err := NewClaimStore(config.ClaimStoreLocation)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create claim store with error: %s", err))
		return nil, fmt.Errorf("failed to create claim store with error: %s", err)
	}
	contractConfigStore, err := NewContractConfigurationStore(config.ContractConfigStoreLocation)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create contract config store with error: %s", err))
		return nil, fmt.Errorf("failed to create contract config store with error: %s", err)
	}
	providerConfigStore, err := NewProviderConfigurationStore(config.ProviderConfigStoreLocation)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create provider config store with error: %s", err))
		return nil, fmt.Errorf("failed to create provider config store with error: %s", err)
	}

	serviceIDs := loadServiceRegistry(config, logger)
	proxies := loadProxies(config, logger, serviceIDs)

	// Initialize auth manager if configured
	var authManager *ArkeoAuthManager
	if config.ArkeoAuthContractId > 0 && config.ArkeoAuthMnemonic != "" {
		nonceStore, err := NewNonceStore(config.ArkeoAuthNonceStore)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to create nonce store: %s", err))
			return nil, fmt.Errorf("failed to create nonce store: %s", err)
		}

		authManager, err = NewArkeoAuthManager(
			config.ArkeoAuthContractId,
			config.ArkeoAuthChainId,
			config.ArkeoAuthMnemonic,
			nonceStore,
			logger,
		)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to create auth manager: %s", err))
			return nil, fmt.Errorf("failed to create auth manager: %s", err)
		}

		logger.Info("arkeo auth configured",
			"contractId", config.ArkeoAuthContractId,
			"chainId", config.ArkeoAuthChainId,
		)
	}

	return &Proxy{
		Metadata:            NewMetadata(config),
		Config:              config,
		MemStore:            NewMemStore(config.HubProviderURI, authManager, logger),
		ClaimStore:          claimStore,
		ContractConfigStore: contractConfigStore,
		proxies:             proxies, // <-- use the local variable here
		proxyMu:             sync.RWMutex{},
		logger:              logger,
		ProviderConfigStore: providerConfigStore,
		serviceIDs:          serviceIDs,
		authManager:         authManager,
		serviceMu:           sync.RWMutex{},
	}, nil
}

func loadProxies(config conf.Configuration, logger log.Logger, serviceIDs map[string]int32) map[string]*url.URL {
	proxies := make(map[string]*url.URL)
	serviceMap := make(map[string]conf.ServiceConfig)
	for _, svc := range config.Services {
		serviceMap[svc.Name] = svc
	}

	for serviceName := range serviceIDs {
		svc, configured := serviceMap[serviceName]
		rawURL := svc.RpcUrl
		if !configured {
			envKey := strings.ToUpper(strings.ReplaceAll(serviceName, "-", "_"))
			rawURL = os.Getenv(envKey)
		}
		if rawURL == "" {
			proxies[serviceName] = nil
			continue
		}
		parsed, err := url.Parse(strings.TrimSpace(rawURL))
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			// URLs and parse errors can contain provider credentials or API keys.
			logger.Error("invalid upstream URL", "service", serviceName)
			proxies[serviceName] = nil
			continue
		}
		if configured && svc.RpcUser != "" && svc.RpcPass != "" {
			parsed.User = url.UserPassword(svc.RpcUser, svc.RpcPass)
		}
		proxies[serviceName] = parsed
		logger.Info("proxy configured", "service", serviceName)
	}
	return proxies
}

// loadServiceRegistry attempts to fetch the on-chain service registry via REST
// (defaulting to the legacy static list on failure).
func loadServiceRegistry(config conf.Configuration, logger log.Logger) map[string]int32 {
	registry := make(map[string]int32)

	// Attempt to pull from REST gateway if available.
	if config.HubProviderURI != "" {
		reqURL := strings.TrimRight(config.HubProviderURI, "/") + "/arkeo/services"
		resp, err := http.Get(reqURL) //nolint:gosec // expected simple GET to local/known endpoint
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			var payload struct {
				Services []struct {
					ServiceId int32  `json:"service_id"`
					Name      string `json:"name"`
				} `json:"services"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&payload); err == nil {
				for _, svc := range payload.Services {
					registry[strings.ToLower(svc.Name)] = svc.ServiceId
				}
			} else {
				logger.Error("DEBUG: failed to decode registry response", "err", err)
			}
		} else if err != nil {
			logger.Error("DEBUG: failed to fetch registry", "err", err)
		} else {
			logger.Error("DEBUG: registry fetch non-200", "status", resp.StatusCode)
		}
	}

	// Fallback to static map if empty.
	if len(registry) == 0 {
		for name, id := range common.ServiceLookup {
			registry[name] = id
		}
	}

	return registry
}

// refreshServiceRegistry updates the in-memory registry periodically.
func (p *Proxy) refreshServiceRegistry(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reg := loadServiceRegistry(p.Config, p.logger)
			if len(reg) == 0 {
				continue
			}
			p.serviceMu.Lock()
			p.serviceIDs = reg
			p.serviceMu.Unlock()

			// rebuild proxies to include any new services (using existing config/env)
			newProxies := loadProxies(p.Config, p.logger, reg)
			p.proxyMu.Lock()
			p.proxies = newProxies
			p.proxyMu.Unlock()

			p.logger.Info("DEBUG: refreshed service registry", "count", len(reg))
		}
	}
}

// Given a request, send it to the appropriate url
func (p *Proxy) handleRequestAndRedirect(w http.ResponseWriter, r *http.Request) {
	// Limit the Size of incoming requests

	p.logger.Info("DEBUG:TRACE: handleRequestAndRedirect called",
		"path", r.URL.Path,
		"method", r.Method,
	)

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // TODO: Check

	// remove arkauth query arg
	values := r.URL.Query()
	values.Del(QueryArkAuth)
	r.URL.RawQuery = values.Encode()

	parts := strings.Split(r.URL.Path, "/")

	serviceName := r.Header.Get(ServiceHeader)
	pulledFromPath := false
	if len(serviceName) == 0 && len(parts) > 1 {
		pulledFromPath = true
		serviceName = parts[1]
	}

	p.proxyMu.RLock()
	uri, exists := p.proxies[serviceName]
	p.proxyMu.RUnlock()
	if !exists || uri == nil {
		p.logger.Error("DEBUG:TRACE: Service proxy not found or nil", "serviceName", serviceName)
		respondWithError(w, "could not find service", http.StatusBadRequest)
		return
	}

	p.logger.Info("DEBUG: Service selected",
		"serviceName", serviceName,
	)

	r.URL.Scheme = uri.Scheme
	r.URL.Host = uri.Host
	r.URL.User = uri.User
	if pulledFromPath {
		parts[1] = uri.Path // replace the service name with uri path (if exists)
		r.URL.Path = path.Join(parts...)
	}

	// Sanitize URL
	// ensure a path always has a "/" prefix
	if len(r.URL.Path) > 1 && !strings.HasPrefix(r.URL.Path, "/") {
		r.URL.Path = fmt.Sprintf("/%s", r.URL.Path)
	}

	// check for the WebSocket upgrade header
	if websocket.IsWebSocketUpgrade(r) {
		p.logger.Info("WebSocket upgrade", "service", serviceName)
		wsProxyURL := *r.URL
		wsProxyURL.Scheme = "ws"
		if uri.Scheme == "https" {
			wsProxyURL.Scheme = "wss"
		}
		wsProxy := websocketproxy.NewProxy(&wsProxyURL)
		wsProxy.ServeHTTP(w, r)
		return
	}

	// Serve a reverse proxy for a given url
	// create the reverse proxy
	proxy := common.NewSingleHostReverseProxy(r.URL)
	proxy.ModifyResponse = func(resp *http.Response) error {
		p.logger.Info("upstream response", "status", resp.StatusCode, "service", serviceName)
		return nil
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		p.logger.Error("upstream request failed", "service", serviceName)
		http.Error(rw, "upstream request failed", http.StatusBadGateway)
	}
	p.logger.Info("proxy request", "service", serviceName, "method", r.Method)
	proxy.ServeHTTP(w, r)
	p.logger.Info("proxy request completed", "service", serviceName)
}

func (p *Proxy) handleMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Only include these fields at the top level of "config"
	// Also, include "version" at the top level.
	type serviceInfo struct {
		Name string `json:"name"`
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	type configInfo struct {
		Moniker           string        `json:"moniker"`
		Website           string        `json:"website"`
		Description       string        `json:"description"`
		Location          string        `json:"location"`
		Port              string        `json:"port"`
		SourceChain       string        `json:"source_chain"`
		HubProviderURI    string        `json:"hub_provider_uri"`
		EventStreamHost   string        `json:"event_stream_host"`
		ProviderPubKey    string        `json:"provider_pubkey"`
		FreeTierRateLimit int           `json:"free_tier_rate_limit"`
		Services          []serviceInfo `json:"services"`
	}
	type metadataResponse struct {
		Version string     `json:"version"`
		Config  configInfo `json:"config"`
	}

	cfg := p.Metadata.Configuration // use the canonical config as source

	// Build the services array from config.Services
	services := make([]serviceInfo, 0, len(cfg.Services))
	for _, svc := range cfg.Services {
		services = append(services, serviceInfo{
			Name: svc.Name,
			ID:   strconv.Itoa(svc.Id),
			Type: svc.Type,
		})
	}

	config := configInfo{
		Moniker:           cfg.Moniker,
		Website:           cfg.Website,
		Description:       cfg.Description,
		Location:          cfg.Location,
		Port:              cfg.Port,
		SourceChain:       cfg.SourceChain,
		HubProviderURI:    cfg.HubProviderURI,
		EventStreamHost:   cfg.EventStreamHost,
		ProviderPubKey:    cfg.ProviderPubKey.String(),
		FreeTierRateLimit: cfg.FreeTierRateLimit,
		Services:          services,
	}

	resp := metadataResponse{
		Version: p.Metadata.Version,
		Config:  config,
	}

	d, _ := json.Marshal(resp)
	_, _ = w.Write(d)
}

func (p *Proxy) handleContract(w http.ResponseWriter, r *http.Request) {

	r.Header.Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id, ok := vars["id"]
	if !ok {
		respondWithError(w, "missing id in uri", http.StatusBadRequest)
		return
	}

	contractId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		p.logger.Error("fail to parse contract id", "error", err, "id", id)
		respondWithError(w, fmt.Sprintf("bad contract id: %s", err), http.StatusBadRequest)
		return
	}

	contractConf, err := p.ContractConfigStore.Get(contractId)
	if err != nil {
		p.logger.Error("fail to fetch contract", "error", err, "id", contractId)
		respondWithError(w, fmt.Sprintf("bad contract id: %s", err), http.StatusBadRequest)
		return
	}

	// check authorization
	var auth ContractAuth
	raw := r.Header.Get(QueryContract)

	if len(raw) == 0 {
		args := r.URL.Query()
		vals, ok := args[QueryContract]
		if ok && len(vals) > 0 {
			raw = vals[0]
		}
	}

	if len(raw) > 0 {

		auth, err = parseContractAuth(raw)
		if err != nil {
			p.logger.Error("fail to parse contract auth", "error", err)
			respondWithError(w, fmt.Sprintf("bad contract auth: %s", err), http.StatusBadRequest)
			return
		}

		contract, err := p.MemStore.Get(contractConf.Key())
		if err != nil {
			p.logger.Error("fail to fetch contract", "error", err, "id", contractConf.Key())
			respondWithError(w, fmt.Sprintf("missing contract: %s", err), http.StatusNotFound)
			return
		}

		p.logger.Info("DEBUG:fetched contract", "contract", contract)

		if err := auth.Validate(contractConf.LastTimeStamp, contract.Client); err != nil {
			p.logger.Error("fail to validate contract auth", "error", err)
			respondWithError(w, fmt.Sprintf("bad contract auth: %s", err), http.StatusBadRequest)
			return
		}
		contractConf.LastTimeStamp = auth.Timestamp
		if err := p.ContractConfigStore.Set(contractConf); err != nil {
			p.logger.Error("fail to save contract config", "error", err)
			respondWithError(w, fmt.Sprintf("fail to save contract config: %s", err), http.StatusBadRequest)
			return
		}
	} else {
		p.logger.Error("missing contract auth")
		respondWithError(w, fmt.Sprintf("missing contract auth: %s", err), http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		d, _ := json.Marshal(contractConf)
		_, _ = w.Write(d)
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
			return
		}

		type PostContractConfig struct {
			PerUserRateLimit     int      `json:"per_user_rate_limit"`
			CORs                 CORs     `json:"cors"`
			WhitelistIPAddresses []string `json:"white_listed_ip_addresses"`
		}
		var changes PostContractConfig
		if err := json.Unmarshal(body, &changes); err != nil {
			http.Error(w, "Error unmarshaling JSON data", http.StatusBadRequest)
			return
		}

		contractConf.PerUserRateLimit = changes.PerUserRateLimit
		contractConf.CORs = changes.CORs
		contractConf.WhitelistIPAddresses = changes.WhitelistIPAddresses
		err = p.ContractConfigStore.Set(contractConf)
		if err != nil {
			p.logger.Error("fail to save contract config", "error", err, "id", contractConf.ContractId)
			respondWithError(w, fmt.Sprintf("failed to save contract config: %s", err), http.StatusInternalServerError)
			return
		}
	default:
		p.logger.Error("unsupported request method", "method", r.Method)
		respondWithError(w, fmt.Sprintf("unsupported request method: %s", r.Method), http.StatusBadRequest)
	}
}

func (p *Proxy) handleOpenClaims(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "application/json")

	openClaims := make([]Claim, 0)
	for _, claim := range p.ClaimStore.List() {

		p.logger.Debug("claim:", "key", claim.Key(), "nonce", claim.Nonce)

		if claim.Claimed {
			p.logger.Info("open-claims: skip claimed entry",
				"contract_id", claim.ContractId,
				"nonce", claim.Nonce,
				"spender", claim.Spender.String(),
			)
			continue
		}

		contract, err := p.MemStore.Get(claim.Key())

		if err != nil {
			p.logger.Error("open-claims: failed to fetch contract for claim",
				"contract_id", claim.ContractId,
				"nonce", claim.Nonce,
				"error", err,
			)
			continue
		}

		if contract.IsExpired(p.MemStore.GetHeight()) {
			_ = p.ClaimStore.Remove(claim.Key()) // clearly expired
			p.logger.Info("open-claims: claim expired and removed",
				"contract_id", claim.ContractId,
				"nonce", claim.Nonce,
			)
			continue
		}

		p.logger.Debug("open-claims: claim still open",
			"contract_id", claim.ContractId,
			"nonce", claim.Nonce,
			"spender", claim.Spender.String(),
		)

		openClaims = append(openClaims, claim)
	}

	d, _ := json.Marshal(openClaims)
	_, _ = w.Write(d)
}

func (p *Proxy) handleMarkClaimed(w http.ResponseWriter, r *http.Request) {
	// This mutates payout bookkeeping and is not a public data endpoint.
	// A loopback check alone is unsafe when a reverse proxy runs on this host.
	expected := os.Getenv("SENTINEL_ADMIN_TOKEN")
	provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(expected) < 32 || subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) != 1 {
		respondWithError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	w.Header().Set("Content-Type", "application/json")

	type markReq struct {
		ContractID uint64 `json:"contract_id"`
		Nonce      uint64 `json:"nonce"`
	}
	var req markReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, "bad request", http.StatusBadRequest)
		return
	}

	updated := 0
	claims := p.ClaimStore.List()
	for i := range claims {
		c := claims[i]
		if c.ContractId == req.ContractID && uint64(c.Nonce) == req.Nonce {
			// flip the bit; do NOT remove — we want highestNonce to remain monotonic
			if !c.Claimed {
				c.Claimed = true
				if err := p.ClaimStore.Set(c); err != nil { // <-- Set instead of Put
					respondWithError(w, "persist failed", http.StatusInternalServerError)
					return
				}
			}
			updated = 1
			break
		}
	}

	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "updated": updated})
}

func (p *Proxy) handleActiveContract(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	service, ok := vars["service"]
	if !ok {
		respondWithError(w, "missing service in uri", http.StatusBadRequest)
		return
	}
	pubkey, ok := vars["spender"]
	if !ok {
		respondWithError(w, "missing spender pubkey in uri", http.StatusBadRequest)
		return
	}

	providerPK := p.Config.ProviderPubKey

	r.URL.Path = fmt.Sprintf("/arkeo/active-contract/%s/%s/%s",
		providerPK.String(),
		service,
		pubkey,
	)

	// Create reverse proxy with custom director to add auth
	target := p.proxies["arkeo-mainnet-fullnode"]
	proxy := p.createAuthenticatedReverseProxy(target)
	proxy.ServeHTTP(w, r)
}

func (p *Proxy) handleClaim(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	id, ok := vars["id"]
	if !ok {
		respondWithError(w, "missing id in uri", http.StatusBadRequest)
		return
	}
	contractId, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		p.logger.Error("fail to parse contractId", "error", err, "contractId", id)
		respondWithError(w, fmt.Sprintf("bad contractId: %s", err), http.StatusBadRequest)
		return
	}

	claimKey := NewClaim(contractId, nil, 0, "").Key()
	claim, err := p.ClaimStore.Get(claimKey)
	if err != nil {
		p.logger.Error("fail to get claim from memstore", "error", err, "key", claimKey)
		respondWithError(w, fmt.Sprintf("fetch contract error: %s", err), http.StatusBadRequest)
		return
	}
	p.logger.Info(fmt.Sprintf("claim data %v", claim))

	d, _ := json.Marshal(claim)
	_, _ = w.Write(d)
}

func (p *Proxy) Run() {
	p.logger.Info("Starting Sentinel (reverse proxy)....")
	p.Config.Print()

	go p.EventListener(p.Config.EventStreamHost, p.authManager)

	router := p.getRouter()

	// Configure Logrus
	logrus.SetFormatter(&logrus.TextFormatter{})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)

	// Periodically refresh registry in background.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var g errgroup.Group
	g.Go(func() error {
		p.refreshServiceRegistry(ctx)
		return nil
	})

	// Add the Logrus middleware to the router
	loggingRouter := p.logrusMiddleware(router)

	// Check if TLS certificates are configured
	if p.Config.TLS.HasTLS() {
		// Start a goroutine that listens to on port 80 and redirects HTTP to HTTPS
		go func() {
			redirectServer := &http.Server{
				Addr: fmt.Sprintf(":%s", p.Config.Port),
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, "https://"+r.Host+r.URL.String(), http.StatusMovedPermanently)
				}),
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 5 * time.Second,
				IdleTimeout:  5 * time.Second,
			}
			if err := redirectServer.ListenAndServe(); err != nil {
				panic(err)
			}
		}()

		// Start HTTPS server on port 443
		server := &http.Server{
			Addr:              ":443",
			Handler:           loggingRouter,
			ReadTimeout:       5 * time.Second, // TODO: updated it to use config
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       120 * time.Second,
			TLSConfig: &tls.Config{
				// Policies
				MinVersion: tls.VersionTLS13,
				CipherSuites: []uint16{
					tls.TLS_AES_128_GCM_SHA256,
					tls.TLS_AES_256_GCM_SHA384,
					tls.TLS_CHACHA20_POLY1305_SHA256,
				},
			},
			MaxHeaderBytes: 1 << 20,
		}
		if err := server.ListenAndServeTLS(p.Config.TLS.Cert, p.Config.TLS.Key); err != nil {
			panic(err)
		}
	} else {
		// Start an HTTP server on the configured port
		server := &http.Server{
			Addr:              fmt.Sprintf(":%s", p.Config.Port),
			Handler:           loggingRouter,
			ReadTimeout:       5 * time.Second, // TODO: updated it to use config
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 20,
		}
		if err := server.ListenAndServe(); err != nil {
			cancel()
			panic(err)
		}
	}

	// wait for background goroutines (refresh) to exit
	_ = g.Wait()
}

func (p *Proxy) getRouter() *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc(RoutesMetaData, p.handleMetadata).Methods(http.MethodGet)
	router.HandleFunc(RoutesActiveContract, p.handleActiveContract).Methods(http.MethodGet)
	router.HandleFunc(RoutesClaim, p.handleClaim).Methods(http.MethodGet)
	router.HandleFunc(RoutesClaims, p.handleClaims).Methods(http.MethodGet)
	router.HandleFunc(RoutesOpenClaims, p.handleOpenClaims).Methods(http.MethodGet)

	router.HandleFunc("/mark-claimed", p.handleMarkClaimed).Methods(http.MethodPost)
	router.HandleFunc("/mark-claimed/", p.handleMarkClaimed).Methods(http.MethodPost)
	router.HandleFunc("/{service}/mark-claimed", p.handleMarkClaimed).Methods(http.MethodPost)
	router.HandleFunc("/{service}/mark-claimed/", p.handleMarkClaimed).Methods(http.MethodPost)

	router.HandleFunc(RouteManage, p.handleContract).Methods(http.MethodGet, http.MethodPost)
	router.HandleFunc(RouteProviderData, p.handleProviderData).Methods(http.MethodGet)
	router.PathPrefix("/").Handler(
		p.auth(
			handlers.ProxyHeaders(
				http.HandlerFunc(p.handleRequestAndRedirect),
			),
		),
	)
	return router
}

func (p *Proxy) logrusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		logger := logrus.WithFields(logrus.Fields{
			"method": r.Method,
			"path":   r.URL.Path, // Query parameters can contain payment authorizations.
			"remote": p.getRemoteAddr(r),
		})
		next.ServeHTTP(w, r)
		logger.Infof("Request handled in %v", time.Since(start))
	})
}

func respondWithError(w http.ResponseWriter, message string, code int) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		response = []byte(`{"error": "failed to marshal response payload"}`)
		code = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(response)
}

func (p *Proxy) handleProviderData(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	serviceString, ok := vars["service"]
	if !ok {
		respondWithError(w, "missing service in uri", http.StatusBadRequest)
		return
	}
	service := common.Service(common.ServiceLookup[serviceString])

	providerConfigData, err := p.ProviderConfigStore.Get(p.Config.ProviderPubKey, service.String())
	if err != nil {
		p.logger.Error("failed to get provider details", "error", err, "provider", p.Config.ProviderPubKey)
		respondWithError(w, fmt.Sprintf("Invalid Provider: %s", err), http.StatusBadRequest)
		return
	}

	d, _ := json.Marshal(providerConfigData)
	_, _ = w.Write(d)
}

func (p *Proxy) handleClaims(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	contractID := r.URL.Query().Get("contract_id")
	client := r.URL.Query().Get("client") // optional

	var claims []Claim
	var highestNonce uint64 = 0

	for _, claim := range p.ClaimStore.List() {
		// Filter by contract_id if provided
		if contractID != "" && strconv.FormatUint(claim.ContractId, 10) != contractID {
			continue
		}
		// Filter by client (spender) if provided
		if client != "" && claim.Spender != nil && claim.Spender.String() != client {
			continue
		}
		claims = append(claims, claim)
		if uint64(claim.Nonce) > highestNonce {
			highestNonce = uint64(claim.Nonce)
		}
	}

	response := map[string]interface{}{
		"claims":       claims,
		"highestNonce": highestNonce,
	}
	_ = json.NewEncoder(w).Encode(response)
}

// createAuthenticatedReverseProxy creates a reverse proxy that adds auth headers
func (p Proxy) createAuthenticatedReverseProxy(target *url.URL) *httputil.ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		// Preserve the original request path, don't use target.Path
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
		passwd, ok := req.URL.User.Password()
		if ok {
			req.SetBasicAuth(req.URL.User.Username(), passwd)
		}

		// Add auth header if configured
		if p.authManager != nil {
			authHeader, err := p.authManager.GenerateAuthHeader()
			if err != nil {
				p.logger.Error("failed to generate auth header for reverse proxy", "error", err)
			} else {
				req.Header.Set(QueryArkAuth, authHeader)
			}
		}
	}
	return &httputil.ReverseProxy{Director: director}
}
