package sentinel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/time/rate"

	"github.com/arkeonetwork/arkeo/common"
	"github.com/arkeonetwork/arkeo/common/cosmos"
	"github.com/arkeonetwork/arkeo/x/arkeo/types"
)

const (
	QueryArkAuth  = "arkauth"
	QueryContract = "arkcontract"
	ServiceHeader = "arkservice"
)

// Create a map to hold the rate limiters for each visitor and a mutex.
var (
	visitors = make(map[string]*rate.Limiter)
	mu       sync.Mutex
)

type ContractAuth struct {
	ContractId uint64
	Timestamp  int64
	Signature  []byte
	ChainId    string
}

type ArkAuth struct {
	ContractId uint64
	Spender    common.PubKey
	Nonce      int64
	Signature  []byte
	ChainId    string
}

// String implement fmt.Stringer
func (aa ArkAuth) String() string {
	return GenerateArkAuthString(aa.ContractId, aa.Nonce, aa.Signature, aa.ChainId)
}

func GenerateArkAuthString(contractId uint64, nonce int64, signature []byte, chainId string) string {
	return fmt.Sprintf("%d:%d:%s", contractId, nonce, hex.EncodeToString(signature))
}

func GenerateMessageToSign(contractId uint64, nonce int64, chainId string) string {
	return fmt.Sprintf("%d:%d:", contractId, nonce)
}

func parseContractAuth(raw string) (ContractAuth, error) {
	var auth ContractAuth
	var err error

	parts := strings.SplitN(raw, ":", 3)

	if len(parts) > 0 {
		auth.ContractId, err = strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return auth, err
		}
	}

	if len(parts) > 1 {
		auth.Timestamp, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return auth, err
		}
	}

	if len(parts) > 2 {
		auth.Signature, err = hex.DecodeString(parts[2])
		if err != nil {
			return auth, err
		}
	}
	return auth, nil
}

func parseArkAuth(raw string, configChainId string) (ArkAuth, error) {

	var aa ArkAuth
	var err error

	aa.ChainId = configChainId

	parts := strings.SplitN(raw, ":", 4)

	if len(parts) == 1 {
		// Only contractId provided (for open contracts)

		aa.ContractId, err = strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return aa, err
		}

	} else if len(parts) == 3 {
		// Format: contractId:nonce:signature

		aa.ContractId, err = strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return aa, err
		}

		aa.Nonce, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return aa, err
		}

		aa.Signature, err = hex.DecodeString(parts[2])
		if err != nil {
			return aa, err
		}

	} else if len(parts) == 4 {
		// Format: contractId:pubKey:nonce:signature

		aa.ContractId, err = strconv.ParseUint(parts[0], 10, 64)
		if err != nil {
			return aa, err
		}

		pubKey, err := cosmos.GetPubKeyFromBech32(cosmos.Bech32PubKeyTypeAccPub, parts[1])
		if err != nil {
			return aa, err
		}
		aa.Spender, err = common.NewPubKeyFromCrypto(pubKey)
		if err != nil {
			return aa, err
		}

		aa.Nonce, err = strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return aa, err
		}

		aa.Signature, err = hex.DecodeString(parts[3])
		if err != nil {
			return aa, err
		}

	} else {
		return aa, fmt.Errorf("invalid arkauth format")
	}

	return aa, nil

}

func (aa ArkAuth) Validate(provider common.PubKey) error {
	creator, err := provider.GetMyAddress()
	if err != nil {
		return fmt.Errorf("internal server error: %w", err)
	}
	msg := types.NewMsgClaimContractIncome(creator, aa.ContractId, aa.Nonce, aa.Signature)
	err = msg.ValidateBasic()
	return err
}

func (auth ContractAuth) Validate(lastTimestamp int64, client common.PubKey) error {
	if auth.ContractId == 0 {
		return fmt.Errorf("contract id cannot be zero")
	}
	if auth.Timestamp <= lastTimestamp {
		return fmt.Errorf("timestamp must be larger than %d", lastTimestamp)
	}

	pk, err := cosmos.GetPubKeyFromBech32(cosmos.Bech32PubKeyTypeAccPub, client.String())
	if err != nil {
		return err
	}

	msg := fmt.Sprintf("%d:%d:%s", auth.ContractId, auth.Timestamp, auth.ChainId)

	if !pk.VerifySignature([]byte(msg), auth.Signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

func (auth ContractAuth) String() string {
	sig := hex.EncodeToString(auth.Signature)
	return fmt.Sprintf("Contract Id: %d, Timestamp: %d, Signature: %s", auth.ContractId, auth.Timestamp, sig)
}

func (p Proxy) fetchArkAuth(r *http.Request) (aa ArkAuth, err error) {
	rawHeader := r.Header.Get(QueryArkAuth)
	if len(rawHeader) > 0 {
		aa, err = parseArkAuth(rawHeader, p.Config.SourceChain)
		if err != nil {
			return aa, err
		}
		return aa, nil
	}
	args := r.URL.Query()
	raw, aaOK := args[QueryArkAuth]
	if aaOK {
		aa, err = parseArkAuth(raw[0], p.Config.SourceChain)
		if err != nil {
			return aa, err
		}
	}
	return aa, nil
}

func (p Proxy) auth(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
			w.Header().Set("Access-Control-Max-Age", "3600")
			w.WriteHeader(http.StatusOK)
			return
		}

		aa, err := p.fetchArkAuth(r)
		remoteAddr := p.getRemoteAddr(r)
		if err != nil {
			http.Error(w, "invalid payment authorization", http.StatusBadRequest)
			return
		}

		var contract types.Contract
		if aa.ContractId > 0 {
			contract, err = p.MemStore.Get(strconv.FormatUint(aa.ContractId, 10))
			if err != nil {
				p.logger.Error("failed to fetch contract", "error", err)
			}

			// Do not serve expired subscription contracts
			if contract.Id != 0 && contract.Type == types.ContractType_SUBSCRIPTION && contract.IsExpired(p.MemStore.GetHeight()) {
				http.Error(w, "subscription contract expired", http.StatusPaymentRequired)
				return
			}
		}

		// Always require a non-empty signature for PAY_AS_YOU_GO contracts
		if contract.Type == types.ContractType_PAY_AS_YOU_GO && len(aa.Signature) == 0 {
			p.logger.Error("Missing signature for PAY_AS_YOU_GO contract", "contract_id", contract.Id)
			http.Error(w, "Signature required for pay-as-you-go contracts", http.StatusUnauthorized)
			return
		}

		// fetch conf and check whitelist/IP/rate
		whitelisted := false
		if !contract.Client.IsEmpty() {
			conf, err := p.ContractConfigStore.Get(contract.Id)
			if err != nil {
				p.logger.Error("failed to fetch contract", "error", err)
			} else {
				w = p.enableCORS(w, conf.CORs)

				// Check IP whitelist
				addr := remoteAddr
				for _, ip := range conf.WhitelistIPAddresses {
					if strings.EqualFold(addr, ip) {
						whitelisted = true
						break
					}
				}

				if len(conf.WhitelistIPAddresses) > 0 && !whitelisted {
					p.logger.Info("DEBUG: IP not in contract whitelist, falling through to free tier", "addr", addr)
					http.Error(w, "client address is not authorized for this contract", http.StatusForbidden)
					return
				}

			}
		}

		// treat open contracts + whitelisted IPs as paid
		if err == nil && (aa.Validate(p.Config.ProviderPubKey) == nil || (contract.IsOpenAuthorization() && whitelisted)) {
			w.Header().Set("tier", "paid")

			// Determine service name from header or URL path.
			rawHeaderService := r.Header.Get(ServiceHeader)
			serviceName := rawHeaderService
			if serviceName == "" {
				parts := strings.Split(r.URL.Path, "/")
				if len(parts) > 1 {
					serviceName = parts[1]
				}
			}

			// Log the raw header and derived service name.
			p.logger.Info("DEBUG: service header and path",
				"header_service", rawHeaderService,
				"url_path", r.URL.Path,
				"derived_service_name", serviceName,
			)

			// Try to resolve via dynamic registry; fallback to legacy parse for logging only.
			p.serviceMu.RLock()
			reqServiceID, ok := p.serviceIDs[strings.ToLower(serviceName)]
			p.serviceMu.RUnlock()

			if ok {
				p.logger.Info("DEBUG: service match check",
					"contract_id", contract.Id,
					"contract_service_enum", contract.Service,
					"request_service_id", reqServiceID,
				)

				if int32(reqServiceID) != int32(contract.Service) {
					p.logger.Error("Service match failed",
						"serviceName", serviceName,
						"contract_id", contract.Id,
						"contract_service_enum", contract.Service,
						"request_service_id", reqServiceID,
					)
					http.Error(w, "Service mismatch", http.StatusUnauthorized)
					return
				}
			} else {
				http.Error(w, "unknown service", http.StatusUnauthorized)
				return
			}

			httpCode, tierErr := p.paidTier(aa, remoteAddr)
			if tierErr == nil {
				next.ServeHTTP(w, r)
				return
			}
			p.logger.Error("DEBUG: paidTier failed", "error", tierErr, "http_code", httpCode)
			http.Error(w, tierErr.Error(), httpCode)
			return
		}

		// If the contract is present and type is PAY_AS_YOU_GO, do not fall through to the free tier
		if contract.Id != 0 && contract.Type == types.ContractType_PAY_AS_YOU_GO {
			http.Error(w, "Pay-as-you-go contracts do not fall through to free tier.", http.StatusUnauthorized)
			return
		}

		w.Header().Set("tier", "free")
		httpCode, err := p.freeTier(remoteAddr)
		if err != nil {
			http.Error(w, err.Error(), httpCode)
			return
		}
		next.ServeHTTP(w, r)
	})
}

const (
	forwardHeaderName = `X-Forwarded-For`
	xRealIPName       = `X-Real-Ip`
)

func (p Proxy) getRemoteAddr(r *http.Request) string {
	// Do not accept client-controlled forwarding headers as a rate-limit identity.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (p Proxy) isRateLimited(contractId uint64, key string, limitTokens int, windowSeconds int) bool {
	mu.Lock()
	defer mu.Unlock()

	key = fmt.Sprintf("%d-%s", contractId, key)
	limiter, exists := visitors[key]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(float64(limitTokens)/float64(windowSeconds)), limitTokens)
		visitors[key] = limiter
	}

	allowed := limiter.Allow()
	p.logger.Info("DEBUG: Rate limiting check",
		"key", key,
		"limit_per_sec", limiter.Limit(),
		"burst", limiter.Burst(),
		"allowed", allowed,
	)
	if allowed {
		p.logger.Debug("DEBUG: Rate limit result", "status", "allowed", "key", key)
	} else {
		p.logger.Debug("DEBUG: Rate limit result", "status", "rate limited", "key", key)
	}
	return !allowed
}

func (p Proxy) freeTier(remoteAddr string) (int, error) {
	if ok := p.isRateLimited(0, remoteAddr, p.Config.FreeTierRateLimit, 60); ok {
		return http.StatusTooManyRequests, fmt.Errorf("free client is rate limited (%s)", http.StatusText(429))
	}

	return http.StatusOK, nil
}

func (p Proxy) paidTier(aa ArkAuth, remoteAddr string) (code int, err error) {

	// Fetch contract by ID; error if not found or datastore issue.
	key := strconv.FormatUint(aa.ContractId, 10)
	contract, err := p.MemStore.Get(key)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("internal server error: %w", err)
	}

	if contract.Id != aa.ContractId || !contract.Provider.Equals(p.Config.ProviderPubKey) {
		return http.StatusUnauthorized, fmt.Errorf("contract is not served by this provider")
	}
	expectedSpender := contract.GetSpender()
	if aa.Spender.IsEmpty() { aa.Spender = expectedSpender }
	if !aa.Spender.Equals(expectedSpender) {
		return http.StatusUnauthorized, fmt.Errorf("unauthorized contract spender")
	}

	// Check if the contract has expired (based on current chain height).
	// If expired, require the client to open a new contract before continuing.
	if contract.IsExpired(p.MemStore.GetHeight()) {
		return http.StatusPaymentRequired, fmt.Errorf("open a contract")
	}

	if contract.IsPayAsYouGo() {
		if aa.Nonce <= 0 || aa.Nonce <= contract.Nonce {
			return http.StatusBadRequest, fmt.Errorf("nonce must increase")
		}
		if contract.Deposit.IsNil() || contract.Rate.Amount.IsNil() || contract.Rate.Amount.IsNegative() {
			return http.StatusPaymentRequired, fmt.Errorf("invalid contract balance")
		}
		cost := new(big.Int).Mul(big.NewInt(aa.Nonce), contract.Rate.Amount.BigInt())
		if cost.Cmp(contract.Deposit.BigInt()) > 0 {
			return http.StatusPaymentRequired, fmt.Errorf("contract spent")
		}
	}

	// Enforce per-contract paid tier rate limiting.
	if ok := p.isRateLimited(contract.Id, remoteAddr, int(contract.QueriesPerMinute), 60); ok {
		return http.StatusTooManyRequests, fmt.Errorf("paid client is rate limited (%s)", http.StatusText(429))
	}

	// For open authorization (subscription) contracts, skip PAYG nonce/signature tracking.
	// Open contracts do not require per-request client signatures or nonce/accounting.
	if contract.IsSubscription() && contract.IsOpenAuthorization() {
		p.logger.Debug("paidTier: open authorization contract; skipping claim enqueue",
			"contract_id", contract.Id,
			"nonce", aa.Nonce,
			"service", contract.Service.String(),
			"spender", aa.Spender.String(),
		)
		return http.StatusOK, nil
	}

	// Accept only signature forms accepted by on-chain settlement.
	pk, err := cosmos.GetPubKeyFromBech32(cosmos.Bech32PubKeyTypeAccPub, expectedSpender.String())
	if err != nil || len(aa.Signature) != 64 {
		return http.StatusUnauthorized, fmt.Errorf("invalid client signature")
	}
	valid := false
	for _, chainID := range []string{"", p.Config.ArkeoAuthChainId} {
		pre := []byte(fmt.Sprintf("%d:%d:%s", aa.ContractId, aa.Nonce, chainID))
		digest := sha256.Sum256(pre)
		if pk.VerifySignature(pre, aa.Signature) || pk.VerifySignature(digest[:], aa.Signature) { valid = true; break }
	}
	if !valid { return http.StatusUnauthorized, fmt.Errorf("invalid signature for client") }
	claim := NewClaim(aa.ContractId, expectedSpender, aa.Nonce, hex.EncodeToString(aa.Signature))
	claim.Provider = p.Config.ProviderPubKey
	if err := p.ClaimStore.Accept(claim); err != nil {
		if errors.Is(err, ErrClaimNonce) { return http.StatusBadRequest, err }
		return http.StatusInternalServerError, fmt.Errorf("claim persistence failed")
	}

	p.logger.Info("paidTier: claim stored",
		"contract_id", claim.ContractId,
		"nonce", claim.Nonce,
		"spender", claim.Spender.String(),
		"service", contract.Service.String(),
	)
	contract.Nonce = aa.Nonce
	p.MemStore.Put(contract)

	return http.StatusOK, nil
}

func (p Proxy) enableCORS(w http.ResponseWriter, cors CORs) http.ResponseWriter {
	if len(cors.AllowOrigins) > 0 {
		w.Header().Set("Access-Control-Allow-Origin", strings.Join(cors.AllowOrigins, ", "))
	}
	if len(cors.AllowMethods) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(cors.AllowMethods, ", "))
	}
	if len(cors.AllowHeaders) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(cors.AllowHeaders, ", "))
	}
	return w
}
