package sentinel

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/cosmos/cosmos-sdk/types/module"

	"github.com/arkeonetwork/arkeo/common"
	"github.com/arkeonetwork/arkeo/common/cosmos"
	"github.com/arkeonetwork/arkeo/x/arkeo/types"
)

var ModuleBasics = module.NewBasicManager()

// TODO: this should receive events from arkeo chain to update its database
// TODO: clean up contracts from memory after they expire
type MemStore struct {
	storeLock   *sync.Mutex
	db          map[string]types.Contract
	client      http.Client
	baseURL     string
	blockHeight atomic.Int64
	logger      log.Logger
	authManager *ArkeoAuthManager
}

func NewMemStore(baseURL string, authManager *ArkeoAuthManager, logger log.Logger) *MemStore {
	return &MemStore{
		storeLock: &sync.Mutex{},
		db:        make(map[string]types.Contract),
		client: http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		baseURL:     baseURL,
		authManager: authManager,
		logger:      logger,
	}
}

func (k *MemStore) Key(pubkey, service, spender string) string {
	return fmt.Sprintf("%s/%s/%s", pubkey, service, spender)
}

func (k *MemStore) GetHeight() int64 {
	return k.blockHeight.Load()
}

func (k *MemStore) SetHeight(height int64) {
	if height >= 0 {
		k.blockHeight.Store(height)
	}
}

func (k *MemStore) Get(key string) (types.Contract, error) {
	k.storeLock.Lock()
	defer k.storeLock.Unlock()
	contract, ok := k.db[key]
	// contract is not in cache or contract expired , fetch it
	if !ok || contract.IsExpired(k.GetHeight()) {
		crtUpStream, err := k.fetchContract(key)
		if err != nil {
			return crtUpStream, err
		}
		if !crtUpStream.IsExpired(k.GetHeight()) {
			k.db[key] = crtUpStream
		}
		return crtUpStream, nil
	}
	// contract still valid
	return contract, nil
}

func (k *MemStore) Put(contract types.Contract) {
	k.storeLock.Lock()
	defer k.storeLock.Unlock()
	key := contract.Key()
	if contract.IsExpired(k.GetHeight()) {
		delete(k.db, key)
		return
	}
	if previous, ok := k.db[key]; ok && previous.Nonce > contract.Nonce {
		contract.Nonce = previous.Nonce
	}
	k.db[key] = contract
}

func (k *MemStore) GetActiveContract(provider common.PubKey, service common.Service, spender common.PubKey) (types.Contract, error) {
	k.storeLock.Lock()
	defer k.storeLock.Unlock()
	// iterate through the map to find the contract
	for _, contract := range k.db {
		if !contract.IsExpired(k.GetHeight()) && contract.Provider.Equals(provider) && contract.Service == service && contract.GetSpender().Equals(spender) {
			return contract, nil
		}
	}
	// we should also probably call arkeo if we don't find the contract as we do below.

	return types.Contract{}, fmt.Errorf("contract not found")
}

func (k *MemStore) fetchContract(key string) (types.Contract, error) {
	// TODO: this should cache a "miss" for 5 seconds, to stop DoS/thrashing
	var contract types.Contract

	type fetchContract struct {
		Id                 string          `protobuf:"varint,13,opt,name=id,proto3" json:"id,omitempty"`
		Provider           common.PubKey   `json:"provider"`
		ProviderPubKey     common.PubKey   `protobuf:"bytes,1,opt,name=provider_pub_key,json=providerPubKey,proto3,casttype=github.com/arkeonetwork/arkeo/common.PubKey" json:"provider_pub_key,omitempty"`
		Service            common.Service  `protobuf:"varint,2,opt,name=service,proto3,casttype=github.com/arkeonetwork/arkeo/common.Service" json:"service,omitempty"`
		Client             common.PubKey   `protobuf:"bytes,3,opt,name=client,proto3,casttype=github.com/arkeonetwork/arkeo/common.PubKey" json:"client,omitempty"`
		Delegate           common.PubKey   `protobuf:"bytes,4,opt,name=delegate,proto3,casttype=github.com/arkeonetwork/arkeo/common.PubKey" json:"delegate,omitempty"`
		Type               json.RawMessage `protobuf:"varint,5,opt,name=type,proto3,enum=arkeo.arkeo.ContractType" json:"type,omitempty"`
		Height             string          `protobuf:"varint,6,opt,name=height,proto3" json:"height,omitempty"`
		Duration           string          `protobuf:"varint,7,opt,name=duration,proto3" json:"duration,omitempty"`
		Rate               cosmos.Coin     `protobuf:"varint,8,opt,name=rate,proto3" json:"rate,omitempty"`
		Deposit            string          `protobuf:"varint,9,opt,name=deposit,proto3" json:"deposit,omitempty"`
		Paid               string          `protobuf:"varint,10,opt,name=paid,proto3" json:"paid,omitempty"`
		Nonce              string          `protobuf:"varint,11,opt,name=nonce,proto3" json:"nonce,omitempty"`
		SettlementDuration string          `json:"settlement_duration"`
		SettlementHeight   string          `protobuf:"varint,12,opt,name=settlement_height,json=settlementHeight,proto3" json:"settlement_height,omitempty"`
		Authorization      json.RawMessage `protobuf:"varint,15,opt,name=authorization,proto3,enum=arkeo.arkeo.ContractAuthorization" json:"authorization,omitempty"`
		QueriesPerMinute   string          `protobuf:"varint,16,opt,name=queries_per_minute,json=queriesPerMinute,proto3" json:"queries_per_minute,omitempty"`
	}

	type fetch struct {
		Contract fetchContract `json:"contract"`
	}

	var data fetch
	requestURL := fmt.Sprintf("%s/arkeo/contract/%s", k.baseURL, key)
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return contract, fmt.Errorf("invalid contract endpoint")
	}

	// Add authentication header if auth manager is configured
	if k.authManager != nil {
		authHeader, err := k.authManager.GenerateAuthHeader()
		if err != nil {
			k.logger.Error("fail to generate auth header", "error", err)
			return contract, err
		}
		req.Header.Set(QueryArkAuth, authHeader)
	}

	res, err := k.client.Do(req)
	if err != nil {
		return contract, fmt.Errorf("contract endpoint request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return contract, fmt.Errorf("contract endpoint returned status %d", res.StatusCode)
	}

	const maxContractResponse = 1 << 20
	resBody, err := io.ReadAll(io.LimitReader(res.Body, maxContractResponse+1))
	if err != nil {
		k.logger.Error("DEBUG: fail to read from response body", "error", err)
		return contract, err
	}

	if len(resBody) > maxContractResponse {
		return contract, fmt.Errorf("contract endpoint response exceeds limit")
	}

	err = json.Unmarshal(resBody, &data)
	if err != nil {
		k.logger.Error("DEBUG: fail to unmarshal response", "error", err)
		return contract, err
	}

	c := data.Contract
	id, err := strconv.ParseUint(c.Id, 10, 64)
	if err != nil || id == 0 {
		return contract, fmt.Errorf("invalid contract ID")
	}
	if requested, err := strconv.ParseUint(key, 10, 64); err == nil && requested != id {
		return contract, fmt.Errorf("contract ID mismatch")
	}
	contract.Id = id
	contract.Provider = c.Provider
	if contract.Provider.IsEmpty() {
		contract.Provider = c.ProviderPubKey
	}
	if contract.Provider.IsEmpty() || c.Client.IsEmpty() || c.Service <= 0 {
		return contract, fmt.Errorf("invalid contract identity")
	}
	contract.Service, contract.Client, contract.Delegate = c.Service, c.Client, c.Delegate
	kind, err := parseContractEnum(c.Type, types.ContractType_value)
	if err != nil || (kind != 0 && kind != 1) {
		return contract, fmt.Errorf("invalid contract type")
	}
	contract.Type = types.ContractType(kind)
	auth, err := parseContractEnum(c.Authorization, types.ContractAuthorization_value)
	if err != nil || (auth != 0 && auth != 1) {
		return contract, fmt.Errorf("invalid contract authorization")
	}
	contract.Authorization = types.ContractAuthorization(auth)
	for _, field := range []struct {
		name, raw string
		target    *int64
		optional  bool
	}{
		{"height", c.Height, &contract.Height, false}, {"duration", c.Duration, &contract.Duration, false},
		{"nonce", c.Nonce, &contract.Nonce, true}, {"settlement height", c.SettlementHeight, &contract.SettlementHeight, true},
		{"settlement duration", c.SettlementDuration, &contract.SettlementDuration, true}, {"queries per minute", c.QueriesPerMinute, &contract.QueriesPerMinute, true},
	} {
		if field.raw == "" && field.optional {
			continue
		}
		n, err := strconv.ParseInt(field.raw, 10, 64)
		if err != nil || n < 0 {
			return contract, fmt.Errorf("invalid contract %s", field.name)
		}
		*field.target = n
	}
	if contract.Duration > math.MaxInt64-contract.Height || contract.SettlementDuration > math.MaxInt64-contract.Height-contract.Duration {
		return contract, fmt.Errorf("contract height overflow")
	}
	contract.Rate = c.Rate
	if c.Rate.Amount.IsNil() || !c.Rate.IsValid() {
		return contract, fmt.Errorf("invalid contract rate")
	}
	var valid bool
	contract.Deposit, valid = cosmos.NewIntFromString(c.Deposit)
	if !valid || contract.Deposit.IsNegative() {
		return contract, fmt.Errorf("invalid contract deposit")
	}
	paid := c.Paid
	if paid == "" {
		paid = "0"
	}
	contract.Paid, valid = cosmos.NewIntFromString(paid)
	if !valid || contract.Paid.IsNegative() || contract.Paid.GT(contract.Deposit) {
		return contract, fmt.Errorf("invalid contract paid amount")
	}

	return contract, nil
}

func parseContractEnum(raw json.RawMessage, names map[string]int32) (int32, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var n int32
	if json.Unmarshal(raw, &n) == nil {
		return n, nil
	}
	var name string
	if json.Unmarshal(raw, &name) == nil {
		if n, ok := names[strings.ToUpper(name)]; ok {
			return n, nil
		}
	}
	return 0, fmt.Errorf("invalid contract enum")
}
