package sentinel

import (
 "encoding/json"
 "fmt"
 "math"
 "net/http"
 "net/http/httptest"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 "github.com/cometbft/cometbft/libs/log"
 "github.com/stretchr/testify/require"
 "github.com/arkeonetwork/arkeo/common"
 "github.com/arkeonetwork/arkeo/common/cosmos"
 "github.com/arkeonetwork/arkeo/x/arkeo/types"
)

func paymentTestProxy(t *testing.T) (*Proxy, types.Contract, ArkAuth) {
 t.Helper()
 cfg := newTestConfig()
 client, key := newSigningTestClient(t)
 store, err := NewClaimStore("")
 require.NoError(t, err)
 t.Cleanup(func() { _ = store.Close() })
 p := &Proxy{Config: cfg, MemStore: NewMemStore("", nil, log.NewNopLogger()), ClaimStore: store, logger: log.NewNopLogger()}
 c := types.NewContract(cfg.ProviderPubKey, common.BTCService, client)
 c.Id, c.Height, c.Duration, c.SettlementDuration, c.QueriesPerMinute = 87654, 1, 100, 20, 100000
 c.Type = types.ContractType_PAY_AS_YOU_GO
 c.Rate = cosmos.NewInt64Coin("uarkeo", 2)
 c.Deposit = cosmos.NewInt(100)
 p.MemStore.SetHeight(2)
 p.MemStore.Put(c)
 auth := ArkAuth{ContractId:c.Id, Nonce:1, Spender:client}
 signTestArkAuth(t, key, &auth)
 return p,c,auth
}

func TestPaidTierRejectsDifferentSignerAndOverflow(t *testing.T) {
 p,c,auth := paymentTestProxy(t)
 other,key := newSigningTestClient(t)
 auth.Spender=other
 signTestArkAuth(t,key,&auth)
 code,err:=p.paidTier(auth,"")
 require.Error(t,err); require.Equal(t,http.StatusUnauthorized,code)
 auth.Spender=c.Client; auth.Nonce=math.MaxInt64
 code,err=p.paidTier(auth,"")
 require.Error(t,err); require.Equal(t,http.StatusPaymentRequired,code)
 require.Empty(t,p.ClaimStore.List())
}

func TestConcurrentReplayCanOnlyBeAcceptedOnce(t *testing.T) {
 p,_,auth:=paymentTestProxy(t)
 var accepted atomic.Int32
 var wg sync.WaitGroup
 for i:=0;i<32;i++ { wg.Add(1); go func(){ defer wg.Done(); if code,err:=p.paidTier(auth,""); err==nil && code==http.StatusOK { accepted.Add(1) } }() }
 wg.Wait()
 require.EqualValues(t,1,accepted.Load())
}

func TestDelayedSettlementCannotOverwriteNewClaim(t *testing.T) {
 store,err:=NewClaimStore(t.TempDir());require.NoError(t,err);defer store.Close()
 first:=NewClaim(9,nil,1,"first");require.NoError(t,store.Accept(first))
 require.NoError(t,store.Accept(NewClaim(9,nil,2,"second")))
 marked,err:=store.MarkClaimed(9,1);require.NoError(t,err);require.False(t,marked)
 got,err:=store.Get("9");require.NoError(t,err);require.EqualValues(t,2,got.Nonce);require.False(t,got.Claimed)
 require.Error(t,store.Set(first))
 marked,err=store.MarkClaimed(9,2);require.NoError(t,err);require.True(t,marked)
 require.Error(t,store.Accept(NewClaim(9,nil,2,"replayed")))
}

func TestSharedNonceStoreReservesDistinctDurableValues(t *testing.T) {
 dir:=t.TempDir();store,err:=NewNonceStore(dir);require.NoError(t,err)
 var wg sync.WaitGroup
 values:=make(chan int64,32)
 for i:=0;i<32;i++ { wg.Add(1);go func(){defer wg.Done();n,e:=store.ReserveAfter(42,0);if e!=nil {t.Error(e);return};values<-n}() }
 wg.Wait();close(values)
 seen:=map[int64]bool{};for n:=range values {require.False(t,seen[n]);seen[n]=true};require.Len(t,seen,32)
 require.Error(t,store.Set(42,2));require.NoError(t,store.Close())
 reopened,err:=NewNonceStore(dir);require.NoError(t,err);defer reopened.Close()
 n,err:=reopened.ReserveAfter(42,0);require.NoError(t,err);require.EqualValues(t,33,n)
}

func TestRegistryFetchHasBoundedTimeAndRejectsDuplicateServices(t *testing.T) {
 slow:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){time.Sleep(50*time.Millisecond)}));defer slow.Close()
 require.Empty(t,fetchServiceRegistry(slow.URL,&http.Client{Timeout:time.Millisecond},log.NewNopLogger()))
 duplicate:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){_,_=w.Write([]byte(`{"services":[{"name":"btc-mainnet-fullnode","service_id":10},{"name":"btc-mainnet-fullnode","service_id":11}]}`))}));defer duplicate.Close()
 require.Empty(t,fetchServiceRegistry(duplicate.URL,&http.Client{Timeout:time.Second},log.NewNopLogger()))
}

func TestContractLookupRejectsMalformedAndMismatchedAccounting(t *testing.T) {
 cfg:=newTestConfig()
 valid:=map[string]any{"id":"42","provider":cfg.ProviderPubKey,"client":cfg.ProviderPubKey,"service":10,"type":"PAY_AS_YOU_GO","authorization":"STRICT","height":"1","duration":"100","settlement_duration":"20","rate":map[string]any{"denom":"uarkeo","amount":"2"},"deposit":"100","paid":"0","nonce":"1"}
 for _,tc:=range []struct{field string;value any;valid bool}{{"id","42",true},{"id","43",false},{"nonce","-1",false},{"deposit","bad",false},{"paid","101",false},{"duration",fmt.Sprint(int64(math.MaxInt64)),false},{"type","UNRECOGNIZED",false}} {
  t.Run(tc.field+fmt.Sprint(tc.value),func(t *testing.T){
   data:=map[string]any{};for k,v:=range valid {data[k]=v};data[tc.field]=tc.value
   server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){_=json.NewEncoder(w).Encode(map[string]any{"contract":data})}));defer server.Close()
   store:=NewMemStore(server.URL,nil,log.NewNopLogger());c,err:=store.fetchContract("42")
   if tc.valid {require.NoError(t,err);require.EqualValues(t,20,c.SettlementDuration)} else {require.Error(t,err)}
  })
 }
}

func TestHeightReadWriteIsRaceSafe(t *testing.T) {
 store:=NewMemStore("",nil,log.NewNopLogger());var wg sync.WaitGroup
 for i:=0;i<8;i++ {wg.Add(1);go func(){defer wg.Done();for n:=int64(1);n<1000;n++{store.SetHeight(n);_ =store.GetHeight()}}()};wg.Wait()
}
