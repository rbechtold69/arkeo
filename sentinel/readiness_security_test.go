package sentinel

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cometbft/cometbft/libs/log"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"

	"github.com/arkeonetwork/arkeo/common"
	"github.com/arkeonetwork/arkeo/sentinel/conf"
)

func TestMarkClaimedRequiresConfiguredAdminToken(t *testing.T) {
	for _, token := range []string{"", "short", "01234567890123456789012345678901"} {
		t.Setenv("SENTINEL_ADMIN_TOKEN", token)
		p := &Proxy{}
		r := httptest.NewRequest(http.MethodPost, "/mark-claimed", bytes.NewBufferString(`{"contract_id":1,"nonce":1}`))
		r.Header.Set("Authorization", "Bearer wrong")
		w := httptest.NewRecorder()
		p.handleMarkClaimed(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 before accessing claim store, got %d", w.Code)
		}
	}
}

func TestContractFetchRejectsRedirectsAndHTTPFailures(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			redirected := false
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirected = true
			}))
			defer target.Close()
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.URL)
				w.WriteHeader(status)
			}))
			defer upstream.Close()
			store := NewMemStore(upstream.URL, nil, log.NewNopLogger())
			if _, err := store.fetchContract("1"); err == nil {
				t.Fatal("expected endpoint failure")
			}
			if redirected {
				t.Fatal("contract authentication must not follow redirects")
			}
		})
	}
}

func TestContractFetchUsesConfiguredTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{"contract":{}}`))
	}))
	defer upstream.Close()
	store := NewMemStore(upstream.URL, nil, log.NewNopLogger())
	store.client.Timeout = time.Millisecond
	if _, err := store.fetchContract("1"); err == nil {
		t.Fatal("expected configured timeout")
	}
}

func TestProviderCredentialsDoNotAppearInProxyLogs(t *testing.T) {
	var output bytes.Buffer
	config := conf.Configuration{Services: []conf.ServiceConfig{{
		Name: "test-service", RpcUrl: "https://example.com/private-key?token=query-secret",
		RpcUser: "private-user", RpcPass: "private:p@ss",
	}}}
	proxies := loadProxies(config, log.NewTMLogger(&output), map[string]int32{"test-service": 1})
	upstream := proxies["test-service"]
	if upstream == nil {
		t.Fatal("expected configured proxy")
	}
	password, _ := upstream.User.Password()
	if upstream.User.Username() != "private-user" || password != "private:p@ss" {
		t.Fatal("upstream credentials were not preserved")
	}
	for _, secret := range []string{"private-key", "query-secret", "private-user", "private:p@ss"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("logs disclosed %q", secret)
		}
	}
	config.Services[0].RpcUrl = "https://example.com/%invalid-private-key"
	if loadProxies(config, log.NewTMLogger(&output), map[string]int32{"test-service": 1})["test-service"] != nil {
		t.Fatal("malformed URL must be disabled")
	}
	if strings.Contains(output.String(), "private-key") {
		t.Fatal("parse-error log disclosed URL credentials")
	}
}

func TestGeneratedArkAuthRoundTripsParser(t *testing.T) {
	signature := []byte{1, 2, 3}
	auth, err := parseArkAuth(GenerateArkAuthString(42, 7, signature, "test-chain"), "test-chain")
	if err != nil || auth.ContractId != 42 || auth.Nonce != 7 || !bytes.Equal(auth.Signature, signature) {
		t.Fatalf("generated auth cannot be parsed: %v %#v", err, auth)
	}
}

func TestForwardedHeadersCannotSpoofRateLimitIdentity(t *testing.T) {
	p := Proxy{}
	r := httptest.NewRequest(http.MethodGet, "/status", nil)
	r.RemoteAddr = "[2001:db8::1]:1234"
	r.Header.Set("X-Real-Ip", "127.0.0.1")
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	if got := p.getRemoteAddr(r); got != "2001:db8::1" {
		t.Fatalf("unexpected identity: %s", got)
	}
}

func newSigningTestClient(t *testing.T) (common.PubKey, cryptotypes.PrivKey) {
	t.Helper()
	key := secp256k1.GenPrivKey()
	pub, err := common.NewPubKeyFromCrypto(key.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	return pub, key
}

func signTestArkAuth(t *testing.T, key cryptotypes.PrivKey, auth *ArkAuth) {
	t.Helper()
	signature, err := key.Sign([]byte(fmt.Sprintf("%d:%d:", auth.ContractId, auth.Nonce)))
	if err != nil {
		t.Fatal(err)
	}
	auth.Signature = signature
}
