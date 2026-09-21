package sentinel

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
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
