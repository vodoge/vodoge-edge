package devsignal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testConfig() Config {
	return Config{
		BindIP:        "127.0.0.1",
		Port:          0,
		OperatorCIDRs: []string{"127.0.0.0/8"},
		Token:         "s3cret",
		Insecure:      true,
		Answer: func(context.Context, string) (string, error) {
			return "v=0\r\na=candidate:1 1 udp 2130706431 192.168.78.10 40002 typ host\r\n", nil
		},
		Stats: func() any { return map[string]string{"status": "idle"} },
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(testConfig())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	return s
}

// TestNewRefusesAnUnspecifiedBind is the rule from the T040 card: the local
// signalling endpoint hands out internal ICE host candidates, so it may only
// listen on the edge VM's internal address, never on every interface.
func TestNewRefusesAnUnspecifiedBind(t *testing.T) {
	for _, addr := range []string{"0.0.0.0", "::", ""} {
		cfg := testConfig()
		cfg.BindIP = addr
		if _, err := New(cfg); err == nil {
			t.Fatalf("binding %q must be refused", addr)
		}
	}
}

func TestNewRefusesAMissingOperatorNetwork(t *testing.T) {
	cfg := testConfig()
	cfg.OperatorCIDRs = nil
	if _, err := New(cfg); err == nil {
		t.Fatal("a server with no operator network must be refused")
	}
	cfg = testConfig()
	cfg.OperatorCIDRs = []string{"not-a-cidr"}
	if _, err := New(cfg); err == nil {
		t.Fatal("a malformed operator network must be refused")
	}
}

func TestNewGeneratesATokenWhenNoneIsConfigured(t *testing.T) {
	cfg := testConfig()
	cfg.Token = ""
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer s.Shutdown(context.Background())
	if len(s.Token()) < 16 {
		t.Fatalf("generated token is too short: %q", s.Token())
	}
	if !strings.Contains(s.URL(), s.Token()) {
		t.Fatalf("the startup URL must carry the token: %s", s.URL())
	}
}

func TestAuthorizeIsTheOnlyGate(t *testing.T) {
	s := newTestServer(t)
	header := http.Header{TokenHeader: []string{"s3cret"}}

	if err := s.Authorize("127.0.0.1:5555", header, ""); err != nil {
		t.Fatalf("the local operator must be allowed: %v", err)
	}
	if err := s.Authorize("127.0.0.1:5555", http.Header{}, "s3cret"); err != nil {
		t.Fatalf("the token may also arrive in the query: %v", err)
	}
	if err := s.Authorize("192.168.78.1:5555", header, ""); err == nil {
		t.Fatal("a caller outside the operator network must be refused even with the right token")
	}
	if err := s.Authorize("127.0.0.1:5555", http.Header{}, "wrong"); err == nil {
		t.Fatal("a bad token must be refused")
	}
	if err := s.Authorize("127.0.0.1:5555", http.Header{}, ""); err == nil {
		t.Fatal("a missing token must be refused")
	}
	if err := s.Authorize("garbage", header, ""); err == nil {
		t.Fatal("an unparsable client address must be refused")
	}
}

func TestEveryRouteRefusesAnUnauthorisedCaller(t *testing.T) {
	s := newTestServer(t)
	h := s.Handler()
	routes := []struct{ method, path string }{
		{http.MethodGet, "/"},
		{http.MethodPost, "/offer"},
		{http.MethodPost, "/hangup"},
		{http.MethodGet, "/stats"},
	}
	for _, route := range routes {
		// Right network, no token.
		req := httptest.NewRequest(route.method, route.path, strings.NewReader(`{"sdp":"v=0"}`))
		req.RemoteAddr = "127.0.0.1:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s without a token returned %d, want 403", route.method, route.path, rec.Code)
		}

		// Right token, wrong network.
		req = httptest.NewRequest(route.method, route.path, strings.NewReader(`{"sdp":"v=0"}`))
		req.RemoteAddr = "10.9.8.7:5555"
		req.Header.Set(TokenHeader, "s3cret")
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s from a foreign network returned %d, want 403", route.method, route.path, rec.Code)
		}
	}
}

func TestOfferReturnsTheAnswerToTheLocalOperator(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/offer", strings.NewReader(`{"sdp":"v=0\r\n"}`))
	req.RemoteAddr = "127.0.0.1:5555"
	req.Header.Set(TokenHeader, "s3cret")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("offer returned %d: %s", rec.Code, rec.Body.String())
	}
	var body answerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode answer: %v", err)
	}
	if !strings.Contains(body.SDP, "typ host") {
		t.Fatalf("unexpected answer: %q", body.SDP)
	}
}

func TestOfferRejectsAnEmptyBody(t *testing.T) {
	s := newTestServer(t)
	for _, body := range []string{`{}`, `{"sdp":"  "}`, `not json`} {
		req := httptest.NewRequest(http.MethodPost, "/offer", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:5555"
		req.Header.Set(TokenHeader, "s3cret")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("offer %q returned %d, want 400", body, rec.Code)
		}
	}
}

func TestIndexServesThePageWithEchoCancellationOff(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/?token=s3cret", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("index returned %d", rec.Code)
	}
	// The stand-in peer proves the browser-to-edge direction by echoing the
	// operator's own voice back. Chrome's echo canceller would delete exactly
	// that evidence, so the page must switch it off.
	if !strings.Contains(rec.Body.String(), "echoCancellation: false") {
		t.Fatal("the demo page must disable echo cancellation")
	}
	if !strings.Contains(rec.Body.String(), "getUserMedia") {
		t.Fatal("the demo page must ask for a microphone")
	}
}

func TestStatsRequiresTheTokenAndReturnsJSON(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/stats?token=s3cret", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("stats returned %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if body["status"] != "idle" {
		t.Fatalf("unexpected stats: %v", body)
	}
}

func TestTLSCertificateIsGeneratedForTheBindAddress(t *testing.T) {
	cfg := testConfig()
	cfg.Insecure = false
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer s.Shutdown(context.Background())
	if len(s.Fingerprint()) != 64 {
		t.Fatalf("expected a sha256 fingerprint, got %q", s.Fingerprint())
	}
	if !strings.HasPrefix(s.URL(), "https://") {
		t.Fatalf("the operator URL must be https: %s", s.URL())
	}
}
