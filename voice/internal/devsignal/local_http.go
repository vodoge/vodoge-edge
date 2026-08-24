// Package devsignal is the phase-a local signalling endpoint.
//
// It exists so an operator sitting at the VMware host can set up the loopback
// call with nothing but a browser: no cloud, no IMS, no contract change. It is
// deliberately not the production signalling path -- that one is a separate WSS
// channel between the edge and the gateway and is out of scope here.
//
// Two rules shape this file:
//
//   - It binds to one explicit address on the edge VM's internal interface. An
//     unspecified bind (0.0.0.0 / ::) is refused outright, because the same VM
//     also faces the modems and the upstream NAT and this endpoint hands out
//     internal host candidates.
//   - Only a caller from the configured local-operator network, carrying the
//     session token, gets an answer at all. Everything else gets 403 before any
//     SDP is generated.
//
// It serves HTTPS with a self-signed certificate generated at startup, because
// Chrome only exposes getUserMedia to a secure context and the page is not on
// localhost from the browser's point of view. The operator accepts the
// certificate warning once per browser profile.
package devsignal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

// TokenHeader carries the session token on API calls; the page also accepts it
// as a ?token= query parameter so the operator can paste one URL.
const TokenHeader = "X-Vodoge-Voice-Token"

// Config configures the local signalling endpoint.
type Config struct {
	// BindIP must be a concrete address on the edge VM. Unspecified addresses
	// are refused.
	BindIP string
	// Port is the HTTPS port.
	Port int
	// OperatorCIDRs is the allow list of client networks. A caller outside it
	// never reaches Answer.
	OperatorCIDRs []string
	// Token authenticates the operator. Empty means "generate one at startup".
	Token string
	// Insecure serves plain HTTP. Only for tests: Chrome will refuse to give
	// the page a microphone over plain HTTP from a non-localhost origin.
	Insecure bool

	// Answer performs the offer/answer exchange. It is the only hook that
	// touches media.
	Answer func(ctx context.Context, offer string) (string, error)
	// Hangup tears the current call down. Optional.
	Hangup func(ctx context.Context) error
	// Stats returns the JSON-serialisable snapshot shown on the page.
	Stats func() any
	Logf  func(string, ...any)
}

// Server is the local signalling endpoint.
type Server struct {
	cfg         Config
	nets        []*net.IPNet
	token       string
	listener    net.Listener
	httpServer  *http.Server
	fingerprint string
}

// New validates the configuration and binds the listener.
func New(cfg Config) (*Server, error) {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Answer == nil {
		return nil, errors.New("devsignal: no answer hook")
	}
	ip := net.ParseIP(strings.TrimSpace(cfg.BindIP))
	if ip == nil {
		return nil, fmt.Errorf("devsignal: bind address %q is not an IP", cfg.BindIP)
	}
	if ip.IsUnspecified() {
		return nil, errors.New("devsignal: refusing to bind an unspecified address: this endpoint hands out internal host candidates and must stay on the edge VM's internal interface")
	}
	nets, err := parseCIDRs(cfg.OperatorCIDRs)
	if err != nil {
		return nil, err
	}
	if len(nets) == 0 {
		return nil, errors.New("devsignal: no operator network configured")
	}
	token := strings.TrimSpace(cfg.Token)
	if token == "" {
		token, err = randomToken()
		if err != nil {
			return nil, err
		}
	}
	s := &Server{cfg: cfg, nets: nets, token: token}

	addr := net.JoinHostPort(ip.String(), fmt.Sprint(cfg.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("devsignal: listen on %s: %w", addr, err)
	}
	if !cfg.Insecure {
		cert, fingerprint, err := selfSignedCert(ip)
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
		s.fingerprint = fingerprint
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	s.listener = ln
	s.httpServer = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

// Handler exposes the routes without a listener, for tests.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.guard(s.handleIndex))
	mux.HandleFunc("/offer", s.guard(s.handleOffer))
	mux.HandleFunc("/hangup", s.guard(s.handleHangup))
	mux.HandleFunc("/stats", s.guard(s.handleStats))
	return mux
}

// Token is the session token; the startup log prints it inside the URL.
func (s *Server) Token() string { return s.token }

// Fingerprint is the SHA-256 of the self-signed certificate, so the operator
// can tell the expected certificate warning from an unexpected one.
func (s *Server) Fingerprint() string { return s.fingerprint }

// URL is the address to paste into the browser on the VMware host.
func (s *Server) URL() string {
	scheme := "https"
	if s.cfg.Insecure {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/?token=%s", scheme, s.listener.Addr().String(), s.token)
}

// Serve blocks until the server is shut down.
func (s *Server) Serve() error {
	err := s.httpServer.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops the endpoint.
func (s *Server) Shutdown(ctx context.Context) error { return s.httpServer.Shutdown(ctx) }

// ---------------------------------------------------------------------------
// Authorisation
// ---------------------------------------------------------------------------

// Authorize is the single gate. It is exported so the test suite can hold it to
// the rule directly rather than through six handlers.
func (s *Server) Authorize(remoteAddr string, header http.Header, query string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("devsignal: unparsable client address %q", remoteAddr)
	}
	if !s.isOperatorNetwork(ip) {
		return fmt.Errorf("devsignal: %s is not on a local operator network", ip)
	}
	presented := strings.TrimSpace(header.Get(TokenHeader))
	if presented == "" {
		presented = strings.TrimSpace(query)
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(s.token)) != 1 {
		return errors.New("devsignal: bad session token")
	}
	return nil
}

func (s *Server) isOperatorNetwork(ip net.IP) bool {
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := s.Authorize(r.RemoteAddr, r.Header, r.URL.Query().Get("token")); err != nil {
			s.cfg.Logf("refused %s %s from %s: %v", r.Method, r.URL.Path, r.RemoteAddr, err)
			http.Error(w, "forbidden: local operator only", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(localPage))
}

type offerRequest struct {
	SDP string `json:"sdp"`
}

type answerResponse struct {
	SDP string `json:"sdp"`
}

func (s *Server) handleOffer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req offerRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
		http.Error(w, "bad offer: "+err.Error(), http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.SDP) == "" {
		http.Error(w, "bad offer: empty sdp", http.StatusBadRequest)
		return
	}
	answer, err := s.cfg.Answer(r.Context(), req.SDP)
	if err != nil {
		s.cfg.Logf("answer failed: %v", err)
		http.Error(w, "answer failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, answerResponse{SDP: answer})
}

func (s *Server) handleHangup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Hangup == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "no call"})
		return
	}
	if err := s.cfg.Hangup(r.Context()); err != nil {
		http.Error(w, "hangup failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Stats == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "no call"})
		return
	}
	writeJSON(w, http.StatusOK, s.cfg.Stats())
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseCIDRs(raw []string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("devsignal: operator network %q: %w", item, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func randomToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("devsignal: generate token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func selfSignedCert(ip net.IP) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("devsignal: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("devsignal: serial: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "vodoge-voice local signalling"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{ip, net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("devsignal: create certificate: %w", err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}

// localPage is the operator's console for phase a. It is embedded rather than
// served from disk so the binary is the whole deployment.
//
// echoCancellation, noiseSuppression and autoGainControl are all switched off
// on purpose: the stand-in IMS peer proves the browser-to-edge direction by
// echoing the operator's own voice back, and Chrome's echo canceller would
// remove exactly that evidence.
const localPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>vodoge-voice loopback</title>
<style>
 body { font: 14px/1.5 system-ui, sans-serif; margin: 2rem; max-width: 60rem; }
 button { font-size: 1rem; padding: .4rem 1rem; margin-right: .5rem; }
 pre { background: #f4f4f4; padding: .75rem; overflow: auto; }
 .row { display: flex; gap: 2rem; align-items: flex-start; }
 .row > div { flex: 1; }
 #state { font-weight: 600; }
</style>
</head>
<body>
<h1>vodoge-voice loopback (phase a)</h1>
<p>Browser &rarr; WebRTC/PCMU/DTLS-SRTP &rarr; edge VM &rarr; plaintext RTP on 127.0.0.1 &rarr;
vowifi-go relay &rarr; stand-in IMS peer (tone + delayed echo). No IMS, no ePDG, no cloud.</p>
<p><button id="start">Start call</button><button id="stop">Hang up</button>
<span id="state">idle</span></p>
<audio id="remote" autoplay></audio>
<div class="row">
 <div><h2>Browser</h2><pre id="browserStats">-</pre></div>
 <div><h2>Edge</h2><pre id="edgeStats">-</pre></div>
</div>
<script>
var token = new URLSearchParams(location.search).get('token') || '';
var pc = null, timer = null;
var stateEl = document.getElementById('state');

function setState(s) { stateEl.textContent = s; }

function gathered(pc) {
  return new Promise(function (resolve) {
    if (pc.iceGatheringState === 'complete') { resolve(); return; }
    pc.addEventListener('icegatheringstatechange', function () {
      if (pc.iceGatheringState === 'complete') { resolve(); }
    });
    setTimeout(resolve, 3000);
  });
}

async function start() {
  if (pc) { return; }
  setState('requesting microphone');
  var stream = await navigator.mediaDevices.getUserMedia({
    audio: { echoCancellation: false, noiseSuppression: false, autoGainControl: false }
  });
  pc = new RTCPeerConnection({ iceServers: [] });
  pc.oniceconnectionstatechange = function () { setState('ice: ' + pc.iceConnectionState); };
  pc.ontrack = function (e) { document.getElementById('remote').srcObject = e.streams[0]; };
  stream.getAudioTracks().forEach(function (t) { pc.addTrack(t, stream); });
  var offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  await gathered(pc);
  setState('offering');
  var res = await fetch('/offer?token=' + encodeURIComponent(token), {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ sdp: pc.localDescription.sdp })
  });
  if (!res.ok) { setState('offer refused: ' + res.status + ' ' + (await res.text())); return; }
  var body = await res.json();
  await pc.setRemoteDescription({ type: 'answer', sdp: body.sdp });
  setState('answered');
  timer = setInterval(poll, 1000);
}

async function stop() {
  if (timer) { clearInterval(timer); timer = null; }
  if (pc) { pc.close(); pc = null; }
  await fetch('/hangup?token=' + encodeURIComponent(token), { method: 'POST' });
  setState('idle');
}

async function poll() {
  if (pc) {
    var out = { sent: 0, received: 0, codec: '', rtt: null, jitter: null };
    var report = await pc.getStats();
    report.forEach(function (s) {
      if (s.type === 'outbound-rtp' && s.kind === 'audio') { out.sent = s.packetsSent; }
      if (s.type === 'inbound-rtp' && s.kind === 'audio') {
        out.received = s.packetsReceived;
        out.jitter = s.jitter;
      }
      if (s.type === 'codec' && s.mimeType) { out.codec = s.mimeType; }
      if (s.type === 'candidate-pair' && s.nominated) { out.rtt = s.currentRoundTripTime; }
    });
    document.getElementById('browserStats').textContent = JSON.stringify(out, null, 2);
  }
  var res = await fetch('/stats?token=' + encodeURIComponent(token));
  document.getElementById('edgeStats').textContent = JSON.stringify(await res.json(), null, 2);
}

document.getElementById('start').onclick = function () { start().catch(function (e) { setState('error: ' + e); }); };
document.getElementById('stop').onclick = function () { stop(); };
</script>
</body>
</html>
`
