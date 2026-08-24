// Command vodoge-voice is the edge media endpoint for VoWiFi calls.
//
// Phase a runs the whole media path with no IMS, no ePDG and no cloud:
//
//	host Chrome (192.168.78.1)
//	  -- WebRTC / PCMU / DTLS-SRTP / ICE host candidate -->
//	edge VM (192.168.78.10) vodoge-voice
//	  pion PeerConnection (DTLS terminates here)
//	  identity payload transform (phase 1, no cgo)
//	  -- plaintext RTP over 127.0.0.1 -->
//	voicehost.NewRTPRelaySessionForIMSRemote
//	  client leg: ClientListenIP = ClientAdvertiseIP = 127.0.0.1
//	  IMS leg:    a stand-in peer on the same host (tone + delayed echo)
//
// The point of the exercise is that the browser and the stand-in peer are
// audible to each other in both directions, which is what proves the relay is
// actually carrying media rather than just being constructible.
//
// Nothing here touches the modems, the cloud gateway or the edge-cloud
// contract. It builds with CGO_ENABLED=0 and is meant to be cross-compiled on
// the workstation and copied to the edge VM.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yuanshuai1122/vodoge-edge/voice/internal/bridge"
	"github.com/yuanshuai1122/vodoge-edge/voice/internal/devsignal"
)

func main() {
	var (
		bindIP        = flag.String("bind-ip", "192.168.78.10", "address the local signalling endpoint binds to; must be a concrete internal address")
		bindPort      = flag.Int("bind-port", 8443, "port for the local signalling endpoint")
		insecureHTTP  = flag.Bool("insecure-http", false, "serve the signalling endpoint over plain HTTP (Chrome will then refuse the microphone)")
		operatorCIDRs = flag.String("operator-cidr", "192.168.78.0/24", "comma-separated client networks allowed to place a local call")
		token         = flag.String("token", "", "session token; generated and printed at startup when empty")

		mediaIfaces  = flag.String("media-interface", "ens160", "comma-separated interfaces ICE may gather host candidates from")
		mediaIPs     = flag.String("media-ip", "192.168.78.10", "comma-separated addresses allowed to appear as ICE candidates")
		mediaPortMin = flag.Uint("media-port-min", 0, "lower bound of the RTP port range (0 = ephemeral)")
		mediaPortMax = flag.Uint("media-port-max", 0, "upper bound of the RTP port range (0 = ephemeral)")

		loopbackIP = flag.String("loopback-ip", "127.0.0.1", "loopback address carrying plaintext RTP between the bridge and the relay")

		toneHz      = flag.Float64("tone-hz", 440, "frequency of the tone the stand-in IMS peer plays")
		toneOnMS    = flag.Int("tone-on-ms", 300, "how long each beep from the stand-in IMS peer lasts")
		toneOffMS   = flag.Int("tone-off-ms", 1200, "gap between beeps from the stand-in IMS peer")
		echoDelayMS = flag.Int("echo-delay-ms", 700, "how long the stand-in IMS peer holds audio before echoing it back")

		statsEvery = flag.Duration("stats-interval", 10*time.Second, "how often to log the media counters; 0 disables")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "vodoge-voice: ", log.LstdFlags|log.Lmicroseconds)

	policy := bridge.LocalMediaPolicy{
		Interfaces:   splitList(*mediaIfaces),
		AdvertiseIPs: splitList(*mediaIPs),
		PortMin:      uint16(*mediaPortMin),
		PortMax:      uint16(*mediaPortMax),
	}
	if err := policy.Validate(); err != nil {
		logger.Fatalf("media policy: %v", err)
	}

	a := &app{
		logger: logger,
		policy: policy,
		loopback: bridge.LoopbackConfig{
			LoopbackIP: *loopbackIP,
			Peer: bridge.FakePeerConfig{
				ToneHz:      *toneHz,
				ToneOnMS:    *toneOnMS,
				ToneOffMS:   *toneOffMS,
				EchoDelayMS: *echoDelayMS,
			},
		},
	}

	srv, err := devsignal.New(devsignal.Config{
		BindIP:        *bindIP,
		Port:          *bindPort,
		OperatorCIDRs: splitList(*operatorCIDRs),
		Token:         *token,
		Insecure:      *insecureHTTP,
		Answer:        a.answer,
		Hangup:        a.hangup,
		Stats:         a.stats,
		Logf:          logger.Printf,
	})
	if err != nil {
		logger.Fatalf("local signalling endpoint: %v", err)
	}

	logger.Printf("local signalling endpoint: %s", srv.URL())
	if fp := srv.Fingerprint(); fp != "" {
		logger.Printf("self-signed certificate sha256: %s (expect one certificate warning per browser profile)", fp)
	}
	logger.Printf("ice candidates limited to interfaces=%v addresses=%v", policy.Interfaces, policy.AdvertiseIPs)
	logger.Printf("plaintext RTP loopback on %s; relay transforms are deliberately not installed", *loopbackIP)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *statsEvery > 0 {
		go a.logStats(ctx, *statsEvery)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		a.closeCall()
	}()

	if err := srv.Serve(); err != nil {
		logger.Fatalf("serve: %v", err)
	}
	logger.Printf("stopped")
}

// app holds the single active call. Phase a is one operator at one browser, so
// a new offer replaces the previous call rather than queueing beside it.
type app struct {
	logger   *log.Logger
	policy   bridge.LocalMediaPolicy
	loopback bridge.LoopbackConfig

	mu      sync.Mutex
	call    *bridge.Call
	started time.Time
}

func (a *app) answer(ctx context.Context, offer string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.call != nil {
		a.logger.Printf("replacing the active call")
		_ = a.call.Close()
		a.call = nil
	}
	cfg := bridge.CallConfig{
		Policy:   a.policy,
		Loopback: a.loopback,
		Logf:     a.logger.Printf,
	}
	cfg.Loopback.Context = context.WithoutCancel(ctx)
	call, err := bridge.NewCall(cfg)
	if err != nil {
		return "", err
	}
	answer, err := call.Answer(a.policy, offer)
	if err != nil {
		_ = call.Close()
		return "", err
	}
	a.call = call
	a.started = time.Now()
	a.logger.Printf("call up: %+v", call.Stats().Loopback)
	return answer, nil
}

func (a *app) hangup(context.Context) error {
	a.closeCall()
	return nil
}

func (a *app) closeCall() {
	a.mu.Lock()
	call := a.call
	a.call = nil
	a.mu.Unlock()
	if call == nil {
		return
	}
	a.logger.Printf("call down: %+v", call.Stats())
	if err := call.Close(); err != nil && !errors.Is(err, context.Canceled) {
		a.logger.Printf("close call: %v", err)
	}
}

func (a *app) stats() any {
	a.mu.Lock()
	call := a.call
	started := a.started
	a.mu.Unlock()
	if call == nil {
		return map[string]any{"status": "idle"}
	}
	return map[string]any{
		"status":     "up",
		"uptime_sec": int(time.Since(started).Seconds()),
		"call":       call.Stats(),
	}
}

func (a *app) logStats(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		a.mu.Lock()
		call := a.call
		a.mu.Unlock()
		if call == nil {
			continue
		}
		s := call.Stats()
		a.logger.Printf("media: browser->edge %d pkt, edge->relay %d pkt, relay client->ims %d pkt, fake peer rx %d / tx %d, relay ims->client %d pkt, relay->browser %d pkt, dropped %d/%d",
			s.Peer.FromBrowserRTP, s.Loopback.BridgeToRelayRTP, s.Loopback.Relay.ClientToIMSRTPPackets,
			s.Loopback.FakeIMSPeer.ReceivedRTP, s.Loopback.FakeIMSPeer.SentRTP,
			s.Loopback.Relay.IMSToClientRTPPackets, s.Peer.ToBrowserRTP,
			s.Loopback.Dropped, s.Peer.Dropped)
	}
}

func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
