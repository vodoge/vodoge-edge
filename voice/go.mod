module github.com/yuanshuai1122/vodoge-edge/voice

go 1.26.3

// The IMS media relay is consumed from the read-only local mirror of
// github.com/boa-z/vowifi-go. T040 forbids editing anything under vendor-mirror/,
// so it is wired in by path rather than forked.
replace github.com/boa-z/vowifi-go => ../../vendor-mirror/vowifi-go-1e9c6e6

require (
	github.com/boa-z/vowifi-go v0.0.0-00010101000000-000000000000
	github.com/pion/interceptor v0.1.47
	github.com/pion/rtp v1.10.5
	github.com/pion/webrtc/v4 v4.2.18
)

require (
	github.com/emiago/sipgo v1.4.0 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/pion/datachannel v1.6.2 // indirect
	github.com/pion/dtls/v3 v3.1.5 // indirect
	github.com/pion/ice/v4 v4.4.0 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.1.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.17 // indirect
	github.com/pion/sctp v1.11.1 // indirect
	github.com/pion/sdp/v3 v3.0.19 // indirect
	github.com/pion/srtp/v3 v3.0.12 // indirect
	github.com/pion/stun/v3 v3.1.6 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/pion/turn/v5 v5.0.12 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/net v0.50.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)
