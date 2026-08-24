# vodoge-voice phase a — edge loopback call

Phase a proves the media path end to end **without IMS, ePDG, the cloud, the
modems or a US SIM**. If audio is audible in both directions here, the only
thing left between this and a real VoWiFi call is signalling and the IMS-facing
codec — not the media plumbing.

```
host Chrome (192.168.78.1)
  |  WebRTC / PCMU / DTLS-SRTP / ICE host candidate
  v
edge VM (192.168.78.10)  vodoge-voice
  |  pion PeerConnection            <- DTLS terminates here
  |  payload transform = identity   <- phase 1, no cgo
  v
127.0.0.1 plaintext RTP
  |
  v
voicehost.NewRTPRelaySessionForIMSRemote   (vendor-mirror, unmodified)
  client leg : ClientListenIP = ClientAdvertiseIP = 127.0.0.1
  IMS leg    : a stand-in peer on the same host (tone + delayed echo)
```

## Why there is no audio file in this directory

The stand-in IMS peer synthesises its own audio, so phase a needs no sample
asset: it plays a gated 440 Hz beep and echoes back whatever it receives after
`-echo-delay-ms`. Both are generated in `internal/bridge/loopback.go`.

That choice is what makes "audible in both directions" a single observation
instead of two:

- the **beep** can only be heard if the IMS leg -> client leg -> browser
  direction is alive; it does not depend on the microphone at all;
- the **echo** can only be heard if the browser -> client leg -> IMS leg
  direction is alive as well, because it is the operator's own voice coming
  back.

Hearing a beep and then your own voice about 0.7 s later means both directions
carried media through the relay. One-way failures are audible as "beep, but no
echo" or "echo, but no beep", which is why the peer does both rather than one.

## Build

The edge VM has no Go toolchain and its DNS is fake-IP (everything resolves into
198.18.0.0/16), so installing one there is a detour. Cross-compile on the
workstation instead — phase 1 is deliberately cgo-free precisely so this works:

```sh
cd vodoge-edge/voice
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/vodoge-voice ./cmd/vodoge-voice
scp /tmp/vodoge-voice vodoge-edge:/tmp/vodoge-voice
```

`go.mod` resolves `github.com/boa-z/vowifi-go` through a `replace` pointing at
`../../vendor-mirror/vowifi-go-1e9c6e6`. The mirror must therefore sit beside
the `vodoge-edge` checkout, exactly as it does in the workspace. It is
**read-only**: T040 requires zero changes to vowifi-go.

## Run on the edge VM

```sh
ssh vodoge-edge
/tmp/vodoge-voice \
  -bind-ip 192.168.78.10 -bind-port 8443 \
  -operator-cidr 192.168.78.0/24 \
  -media-interface ens160 -media-ip 192.168.78.10
```

It prints the URL to open, including a freshly generated session token, plus the
SHA-256 of the self-signed certificate it just made.

Two deliberate restrictions, both from the T040 card:

- the signalling endpoint binds **one concrete internal address**; an
  unspecified bind (`0.0.0.0`) is refused at startup, because this endpoint
  hands out internal ICE host candidates;
- only a caller inside `-operator-cidr` carrying the token gets an answer. The
  `192.168.78.10` host candidate is therefore never offered to an arbitrary
  browser. `LocalMediaPolicy.AuditAnswer` re-reads the generated SDP and refuses
  to emit anything that is not a host candidate on `-media-ip`.

## Place the call

1. Open the printed `https://192.168.78.10:8443/?token=...` in Chrome **on the
   VMware host**. HTTPS with a self-signed certificate is not decoration:
   Chrome only exposes `getUserMedia` to a secure context, and this page is not
   on `localhost` from the browser's point of view. Accept the warning once per
   browser profile and check the fingerprint against the startup log.
2. Click **Start call** and grant the microphone.
3. Listen. Expect the beep within a second, then your own voice delayed.
4. The page shows the browser's own `getStats()` counters next to the edge's.

If the host firewall or the VMware network ever gets in the way, the ICE state
on the page stops at `checking`; the media counters all stay at zero and the
edge log shows no `browser track:` line.

## Reading the counters

`GET /stats` (and the right-hand pane of the page) returns every hop:

| field | meaning |
| --- | --- |
| `peer.from_browser_rtp_packets` | SRTP packets unwrapped from Chrome |
| `loopback.bridge_to_relay_rtp_packets` | packets written into the relay's client leg |
| `loopback.relay.client_to_ims_rtp_packets` | packets the relay forwarded toward IMS |
| `loopback.fake_ims_peer.received_rtp_packets` | packets the stand-in peer heard |
| `loopback.fake_ims_peer.sent_rtp_packets` | tone+echo packets it sent back |
| `loopback.relay.ims_to_client_rtp_packets` | packets the relay forwarded back |
| `peer.to_browser_rtp_packets` | packets re-encrypted toward Chrome |
| `loopback.relay_transforms_installed` | must stay **false** (see below) |

All seven counters have to move. A single stalled one localises the break
immediately, which is the whole reason they are reported per hop.

## Two constraints worth restating

**`RTPRelayTransforms` is off limits.** `rtp_relay.go` runs its RTP quality
statistics (`:1341`), RTCP feedback inspection (`:1352`) and two-way DTMF
handling (`:1355`) only while the transform is `nil`, and it drops all three
*silently* when one is attached. Payload conversion therefore happens on the
WebRTC side of the loopback, through `bridge.PayloadTransform`.
`relay_transforms_installed` in `/stats` exists so the running process can prove
that at any moment.

**PCMU is milestone 1, not the destination.** RFC 7874 guarantees the browser
has G.711 and the relay's `forwardLoop` only moves bytes, so a PCMU-to-PCMU
bridge needs no transcoding and no cgo. But the IMS-facing validator in
`voiceclient/sdp_media.go:14-17` accepts only AMR, AMR-WB and telephone-event —
**PCMU is not on that list**. When the IMS leg becomes real, an AMR-WB codec has
to slot into `PayloadTransform`, which is exactly why that seam exists now:
`Transform` already reports its own payload type and clock rate, and `convert`
already rescales timestamps.

## Tests

```sh
cd vodoge-edge/voice && go test ./...
```

`TestBrowserToFakePeerIsAudibleBothWays` runs the whole path in process with a
second pion peer standing in for Chrome: real offer/answer, real DTLS-SRTP, real
UDP. It asserts every hop counter rather than any single one, because every
earlier "the media path works" claim in this project failed at a hop that was
individually green.
