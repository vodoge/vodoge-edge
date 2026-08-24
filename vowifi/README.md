# vowifi

IKEv2 / ESP transport and IKE_SA_INIT for the VoWiFi tunnel, injected into the
read-only `vowifi-go` mirror rather than forked from it.

This is T041a. It is the transport plus `IKE_SA_INIT`. IKE_AUTH, the EAP-AKA
bridge, the live ePDG probe and the ESP data plane are T041b through T041e.

## Why a separate module, and why no fork

`vendor-mirror/vowifi-go-1e9c6e6` is already built for substitution.
`engine/swu/ike_tunnel_manager.go` declares `IKEInitRunner` (`:22`),
`IKEAuthRunner` (`:24`), `IKETransportFactory` (`:28`) and
`IKEESPTransportFactory` (`:30`), and `EstablishTunnel` falls back to its
built-ins **only when those fields are nil** (`:152-154`, `:168-171`,
`:374-387`, `:389-401`). So nothing here edits the mirror; `vowifi/go.mod`
points a `replace` at the unmodified copy, exactly as `voice/go.mod` does.

`go build -overlay` is banned. An overlay changes what the compiler sees while
leaving every file on disk untouched, so `scripts/verify-vendor-mirror.sh` would
still pass and "not one byte of the mirror changed" would become a false
statement that keeps all of its formal compliance. Debugging an intermittent
tunnel at 3am against a source tree that does not describe the running binary is
the most expensive failure mode available here.

The full seam inventory, with the evidence behind each claim, is in
`docs/goals/vodoge-vowifi-call/notes/T041-injection-seams.md`.

## What is in here

| Package | Contents |
| --- | --- |
| `internal/ike` | the single UDP socket, the DH groups, the proposal builder, the `IKE_SA_INIT` runner |
| `internal/capture` | pcap recording and offline replay of raw IKE/ESP datagrams |
| `cmd/vodoge-ike-probe` | one-shot probe against an ePDG, with capture and replay modes |

### One socket, pinned to 4500

`ike.Socket` is a single `*net.UDPConn` that implements all three mirror
interfaces at once:

- `ikev2.InitTransport` (`engine/swu/ikev2/init.go:27-29`)
- `swu.ESPPacketReadWriteTransport` (`engine/swu/packet_session.go:31-34`)
- `swu.NATTKeepaliveSender` (`engine/swu/packet_session.go:282-284`)

It has to be one type, because the mirror's own `UDPESPPacketTransport.
ReadESPPacket` hits `continue` on any datagram carrying the non-ESP marker
(`engine/swu/udp_esp_transport.go:110`) - and on port 4500 that marker is
precisely what an IKE message looks like. Sharing that reader would make IKE
replies disappear with no error anywhere. Demultiplexing therefore happens in one
read loop that owns both sides.

Port 4500 is not arbitrary. Measured on the edge VM as uid 1000 on 2026-08-24:

```
PORT 500  bind FAIL errno=13 Permission denied
PORT 4500 bind OK
net.ipv4.ip_unprivileged_port_start = 1024
```

T038 already showed T-Mobile and AT&T answering `IKE_SA_INIT` completely on both
500 and 4500, so using only 4500 costs no reachability, keeps the non-ESP marker
on every message, and keeps IKE and ESP on one five-tuple so their NAT mappings
cannot drift apart.

Retransmission follows RFC 7296 section 2.1 with exponential backoff, and
responses are matched on the IKE header (initiator SPI, message id, exchange
type, response flag). Matching is not decoration: a late answer to an earlier
request arrives on the same socket, and accepting it would bind a stale responder
SPI and nonce to the current exchange.

### DH groups

`{14, 2, 19, 31}` go on the wire, in that order, because that is the set T038 put
in front of seven live ePDGs. All seven chose group 14 and none chose 31 - while
the stock runner hardcodes 31 in three places inside the `RunIKE_SA_INIT` call
chain (`init.go:159`, `init.go:342`, `sa.go:81`), which is why this package
replaces that function outright instead of patching lines.

MODP groups are `math/big` (RFC 3526 for 1536/2048, RFC 2409 section 6.2 for
1024). Watch the naming: **IKE group 2 is MODP-1024, not MODP-1536**; MODP-1536
is group 5. Both are implemented; only group 2 is proposed, matching T038.

The tests do not restate the primes. They check the RFC closed form
`p = 2^n - 2^(n-64) - 1 + 2^64 * (floor(2^(n-130) * pi) + offset)` by recovering
the pi term and comparing it against Go's own `math.Pi`, then check that `p` and
`(p-1)/2` are both prime and that 2 generates the order-q subgroup. A test that
compares a constant against a copy of itself guards nothing.

### NAT detection actually happens

The stock stack sends no `NAT_DETECTION` at all on the common path:
`initNATPayloads` (`init.go:371-373`) returns nil whenever `LocalPort` is zero,
and the mirror's own `ikev2.UDPTransport` dials without binding, so it usually is.
`detectNAT` (`init.go:385-387`) short-circuits on the same condition, making
`InitResult.NATDetected` a constant false. Both failures are silent.

Here the socket pins the local port, so it is never zero, and `InitRunner`
returns `ErrMissingNATDetectionInputs` rather than quietly omitting the payloads.
Skipping requires setting `AllowMissingNATDetection` on purpose.

### Legacy T-Mobile suite: declared, not implemented

T038 saw one node (`208.54.26.131`) offering 3DES / HMAC-SHA1-96 / AES128-XCBC.
That suite is blocked by a type wall, not a missing switch case:
`ikev2.KeyMaterialProfile.PRF` is a `crypto.Hash` (`keys.go:13`) and AES-XCBC-PRF
is a CMAC construction that no `crypto.Hash` value can express. Changing the
field type would ripple across the whole `ikev2` package, i.e. a fork.

`ike.LegacySuiteBlockers()` names each blocking site, and the proposal builder
refuses to emit those transform ids. The way around it is candidate rotation, not
an address blocklist: T038 got seven distinct IPs from seven lookups and
`.26.131` was merely one of them, so the pool may hold other legacy nodes. The
probe tries candidates until one succeeds and reports the suite each failure
selected.

### Capture and replay

The first contact with a real ePDG happens once, at 3am, over a Dallas egress. If
it is not reproducible offline, every later debugging round needs live hardware
and a live carrier. Upstream `internal/tracefixture` covers SIP text only; the
IKE/ESP layer had no replay ability.

`internal/capture` writes a classic pcap (LINKTYPE_RAW, synthesised IPv4/IPv6 and
UDP headers) so Wireshark dissects ISAKMP and ESP directly, plus a
`<name>.session.json` sidecar. The sidecar holds the replay seed - initiator SPI,
`NonceI`, DH group and DH scalar - because `RunIKE_SA_INIT` generates all of
those internally and a replay without them cannot reproduce its own request.

The seed is written only under `RecordSecrets`, with a warning in the file and on
stderr, because anyone holding the sidecar and the pcap can derive the IKE SA
keys. It is a lab artifact, not a distributable.

`capture.ReplayTransport` implements the same three mirror interfaces as the live
socket. `RequireExactRequests` makes the replay assert the outgoing bytes against
the recording, which is the difference between "the replay produced something
plausible" and "the replay reproduced the recording".

## Building and running

The edge VM has no Go toolchain. Cross-compile on a workstation and copy, the
same way T040a does:

```sh
cd vowifi
GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o vodoge-ike-probe ./cmd/vodoge-ike-probe
scp vodoge-ike-probe vodoge-edge:/tmp/
```

```sh
# one probe, recorded so it can be replayed later
./vodoge-ike-probe -target epdg.epc.mnc260.mcc310.pub.3gppnetwork.org \
    -capture /tmp/epdg.pcap -record-secrets

# same exchange, offline, no network at all
./vodoge-ike-probe -replay /tmp/epdg.pcap
```

Edge DNS is rewritten into fake-IP `198.18.0.0/16`; the probe detects that and
says so instead of dialling a bogus address. Pass an address resolved out of band
(T038 used DoH) when that happens.

`IKE_SA_INIT` carries no identity, so a successful probe proves reachability and
algorithm selection and nothing more. Whether the carrier accepts this SIM is an
IKE_AUTH question and belongs to T041b/d, under goal oracle criterion 2b.

## Tests

```sh
cd vowifi && GOWORK=off go test ./...
```

Everything runs on loopback against a fake ePDG; no hardware, no US line, no
carrier. `TestFakeEPDGSeparatesEAPSuccessFromChildSA` is the first fixture in
this repository that refuses the "EAP-Success and the CHILD_SA arrive in one
message" assumption - it drives an IKE_AUTH ladder over the real socket and fails
if the two ever share a message id. Its payloads are unencrypted because SK
handling is T041b; what it pins is the sequencing.

`scripts/verify-vendor-mirror.sh` proves the mirror is untouched, and CI runs it
with `VODOGE_VERIFY_STRICT_EOL=1`.
