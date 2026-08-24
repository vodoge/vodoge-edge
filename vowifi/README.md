# vowifi

IKEv2 / ESP transport and IKE_SA_INIT for the VoWiFi tunnel, injected into the
read-only `vowifi-go` mirror rather than forked from it.

This is T041a plus T041b: the transport, `IKE_SA_INIT`, and the whole `IKE_AUTH`
loop with RFC 5998 EAP-only authentication. The real USIM bridge (T041c), the
live ePDG contact (T041d) and the ESP data plane plus IKE fragmentation (T041e)
are still to come; the AKA provider here is an injected test implementation and
nothing in this module has ever touched hardware or a carrier.

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
| `internal/ike` | the single UDP socket, the DH groups, the proposal builder, the `IKE_SA_INIT` runner, the `IKE_AUTH` runner and the EAP-AKA driver |
| `internal/capture` | pcap recording, offline replay of raw IKE/ESP datagrams, and AUTH payload extraction |
| `cmd/vodoge-ike-probe` | one-shot probe against an ePDG, with capture, replay and AUTH export modes |

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

### IKE_AUTH: our own loop, and why

This is T041b. `ike.AuthRunner` replaces `ikev2.RunIKE_AUTH_Full` wholesale
rather than wrapping it, for two reasons that cannot be worked around from
outside the mirror.

`RunIKE_AUTH_EAPIdentity` builds its first request with
`BuildIKEAuthInitialPayloads` (`auth.go:182` calling `auth.go:840-888`), which
returns `{IDi, CP, SA, TSi, TSr}`. There is no **IDr**, and
`EAP_ONLY_AUTHENTICATION` does not appear anywhere under `engine/` - a grep of
the whole mirror returns nothing. RFC 5998 EAP-only authentication needs both:
without the notify, an ePDG follows plain RFC 7296 section 2.16 and expects to
prove its identity with a certificate, which this stack cannot validate.

`RunIKE_AUTH_Full` also treats EAP-Success arriving without a CHILD_SA in the
same message as an error (`auth.go:326`). That is what a *correct* ladder looks
like. RFC 7296 section 2.16 and RFC 5998 section 2 both put EAP-Success in its
own exchange and `AUTH` plus `SAr2/TSi/TSr` in the next one.

The payloads we send, in wire order:

```
HDR, SK { IDi, IDr, CP, SA, TSi, TSr, N(EAP_ONLY_AUTHENTICATION) }
```

RFC 7296 section 2.5 lets a notify sit anywhere, so the position is a
compatibility choice, not a correctness one; it follows the RFC 5998 section 2
example while keeping the mirror's CP placement. A missing IDr is an error
(`ErrMissingResponderID`), not a quieter request - the same decision T041a made
about `NAT_DETECTION`, for the same reason.

The ladder:

```
-> IDi, IDr, CP, SA, TSi, TSr, N(EAP_ONLY_AUTHENTICATION)
<- IDr, EAP-Request/AKA-Identity
-> EAP-Response/AKA-Identity
<- EAP-Request/AKA-Challenge
-> EAP-Response/AKA-Challenge
<- EAP-Success                       (message N,   alone)
-> AUTH
<- AUTH, CP, SAr2, TSi, TSr          (message N+1, never N)
```

`AuthRunner` refuses a response that puts EAP-Success and the CHILD_SA in one
message (`ErrEAPSuccessWithChildSA`): taking a CHILD_SA from a peer whose AUTH
we have not seen would defeat the point of verifying it.

### The AUTH payload, and the byte most likely to be wrong

```
InitiatorSignedOctets = RealMessage1 | NonceRData | prf(SK_pi, RestOfInitIDPayload)
ResponderSignedOctets = RealMessage2 | NonceIData | prf(SK_pr, RestOfRespIDPayload)
AUTH                  = prf(prf(MSK, "Key Pad for IKEv2"), <SignedOctets>)
```

`RealMessage1/2` are the IKE_SA_INIT request and response verbatim, header
included, which is why `AuthRunner` refuses an `InitResult` that dropped them
instead of signing something else. `RestOf...IDPayload` is the ID payload
*body* - one ID Type octet, three RESERVED, then the data - and never the
generic payload header. A received IDr is MACed over the octets that arrived,
not over a re-encoding of the parsed value.

The payload on the wire is RFC 7296 section 3.8: one **Auth Method** octet,
three RESERVED octets, then the data.

**Auth Method = 2 (Shared Key Message Integrity Code).** This is reasoned, not
measured. RFC 7296 section 2.16 says that when the EAP method produces a shared
key, both peers compute AUTH "using the syntax for shared secrets specified in
Section 2.15", with the MSK as the shared secret; section 2.15 defines method 2
as exactly that syntax, and RFC 5998 section 3 inherits it. **There is no
captured evidence from a real ePDG anywhere in this repository**, so:

- it is one named constant, `ike.AuthMethodSharedKeyMIC`;
- `AuthRunner.AuthMethod` and `AuthRunner.ExpectedPeerAuthMethod` override it;
- a responder using a different method is a named error, `ErrPeerAuthMethod`,
  not a silent acceptance;
- every AUTH payload can be exported out of a pcap on its own (below), so the
  first live contact is diagnosed from the recording rather than from a second
  live attempt.

`N(EAP_ONLY_AUTHENTICATION) = 16417` is in the same category: it is the RFC 5998
section 5 IANA allocation, nothing here has seen it come back from a live node,
and it is one constant so that one line changes if T041d disagrees.

### The peer AUTH is actually verified

`AuthRunner` recomputes `ResponderSignedOctets` from the IDr the responder sent
and compares in constant time. Failure is `ErrPeerAuthFailed`; an absent AUTH is
`ErrPeerAuthMissing`. A responder that produces an AUTH *before* EAP finishes
has ignored `EAP_ONLY_AUTHENTICATION` and is presenting a certificate, so it is
`ErrResponderIgnoredEAPOnly` rather than an unverifiable payload we quietly
accept. Each of those has an opt-out flag, and each opt-out is off by default.

The test for this is not "our verifier likes our own output": the fake ePDG
flips one bit of an otherwise valid AUTH, and the test additionally asserts that
the responder still accepted *ours*, so the forgery is isolated to one side.

### EAP-AKA failure paths

`eapaka.BuildChallengeResponseFromProvider` (`crypto.go:204`) already converts
`sim.ErrSyncFailure` into an `AT_AUTS` EAP-Response/AKA-Synchronization-Failure
and `sim.ErrAuthFailure` into an EAP-Response/AKA-Authentication-Reject, both
already MAC-correct. All this package has to do is classify the card error
correctly and put the packet on the wire instead of aborting.

Both are exercised end to end, and the assertion is on the responder's side: the
fake ePDG decrypts the packet and reads the AUTS out of it, then resynchronises
and challenges again. A synchronisation failure is retried
(`MaxResyncAttempts`, default 1) because that is what resynchronisation is for;
an Authentication-Reject stops with `ErrAKAAuthFailure`, because we have just
decided this is not our network.

### The AKA deadline seam, which exists before the card does

`sim.AKAProvider` is one method with no context:

```go
CalculateAKA(rand16, autn16 []byte) (sim.AKAResult, error)   // engine/sim/sim.go:116-118
```

There is no deadline and no cancellation. T041b injects a test provider, but
T041c will inject a bridge to the real card, and behind that bridge the Rust
arbiter is bounded at **300 seconds or not at all** until T058 lands. An ePDG
has abandoned the IKE_AUTH exchange long before then, so waiting cannot succeed;
it can only hide the fault. Leaving the seam to T041c would mean discovering
then that there is nowhere to put it.

`ike.WithAKADeadline(ctx, provider, timeout)` is that place.
`AuthRunner.AKATimeout` applies it automatically (`DefaultAKATimeout`, 20s;
negative disables it). The honest limitation, stated rather than hidden: **the
abandoned call keeps running.** Its goroutine cannot be cancelled because the
interface offers no way to ask. It writes to a buffered channel and exits on its
own, and it works on private copies of RAND/AUTN so it cannot scribble on a
buffer the caller moved past - but it still occupies the card. A real bridge
needs its own serialisation on top, and that is T041c's problem; this wrapper
only guarantees that the IKE side stops waiting.

A timeout must not be mistaken for a card refusal:
`ErrAKADeadlineExceeded` is neither `sim.ErrSyncFailure` nor
`sim.ErrAuthFailure`, so eapaka does not manufacture an AT_AUTS out of a stall.
There is a test for exactly that.

### The fake ePDG is encrypted now

T041a's IKE_AUTH fixture travelled in clear and could only pin message
sequencing. That is not enough for T041b: the AUTH payload is keyed by material
that exists only if both sides ran the same key derivation, so a plaintext
fixture cannot check it at all.

The fixture now derives the IKE SA keys the responder way, decrypts every
request with the mirror's own `UnprotectMessage` (`sk.go:126`) and encrypts every
response with `ProtectMessage` (`sk.go:16`). A request that was not really
protected fails at "expected single SK payload".

Two things are deliberately *not* shared between the two sides:

- The RFC 7296 section 2.15 composition. The fixture writes it out itself
  instead of calling `ike.SharedKeyAuth`. There is only one HMAC in the standard
  library so the primitive is necessarily common, but the part that is actually
  error-prone - the order of the three concatenated pieces, the key-pad step,
  whether the ID payload header is included - is written twice and only agrees
  if it is right. `auth_payloads_test.go` goes further and re-derives HMAC from
  RFC 2104 using only `crypto/sha256`, which is this card's version of T041a
  cross-checking `crypto/ecdh` against `crypto/elliptic`.
- The EAP identity. The responder derives keys from the `AT_IDENTITY` string it
  received, not from a configured constant, so the two only agree if the
  identity really made it across.

What *is* shared is the stand-in USIM secret, which is exactly what a real K is:
one value held by both the card and the operator's AuC. `usimDerive` is an
openly labelled deterministic function and **not Milenage**. Inventing a
Milenage vector from memory is the anti-pattern this project keeps paying for,
so nothing here claims to be one.

### Exporting AUTH payloads out of a recording

Both AUTH payloads live inside SK, so a pcap opened without keys shows nothing.
The keys come back from replaying IKE_SA_INIT out of the same recording, so a
pcap plus its sidecar is enough - no live carrier, no hardware:

```sh
./vodoge-ike-probe -replay /tmp/ike-auth.pcap -export-auth /tmp/auth
```

```
  IKE_AUTH     4 exchange(s) reproduced byte for byte
  IDr sent     true; EAP_ONLY_AUTHENTICATION sent true
  EAP-Success  message 3; CHILD_SA message 4
  peer AUTH    verified=true method=2
  AUTH tx msg 4  method=2 reserved=000000 data=32 octets encrypted=true
```

The written `.auth.bin` files contain the **whole body, header included**.
Stripping the four-octet header would hide the byte most likely to be wrong.

Replaying IKE_AUTH needs more seed than IKE_SA_INIT did. On top of the SPI,
nonce and DH scalar, the ladder consumes a fresh child SPI, one CBC IV per
protected message, and the card's answers - and every one of those changes the
ciphertext. `capture.AuthSeed` carries all of them plus both identities, so the
recording is self-describing. Without it a "replay" would merely be a re-run
that happened to reach the same conclusion, which is the weaker claim this
repository has been burnt by before.

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
algorithm selection and nothing more. The probe deliberately does not run a live
`IKE_AUTH`: that needs a real USIM, which is T041c, and a real ePDG, which is
T041d. It does replay a recorded `IKE_AUTH` ladder, and it can export the AUTH
payloads out of one.

## Tests

```sh
cd vowifi && GOWORK=off go test ./...
```

Everything runs on loopback against a fake ePDG; no hardware, no US line, no
carrier. Nothing in this module has ever spoken to a real operator, so no test
here is evidence for goal oracle criterion 2b.

`TestFakeEPDGSeparatesEAPSuccessFromChildSA` (T041a) refuses the "EAP-Success and
the CHILD_SA arrive in one message" assumption by driving a plaintext ladder over
the real socket. `TestAuthRunnerWalksTheWholeLadder` and
`TestAuthRunnerRejectsEAPSuccessSharingTheChildSA` (T041b) do the stronger
version: the fixture is encrypted, and the second one makes the fake do the wrong
thing on purpose so the refusal is the runner's, not the fixture's.

`-race` is not available in this environment: the Windows Go toolchain has no C
compiler, and the WSL Go is 1.24 against a go1.26.3 module. Following T041a, the
substitute is `GOWORK=off go test ./... -count=5`, reported as what it is - a
repeat run, not a race detector.

`scripts/verify-vendor-mirror.sh` proves the mirror is untouched, and CI runs it
with `VODOGE_VERIFY_STRICT_EOL=1`. On a Windows workstation the strict mode
always reports drift, because `core.autocrlf=true` leaves the mirror CRLF on
disk; the check separates that into `EOL-ONLY` and says so. To reproduce the CI
result, materialise the mirror the way `.github/workflows/ci.yml` does, with
`git -c core.autocrlf=false ... checkout-index -a -f` into a clean tree.
