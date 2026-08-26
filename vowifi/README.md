# vowifi

IKEv2 / ESP transport and IKE_SA_INIT for the VoWiFi tunnel, injected into the
read-only `vowifi-go` mirror rather than forked from it.

This is T041a through T041d: the transport, `IKE_SA_INIT`, the whole `IKE_AUTH`
loop with RFC 5998 EAP-only authentication, the real USIM bridge, and the first
live contact with a carrier. The ESP data plane plus IKE fragmentation (T041e)
is still to come.

**On 2026-08-24 this stack got an EAP-AKA Challenge out of T-Mobile US, answered
it with the eUICC on the bench, and got EAP-Success back.** That is goal oracle
criterion 2b, and the evidence is in
`docs/goals/vodoge-vowifi-call/notes/T072-first-epdg-contact.md`. The tunnel did
*not* come up: the ePDG rejected the final exchange with
`INTERNAL_ADDRESS_FAILURE`, which is a configuration-payload problem and belongs
to criterion 4. Do not read "criterion 2b holds" as "the tunnel works".

**T081 went after that rejection and did not clear it.** Three CFG_REQUEST
shapes were put in front of T-Mobile US, and all three were answered
`INTERNAL_ADDRESS_FAILURE`; a fourth run tried the IDr shape TS 24.302 actually
specifies and was refused before EAP even started. **The tunnel is still down.**
What did change is that the failure now has a name, a decoder and a control test
- see [the configuration payload](#the-configuration-payload-and-why-notify-36-is-not-an-authentication-failure).

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
| `internal/aka` | the bridge from `sim.AKAProvider` to the real USIM, over the edge daemon's AT lease socket |
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

**T041d measured that IDr and it is wrong for T-Mobile US.** Five distinct GSLB
nodes on 2026-08-24: every `IKE_AUTH` carrying an IDr came back
`AUTHENTICATION_FAILED` at message 1, and every one without got an EAP-AKA
Challenge. Two different, defensible values were tried - the card-derived FQDN
and the canonical name it resolves to - and both were refused, so this ePDG
objects to the payload being there rather than to what is in it. Note that its
*own* IDr is byte-for-byte the card-derived name, so this is not a naming
mismatch.

So `ike.LiveConfig.ResponderID` sends nothing when it is left zero, the probe's
`-idr` defaults to `none`, and `TestTheLiveDefaultSendsNoIDr` pins it.
`AuthRunner`'s own default is unchanged: it is the lower-level component with
its own contract, and `-idr card` / `-idr dns` still reproduce the table above.

This is the single most expensive thing T041d learned, because
`AUTHENTICATION_FAILED` reads exactly like "the operator does not accept this
SIM" and it was in fact "delete one payload".

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

### The configuration payload, and why notify 36 is not an authentication failure

This is T081. `INTERNAL_ADDRESS_FAILURE` (notify 36) arrives *after* EAP-Success,
on the message carrying `AUTH`. By then the operator has accepted the card, the
`RES` and our `AUTH` payload. RFC 7296 section 3.10.1 makes notify 36 a verdict
on one thing only: the `CFG_REQUEST` we sent in the first `IKE_AUTH` request.

The mirror's `ikev2.SWuConfigurationRequest()`
(`session_payloads.go:146-153`) asks for four attributes:

```
CFG_REQUEST { INTERNAL_IP4_ADDRESS, INTERNAL_IP4_DNS,
              INTERNAL_IP6_ADDRESS, INTERNAL_IP6_DNS }
```

There is no P-CSCF in it, and the mirror does not define the constants: the
attribute list in `session_payloads.go:26-34` stops at 15, while RFC 7651
allocated **20 = `P_CSCF_IP4_ADDRESS`** and **21 = `P_CSCF_IP6_ADDRESS`**.
Without one, a tunnel that came up would have nowhere to send `REGISTER`, so
criterion 4 needs them regardless of what notify 36 turns out to be about.

`internal/ike/config_payload.go` owns the request now. Shapes are **named**,
because each one costs an SQN step to measure and a receipt has to say which one
produced which answer:

| `-cfg` | attributes | TS |
| --- | --- | --- |
| `mirror` | the four above, byte for byte | IPv4 |
| `dual` **(default)** | those four **plus 20 and 21** | IPv4 |
| `ipv4` | `IP4_ADDRESS`, `IP4_DNS`, `P_CSCF_IP4` | IPv4 |
| `ipv6` | `IP6_ADDRESS`, `IP6_DNS`, `P_CSCF_IP6` | IPv6 |
| `ipv4-nopcscf` / `ipv6-nopcscf` | the family axis without the P-CSCF axis | matching |
| `none` | **no CP payload at all** - not an empty one | IPv4 |

The traffic selectors belong to the variant rather than being a separate knob:
asking for an IPv6 address over a tunnel whose `TSi` covers only `0.0.0.0/0`
describes a tunnel that cannot carry the address it just asked for. The mirror
has no IPv6 selector helper (`IPv4AnyTrafficSelectors` at
`session_payloads.go:224-232` is the whole of it), so `ike.IPv6AnyTrafficSelectors`
is written here and round-trips through the mirror's own codec in a test.

**What was measured, on 2026-08-24, against T-Mobile US:**

| `-cfg` | `-idr` | result | SQN |
| --- | --- | --- | --- |
| `mirror` | none | notify 36 (T072) | 1 |
| `dual` | none | **notify 36** | 1 |
| `ipv6` | none | **notify 36** | 1 |
| `dual` | `apn` | `AUTHENTICATION_FAILED` at message 1 | **0** |

So the missing P-CSCF was *not* what notify 36 was about, and neither was the
dual-family ask. Both are still the right thing to send; neither is sufficient.
`ipv4` is the one cell nobody has spent an SQN on. Full write-up, including what
is left to try and why each candidate is ranked where it is, in
`docs/goals/vodoge-vowifi-call/notes/T081-cfg-request.md`.

#### `-cfg none`: the shape that is not a guess

Every variant above is a guess about which attribute T-Mobile objected to, and
three of those guesses have now been refused identically. A fourth costs an SQN
step to learn a fourth "no". So `none` sends **no configuration payload at
all** - the payload is absent from the message, which is not the same message as
an empty `CFG_REQUEST`: RFC 7296 section 3.15 has the initiator ask to be
configured *by sending the payload*, so an empty one is still asking.

It is one axis from `dual`: same traffic selectors, same everything else, minus
the payload. Its three possible answers each eliminate a different two thirds of
what is left:

| answer | `LiveOutcome` | what it licenses next |
| --- | --- | --- |
| `FAILED_CP_REQUIRED` (37) | `configuration-required` | the ePDG **parses** the CP, so bisecting the attribute list is worth an SQN step |
| CHILD_SA | `tunnel-established` | the fault is **entirely** inside the attribute list |
| `INTERNAL_ADDRESS_FAILURE` (36) again | `internal-address-rejected` | notify 36 was **never about the CP**; the arrow moves to the subscription |

None of the three is criterion 4, including the second: an SA built on a request
that asked for no address has no address to source packets from and no P-CSCF to
send `REGISTER` to, so `LiveResult.TunnelIsUp` stays false in all three.
`ike.ErrFailedCPRequired` wraps the mirror's `ikev2.ErrNotifyFailedCPRequired`
the same way `ErrInternalAddressFailure` wraps its own, and the two are kept in
separate outcomes on purpose - they arrive at the same point in the ladder and
say opposite things.

**All three branches are proven offline before any of them is measured.** The
fake ePDG grew one knob, `requireCP`, and
`TestTheNoCPExperimentHasThreeDistinguishableAnswers` drives the *same*
production code past the *same* fixture three times, varying only how the
responder answers, and asserts the three land in three distinct named outcomes
with non-overlapping error classes. `TestTheFixtureAsksForACPOnlyWhenNoneWasSent`
is its negative control: the same `requireCP` responder must build a CHILD_SA
for a request that *does* carry a CP, so the notify-37 row is evidence about our
code rather than about a fixture that recites 37. The recording round-trips too
(`TestANoneVariantRecordingReplaysAsARequestWithNoCP`), because a request defined
by an absent payload is the easiest one for a replay to silently put back.

The live run is **not** in this deliverable. Write-up and the exact command in
`docs/goals/vodoge-vowifi-call/notes/T088-no-cp-probe.md`.

The fourth row is worth its own sentence. TS 24.302 section 7.2.2 says the SWu
`IDr` is not the ePDG's name, it is the **APN-FQDN** of the PDN to attach to
(TS 23.003 section 19.4.2.4,
`ims.apn.epc.mnc240.mcc310.pub.3gppnetwork.org`). That is a much better reason to
send an IDr than the one T041d tried, and T-Mobile refused it too - at message 1,
before any Challenge, so it cost nothing. Three defensible IDr values have now
been refused, which retires "T072 sent the wrong IDr shape" as an explanation.
`ike.LiveConfig.ResponderID` still defaults to sending none and
`TestTheLiveDefaultSendsNoIDr` still pins it; `-idr apn` is a diagnostic, like
`-idr card` and `-idr dns` before it.

The failure is named rather than described. `ike.ErrInternalAddressFailure`
wraps the mirror's `ikev2.ErrNotifyInternalAddressFailure` and carries the
request that was refused in its own text, and `ike.OutcomeAddressRejected` is a
distinct outcome from `challenge-answered` - it is strictly *later*, and it
points at a different file. The fake ePDG grew `requirePCSCF` and
`requireSingleFamily` knobs so that both candidate causes are enforced by some
responder rather than asserted by our own encoder, and the control pair
(`TestTheDefaultRequestSatisfiesAnEPDGThatWantsPCSCF` and
`TestTheMirrorRequestStillGetsNotify36`) runs the same responder against both
shapes.

`ConfigReply` decodes the other direction. An attribute whose value is the wrong
length for its type is an error, not a skipped field, because four octets read
as an address when the responder meant something else would put a wrong address
into a receipt that claims to be evidence. Attributes nobody has a constant for
are kept and printed as hex rather than dropped.

Finally, the variant name travels into the capture sidecar
(`capture.AuthSeed.ConfigVariant`). The `CFG_REQUEST` is inside the first
protected message, so changing it changes that message's ciphertext - and
without the name in the sidecar, the day the default moves is the day
`/root/t072/epdg-challenge.pcap`, the only recording of a real carrier accepting
this card, stops reproducing its own bytes with nothing to say why. An empty
value means the recording predates named variants, and the replay reads that as
`mirror`, which is what those runs sent.

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
needs its own serialisation on top; this wrapper only guarantees that the IKE
side stops waiting. T041c built that bridge and its own bound - see
[the card bridge](#the-card-bridge-internalaka), which is where the question
"what does the *next* challenge meet" is answered.

A timeout must not be mistaken for a card refusal:
`ErrAKADeadlineExceeded` is neither `sim.ErrSyncFailure` nor
`sim.ErrAuthFailure`, so eapaka does not manufacture an AT_AUTS out of a stall.
There is a test for exactly that.

### The card bridge: `internal/aka`

`aka.Provider` implements `sim.AKAProvider` by asking the edge daemon, over a
0600 unix socket under `/run` speaking one JSON object per line
(`edge-modem/src/at.rs:806-820`):

```json
{"op":"authenticate","imei":"867018069514820","rand":"<32 hex>","autn":"<32 hex>"}
```

**It builds no APDU and classifies no status word.** All of that already exists
on the Rust side and was measured on the bench by T047: the FCP tag-84 gate that
refuses to AUTHENTICATE against whatever else might be selected, the
basic-channel `00 88 00 81 22 10<RAND>10<AUTN> 00`, the 61xx/6Cxx recovery, and
the mapping from status word to outcome. Redoing any of it here would create a
second source of truth for the one thing on this path that cannot be settled by
reading code - what the card actually says - and only one of the two copies
would ever meet hardware.

The three outcome labels map onto the three shapes `sim` already has:

| daemon outcome | what this package returns |
| --- | --- |
| `success` | `sim.AKAResult{RES, CK, IK}`, no error (`kc` is dropped; EAP-AKA has no use for it) |
| `sync_failure` | `sim.NewSyncFailureError(auts)`, empty result, so eapaka's AUTS-carrier path builds the `AT_AUTS` |
| `authentication_failure` | `sim.NewMACFailureError()` wrapped with the raw status word, so eapaka builds the Authentication-Reject |
| `{"ok":false,...}` | `ErrLeaseRefused`, **never** either of the above |

That last row is the safety property. A broken pipe, a `6E00` from `STATUS`, an
unmapped status word: none of those is the card rejecting a challenge, and
`eapaka.BuildAKAFailureResponse` turns `sim.ErrAuthFailure` and
`sim.ErrSyncFailure` into MAC-correct packets. Forging either out of a transport
fault would put a message on the wire that the card never authorised, and the
network would believe it.

#### Only `authenticate`, never `execute_at`

The lease speaks two operations (`AtLease`, `edge-modem/src/at.rs:726-740`).
`execute_at` runs an arbitrary AT command, which is total control of the module -
USB re-enumeration, messaging, profile switching. This package sends
`authenticate` and nothing else, and that is asserted rather than asserted-in-a-
comment: `TestProviderOnlyEverSendsAuthenticate` reads back every request line
the package produced and fails on any other `op`, on the substring `execute_at`,
and on any field outside `{op, imei, rand, autn}`. `vodoge-ike-probe` has no flag
that could ask for anything else and must not grow one.

The transport is a unix socket on the box. It is never a TCP listener and never
crosses a machine boundary. The socket is mode 0600 and owned by root, so the
caller runs as root; a non-root caller gets `aka.ErrDial`, not a hang.

#### The hard deadline, and what the *next* challenge meets

`sim.AKAProvider.CalculateAKA` has no context and no cancellation, so the bound
has to be enforced from inside the bridge. `Provider.Timeout` (default 15s) is a
socket deadline over the whole call - slot, dial, write, read - and it is set
below `ike.DefaultAKATimeout` (20s) on purpose, so the error that reaches the IKE
state machine names the socket and the phase instead of the outer wrapper's
generic "something below me is slow". The outer bound stays as a backstop.

A bound is needed because the far side has none worth relying on: the Rust
arbiter's `acquire()` has no timeout at all (`at.rs:646-666`), the per-command
ceiling is `MAX_LEASE_TIMEOUT` = 300s, and a wedged holder is unbounded. T047
watched a real AKA challenge wait **41.5 seconds** behind a slow poll. The ePDG
gave up long before that.

**The abandoned exchange keeps running.** This is the part that leaves ghosts, so
it is spelled out:

1. **The port stays held.** The daemon is blocked in `acquire()` or in the
   AUTHENTICATE itself and cannot be told we left. The next challenge queues
   behind it and will also time out unless the holder finished meanwhile - which
   is the correct report, because the card genuinely is unavailable.
2. **Nothing is retried.** One call, one request line. A retry piles a second
   AUTHENTICATE onto a port that is already stuck, and an AUTHENTICATE the card
   *accepts* advances SQN - so a retry on a timeout can desynchronise the card
   against the network, and that surfaces much later as an AT_AUTS storm with
   nothing pointing back here.
3. **A late answer can never be read as somebody else's.** Every call gets its
   own connection. On a pooled connection, a request that timed out and a reply
   that landed a millisecond later would leave the stream one message out of
   step, and every subsequent challenge would be answered with the previous
   challenge's RES: a tunnel that comes up on the wrong keys and looks like a
   carrier problem.
4. **The daemon's connection budget cannot be exhausted from here.** An abandoned
   connection still occupies one of the daemon's `MAX_LEASE_CLIENTS` = 8 slots
   until its thread unblocks, and the console shares that budget. The abandoned
   connection is therefore handed to a reaper rather than closed blind: the
   reaper reads the late answer, reports it through `Observe`, and only then
   frees an in-flight slot. `MaxInFlight` (default 4) caps how many may be
   outstanding; past that, a challenge is refused immediately with `ErrBusy`
   rather than queued. After `Grace` (default 5m) the reaper gives up and closes
   anyway, so a permanently wedged holder costs a slot, not a goroutine.

`ErrTimeout` and `ErrBusy` are neither `sim.ErrSyncFailure` nor
`sim.ErrAuthFailure`, so a stall cannot be laundered into a card verdict. Tests
cover each of these; the deadline ones were checked by mutation (removing the
socket deadline hangs `TestProviderStopsWaitingAtItsDeadline`; mapping `ok:false`
onto `sim.NewMACFailureError` reddens `TestProviderNeverForgesACardRefusal`).

#### Bench forensics: `-aka-selftest`

```sh
# run as root: the lease socket is 0600
/root/vodoge-ike-probe -aka-selftest -aka-imei 867018069514820
/root/vodoge-ike-probe -aka-selftest -aka-imei 867018069514820 \
    -aka-rand 000102030405060708090A0B0C0D0E0F \
    -aka-autn 0000000000018000A1A2A3A4A5A6A7A8
```

It touches no network. It does touch the card: a challenge the card accepts
advances SQN, which is normal and expected by the network, but it is why this is
not a thing to run in a loop. RES is printed in full (it travels inside EAP
anyway); CK and IK are printed only as lengths, so a receipt built from this
output is safe to paste.

What T069 measured on `867018069514820` (WEBBING profile, EC20-CE), first hand:

| AUTN | shape | answer |
| --- | --- | --- |
| `101112131415161718191A1B1C1D1E1F` | T033/T047 synthetic, AMF separation bit clear | `9862` |
| `0000000000018000A1A2A3A4A5A6A7A8` | well formed, **AMF `8000`**, EPS separation bit set | `9862` |
| `0000000000010000A1A2A3A4A5A6A7A8` | well formed, AMF `0000`, UMTS AKA | `9862` |
| `FFFFFFFFFFFE8000A1A2A3A4A5A6A7A8` | SQN far in the future | `9862` |
| `000...000` / `FFF...FFF` | degenerate | `9862` |
| `0000000000018000A1A2A3A4A5A6A7A8` with a fresh RAND | same AUTN, different RAND | `9862` |

So on this card the refusal is always in the **status word**, never `9000` with
body tag `DD`; and the MAC is checked before the sequence number, because a
far-future SQN still answers `9862` rather than a `DC` resynchronisation. That
retires the open question T047 recorded - for the *refusal* half of it.

**What is still untested, and cannot be tested here:** a challenge whose MAC is
correct. K lives only in the card and in the operator's AuC, so no AUTN made on
this bench can verify. The `DB` success body and the `DC` synchronisation body
have therefore still never been seen from real hardware; the parsers for them are
covered by unit tests only. That is T041d's to close, against a real ePDG.

**T041d closed it.** On 2026-08-24 T-Mobile US produced a Challenge whose MAC
*was* correct, and this card answered it:

```
AT_RAND  00B4149F82C51FC005873EFF0B3EF595
AT_AUTN  E0F1271A6ACD00000369EEA305810731
RES      E225E8F895564EAD          (CK and IK 16 octets each, not printed)
```

`outcome success` from the daemon in 155 ms, and EAP-Success from the operator
in the next message. The `DB` success body has now been seen from real hardware;
the `DC` resynchronisation body still has not.

`867018069509705` (China Mobile, not an eUICC) answers `6E00` to the `STATUS`
that reads the FCP, so the gate refuses it with `status_refused` before any
AUTHENTICATE is sent - and the bridge reports that as "not a card verdict",
which is the behaviour that matters. Verified on hardware, unchanged from T047.

The deadline was verified on hardware too, three ways: against the real daemon
with a 5 ms bound (gave up at 5 ms, one request, and the reaper then collected
the abandoned exchange's real answer - `9862` at 28 ms - proving it had kept
running); with the very next challenge succeeding normally at 28 ms; and against
a socket that accepts and never answers, where six challenges at a 400 ms bound
produced four timeouts and two immediate `ErrBusy` refusals, with the stall
server confirming it had accepted exactly four connections.

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
algorithm selection and nothing more.

### `-auth`: the whole ladder, against the ePDG the card names

```sh
# as root: the AT lease socket is 0600
./vodoge-ike-probe -auth -aka-imei 867018069514820 \
    -capture /root/t072/epdg.pcap -record-secrets

# derive and resolve, send nothing
./vodoge-ike-probe -auth -aka-imei 867018069514820 -dry-run
```

**There is no flag for the operator.** `-auth` reads the card through the edge
daemon's `/api/status`, derives the ePDG FQDN and the IMPI from the IMSI and the
EF_AD-derived MNC length, and refuses `-target` outright. Criterion 2b rejects an
identity we chose, and the cheapest way to be able to say we did not choose one
is to have nowhere to put one. `-aka-imei` selects *hardware*; that IMEI never
goes on the wire and two tests assert it.

The name is resolved over DoH, not the system resolver, because the box answers
every name - random ones included - out of `198.18.0.0/16` (T036). An answer in
that range is `ErrFakeIPAnswer` rather than an address to dial.

`-idr` (`none` by default, see above), `-no-eap-only` and `-keepalive` vary the
three decisions that had no live evidence behind them. `-egress-candidates` feeds
the NAT-D reverse solve that reports which of this box's two UDP exits the
responder saw; on 2026-08-24 that was `34.174.243.156` (GCP, Dallas) on all three
solved exchanges, never the Beijing CGNAT.

A live run costs a real AUTHENTICATE on a real card, which advances SQN when the
card accepts it. `MaxLiveAuthCandidates` is 3 and it is a constant, not a
default: if three GSLB nodes will not answer `IKE_SA_INIT`, that is a network
result and a fourth attempt is impatience.

### Reading a rejection

The outcome is one of `udp-unreachable`, `ike-auth-no-reply`,
`ike-auth-rejected`, `card-refused-challenge`, `challenge-answered`,
`tunnel-established`. Keeping them apart is the whole job: the first is a fact
about the path that no payload edit can change, the middle two say our payloads
are wrong, and the last three are about the card and the operator. The probe
prints `LiveOutcome.Explain()` next to the verdict so a receipt cannot quietly
promote one into another.

## Tests

```sh
cd vowifi && GOWORK=off go test ./...
```

Everything runs on loopback against a fake ePDG; no hardware, no US line, no
carrier. **No test here is evidence for goal oracle criterion 2b** - that
evidence is a pcap taken against T-Mobile US, and it lives on the edge box with
the note that describes it. What the tests do is stop the measured facts from
being refactored away: `TestTheLiveDefaultSendsNoIDr` pins the IDr finding,
`TestThreeDigitMNCSurvivesTheWholeDerivation` pins the three digits that come off
the card, and `TestCardRefusalIsClassifiedAsClassThreeNotAsAFailedExchange` pins
the distinction the receipt is written in.

`TestFakeEPDGSeparatesEAPSuccessFromChildSA` (T041a) refuses the "EAP-Success and
the CHILD_SA arrive in one message" assumption by driving a plaintext ladder over
the real socket. `TestAuthRunnerWalksTheWholeLadder` and
`TestAuthRunnerRejectsEAPSuccessSharingTheChildSA` (T041b) do the stronger
version: the fixture is encrypted, and the second one makes the fake do the wrong
thing on purpose so the refusal is the runner's, not the fixture's.

`TestLadderRunsWithTheCardBehindTheLeaseSocket` and
`TestLeaseRefusalBecomesAnAuthenticationRejectOnTheWire` (T041c) run the whole
ladder with a fake lease daemon on a real unix socket as the only source of
RES/CK/IK, and assert on the responder's side. They are not a substitute for the
bench evidence in the T041 note; what they pin is the part the bench cannot show
cheaply - that the bridge is wire-compatible with the ladder, and that a `9862`
from the socket leaves as an Authentication-Reject rather than as a retry.

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
