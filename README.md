# VoDoge Edge

VoDoge Edge is the Rust agent that runs beside USB cellular modems in a
customer site. It owns hardware access, keeps working while the Internet is
unavailable, and connects outward to the VoDoge cloud control plane.

## License, and where to get the source

This repository is not under one license. The complete map is in
[`LICENSE`](LICENSE); attribution is in [`NOTICE`](NOTICE).

| Path | License | Full text |
| --- | --- | --- |
| `contract/` `edge-core/` `edge-modem/` `edge-store/` `edge-uplink/` `edge-agent/` `edge-panel/` `edge-proxy/` `edge-bin/`, and the repository root | Apache-2.0 | `LICENSE`, section 6 |
| `voice/` (binary `vodoge-voice`) | AGPL-3.0-or-later | `voice/LICENSE` |
| `vowifi/` (binary `vodoge-ike-probe`) | AGPL-3.0-or-later | `vowifi/LICENSE` |

The two Go modules are AGPL because both `require github.com/boa-z/vowifi-go`,
which is AGPL-3.0 with no linking exception, and roughly 39,900 lines of it are
compiled into those binaries. `LICENSE` section 4 records the five conditions
the Apache-2.0 half currently rests on, each written so it can be checked and
falsified rather than assumed — the first thing to re-read before wiring the
Rust agent to either Go binary.

Upstream is not vendored here. Both `go.mod` files `replace` it with a path to a
read-only mirror that lives outside this repository, pinned at commit
`1e9c6e6a`. `scripts/verify-vendor-mirror.sh` checks that mirror against the
upstream commit's blobs and prints how many of the 212 files match; run it
before trusting any statement that the mirror is unmodified. It also prints how
to materialise the mirror if you do not have it.

### If you are talking to one of these services over a network

`vodoge-voice` and `vodoge-ike-probe` are AGPL-3.0 programs, and they exist so
that people can place calls through them. AGPL-3.0 section 13 gives everyone who
interacts with them remotely over a network the right to receive the
Corresponding Source. Here is that offer. It is deliberate, not incidental:

> The complete Corresponding Source for the version you are talking to is
> published at <https://github.com/yuanshuai1122/vodoge-edge>, and may be
> obtained by anyone, at no charge, over the network, without an account:
>
> ```sh
> git clone https://github.com/yuanshuai1122/vodoge-edge
> ```
>
> The upstream AGPL dependency compiled into these binaries is at
> <https://github.com/boa-z/vowifi-go>, commit `1e9c6e6a`.

This repository is public on purpose so that the offer above stays satisfiable.
A binary that serves network users must correspond to a commit that is actually
published there — do not run a private patch against them without pushing it.

## Current scope

The first delivered slices are deliberately I/O-free so their behavior can be
reviewed before real hardware is attached:

- `edge-core` contains the `ModemFamily x CarrierProfile x Vertical` device
  context, declarative TOML capability matrix, vertical factory resolution,
  pure SMS bearer routing, and multi-source registration arbitration. `cn` and
  `intl` are built-in; `lab` is a fictional vertical that proves a new region
  is one factory file plus one registry line.
- `edge-modem` owns QMUX/QMI framing, CTL sync, client-ID allocation, a
  transport-agnostic session, DMS, NAS, WMS, and UIM codecs. WMS list entries
  keep the returned tag so mixed MO/MT rows can be filtered after the fact.
  UIM can open an ISD-R channel and read the EID. Linux builds include a
  `cdc-wdm` adapter; macOS tests use a fake transport.
- `edge-uplink` models the durable upstream journal: stable envelope IDs,
  cumulative acknowledgements, replay order, recovery hints, and audited gap
  acceptance. It intentionally does not open SQLite or WSS connections yet.
- `edge-agent` executes `CommandDeliver`: persist `cmd_id`, emit
  `CommandReceipt` (`accepted` / `duplicate`), run `SendSms` at most once
  through a `SendPort`, install a JSON `UpdateCapabilityMatrix` after sha256
  verification, and always sequence a terminal `CommandResult`.
- `edge-panel` is the offline LAN UI (Axum + embedded HTML) over the SQLite
  local inbox. It does not call the cloud.
- `contract` contains protocol types generated from the edge-cloud JSON Schema.

The matrix records real hardware facts such as EC20 plus China Telecom having
no usable SMS bearer. Unsupported combinations are rejected before a blind
send attempt.

## Where this actually runs

There is exactly **one** edge deployment today, and **one** cloud host. Nothing
else exists — no fleet, no staging tier, no second region.

| Role | Host | Notes |
| --- | --- | --- |
| Edge agent (this repo) | `192.168.6.83:2222` | Local VMware VM, EC20 modems attached |
| Cloud control plane | `43.108.53.126` | Gateway + console + PostgreSQL + Redis |
| Base domain | `vodoge.com` | |
| First tenant | `a.vodoge.com` | That tenant is us |

`region` appears in the device certificate and in `tenants`, but it is a field,
not a second site or a second database. Treat any doc that says "regional data
plane" as describing a possible future split, not current infrastructure.

## Security baseline

Every future edge-to-cloud connection is WSS with mTLS and TLS 1.3 only. The
agent must fail closed for plain WebSocket, TLS 1.2 or older, invalid server
certificates, and downgrade retries. TLS 0-RTT application data is prohibited.
The full decision is in `docs/adr/0001-uplink-tls.md`.

## Layout

```
contract/    Generated edge-cloud protocol types
edge-core/   Pure domain model, capability matrix, and policy factories
edge-modem/  QMI codecs, ModemPort, discovery, inbox collection
edge-store/  SQLite local store and uplink outbox
edge-uplink/ Pure cumulative acknowledgement and loss-marker state
edge-agent/  CommandExecutor: receipt, SendSms, capability-matrix install
edge-panel/  Offline Axum panel over the SQLite inbox
docs/        Architecture decisions

voice/       Go: IMS media relay (vodoge-voice)      -- AGPL-3.0, see LICENSE
vowifi/      Go: IKEv2/EAP-AKA stack (vodoge-ike-probe) -- AGPL-3.0, see LICENSE
```

## Picking up the work

The plan, the environment, and the traps live in the cloud repo:
`vodoge-cloud/docs/execution-plan.md`. Read it before changing anything here —
in particular the note that most of `edge-bin` sits behind
`#[cfg(target_os = "linux")]` and does not compile on a Mac at all, so a green
`cargo build` on the workstation proves less than it looks like. Type-check and
build releases on the edge machine.

## Development

Install a Rust toolchain compatible with the workspace's declared MSRV, then:

```sh
cargo test
```

Hardware transport, persistence, uplink, and the single-binary application are
added as separate, independently testable milestones.
