# VoDoge Edge

VoDoge Edge is the Rust agent that runs beside USB cellular modems in a
customer site. It owns hardware access, keeps working while the Internet is
unavailable, and connects outward to the VoDoge cloud control plane.

## Current scope

The first delivered slices are deliberately I/O-free so their behavior can be
reviewed before real hardware is attached:

- `edge-core` contains the `ModemFamily x CarrierProfile x Vertical` device
  context, declarative TOML capability matrix, vertical factory resolution,
  pure SMS bearer routing, and multi-source registration arbitration. `cn` and
  `intl` are built-in; `lab` is a fictional vertical that proves a new region
  is one factory file plus one registry line.
- `edge-modem` owns QMUX/QMI framing, CTL sync, client-ID allocation, a
  transport-agnostic session, DMS identity/operating-mode codecs, and NAS
  serving-system plus LTE cell-location codecs. Linux builds include a
  `cdc-wdm` adapter; macOS tests use a fake transport.
- `edge-uplink` models the durable upstream journal: stable envelope IDs,
  cumulative acknowledgements, replay order, recovery hints, and audited gap
  acceptance. It intentionally does not open SQLite or WSS connections yet.
- `contract` contains protocol types generated from the edge-cloud JSON Schema.

The matrix records real hardware facts such as EC20 plus China Telecom having
no usable SMS bearer. Unsupported combinations are rejected before a blind
send attempt.

## Security baseline

Every future edge-to-cloud connection is WSS with mTLS and TLS 1.3 only. The
agent must fail closed for plain WebSocket, TLS 1.2 or older, invalid server
certificates, and downgrade retries. TLS 0-RTT application data is prohibited.
The full decision is in `docs/adr/0001-uplink-tls.md`.

## Layout

```
contract/    Generated edge-cloud protocol types
edge-core/   Pure domain model, capability matrix, and policy factories
edge-modem/  QMUX/QMI framing, session, and DMS codecs
edge-uplink/ Pure cumulative acknowledgement and loss-marker state
docs/        Architecture decisions
```

## Development

Install a Rust toolchain compatible with the workspace's declared MSRV, then:

```sh
cargo test
```

Hardware transport, persistence, uplink, and the single-binary application are
added as separate, independently testable milestones.
