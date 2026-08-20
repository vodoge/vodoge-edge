# VoDoge Edge

VoDoge Edge is the Rust agent that runs beside USB cellular modems at a customer site.

## Design principles

- Hardware interaction stays at the edge, close to USB modem and SIM resources.
- The agent continues to receive and store messages while the Internet is unavailable.
- Devices establish outbound WSS connections; customer sites need no inbound ports.
- Cloud transport uses mTLS and TLS 1.3 only, with no downgrade or TLS 0-RTT application data.
- Modem, carrier, and vertical differences are represented as declarative capabilities rather than scattered conditionals.

## Status

The project is in active foundational development. The first milestones establish the capability matrix, vertical policy model, and secure uplink contract.

See the repository history for independently reviewable implementation slices.
