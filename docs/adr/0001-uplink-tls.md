# ADR 0001: Edge Uplink Uses TLS 1.3 Only

## Status

Accepted.

## Decision

The future edge-to-cloud uplink must use WSS over TLS 1.3 with mutual TLS
authentication. The edge presents its issued device certificate and validates
the cloud certificate chain and server name.

TLS 1.2 and earlier versions are not permitted. The transport configuration
must fail closed when TLS 1.3 cannot be negotiated; it must not retry with an
older protocol version or a plaintext WebSocket. TLS 1.3 early data (0-RTT) is
disabled because device registration, command acknowledgement, and telemetry
uploads are not universally replay-safe.

## Consequences

`edge-core` remains transport-free and therefore has no TLS dependency. The
uplink crate that is introduced later owns enforcement of this ADR and needs
tests proving that TLS 1.2, plaintext WS, and 0-RTT are rejected.
