# VoDoge Edge

The Rust agent that runs beside USB cellular modems on a customer site. It owns
hardware access, keeps working while the Internet is unavailable, and connects
outward to the [VoDoge Cloud](https://github.com/vodoge/vodoge-cloud) control
plane.

One binary, one SQLite directory. That is the whole deployment.

---

## What it does

Plug a few Quectel modems into a small Linux box and the agent will:

- **Find them itself.** Every few seconds it enumerates `cdc-wdm` and serial
  endpoints, probes identity over QMI, and falls back to AT for modules that do
  not speak QMI at all. Nothing is hard-coded to a device path, because device
  paths change every time USB re-enumerates.
- **Collect SMS and hold onto it.** Messages land in a local SQLite inbox first
  and go upstream second. An offline agent keeps collecting; a reconnected one
  drains what it gathered.
- **Refuse what it knows will not work.** A capability matrix records measured
  `(modem family, carrier)` facts. An unsupported pairing is refused by name
  rather than attempted and silently lost.
- **Serve a LAN panel.** `:8743` shows every module, its card and where it is
  registered, plots the last hour of which modules were answering, reads signal
  back on demand, and can send SMS, scan operators, switch eSIM profiles and run
  AT — with no cloud involved.
- **Answer the cloud.** Commands arrive over one outbound WSS connection and
  produce a receipt and a terminal result, exactly once each.

## Design

Eleven crates, one binary. The split is not decoration — `edge-core` is guarded
by CI that fails if its source so much as *names* `std::fs`, `std::net`,
`std::io` or `std::process`:

```
contract/       Protocol types, generated from the edge-cloud JSON Schema
edge-core/      Pure domain: capability matrix, strategies, settlement, policy
                ── no I/O, enforced by scripts/check-core-source.sh
edge-modem/     QMI/QMUX codecs, AT transport, eUICC (ES10c), discovery
edge-store/     SQLite: local inbox, uplink outbox, persisted matrix
edge-uplink/    Cumulative acknowledgement and gap state — pure
edge-agent/     Command execution: receipt, dispatch, terminal result
edge-panel/     Axum LAN panel and the in-process log ring
edge-panel-api/ The panel's HTTP types, shared by its two halves — no I/O,
                and must stay buildable for wasm32
edge-ui/        The panel's browser half: Leptos, built by trunk into
                edge-ui/dist/ and embedded into edge-panel
edge-proxy/     Per-modem proxy listeners
edge-bin/       The single binary that wires all of the above together

voice/          Go: IMS media relay (vodoge-voice)         ── AGPL-3.0
vowifi/         Go: IKEv2/EAP-AKA stack (vodoge-ike-probe) ── AGPL-3.0
```

Two rules earn their keep repeatedly:

**A pairing that has not been measured is not supported.** The matrix
distinguishes "measured and refused" from "nobody has ever tried", and only the
second is worth interrupting an operator about.

**Most of `edge-bin` is behind `#[cfg(target_os = "linux")]`.** A green
`cargo build` on macOS proves less than it looks like — several modules do not
compile there at all. Type-check and build releases on the target.

## Deploying

The procedure below is the real one, with hostnames replaced by placeholders.
It assumes a fresh Ubuntu install with the modems plugged in over USB.

### 1. Silence the competition

Ubuntu ships ModemManager enabled, and it will grab the serial ports out from
under the agent:

```sh
systemctl disable --now ModemManager
systemctl mask ModemManager
```

### 2. Toolchain

```sh
apt-get update
apt-get install -y build-essential pkg-config libssl-dev git curl sqlite3 cargo
```

Any Rust meeting the workspace MSRV will do; distribution packages are usually
new enough and avoid a rustup download.

### 3. Build

```sh
git clone https://github.com/vodoge/vodoge-edge /root/vodoge-edge-build
cd /root/vodoge-edge-build
cargo test --workspace
cargo build --release -p edge-bin
install -m 0755 target/release/vodoge-edge /usr/local/bin/vodoge-edge
```

### 4. Identity

The agent authenticates to the gateway with a client certificate. Three files
go in `/etc/vodoge-edge`:

| File | What it is |
| --- | --- |
| `ca.crt` | the device CA, used to verify the gateway's server certificate |
| `device.crt` | this device's client certificate |
| `device.key` | its private key, mode `600` |

Generate the key and CSR **on the edge machine** so the private key never
travels:

```sh
mkdir -p /etc/vodoge-edge && cd /etc/vodoge-edge
openssl ecparam -genkey -name prime256v1 -out device.key
chmod 600 device.key
openssl req -new -key device.key -out /tmp/device.csr \
    -subj "/CN=DEVICE_ID/O=TENANT_ID/OU=REGION"
```

Send `/tmp/device.csr` to whoever holds the device CA, and install what comes
back. Normally that is the cloud's enrollment endpoint, which mints a fresh
device; to reuse an existing device's identity, see
[Replacing the machine](#replacing-the-machine).

> **The private key must be PKCS#8.** `openssl ecparam -genkey` writes SEC1,
> which the agent's parser rejects — and the only symptom is
> `uplink: device key missing`, which reads like a missing file. Convert it:
>
> ```sh
> openssl pkcs8 -topk8 -nocrypt -in device.key -out k && mv k device.key
> chmod 600 device.key
> ```
>
> `head -1 device.key` should say `BEGIN PRIVATE KEY`, not `BEGIN EC PARAMETERS`.

### 5. Run it

```ini
# /etc/systemd/system/vodoge-edge.service
[Unit]
Description=VoDoge edge agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vodoge-edge
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
systemctl daemon-reload && systemctl enable --now vodoge-edge
journalctl -u vodoge-edge -f
```

A healthy start logs the panel address and its device id, then a `poll ... ok`
line per module every few seconds.

### Configuration

Every setting has a working default; set one only to override it.

| Variable | Default | Meaning |
| --- | --- | --- |
| `VODOGE_UPLINK_URL` | compiled in | `wss://HOST:PORT/v1/edge` |
| `VODOGE_EDGE_CERTS` | `/etc/vodoge-edge` | where the three files above live |
| `VODOGE_EDGE_DATA` | `/var/lib/vodoge-edge` | SQLite inbox and outbox |
| `VODOGE_EDGE_PANEL` | `0.0.0.0:8743` | LAN panel bind address |
| `VODOGE_PUBLIC_IP_URL` | a public echo service | how the host learns its egress IP |

### After enrolling: push the capability matrix

A fresh agent logs `no stored capability matrix; using the built-in one` and
falls back to compiled-in defaults. Publish the support ledger from the cloud
once, and the agent stores what it receives:

```sh
publish-ledger TENANT_ID
```

Restart and the log should say `capability matrix restored from store`. If it
still says "no stored capability matrix", the push did not land — and the agent
will keep making capability decisions from the built-in table without saying so
again.

### Replacing the machine

Rebuilt hardware keeps its identity only if two things come across.

**The certificate.** Enrollment always creates a *new* device, so re-enrolling
orphans the old one's history. To keep it, have the device CA sign a CSR
carrying the existing device's UUID:

```
CN = <existing device id>   O = <tenant id>   OU = <region>
```

with `keyUsage=digitalSignature`, `extendedKeyUsage=clientAuth`, ECDSA/SHA-256.

**The uplink sequence.** The cloud remembers how many envelopes it has received;
a rebuilt agent starts at 1, and the uplink stops rather than reuse spent
numbers:

```
uplink: ack cursor 119517 exceeds last allocated sequence 5
```

Take `N` from the cloud (`SELECT MAX(seq) FROM app.ingress WHERE device_id = …`),
stop the agent, and shift the queue above it:

```sql
UPDATE uplink_outbox SET seq = seq + N;
UPDATE uplink_cursor
   SET committed_through = N,
       last_allocated = (SELECT MAX(seq) FROM uplink_outbox)
 WHERE id = 1;
```

Shift rather than clear. Setting the cursor alone would mark anything already
queued — real messages the modems collected — as delivered, and drop it.

> The matrix and the cursor live in `inbox.db`, the queue in `outbox.db`, both
> under `VODOGE_EDGE_DATA`. Carry the whole directory if you can; if you cannot,
> the two steps above are the minimum.

## Upgrading a running agent

The section above installs onto a fresh box. This one replaces the binary under
a fleet that is already being managed — a different job, because the modems are
on USB/IP and **nobody can reach them physically**. Rolling back has to be a
thing you can do in one command at 3am, not something you reconstruct.

### 1. Build and check before touching anything

```sh
cd edge-ui && trunk build --release && cd ..   # panel bundle first: edge-panel embeds it
cargo test --workspace
cargo build --release -p edge-bin
```

⚠️ The `trunk build` has to come first. `edge-panel` pulls `edge-ui/dist/` in
with `include_bytes!`, so building in the other order silently ships whatever
bundle was lying around — or fails with a missing-file error that says nothing
about trunk.

Confirm the binary really contains the panel you just built, rather than a
stale one:

```sh
strings target/release/vodoge-edge | grep -c edge-ui_bg.wasm   # expect > 0
```

### 2. Keep the way back

```sh
cmp -s /usr/local/bin/vodoge-edge target/release/vodoge-edge \
  && echo "already deployed — keeping .prev as it is" \
  || cp -a /usr/local/bin/vodoge-edge /usr/local/bin/vodoge-edge.prev
sha256sum /usr/local/bin/vodoge-edge.prev target/release/vodoge-edge
```

Keep that output. `.prev` is the rollback, and the two hashes are how you tell
afterwards which one is actually running — size alone is not enough, and on
2026-08-29 a deploy on the cloud half went out with a matching size and corrupt
content.

⚠️ **The `cmp` guard is the point of that first line, not decoration.** A plain
`cp` here is only correct the first time. On 2026-09-04 this block ran twice in
a row: the second run copied the *newly installed* binary over `.prev`, so both
paths held the same bytes and the way back was gone — discovered only because
the rollback was needed. The guard makes a second run a no-op instead of a
silent loss. Rebuilding `.prev` afterwards means checking out the previous
commit and doing a full release build, which is the one thing you do not want
to be doing at the moment you reached for the rollback.

### 3. Swap and restart

```sh
install -m 0755 target/release/vodoge-edge /usr/local/bin/vodoge-edge
systemctl restart vodoge-edge
```

The service is `Restart=always` with `RestartSec=5`, so a binary that crashes on
start will loop rather than stop — which looks like "running" in
`systemctl is-active`. Check the log, not the unit state.

### 4. Prove it came back

```sh
systemctl status vodoge-edge --no-pager
journalctl -u vodoge-edge -n 30 --no-pager
curl -s localhost:8743/api/status | head -c 200      # modems still enumerated?
```

Give it a poll cycle (about ten seconds) and look for `poll /dev/... ok` lines
naming the IMEIs you expect. **The panel loading is not the test** — the panel
is a browser artefact, and the agent managing modems is the thing that matters.
`/api/status` answers even when the browser half is broken, which is exactly why
it stays a plain JSON endpoint.

### Rolling back

```sh
install -m 0755 /usr/local/bin/vodoge-edge.prev /usr/local/bin/vodoge-edge
systemctl restart vodoge-edge
```

**Downgrading does not corrupt the store, and cannot be made to.** `migrate()`
is forward-only: it walks `MIGRATIONS[user_version..]` upward and stops. Put an
older binary on a newer database and its loop simply does not run, because
`user_version` is already past the end of the migrations it knows about. The
one destructive path, `Store::rollback_to`, drops eleven tables — and it is
reachable from tests only. `main()` takes no arguments, there are no
subcommands, and `Store::open` calls `migrate()` and nothing else, so no
startup can reach it.

What downgrading *can* do is leave an old binary reading a schema built by a
newer one. That is fine for additive changes and is not something this
mechanism checks for you, so the honest rule is: **check whether the release
you are leaving touched `edge-store/` or `contract/`.**

```sh
git diff <old-tag>..<new-tag> --stat -- edge-store/ contract/   # empty = free rollback
```

For the panel rewrite specifically (`e22380d..763d3a3`, the Leptos migration),
that command is empty — those two crates were not touched at all, so rolling
back across it is unconditionally safe.

## Development

```sh
cargo test              # runs everywhere
cargo test --workspace  # on Linux, this is the one that counts
```

Guards CI enforces, all runnable locally:

```sh
sh scripts/check-core-deps.sh      # edge-core has no I/O dependency
sh scripts/check-core-source.sh    # edge-core names no I/O std module
sh scripts/verify-vendor-mirror.sh # the AGPL mirror is byte-identical

python3 contract/codegen/generate.py --check \
    --schema contract/schema/edge-cloud.v1.schema.json --rust contract/src/lib.rs
```

Contract types are **generated**. Editing `contract/src/lib.rs` by hand produces
a file no run can reproduce, and CI says so.

> The same schema exists in the cloud repository. It is the one file that will
> drift; change it in both in the same commit.

## Security baseline

Every edge-to-cloud connection is WSS with mTLS, TLS 1.3 only. The agent fails
closed for plain WebSocket, TLS 1.2 or older, invalid server certificates, and
downgrade retries. TLS 0-RTT application data is prohibited. The reasoning is in
`docs/adr/0001-uplink-tls.md`.

The LAN panel has no authentication and binds `0.0.0.0` by default. It can send
SMS and run AT commands. Put it on a trusted network or change
`VODOGE_EDGE_PANEL` to a loopback address.

## License, and where to get the source

This repository is not under one license. The complete map is in
[`LICENSE`](LICENSE); attribution is in [`NOTICE`](NOTICE).

| Path | License | Full text |
| --- | --- | --- |
| `contract/` `edge-core/` `edge-modem/` `edge-store/` `edge-uplink/` `edge-agent/` `edge-panel/` `edge-panel-api/` `edge-ui/` `edge-proxy/` `edge-bin/`, and the repository root | Apache-2.0 | `LICENSE`, section 6 |
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
> published at <https://github.com/vodoge/vodoge-edge>, and may be
> obtained by anyone, at no charge, over the network, without an account:
>
> ```sh
> git clone https://github.com/vodoge/vodoge-edge
> ```
>
> The upstream AGPL dependency compiled into these binaries is at
> <https://github.com/boa-z/vowifi-go>, commit `1e9c6e6a`.

This repository is public on purpose so that the offer above stays satisfiable.
A binary that serves network users must correspond to a commit that is actually
published there — do not run a private patch against them without pushing it.
