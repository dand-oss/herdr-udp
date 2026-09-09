# Resumable remote Herdr: SSH-bootstrapped QUIC behind the endpoint seam

Status: design for branch `feat/quic-endpoint`, based on `v0.9.0` (`b99002ac`).
Supersedes the 0.7.x-era design and the post-0.9.0 plan; the earlier
`feat/resumable-quic` branch is the source inventory (§9), not the target.

## 1. Summary

Herdr keeps OpenSSH for authentication, host verification, remote platform
detection, binary bootstrap, server start, and fallback. For the live client
protocol it prefers an SSH-bootstrapped, certificate-pinned QUIC connection that
carries the **unmodified framed `ClientMessage`/`ServerMessage` byte stream** —
exactly what the SSH stdio bridge carries today — and plugs in behind v0.9.0's
endpoint seam (`ConnectTarget` → `LocalStream` + lifetime) as an opaque,
resilient pipe. QUIC does not interpret render content and the server render
path is untouched.

User-visible contract:

> Start `herdr --remote fedora` or add the machine with `herdr machine add`.
> Change networks, ride through a 2-minute tunnel, or close the laptop, and
> return to the same server-owned session without re-authenticating. While the
> path is recovering the screen stays live and input keeps flowing; if the path
> is truly lost, the client reconnects over QUIC with a cached credential and
> receives a fresh complete state. If UDP is unavailable, the existing SSH bridge
> is used transparently.

Not Mosh prediction, not Eternal Terminal byte replay. Herdr already owns the
important primitive — authoritative server-side terminal state rendered into
complete client state (`ClientShellSnapshot` + `PaneSurfaceFrame`) — and v0.9.0
already has revision/baseline fencing and supervisor-driven resync. QUIC's job is
to make a lost connection rare (path migration, retransmission) and cheap when it
happens (no `ssh` re-exec, no auth round).

## 2. Requirements, in priority order

1. **No regressions outside remote.** Local Unix-socket clients, direct attach,
   plugins/APIs, server persistence, handoff, stock `--remote` over SSH, and
   render/layout performance are unchanged. Stock servers and clients never bind
   UDP, mint TLS material, or start reconnect tasks. Pane-scaled loops gain no
   work: the adapter is per-connection.
2. **Follow upstream's boundaries.** Runtime/session facts live in the server and
   are exposed through negotiated capabilities; presentation state lives in the
   client. QUIC sits entirely behind `EndpointTransport`/`ConnectTarget` and one
   capability string. Never touch `headless/*` render, `client_transport.rs`
   writer internals, or `retained_surface.rs`.
3. **Roam and tunnel.** IP change, NAT rebind, ≥120 s blackholes, and laptop sleep
   recover without re-authentication, without terminating pane processes, and
   without freezing input before the connection is presumed dead.
4. **Perform on lossy links.** Random radio loss must not collapse throughput
   (BBR), control must not be starved by bulk output, and stale output must not
   accumulate unboundedly.
5. **Network health is never pane-process health.** A sleeping client or blocked
   transport must not backpressure a remote application. Upstream's one-slot
   render queue and PTY/render separation already guarantee this for the Unix
   socket; the QUIC adapter presents itself as an ordinary Unix client so the
   same guarantee holds.

## 3. Decisions

| Area | Decision |
| --- | --- |
| Integration depth | Opaque framed-byte pipe. No QUIC-specific render generations, sync requests, resource caches, or status wire messages. Recovery after a truly lost connection is upstream's: drop the client connection, supervisor re-handshakes, fresh snapshot + full surface. |
| Server placement | In-process `RemoteQuicServer` inside the server. Authenticated QUIC connections are adapted via a Unix socketpair into the existing client accept path. One userspace copy per frame; no sidecar daemon. |
| Client placement | A bridge task owned by `connect_saved_ssh` (saved machines, noninteractive) and `run_remote` (standalone, interactive). Both return `{ stream: LocalStream, lifetime }` to their existing callers. The thin client is unaware of QUIC except for a local-only status hint. |
| Liveness signal | Upstream's `endpoint.health.ping.v1`/`pong.v1` flow end-to-end through QUIC unmodified. The bridge additionally originates its own health pings on `PathMonitor`'s schedule (1 s fast-probe, not the client's 5 s cadence) and counts *any* QUIC→client frame as liveness, exactly as upstream's `EndpointHealth` does. No frame decoding, no dedupe against client pings (duplicates are a few bytes), no `RemotePing/RemotePong` wire variants. |
| Recovering-path grace | The bridge injects a local-only `ServerMessage::EndpointControl { kind: "endpoint.transport.status.v1" }` toward the thin client when the QUIC path enters/leaves `recovering`. While recovering, the client's heartbeat deadline is 150 s instead of 10 s and the endpoint shows Roaming rather than Reconnecting; input keeps flowing on the reliable control stream. The hint never crosses the server API. SSH endpoints are unchanged. |
| After grace / lost | One close policy: the bridge closes the QUIC connection and the local socket. The thin client's supervisor reconnects to the same local socket; the bridge's next accepted connection reuses the process-wide cached credential and dials QUIC directly — no SSH. Supervisor backoff stays upstream's 0.5→30 s. Standalone `--remote` gets the same behavior by supervising its forwarded Local endpoint (today Local is supervised only when a saved machine is enabled). |
| Transport ladder | Sequential, per accepted local connection: cached credential or SSH bootstrap → QUIC dial (2 s) → on rejection one re-bootstrap → SSH stdio fallback. One-way: once on SSH, stay for that connection. No QUIC-vs-SSH race: a host that blackholes UDP costs one 2 s timeout per connection; if measurement shows that matters, add a per-target negative cache, not a race. |
| Auth bootstrap | Normal OpenSSH. Hidden `herdr [--session S] remote-quic-bootstrap <client-id>` runs on the remote host, talks to the running server over its protected Unix socket, and prints a versioned record `{ schema version, server instance id, UDP port, certificate SHA-256 fingerprint, capability token, expiry }`. The client resolves the `ssh -G` hostname to candidate addresses itself. Never log the token. |
| TLS identity | Per-server-process self-signed certificate (rcgen), key in memory only. Client pins the fingerprint delivered over SSH. ALPN `herdr/1`. No 0-RTT; no mutating data as early data. |
| Client authorization | 32-byte capability token scoped to Unix user, session, server instance, logical client id. Server stores SHA-256 only, bounded table, fenced per connection generation. Presented only inside the pinned TLS connection as the first frame (`RemoteQuicHello`). |
| Credential lifetime | Token/idle lifetime default 24 h, configurable. Not persisted across a cold restart. Transferred across live handoff. |
| Handoff | `perform_live_handoff` exports/imports cert, key, instance id, tokens, and UDP fds so QUIC clients re-dial the successor with their token and no SSH. `HandoffManifest.remote_quic` is optional; absent on stock servers. |
| Server detection | Bootstrap-only: the bridge runs `remote-quic-bootstrap` over SSH; a stock server (unknown subcommand) or a server with `remote.transport = ssh` fails it, and the bridge stays on SSH for that connection. No capability string in `endpoint.welcome.v1`, no `herdr status` field: the bridge decides before any welcome exists, and one failed SSH round per process per target is cheaper than plumbing a flag through every status path. Bootstrap record and `RemoteQuicHello` carry their own `REMOTE_QUIC_SCHEMA_VERSION`, never `PROTOCOL_VERSION`. |
| Congestion control | quinn with BBR on both sides. No runtime knob. A compile-time Cubic swap exists only if it stays under 20 LOC. |
| Streams | One bidirectional stream per connection carrying the framed protocol in both directions. QUIC provides reliability, ordering, retransmission, migration. No stream-per-message, no application TCP analogue. |
| Input semantics | Input flows while the connection is alive, regardless of render staleness. Frozen only once the client is Reconnecting. No replay across a destroyed connection: a final pre-loss key may be lost, never duplicated. |
| Multi-client | A fresh QUIC connection is an ordinary new client connection; upstream's foreground/projection semantics apply unchanged. Older connection generations for the same token are fenced. |
| Config | `[remote] transport = "auto" \| "ssh"`, `quic_port_range`, `quic_idle_timeout_seconds` (credential lifetime, 24 h), `quic_transport_idle_timeout_seconds` (180 s default: must exceed the 150 s roaming grace or the server drops a tunnel-length blackhole before the client would). `auto` = QUIC then SSH. No `quic`-only mode, no `ssh_fallback` toggle, no grace knob. `endpoints.json` schema unchanged (`deny_unknown_fields`). |
| Platform | Unix clients; Linux/macOS remotes. Windows client remains SSH-only; quinn deps are Unix-gated. |
| Upstream engagement | Fork feature, no PR. Fork clients work against stock servers (bootstrap fails → SSH) and stock clients never send a bootstrap request. |

## 4. Goals and non-goals

Goals: recover from blackholes, NAT rebinding, IP change, and sleep without
re-auth or pane interruption; keep SSH keys/aliases/agent/bootstrap unchanged;
prefer QUIC when reachable with zero-surprise SSH fallback; keep input alive
during path recovery; bound every queue; prove recovered display equals a
perfect-connectivity session at the same server state.

Non-goals: predictive local echo; byte or frame replay; surviving server-process
death; exactly-once input across a destroyed connection; public-CA/ACME or a
Herdr network service; privileged host-wide gateway; 0-RTT; mixing local and
remote panes in one session; replacing SSH auth or forwarding SSH over QUIC;
per-machine transport preference in the saved-machine catalog.

## 5. Architecture

### 5.1 Topology

```
local machine                                                        remote machine
┌──────────────────────────────────────────────────────────┐
│ herdr client (upstream shell/UI, untouched)              │
│   EndpointSupervisors.connect_once(ConnectTarget)        │
│     Local        ── unix sock ─► local server            │
│     Ssh(profile) ── unix sock ─► QuicBridge  ┐           │
│                                              │           │        herdr server daemon
│      ladder: credential → QUIC dial →         │           │          ├─ herdr-client.sock ◄── remote-client-bridge (ssh, unchanged)
│              rebootstrap once → SSH fallback │           │          │
│      ┌── ssh -T … remote-quic-bootstrap ─────┼───────────┼─────────►│  bootstrap only → record{instance,port,fp,token}
│      └── QUIC bi-stream (pinned fp, token) ──┼───────────┼─────────►└─ RemoteQuicServer: accept → verify hello → socketpair
│                                                                         → existing client acceptor (same as a unix client)
└──────────────────────────────────────────────────────────┘
```

Standalone `herdr --remote <target>` uses the same bridge; its local socket is
the client's Local endpoint.

### 5.2 Bootstrap sequence

```
client                          ssh -T target                     remote herdr server
  │ prepare_remote_herdr (locate/install/start, as today)           │
  │ Welcome.capabilities ∋ remote_quic?  ──no──► SSH bridge only     │
  │ ── remote-quic-bootstrap <client-id> ────► ClientMessage::RemoteBootstrap
  │ ◄── RemoteBootstrapRecord ─────────────── ServerMessage::RemoteBootstrap
  │   (lazily starts RemoteQuicServer: bind UDP from range, mint identity)
  │ QUIC dial: IPv6-first happy-eyeballs on `ssh -G` hostname, ALPN herdr/1, pinned fp
  │ first frame: RemoteQuicHello{schema, instance, client id, token}
  │ ◄── accepted → socketpair → normal Hello/Welcome over the stream
```

The server binds UDP and creates TLS material only on the first bootstrap
request; a server that never sees one is byte-identical in behavior to stock.

### 5.3 Client bridge

One ladder run per accepted local connection:

- Obtains a credential (process-wide cache keyed by target+session, else SSH
  `remote-quic-bootstrap`), dials QUIC, sends `RemoteQuicHello`, waits for
  `RemoteQuicAccepted`. Bootstrap failure → SSH stdio fallback for this
  connection (the ssh child is the one `SshStdioBridge` spawns today). A dial
  timeout falls back to SSH only while the credential is unproven (UDP filtered
  from the start). Once a credential has carried a live session, a timeout is
  read as an outage: the bridge TCP-probes the SSH port (3 s); nothing answering
  closes the local socket so the supervisor paces a QUIC-first retry, an
  answering port earns QUIC exactly one more dial before SSH carries the
  connection. Without this rule a client whose outage ended during the patient
  SSH rung stayed on SSH, roaming lost, until its next reconnect.
- Copies frames between the local Unix socket and the QUIC bidirectional stream,
  frame-aligned (`[u32 LE len][payload]`) so it can inject its own frames, with
  bounded buffers and backpressure in both directions. Payloads are opaque.
- Owns `PathMonitor`: fast-probe after 1 s of silence, recovering after 2 s + 2
  unanswered probes, `Endpoint::rebind()` every 10 s of silence (sleep → tether →
  wifi must not strand on the second-to-last address), lost at 150 s. Probes are
  ordinary `endpoint.health.ping.v1` frames; any received frame is liveness.
- Emits `endpoint.transport.status.v1 { state: live | recovering }` to the
  thin client on transitions. Never forwards it upstream.
- Lost, superseded, or server-closed → close the local socket. The supervisor's
  next connection reuses the cached credential with `connection_generation + 1`
  and skips SSH entirely. Connect-time `Retry` failures get a bounded budget
  (5 attempts, 250 ms → 4 s) before SSH fallback; `Rebootstrap` drops the cached
  credential and re-runs SSH bootstrap once.

### 5.4 Server adapter

`RemoteQuicServer` (lazy, one per server process): quinn endpoint on a port from
`quic_port_range`, `ServerIdentity`, token table, 32-connection pre-auth
admission semaphore. Per accepted connection: read `RemoteQuicHello`, validate
token/instance/schema, fence older generations of the same token, create a
`UnixStream::pair()`, hand one end to the existing client acceptor path, and
copy bytes between the other end and the QUIC stream. Close codes follow
`quic_policy` (0x100–0x106, add-only). Handoff exports identity, tokens, and UDP
fds; the successor imports them before accepting.

### 5.5 Client health integration

`registry.rs` gains awareness of `endpoint.transport.status.v1` from its local
transport: `EndpointHealth` takes a `recovering: bool`; `action()` uses 150 s
when set, 10 s otherwise. The endpoint status enum gains `Roaming` (presentation
only, client-side). Standalone `--remote` marks its forwarded Local endpoint as
supervised (today only federated clients supervise Local) so a bridge-closed
socket reconnects instead of exiting the client. No server change.

### 5.6 Congestion control

BBR (`quinn::congestion::BbrConfig`) on both endpoints, already wired. Cubic is
loss-based and treats random radio loss as congestion; BBR paces to measured
bottleneck bandwidth. quinn documents BBR as experimental; the benchmark harness
(§8) records the numbers, but no runtime switch is exposed.

## 6. Integration seams in v0.9.0

| File | Change |
| --- | --- |
| `src/client/endpoint/supervisor.rs::connect_once` | `ConnectTarget::Ssh` arm unchanged; `connect_saved_ssh` internally runs the ladder and still returns `{ stream, bridge }`. |
| `src/remote/saved.rs::connect_saved_ssh` | Replace `SshStdioBridge::start` with the ladder-driven bridge (noninteractive: never prompts; QUIC failure is silent). |
| `src/remote/attach.rs::run_remote` | Same replacement (interactive); `run_client_process` unchanged. Add `remote-quic-bootstrap` subcommand + `request_remote_quic_bootstrap` + candidate resolution. |
| `src/main.rs` | Hidden `remote-quic-bootstrap` dispatch next to `remote-client-bridge`. |
| `src/protocol/endpoint.rs` | `TRANSPORT_STATUS_KIND = "endpoint.transport.status.v1"` (client-local). |
| `src/protocol/wire.rs` | `ClientMessage::RemoteBootstrap(RemoteBootstrapRequest)`, `ServerMessage::RemoteBootstrap(RemoteBootstrapRecord)`, `RemoteQuicHello`, `REMOTE_QUIC_SCHEMA_VERSION`. Bump `PROTOCOL_VERSION` per the published-protocol rule. |
| `src/server/headless/bootstrap.rs` (or `headless.rs`) | Hold `Option<RemoteQuicServer>`; lazy start on `ServerEvent::RemoteBootstrap`; accepted socketpairs enter the existing acceptor. |
| `src/server/handoff.rs`, `headless/lifecycle.rs` | Optional `remote_quic` manifest field; export/import around `perform_live_handoff`. |
| `src/client/endpoint/{health,registry,control}.rs`, endpoint status UI | Recovering-aware deadline, `Roaming` status, parse of the local hint. |
| `src/config/model.rs`, docs config reference | `[remote]` keys above. |
| `Cargo.toml` | quinn, rustls, rcgen, tokio net features — Unix-gated. |
| New: `src/remote/quic.rs`, `src/remote/quic_bridge.rs`, `src/remote/quic_policy.rs`, `src/remote/frame.rs`, `src/server/remote_quic.rs` | Cherry-picked and trimmed per §9. |

## 7. Wire and protocol changes

- Bootstrap request/record and `RemoteQuicHello` are bincode messages inside the
  existing framing. Their compatibility is `REMOTE_QUIC_SCHEMA_VERSION`,
  independent of client/server build versions (which may differ post-0.9.0).
- `endpoint.transport.status.v1` is client-local. The server never emits or
  receives it.
- No render, sync, status, URL, or resource messages are added.

## 8. Verification

### 8.1 Compatibility gate

- Stock v0.9.0 client ↔ fork server: identical behavior; no bootstrap ever requested.
- Fork client ↔ stock server: bootstrap fails, SSH path only, no UDP dial.
- Fork server without any `--remote` client: no UDP socket, no TLS material.
- `transport = "ssh"`: byte-for-byte today's SSH bridge behavior.
- `just check` green; `just bench-render-scale` unchanged.

### 8.2 Unit and in-process tests

Fingerprint pin success/failure; wrong/expired/cross-session/cross-instance
tokens; admission semaphore; generation fencing; no token in logs; accepted QUIC
connection is an ordinary client to the acceptor (one test through the real
acceptor); ladder step transitions (dial timeout → SSH, rejection → rebootstrap
once → SSH, superseded → close); `PathMonitor` schedule and rebind cadence;
frame-aligned pump preserves frames and injects a well-formed status frame;
credential cache expiry and generation increment; health deadline 150 s while
recovering, 10 s otherwise; handoff continuity (`tests/live_handoff.rs`: successor
keeps instance/port/fingerprint/tokens).

### 8.3 Real-surface scenarios

Run 2026-09-08 on `feat/quic-endpoint` debug builds: thin client
`herdr --remote quicrepro --session quicrepro` in a pane of the maintainer's
session, "remote" = a second local user reached over `ssh 127.0.0.1`
(`AllowUsers herdr-quic@127.0.0.1`), server QUIC on UDP 48001. Outages via an
`nft` output chain on `lo` (UDP 48001 both ways; "full" also TCP 22), address
change by dropping the client's current UDP source port, sleep by
`SIGSTOP`/`fg` of the launcher and client. Input was typed through the outer
pane and verified in the remote pane through the remote CLI.

| Scenario | Expected | Observed |
| --- | --- | --- |
| 3 s UDP blackhole | no visible event | no log line, no status change; keystrokes typed during the hole delivered |
| Interface flap (old address dead) | recovers within one rebind interval, no re-handshake | recovering at +2.4 s, rebind at +10.4 s, live 2 ms later on a new source port; same connection generation; input flows |
| 30 s blackhole | roaming, input delivered on recovery, no reconnect | recovering at +4 s, live 107 ms after the hole lifted; keystroke typed at +10 s delivered; no reconnect, no toast |
| 120 s blackhole | same as 30 s | recovering at +7 s, live 1.9 s after lift (slow-probe window); keystroke typed at +60 s delivered; no reconnect |
| 200 s full outage (UDP + SSH) | reconnecting at 150 s, QUIC re-dial with cached token, zero SSH | lost at +149 s; "Local · reconnecting"; paced retries every 5–13 s (dial 2 s + probe 3 s + supervisor backoff); QUIC connected 9.7 s after restore with the cached token, generation 7, zero SSH sessions; keystroke typed at +100 s lost (in flight when the connection was abandoned) |
| Sleep 10 min | reattached with cached token, zero SSH | server idle-timed the connection at 180 s; on wake the bridge saw the dead stream, closed local, QUIC reconnected in 866 ms with the cached token; zero SSH; "connection lost" modal cleared on reconnect |
| Server live handoff | QUIC clients re-dial successor without SSH | successor adopted the UDP sockets (`capabilities=7`); client closed by peer (code 260), re-dialed in 1.08 s, zero SSH, panes preserved. A handoff that failed to spawn (deleted exe) also rolled back cleanly: client re-dialed the old server in 1.07 s |
| UDP blocked from start | SSH fallback after one 2 s dial | first prompt 3.0 s after launch: bootstrap, 2 s dial timeout, SSH stdio bridge |
| Screen equivalence | client equals a perfect-connectivity view | after the sleep reconnect every non-empty line of the remote pane (33) appeared verbatim in the thin client's pane region |

Reference: first prompt 0.76 s after launch on QUIC (warm SSH control master,
loopback). Standalone `--remote` has no endpoint row, so roaming is not visible
there; saved machines show it in the sidebar.

### 8.4 Benchmark

`src/remote/benchmark.rs` (`#[ignore]`d test `remote_quic_3g_benchmark`) drives a
real in-process `HeadlessServer` and a semantic client (`TerminalHello` →
`AttachTerminal` → `Input`/`Terminal` frames) through the real `QuicBridge` and a
userspace UDP relay with the 3G profile (1.6/0.75 Mbit, 260–340 ms RTT, 1-in-101
deterministic loss) and blackout windows. Markers are one letter repeated five
times so a coalesced diff still changes every cell; the 250 ms gap is measured
from the echo. `HERDR_BENCH_KEYSTROKES` (default 60), `HERDR_BENCH_REPORT` (JSON).

```
cargo test --bin herdr -- --ignored --nocapture remote_quic_3g_benchmark
```

Run 2026-09-08, debug build, loopback; bytes are `Terminal` frame payloads:

| arm | p50 ms | p95 ms | p99 ms | fps | bytes/frame | lost | wall s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| direct (Unix socket) | 5.1 | 9.8 | 12.9 | 7.80 | 78.0 | 0 | 15.4 |
| quic_online | 8.2 | 22.5 | 27.0 | 7.80 | 77.6 | 0 | 15.6 |
| quic_3g | 311.1 | 962.9 | 1015.1 | 3.21 | 78.0 | 0 | 37.0 |
| quic_3g_blackout | 308.8 | 341.5 | 974.0 | 2.01 | 77.8 | 0 | 61.7 |

| blackout window | recovery ms | mid-blackout keystroke echoed |
| --- | --- | --- |
| 5 s | 651 | yes |
| 20 s | 694 | yes |

The QUIC pipe adds ~3 ms p50 over the Unix socket unshaped and nothing beyond
one RTT on 3G; the 3G p95/p99 are the deterministic loss events costing a
retransmit round. fps in the blackout arm is diluted by the 25 s of outage
inside its wall time.

### 8.5 Address-change scenario (plan item 1)

`src/remote/benchmark.rs` (`#[ignore]`d test `remote_quic_address_change_scenario`,
needs root) runs the in-process `HeadlessServer` inside a network namespace
on `10.253.1.2` and the real `QuicBridge` in the root namespace, joined by a
veth pair. Each flap deletes the root end's address (the server becomes
unreachable and the kernel's source choice for it falls back to the host's
default route), types a marker into the dead second, and 1 s later raises a
different address with a route preferring it as source. Recovery is measured
from the new address being raised to the first server frame; the marker's
echo is measured from the same instant. `address_change_port_dead` first
blackholes every namespace reply to the client's current UDP port (`ip rule
... dport N blackhole`), which is §8.3's flap model — the old tuple is dead —
and the NAT-mapping loss it stands for. Four flaps per variant, eight ordinary
keystrokes before and after each; three runs per build.

Run 2026-09-09, debug builds, `FLAP_GAP` 1 s, budget 1 s; recovery in ms
over 12 flaps per cell:

| build | variant | recovery min | median | max | budget | keys p50 / p95 ms |
| --- | --- | --- | --- | --- | --- | --- |
| `6f62d3c6` (10 s silence timer only) | address_change | 57.0 | 336.5 | 454.0 | 12/12 | 11.5 / 19.7 |
| `6f62d3c6` | address_change_port_dead | 13779.6 | 13790.8 | 13814.7 | 0/12 | 11.6 / 18.8 |
| rebind on evidence (plan item 1) | address_change | 11.2 | 13.1 | 21.5 | 12/12 | 11.6 / 17.4 |
| rebind on evidence | address_change_port_dead | 11.2 | 14.1 | 19.4 | 12/12 | 11.3 / 21.1 |

Zero lost keystrokes in every cell; the marker typed into the dead second was
echoed within 0.1 ms of recovery every time. The baseline's address-only
recovery is quinn's PTO on the packets sent while the address was dead — a
wildcard socket follows the route change by itself — and its port-dead
recovery is `REBIND_AFTER` counted from the oldest unanswered probe. With the
watcher, `HERDR_LOG=herdr=info` shows two rebinds per flap: one when the
source falls back to the default route, one when the new address appears.

## 9. Source inventory from `feat/resumable-quic`

Cherry-pick files, not commits (commits interleave core and integration).

| Keep (re-home) | Delete |
| --- | --- |
| `remote/quic.rs`: `PathMonitor`, `FingerprintVerifier`, `QuicSession::connect`, candidate dialing, `rebind_endpoint`, TLS/ALPN/BBR config | `remote/quic.rs`: render-record gap validation, `reconstruct_frame`, `ResourceCache`, resize/terminal-mode deferral, `SyncRequest` emission |
| `server/remote_quic.rs`: `ServerIdentity`, token table + `validate_capability` + fencing, admission semaphore, listener start/stop, `export_handoff`/`import_handoff` | `server/remote_quic.rs`: `QuicControlSender`, `BoundedControlQueue`, `QuicRenderSender`, Kitty splitting, `publish_server_output`, direct `ServerEvent::ClientConnected` construction |
| `remote/proxy.rs` → `quic_bridge.rs`: listener shape, reconnect budget, SSH bootstrap helpers, ssh child reaping | `remote/proxy.rs`: QUIC/SSH race, input router, hello replay, SSH reconnect loop, transport status fan-out, `ClientDetached` handling |
| `remote/quic_policy.rs`, `remote/frame.rs` unchanged | `wire.rs`: `RemoteQuicStreamHeader`, `RemoteQuicResourceRef`, `RemoteQuicRenderRecord`, `RemoteTransportStatus`, `RemotePing/Pong`, `ServerMessage::{TransportStatus, ClientDetached, OpenUrl}`, `ClientMessage::SyncRequest` |
| `remote/attach.rs`: `remote-quic-bootstrap`, `request_remote_quic_bootstrap`, candidate resolution | all edits to `headless.rs`, `client_transport.rs`, `render_stream.rs`, `clients.rs`, `client/mod.rs`, `app/input/*`, `ui/scrollbar.rs` (upstream has the fixes or the feature) |
| `wire.rs`: `RemoteBootstrapRequest/Record`, `RemoteQuicHello` (drop `launch_mode`, add schema version) | `config`: `transport = quic`, `ssh_fallback` |
| `config/model.rs` `[remote]` keys listed in §3; config reference docs | Benchmark arms driving `ClientWriter`/`TerminalFrame` (rework per §8.4) |
| `tests/live_handoff.rs` QUIC authority assertions | |

## 10. Rollout

1. **Scaffold.** Cherry-pick kept modules, Cargo deps (Unix-gated), config keys.
   Compile with render-lane code removed. No integration.
2. **Server adapter.** Accept → hello/token → socketpair → acceptor. Lazy start on
   `ServerEvent::RemoteBootstrap`. Tests in §8.2.
3. **Client bridge.** `QuicBridge` listener wired into `connect_saved_ssh` and
   `run_remote` in place of `SshStdioBridge`; bridge-originated probes; local
   status hint.
4. **Client grace.** Recovering-aware `EndpointHealth`, `Roaming` status,
   supervised Local endpoint for standalone `--remote`.
5. **Handoff.** Manifest field, export/import, re-enable live_handoff assertions.
6. **Real-surface verification** (§8.3) via `herdr-throwaway-repro`.
7. **Benchmark rework** (§8.4); record numbers here.
8. **Docs.** `docs/next/.../persistence-remote.mdx` and `connecting-machines.mdx`
   transport paragraphs; config reference.

## 11. Risks

- **Supervisor backoff cap.** After the 150 s grace, a saved-machine reconnect
  can wait up to 30 s in upstream's backoff even though a QUIC re-dial is cheap.
  Measure; a transport-aware cap is a small follow-up in `supervisor.rs`.
- **Herdr Cloud.** If Cloud's agent is a machine-out tunnel that also serves
  SSH-reachable hosts, direct-path QUIC narrows to users who refuse an account.
  The footprint is small enough that abandonment is cheap; the bootstrap record
  shape is broker-friendly by construction.
- **Standalone `--remote` supervision.** Supervising the Local endpoint when
  launched by `--remote` is a client-side behavior change in `client/mod.rs`
  (`federated` gate). It must not alter plain local `herdr` behavior; gate it on
  the `--remote` launch, not on catalog state.
- **Version skew is normal.** Bootstrap record and hello have their own schema
  version. Never compare `PROTOCOL_VERSION` for QUIC negotiation.
- **Firewalls / ProxyJump / Tailscale.** QUIC dials the `ssh -G` resolved host;
  unreachable UDP falls back one-way to SSH. Tailnet users get QUIC over the
  tailnet IP when UDP is allowed — document it.
- **Upstream churn.** ~6 upstream files touched lightly; expect trivial conflicts
  per release.
- **BBR is quinn-experimental.** Benchmark numbers must come from the reworked
  harness before being cited.

## Appendix: branch mechanics

- Target: `../herdr-worktrees/quic-endpoint` on `feat/quic-endpoint` from `v0.9.0`.
- Source: `feat/resumable-quic` (`8cdc4519`) in `../herdr`, kept as archived
  reference; merge base with `v0.9.0` is `c2637dc1`.
- Clean upstream reference: `../herdr-worktrees/v0.9.0`.
