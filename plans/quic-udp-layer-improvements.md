# Five bounded improvements to the herdr QUIC/UDP layer

Status: proposal | Target: `feat/quic-endpoint` at `277d2b5d` (v0.9.0 base) |
Written: 2026-09-09 | Companion: `DESIGNDOC-RESUMABLE-HERDR.md`

Each item names the measured problem in the branch's own scenario table or
benchmark (design doc §8.3–8.4), the exact change, the expected gain, how to
prove it with the existing harness, and the risk. None of them touches
`headless/*`, `client_transport.rs`, or `retained_surface.rs`; all stay behind
the endpoint seam. Items 1 and 2 are reliability, 3, 4 and 5 are performance. They are listed in implementation order.

Numbers quoted from the design doc were taken on debug builds over loopback
with the userspace 3G relay (1.6/0.75 Mbit, 260–340 ms RTT, 1-in-101 loss).
Every claim below must be re-measured with `remote_quic_3g_benchmark` and the
§8.3 scenarios at the SHA that carries the change, before and after.

Two things learned the hard way on a sibling project (`eversh`/`everudp`,
same quinn version among three QUIC engines tested): per-packet micro-tuning
of the send path (immediate flush, inline ACK processing, single-path
scheduling shortcuts, PGO) measured null against a direct-UDP baseline, and
swapping the QUIC engine changed nothing. The wins that did measure were in
ACK scheduling (item 3) and in *not buffering* stale output (item 4). Do not
spend time on the first category.

---

## 1. Rebind on address-change evidence, not on a 10 s timer

**Status: implemented and measured** (see "Result" below). Baseline `6f62d3c6`.

**Problem.** `PathMonitor` rebinds the local socket only after
`REBIND_AFTER` = 10 s of silence (`src/remote/quic.rs`). The interface-flap
scenario shows the cost directly: recovering at +2.4 s, rebind at +10.4 s,
live 2 ms after the rebind. Eight seconds of every flap are the timer, not the
network. Sleep/wake and tether-to-wifi pay the same.

**Change (as built).** A platform address-change source feeds the bridge's
path driver, which rebinds the moment the *evidence* says this path's source
address moved:

- `src/platform/unix_common.rs`: `AddressChangeSource`, one non-blocking
  descriptor plus a per-platform "does this message describe a change"
  parser; `drain()` reads everything pending and reports whether any message
  was address, link, or route evidence (`ENOBUFS` counts as evidence).
- Linux (`src/platform/linux.rs`): `AF_NETLINK`/`NETLINK_ROUTE` socket
  subscribed to `RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR |
  RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE`; only `nlmsghdr` types are parsed.
  libc only; `nlmsghdr`/`sockaddr_nl` are defined locally because the libc
  crate does not export them for glibc.
- macOS (`src/platform/macos.rs`): a `PF_ROUTE` raw socket — the socket
  `route -n monitor` reads — instead of `SCDynamicStore`: no child process,
  no CoreFoundation, and it announces `RTM_NEWADDR`/`RTM_DELADDR`/
  `RTM_IFINFO`/`RTM_ADD`/`RTM_DELETE`/`RTM_CHANGE` directly. Not yet
  compiled or exercised on a Mac; the parser has a unit test.
- Other Unix targets: `Err(Unsupported)`; the bridge logs it and keeps the
  10 s silence timer as the only trigger, exactly as before.
- `src/remote/quic_bridge.rs` `drive_path`: registers the source with the
  Tokio reactor (`AsyncFd`) as a fourth `select!` branch. On evidence it
  re-derives the source address the kernel would use for the peer
  (`local_source_for`: bind a wildcard UDP socket, `connect()` it, read
  `local_addr()`; no datagram is sent) and compares with the last known
  one. Only a *changed* source (including "no route any more") rebinds, so
  Docker bridges, VPN toggles and periodic IPv6 router advertisements cost
  one route lookup and nothing else. After the rebind it sends a health ping
  at once so the new path proves itself within one RTT.
- `PathMonitor::address_changed`: 500 ms debounce (`REBIND_DEBOUNCE`). A
  change inside the window is deferred to the end of the window, not
  dropped, and carried by the next tick with a probe; `next_deadline`
  accounts for it. An evidence rebind re-arms the `REBIND_AFTER` fallback so
  the timer does not fire a redundant second rebind. `Lost` ignores
  evidence. Unit-tested without sockets.

**Result.** New scenario `remote_quic_address_change_scenario`
(`src/remote/benchmark.rs`, `#[ignore]`, needs root): the in-process server
runs inside a network namespace, the bridge reaches it over a veth pair, and
the test deletes the root end's address, types a marker into the dead second,
and raises a different address 1 s later — real netlink events, a real dead
source address, a real default-route fallback in between. Two variants:
`address_change` (only the address moves) and `address_change_port_dead`
(the namespace also blackholes replies to the client's old UDP port first,
the design doc's own flap model and the NAT reality it stands for). Design
doc §8.5 has the table. Summary, debug build, three runs of four flaps per
variant each, recovery = new address raised → first frame from the server:

| variant | baseline `6f62d3c6` | with this change |
| --- | --- | --- |
| address only | 57–454 ms (median 337) | 11–22 ms (median 13) |
| old port dead | 13.78–13.81 s (median 13.79) | 11–19 ms (median 14) |

Both are under the preregistered 1 s budget on every flap; the baseline
misses it on every port-dead flap. Keystroke p50/p95 between flaps is
unchanged (~11.5 / ~19 ms in both builds), zero lost keystrokes. The
address-only baseline is fast-ish because a wildcard UDP socket follows the
kernel's route choice on its own, so recovery there is only quinn's PTO on
the packets sent into the dead second; the port-dead baseline is the
`REBIND_AFTER` timer measured from the oldest unanswered probe.

**Not measured here.** Sleep/wake and a real tether → wifi switch on a
laptop, and the macOS route socket. Those are the field-week items.

**Risk.** Low, as predicted: a spurious announcement costs one route lookup;
only a changed source costs a rebind and a path validation, at most one per
500 ms.

---

## 2. Transport-aware reconnect pacing and one keepalive, not three

**Problem A.** After the 150 s roaming grace the bridge closes the local
socket and the thin client's supervisor reconnects with upstream's
0.5 s → 30 s backoff (`src/client/endpoint/supervisor.rs:11–12`). The QUIC
ladder underneath already paces itself at 250 ms → 4 s
(`quic_bridge.rs:69–70`). In the 200 s full-outage scenario the client came
back 9.7 s after the network did, and the design lists the 30 s cap as its
first risk. A proven credential makes a reconnect cheap; the pacing does not
know that.

**Problem B.** Three liveness mechanisms overlap on an idle connection: the
server's QUIC `keep_alive_interval` of 15 s (`remote_quic.rs:48`), the
bridge's own probes (1 s fast after silence, 2 s slow), and the thin client's
5 s `endpoint.health.ping`. Each is a radio wakeup on mobile and each
inflates the packet count that item 3 tries to cut.

**Change.**

- A: when the bridge closes the local socket for a `lost`/`superseded` exit
  and holds a *proven* credential, it tells the supervisor (a local-only
  `endpoint.transport.status.v1 { state: "reconnect-fast" }` frame, the same
  channel as `recovering`) to cap backoff at 4 s for the next episode. The
  supervisor keeps 30 s for SSH endpoints and for unproven credentials.
- B: drop the server `keep_alive_interval` (the bridge probes on a stricter
  schedule than 15 s and any frame counts as liveness), and let the bridge
  suppress its own probe when a client health ping went out in the last
  interval (it already sees the frame length; it does not need to decode to
  know a frame was sent).

**Expected gain.** Post-grace reconnect from ~10 s to ~2–4 s after the
network returns. Idle packet rate from ~3 per 5 s to ~1 per 5 s.

**Measure.** §8.3 "200 s full outage" row (time from restore to connected),
and idle packet count over 10 minutes from the relay counter.

**Risk.** Low for A (a smaller cap on an already-paced path). Low-medium for
B: the server idle timeout (180 s default) must stay comfortably above the
slowest client probe interval, which it does at 2 s; state that invariant in
a test.

---

## 3. Negotiate ACK frequency so ACKs ride on the echo, and shorten PTO

**Problem.** With quinn defaults every ack-eliciting packet gets its own ACK
packet, and the peer-advertised `max_ack_delay` of 25 ms is added to every
probe timeout. For keystroke traffic that means two extra packets per key
(client ACK of the render frame, server ACK of the input) and a PTO that is
25 ms longer than the path warrants. On radio links packet count is battery
and wakeups; on lossy links PTO is the tail.

The `everudp` project measured exactly this with a held input ACK: 25.3 %
fewer packets on the wire in two ABBA blocks at zero loss, with no change in
latency because the ACK left inside the output packet that was already going
back. Herdr's echo path is the same shape: input frame in, render frame out
within milliseconds.

**Change.** In both `transport_config` functions:

```rust
let mut ack = quinn::AckFrequencyConfig::default();
ack.max_ack_delay(Some(Duration::from_millis(10)))
   .ack_eliciting_threshold(VarInt::from_u32(2))
   .reordering_threshold(VarInt::from_u32(1));
transport.ack_frequency_config(Some(ack));
```

`max_ack_delay(10 ms)` is the whole point: long enough for the render frame
(server) or the next keystroke (client) to carry the ACK, short enough that
PTO shrinks by 15 ms relative to the default. The extension is negotiated, so
a stock peer that does not support it simply keeps RFC 9000 behavior — this
is safe against any server or client version.

**Expected gain.** 20–25 % fewer packets during typing; PTO shorter by ~15 ms
on every path; no median latency change (verify, do not assume). Nothing on
bulk transfer.

**Measure.** Packet counts from the relay in `benchmark.rs` (it already sits
on the UDP path; add a counter per arm) at zero loss, ABBA order, plus the
p50/p95 of the same runs to prove no latency regression. Prereg the cutoff:
accept if packets fall ≥ 15 % and p50 moves less than 5 %.

**Risk.** Low. quinn 0.11.15 implements the extension on both sides. If a
peer misbehaves, the fallback is standard ACKs.

---

## 4. Size QUIC windows to the link so backpressure reaches the one-slot render queue

**Problem.** The server offers a 4 MiB send window and the client a 2 MiB
stream / 8 MiB connection receive window (`src/server/remote_quic.rs:38–40`,
`src/remote/quic.rs:116–118`). The design's own requirement 5 says stale
output must not accumulate unboundedly, and relies on upstream's one-slot
render queue for that. But that queue only sees backpressure once QUIC stops
accepting bytes. On the 3G profile (0.75 Mbit down) the bandwidth-delay
product is about 28 KB; 4 MiB of buffered frames is roughly 45 s of screen
that is already stale when it leaves the server, and every keystroke echo
queues behind it. The socketpair between acceptor and adapter adds another
~200 KB of kernel buffer in front of that. This is the mechanism behind a
laggy `cat bigfile` or a fast-scrolling agent log on a slow link.

**Change.**

- Server `QUIC_SEND_WINDOW` 4 MiB → 512 KiB; client `CLIENT_STREAM_RECEIVE_WINDOW`
  2 MiB → 512 KiB and `CLIENT_RECEIVE_WINDOW` 8 MiB → 1 MiB. Keep
  `MAX_GRAPHICS_FRAME_SIZE` frames working: a window smaller than one frame
  just streams the frame in pieces; it does not break it.
- Shrink the adapter socketpair's send buffer (`SO_SNDBUF` on the
  `adapter_end`, `remote_quic.rs:~690`) to 64 KiB so the acceptor's write
  blocks, and the one-slot queue coalesces, within one or two frames of the
  link filling.
- Optional second step: make the send window adaptive from
  `Connection::stats().path.rtt` and the BBR bandwidth estimate
  (`2 × BDP`, clamped to [128 KiB, 4 MiB]). Only if the fixed cut is not
  enough on real links.

**Expected gain.** Input-to-visible during bulk output on the 3G arm drops
from "seconds, growing" to about one RTT plus one frame. Zero effect on the
`direct` and `quic_online` arms. LAN throughput for large graphics frames is
unchanged as long as the window stays above the LAN BDP (100 Mbit × 1 ms ≈
12 KB).

**Measure.** Add a benchmark arm that runs `yes | head -c 50M` in the pane
while typing markers (the harness already types markers on a 250 ms cadence;
only the pane workload is new). Report p50/p95 input-to-visible with and
without bulk output, plus bytes buffered in the QUIC send stream over time.
Also A/B BBR vs Cubic on this arm: quinn marks BBR experimental (design §5.6,
risk list) and the branch has never measured the claim it rests on.

**Risk.** Medium. Too small a window caps throughput on high-BDP links
(satellite, cross-continent): 512 KiB at 200 ms RTT is ~20 Mbit, more than
any terminal needs but worth stating. The adaptive step removes the concern.

---

## 5. Bridge-side tail-loss probe for lone keystroke packets

**Problem.** The 3G arm's p95/p99 of 963/1015 ms against a 311 ms median is
the loss tail: a lost keystroke packet with nothing behind it cannot be
detected by packet or time threshold, so it waits for the PTO, roughly
`srtt + 4·rttvar + max_ack_delay`, which with the relay's 40 ms jitter band
lands near 2–3 RTT. RFC 9002 has no tail-loss probe; QUIC only sends PTO
probes. The `everudp` loss diagnostic saw the same shape at 5 % loss: the
slowest trials were single retransmissions waiting on the timer.

**Change.** The bridge already injects frames of its own on the uplink. After
forwarding an uplink frame, if no further uplink frame follows within
`max(srtt / 4, 20 ms)` (from `Connection::stats().path.rtt`), send one
`endpoint.health.ping.v1` frame. That ping is a new ack-eliciting packet; its
ACK arrives one RTT later and, if the keystroke packet was lost, quinn's
*time threshold* now declares the earlier packet lost at 9/8 × RTT after the
later packet's ACK instead of waiting for PTO, and retransmits at once.

Gate it: only when the uplink has been idle for the window (a typing burst
never sends more than one probe per gap), only while the path state is
`live`, and never more than 4 probes/s. Item 3's smaller `max_ack_delay`
compounds with this.

**Expected gain.** Tail latency on lossy links from ~3 RTT to ~2.2 RTT for a
lost keystroke, with no change to the median and one extra tiny packet per
typing pause. On the 3G arm that is p95 from ~960 ms to roughly ~700 ms.

**Measure.** `quic_3g` arm p95/p99 with `HERDR_BENCH_KEYSTROKES=600` so the
tail is stable; packet counter to bound the cost. Prereg: accept if p95 falls
≥ 20 % and packets rise ≤ 10 %.

**Risk.** Low-medium. The probe is a normal client health ping, so a stock
server answers it. The risk is over-probing on a busy uplink; the idle gate
and rate cap bound it. Do not lower `packet_threshold` below 3 or set
`time_threshold` below 9/8 to chase this further; those trade spurious
retransmits for the same gain.

---

## Order and what not to do

The numbering above is the implementation order. 1 and 2 are small,
reliability-only, and fix the two largest measured delays (flap recovery and
post-grace reconnect). 3 is a config change with a packet-count proof. 4 needs
its benchmark arm built first. 5 is last because it compounds with 3 and needs
the largest sample to judge. Each lands with its before/after numbers appended
to the design doc's §8 tables at the SHA measured.

Not worth doing, on evidence: flushing per frame more aggressively, moving
the pump off Tokio, replacing quinn, 0-RTT resumption, or any change whose
justification is "QUIC should be as fast as raw UDP". The measured gap
between a QUIC pipe and a raw UDP loop on the same host is about 170 µs per
keystroke across three engines; nobody can perceive it, and herdr's own
render path is thirty times larger than that.
