//! QUIC client transport for the remote bridge.
//!
//! Dialing, certificate pinning, and path liveness only. What flows over the
//! stream once the hello is accepted is an opaque sequence of length-prefixed
//! frames: this module never decodes it. `quic_bridge` owns the byte pump and
//! turns a `SessionExit` into a ladder decision.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tracing::debug;

use super::frame::{hash_bytes, lock, read_async_message, write_async_message};
use super::quic_policy::{
    REMOTE_QUIC_CLOSE_AUTH, REMOTE_QUIC_CLOSE_EVICTED, REMOTE_QUIC_CLOSE_PROTOCOL,
    REMOTE_QUIC_CLOSE_REPLACED, REMOTE_QUIC_CLOSE_SHUTDOWN,
};
use crate::protocol::{
    RemoteQuicAccepted, RemoteQuicHello, MAX_FRAME_SIZE, REMOTE_QUIC_ALPN, REMOTE_QUIC_HASH_BYTES,
    REMOTE_QUIC_SCHEMA_VERSION,
};

/// Budget for one candidate's QUIC handshake. Every candidate is dialed
/// concurrently, so this bounds the whole dial set rather than each address in
/// turn.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Head start given to each earlier candidate, Happy-Eyeballs style: the
/// preferred (IPv6-first) address gets to win an uncontested race on a dual
/// stacked host without making a broken AAAA record cost the full budget.
const DIAL_STAGGER: Duration = Duration::from_millis(250);
/// Deadline for the hello/acceptance exchange once the transport handshake is
/// done. Separate from `CONNECT_TIMEOUT`: this covers the server's token
/// validation, not path reachability.
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
/// Name presented in the TLS SNI. The certificate is pinned by fingerprint, so
/// this is only a placeholder rustls requires.
const TLS_SERVER_NAME: &str = "herdr";
/// Cadence at which a healthy path is re-probed. The bridge originates a
/// health ping on this schedule; the transport contributes no keep-alive of
/// its own, so this is the only liveness traffic.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// Silence at which probing switches to `FAST_PROBE_INTERVAL`. Nothing the
/// user can see happens here: no status change, no change in how input is
/// handled. Probes into a dead path are free, so this is deliberately eager.
const FAST_PROBE_AFTER: Duration = Duration::from_secs(1);
/// Silence required — together with `RECOVERING_MIN_UNANSWERED_PROBES` —
/// before the path is declared `Recovering`, which the bridge reports to the
/// thin client so it stretches its heartbeat deadline instead of declaring the
/// endpoint dead.
///
/// Input keeps flowing across this threshold: the QUIC stream is reliable and
/// ordered, so while the connection lives it delivers keystrokes in order
/// exactly as the SSH bridge did. What this threshold buys is the right to
/// tell the client it is roaming, and that must not fire on a merely slow
/// path.
const STALE_CORROBORATED_AFTER: Duration = Duration::from_secs(2);
/// Consecutive unanswered probes required before declaring `Recovering`.
///
/// Silence alone is not enough evidence, because silence is measured against
/// a wall clock the peer never agreed to: a delayed timer — a stalled
/// runtime, a suspended laptop whose monotonic clock skipped the sleep —
/// can make one outstanding probe look ancient the moment we wake, before the
/// peer has had a single round trip in which to answer. Two probes means at
/// least one full fast round happened while we were actually awake.
const RECOVERING_MIN_UNANSWERED_PROBES: u32 = 2;
/// Probe cadence while the path is silent, for the first `FAST_PROBE_WINDOW`.
/// Detecting the path's *return* is the only latency-critical part of an
/// outage, and probes sent into a dead path cost nothing.
const FAST_PROBE_INTERVAL: Duration = Duration::from_millis(500);
/// How long to probe aggressively before backing off, so a long outage does
/// not hold a mobile radio awake for its whole duration.
const FAST_PROBE_WINDOW: Duration = Duration::from_secs(30);
/// Probe cadence after `FAST_PROBE_WINDOW` of continuous silence.
const SLOW_PROBE_INTERVAL: Duration = Duration::from_secs(2);
/// Rebind the local socket after this much silence, and again after every
/// further `REBIND_AFTER` the silence continues. Rebinding answers a local
/// address change from sleep or roaming; doing it for a brief flap only
/// forces needless path validation and discards congestion state, and doing
/// it *once* per outage strands a sleep -> tether -> wifi sequence on the
/// second-to-last address.
const REBIND_AFTER: Duration = Duration::from_secs(10);
/// Minimum gap between rebinds driven by address-change evidence, so an
/// interface that flaps several times a second does not thrash the path and
/// discard congestion state on every flap. A change that lands inside the
/// window is not lost: it is deferred to the end of the window.
const REBIND_DEBOUNCE: Duration = Duration::from_millis(500);
/// Silence after which the path is declared `Lost`. This, not quinn's idle
/// timeout, is the client's dead-peer bound: the negotiated idle timeout is
/// the minimum of the two peers' advertised values, so it is the server's
/// configured `quic_transport_idle_timeout_seconds` — anywhere from 10 to 600
/// seconds — and may be far longer than this. `Connection::closed` still
/// reports real failures immediately; this covers only a peer that keeps the
/// transport nominally alive while never answering a probe.
///
/// It is also the grace the thin client is told to wait while `Recovering`, so
/// the client gives up at the same moment the bridge does rather than before.
pub(crate) const ROAMING_GRACE: Duration = Duration::from_secs(150);

/// Transport-level idle timeout advertised by the client. Only a backstop: the
/// bridge probes on `PathMonitor`'s schedule and gives up after
/// `ROAMING_GRACE`, so the application, not quinn, owns liveness detection.
///
/// The negotiated timeout is min(client, server), so any client value below
/// the server's would silently override the configured
/// `quic_transport_idle_timeout_seconds`. Advertising the largest value the
/// server can be configured with, plus slack, keeps the server's setting the
/// one that governs across its whole supported range.
const CLIENT_MAX_IDLE_TIMEOUT: Duration =
    Duration::from_secs(crate::config::REMOTE_TRANSPORT_IDLE_TIMEOUT_MAX_SECONDS + 10);
// Flow-control caps, not allocations. They are deliberately generous: the
// ceiling is send_window/RTT on every path, so shrinking them to suit one
// high-latency profile would throttle low-RTT attach and stall the multi-MB
// graphics frames the protocol's larger frame cap exists to carry. The
// per-stream window has to cover a full-screen repaint plus an inline
// graphics payload in flight at once, or a high-BDP path blocks the single
// stream mid-frame.
const CLIENT_STREAM_RECEIVE_WINDOW: u32 = 2 * 1024 * 1024;
const CLIENT_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CLIENT_SEND_WINDOW: u64 = 1024 * 1024;

/// What the bridge should tell the thin client about the QUIC path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathState {
    /// The peer answered recently.
    Live,
    /// The peer has been silent long enough to be presumed unreachable, but
    /// the connection still exists and input still flows over it.
    Recovering,
    /// Silence outlasted `ROAMING_GRACE`. Terminal: the bridge tears the
    /// connection down, and the monitor stays in this state.
    Lost,
}

/// Outcome of a scheduled liveness tick.
///
/// `probe` obliges the caller to send a health ping and report it back through
/// [`PathMonitor::probe_sent`]; skipping that leaves the probe deadline in the
/// past and the next tick due immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TickOutcome {
    /// Send a health ping now.
    pub(crate) probe: bool,
    /// Rebind the local UDP socket before sending it.
    pub(crate) rebind: bool,
    /// The path changed state; report it to the thin client.
    pub(crate) transition: Option<PathState>,
}

/// Owns path liveness: probe scheduling, silence tracking, and the transitions
/// the bridge reports to the thin client.
///
/// Liveness is proved by *any* frame arriving from the server, not only by a
/// health pong: the pipe is opaque, so every byte the peer sends is equally
/// good evidence that the path works.
#[derive(Debug)]
pub(crate) struct PathMonitor {
    /// When the last probe was sent. Drives the judging cadence only.
    last_probe_at: Instant,
    /// Last moment the path proved itself, by a probe going out or a frame
    /// coming in. Drives the healthy cadence, so a busy connection is not
    /// probed on top of the traffic that already proves it live.
    last_signal_at: Instant,
    /// Send time of the oldest probe no inbound frame has retired yet. Drives
    /// silence only.
    oldest_unacked_at: Option<Instant>,
    /// How many probes have been sent since the last inbound frame.
    /// Corroborates silence, which a delayed timer can otherwise overstate.
    unanswered_probes: u32,
    /// Instant when silence first exceeded `FAST_PROBE_AFTER`, starting the
    /// fast-probe window.
    fast_probe_since: Option<Instant>,
    /// Instant of the most recent endpoint rebind, so the next one can be
    /// re-armed a further `REBIND_AFTER` into the same outage.
    rebound_at: Option<Instant>,
    /// Instant of the most recent rebind driven by address-change evidence.
    /// Unlike `rebound_at` it survives inbound frames: the debounce bounds
    /// rebinds per unit of time, not per outage.
    evidence_rebound_at: Option<Instant>,
    /// An address change arrived inside the debounce window and still owes
    /// the path a rebind when the window ends.
    evidence_rebind_pending: bool,
    state: PathState,
}

impl PathMonitor {
    /// The first probe is due immediately: liveness has to be measured from
    /// connect, not from one `HEARTBEAT_INTERVAL` later.
    ///
    /// Every threshold here is measured with `Instant`, i.e. CLOCK_MONOTONIC,
    /// which on Linux excludes time the machine spent suspended. A laptop that
    /// sleeps for an hour therefore measures ~0 silence on wake, no matter how
    /// long the peer has actually been unreachable: nothing in this type can
    /// detect the outage until the first post-wake probe round trip fails,
    /// which is why detection is driven by probe *responses* rather than by
    /// elapsed time, and why `RECOVERING_MIN_UNANSWERED_PROBES` refuses to act
    /// on a single stale-looking probe. Deliberate: CLOCK_BOOTTIME would
    /// report the sleep as silence and announce an outage on a path that is
    /// fine, and no clock can shorten the one round trip recovery costs.
    pub(crate) fn new(now: Instant) -> Self {
        let due = now.checked_sub(HEARTBEAT_INTERVAL).unwrap_or(now);
        Self {
            last_probe_at: due,
            last_signal_at: due,
            oldest_unacked_at: None,
            unanswered_probes: 0,
            fast_probe_since: None,
            rebound_at: None,
            evidence_rebound_at: None,
            evidence_rebind_pending: false,
            state: PathState::Live,
        }
    }

    /// Records evidence that the local address the path uses changed — the
    /// kernel announced an address, link, or route change and the source
    /// address chosen for the peer is no longer the one the connection was
    /// using — and says whether to rebind right now. `false` inside the
    /// debounce window means the rebind is deferred, not dropped: the next
    /// [`Self::on_tick`] at [`Self::next_deadline`] carries it.
    ///
    /// Evidence beats the silence timer: a rebind here also re-arms the
    /// `REBIND_AFTER` fallback, so the timer does not fire a second, redundant
    /// rebind a few seconds later. `Lost` is terminal and ignores it.
    pub(crate) fn address_changed(&mut self, now: Instant) -> bool {
        if self.state == PathState::Lost {
            return false;
        }
        let inside_debounce = self
            .evidence_rebound_at
            .and_then(|previous| now.checked_duration_since(previous))
            .is_some_and(|since| since < REBIND_DEBOUNCE);
        if inside_debounce {
            self.evidence_rebind_pending = true;
            return false;
        }
        self.note_evidence_rebind(now);
        true
    }

    fn note_evidence_rebind(&mut self, now: Instant) {
        self.evidence_rebound_at = Some(now);
        self.evidence_rebind_pending = false;
        self.rebound_at = Some(now);
    }

    /// A deferred evidence rebind whose debounce window has ended.
    fn deferred_rebind_due(&self, now: Instant) -> bool {
        self.evidence_rebind_pending
            && self
                .evidence_rebound_at
                .and_then(|previous| now.checked_duration_since(previous))
                .is_none_or(|since| since >= REBIND_DEBOUNCE)
    }

    /// Records an inbound frame, whatever it carried, and reports the
    /// transition it caused. `Some(PathState::Live)` means the path just came
    /// back from `Recovering` and the thin client has to be told.
    ///
    /// `Lost` is terminal, so a frame arriving after the bridge has already
    /// decided to tear the connection down does not resurrect it.
    pub(crate) fn received(&mut self, now: Instant) -> Option<PathState> {
        self.oldest_unacked_at = None;
        self.unanswered_probes = 0;
        self.fast_probe_since = None;
        self.rebound_at = None;
        self.last_signal_at = now;
        if self.state == PathState::Recovering {
            self.state = PathState::Live;
            Some(PathState::Live)
        } else {
            None
        }
    }

    pub(crate) fn probe_sent(&mut self, now: Instant) {
        self.last_probe_at = now;
        self.last_signal_at = now;
        // Keep the oldest: it, not the newest, measures the silence.
        self.oldest_unacked_at.get_or_insert(now);
        self.unanswered_probes = self.unanswered_probes.saturating_add(1);
    }

    /// Evaluates silence thresholds and says what the caller owes the path.
    pub(crate) fn on_tick(&mut self, now: Instant) -> TickOutcome {
        let idle = TickOutcome {
            probe: false,
            rebind: false,
            transition: None,
        };
        if self.state == PathState::Lost {
            return idle;
        }
        // A rebind deferred by the debounce is owed before anything else, and
        // is followed by a probe so the new path proves itself at once.
        if self.deferred_rebind_due(now) {
            self.note_evidence_rebind(now);
            return TickOutcome {
                probe: true,
                rebind: true,
                transition: None,
            };
        }
        let Some(silence) = self.silence(now) else {
            return TickOutcome {
                probe: true,
                ..idle
            };
        };
        if silence >= ROAMING_GRACE {
            self.state = PathState::Lost;
            return TickOutcome {
                transition: Some(PathState::Lost),
                ..idle
            };
        }
        if silence >= FAST_PROBE_AFTER && self.fast_probe_since.is_none() {
            self.fast_probe_since = Some(now);
        }
        // Two independent pieces of evidence, and the transition is announced
        // exactly once: the probe count is checked before this tick's own
        // probe is sent, so a timer that fired late still owes the peer one
        // honest fast round before the client is told it is roaming.
        let transition = if silence >= STALE_CORROBORATED_AFTER
            && self.unanswered_probes >= RECOVERING_MIN_UNANSWERED_PROBES
            && self.state == PathState::Live
        {
            self.state = PathState::Recovering;
            Some(PathState::Recovering)
        } else {
            None
        };
        // Re-armed every REBIND_AFTER of continued silence, not once per
        // outage: sleep -> tether -> wifi changes the local address more than
        // once inside a single outage, and only the rebind that follows the
        // *final* change can recover the connection.
        let rebind = match self.rebound_at {
            None => silence >= REBIND_AFTER,
            Some(previous) => now
                .checked_duration_since(previous)
                .is_some_and(|since| since >= REBIND_AFTER),
        };
        if rebind {
            self.rebound_at = Some(now);
        }
        TickOutcome {
            probe: true,
            rebind,
            transition,
        }
    }

    /// Next instant the caller must wake to probe and judge.
    ///
    /// One deadline covers both because sending advances `last_probe_at`: an
    /// unanswered probe is re-evaluated a judge interval after the last send,
    /// and a quiet healthy path is simply probed again a heartbeat after its
    /// last sign of life.
    pub(crate) fn next_deadline(&self, now: Instant) -> Instant {
        let liveness = if self.oldest_unacked_at.is_some() {
            self.last_probe_at + self.judge_interval(now)
        } else {
            self.last_signal_at + HEARTBEAT_INTERVAL
        };
        match (self.evidence_rebind_pending, self.evidence_rebound_at) {
            (true, Some(previous)) => liveness.min(previous + REBIND_DEBOUNCE),
            (true, None) => now,
            (false, _) => liveness,
        }
    }

    #[cfg(test)]
    pub(crate) fn state(&self) -> PathState {
        self.state
    }

    /// How long the peer has been silent, measured from the oldest probe it
    /// has not answered. `None` when nothing is outstanding.
    fn silence(&self, now: Instant) -> Option<Duration> {
        self.oldest_unacked_at
            .and_then(|sent_at| now.checked_duration_since(sent_at))
    }

    /// Long outages back off so a dead radio is not held awake, but only past
    /// the window in which the path plausibly returns soon.
    fn judge_interval(&self, now: Instant) -> Duration {
        match self.fast_probe_since {
            Some(since)
                if now
                    .checked_duration_since(since)
                    .is_some_and(|elapsed| elapsed >= FAST_PROBE_WINDOW) =>
            {
                SLOW_PROBE_INTERVAL
            }
            _ => FAST_PROBE_INTERVAL,
        }
    }
}

/// Everything one dial needs: where to go, what certificate to accept, and the
/// credential to present on the stream.
pub(crate) struct QuicClientParams {
    /// Resolved server addresses in preference order, IPv6 first. Dialed
    /// concurrently, staggered by `DIAL_STAGGER`.
    pub(crate) candidates: Vec<SocketAddr>,
    pub(crate) fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
    pub(crate) hello: RemoteQuicHello,
}

/// Why a dial set produced no session.
#[derive(Debug)]
pub(crate) enum ConnectError {
    /// No candidate finished a handshake inside its budget. Indistinguishable
    /// from a filtered UDP path, which is what the SSH fallback exists for.
    Timeout(String),
    /// The server spoke and refused the credential or the schema. Retrying the
    /// same dial cannot help.
    Rejected(SessionExit),
    /// Local setup failed or the path failed in a way that says nothing about
    /// the credential.
    Other(String),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout(detail) => write!(formatter, "QUIC dial timed out: {detail}"),
            Self::Rejected(exit) => write!(formatter, "QUIC dial rejected: {exit}"),
            Self::Other(detail) => write!(formatter, "QUIC dial failed: {detail}"),
        }
    }
}

/// How a session ended, in terms of what the bridge may do next.
#[derive(Debug)]
pub(crate) enum SessionExit {
    /// Redial with the credential already held.
    Retry(String),
    /// The credential is unusable; a fresh SSH bootstrap is required.
    Rebootstrap(String),
    /// A newer generation of this capability was accepted: another client has
    /// taken the session over. Terminal — reconnecting would fence the client
    /// that just won, which would fence this one straight back.
    Superseded,
    /// This side closed the connection deliberately. Nothing to reconnect to.
    Shutdown(String),
}

impl fmt::Display for SessionExit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retry(detail) => write!(formatter, "retryable: {detail}"),
            Self::Rebootstrap(detail) => write!(formatter, "credential unusable: {detail}"),
            Self::Superseded => write!(formatter, "session taken over by a newer connection"),
            Self::Shutdown(detail) => write!(formatter, "closed locally: {detail}"),
        }
    }
}

/// A live QUIC connection and the endpoint that owns its socket.
///
/// Dropping the session closes the endpoint, which also kills the stream
/// halves `connect` handed out: keep it alive for as long as the pump runs.
///
/// `Debug` so tests can `expect_err` on `connect`; the derive prints only
/// quinn handles and counters, never buffered bytes.
#[derive(Debug)]
pub(crate) struct QuicSession {
    endpoint: Endpoint,
    connection: Connection,
    /// Address family of the peer, so a rebind picks the same family the
    /// connection was established on.
    remote_ip: IpAddr,
}

impl QuicSession {
    /// Dials every candidate at once, Happy-Eyeballs style: one QUIC handshake
    /// per address, staggered by `DIAL_STAGGER` so the preferred address keeps
    /// a small head start, and the first completed hello exchange wins. Losing
    /// endpoints are closed rather than dropped, because dropping an
    /// `Endpoint` leaves its driver task and UDP socket alive.
    ///
    /// Every dial presents the same connection generation, so the server
    /// fences all but one of them out even if two handshakes overlap; at most
    /// one can be accepted.
    pub(crate) async fn connect(
        params: QuicClientParams,
    ) -> Result<(Self, SendStream, RecvStream), ConnectError> {
        let QuicClientParams {
            candidates,
            fingerprint,
            hello,
        } = params;
        if candidates.is_empty() {
            return Err(ConnectError::Other(
                "remote QUIC bootstrap returned no reachable address candidates".to_owned(),
            ));
        }

        // Endpoints of dials still in flight. A task removes its own entry
        // when it finishes, so whatever is left when `connect` returns belongs
        // to a loser that is about to be aborted and has to be closed here.
        let in_flight = Arc::new(Mutex::new(Vec::new()));
        let mut dials = tokio::task::JoinSet::new();
        for (index, candidate) in candidates.into_iter().enumerate() {
            let hello = hello.clone();
            let in_flight = Arc::clone(&in_flight);
            let stagger = DIAL_STAGGER.saturating_mul(u32::try_from(index).unwrap_or(u32::MAX));
            dials.spawn(async move {
                if !stagger.is_zero() {
                    tokio::time::sleep(stagger).await;
                }
                dial_candidate(index, candidate, fingerprint, hello, &in_flight).await
            });
        }

        let mut errors = Vec::new();
        let mut outcome = None;
        while let Some(joined) = dials.join_next().await {
            match joined {
                Ok(Ok(session)) => {
                    outcome = Some(session);
                    break;
                }
                Ok(Err(error)) => errors.push(error),
                Err(error) => errors.push(ConnectError::Other(format!(
                    "QUIC dial task failed: {error}"
                ))),
            }
        }
        // Closing an abandoned endpoint from here rather than inside the task
        // is what makes aborting the losers safe: the close reaches the shared
        // endpoint state even if the task is still between awaits.
        for (_, endpoint) in lock(&in_flight).drain(..) {
            endpoint.close(VarInt::from_u32(0), b"candidate abandoned");
        }
        match outcome {
            Some(session) => Ok(session),
            None => Err(combine_dial_errors(errors)),
        }
    }

    /// Migrates the connection to a freshly bound local socket, which is the
    /// only way to follow a local address change (sleep, tether, roam).
    pub(crate) fn rebind(&self) -> Result<(), String> {
        rebind_endpoint(&self.endpoint, self.remote_ip)
    }

    /// The peer address this connection was established to.
    pub(crate) fn remote_addr(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Resolves when the connection ends, classifying what the bridge may do.
    pub(crate) async fn closed(&self) -> SessionExit {
        classify_close(&self.connection.closed().await)
    }

    /// Closes the connection with an application code, and the endpoint with
    /// it: one endpoint serves one session, so its socket and driver task have
    /// nothing left to do.
    pub(crate) fn close(&self, code: u32, reason: &[u8]) {
        self.connection.close(VarInt::from_u32(code), reason);
        self.endpoint.close(VarInt::from_u32(code), reason);
    }

    #[cfg(test)]
    pub(crate) fn connection(&self) -> &Connection {
        &self.connection
    }
}

impl Drop for QuicSession {
    fn drop(&mut self) {
        // Dropping an `Endpoint` does not release its UDP socket or stop its
        // driver task, so a session dropped without an explicit `close` would
        // leak both for the life of the process.
        self.endpoint.close(VarInt::from_u32(0), b"session dropped");
    }
}

/// One candidate's handshake: transport, then the hello exchange on the single
/// bidirectional stream the whole session uses.
async fn dial_candidate(
    index: usize,
    candidate: SocketAddr,
    fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
    hello: RemoteQuicHello,
    in_flight: &Mutex<Vec<(usize, Endpoint)>>,
) -> Result<(QuicSession, SendStream, RecvStream), ConnectError> {
    let endpoint =
        make_client_endpoint(candidate.ip(), fingerprint).map_err(ConnectError::Other)?;
    lock(in_flight).push((index, endpoint.clone()));
    let result = handshake(candidate, &endpoint, hello).await;
    lock(in_flight).retain(|(registered, _)| *registered != index);
    if let Err(error) = &result {
        debug!(%candidate, %error, "remote QUIC candidate failed");
        endpoint.close(VarInt::from_u32(0), b"handshake abandoned");
    }
    result
}

async fn handshake(
    candidate: SocketAddr,
    endpoint: &Endpoint,
    hello: RemoteQuicHello,
) -> Result<(QuicSession, SendStream, RecvStream), ConnectError> {
    let connecting = endpoint
        .connect(candidate, TLS_SERVER_NAME)
        .map_err(|err| {
            ConnectError::Other(format!(
                "failed to start QUIC connection to {candidate}: {err}"
            ))
        })?;
    let connection = match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(err)) => return Err(ConnectError::Other(format!("{candidate}: {err}"))),
        Err(_) => {
            return Err(ConnectError::Timeout(format!(
                "{candidate}: handshake did not complete in {CONNECT_TIMEOUT:?}"
            )))
        }
    };
    let (mut send, mut recv) = match tokio::time::timeout(HELLO_TIMEOUT, connection.open_bi()).await
    {
        Ok(Ok(streams)) => streams,
        Ok(Err(err)) => {
            return Err(classify_handshake_failure(
                &connection,
                format!("{candidate}: failed to open the QUIC stream: {err}"),
            ))
        }
        Err(_) => {
            return Err(ConnectError::Timeout(format!(
                "{candidate}: timed out opening the QUIC stream"
            )))
        }
    };
    let generation = hello.connection_generation;
    if let Err(error) = write_async_message(&mut send, &hello, MAX_FRAME_SIZE).await {
        return Err(classify_handshake_failure(
            &connection,
            format!("{candidate}: {error}"),
        ));
    }
    let accepted: RemoteQuicAccepted =
        match tokio::time::timeout(HELLO_TIMEOUT, read_async_message(&mut recv, MAX_FRAME_SIZE))
            .await
        {
            Ok(Ok(accepted)) => accepted,
            Ok(Err(error)) => {
                return Err(classify_handshake_failure(
                    &connection,
                    format!("{candidate}: {error}"),
                ))
            }
            Err(_) => {
                return Err(ConnectError::Timeout(format!(
                    "{candidate}: timed out waiting for the remote QUIC acceptance"
                )))
            }
        };
    // A peer that answers with a schema it invented is running a different
    // build, and only a fresh bootstrap can resolve that.
    if accepted.schema_version != REMOTE_QUIC_SCHEMA_VERSION {
        return Err(ConnectError::Rejected(SessionExit::Rebootstrap(format!(
            "remote QUIC schema {} does not match local schema {REMOTE_QUIC_SCHEMA_VERSION}",
            accepted.schema_version
        ))));
    }
    if accepted.connection_generation != generation {
        return Err(ConnectError::Other(format!(
            "{candidate}: remote QUIC accepted generation {} instead of {generation}",
            accepted.connection_generation
        )));
    }
    let remote_ip = connection.remote_address().ip();
    Ok((
        QuicSession {
            endpoint: endpoint.clone(),
            connection,
            remote_ip,
        },
        send,
        recv,
    ))
}

/// A stream failure right after the hello is usually the server's verdict: it
/// closes the connection with an application code instead of answering. Ask
/// the connection for that code rather than trusting the stringified stream
/// error, which is the same reasoning `classify_close` follows.
///
/// Only a verdict about the credential becomes `Rejected`; a retryable close
/// says nothing more than the path did, so it stays `Other` and lets the
/// ladder treat it as a failed path.
fn classify_handshake_failure(connection: &Connection, detail: String) -> ConnectError {
    match connection
        .close_reason()
        .map(|error| classify_close(&error))
    {
        Some(SessionExit::Retry(_)) | None => ConnectError::Other(detail),
        Some(exit) => ConnectError::Rejected(exit),
    }
}

/// Reduces a fully failed dial set to one verdict.
///
/// A rejection outranks a path failure: the server actively refused the
/// credential, which no other candidate's silence can contradict, and acting
/// on it is what saves the ladder from redialing a credential that can only
/// fail again.
fn combine_dial_errors(errors: Vec<ConnectError>) -> ConnectError {
    let mut details = Vec::with_capacity(errors.len());
    let mut only_timeouts = !errors.is_empty();
    for error in errors {
        match error {
            ConnectError::Rejected(exit) => return ConnectError::Rejected(exit),
            ConnectError::Timeout(detail) => details.push(detail),
            ConnectError::Other(detail) => {
                only_timeouts = false;
                details.push(detail);
            }
        }
    }
    let detail = format!("all remote QUIC paths failed: {}", details.join("; "));
    if only_timeouts {
        ConnectError::Timeout(detail)
    } else {
        ConnectError::Other(detail)
    }
}

/// Decides whether a closed connection can be retried with the credential we
/// hold, needs a fresh bootstrap, or must not be reconnected at all.
///
/// Keyed on the QUIC application close code, never on the reason string: the
/// reason is a human-readable diagnostic the server is free to reword, and
/// matching substrings in it made every log message a load-bearing part of the
/// protocol. Unknown codes and every transport-level failure retry, because
/// re-bootstrapping costs an SSH round trip and only helps when the
/// credential, the protocol, or the server process itself is the problem.
fn classify_close(error: &quinn::ConnectionError) -> SessionExit {
    let detail = error.to_string();
    let frame = match error {
        quinn::ConnectionError::ApplicationClosed(frame) => frame,
        // We closed it ourselves, so there is nothing to reconnect to and
        // redialing would undo the teardown that is in progress.
        quinn::ConnectionError::LocallyClosed => return SessionExit::Shutdown(detail),
        _ => return SessionExit::Retry(detail),
    };
    match u32::try_from(u64::from(frame.error_code)) {
        // The credential itself is the problem — rejected, from an
        // incompatible build, tied to a process that is gone, or evicted from
        // the server's token table. Redialing with it can only fail again.
        Ok(
            REMOTE_QUIC_CLOSE_AUTH
            | REMOTE_QUIC_CLOSE_PROTOCOL
            | REMOTE_QUIC_CLOSE_SHUTDOWN
            | REMOTE_QUIC_CLOSE_EVICTED,
        ) => SessionExit::Rebootstrap(detail),
        // Another client took the session over. Reconnecting would fence it
        // and invite it to fence us back, forever, so this one stops.
        Ok(REMOTE_QUIC_CLOSE_REPLACED) => SessionExit::Superseded,
        // HANDOFF and RESYNC both want the credential we hold, and so does
        // any code a newer server invents: a redial is the cheap guess.
        _ => SessionExit::Retry(detail),
    }
}

fn make_client_endpoint(
    remote_ip: IpAddr,
    fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
) -> Result<Endpoint, String> {
    let mut endpoint = Endpoint::client(wildcard_for(remote_ip))
        .map_err(|err| format!("failed to bind local QUIC socket: {err}"))?;
    endpoint.set_default_client_config(client_config(fingerprint)?);
    Ok(endpoint)
}

fn client_config(fingerprint: [u8; REMOTE_QUIC_HASH_BYTES]) -> Result<quinn::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(FingerprintVerifier {
        fingerprint,
        provider: Arc::clone(&provider),
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| format!("failed to enable TLS 1.3: {err}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![REMOTE_QUIC_ALPN.to_vec()];
    tls.enable_early_data = false;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|err| format!("failed to configure QUIC TLS: {err}"))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            CLIENT_MAX_IDLE_TIMEOUT
                .try_into()
                .map_err(|_| "QUIC idle timeout is too large".to_owned())?,
        ))
        // No `keep_alive_interval`: the bridge already probes on
        // `PathMonitor`'s schedule and judges the answers, so a quinn PING
        // timer would be a second, dumber liveness mechanism — it keeps a
        // dead connection nominally alive without telling anyone, and its
        // traffic is exactly what the health pings already provide.
        //
        // The server opens no streams towards the client: everything travels
        // on the one bidirectional stream this side opens.
        .max_concurrent_bidi_streams(VarInt::from_u32(0))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(CLIENT_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(CLIENT_RECEIVE_WINDOW))
        .send_window(CLIENT_SEND_WINDOW)
        // Loss-based control (quinn's Cubic default) treats random radio loss
        // as congestion and repeatedly collapses the window; the classic
        // MSS/(RTT*sqrt(p)) ceiling is Reno's, and Cubic's window growth
        // differs, so treat that only as the qualitative direction, not as a
        // predicted rate. BBR paces to measured bottleneck bandwidth instead.
        // quinn documents its BBR as experimental, and this default currently
        // rests on single-trial shaped-link measurements rather than a
        // counterbalanced CUBIC/BBR comparison across RTTs and loads.
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// Accepts exactly one certificate: the one whose DER hashes to the
/// fingerprint delivered over the authenticated SSH bootstrap. There is no CA,
/// no name check, and no expiry check to fall back on.
#[derive(Debug)]
struct FingerprintVerifier {
    fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if hash_bytes(end_entity.as_ref()) == self.fingerprint {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "remote QUIC certificate fingerprint mismatch".to_owned(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn rebind_endpoint(endpoint: &Endpoint, remote_ip: IpAddr) -> Result<(), String> {
    let socket = UdpSocket::bind(wildcard_for(remote_ip))
        .map_err(|err| format!("failed to bind replacement UDP socket: {err}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|err| format!("failed to configure replacement UDP socket: {err}"))?;
    endpoint
        .rebind(socket)
        .map_err(|err| format!("failed to migrate QUIC endpoint: {err}"))
}

/// The local address the kernel would send from to reach `remote` right now,
/// or `None` when no route exists. Connecting an unsent UDP socket performs
/// exactly the route lookup the endpoint's wildcard socket goes through on
/// every send, without sending anything; comparing two answers is how the
/// bridge turns a kernel "something changed" announcement into "*my* path
/// changed".
pub(crate) fn local_source_for(remote: SocketAddr) -> Option<IpAddr> {
    let socket = UdpSocket::bind(wildcard_for(remote.ip())).ok()?;
    socket.connect(remote).ok()?;
    socket.local_addr().ok().map(|address| address.ip())
}

/// Local bind address matching the peer's address family: a v4 peer needs a v4
/// socket, and a v6 socket bound to `::` cannot reach it.
fn wildcard_for(remote_ip: IpAddr) -> SocketAddr {
    match remote_ip {
        IpAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        IpAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{REMOTE_QUIC_ID_BYTES, REMOTE_QUIC_TOKEN_BYTES};
    use rustls::client::danger::ServerCertVerifier as _;
    use tokio::sync::mpsc;

    #[test]
    fn the_first_probe_is_due_immediately_then_once_per_heartbeat() {
        let now = Instant::now();
        let mut monitor = PathMonitor::new(now);
        assert_eq!(
            monitor.next_deadline(now),
            now,
            "liveness must be measured from connect, not one interval later"
        );
        assert_eq!(
            monitor.on_tick(now),
            TickOutcome {
                probe: true,
                rebind: false,
                transition: None,
            }
        );
        monitor.probe_sent(now);
        assert_eq!(monitor.received(now), None);
        assert_eq!(
            monitor.next_deadline(now),
            now + HEARTBEAT_INTERVAL,
            "an idle healthy path must not be probed more often than this"
        );
    }

    #[test]
    fn every_probe_is_judged_on_the_fast_deadline_whatever_prompted_it() {
        let sent = Instant::now();
        let mut monitor = PathMonitor::new(sent);
        monitor.probe_sent(sent);
        // The bug this pins: deciding cadence before sending left a
        // heartbeat-originated probe unjudged for a whole HEARTBEAT_INTERVAL
        // while an input-originated one was judged in FAST_PROBE_INTERVAL.
        assert_eq!(monitor.next_deadline(sent), sent + FAST_PROBE_INTERVAL);
        assert_eq!(
            monitor.silence(sent + Duration::from_secs(1)),
            Some(Duration::from_secs(1))
        );
    }

    /// Any frame from the server proves the path, not just a health pong: the
    /// pipe is opaque, so server output is exactly as good as evidence.
    #[test]
    fn any_received_frame_returns_the_path_to_the_healthy_cadence() {
        let sent = Instant::now();
        let mut monitor = PathMonitor::new(sent);
        monitor.probe_sent(sent);
        assert_eq!(monitor.received(sent), None);
        assert_eq!(monitor.silence(sent + Duration::from_secs(9)), None);
        // Measured from the moment the path last proved itself, so a busy
        // connection is not probed on top of the traffic that proves it live.
        assert_eq!(monitor.next_deadline(sent), sent + HEARTBEAT_INTERVAL);
    }

    #[test]
    fn the_oldest_unanswered_probe_measures_silence() {
        let first = Instant::now();
        let mut monitor = PathMonitor::new(first);
        monitor.probe_sent(first);
        monitor.probe_sent(first + Duration::from_secs(1));
        assert_eq!(
            monitor.silence(first + Duration::from_secs(2)),
            Some(Duration::from_secs(2)),
            "a newer probe must not reset the silence the older one proves"
        );
    }

    #[test]
    fn probing_backs_off_only_after_the_fast_window() {
        let sent = Instant::now();
        let mut monitor = PathMonitor::new(sent);
        monitor.probe_sent(sent);
        let stale_at = sent + FAST_PROBE_AFTER;
        let tick = monitor.on_tick(stale_at);
        assert!(tick.probe);
        monitor.probe_sent(stale_at);
        assert!(monitor.fast_probe_since.is_some());

        let just_stale = stale_at + (FAST_PROBE_WINDOW - Duration::from_millis(1));
        assert_eq!(
            monitor.next_deadline(just_stale),
            stale_at + FAST_PROBE_INTERVAL
        );
        let long_stale = stale_at + FAST_PROBE_WINDOW;
        assert_eq!(
            monitor.next_deadline(long_stale),
            stale_at + SLOW_PROBE_INTERVAL,
            "a long outage must stop holding the radio awake at 2 Hz"
        );
    }

    #[test]
    fn path_monitor_outage_lifecycle_and_recovery() {
        let now = Instant::now();
        let mut monitor = PathMonitor::new(now);

        // 1. The connect tick probes immediately and reports nothing.
        assert_eq!(monitor.next_deadline(now), now);
        let tick = monitor.on_tick(now);
        assert!(tick.probe);
        assert_eq!(tick.transition, None);
        monitor.probe_sent(now);
        assert_eq!(monitor.state(), PathState::Live);

        // 2. FAST_PROBE_AFTER: probing speeds up, but nothing the user can see
        // happens yet — one late answer is not an outage.
        let t1 = now + FAST_PROBE_AFTER;
        let tick = monitor.on_tick(t1);
        assert_eq!(tick.transition, None);
        monitor.probe_sent(t1);
        assert!(monitor.fast_probe_since.is_some());
        assert_eq!(monitor.state(), PathState::Live);

        // 3. STALE_CORROBORATED_AFTER with two probes already unanswered: the
        // client is told it is roaming, exactly once.
        let t2 = now + STALE_CORROBORATED_AFTER;
        let tick = monitor.on_tick(t2);
        assert_eq!(
            tick,
            TickOutcome {
                probe: true,
                rebind: false,
                transition: Some(PathState::Recovering),
            }
        );
        monitor.probe_sent(t2);
        assert_eq!(monitor.state(), PathState::Recovering);

        // A second announcement must not fire while the path stays dead, or
        // the status line thrashes for the whole outage.
        let t2b = t2 + FAST_PROBE_INTERVAL;
        assert_eq!(monitor.on_tick(t2b).transition, None);
        monitor.probe_sent(t2b);

        // 4. REBIND_AFTER: the local socket is rebound.
        let t10 = now + REBIND_AFTER;
        let tick = monitor.on_tick(t10);
        assert!(tick.rebind);
        assert_eq!(tick.transition, None);
        monitor.probe_sent(t10);
        // Rebinding again immediately would only discard congestion state.
        let t11 = t10 + Duration::from_secs(1);
        let tick = monitor.on_tick(t11);
        assert!(!tick.rebind);
        monitor.probe_sent(t11);

        // 5. A frame arrives: the path is live again and the client is told.
        assert_eq!(monitor.received(t11), Some(PathState::Live));
        assert_eq!(monitor.state(), PathState::Live);
        assert_eq!(monitor.next_deadline(t11), t11 + HEARTBEAT_INTERVAL);

        // 6. Silence past the grace loses the path, and stays there.
        monitor.probe_sent(t11);
        let lost_at = t11 + ROAMING_GRACE;
        assert_eq!(
            monitor.on_tick(lost_at),
            TickOutcome {
                probe: false,
                rebind: false,
                transition: Some(PathState::Lost),
            }
        );
        assert_eq!(monitor.state(), PathState::Lost);
        assert_eq!(
            monitor.on_tick(lost_at + ROAMING_GRACE),
            TickOutcome {
                probe: false,
                rebind: false,
                transition: None,
            },
            "a lost path is torn down, not announced twice"
        );
        assert_eq!(monitor.received(lost_at), None);
        assert_eq!(monitor.state(), PathState::Lost);
    }

    /// A timer that fires late — a stalled runtime, a laptop resuming from
    /// sleep — can make a single outstanding probe look ancient before the
    /// peer has had one round trip in which to answer. Announcing on that
    /// evidence repaints the UI for a path that is fine.
    #[test]
    fn one_unanswered_probe_never_announces_however_old_it_looks() {
        let sent = Instant::now();
        let mut monitor = PathMonitor::new(sent);
        monitor.probe_sent(sent);

        let long_after = sent + STALE_CORROBORATED_AFTER * 10;
        let tick = monitor.on_tick(long_after);
        assert_eq!(
            tick,
            TickOutcome {
                probe: true,
                rebind: true,
                transition: None,
            },
            "one probe is not evidence of an outage, however stale it looks"
        );
        assert_eq!(monitor.state(), PathState::Live);
        monitor.probe_sent(long_after);

        // The probe that tick asked for was the second one, so the next round
        // has the two independent failures the announcement requires.
        let next = long_after + FAST_PROBE_INTERVAL;
        assert_eq!(
            monitor.on_tick(next).transition,
            Some(PathState::Recovering)
        );
        assert_eq!(monitor.state(), PathState::Recovering);
    }

    /// A single sleep -> tether -> wifi sequence changes the local address more
    /// than once inside one outage, and only the rebind that follows the last
    /// change can revive the connection.
    #[test]
    fn rebind_is_re_armed_every_interval_of_continued_silence() {
        let sent = Instant::now();
        let mut monitor = PathMonitor::new(sent);
        monitor.probe_sent(sent);

        let mut rebinds = Vec::new();
        let mut elapsed = Duration::ZERO;
        // Walk the whole outage at the fast cadence, which is the shortest
        // tick spacing and so the strictest test of the re-arm window.
        while elapsed < ROAMING_GRACE {
            elapsed += FAST_PROBE_INTERVAL;
            let tick = monitor.on_tick(sent + elapsed);
            if tick.transition == Some(PathState::Lost) {
                break;
            }
            if tick.rebind {
                rebinds.push(elapsed);
            }
        }
        let expected: Vec<Duration> = (1..=14).map(|step| REBIND_AFTER * step).collect();
        assert_eq!(
            rebinds, expected,
            "rebind must re-arm every REBIND_AFTER of silence up to ROAMING_GRACE"
        );

        // An inbound frame disarms it: the next outage starts its own schedule.
        let mut monitor = PathMonitor::new(sent);
        monitor.probe_sent(sent);
        let first = sent + REBIND_AFTER;
        assert!(monitor.on_tick(first).rebind);
        let _ = monitor.received(first);
        monitor.probe_sent(first);
        assert!(
            !monitor.on_tick(first + FAST_PROBE_INTERVAL).rebind,
            "a recovered path must not inherit the previous outage's rebind clock"
        );
    }

    /// The reason string is a diagnostic the server may reword at will, so the
    /// classification hangs off the numeric close code. Every code the server
    /// can send is pinned here: getting this wrong either loops the client
    /// through a doomed reconnect or throws away a still-valid credential and
    /// an SSH round trip.
    #[test]
    fn close_classification_follows_the_application_code_not_the_reason() {
        use super::super::quic_policy::{REMOTE_QUIC_CLOSE_HANDOFF, REMOTE_QUIC_CLOSE_RESYNC};

        let closed = |code: u32, reason: &'static str| {
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: VarInt::from_u32(code),
                reason: bytes::Bytes::from_static(reason.as_bytes()),
            })
        };

        for code in [REMOTE_QUIC_CLOSE_HANDOFF, REMOTE_QUIC_CLOSE_RESYNC, 0xdead] {
            assert!(
                matches!(
                    classify_close(&closed(code, "capability protocol server instance")),
                    SessionExit::Retry(_)
                ),
                "code {code:#x} must reconnect with the credential we hold, whatever the reason says"
            );
        }

        for code in [
            REMOTE_QUIC_CLOSE_AUTH,
            REMOTE_QUIC_CLOSE_PROTOCOL,
            REMOTE_QUIC_CLOSE_SHUTDOWN,
            REMOTE_QUIC_CLOSE_EVICTED,
        ] {
            assert!(
                matches!(
                    classify_close(&closed(code, "nothing quotable here")),
                    SessionExit::Rebootstrap(_)
                ),
                "code {code:#x} invalidates the credential and must re-bootstrap"
            );
        }

        // Two clients that both redial on REPLACED fence each other forever:
        // each reconnect makes a newer generation that evicts the other.
        assert!(
            matches!(
                classify_close(&closed(REMOTE_QUIC_CLOSE_REPLACED, "replaced")),
                SessionExit::Superseded
            ),
            "a superseded generation must stop, not race the client that took over"
        );

        assert!(
            matches!(
                classify_close(&quinn::ConnectionError::TimedOut),
                SessionExit::Retry(_)
            ),
            "a transport timeout says nothing about the credential"
        );
        assert!(
            matches!(
                classify_close(&quinn::ConnectionError::LocallyClosed),
                SessionExit::Shutdown(_)
            ),
            "a connection this side closed must not be redialed"
        );
    }

    #[test]
    fn the_pinned_verifier_accepts_only_the_bootstrapped_certificate() {
        let certificate = CertificateDer::from(vec![7u8; 64]);
        let verifier = FingerprintVerifier {
            fingerprint: hash_bytes(certificate.as_ref()),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        let name = ServerName::try_from(TLS_SERVER_NAME).expect("server name");
        let now = UnixTime::since_unix_epoch(Duration::ZERO);
        assert!(verifier
            .verify_server_cert(&certificate, &[], &name, &[], now)
            .is_ok());

        let wrong = CertificateDer::from(vec![1, 2, 3]);
        assert!(
            verifier
                .verify_server_cert(&wrong, &[], &name, &[], now)
                .is_err(),
            "there is no CA to fall back on: an unpinned certificate must fail"
        );
    }

    fn test_hello(generation: u64) -> RemoteQuicHello {
        RemoteQuicHello {
            schema_version: REMOTE_QUIC_SCHEMA_VERSION,
            server_instance_id: [5u8; REMOTE_QUIC_ID_BYTES],
            logical_client_id: [6u8; REMOTE_QUIC_ID_BYTES],
            capability_token: [7u8; REMOTE_QUIC_TOKEN_BYTES],
            connection_generation: generation,
        }
    }

    #[derive(Clone, Copy)]
    enum Verdict {
        Accept,
        Reject(u32),
    }

    /// The minimum a server has to do for `connect` to be exercised for real:
    /// terminate the pinned TLS handshake, read the hello off the one
    /// bidirectional stream, and either answer it or close with a code.
    struct TestServer {
        /// Held only to keep the listener alive for the test's duration.
        _endpoint: Endpoint,
        address: SocketAddr,
        fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
        hellos: mpsc::UnboundedReceiver<RemoteQuicHello>,
    }

    fn start_test_server(verdict: Verdict) -> TestServer {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec![TLS_SERVER_NAME.to_owned()])
                .expect("self-signed certificate");
        let certificate_der = cert.der().to_vec();
        let fingerprint = hash_bytes(&certificate_der);
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("enable TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(certificate_der)], key)
        .expect("server certificate");
        tls.alpn_protocols = vec![REMOTE_QUIC_ALPN.to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("configure QUIC TLS");
        let endpoint = Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("bind test server");
        let address = endpoint.local_addr().expect("test server address");
        let (hello_tx, hellos) = mpsc::unbounded_channel();
        let accepting = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accepting.accept().await {
                let Ok(connection) = incoming.await else {
                    continue;
                };
                let hello_tx = hello_tx.clone();
                tokio::spawn(async move {
                    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                        return;
                    };
                    let Ok(hello) =
                        read_async_message::<RemoteQuicHello>(&mut recv, MAX_FRAME_SIZE).await
                    else {
                        return;
                    };
                    let connection_generation = hello.connection_generation;
                    let _ = hello_tx.send(hello);
                    match verdict {
                        Verdict::Accept => {
                            let accepted = RemoteQuicAccepted {
                                schema_version: REMOTE_QUIC_SCHEMA_VERSION,
                                connection_generation,
                            };
                            let _ = write_async_message(&mut send, &accepted, MAX_FRAME_SIZE).await;
                            connection.closed().await;
                        }
                        Verdict::Reject(code) => {
                            connection.close(VarInt::from_u32(code), b"test rejection")
                        }
                    }
                });
            }
        });
        TestServer {
            _endpoint: endpoint,
            address,
            fingerprint,
            hellos,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pinned_dial_presents_the_hello_and_takes_the_acceptance() {
        let mut server = start_test_server(Verdict::Accept);
        let hello = test_hello(9);
        let (session, _send, _recv) = QuicSession::connect(QuicClientParams {
            candidates: vec![server.address],
            fingerprint: server.fingerprint,
            hello: hello.clone(),
        })
        .await
        .expect("connect to the test server");

        let observed = tokio::time::timeout(Duration::from_secs(2), server.hellos.recv())
            .await
            .expect("hello delivery timeout")
            .expect("hello");
        assert!(
            observed == hello,
            "the hello must reach the server verbatim as the first frame"
        );
        assert_eq!(session.connection().remote_address(), server.address);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_certificate_that_is_not_pinned_never_completes_a_handshake() {
        let server = start_test_server(Verdict::Accept);
        let error = QuicSession::connect(QuicClientParams {
            candidates: vec![server.address],
            fingerprint: hash_bytes(b"some other server's certificate"),
            hello: test_hello(1),
        })
        .await
        .expect_err("an unpinned certificate must not be accepted");
        assert!(
            matches!(error, ConnectError::Other(_)),
            "a rejected certificate is a path failure, not a credential verdict: {error}"
        );
    }

    /// The server's verdict arrives as a connection close rather than a
    /// message, so `connect` has to read the close code instead of reporting
    /// the stream error it sees first.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_capability_asks_for_a_fresh_bootstrap() {
        let server = start_test_server(Verdict::Reject(REMOTE_QUIC_CLOSE_AUTH));
        let error = QuicSession::connect(QuicClientParams {
            candidates: vec![server.address],
            fingerprint: server.fingerprint,
            hello: test_hello(2),
        })
        .await
        .expect_err("a refused capability cannot yield a session");
        assert!(
            matches!(error, ConnectError::Rejected(SessionExit::Rebootstrap(_))),
            "an AUTH close must invalidate the cached credential: {error}"
        );
    }

    /// Two dead candidates each burn the full per-candidate QUIC connect
    /// budget. Dialing them in parallel must cost about one budget, not two,
    /// so a host with both an AAAA and an A record is not punished.
    #[test]
    fn quic_candidates_are_dialed_in_parallel() {
        // Bound but never read: the handshake gets no response and times out.
        let silent = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind silent");
        let silent_alias =
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind silent alias");
        let candidates = vec![
            silent.local_addr().expect("silent address"),
            silent_alias.local_addr().expect("silent alias address"),
        ];

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let started = Instant::now();
        let error = runtime
            .block_on(QuicSession::connect(QuicClientParams {
                candidates: candidates.clone(),
                fingerprint: [9u8; REMOTE_QUIC_HASH_BYTES],
                hello: test_hello(1),
            }))
            .expect_err("silent candidates cannot complete a handshake");
        let elapsed = started.elapsed();

        let ConnectError::Timeout(detail) = &error else {
            panic!("a silent path is a timeout, not {error}");
        };
        for candidate in &candidates {
            assert!(
                detail.contains(&candidate.to_string()),
                "every candidate must be reported: {detail}"
            );
        }
        // Sequential dialing would need two full CONNECT_TIMEOUT budgets;
        // parallel dialing needs one plus the stagger.
        assert!(
            elapsed < CONNECT_TIMEOUT + DIAL_STAGGER * 5,
            "parallel dial took {elapsed:?}"
        );
    }

    #[test]
    fn address_change_evidence_rebinds_at_once_and_re_arms_the_silence_timer() {
        let now = Instant::now();
        let mut monitor = PathMonitor::new(now);
        assert!(monitor.on_tick(now).probe);
        monitor.probe_sent(now);

        // Evidence at +1 s: rebind immediately, no state change.
        let t1 = now + Duration::from_secs(1);
        assert!(monitor.address_changed(t1));
        assert_eq!(monitor.state(), PathState::Live);
        // The silence-timer rebind is re-armed from the evidence rebind: at
        // +10 s (REBIND_AFTER after the oldest probe) nothing fires; at
        // +11 s it does.
        let t10 = now + REBIND_AFTER;
        assert!(
            !monitor.on_tick(t10).rebind,
            "evidence rebind must re-arm the timer"
        );
        let t11 = t1 + REBIND_AFTER;
        assert!(monitor.on_tick(t11).rebind);
    }

    #[test]
    fn address_changes_inside_the_debounce_window_are_deferred_not_dropped() {
        let now = Instant::now();
        let mut monitor = PathMonitor::new(now);
        // A frame just arrived, so the next liveness deadline is a full
        // heartbeat away and the debounce window is what sets the deadline.
        assert_eq!(monitor.received(now), None);
        assert!(monitor.address_changed(now));
        // A second change 100 ms later is inside the window.
        let t100 = now + Duration::from_millis(100);
        assert!(!monitor.address_changed(t100));
        // The deferred rebind is due at the end of the window, ahead of the
        // heartbeat.
        assert_eq!(monitor.next_deadline(t100), now + REBIND_DEBOUNCE);
        let early = monitor.on_tick(now + Duration::from_millis(400));
        assert!(
            !early.rebind,
            "the debounce must hold until the window ends"
        );
        let due = monitor.on_tick(now + REBIND_DEBOUNCE);
        assert!(
            due.rebind && due.probe,
            "the deferred rebind fires with a probe"
        );
        assert_eq!(due.transition, None);
        // Once carried, it is not owed again.
        let after = monitor.on_tick(now + REBIND_DEBOUNCE + Duration::from_millis(1));
        assert!(!after.rebind);
        assert!(
            monitor.next_deadline(now + REBIND_DEBOUNCE) > now + REBIND_DEBOUNCE,
            "no deferred rebind must be pending"
        );
    }

    #[test]
    fn address_change_evidence_is_ignored_once_the_path_is_lost() {
        let now = Instant::now();
        let mut monitor = PathMonitor::new(now);
        monitor.probe_sent(now);
        let gone = monitor.on_tick(now + ROAMING_GRACE);
        assert_eq!(gone.transition, Some(PathState::Lost));
        assert!(!monitor.address_changed(now + ROAMING_GRACE + Duration::from_secs(1)));
        assert!(
            !monitor
                .on_tick(now + ROAMING_GRACE + Duration::from_secs(2))
                .rebind
        );
    }

    #[test]
    fn a_frame_between_two_evidence_rebinds_does_not_reset_the_debounce() {
        let now = Instant::now();
        let mut monitor = PathMonitor::new(now);
        assert!(monitor.address_changed(now));
        assert_eq!(monitor.received(now + Duration::from_millis(50)), None);
        assert!(
            !monitor.address_changed(now + Duration::from_millis(100)),
            "the debounce bounds rebinds per unit of time, not per outage"
        );
    }

    #[test]
    fn the_local_source_for_loopback_is_loopback() {
        let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 4433));
        assert_eq!(local_source_for(v4), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }
}
