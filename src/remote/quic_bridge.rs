//! Local Unix-socket bridge that carries the framed client protocol over an
//! SSH-bootstrapped QUIC connection, with the SSH stdio bridge as fallback.
//!
//! The bridge listens on a private local socket exactly like
//! [`super::attach::SshStdioBridge`]: the thin client connects to it and
//! speaks the ordinary `ClientMessage`/`ServerMessage` protocol. Each accepted
//! connection runs the transport ladder once — cached credential or SSH
//! bootstrap, QUIC dial, live pump, SSH fallback — and every frame it carries
//! is opaque. The only frames the bridge originates are health pings toward
//! the server, which drive path liveness when the client has none in flight,
//! and local-only transport status hints toward the thin client.
//!
//! One close policy: when a live QUIC connection ends, or the ladder gives up,
//! the local socket is closed. The server saw an ordinary client connection,
//! so resuming needs a fresh `Hello` and only the thin client's supervisor can
//! send one; its next connection reuses the cached credential and skips SSH.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use interprocess::local_socket::traits::Listener as _;
use interprocess::local_socket::ListenerNonblockingMode;
use serde::Serialize;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, Interest};
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tracing::{debug, info, warn};

use super::attach::{
    apply_managed_ssh_options, apply_noninteractive_ssh_options, bridge_connection, command_failed,
    remote_session_command, ManagedSshOptions, RemoteHerdr,
};
use super::frame::lock;
use super::process::wait_with_output_timeout;
use super::quic::{
    local_source_for, ConnectError, PathMonitor, PathState, QuicClientParams, QuicSession,
    SessionExit, ROAMING_GRACE,
};
use crate::config::RemoteTransportConfig;
use crate::platform::{open_address_change_source, AddressChangeSource};
use crate::protocol::endpoint::{HEALTH_PING_KIND, TRANSPORT_STATUS_KIND};
use crate::protocol::{
    ClientMessage, RemoteBootstrapRecord, RemoteQuicHello, ServerMessage, MAX_FRAME_SIZE,
    MAX_GRAPHICS_FRAME_SIZE, REMOTE_QUIC_ID_BYTES, REMOTE_QUIC_SCHEMA_VERSION,
};

const ACCEPT_POLL: Duration = Duration::from_millis(50);
const SOCKET_PERMISSION_MODE: u32 = 0o600;
/// Slice length for waits that must notice bridge shutdown promptly.
const SHUTDOWN_POLL: Duration = Duration::from_millis(100);
/// Length of the `[u32 LE len]` frame header the client protocol uses.
const FRAME_HEADER_BYTES: usize = 4;
/// Ceiling on a noninteractive bootstrap round trip. Interactive runs have a
/// human at the terminal who can answer a passphrase prompt, so they wait as
/// long as every other interactive `ssh` call in `attach.rs` does.
const BOOTSTRAP_SSH_TIMEOUT: Duration = Duration::from_secs(15);
/// Window in which a re-bootstrap keeps retrying. A server that just restarted
/// or completed a handoff can need a moment before it answers.
const REBOOTSTRAP_DEADLINE: Duration = Duration::from_secs(15);
const REBOOTSTRAP_RETRY_DELAY: Duration = Duration::from_millis(250);
/// First delay before redialing after a rejected dial, doubling per attempt up
/// to [`QUIC_RECONNECT_MAX_DELAY`]. Without it a dial that is rejected
/// immediately — a stale connection generation, say — spins full-speed TLS
/// handshakes on both ends.
const QUIC_RECONNECT_BASE_DELAY: Duration = Duration::from_millis(250);
const QUIC_RECONNECT_MAX_DELAY: Duration = Duration::from_secs(4);
/// Rejected dials tolerated in one run before handing the connection to SSH.
/// Backoff alone cannot repair a credential the server keeps refusing.
const MAX_CONSECUTIVE_QUIC_RETRIES: u32 = 5;
/// TCP connect budget for the SSH reachability probe that decides whether a
/// QUIC dial timeout means "UDP is filtered" or "the network is down".
const SSH_REACHABILITY_TIMEOUT: Duration = Duration::from_secs(3);
/// A cached credential is treated as spent this long before its real deadline,
/// so a dial started now cannot lose a race against the server's own expiry
/// check.
const CREDENTIAL_EXPIRY_SLACK: Duration = Duration::from_secs(30);
/// Application close code the bridge sends when it tears a connection down.
/// The server never interprets a client's close code — it only sees the
/// connection end — so one code covers every bridge-side close.
const CLOSE_BRIDGE_DONE: u32 = 0;

/// The QUIC path is carrying frames normally.
pub(crate) const TRANSPORT_STATE_LIVE: &str = "live";
/// The QUIC path is silent but not yet abandoned: the thin client stretches its
/// heartbeat deadline to the roaming grace and shows roaming, not reconnecting.
pub(crate) const TRANSPORT_STATE_RECOVERING: &str = "recovering";

pub(crate) struct QuicBridgeConfig {
    pub target: String,
    pub remote_herdr: RemoteHerdr,
    pub session: String,
    pub ssh_options: Option<ManagedSshOptions>,
    pub noninteractive: bool,
    pub transport: RemoteTransportConfig,
    pub logical_client_id: [u8; REMOTE_QUIC_ID_BYTES],
}

impl QuicBridgeConfig {
    /// One logical client per process: the token a bootstrap mints is scoped
    /// to it, and every local connection this process's bridges accept
    /// reconnects as the same logical client with a newer generation.
    pub(crate) fn process_logical_client_id() -> [u8; REMOTE_QUIC_ID_BYTES] {
        static ID: LazyLock<[u8; REMOTE_QUIC_ID_BYTES]> = LazyLock::new(|| {
            let mut id = [0u8; REMOTE_QUIC_ID_BYTES];
            if let Err(err) = getrandom::fill(&mut id) {
                // Fall back to process identity: the id only namespaces the
                // token; the token itself is the secret.
                warn!(%err, "system randomness unavailable for the remote client id");
                let pid = std::process::id().to_le_bytes();
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
                    .to_le_bytes();
                id[..4].copy_from_slice(&pid);
                id[4..].copy_from_slice(&nanos[..12]);
            }
            id
        });
        *ID
    }
}

/// Listener owning the local socket the thin client attaches to. Same shape as
/// [`super::attach::SshStdioBridge`]: a private socket, one accept thread, and
/// a stop flag that unblocks it.
pub(crate) struct QuicBridge {
    local_socket: PathBuf,
    socket_identity: crate::ipc::SocketFileIdentity,
    should_stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl QuicBridge {
    pub(crate) fn start(config: QuicBridgeConfig, local_socket: PathBuf) -> io::Result<Self> {
        crate::ipc::prepare_socket_path(&local_socket, |path| {
            format!("remote bridge is already listening at {}", path.display())
        })?;
        let listener = crate::ipc::bind_private_local_listener(&local_socket)?;
        let socket_identity = crate::ipc::socket_file_identity(&local_socket)?;
        if let Err(err) =
            crate::ipc::restrict_socket_permissions(&local_socket, SOCKET_PERMISSION_MODE)
        {
            let _ = crate::ipc::remove_socket_file_if_owned(&local_socket, &socket_identity);
            return Err(err);
        }
        if let Err(err) = listener.set_nonblocking(ListenerNonblockingMode::Accept) {
            let _ = crate::ipc::remove_socket_file_if_owned(&local_socket, &socket_identity);
            return Err(err);
        }

        let config = Arc::new(config);
        let should_stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&should_stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok(mut stream) => {
                        if let Err(err) = crate::ipc::set_local_stream_polling(&mut stream, false) {
                            tracing::error!(
                                error = %err,
                                "remote bridge failed to prepare client socket"
                            );
                            continue;
                        }
                        if let Err(err) = bridge_local_connection(stream, &config, &thread_stop) {
                            if config.noninteractive {
                                warn!(error = %err, "saved remote endpoint bridge failed");
                            } else {
                                eprintln!("herdr: remote bridge failed: {err}");
                            }
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_POLL);
                    }
                    Err(err) => {
                        if config.noninteractive {
                            warn!(error = %err, "saved remote endpoint listener failed");
                        } else {
                            eprintln!("herdr: remote bridge listener failed: {err}");
                        }
                        break;
                    }
                }
            }
        });

        Ok(Self {
            local_socket,
            socket_identity,
            should_stop,
            thread: Some(thread),
        })
    }
}

impl Drop for QuicBridge {
    fn drop(&mut self) {
        self.should_stop.store(true, Ordering::Release);
        let _ = crate::ipc::remove_socket_file_if_owned(&self.local_socket, &self.socket_identity);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Transport ladder
// ---------------------------------------------------------------------------

/// What the ladder does next for one accepted local connection.
#[derive(Clone, Debug, PartialEq, Eq)]
enum LadderStep {
    /// Dial QUIC with the credential in hand, after `delay`.
    ConnectQuic { delay: Duration },
    /// Discard the cached credential and mint a fresh one over SSH.
    Rebootstrap,
    /// Carry this connection on the SSH stdio bridge for the rest of its life.
    SshFallback(String),
    /// Close the local socket and let the thin client reconnect.
    CloseLocal(String),
    /// A dial to a server that has already carried QUIC timed out: check
    /// whether the SSH port answers before conceding the connection to SSH.
    ProbeSsh(String),
}

#[derive(Debug)]
enum LadderEvent {
    /// A usable credential is cached.
    Bootstrapped,
    /// No credential could be minted; a stock server rejects the hidden
    /// bootstrap subcommand, which is exactly how a fork client learns to stay
    /// on SSH.
    BootstrapFailed(String),
    ConnectFailed(ConnectError),
    /// A live session ended.
    SessionEnded(SessionExit),
    /// The SSH port accepted a TCP connection: the network is up, so a QUIC
    /// timeout means UDP really is filtered on this path.
    SshReachable,
    /// The SSH port did not answer either: the whole network is down, and
    /// nothing is gained by trying to carry the client over SSH.
    SshUnreachable(String),
}

/// Budget spent by one ladder run. A run covers a single local connection, so
/// the counters never carry over to the next client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LadderState {
    /// Dials rejected by the server so far, without reaching a live session.
    rejected_dials: u32,
    /// Whether this run already minted a fresh credential.
    rebootstrapped: bool,
    /// Whether the credential in hand has carried a live QUIC session before.
    /// A proven credential turns a dial timeout from "UDP is filtered here"
    /// into "the network is probably down", which SSH cannot fix either.
    credential_proven: bool,
    /// Whether this run already re-dialed QUIC after the SSH port answered.
    redialed_after_probe: bool,
}

/// The ladder, as a pure function of the run's budget and the latest event.
fn next_step(state: &mut LadderState, event: LadderEvent) -> LadderStep {
    match event {
        LadderEvent::Bootstrapped => {
            // A fresh credential resets the rejection budget: the dials that
            // spent it were refused for a credential that no longer exists.
            state.rejected_dials = 0;
            LadderStep::ConnectQuic {
                delay: Duration::ZERO,
            }
        }
        LadderEvent::BootstrapFailed(detail) => LadderStep::SshFallback(detail),
        // Every live session ends the run. The server treated the connection
        // as an ordinary client, so continuing needs a new Hello, which only
        // the thin client can send on its next connection — and that one
        // reuses the cached credential, so it costs no SSH.
        LadderEvent::SessionEnded(exit) => LadderStep::CloseLocal(exit.to_string()),
        // A dial that never reached the server says nothing about the
        // credential: only the path is suspect. On a path that never carried
        // QUIC, SSH is the answer. On one that did, an outage is far likelier
        // than a UDP filter appearing mid-session, and conceding to SSH at the
        // first sign of it would strand the client on SSH for the rest of the
        // connection the moment the network returns.
        LadderEvent::ConnectFailed(ConnectError::Timeout(detail)) => {
            if state.credential_proven && !state.redialed_after_probe {
                LadderStep::ProbeSsh(detail)
            } else {
                LadderStep::SshFallback(detail)
            }
        }
        LadderEvent::ConnectFailed(ConnectError::Other(detail)) => LadderStep::SshFallback(detail),
        // The network is up and UDP still failed: SSH gets one more QUIC dial
        // to beat before it carries the connection.
        LadderEvent::SshReachable => {
            state.redialed_after_probe = true;
            LadderStep::ConnectQuic {
                delay: Duration::ZERO,
            }
        }
        // Nothing answers. Give the connection back so the thin client's
        // supervisor paces the retries; the next one dials QUIC first again.
        LadderEvent::SshUnreachable(detail) => LadderStep::CloseLocal(detail),
        LadderEvent::ConnectFailed(ConnectError::Rejected(SessionExit::Superseded)) => {
            LadderStep::CloseLocal(SessionExit::Superseded.to_string())
        }
        LadderEvent::ConnectFailed(ConnectError::Rejected(SessionExit::Shutdown(detail))) => {
            LadderStep::CloseLocal(detail)
        }
        LadderEvent::ConnectFailed(ConnectError::Rejected(SessionExit::Rebootstrap(detail))) => {
            if state.rebootstrapped {
                // The credential this run minted was refused too, so the
                // server is not going to accept anything we can mint.
                LadderStep::SshFallback(detail)
            } else {
                state.rebootstrapped = true;
                LadderStep::Rebootstrap
            }
        }
        LadderEvent::ConnectFailed(ConnectError::Rejected(SessionExit::Retry(detail))) => {
            state.rejected_dials = state.rejected_dials.saturating_add(1);
            if state.rejected_dials >= MAX_CONSECUTIVE_QUIC_RETRIES {
                LadderStep::SshFallback(detail)
            } else {
                LadderStep::ConnectQuic {
                    delay: quic_reconnect_delay(state.rejected_dials),
                }
            }
        }
    }
}

/// Exponential backoff for the `attempt`-th rejected dial, capped so a long
/// outage still retries at a useful cadence.
fn quic_reconnect_delay(attempt: u32) -> Duration {
    QUIC_RECONNECT_BASE_DELAY
        .saturating_mul(
            1u32.checked_shl(attempt.saturating_sub(1))
                .unwrap_or(u32::MAX),
        )
        .min(QUIC_RECONNECT_MAX_DELAY)
}

/// Where an accepted local connection ended up.
enum RunOutcome {
    /// The run is over; dropping the local stream closes the socket.
    Done,
    /// Carry the connection on the SSH stdio bridge.
    Ssh {
        stream: crate::ipc::LocalStream,
        detail: String,
    },
}

/// Either the ladder continues with an event, or this run is finished.
enum Progress {
    Event(LadderEvent),
    Done,
}

fn bridge_local_connection(
    stream: crate::ipc::LocalStream,
    config: &Arc<QuicBridgeConfig>,
    should_stop: &Arc<AtomicBool>,
) -> io::Result<()> {
    let outcome = if config.transport == RemoteTransportConfig::Ssh {
        RunOutcome::Ssh {
            stream,
            detail: "remote.transport is set to ssh".to_owned(),
        }
    } else {
        run_quic_ladder(stream, config, should_stop)
    };

    match outcome {
        RunOutcome::Done => Ok(()),
        RunOutcome::Ssh { stream, detail } => {
            info!(
                target = %config.target,
                %detail,
                "carrying the remote client on the SSH stdio bridge"
            );
            bridge_connection(
                stream,
                &config.target,
                &config.remote_herdr,
                &config.session,
                config.ssh_options.as_ref(),
                config.noninteractive,
                should_stop,
            )
        }
    }
}

fn run_quic_ladder(
    stream: crate::ipc::LocalStream,
    config: &Arc<QuicBridgeConfig>,
    should_stop: &Arc<AtomicBool>,
) -> RunOutcome {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            return RunOutcome::Ssh {
                stream,
                detail: format!("failed to start the QUIC runtime: {err}"),
            }
        }
    };

    let key = credential_key(config);
    // Taken by whichever rung consumes the local connection: the QUIC pump, or
    // the SSH stdio bridge.
    let mut local = Some(stream);
    let mut state = LadderState::default();
    let mut step = LadderStep::ConnectQuic {
        delay: Duration::ZERO,
    };

    loop {
        let event = match step {
            LadderStep::ConnectQuic { delay } => {
                if !sleep_interruptible(delay, should_stop) {
                    return RunOutcome::Done;
                }
                match credential(config, &key) {
                    Err(detail) => LadderEvent::BootstrapFailed(detail),
                    Ok(credential) => {
                        state.credential_proven = credential.proven;
                        match connect_and_pump(
                            &runtime,
                            config,
                            credential,
                            &mut local,
                            should_stop,
                        ) {
                            Progress::Event(event) => {
                                if let LadderEvent::SessionEnded(exit) = &event {
                                    if credential_is_dead(exit) {
                                        drop_credential(&key);
                                    }
                                }
                                event
                            }
                            Progress::Done => return RunOutcome::Done,
                        }
                    }
                }
            }
            LadderStep::Rebootstrap => match rebootstrap(config, &key, should_stop) {
                Ok(()) => LadderEvent::Bootstrapped,
                Err(detail) => LadderEvent::BootstrapFailed(detail),
            },
            LadderStep::ProbeSsh(detail) => match ssh_port_reachable(config) {
                Ok(()) => {
                    debug!(target = %config.target, %detail, "SSH port answers; re-dialing QUIC once");
                    LadderEvent::SshReachable
                }
                Err(probe) => LadderEvent::SshUnreachable(format!(
                    "retryable: {detail}; SSH port unreachable too ({probe})"
                )),
            },
            LadderStep::SshFallback(detail) => {
                let Some(stream) = local.take() else {
                    // Unreachable: a live session always ends the run, so the
                    // local connection is still here whenever SSH is chosen.
                    return RunOutcome::Done;
                };
                return RunOutcome::Ssh { stream, detail };
            }
            LadderStep::CloseLocal(detail) => {
                info!(
                    target = %config.target,
                    %detail,
                    "closing the local remote socket; the client reconnects the ladder"
                );
                return RunOutcome::Done;
            }
        };
        step = next_step(&mut state, event);
    }
}

/// Dial the credential, then pump frames until the connection or the local
/// client ends.
fn connect_and_pump(
    runtime: &tokio::runtime::Runtime,
    config: &QuicBridgeConfig,
    credential: Credential,
    local: &mut Option<crate::ipc::LocalStream>,
    should_stop: &AtomicBool,
) -> Progress {
    let Credential {
        record,
        candidates,
        generation,
        proven: _,
    } = credential;
    let params = QuicClientParams {
        candidates,
        fingerprint: record.certificate_fingerprint,
        hello: RemoteQuicHello {
            schema_version: REMOTE_QUIC_SCHEMA_VERSION,
            server_instance_id: record.server_instance_id,
            logical_client_id: config.logical_client_id,
            capability_token: record.capability_token,
            connection_generation: generation,
        },
    };

    let (session, send, recv) = match runtime.block_on(QuicSession::connect(params)) {
        Ok(connected) => connected,
        Err(err) => return Progress::Event(LadderEvent::ConnectFailed(err)),
    };

    let Some(stream) = local.take() else {
        // Unreachable: only one dial per run reaches this point.
        session.close(CLOSE_BRIDGE_DONE, b"bridge done");
        return Progress::Done;
    };
    let stream = match into_std_stream(stream) {
        Ok(stream) => stream,
        Err(err) => {
            warn!(error = %err, "remote bridge could not hand the local socket to QUIC");
            session.close(CLOSE_BRIDGE_DONE, b"bridge done");
            return Progress::Done;
        }
    };

    info!(
        target = %config.target,
        generation,
        "remote QUIC transport connected"
    );
    mark_credential_proven(&credential_key(config));
    let exit = runtime.block_on(run_pump(&session, send, recv, stream, should_stop));
    session.close(CLOSE_BRIDGE_DONE, b"bridge done");

    match exit {
        PumpExit::LocalClosed | PumpExit::Stopped => Progress::Done,
        PumpExit::Closed(exit) => Progress::Event(LadderEvent::SessionEnded(exit)),
        PumpExit::Ended(detail) => {
            Progress::Event(LadderEvent::SessionEnded(SessionExit::Retry(detail)))
        }
    }
}

/// Whether the credential the bridge holds is worth keeping after this exit.
fn credential_is_dead(exit: &SessionExit) -> bool {
    match exit {
        SessionExit::Rebootstrap(_) => true,
        // The server process is gone, and the port, certificate, and instance
        // id died with it.
        SessionExit::Shutdown(_) => true,
        SessionExit::Retry(_) | SessionExit::Superseded => false,
    }
}

/// Sleep in slices so a reconnect backoff never delays bridge shutdown.
/// Returns false when the bridge is stopping.
fn sleep_interruptible(total: Duration, should_stop: &AtomicBool) -> bool {
    let deadline = Instant::now() + total;
    loop {
        if should_stop.load(Ordering::Acquire) {
            return false;
        }
        let now = Instant::now();
        if now >= deadline {
            return true;
        }
        thread::sleep(deadline.saturating_duration_since(now).min(SHUTDOWN_POLL));
    }
}

// ---------------------------------------------------------------------------
// Frame pump
// ---------------------------------------------------------------------------

/// Why the live pump stopped.
#[derive(Debug)]
enum PumpExit {
    /// The thin client hung up.
    LocalClosed,
    /// Bridge shutdown was requested.
    Stopped,
    /// The QUIC connection closed, classified by what may happen next.
    Closed(SessionExit),
    /// The pipe ended locally — path lost, stream error — so the next
    /// connection has to be a brand-new one.
    Ended(String),
}

/// Copy frames between the local socket and the QUIC stream until one side
/// ends, while [`PathMonitor`] probes and rebinds the path underneath.
async fn run_pump(
    session: &QuicSession,
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    local: std::os::unix::net::UnixStream,
    should_stop: &AtomicBool,
) -> PumpExit {
    let local = match tokio::net::UnixStream::from_std(local) {
        Ok(local) => local,
        Err(err) => return PumpExit::Ended(format!("failed to register the local socket: {err}")),
    };
    let (mut local_read, local_write) = local.into_split();
    let send = AsyncMutex::new(send);
    let local_write = AsyncMutex::new(local_write);
    // Depth one: the monitor only needs to know that *something* arrived, so a
    // receipt dropped because one is already pending loses no information.
    let (receipts_tx, receipts_rx) = mpsc::channel(1);

    let uplink = async {
        match copy_frames(&mut local_read, &send, MAX_FRAME_SIZE, None).await {
            Ok(()) => PumpExit::LocalClosed,
            Err(detail) => PumpExit::Ended(detail),
        }
    };
    let downlink = async {
        match copy_frames(
            &mut recv,
            &local_write,
            MAX_GRAPHICS_FRAME_SIZE,
            Some(receipts_tx),
        )
        .await
        {
            Ok(()) => PumpExit::Ended("remote QUIC stream ended".to_owned()),
            Err(detail) => PumpExit::Ended(detail),
        }
    };
    let monitor = drive_path(session, &send, &local_write, receipts_rx);
    let stop = wait_for_stop(should_stop);
    tokio::pin!(uplink, downlink, monitor, stop);

    tokio::select! {
        exit = &mut uplink => exit,
        exit = &mut downlink => exit,
        exit = &mut monitor => exit,
        exit = session.closed() => PumpExit::Closed(exit),
        () = &mut stop => PumpExit::Stopped,
    }
}

/// Copy length-prefixed frames from `reader` to `writer` until the reader ends
/// cleanly.
///
/// Frames stay opaque: the bridge reads the `[u32 LE len]` header only to keep
/// frame alignment, which is what lets it slip a frame of its own between two
/// forwarded ones. `receipts` is notified as soon as a frame has been read, so
/// path liveness never waits on the far side of the copy draining it.
async fn copy_frames<R, W>(
    reader: &mut R,
    writer: &AsyncMutex<W>,
    max: usize,
    receipts: Option<mpsc::Sender<()>>,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut payload = Vec::new();
    loop {
        if !read_frame(reader, max, &mut payload).await? {
            return Ok(());
        }
        if let Some(receipts) = &receipts {
            let _ = receipts.try_send(());
        }
        let mut writer = writer.lock().await;
        write_frame(&mut *writer, &payload).await?;
    }
}

/// Read one `[u32 LE len][payload]` frame into `payload`. `Ok(false)` means the
/// reader ended cleanly on a frame boundary.
async fn read_frame<R>(reader: &mut R, max: usize, payload: &mut Vec<u8>) -> Result<bool, String>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_BYTES];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(err) => return Err(format!("frame header read failed: {err}")),
    }
    let claimed = u32::from_le_bytes(header) as usize;
    if claimed > max {
        return Err(format!(
            "frame of {claimed} bytes exceeds the {max}-byte limit"
        ));
    }
    payload.clear();
    payload.resize(claimed, 0);
    reader
        .read_exact(payload)
        .await
        .map_err(|err| format!("frame payload read failed: {err}"))?;
    Ok(true)
}

async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let length = u32::try_from(payload.len())
        .map_err(|_| format!("frame of {} bytes exceeds the length prefix", payload.len()))?;
    writer
        .write_all(&length.to_le_bytes())
        .await
        .map_err(|err| format!("frame header write failed: {err}"))?;
    writer
        .write_all(payload)
        .await
        .map_err(|err| format!("frame payload write failed: {err}"))?;
    writer
        .flush()
        .await
        .map_err(|err| format!("frame flush failed: {err}"))
}

/// Own path liveness for a live connection: probe on the monitor's schedule,
/// rebind the local socket when the kernel announces an address change that
/// moved this path's source address (or, failing such evidence, when the
/// silence looks like one), and tell the thin client when the path starts or
/// stops recovering.
async fn drive_path<S, L>(
    session: &QuicSession,
    send: &AsyncMutex<S>,
    local_write: &AsyncMutex<L>,
    mut receipts: mpsc::Receiver<()>,
) -> PumpExit
where
    S: AsyncWrite + Unpin,
    L: AsyncWrite + Unpin,
{
    // Encoded once: the probe is the same frame every time, and the client's
    // own pings pass through untouched, so a duplicate ping is harmless.
    let ping = match health_ping_frame() {
        Ok(ping) => ping,
        Err(detail) => return PumpExit::Ended(detail),
    };
    let mut monitor = PathMonitor::new(Instant::now());
    let remote = session.remote_addr();
    let watcher = open_address_change_watcher();
    let mut watcher_failed = false;
    let mut source_address = local_source_for(remote);

    loop {
        let deadline = tokio::time::Instant::from_std(monitor.next_deadline(Instant::now()));
        tokio::select! {
            announced = address_change_announced(if watcher_failed { None } else { watcher.as_ref() }) => {
                match announced {
                    Err(detail) => {
                        // The silence timer still rebinds; only the fast path is gone.
                        warn!(%detail, "address change notifications stopped; relying on the silence timer");
                        watcher_failed = true;
                    }
                    Ok(false) => {}
                    Ok(true) => {
                        let now = Instant::now();
                        let current = local_source_for(remote);
                        if current == source_address {
                            debug!(source = ?current, "network change announced; path source unchanged");
                        } else {
                            info!(previous = ?source_address, current = ?current, "local path source changed");
                            source_address = current;
                            if monitor.address_changed(now) {
                                match session.rebind() {
                                    Ok(()) => info!("remote QUIC socket rebound on address change"),
                                    Err(detail) => debug!(%detail, "remote QUIC socket rebind failed"),
                                }
                                let write = {
                                    let mut send = send.lock().await;
                                    write_frame(&mut *send, &ping).await
                                };
                                if let Err(detail) = write {
                                    return PumpExit::Ended(detail);
                                }
                                monitor.probe_sent(now);
                            }
                        }
                    }
                }
            }
            receipt = receipts.recv() => {
                if receipt.is_none() {
                    return PumpExit::Ended("remote QUIC stream ended".to_owned());
                }
                if let Some(state) = monitor.received(Instant::now()) {
                    info!(?state, "remote QUIC path recovered");
                    if let Err(detail) = announce_transport_state(local_write, state).await {
                        return PumpExit::Ended(detail);
                    }
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                let now = Instant::now();
                let outcome = monitor.on_tick(now);
                if outcome.probe {
                    let write = {
                        let mut send = send.lock().await;
                        write_frame(&mut *send, &ping).await
                    };
                    if let Err(detail) = write {
                        return PumpExit::Ended(detail);
                    }
                    monitor.probe_sent(now);
                }
                if outcome.rebind {
                    match session.rebind() {
                        Ok(()) => info!("remote QUIC socket rebound"),
                        Err(detail) => debug!(%detail, "remote QUIC socket rebind failed"),
                    }
                }
                match outcome.transition {
                    Some(PathState::Lost) => {
                        return PumpExit::Ended(format!(
                            "remote QUIC path was silent for more than {} s",
                            ROAMING_GRACE.as_secs()
                        ));
                    }
                    Some(state) => {
                        info!(?state, "remote QUIC path silent; recovering");
                        if let Err(detail) = announce_transport_state(local_write, state).await {
                            return PumpExit::Ended(detail);
                        }
                    }
                    None => {}
                }
            }
        }
    }
}

/// Registers the platform's address-change descriptor with the runtime, or
/// returns `None` where there is none: the silence timer is then the only
/// rebind trigger, exactly as before.
fn open_address_change_watcher() -> Option<AsyncFd<AddressChangeSource>> {
    let source = match open_address_change_source() {
        Ok(source) => source,
        Err(err) => {
            debug!(%err, "address change notifications unavailable; relying on the silence timer");
            return None;
        }
    };
    match AsyncFd::with_interest(source, Interest::READABLE) {
        Ok(watcher) => Some(watcher),
        Err(err) => {
            debug!(%err, "failed to register the address change source; relying on the silence timer");
            None
        }
    }
}

/// Resolves when the kernel has announced a change and says whether any of the
/// pending messages was address, link, or route evidence. Never resolves
/// without a watcher, so the branch simply stays idle in the select.
async fn address_change_announced(
    watcher: Option<&AsyncFd<AddressChangeSource>>,
) -> io::Result<bool> {
    let Some(watcher) = watcher else {
        return std::future::pending().await;
    };
    let mut guard = watcher.readable().await?;
    let changed = guard.get_inner().drain();
    // `drain` read until `EAGAIN`, so readiness is spent whatever it found.
    guard.clear_ready();
    changed
}

async fn wait_for_stop(should_stop: &AtomicBool) {
    while !should_stop.load(Ordering::Acquire) {
        tokio::time::sleep(SHUTDOWN_POLL).await;
    }
}

/// Inject the local-only transport status hint toward the thin client. It never
/// crosses the server API, so it is written straight into the local socket.
async fn announce_transport_state<W>(
    local_write: &AsyncMutex<W>,
    state: PathState,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let Some(state) = transport_state_name(state) else {
        return Ok(());
    };
    let frame = transport_status_frame(state)?;
    let mut writer = local_write.lock().await;
    write_frame(&mut *writer, &frame).await
}

fn transport_state_name(state: PathState) -> Option<&'static str> {
    match state {
        PathState::Live => Some(TRANSPORT_STATE_LIVE),
        PathState::Recovering => Some(TRANSPORT_STATE_RECOVERING),
        // A lost path closes the local socket; the client learns it from that,
        // not from a hint it may never get to read.
        PathState::Lost => None,
    }
}

fn transport_status_frame(state: &str) -> Result<Vec<u8>, String> {
    encode_frame(&ServerMessage::EndpointControl {
        kind: TRANSPORT_STATUS_KIND.to_owned(),
        data: format!(r#"{{"state":"{state}"}}"#),
    })
}

/// The bridge's own liveness probe. Upstream's health ping is a plain endpoint
/// control frame, so the server answers it without knowing a bridge exists.
fn health_ping_frame() -> Result<Vec<u8>, String> {
    encode_frame(&ClientMessage::EndpointControl {
        kind: HEALTH_PING_KIND.to_owned(),
        data: String::new(),
    })
}

fn encode_frame<M: Serialize>(message: &M) -> Result<Vec<u8>, String> {
    bincode::serde::encode_to_vec(message, bincode::config::standard())
        .map_err(|err| format!("failed to encode a bridge frame: {err}"))
}

/// Take the accepted local socket as a std `UnixStream` so the pump can hand it
/// to tokio. The `interprocess` stream is a thin wrapper around exactly this
/// descriptor.
fn into_std_stream(stream: crate::ipc::LocalStream) -> io::Result<std::os::unix::net::UnixStream> {
    let crate::ipc::LocalStream::UdSocket(stream) = stream;
    let stream = std::os::unix::net::UnixStream::from(std::os::fd::OwnedFd::from(stream));
    stream.set_nonblocking(true)?;
    Ok(stream)
}

// ---------------------------------------------------------------------------
// Credential cache
// ---------------------------------------------------------------------------

/// A credential reserved for one dial.
struct Credential {
    record: RemoteBootstrapRecord,
    candidates: Vec<SocketAddr>,
    /// Connection generation this dial presents.
    generation: u64,
    /// Whether this credential has carried a live QUIC session before.
    proven: bool,
}

struct CachedCredential {
    record: RemoteBootstrapRecord,
    candidates: Vec<SocketAddr>,
    /// Generation the next dial will present. Monotonic per credential, so the
    /// server fences the older connection out when a redial replaces it.
    next_connection_generation: u64,
    /// Set once a dial with this credential reached a live session.
    proven: bool,
}

/// Keyed by target and session, which is exactly what the token is scoped to.
type CredentialKey = (String, String);
type CredentialCache = HashMap<CredentialKey, CachedCredential>;

/// Process-wide: a reconnecting thin client opens a fresh local connection, and
/// the whole point of caching the credential is that the new connection dials
/// QUIC without another SSH round trip.
static CREDENTIAL_CACHE: LazyLock<Mutex<CredentialCache>> =
    LazyLock::new(|| Mutex::new(CredentialCache::new()));

fn credential_key(config: &QuicBridgeConfig) -> CredentialKey {
    (config.target.clone(), config.session.clone())
}

/// Hand out the cached credential for `key`, reserving the next connection
/// generation. An expired credential is evicted instead: the server would
/// refuse it, and refusals cost a round trip on both ends.
fn reserve_cached_credential(
    cache: &mut CredentialCache,
    key: &CredentialKey,
    now_unix: u64,
) -> Option<Credential> {
    let entry = cache.get_mut(key)?;
    if entry.record.expires_unix_seconds
        <= now_unix.saturating_add(CREDENTIAL_EXPIRY_SLACK.as_secs())
    {
        cache.remove(key);
        return None;
    }
    let generation = entry.next_connection_generation;
    entry.next_connection_generation = generation.saturating_add(1);
    Some(Credential {
        record: entry.record.clone(),
        candidates: entry.candidates.clone(),
        generation,
        proven: entry.proven,
    })
}

fn store_credential(
    cache: &mut CredentialCache,
    key: CredentialKey,
    record: RemoteBootstrapRecord,
    candidates: Vec<SocketAddr>,
) {
    cache.insert(
        key,
        CachedCredential {
            record,
            candidates,
            next_connection_generation: 1,
            proven: false,
        },
    );
}

fn mark_credential_proven(key: &CredentialKey) {
    if let Some(entry) = lock(&CREDENTIAL_CACHE).get_mut(key) {
        entry.proven = true;
    }
}

fn drop_credential(key: &CredentialKey) {
    lock(&CREDENTIAL_CACHE).remove(key);
}

/// Plant a credential so the next local connection dials QUIC straight away.
/// Lets a test drive the real ladder — dial, pump, path monitor — without an
/// SSH round trip, and lets it point the dial at a shaped relay instead of the
/// port the server actually published.
#[cfg(test)]
pub(super) fn seed_credential_for_test(
    config: &QuicBridgeConfig,
    record: RemoteBootstrapRecord,
    candidates: Vec<SocketAddr>,
) {
    store_credential(
        &mut lock(&CREDENTIAL_CACHE),
        credential_key(config),
        record,
        candidates,
    );
}

#[cfg(test)]
pub(super) fn forget_credential_for_test(config: &QuicBridgeConfig) {
    drop_credential(&credential_key(config));
}

/// Reserve a dial's worth of credential, minting one over SSH when the cache
/// has none. The SSH round trip runs outside the lock so a slow bootstrap
/// cannot stall another local connection.
fn credential(config: &QuicBridgeConfig, key: &CredentialKey) -> Result<Credential, String> {
    if let Some(credential) =
        reserve_cached_credential(&mut lock(&CREDENTIAL_CACHE), key, now_unix())
    {
        return Ok(credential);
    }
    bootstrap_credential(config, key)?;
    reserve_cached_credential(&mut lock(&CREDENTIAL_CACHE), key, now_unix())
        .ok_or_else(|| "remote QUIC credential expired on arrival".to_owned())
}

/// Mint a credential over the authenticated SSH path and cache it.
fn bootstrap_credential(config: &QuicBridgeConfig, key: &CredentialKey) -> Result<(), String> {
    let hostname = resolve_ssh_hostname(config).map_err(|err| err.to_string())?;
    let record = request_remote_quic_bootstrap(config).map_err(|err| err.to_string())?;
    if record.schema_version != REMOTE_QUIC_SCHEMA_VERSION {
        return Err(format!(
            "remote QUIC bootstrap schema {} is not {REMOTE_QUIC_SCHEMA_VERSION}",
            record.schema_version
        ));
    }
    let candidates =
        remote_quic_candidates(&hostname, record.port).map_err(|err| err.to_string())?;
    store_credential(
        &mut lock(&CREDENTIAL_CACHE),
        key.clone(),
        record,
        candidates,
    );
    Ok(())
}

/// Replace a credential the server refused, retrying inside
/// [`REBOOTSTRAP_DEADLINE`] because a server that just restarted or handed off
/// can need a moment before it answers.
fn rebootstrap(
    config: &QuicBridgeConfig,
    key: &CredentialKey,
    should_stop: &AtomicBool,
) -> Result<(), String> {
    drop_credential(key);
    let deadline = Instant::now() + REBOOTSTRAP_DEADLINE;
    loop {
        match bootstrap_credential(config, key) {
            Ok(()) => return Ok(()),
            Err(detail) if Instant::now() < deadline => {
                debug!(%detail, "remote QUIC bootstrap not ready; retrying");
                if !sleep_interruptible(REBOOTSTRAP_RETRY_DELAY, should_stop) {
                    return Err(detail);
                }
            }
            Err(detail) => return Err(detail),
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// SSH bootstrap
// ---------------------------------------------------------------------------

/// `herdr [--session S] remote-quic-bootstrap <client id>` on the remote host.
fn remote_quic_bootstrap_command(
    remote_herdr: &RemoteHerdr,
    session: &str,
    logical_client_id: &[u8; REMOTE_QUIC_ID_BYTES],
) -> String {
    remote_session_command(
        remote_herdr,
        session,
        &format!(
            "remote-quic-bootstrap {}",
            format_logical_client_id(logical_client_id)
        ),
    )
}

fn format_logical_client_id(value: &[u8; REMOTE_QUIC_ID_BYTES]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(REMOTE_QUIC_ID_BYTES * 2);
    for byte in value {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

/// Ask the remote server for a QUIC credential over SSH. A stock server has no
/// such subcommand and fails, which is how a fork client learns to stay on SSH.
/// The token is never logged.
fn request_remote_quic_bootstrap(config: &QuicBridgeConfig) -> io::Result<RemoteBootstrapRecord> {
    let mut command = Command::new("ssh");
    apply_managed_ssh_options(&mut command, config.ssh_options.as_ref());
    if config.noninteractive {
        apply_noninteractive_ssh_options(&mut command);
    }
    command
        .arg("-T")
        .arg(&config.target)
        .arg(remote_quic_bootstrap_command(
            &config.remote_herdr,
            &config.session,
            &config.logical_client_id,
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = if config.noninteractive {
        wait_with_output_timeout(command.spawn()?, BOOTSTRAP_SSH_TIMEOUT)?
    } else {
        command.output()?
    };
    if !output.status.success() {
        return Err(bootstrap_failed(&output));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|err| io::Error::other(format!("invalid remote QUIC bootstrap response: {err}")))
}

fn bootstrap_failed(output: &Output) -> io::Error {
    command_failed("remote QUIC bootstrap failed", output)
}

/// Resolve the target's real hostname the way OpenSSH does, so QUIC dials the
/// host the SSH session actually reached rather than an alias.
fn resolve_ssh_hostname(config: &QuicBridgeConfig) -> io::Result<String> {
    resolve_ssh_endpoint(config).map(|(hostname, _)| hostname)
}

/// The host and port OpenSSH would actually connect to for `config.target`.
fn resolve_ssh_endpoint(config: &QuicBridgeConfig) -> io::Result<(String, u16)> {
    let mut command = Command::new("ssh");
    apply_managed_ssh_options(&mut command, config.ssh_options.as_ref());
    let output = command.arg("-G").arg(&config.target).output()?;
    if !output.status.success() {
        return Err(command_failed("failed to resolve SSH target", &output));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let hostname = stdout
        .lines()
        .find_map(|line| line.strip_prefix("hostname "))
        .map(str::trim)
        .filter(|hostname| !hostname.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| io::Error::other("ssh -G did not report a hostname"))?;
    let port = stdout
        .lines()
        .find_map(|line| line.strip_prefix("port "))
        .and_then(|port| port.trim().parse::<u16>().ok())
        .unwrap_or(22);
    Ok((hostname, port))
}

/// Whether the SSH port completes a TCP handshake inside
/// [`SSH_REACHABILITY_TIMEOUT`]. Distinguishes a filtered UDP path (SSH
/// answers) from a dead network (nothing answers) without spawning ssh or
/// authenticating.
fn ssh_port_reachable(config: &QuicBridgeConfig) -> io::Result<()> {
    let (hostname, port) = resolve_ssh_endpoint(config)?;
    let mut last_error = io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        format!("SSH hostname {hostname} has no IP addresses"),
    );
    for address in (hostname.as_str(), port).to_socket_addrs()? {
        match std::net::TcpStream::connect_timeout(&address, SSH_REACHABILITY_TIMEOUT) {
            Ok(_) => return Ok(()),
            Err(err) => last_error = err,
        }
    }
    Err(last_error)
}

fn remote_quic_candidates(hostname: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let mut seen = HashSet::new();
    // IPv6 first, then IPv4: the dial set is staggered in this order, so this
    // is the preference order for a tie. Duplicates are dropped outright
    // because a repeated address would waste a parallel dial.
    let mut candidates = (hostname, port)
        .to_socket_addrs()?
        .filter(|candidate| seen.insert(*candidate))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| if candidate.is_ipv6() { 0 } else { 1 });
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("SSH hostname {hostname} has no IP addresses"),
        ));
    }
    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{read_message, REMOTE_QUIC_HASH_BYTES, REMOTE_QUIC_TOKEN_BYTES};

    fn record(expires_unix_seconds: u64) -> RemoteBootstrapRecord {
        RemoteBootstrapRecord {
            schema_version: REMOTE_QUIC_SCHEMA_VERSION,
            server_instance_id: [7; REMOTE_QUIC_ID_BYTES],
            port: 48_001,
            certificate_fingerprint: [9; REMOTE_QUIC_HASH_BYTES],
            capability_token: [3; REMOTE_QUIC_TOKEN_BYTES],
            expires_unix_seconds,
        }
    }

    fn key() -> CredentialKey {
        ("fedora".to_owned(), "default".to_owned())
    }

    /// End to end over the real machinery: `ssh localhost` runs this build's
    /// `remote-quic-bootstrap` in a throwaway named session (starting that
    /// session's server daemon), the bridge dials QUIC with the minted
    /// credential, and a thin client handshake completes through the pipe.
    /// Needs passwordless `ssh localhost`; never touches the default session.
    #[test]
    #[ignore = "live: needs passwordless ssh localhost and a built target/debug/herdr"]
    fn live_loopback_quic_bridge_carries_a_client_handshake() {
        use std::process::Command;

        let herdr = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/debug/herdr");
        assert!(herdr.is_file(), "build herdr first: {}", herdr.display());
        let session = format!("quicrepro-{}", std::process::id());
        let stop_session = || {
            let _ = Command::new(&herdr)
                .args(["--session", &session, "server", "stop"])
                .env_remove("HERDR_SOCKET_PATH")
                .env_remove("HERDR_CLIENT_SOCKET_PATH")
                .env_remove(crate::session::SESSION_ENV_VAR)
                .output();
        };

        let remote_herdr = RemoteHerdr::for_test_binary(&herdr);

        // Capture this test's tracing so the assertion below can tell a QUIC
        // handshake from a silent SSH fallback.
        #[derive(Clone, Default)]
        struct Log(Arc<Mutex<Vec<u8>>>);
        impl io::Write for Log {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                lock(&self.0).extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let log = Log::default();
        let writer = log.clone();
        // Global, not thread-local: the bridge logs from its accept thread
        // and the pump runtime. Fails only if another test installed one.
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(move || writer.clone())
                .finish(),
        )
        .expect("live test owns the global tracing subscriber");
        let local_socket = std::env::temp_dir().join(format!("herdr-quic-live-{}.sock", session));
        let bridge = QuicBridge::start(
            QuicBridgeConfig {
                target: "localhost".to_owned(),
                remote_herdr,
                session: session.clone(),
                ssh_options: None,
                noninteractive: true,
                transport: RemoteTransportConfig::Auto,
                logical_client_id: QuicBridgeConfig::process_logical_client_id(),
            },
            local_socket.clone(),
        )
        .expect("bridge starts");

        let result = std::panic::catch_unwind(|| {
            let mut client = std::os::unix::net::UnixStream::connect(&local_socket)
                .expect("connect to bridge socket");
            client
                .set_read_timeout(Some(Duration::from_secs(60)))
                .expect("read timeout");
            crate::protocol::write_message(
                &mut client,
                &ClientMessage::TerminalHello {
                    version: crate::protocol::PROTOCOL_VERSION,
                    cols: 80,
                    rows: 24,
                    cell_width_px: 8,
                    cell_height_px: 16,
                    pixel_mouse: false,
                },
            )
            .expect("write hello");
            let welcome: ServerMessage =
                read_message(&mut client, crate::protocol::MAX_FRAME_SIZE).expect("read welcome");
            assert!(
                matches!(welcome, ServerMessage::Welcome { error: None, .. }),
                "{welcome:?}"
            );
            let cached = lock(&CREDENTIAL_CACHE)
                .get(&("localhost".to_owned(), session.clone()))
                .map(|credential| credential.record.port);
            assert!(
                cached.is_some(),
                "no QUIC credential was cached, so the handshake ran over SSH"
            );
            let log = String::from_utf8_lossy(&lock(&log.0)).into_owned();
            assert!(
                log.contains("remote QUIC transport connected"),
                "handshake did not run over QUIC:\n{log}"
            );
            assert!(
                !log.contains("carrying the remote client on the SSH stdio bridge"),
                "bridge fell back to SSH:\n{log}"
            );
            eprintln!(
                "QUIC credential minted for UDP port {}",
                cached.unwrap_or(0)
            );
        });

        drop(bridge);
        stop_session();
        let _ = std::fs::remove_file(&local_socket);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn unreachable_paths_hand_the_connection_to_ssh() {
        let mut state = LadderState::default();
        assert_eq!(
            next_step(
                &mut state,
                LadderEvent::ConnectFailed(ConnectError::Timeout("no answer".to_owned()))
            ),
            LadderStep::SshFallback("no answer".to_owned())
        );
        assert_eq!(
            next_step(
                &mut state,
                LadderEvent::ConnectFailed(ConnectError::Other("no socket".to_owned()))
            ),
            LadderStep::SshFallback("no socket".to_owned())
        );
        assert_eq!(
            next_step(
                &mut state,
                LadderEvent::BootstrapFailed("unknown subcommand".to_owned())
            ),
            LadderStep::SshFallback("unknown subcommand".to_owned())
        );
    }

    #[test]
    fn a_proven_path_checks_ssh_before_conceding_to_it() {
        let mut state = LadderState {
            credential_proven: true,
            ..LadderState::default()
        };
        let timeout = || LadderEvent::ConnectFailed(ConnectError::Timeout("no answer".to_owned()));
        // Network down: nothing answers, so hand the connection back for a
        // paced retry instead of stranding it on SSH once the network returns.
        assert_eq!(
            next_step(&mut state, timeout()),
            LadderStep::ProbeSsh("no answer".to_owned())
        );
        assert_eq!(
            next_step(&mut state, LadderEvent::SshUnreachable("down".to_owned())),
            LadderStep::CloseLocal("down".to_owned())
        );

        // UDP filtered: the SSH port answers, QUIC gets exactly one more dial,
        // and a second timeout concedes the connection to SSH.
        let mut state = LadderState {
            credential_proven: true,
            ..LadderState::default()
        };
        assert!(matches!(
            next_step(&mut state, timeout()),
            LadderStep::ProbeSsh(_)
        ));
        assert_eq!(
            next_step(&mut state, LadderEvent::SshReachable),
            LadderStep::ConnectQuic {
                delay: Duration::ZERO
            }
        );
        assert_eq!(
            next_step(&mut state, timeout()),
            LadderStep::SshFallback("no answer".to_owned())
        );

        // A credential that never carried QUIC keeps the plain fallback.
        let mut fresh = LadderState::default();
        assert_eq!(
            next_step(&mut fresh, timeout()),
            LadderStep::SshFallback("no answer".to_owned())
        );
    }

    #[test]
    fn a_refused_credential_rebootstraps_exactly_once() {
        let mut state = LadderState::default();
        assert_eq!(
            next_step(
                &mut state,
                LadderEvent::ConnectFailed(ConnectError::Rejected(SessionExit::Rebootstrap(
                    "unknown capability".to_owned()
                )))
            ),
            LadderStep::Rebootstrap
        );
        assert_eq!(
            next_step(&mut state, LadderEvent::Bootstrapped),
            LadderStep::ConnectQuic {
                delay: Duration::ZERO
            }
        );
        // The credential this run just minted was refused too: nothing the
        // bridge can mint will be accepted, so SSH carries the connection.
        assert_eq!(
            next_step(
                &mut state,
                LadderEvent::ConnectFailed(ConnectError::Rejected(SessionExit::Rebootstrap(
                    "unknown capability".to_owned()
                )))
            ),
            LadderStep::SshFallback("unknown capability".to_owned())
        );
    }

    #[test]
    fn rejected_dials_back_off_then_fall_back_to_ssh() {
        let mut state = LadderState::default();
        let mut delays = Vec::new();
        for _ in 0..MAX_CONSECUTIVE_QUIC_RETRIES {
            match next_step(
                &mut state,
                LadderEvent::ConnectFailed(ConnectError::Rejected(SessionExit::Retry(
                    "stale generation".to_owned(),
                ))),
            ) {
                LadderStep::ConnectQuic { delay } => delays.push(delay),
                LadderStep::SshFallback(detail) => {
                    assert_eq!(detail, "stale generation");
                    assert_eq!(
                        delays,
                        vec![
                            Duration::from_millis(250),
                            Duration::from_millis(500),
                            Duration::from_secs(1),
                            Duration::from_secs(2),
                        ]
                    );
                    return;
                }
                other => panic!("unexpected step: {other:?}"),
            }
        }
        panic!("the retry budget never ran out: {delays:?}");
    }

    #[test]
    fn reconnect_delay_is_bounded_and_monotonic() {
        assert_eq!(quic_reconnect_delay(1), QUIC_RECONNECT_BASE_DELAY);
        let mut previous = Duration::ZERO;
        for attempt in 1..=32 {
            let delay = quic_reconnect_delay(attempt);
            assert!(delay >= previous, "attempt {attempt} went backwards");
            assert!(
                delay <= QUIC_RECONNECT_MAX_DELAY,
                "attempt {attempt} ran away"
            );
            previous = delay;
        }
        assert_eq!(quic_reconnect_delay(32), QUIC_RECONNECT_MAX_DELAY);
    }

    #[test]
    fn a_superseded_or_shut_down_server_closes_the_local_socket() {
        let mut state = LadderState::default();
        assert!(matches!(
            next_step(
                &mut state,
                LadderEvent::ConnectFailed(ConnectError::Rejected(SessionExit::Superseded))
            ),
            LadderStep::CloseLocal(_)
        ));
        assert_eq!(
            next_step(
                &mut state,
                LadderEvent::ConnectFailed(ConnectError::Rejected(SessionExit::Shutdown(
                    "server is going away".to_owned()
                )))
            ),
            LadderStep::CloseLocal("server is going away".to_owned())
        );
    }

    #[test]
    fn every_live_session_ends_the_run() {
        // The server saw an ordinary client connection; resuming needs a fresh
        // Hello, so the ladder never redials inside the same run.
        for exit in [
            SessionExit::Retry("path lost".to_owned()),
            SessionExit::Rebootstrap("token evicted".to_owned()),
            SessionExit::Superseded,
            SessionExit::Shutdown("bridge done".to_owned()),
        ] {
            let mut state = LadderState::default();
            assert!(
                matches!(
                    next_step(&mut state, LadderEvent::SessionEnded(exit)),
                    LadderStep::CloseLocal(_)
                ),
                "a live session must close the local socket"
            );
        }
    }

    #[test]
    fn only_a_dead_credential_is_dropped_from_the_cache() {
        assert!(credential_is_dead(&SessionExit::Rebootstrap(
            "token evicted".to_owned()
        )));
        assert!(credential_is_dead(&SessionExit::Shutdown(
            "server gone".to_owned()
        )));
        assert!(!credential_is_dead(&SessionExit::Retry(
            "path lost".to_owned()
        )));
        assert!(!credential_is_dead(&SessionExit::Superseded));
    }

    #[test]
    fn a_cached_credential_fences_each_dial_with_a_newer_generation() {
        let mut cache = CredentialCache::new();
        store_credential(&mut cache, key(), record(10_000), Vec::new());

        let first = reserve_cached_credential(&mut cache, &key(), 1_000).expect("cached");
        let second = reserve_cached_credential(&mut cache, &key(), 1_000).expect("cached");
        assert_eq!(first.generation, 1);
        assert_eq!(second.generation, 2);
        assert_eq!(second.record.capability_token, record(0).capability_token);
    }

    #[test]
    fn an_expired_credential_is_evicted_instead_of_dialed() {
        let mut cache = CredentialCache::new();
        let expires_at = 10_000;
        store_credential(&mut cache, key(), record(expires_at), Vec::new());

        // Inside the expiry slack the server would refuse the dial, so the
        // credential is already spent.
        let too_late = expires_at - CREDENTIAL_EXPIRY_SLACK.as_secs();
        assert!(reserve_cached_credential(&mut cache, &key(), too_late).is_none());
        assert!(cache.is_empty(), "an expired credential must be evicted");
        assert!(reserve_cached_credential(&mut cache, &key(), 0).is_none());
    }

    #[tokio::test]
    async fn frames_cross_the_pump_intact() {
        let frames: Vec<Vec<u8>> = vec![
            vec![1, 2, 3],
            vec![0xAB; 100 * 1024],
            Vec::new(),
            vec![7; 17],
        ];
        let (mut source_in, mut source_out) = tokio::io::duplex(512 * 1024);
        let (dest_in, mut dest_out) = tokio::io::duplex(512 * 1024);
        for frame in &frames {
            write_frame(&mut source_in, frame).await.expect("write");
        }
        drop(source_in);

        let writer = AsyncMutex::new(dest_in);
        copy_frames(&mut source_out, &writer, MAX_FRAME_SIZE, None)
            .await
            .expect("clean end of the source");

        let mut payload = Vec::new();
        for expected in &frames {
            assert!(
                read_frame(&mut dest_out, MAX_FRAME_SIZE, &mut payload)
                    .await
                    .expect("read"),
                "a forwarded frame went missing"
            );
            assert_eq!(&payload, expected);
        }
    }

    #[tokio::test]
    async fn an_oversized_frame_is_refused_instead_of_forwarded() {
        let (mut source_in, mut source_out) = tokio::io::duplex(1024);
        let claimed = u32::try_from(MAX_FRAME_SIZE + 1).expect("fits u32");
        source_in
            .write_all(&claimed.to_le_bytes())
            .await
            .expect("write header");
        drop(source_in);

        let writer = AsyncMutex::new(Vec::new());
        let error = copy_frames(&mut source_out, &writer, MAX_FRAME_SIZE, None)
            .await
            .expect_err("an oversized frame must be refused");
        assert!(error.contains("exceeds"), "unexpected error: {error}");
        assert!(
            writer.lock().await.is_empty(),
            "an oversized frame must not be forwarded"
        );
    }

    #[test]
    fn the_injected_status_frame_is_a_readable_server_control() {
        for state in [TRANSPORT_STATE_LIVE, TRANSPORT_STATE_RECOVERING] {
            let payload = transport_status_frame(state).expect("encode");
            let mut framed = Vec::new();
            framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            framed.extend_from_slice(&payload);

            let decoded: ServerMessage =
                read_message(&mut framed.as_slice(), MAX_FRAME_SIZE).expect("decode");
            assert_eq!(
                decoded,
                ServerMessage::EndpointControl {
                    kind: TRANSPORT_STATUS_KIND.to_owned(),
                    data: format!(r#"{{"state":"{state}"}}"#),
                }
            );
        }
    }

    #[test]
    fn the_bridge_probe_is_a_readable_client_health_ping() {
        let payload = health_ping_frame().expect("encode");
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        framed.extend_from_slice(&payload);

        let decoded: ClientMessage =
            read_message(&mut framed.as_slice(), MAX_FRAME_SIZE).expect("decode");
        assert_eq!(
            decoded,
            ClientMessage::EndpointControl {
                kind: HEALTH_PING_KIND.to_owned(),
                data: String::new(),
            }
        );
    }

    #[test]
    fn a_lost_path_is_never_announced_to_the_client() {
        assert_eq!(
            transport_state_name(PathState::Live),
            Some(TRANSPORT_STATE_LIVE)
        );
        assert_eq!(
            transport_state_name(PathState::Recovering),
            Some(TRANSPORT_STATE_RECOVERING)
        );
        assert_eq!(transport_state_name(PathState::Lost), None);
    }

    #[test]
    fn candidates_prefer_ipv6_and_drop_duplicates() {
        let candidates = remote_quic_candidates("localhost", 48_000).expect("resolve localhost");
        let mut seen = HashSet::new();
        for candidate in &candidates {
            assert!(seen.insert(*candidate), "duplicate candidate {candidate}");
            assert_eq!(candidate.port(), 48_000);
        }
        let first_ipv4 = candidates.iter().position(|candidate| candidate.is_ipv4());
        let last_ipv6 = candidates.iter().rposition(|candidate| candidate.is_ipv6());
        if let (Some(first_ipv4), Some(last_ipv6)) = (first_ipv4, last_ipv6) {
            assert!(last_ipv6 < first_ipv4, "IPv6 candidates must come first");
        }
    }

    #[test]
    fn the_logical_client_id_is_lowercase_hex() {
        // The remote side parses this back with `from_str_radix`, so the
        // encoding is part of the bootstrap contract.
        let mut id = [0u8; REMOTE_QUIC_ID_BYTES];
        id[0] = 0x0a;
        id[REMOTE_QUIC_ID_BYTES - 1] = 0xff;
        let encoded = format_logical_client_id(&id);
        assert_eq!(encoded.len(), REMOTE_QUIC_ID_BYTES * 2);
        assert_eq!(encoded, "0a0000000000000000000000000000ff");
    }

    #[test]
    fn an_interrupted_backoff_returns_early() {
        let should_stop = AtomicBool::new(true);
        let started = Instant::now();
        assert!(!sleep_interruptible(Duration::from_secs(30), &should_stop));
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
