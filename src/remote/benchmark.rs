//! §8.4 benchmark: input-to-visible latency and frame cost of a real herdr
//! session carried over the real [`QuicBridge`], under a shaped 3G link and
//! deliberate blackout windows.
//!
//! Nothing here is a model of herdr. One in-process [`HeadlessServer`] runs a
//! real `/bin/sh` pane; a real direct-terminal client speaks the ordinary
//! `TerminalHello`/`Input`/`Terminal` protocol at it. The only synthetic part
//! is the network: a userspace UDP relay between the bridge and the server's
//! QUIC endpoint applies the 3G delay/jitter/bandwidth/loss profile and can
//! drop everything for a window.
//!
//! The arms are measured against the same server, in order, each with a fresh
//! bridge connection:
//!
//! * `direct` — client straight onto the server's Unix socket. Baseline: this
//!   is the server's own render latency with no transport at all.
//! * `quic_online` — client -> bridge -> QUIC -> relay (unshaped) -> server.
//! * `quic_3g` — the same path with the relay in 3G mode for the whole arm.
//! * `quic_3g_blackout` — 3G plus a 5 s and a 20 s outage.
//!
//! Run it with:
//!
//! ```text
//! cargo test --bin herdr -- --ignored --nocapture remote_quic_3g_benchmark
//! ```

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

use super::attach::RemoteHerdr;
use super::quic_bridge::{
    forget_credential_for_test, seed_credential_for_test, QuicBridge, QuicBridgeConfig,
};
use crate::config::RemoteTransportConfig;
use crate::protocol::{
    read_message, write_message, ClientMessage, RemoteBootstrapRecord, RemoteBootstrapRequest,
    ServerMessage, MAX_FRAME_SIZE, MAX_GRAPHICS_FRAME_SIZE, PROTOCOL_VERSION,
};

/// Markers typed per arm. Tail percentiles at the default are dominated by
/// which packets the loss pattern happens to drop; raise it for a stable p99.
const DEFAULT_KEYSTROKES: usize = 60;
/// Gap between markers, so each measurement starts from an idle link.
const KEYSTROKE_GAP: Duration = Duration::from_millis(250);
/// A marker not echoed inside this window counts as a lost keystroke.
const ECHO_TIMEOUT: Duration = Duration::from_secs(10);
/// A keystroke sent mid-blackout is echoed once the path recovers, which costs
/// the outage plus a QUIC loss-recovery round; it gets its own budget.
const RECOVERY_ECHO_TIMEOUT: Duration = Duration::from_secs(30);
/// Ceiling on "time from the relay reopening to the next frame".
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);
/// Frames the server paints on attach are not a measurement.
const SETTLE: Duration = Duration::from_millis(1500);
/// UDP range for this bench's server endpoint. Deliberately clear of the
/// 48000-48100 default so a live herdr on the same machine is untouched.
const QUIC_PORT_RANGE: &str = "48200-48260";
/// `^U`: erases the marker the shell just echoed, so the prompt line never
/// wraps and every marker is measured on a clean line.
const KILL_LINE: u8 = 0x15;
/// Rolling window of visible frame text searched for a marker echo. Frames are
/// diffs, so an echo can straddle two of them.
const VISIBLE_WINDOW: usize = 8 * 1024;
/// Characters in one marker. Long enough that no shell prompt or status text
/// can contain it by accident.
const MARKER_LENGTH: usize = 5;
const CLIENT_COLS: u16 = 100;
const CLIENT_ROWS: u16 = 30;

// ---------------------------------------------------------------------------
// Shaping
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetworkMode {
    /// Relay forwards immediately: measures the bridge, not the link.
    Online,
    ThreeG,
    /// Every datagram is dropped, in both directions.
    Blackhole,
}

/// Delay/jitter/bandwidth/loss model the relay applies per datagram.
#[derive(Clone, Copy)]
struct ShapingProfile {
    down_bytes_per_second: f64,
    up_bytes_per_second: f64,
    base_latency_ms: u64,
    jitter_span_ms: u64,
    /// `Some(n)` drops 1-in-`n` datagrams deterministically.
    loss_every_nth: Option<u64>,
}

/// 1.6 Mbit/s down, 0.75 Mbit/s up, 260-340 ms RTT, ~0.99% loss.
const THREE_G_PROFILE: ShapingProfile = ShapingProfile {
    down_bytes_per_second: 200_000.0,
    up_bytes_per_second: 93_750.0,
    base_latency_ms: 130,
    jitter_span_ms: 41,
    loss_every_nth: Some(101),
};

/// Userspace UDP relay standing in for the WAN hop: one socket, one client at
/// a time, `server` on the far side. Delay is per datagram and bandwidth is a
/// per-direction serialization queue, so a burst pays for itself.
async fn run_udp_proxy(
    socket: Arc<tokio::net::UdpSocket>,
    server: SocketAddr,
    mode: watch::Receiver<NetworkMode>,
    profile: ShapingProfile,
) {
    let mut client = None;
    let mut packet_index = 0u64;
    let mut buffer = vec![0u8; 65_535];
    let mut next_upstream = tokio::time::Instant::now();
    let mut next_downstream = tokio::time::Instant::now();
    loop {
        let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
            return;
        };
        let from_server = source == server;
        let target = if from_server {
            let Some(client) = client else { continue };
            client
        } else {
            client = Some(source);
            server
        };
        packet_index = packet_index.saturating_add(1);
        let current_mode = *mode.borrow();
        let lose_packet = profile
            .loss_every_nth
            .is_some_and(|n| packet_index.is_multiple_of(n));
        if matches!(current_mode, NetworkMode::Blackhole)
            || (matches!(current_mode, NetworkMode::ThreeG) && lose_packet)
        {
            continue;
        }
        let packet = buffer[..length].to_vec();
        let socket = Arc::clone(&socket);
        let delay = if matches!(current_mode, NetworkMode::ThreeG) {
            let rate = if from_server {
                profile.down_bytes_per_second
            } else {
                profile.up_bytes_per_second
            };
            let serialization = Duration::from_secs_f64(packet.len() as f64 / rate);
            let next_delivery = if from_server {
                &mut next_downstream
            } else {
                &mut next_upstream
            };
            let now = tokio::time::Instant::now();
            *next_delivery = (*next_delivery).max(now) + serialization;
            let jitter_ms = packet_index.wrapping_mul(17) % profile.jitter_span_ms;
            next_delivery
                .saturating_duration_since(now)
                .saturating_add(Duration::from_millis(profile.base_latency_ms + jitter_ms))
        } else {
            Duration::ZERO
        };
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = socket.send_to(&packet, target).await;
        });
    }
}

/// Owns the relay socket and its runtime. Dropping it closes the UDP socket.
struct ShapedRelay {
    address: SocketAddr,
    mode: watch::Sender<NetworkMode>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl ShapedRelay {
    fn start(server: SocketAddr) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("relay runtime");
        let socket = runtime
            .block_on(tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind relay socket");
        let address = socket.local_addr().expect("relay address");
        let (mode, mode_rx) = watch::channel(NetworkMode::Online);
        runtime.spawn(run_udp_proxy(
            Arc::new(socket),
            server,
            mode_rx,
            THREE_G_PROFILE,
        ));
        Self {
            address,
            mode,
            runtime: Some(runtime),
        }
    }

    fn set(&self, mode: NetworkMode) {
        let _ = self.mode.send(mode);
    }
}

impl Drop for ShapedRelay {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_millis(200));
        }
    }
}

// ---------------------------------------------------------------------------
// In-process server
// ---------------------------------------------------------------------------

/// A real headless server on a dedicated thread, with its config, data, and
/// socket paths inside one throwaway directory.
struct BenchServer {
    root: PathBuf,
    client_socket: PathBuf,
    /// Terminal id of the workspace's shell pane. A `TerminalHello` client is
    /// pending until it attaches to one, and the attached pane's ANSI stream
    /// is exactly what this bench measures.
    terminal_id: String,
    should_quit: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    /// Kept alive so the app's API receiver never sees a closed channel.
    _api_tx: tokio::sync::mpsc::UnboundedSender<crate::api::ApiRequestMessage>,
}

impl BenchServer {
    fn start() -> Self {
        Self::start_in(None)
    }

    /// Like [`Self::start`], but the server thread first enters the network
    /// namespace at `netns` (a file under `/var/run/netns`), so every socket
    /// the server and its runtime bind lives there. The Unix socket is a
    /// filesystem object and stays reachable from the root namespace.
    fn start_in(netns: Option<PathBuf>) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let root =
            std::env::temp_dir().join(format!("herdr-quic-bench-{}-{stamp}", std::process::id()));
        let cwd = root.join("cwd");
        std::fs::create_dir_all(root.join("config")).expect("bench config dir");
        std::fs::create_dir_all(root.join("data")).expect("bench data dir");
        std::fs::create_dir_all(root.join("run")).expect("bench runtime dir");
        std::fs::create_dir_all(&cwd).expect("bench cwd");

        // Every path the server derives has to land inside the throwaway root,
        // and the socket override has to be set before HeadlessServer::new
        // reads it.
        let client_socket = root.join("client.sock");
        std::env::set_var("XDG_CONFIG_HOME", root.join("config"));
        std::env::set_var("XDG_DATA_HOME", root.join("data"));
        std::env::set_var("XDG_RUNTIME_DIR", root.join("run"));
        std::env::remove_var(crate::api::SOCKET_PATH_ENV_VAR);
        std::env::remove_var(crate::session::SESSION_ENV_VAR);
        crate::session::clear_explicit_session_for_test();
        std::env::set_var(
            crate::server::socket_paths::CLIENT_SOCKET_PATH_ENV_VAR,
            &client_socket,
        );

        let mut config = crate::config::Config::default();
        config.terminal.default_shell = "/bin/sh".to_owned();
        config.remote.transport = RemoteTransportConfig::Auto;
        config.remote.quic_port_range = QUIC_PORT_RANGE.to_owned();

        let (api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let (terminal_tx, terminal_rx) = mpsc::channel();
        let should_quit = Arc::new(AtomicBool::new(false));
        let thread_quit = Arc::clone(&should_quit);
        let thread = thread::Builder::new()
            .name("quic-bench-server".to_owned())
            .spawn(move || {
                if let Some(netns) = netns {
                    enter_network_namespace(&netns);
                }
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("bench server runtime");
                runtime.block_on(async move {
                    let mut app = crate::app::App::new(
                        &config,
                        crate::app::AppPolicy::TEST,
                        None,
                        api_rx,
                        crate::api::EventHub::default(),
                    );
                    app.create_workspace_with_options(cwd, true)
                        .expect("bench workspace with a shell pane");
                    let terminal_id = app
                        .state
                        .workspaces
                        .first()
                        .and_then(|workspace| workspace.terminal_id(workspace.tabs[0].root_pane))
                        .map(ToString::to_string)
                        .expect("shell pane terminal id");
                    let _ = terminal_tx.send(terminal_id);
                    let mut server = crate::server::headless::HeadlessServer::new(
                        app,
                        &[],
                        config.remote.clone(),
                        None,
                        None,
                        thread_quit,
                    )
                    .expect("bench headless server");
                    if let Err(err) = server.run().await {
                        tracing::warn!(%err, "bench headless server exited with an error");
                    }
                });
                runtime.shutdown_timeout(Duration::from_millis(200));
            })
            .expect("spawn bench server thread");

        let terminal_id = terminal_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("server thread reports the shell pane terminal id");

        Self {
            root,
            client_socket,
            terminal_id,
            should_quit,
            thread: Some(thread),
            _api_tx: api_tx,
        }
    }

    /// Mint a QUIC credential over the client socket, which is also this
    /// bench's readiness probe: a served bootstrap proves the event loop runs.
    /// Retries until the socket exists and the loop answers.
    fn bootstrap(
        &self,
        logical_client_id: [u8; crate::protocol::REMOTE_QUIC_ID_BYTES],
    ) -> RemoteBootstrapRecord {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut last = String::from("server never accepted a connection");
        while Instant::now() < deadline {
            match self.try_bootstrap(logical_client_id) {
                Ok(record) => return record,
                Err(detail) => last = detail,
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("remote bootstrap never succeeded: {last}");
    }

    fn try_bootstrap(
        &self,
        logical_client_id: [u8; crate::protocol::REMOTE_QUIC_ID_BYTES],
    ) -> Result<RemoteBootstrapRecord, String> {
        let mut stream = UnixStream::connect(&self.client_socket).map_err(|err| err.to_string())?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|err| err.to_string())?;
        write_message(
            &mut stream,
            &ClientMessage::RemoteBootstrap(RemoteBootstrapRequest {
                session: crate::session::DEFAULT_SESSION_NAME.to_owned(),
                logical_client_id,
            }),
        )
        .map_err(|err| err.to_string())?;
        let response: ServerMessage =
            read_message(&mut stream, MAX_FRAME_SIZE).map_err(|err| err.to_string())?;
        match response {
            ServerMessage::RemoteBootstrap {
                record: Some(record),
                ..
            } => Ok(record),
            ServerMessage::RemoteBootstrap { error, .. } => {
                Err(error.unwrap_or_else(|| "bootstrap refused".to_owned()))
            }
            other => Err(format!("unexpected bootstrap response: {other:?}")),
        }
    }

    fn shutdown(&mut self) {
        self.should_quit.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Drop for BenchServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Move the calling thread into the network namespace at `path`. Threads it
/// spawns afterwards inherit it. Needs `CAP_SYS_ADMIN`.
fn enter_network_namespace(path: &Path) {
    use std::os::fd::AsRawFd as _;
    let file = std::fs::File::open(path).expect("open network namespace");
    let entered = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(
        entered,
        0,
        "setns({}): {}",
        path.display(),
        std::io::Error::last_os_error()
    );
}

// ---------------------------------------------------------------------------
// Semantic client
// ---------------------------------------------------------------------------

struct FrameEvent {
    at: Instant,
    bytes: usize,
    visible: Vec<u8>,
}

/// An ordinary direct-terminal client: `TerminalHello`, `AttachTerminal`, then
/// `Input` out and `Terminal` frames in. Frames are read on their own thread
/// so a measurement loop can wait on them with a deadline without ever timing
/// out mid-frame.
struct TerminalClient {
    stream: UnixStream,
    frames: mpsc::Receiver<FrameEvent>,
    reader: Option<JoinHandle<()>>,
    visible: Vec<u8>,
}

impl TerminalClient {
    fn connect(socket: &Path, terminal_id: &str) -> Self {
        let mut stream = UnixStream::connect(socket).expect("connect terminal client");
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .expect("client read timeout");
        write_message(
            &mut stream,
            &ClientMessage::TerminalHello {
                version: PROTOCOL_VERSION,
                cols: CLIENT_COLS,
                rows: CLIENT_ROWS,
                cell_width_px: 8,
                cell_height_px: 16,
                pixel_mouse: false,
            },
        )
        .expect("write terminal hello");
        let welcome: ServerMessage =
            read_message(&mut stream, MAX_FRAME_SIZE).expect("read welcome");
        assert!(
            matches!(welcome, ServerMessage::Welcome { error: None, .. }),
            "{welcome:?}"
        );
        // A `TerminalHello` connection is pending until it attaches: only an
        // attached (or observing) client is a render target, and its frames
        // are the pane's own ANSI stream.
        write_message(
            &mut stream,
            &ClientMessage::AttachTerminal {
                terminal_id: terminal_id.to_owned(),
                takeover: true,
            },
        )
        .expect("write attach terminal");
        stream
            .set_read_timeout(None)
            .expect("clear client read timeout");

        let mut reader_stream = stream.try_clone().expect("clone client socket");
        let (frames_tx, frames) = mpsc::channel();
        let reader = thread::Builder::new()
            .name("quic-bench-client".to_owned())
            .spawn(move || loop {
                let message: ServerMessage =
                    match read_message(&mut reader_stream, MAX_GRAPHICS_FRAME_SIZE) {
                        Ok(message) => message,
                        Err(_) => return,
                    };
                if let ServerMessage::Terminal(frame) = message {
                    let event = FrameEvent {
                        at: Instant::now(),
                        bytes: frame.bytes.len(),
                        visible: visible_text(&frame.bytes),
                    };
                    if frames_tx.send(event).is_err() {
                        return;
                    }
                }
            })
            .expect("spawn client reader");

        Self {
            stream,
            frames,
            reader: Some(reader),
            visible: Vec::new(),
        }
    }

    fn send(&mut self, data: &[u8]) {
        write_message(
            &mut self.stream,
            &ClientMessage::Input {
                data: data.to_vec(),
            },
        )
        .expect("write client input");
    }

    /// Drain and account frames until `deadline`, looking for `marker` in the
    /// rolling visible text. A frame drained earlier can already carry the
    /// echo, so the buffer is checked before waiting on another frame.
    fn wait_for_marker(
        &mut self,
        marker: &str,
        deadline: Instant,
        metrics: &mut ArmMetrics,
    ) -> Option<Instant> {
        let mut seen = Instant::now();
        loop {
            if contains(&self.visible, marker.as_bytes()) {
                self.visible.clear();
                return Some(seen);
            }
            seen = self.next_frame(deadline, metrics)?.at;
        }
    }

    /// Wait for any single frame, accounting it. Used to time recovery.
    fn wait_for_frame(&mut self, deadline: Instant, metrics: &mut ArmMetrics) -> Option<Instant> {
        self.next_frame(deadline, metrics).map(|event| event.at)
    }

    fn next_frame(&mut self, deadline: Instant, metrics: &mut ArmMetrics) -> Option<FrameEvent> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let event = self.frames.recv_timeout(remaining).ok()?;
        metrics.frames += 1;
        metrics.frame_bytes += event.bytes as u64;
        append_visible(&mut self.visible, &event.visible);
        Some(event)
    }

    /// Account every frame that arrives before `deadline`, so idle repaints
    /// still count toward frames/s and bytes/frame.
    fn drain_until(&mut self, deadline: Instant, metrics: &mut ArmMetrics) {
        while self.next_frame(deadline, metrics).is_some() {}
    }

    /// Swallow the attach repaint so it is not measured.
    fn settle(&mut self) {
        let deadline = Instant::now() + SETTLE;
        let mut discard = ArmMetrics::new("settle");
        self.drain_until(deadline, &mut discard);
        self.visible.clear();
    }

    fn close(mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && haystack.windows(needle.len()).any(|slice| slice == needle)
}

fn append_visible(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(bytes);
    if buffer.len() > VISIBLE_WINDOW {
        let excess = buffer.len() - VISIBLE_WINDOW;
        buffer.drain(..excess);
    }
}

/// Printable text of a frame with escape sequences removed. Frames are ANSI
/// diffs, and herdr may split an echoed run across cursor moves or style
/// changes, so the marker is only reliably contiguous once the escapes are
/// gone.
fn visible_text(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == 0x1b {
            index += 1 + escape_length(&bytes[index + 1..]);
            continue;
        }
        if (0x20..0x7f).contains(&byte) {
            out.push(byte);
        }
        index += 1;
    }
    out
}

/// Length of the escape sequence body after an `ESC`.
fn escape_length(rest: &[u8]) -> usize {
    match rest.first() {
        None => 0,
        // CSI: parameters then one final byte.
        Some(b'[') => {
            let mut index = 1;
            while index < rest.len() && !(0x40..=0x7e).contains(&rest[index]) {
                index += 1;
            }
            (index + 1).min(rest.len())
        }
        // String-terminated: OSC, DCS, APC, PM.
        Some(b']') | Some(b'P') | Some(b'_') | Some(b'^') => {
            let mut index = 1;
            while index < rest.len() {
                if rest[index] == 0x07 {
                    return index + 1;
                }
                if rest[index] == 0x1b && rest.get(index + 1) == Some(&b'\\') {
                    return index + 2;
                }
                index += 1;
            }
            rest.len()
        }
        Some(_) => 1,
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

struct ArmMetrics {
    name: &'static str,
    latencies: Vec<Duration>,
    frames: u64,
    frame_bytes: u64,
    lost: u64,
    wall: Duration,
}

impl ArmMetrics {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            latencies: Vec::new(),
            frames: 0,
            frame_bytes: 0,
            lost: 0,
            wall: Duration::ZERO,
        }
    }

    fn percentile_ms(&self, percentile: f64) -> f64 {
        if self.latencies.is_empty() {
            return f64::NAN;
        }
        let mut sorted = self.latencies.clone();
        sorted.sort_unstable();
        let rank = (percentile * sorted.len() as f64).ceil() as usize;
        let index = rank.saturating_sub(1).min(sorted.len() - 1);
        sorted[index].as_secs_f64() * 1000.0
    }

    fn fps(&self) -> f64 {
        if self.wall.is_zero() {
            return 0.0;
        }
        self.frames as f64 / self.wall.as_secs_f64()
    }

    fn bytes_per_frame(&self) -> f64 {
        if self.frames == 0 {
            return 0.0;
        }
        self.frame_bytes as f64 / self.frames as f64
    }
}

struct BlackoutRecord {
    window: Duration,
    recovery: Option<Duration>,
    echoed: bool,
}

fn keystrokes() -> usize {
    std::env::var("HERDR_BENCH_KEYSTROKES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(DEFAULT_KEYSTROKES)
}

/// Marker for the `index`-th keystroke: one letter repeated, cycling the
/// alphabet. Frames are diffs, and consecutive markers must differ in *every*
/// character — otherwise a server that coalesces the line-erase with the next
/// keystroke emits only the changed cell ("m0000" -> "m0001" is a one-cell
/// diff) and the echo would be unrecognizable rather than late.
fn marker_for(index: usize) -> String {
    let letter = char::from(b'a' + (index % 26) as u8);
    std::iter::repeat_n(letter, MARKER_LENGTH).collect()
}

/// Type one marker, wait for it to come back on a frame, then clear the line.
fn measure_keystroke(client: &mut TerminalClient, marker: &str, metrics: &mut ArmMetrics) {
    // Only this keystroke's frames may satisfy this keystroke.
    client.visible.clear();
    client.send(marker.as_bytes());
    let sent = Instant::now();
    match client.wait_for_marker(marker, sent + ECHO_TIMEOUT, metrics) {
        Some(seen) => metrics.latencies.push(seen.saturating_duration_since(sent)),
        None => metrics.lost += 1,
    }
    client.send(&[KILL_LINE]);
    // The gap runs from the echo, not from the keystroke: it is what gives the
    // server an idle window to paint the erased line on its own frame.
    client.drain_until(Instant::now() + KEYSTROKE_GAP, metrics);
}

fn measure_arm(name: &'static str, client: &mut TerminalClient, count: usize) -> ArmMetrics {
    let mut metrics = ArmMetrics::new(name);
    let started = Instant::now();
    for index in 0..count {
        measure_keystroke(client, &marker_for(index), &mut metrics);
    }
    metrics.wall = started.elapsed();
    metrics
}

/// The 3G arm with two outages: the relay drops everything for the window,
/// a keystroke is typed into the dark, and both the first frame after the
/// relay reopens and that keystroke's echo are timed.
fn measure_blackout_arm(
    client: &mut TerminalClient,
    relay: &ShapedRelay,
    count: usize,
    windows: &[Duration],
) -> (ArmMetrics, Vec<BlackoutRecord>) {
    let mut metrics = ArmMetrics::new("quic_3g_blackout");
    let mut blackouts = Vec::new();
    let started = Instant::now();
    // Windows are spaced through the run so each is preceded and followed by
    // ordinary measured keystrokes.
    let stride = count / (windows.len() + 1);
    let mut next_window = 0usize;
    for index in 0..count {
        measure_keystroke(client, &marker_for(index), &mut metrics);
        if next_window < windows.len() && index + 1 == stride * (next_window + 1) {
            let window = windows[next_window];
            blackouts.push(run_blackout(client, relay, window, &mut metrics));
            next_window += 1;
        }
    }
    metrics.wall = started.elapsed();
    (metrics, blackouts)
}

fn run_blackout(
    client: &mut TerminalClient,
    relay: &ShapedRelay,
    window: Duration,
    metrics: &mut ArmMetrics,
) -> BlackoutRecord {
    // Digits, so a blackout marker can never be confused with the letter
    // markers of the ordinary keystrokes around it.
    let marker = format!("{:0>width$}", window.as_secs(), width = MARKER_LENGTH);
    relay.set(NetworkMode::Blackhole);
    // Let the outage take hold before typing into it, so the keystroke cannot
    // slip out on a datagram already in flight.
    let opened = Instant::now();
    client.drain_until(opened + Duration::from_millis(500), metrics);
    client.send(marker.as_bytes());
    client.drain_until(opened + window, metrics);

    relay.set(NetworkMode::ThreeG);
    let reopened = Instant::now();
    let recovery = client
        .wait_for_frame(reopened + RECOVERY_TIMEOUT, metrics)
        .map(|at| at.saturating_duration_since(reopened));
    let echoed = client
        .wait_for_marker(&marker, reopened + RECOVERY_ECHO_TIMEOUT, metrics)
        .is_some();
    if !echoed {
        metrics.lost += 1;
    }
    client.send(&[KILL_LINE]);
    client.drain_until(Instant::now() + KEYSTROKE_GAP, metrics);
    BlackoutRecord {
        window,
        recovery,
        echoed,
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

fn print_report(arms: &[ArmMetrics], blackouts: &[BlackoutRecord], keystrokes: usize) {
    println!();
    println!("herdr remote QUIC 3G benchmark (debug build; bytes are Terminal frame payloads)");
    println!(
        "{:<18} {:>5} {:>9} {:>9} {:>9} {:>7} {:>12} {:>12} {:>5} {:>8}",
        "arm",
        "keys",
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "fps",
        "bytes/frame",
        "total_bytes",
        "lost",
        "wall_s"
    );
    for arm in arms {
        println!(
            "{:<18} {:>5} {:>9.1} {:>9.1} {:>9.1} {:>7.2} {:>12.1} {:>12} {:>5} {:>8.1}",
            arm.name,
            keystrokes,
            arm.percentile_ms(0.50),
            arm.percentile_ms(0.95),
            arm.percentile_ms(0.99),
            arm.fps(),
            arm.bytes_per_frame(),
            arm.frame_bytes,
            arm.lost,
            arm.wall.as_secs_f64(),
        );
    }
    println!();
    println!(
        "{:<10} {:>12} {:>26}",
        "window_s", "recovery_ms", "mid_blackout_input_echoed"
    );
    for blackout in blackouts {
        println!(
            "{:<10} {:>12} {:>26}",
            blackout.window.as_secs(),
            blackout
                .recovery
                .map(|recovery| format!("{:.1}", recovery.as_secs_f64() * 1000.0))
                .unwrap_or_else(|| "n/a".to_owned()),
            blackout.echoed,
        );
    }
    println!();
}

fn write_json_report(path: &str, arms: &[ArmMetrics], blackouts: &[BlackoutRecord], count: usize) {
    let report = serde_json::json!({
        "keystrokes": count,
        "build": "debug",
        "arms": arms
            .iter()
            .map(|arm| serde_json::json!({
                "arm": arm.name,
                "p50_ms": arm.percentile_ms(0.50),
                "p95_ms": arm.percentile_ms(0.95),
                "p99_ms": arm.percentile_ms(0.99),
                "fps": arm.fps(),
                "bytes_per_frame": arm.bytes_per_frame(),
                "total_bytes": arm.frame_bytes,
                "frames": arm.frames,
                "keystrokes_lost": arm.lost,
                "wall_seconds": arm.wall.as_secs_f64(),
            }))
            .collect::<Vec<_>>(),
        "blackouts": blackouts
            .iter()
            .map(|blackout| serde_json::json!({
                "window_seconds": blackout.window.as_secs(),
                "recovery_ms": blackout
                    .recovery
                    .map(|recovery| recovery.as_secs_f64() * 1000.0),
                "mid_blackout_input_echoed": blackout.echoed,
            }))
            .collect::<Vec<_>>(),
    });
    let mut file = match std::fs::File::create(path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("herdr bench: cannot write {path}: {err}");
            return;
        }
    };
    if let Err(err) = writeln!(
        file,
        "{}",
        serde_json::to_string_pretty(&report).unwrap_or_default()
    ) {
        eprintln!("herdr bench: cannot write {path}: {err}");
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Start a bridge for one arm. Its cached credential points at the relay
/// rather than the port the server published, so every QUIC packet crosses
/// the shaped hop. `config` is the seeded cache key, so the clone must keep
/// its target and session.
fn bridge_arm(config: &QuicBridgeConfig, socket: PathBuf) -> QuicBridge {
    QuicBridge::start(
        QuicBridgeConfig {
            target: config.target.clone(),
            remote_herdr: RemoteHerdr::for_test_binary(Path::new("/nonexistent/herdr")),
            session: config.session.clone(),
            ssh_options: None,
            noninteractive: true,
            transport: RemoteTransportConfig::Auto,
            logical_client_id: config.logical_client_id,
        },
        socket,
    )
    .expect("start the arm's bridge")
}

#[test]
#[ignore = "benchmark: drives a real server, bridge, and shaped relay for minutes"]
fn remote_quic_3g_benchmark() {
    let count = keystrokes();
    let mut server = BenchServer::start();
    let logical_client_id = QuicBridgeConfig::process_logical_client_id();
    let record = server.bootstrap(logical_client_id);
    let relay = ShapedRelay::start(SocketAddr::from((Ipv4Addr::LOCALHOST, record.port)));
    println!(
        "bench: server QUIC port {}, relay {} (3G shaping in userspace)",
        record.port, relay.address
    );

    // The bridge never runs SSH: the credential is planted, and its dial
    // candidate is the relay, so every QUIC packet crosses the shaped hop.
    let bridge_config = QuicBridgeConfig {
        target: format!("quic-bench-{}", std::process::id()),
        remote_herdr: RemoteHerdr::for_test_binary(Path::new("/nonexistent/herdr")),
        session: crate::session::DEFAULT_SESSION_NAME.to_owned(),
        ssh_options: None,
        noninteractive: true,
        transport: RemoteTransportConfig::Auto,
        logical_client_id,
    };
    seed_credential_for_test(&bridge_config, record.clone(), vec![relay.address]);

    let mut arms = Vec::new();
    let mut blackouts = Vec::new();

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // direct: no bridge, no relay. The server's own render latency.
        let mut client = TerminalClient::connect(&server.client_socket, &server.terminal_id);
        client.settle();
        arms.push(measure_arm("direct", &mut client, count));
        client.close();

        for (name, mode) in [
            ("quic_online", NetworkMode::Online),
            ("quic_3g", NetworkMode::ThreeG),
        ] {
            relay.set(mode);
            let socket = server.root.join(format!("{name}.sock"));
            let bridge = bridge_arm(&bridge_config, socket.clone());
            let mut client = TerminalClient::connect(&socket, &server.terminal_id);
            client.settle();
            arms.push(measure_arm(name, &mut client, count));
            client.close();
            drop(bridge);
        }

        relay.set(NetworkMode::ThreeG);
        let socket = server.root.join("quic_3g_blackout.sock");
        let bridge = bridge_arm(&bridge_config, socket.clone());
        let mut client = TerminalClient::connect(&socket, &server.terminal_id);
        client.settle();
        let (metrics, records) = measure_blackout_arm(
            &mut client,
            &relay,
            count,
            &[Duration::from_secs(5), Duration::from_secs(20)],
        );
        arms.push(metrics);
        blackouts = records;
        client.close();
        drop(bridge);
    }));

    forget_credential_for_test(&bridge_config);
    drop(relay);
    server.shutdown();

    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }

    print_report(&arms, &blackouts, count);
    if let Ok(path) = std::env::var("HERDR_BENCH_REPORT") {
        write_json_report(&path, &arms, &blackouts, count);
    }

    for arm in &arms {
        assert_eq!(arm.lost, 0, "{} lost keystrokes", arm.name);
        assert!(
            !arm.latencies.is_empty(),
            "{} measured no keystrokes",
            arm.name
        );
    }
    assert_eq!(blackouts.len(), 2, "both blackout windows must be measured");
    for blackout in &blackouts {
        assert!(
            blackout.recovery.is_some(),
            "no frame arrived after the {} s blackout",
            blackout.window.as_secs()
        );
        assert!(
            blackout.echoed,
            "the keystroke typed during the {} s blackout was never echoed",
            blackout.window.as_secs()
        );
    }
}

// ---------------------------------------------------------------------------
// §8.3 interface flap on a real network stack
// ---------------------------------------------------------------------------
//
// The server runs inside a network namespace on `SERVER_ADDRESS`; the bridge
// stays in the root namespace and reaches it over a veth pair, so the kernel's
// source-address choice for the server is whatever address the root end of the
// pair carries. The scenario deletes that address under a live connection and,
// after `FLAP_GAP`, raises a different one: exactly what a tether -> wifi
// switch or a DHCP renewal onto a new subnet does, with real netlink
// announcements and a real dead source address.
//
// Two variants, both measured from the moment the new address is raised:
//
// * `address_change` — only the address moves. A wildcard socket may follow
//   the route on its own, so this measures what the kernel gives for free.
// * `address_change_port_dead` — additionally, the namespace blackholes every
//   reply to the client's *current* UDP port before the flap. That is the
//   design doc's own flap model (the old tuple is dead, only a rebind recovers)
//   and the NAT reality it stands for: a mapping that died with the old path.
//
// Needs root. Run the compiled test binary under sudo:
//
// ```text
// cargo test --bin herdr --no-run
// sudo target/debug/deps/herdr-<hash> --ignored --nocapture remote_quic_address_change_scenario
// ```

const SCENARIO_NETNS: &str = "herdr-bench";
const SCENARIO_ROOT_LINK: &str = "hb-root";
const SCENARIO_NS_LINK: &str = "hb-ns";
const SERVER_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 253, 1, 2);
/// The root end starts on the server's subnet and then roams between two
/// others; the namespace has return routes for all three.
const CLIENT_ADDRESSES: [Ipv4Addr; 3] = [
    Ipv4Addr::new(10, 253, 1, 1),
    Ipv4Addr::new(10, 253, 3, 1),
    Ipv4Addr::new(10, 253, 4, 1),
];
/// Dead time between the old address vanishing and the new one appearing:
/// a DHCP lease on a new network takes at least this long.
const FLAP_GAP: Duration = Duration::from_secs(1);
/// Flaps per variant; each one cycles to the next client address.
const FLAPS: usize = 4;
/// Ordinary keystrokes measured after every flap.
const KEYSTROKES_PER_FLAP: usize = 8;
/// Preregistered pass rule for the rebind-on-evidence change: the path is
/// live within this long of the address event.
const FLAP_RECOVERY_BUDGET: Duration = Duration::from_secs(1);

fn ip(args: &[&str]) {
    let output = std::process::Command::new("ip")
        .args(args)
        .output()
        .expect("run ip");
    assert!(
        output.status.success(),
        "ip {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn ip_ignore_failure(args: &[&str]) {
    let _ = std::process::Command::new("ip")
        .args(args)
        .stderr(std::process::Stdio::null())
        .status();
}

/// The veth pair and namespace, torn down on drop.
struct ScenarioNetwork {
    /// Index into `CLIENT_ADDRESSES` of the address the root end carries.
    current: usize,
}

impl ScenarioNetwork {
    fn create() -> Self {
        ip_ignore_failure(&["netns", "del", SCENARIO_NETNS]);
        ip_ignore_failure(&["link", "del", SCENARIO_ROOT_LINK]);
        ip(&["netns", "add", SCENARIO_NETNS]);
        ip(&[
            "link",
            "add",
            SCENARIO_ROOT_LINK,
            "type",
            "veth",
            "peer",
            "name",
            SCENARIO_NS_LINK,
        ]);
        ip(&["link", "set", SCENARIO_NS_LINK, "netns", SCENARIO_NETNS]);
        ip(&["link", "set", SCENARIO_ROOT_LINK, "up"]);
        ip(&["-n", SCENARIO_NETNS, "link", "set", "lo", "up"]);
        ip(&["-n", SCENARIO_NETNS, "link", "set", SCENARIO_NS_LINK, "up"]);
        ip(&[
            "-n",
            SCENARIO_NETNS,
            "addr",
            "add",
            &format!("{SERVER_ADDRESS}/24"),
            "dev",
            SCENARIO_NS_LINK,
        ]);
        for address in &CLIENT_ADDRESSES[1..] {
            let octets = address.octets();
            let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
            ip(&[
                "-n",
                SCENARIO_NETNS,
                "route",
                "add",
                &subnet,
                "dev",
                SCENARIO_NS_LINK,
            ]);
        }
        let mut network = Self { current: 0 };
        network.raise_client_address(0);
        network
    }

    fn path() -> PathBuf {
        PathBuf::from("/var/run/netns").join(SCENARIO_NETNS)
    }

    fn client_address(&self) -> Ipv4Addr {
        CLIENT_ADDRESSES[self.current]
    }

    /// The old address dies: its connected route and every route preferring
    /// it as source go with it, so the server is unreachable until
    /// [`Self::raise_client_address`].
    fn drop_client_address(&self) {
        ip(&[
            "addr",
            "del",
            &format!("{}/24", self.client_address()),
            "dev",
            SCENARIO_ROOT_LINK,
        ]);
    }

    /// A new address appears, with a route to the server's subnet that
    /// prefers it as source (the server's subnet is only directly connected
    /// for the first address).
    fn raise_client_address(&mut self, index: usize) {
        let address = CLIENT_ADDRESSES[index];
        ip(&[
            "addr",
            "add",
            &format!("{address}/24"),
            "dev",
            SCENARIO_ROOT_LINK,
        ]);
        if index != 0 {
            let octets = SERVER_ADDRESS.octets();
            let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
            ip(&[
                "route",
                "replace",
                &subnet,
                "dev",
                SCENARIO_ROOT_LINK,
                "src",
                &address.to_string(),
            ]);
        }
        self.current = index;
    }

    /// From now on the namespace drops every datagram it would send to `port`,
    /// whatever the destination address: the client's current 4-tuple is dead
    /// the way a NAT mapping is once the path behind it is gone.
    fn blackhole_replies_to_port(&self, port: u16) {
        ip(&[
            "-n",
            SCENARIO_NETNS,
            "rule",
            "add",
            "dport",
            &port.to_string(),
            "blackhole",
        ]);
    }
}

impl Drop for ScenarioNetwork {
    fn drop(&mut self) {
        // Deleting the namespace deletes the veth pair with it (one end is
        // inside), and the root end's addresses and routes with the link.
        ip_ignore_failure(&["netns", "del", SCENARIO_NETNS]);
        ip_ignore_failure(&["link", "del", SCENARIO_ROOT_LINK]);
    }
}

/// UDP ports bound by this process in the calling thread's namespace. The
/// server's sockets live in the scenario namespace, so from the root namespace
/// this is the bridge's QUIC socket (and nothing else the bench owns).
fn own_udp_ports() -> Vec<u16> {
    let mut inodes = std::collections::HashSet::new();
    for entry in std::fs::read_dir("/proc/self/fd").expect("list own descriptors") {
        let Ok(entry) = entry else { continue };
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let target = target.to_string_lossy().into_owned();
        if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
        {
            inodes.insert(inode.to_owned());
        }
    }
    let table = std::fs::read_to_string("/proc/net/udp").expect("read /proc/net/udp");
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let local = fields.get(1)?;
            let inode = fields.get(9)?;
            if !inodes.contains(*inode) {
                return None;
            }
            let (_, port) = local.rsplit_once(':')?;
            u16::from_str_radix(port, 16).ok()
        })
        .collect()
}

struct FlapRecord {
    variant: &'static str,
    from: Ipv4Addr,
    to: Ipv4Addr,
    /// Ports the namespace blackholed before this flap (port-dead variant).
    dead_ports: Vec<u16>,
    /// New address raised -> first frame from the server.
    recovery: Option<Duration>,
    /// New address raised -> echo of the marker typed while the address was
    /// dead.
    echo: Option<Duration>,
}

impl FlapRecord {
    fn within_budget(&self) -> bool {
        self.recovery
            .is_some_and(|recovery| recovery <= FLAP_RECOVERY_BUDGET)
    }
}

fn run_flap(
    client: &mut TerminalClient,
    network: &mut ScenarioNetwork,
    variant: &'static str,
    index: usize,
    port_dead: bool,
    metrics: &mut ArmMetrics,
) -> FlapRecord {
    let from = network.client_address();
    let next = network.current % (CLIENT_ADDRESSES.len() - 1) + 1;
    let to = CLIENT_ADDRESSES[next];
    // Digits, so a flap marker can never be confused with a letter marker.
    let marker = format!("{:0>width$}", index + 1, width = MARKER_LENGTH);

    let dead_ports = if port_dead {
        let ports = own_udp_ports();
        assert!(!ports.is_empty(), "the bridge's QUIC socket was not found");
        for port in &ports {
            network.blackhole_replies_to_port(*port);
        }
        ports
    } else {
        Vec::new()
    };

    network.drop_client_address();
    let dropped = Instant::now();
    client.drain_until(dropped + Duration::from_millis(500), metrics);
    client.send(marker.as_bytes());
    client.drain_until(dropped + FLAP_GAP, metrics);

    network.raise_client_address(next);
    let raised = Instant::now();
    let recovery = client
        .wait_for_frame(raised + RECOVERY_TIMEOUT, metrics)
        .map(|at| at.saturating_duration_since(raised));
    let echo = client
        .wait_for_marker(&marker, raised + RECOVERY_ECHO_TIMEOUT, metrics)
        .map(|at| at.saturating_duration_since(raised));
    if echo.is_none() {
        metrics.lost += 1;
    }
    client.send(&[KILL_LINE]);
    client.drain_until(Instant::now() + KEYSTROKE_GAP, metrics);
    FlapRecord {
        variant,
        from,
        to,
        dead_ports,
        recovery,
        echo,
    }
}

fn print_flap_report(arms: &[ArmMetrics], flaps: &[FlapRecord]) {
    println!();
    println!(
        "herdr remote QUIC address-change scenario (debug build; {} s dead gap, budget {} ms)",
        FLAP_GAP.as_secs_f64(),
        FLAP_RECOVERY_BUDGET.as_millis()
    );
    println!(
        "{:<26} {:>5} {:>9} {:>9} {:>9} {:>5}",
        "arm", "keys", "p50_ms", "p95_ms", "p99_ms", "lost"
    );
    for arm in arms {
        println!(
            "{:<26} {:>5} {:>9.1} {:>9.1} {:>9.1} {:>5}",
            arm.name,
            arm.latencies.len(),
            arm.percentile_ms(0.50),
            arm.percentile_ms(0.95),
            arm.percentile_ms(0.99),
            arm.lost,
        );
    }
    println!();
    println!(
        "{:<26} {:>3} {:<12} {:<12} {:>12} {:>12} {:>7} {:<12}",
        "variant", "#", "from", "to", "recovery_ms", "echo_ms", "budget", "dead_ports"
    );
    let millis = |value: Option<Duration>| {
        value
            .map(|value| format!("{:.1}", value.as_secs_f64() * 1000.0))
            .unwrap_or_else(|| "n/a".to_owned())
    };
    for (index, flap) in flaps.iter().enumerate() {
        println!(
            "{:<26} {:>3} {:<12} {:<12} {:>12} {:>12} {:>7} {:<12}",
            flap.variant,
            index + 1,
            flap.from,
            flap.to,
            millis(flap.recovery),
            millis(flap.echo),
            if flap.within_budget() { "pass" } else { "FAIL" },
            flap.dead_ports
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    println!();
}

fn write_flap_json_report(path: &str, arms: &[ArmMetrics], flaps: &[FlapRecord]) {
    let report = serde_json::json!({
        "scenario": "address_change",
        "build": "debug",
        "flap_gap_seconds": FLAP_GAP.as_secs_f64(),
        "recovery_budget_ms": FLAP_RECOVERY_BUDGET.as_millis() as u64,
        "arms": arms
            .iter()
            .map(|arm| serde_json::json!({
                "arm": arm.name,
                "keystrokes": arm.latencies.len(),
                "p50_ms": arm.percentile_ms(0.50),
                "p95_ms": arm.percentile_ms(0.95),
                "p99_ms": arm.percentile_ms(0.99),
                "keystrokes_lost": arm.lost,
            }))
            .collect::<Vec<_>>(),
        "flaps": flaps
            .iter()
            .map(|flap| serde_json::json!({
                "variant": flap.variant,
                "from": flap.from.to_string(),
                "to": flap.to.to_string(),
                "dead_ports": flap.dead_ports,
                "recovery_ms": flap.recovery.map(|value| value.as_secs_f64() * 1000.0),
                "echo_ms": flap.echo.map(|value| value.as_secs_f64() * 1000.0),
                "within_budget": flap.within_budget(),
            }))
            .collect::<Vec<_>>(),
    });
    match std::fs::File::create(path) {
        Ok(mut file) => {
            if let Err(err) = writeln!(
                file,
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_default()
            ) {
                eprintln!("herdr bench: cannot write {path}: {err}");
            }
        }
        Err(err) => eprintln!("herdr bench: cannot write {path}: {err}"),
    }
}

#[test]
#[ignore = "scenario: needs root; creates a network namespace and a veth pair"]
fn remote_quic_address_change_scenario() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run the test binary under sudo: the scenario creates a network namespace"
    );
    // `HERDR_LOG=herdr=debug` shows the bridge's rebinds and the server's
    // path validation on stderr, timestamped against the report.
    if let Ok(filter) = tracing_subscriber::EnvFilter::try_from_env("HERDR_LOG") {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .try_init();
    }
    let mut network = ScenarioNetwork::create();
    let mut server = BenchServer::start_in(Some(ScenarioNetwork::path()));
    let logical_client_id = QuicBridgeConfig::process_logical_client_id();
    let record = server.bootstrap(logical_client_id);
    let server_endpoint = SocketAddr::from((SERVER_ADDRESS, record.port));
    println!(
        "scenario: server QUIC endpoint {server_endpoint} in netns {SCENARIO_NETNS}, client starts on {}",
        network.client_address()
    );

    let bridge_config = QuicBridgeConfig {
        target: format!("quic-scenario-{}", std::process::id()),
        remote_herdr: RemoteHerdr::for_test_binary(Path::new("/nonexistent/herdr")),
        session: crate::session::DEFAULT_SESSION_NAME.to_owned(),
        ssh_options: None,
        noninteractive: true,
        transport: RemoteTransportConfig::Auto,
        logical_client_id,
    };
    seed_credential_for_test(&bridge_config, record.clone(), vec![server_endpoint]);
    let mut arms = Vec::new();
    let mut flaps = Vec::new();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for (variant, port_dead) in [
            ("address_change", false),
            ("address_change_port_dead", true),
        ] {
            let socket = server.root.join(format!("{variant}.sock"));
            let bridge = bridge_arm(&bridge_config, socket.clone());
            let mut client = TerminalClient::connect(&socket, &server.terminal_id);
            client.settle();
            let mut metrics = ArmMetrics::new(variant);
            let started = Instant::now();
            for index in 0..KEYSTROKES_PER_FLAP {
                measure_keystroke(&mut client, &marker_for(index), &mut metrics);
            }
            for flap in 0..FLAPS {
                flaps.push(run_flap(
                    &mut client,
                    &mut network,
                    variant,
                    flap,
                    port_dead,
                    &mut metrics,
                ));
                for index in 0..KEYSTROKES_PER_FLAP {
                    let marker = marker_for(KEYSTROKES_PER_FLAP * (flap + 1) + index);
                    measure_keystroke(&mut client, &marker, &mut metrics);
                }
            }
            metrics.wall = started.elapsed();
            arms.push(metrics);
            client.close();
            drop(bridge);
            // The next arm's bridge dials with a newer credential generation,
            // which supersedes this arm's connection on the server. Let that
            // teardown finish before the successor attaches, or the two race.
            thread::sleep(Duration::from_millis(500));
        }
    }));

    forget_credential_for_test(&bridge_config);
    server.shutdown();
    drop(network);

    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }

    print_flap_report(&arms, &flaps);
    if let Ok(path) = std::env::var("HERDR_BENCH_REPORT") {
        write_flap_json_report(&path, &arms, &flaps);
    }

    assert_eq!(flaps.len(), 2 * FLAPS, "every flap must be measured");
    for (index, flap) in flaps.iter().enumerate() {
        assert!(
            flap.recovery.is_some(),
            "{} flap {}: no frame arrived after the new address came up",
            flap.variant,
            index + 1
        );
        assert!(
            flap.echo.is_some(),
            "{} flap {}: the keystroke typed while the address was dead was never echoed",
            flap.variant,
            index + 1
        );
    }
}
