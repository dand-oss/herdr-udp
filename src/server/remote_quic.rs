//! SSH-authorized QUIC transport for remote clients.
//!
//! The transport is an opaque pipe. An authenticated QUIC connection is
//! adapted onto a Unix socketpair whose far end is handed to the ordinary
//! client acceptor, so nothing here decodes the framed protocol it carries:
//! the server render, input, and session paths are byte-for-byte the ones a
//! local Unix client drives.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;
use tracing::{debug, info};

use crate::config::RemoteConfig;
use crate::protocol::{
    RemoteBootstrapRecord, RemoteBootstrapRequest, RemoteQuicAccepted, RemoteQuicHello,
    MAX_FRAME_SIZE, REMOTE_QUIC_ALPN, REMOTE_QUIC_HASH_BYTES, REMOTE_QUIC_ID_BYTES,
    REMOTE_QUIC_SCHEMA_VERSION, REMOTE_QUIC_TOKEN_BYTES,
};
use crate::remote::frame::{hash_bytes, lock, read_async_message, write_async_message};
use crate::remote::quic_policy::{
    REMOTE_QUIC_CLOSE_AUTH, REMOTE_QUIC_CLOSE_EVICTED, REMOTE_QUIC_CLOSE_HANDOFF,
    REMOTE_QUIC_CLOSE_PROTOCOL, REMOTE_QUIC_CLOSE_REPLACED, REMOTE_QUIC_CLOSE_RESYNC,
    REMOTE_QUIC_CLOSE_SHUTDOWN,
};

const MAX_TOKENS: usize = 64;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// A hello is a handful of scalars plus fixed-size identifiers; anything
/// larger is a peer that cannot authenticate anyway, so it is refused before
/// the decoder is handed a length it would trust.
const MAX_HELLO_SIZE: usize = 4096;
const TOKEN_MIN_LIFETIME: Duration = Duration::from_secs(60);
const TOKEN_MAX_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);
// Flow-control caps, not allocations; see the client-side note in
// src/remote/quic.rs. Sized for the render burst a graphics-heavy pane sends,
// not for one high-latency link profile.
const QUIC_SEND_WINDOW: u64 = 4 * 1024 * 1024;
const QUIC_STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;
const QUIC_RECEIVE_WINDOW: u32 = 1024 * 1024;
/// Per-direction copy buffer for one adapted connection. Large enough that a
/// multi-megabyte frame moves in a few syscalls, small enough that 32
/// pre-auth connections cannot pin meaningful memory.
const COPY_BUFFER_BYTES: usize = 64 * 1024;
// Connection close codes live in src/remote/quic_policy.rs: they are on the
// wire, so the client and the server must read them from one place.

/// Receives the server-side end of an accepted, authenticated QUIC client.
/// The callee treats it exactly like a freshly accepted Unix-socket client:
/// the socket carries the ordinary framed protocol, starting with the client's
/// own `Hello`.
pub(crate) type AcceptedClientSink = Arc<dyn Fn(StdUnixStream) + Send + Sync>;

#[derive(Debug)]
struct Capability {
    session: String,
    logical_client_id: [u8; REMOTE_QUIC_ID_BYTES],
    expires_unix_seconds: u64,
    connection_generation: u64,
    active_connection: Option<Connection>,
    issued_order: u64,
}

struct ServerState {
    server_instance_id: [u8; REMOTE_QUIC_ID_BYTES],
    tokens: Mutex<HashMap<[u8; REMOTE_QUIC_HASH_BYTES], Capability>>,
    token_order: AtomicU64,
    /// The single session this server process owns. A capability minted for
    /// another session never validates here.
    active_session: String,
    sink: AcceptedClientSink,
}

/// Process-lifetime QUIC endpoint. It is constructed only after an authenticated
/// local bootstrap request, so ordinary/local Herdr never binds UDP or creates TLS material.
pub(crate) struct RemoteQuicServer {
    endpoints: Vec<Endpoint>,
    /// Duplicates of the bound UDP sockets, kept only so a live handoff can
    /// pass the listening sockets to the successor process. They are never
    /// read from: quinn owns its own duplicate of each.
    sockets: Vec<UdpSocket>,
    state: Arc<ServerState>,
    port: u16,
    identity: ServerIdentity,
    token_lifetime: Duration,
    handed_off: AtomicBool,
}

impl RemoteQuicServer {
    /// Binds the listener and spawns its accept loops onto the ambient tokio
    /// runtime, which is the server's own.
    pub(crate) fn start(
        config: &RemoteConfig,
        active_session: String,
        sink: AcceptedClientSink,
    ) -> io::Result<Self> {
        let (start_port, end_port) = parse_port_range(&config.quic_port_range)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        let identity = ServerIdentity::generate().map_err(|err| {
            io::Error::other(format!("failed to mint remote QUIC identity: {err}"))
        })?;
        let server_config =
            make_server_config(&identity, config.validated_transport_idle_timeout()).map_err(
                |err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("failed to build remote QUIC server config: {err}"),
                    )
                },
            )?;
        let (sockets, port) = bind_sockets(start_port, end_port)?;
        let endpoints = make_endpoints(&server_config, &sockets)?;

        let mut server_instance_id = [0u8; REMOTE_QUIC_ID_BYTES];
        getrandom::fill(&mut server_instance_id).map_err(|err| {
            io::Error::other(format!("failed to generate QUIC server instance id: {err}"))
        })?;
        let state = Arc::new(ServerState {
            server_instance_id,
            tokens: Mutex::new(HashMap::new()),
            token_order: AtomicU64::new(1),
            active_session,
            sink,
        });

        for endpoint in &endpoints {
            tokio::spawn(accept_connections(endpoint.clone(), Arc::clone(&state)));
        }
        info!(
            port,
            endpoints = endpoints.len(),
            "remote QUIC endpoint enabled"
        );
        Ok(Self {
            endpoints,
            sockets,
            state,
            port,
            identity,
            token_lifetime: token_lifetime(config),
            handed_off: AtomicBool::new(false),
        })
    }

    /// Rebuilds the endpoint in a successor process from an exported state and
    /// the inherited sockets. Server instance id, certificate, and port are
    /// preserved, so a client's existing capability and pinned certificate
    /// fingerprint keep validating: it reconnects instead of rebootstrapping
    /// over SSH.
    pub(crate) fn resume(
        config: &RemoteConfig,
        active_session: String,
        sink: AcceptedClientSink,
        state: RemoteQuicHandoffState,
        sockets: Vec<UdpSocket>,
    ) -> io::Result<Self> {
        if sockets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote QUIC handoff carried no sockets",
            ));
        }
        let identity = ServerIdentity {
            certificate_der: state.certificate_der,
            private_key_der: state.private_key_der,
            fingerprint: state.certificate_fingerprint,
        };
        let server_config =
            make_server_config(&identity, config.validated_transport_idle_timeout()).map_err(
                |err| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("failed to restore remote QUIC certificate: {err}"),
                    )
                },
            )?;
        for socket in &sockets {
            socket.set_nonblocking(true)?;
        }
        let endpoints = make_endpoints(&server_config, &sockets)?;

        let now = unix_seconds();
        let mut inherited: Vec<HandoffToken> = state
            .tokens
            .into_iter()
            .filter(|token| token.expires_unix_seconds > now)
            .collect();
        // Newest capabilities win if the snapshot somehow carries more than
        // this process would ever mint.
        inherited.sort_unstable_by_key(|token| std::cmp::Reverse(token.issued_order));
        inherited.truncate(MAX_TOKENS);
        let token_order = inherited
            .iter()
            .map(|token| token.issued_order)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let tokens = inherited
            .into_iter()
            .map(|token| {
                (
                    token.token_hash,
                    Capability {
                        session: token.session,
                        logical_client_id: token.logical_client_id,
                        expires_unix_seconds: token.expires_unix_seconds,
                        connection_generation: token.connection_generation,
                        active_connection: None,
                        issued_order: token.issued_order,
                    },
                )
            })
            .collect::<HashMap<_, _>>();

        let server_state = Arc::new(ServerState {
            server_instance_id: state.server_instance_id,
            tokens: Mutex::new(tokens),
            token_order: AtomicU64::new(token_order),
            active_session,
            sink,
        });
        for endpoint in &endpoints {
            tokio::spawn(accept_connections(
                endpoint.clone(),
                Arc::clone(&server_state),
            ));
        }
        info!(
            port = state.port,
            endpoints = endpoints.len(),
            capabilities = lock(&server_state.tokens).len(),
            "remote QUIC endpoint resumed from handoff"
        );
        Ok(Self {
            endpoints,
            sockets,
            state: server_state,
            port: state.port,
            identity,
            token_lifetime: token_lifetime(config),
            handed_off: AtomicBool::new(false),
        })
    }

    /// UDP port the endpoint listens on.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Mints one capability for the session this server owns. The plaintext
    /// token travels back over the authenticated SSH channel and is never
    /// logged; the server keeps only its SHA-256.
    pub(crate) fn bootstrap(
        &self,
        request: &RemoteBootstrapRequest,
    ) -> Result<RemoteBootstrapRecord, String> {
        if request.session != self.state.active_session {
            return Err(format!(
                "remote bootstrap session mismatch: requested {}, server owns {}",
                request.session, self.state.active_session
            ));
        }

        let mut token = [0u8; REMOTE_QUIC_TOKEN_BYTES];
        getrandom::fill(&mut token)
            .map_err(|err| format!("failed to generate remote capability: {err}"))?;
        let token_hash = hash_bytes(&token);
        let expires_unix_seconds = unix_seconds().saturating_add(self.token_lifetime.as_secs());
        let issued_order = self.state.token_order.fetch_add(1, Ordering::Relaxed);

        let mut tokens = lock(&self.state.tokens);
        tokens.retain(|_, capability| capability.expires_unix_seconds > unix_seconds());
        if tokens.len() >= MAX_TOKENS {
            if let Some(oldest) = tokens
                .iter()
                .min_by_key(|(_, capability)| capability.issued_order)
                .map(|(hash, _)| *hash)
            {
                if let Some(removed) = tokens.remove(&oldest) {
                    if let Some(connection) = removed.active_connection {
                        // The capability is gone from the table, so the token
                        // this client holds can no longer validate: it has to
                        // bootstrap a new one rather than retry with a
                        // credential that now resolves to nothing.
                        connection.close(
                            VarInt::from_u32(REMOTE_QUIC_CLOSE_EVICTED),
                            b"capability evicted",
                        );
                    }
                }
            }
        }
        tokens.insert(
            token_hash,
            Capability {
                session: request.session.clone(),
                logical_client_id: request.logical_client_id,
                expires_unix_seconds,
                connection_generation: 0,
                active_connection: None,
                issued_order,
            },
        );

        Ok(RemoteBootstrapRecord {
            schema_version: REMOTE_QUIC_SCHEMA_VERSION,
            server_instance_id: self.state.server_instance_id,
            port: self.port,
            certificate_fingerprint: self.identity.fingerprint,
            capability_token: token,
            expires_unix_seconds,
        })
    }

    /// Snapshots everything a successor process needs to keep existing
    /// capabilities usable, together with duplicates of the listening UDP
    /// sockets (IPv4 first, then IPv6 when bound). The duplicates are what
    /// travel to the successor; this process keeps its own.
    pub(crate) fn export_handoff(&self) -> io::Result<(RemoteQuicHandoffState, Vec<UdpSocket>)> {
        let mut sockets = Vec::with_capacity(self.sockets.len());
        for socket in &self.sockets {
            sockets.push(socket.try_clone()?);
        }
        let socket_fd_count = u8::try_from(sockets.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "too many remote QUIC sockets to hand off",
            )
        })?;
        let tokens = lock(&self.state.tokens)
            .iter()
            .map(|(token_hash, capability)| HandoffToken {
                token_hash: *token_hash,
                session: capability.session.clone(),
                logical_client_id: capability.logical_client_id,
                expires_unix_seconds: capability.expires_unix_seconds,
                connection_generation: capability.connection_generation,
                issued_order: capability.issued_order,
            })
            .collect();
        Ok((
            RemoteQuicHandoffState {
                server_instance_id: self.state.server_instance_id,
                certificate_der: self.identity.certificate_der.clone(),
                private_key_der: self.identity.private_key_der.clone(),
                certificate_fingerprint: self.identity.fingerprint,
                port: self.port,
                socket_fd_count,
                tokens,
            },
            sockets,
        ))
    }

    /// Closes every endpoint with the handoff code, telling connected clients
    /// to reconnect with the capability they already hold instead of
    /// rebootstrapping over SSH. Suppresses the shutdown close on drop.
    pub(crate) fn close_for_handoff(&self) {
        self.handed_off.store(true, Ordering::Release);
        for endpoint in &self.endpoints {
            endpoint.close(
                VarInt::from_u32(REMOTE_QUIC_CLOSE_HANDOFF),
                b"server handoff",
            );
        }
    }

    /// Closes every endpoint permanently: the port, certificate, and instance
    /// id die with this process, so clients must bootstrap again.
    pub(crate) fn close_for_shutdown(&self) {
        for endpoint in &self.endpoints {
            endpoint.close(
                VarInt::from_u32(REMOTE_QUIC_CLOSE_SHUTDOWN),
                b"server shutdown",
            );
        }
    }
}

impl Drop for RemoteQuicServer {
    fn drop(&mut self) {
        if self.handed_off.load(Ordering::Acquire) {
            // `close_for_handoff` already told clients to reconnect; a second
            // close would look like a permanent shutdown.
            return;
        }
        self.close_for_shutdown();
    }
}

/// Everything a successor process needs to keep already-issued capabilities
/// valid across a live handoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RemoteQuicHandoffState {
    pub(crate) server_instance_id: [u8; REMOTE_QUIC_ID_BYTES],
    pub(crate) certificate_der: Vec<u8>,
    pub(crate) private_key_der: Vec<u8>,
    pub(crate) certificate_fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
    pub(crate) port: u16,
    /// Number of UDP socket descriptors that travel with this state.
    #[serde(default)]
    pub(crate) socket_fd_count: u8,
    pub(crate) tokens: Vec<HandoffToken>,
}

/// One capability, hashed rather than in the clear: the plaintext token never
/// leaves the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HandoffToken {
    pub(crate) token_hash: [u8; REMOTE_QUIC_HASH_BYTES],
    pub(crate) session: String,
    pub(crate) logical_client_id: [u8; REMOTE_QUIC_ID_BYTES],
    pub(crate) expires_unix_seconds: u64,
    pub(crate) connection_generation: u64,
    pub(crate) issued_order: u64,
}

fn token_lifetime(config: &RemoteConfig) -> Duration {
    Duration::from_secs(config.quic_idle_timeout_seconds)
        .clamp(TOKEN_MIN_LIFETIME, TOKEN_MAX_LIFETIME)
}

fn parse_port_range(value: &str) -> Result<(u16, u16), String> {
    let (start, end) = value
        .split_once('-')
        .ok_or_else(|| "remote.quic_port_range must look like 48000-48100".to_owned())?;
    let start = start
        .trim()
        .parse::<u16>()
        .map_err(|_| "remote.quic_port_range has an invalid start port".to_owned())?;
    let end = end
        .trim()
        .parse::<u16>()
        .map_err(|_| "remote.quic_port_range has an invalid end port".to_owned())?;
    if start < 1024 || start > end {
        return Err("remote.quic_port_range must be an ascending unprivileged range".to_owned());
    }
    Ok((start, end))
}

/// The self-signed TLS material the client pins by fingerprint. Kept in DER
/// so a live handoff can rebuild the exact same identity in the successor.
#[derive(Clone)]
struct ServerIdentity {
    certificate_der: Vec<u8>,
    private_key_der: Vec<u8>,
    fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
}

impl ServerIdentity {
    fn generate() -> Result<Self, Box<dyn std::error::Error>> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["herdr".to_owned()])?;
        let certificate_der = cert.der().to_vec();
        Ok(Self {
            fingerprint: hash_bytes(&certificate_der),
            certificate_der,
            private_key_der: signing_key.serialize_der(),
        })
    }
}

fn make_server_config(
    identity: &ServerIdentity,
    idle_timeout: Duration,
) -> Result<quinn::ServerConfig, Box<dyn std::error::Error>> {
    let cert_der = rustls::pki_types::CertificateDer::from(identity.certificate_der.clone());
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(identity.private_key_der.clone()).into();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)?;
    tls.alpn_protocols = vec![REMOTE_QUIC_ALPN.to_vec()];
    tls.max_early_data_size = 0;

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.migration(true);
    server_config.transport_config(Arc::new(transport_config(idle_timeout)?));
    Ok(server_config)
}

fn transport_config(idle_timeout: Duration) -> Result<quinn::TransportConfig, io::Error> {
    let mut transport = quinn::TransportConfig::default();
    let idle = idle_timeout.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC idle timeout is too large",
        )
    })?;
    transport
        .max_idle_timeout(Some(idle))
        // No transport keep-alive: the client bridge probes the path with
        // health pings on a cadence far inside the shortest configurable idle
        // timeout, and every one of them elicits a pong, so a server ping on
        // top would only be a third radio wakeup on an idle link. A middlebox
        // binding is kept warm by the client's probes, which is the direction
        // a NAT mapping needs anyway.
        .keep_alive_interval(None)
        // One bidirectional stream carries the whole framed protocol; a peer
        // that opens more is not speaking this transport.
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(QUIC_RECEIVE_WINDOW))
        .send_window(QUIC_SEND_WINDOW)
        // See the matching note in src/remote/quic.rs: BBR paces to measured
        // bottleneck bandwidth, so random loss on a mobile path does not
        // collapse the send window the way loss-based Cubic does.
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Ok(transport)
}

/// Binds the first port in the range that IPv4 accepts. IPv6 is best effort
/// at that same port: refusing the port because its v6 half is taken would
/// leave the client with no endpoint at all, so the failure is logged and the
/// IPv4-only listener is kept.
fn bind_sockets(start_port: u16, end_port: u16) -> io::Result<(Vec<UdpSocket>, u16)> {
    let mut last_error = None;
    for port in start_port..=end_port {
        let ipv4_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
        let ipv4_socket = match bind_udp_socket(Domain::IPV4, ipv4_address) {
            Ok(socket) => socket,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let mut sockets = vec![ipv4_socket];

        let ipv6_address = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
        match bind_udp_socket(Domain::IPV6, ipv6_address) {
            Ok(socket) => sockets.push(socket),
            Err(error) => {
                debug!(%error, port, "IPv6 QUIC listener unavailable; using IPv4");
            }
        }
        return Ok((sockets, port));
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no free UDP port in {start_port}-{end_port}"),
        )
    }))
}

/// Hands quinn its own duplicate of each socket, so the originals stay
/// available for a later handoff.
fn make_endpoints(
    server_config: &quinn::ServerConfig,
    sockets: &[UdpSocket],
) -> io::Result<Vec<Endpoint>> {
    sockets
        .iter()
        .map(|socket| make_endpoint(server_config.clone(), socket.try_clone()?))
        .collect()
}

fn bind_udp_socket(domain: Domain, address: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if domain == Domain::IPV6 {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn make_endpoint(server_config: quinn::ServerConfig, socket: UdpSocket) -> io::Result<Endpoint> {
    Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
}

/// Pre-auth admission cap: each accepted handshake spawns unauthenticated work
/// (TLS handshake, hello decode) and quinn's default allows up to 65,536
/// concurrent incoming, so without a bound an attacker can exhaust memory/CPU
/// before ever authenticating. Excess handshakes are refused outright.
const MAX_PREAUTH_CONNECTIONS: usize = 32;

async fn accept_connections(endpoint: Endpoint, state: Arc<ServerState>) {
    let admission = Arc::new(Semaphore::new(MAX_PREAUTH_CONNECTIONS));
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = Arc::clone(&admission).try_acquire_owned() else {
            debug!(remote = %incoming.remote_address(), "refusing QUIC connection: admission limit reached");
            incoming.refuse();
            continue;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _permit = permit;
            match incoming.await {
                Ok(connection) => {
                    // Every failure path inside `serve_connection` closes with
                    // the code the client needs to act on, so there is nothing
                    // left to decide here.
                    if let Err(err) = serve_connection(connection.clone(), state).await {
                        debug!(err = %err, remote = %connection.remote_address(), "remote QUIC connection ended");
                    }
                }
                Err(err) => debug!(err = %err, "remote QUIC handshake failed"),
            }
        });
    }
}

async fn serve_connection(connection: Connection, state: Arc<ServerState>) -> Result<(), String> {
    let (send, recv, hello) = match accept_hello(&connection).await {
        Ok(accepted) => accepted,
        Err(err) => {
            connection.close(
                VarInt::from_u32(REMOTE_QUIC_CLOSE_PROTOCOL),
                b"unusable remote QUIC hello",
            );
            return Err(err);
        }
    };

    let fence = validate_and_fence(&state, &connection, &hello)?;
    let outcome = adapt_connection(&connection, send, recv, &state, &hello).await;
    if outcome.is_err() {
        // The credential is untouched, so the client re-dials with the one it
        // already holds rather than paying for another SSH bootstrap.
        connection.close(
            VarInt::from_u32(REMOTE_QUIC_CLOSE_RESYNC),
            b"remote QUIC pipe failed",
        );
    }
    clear_active_connection(&state, fence);
    outcome
}

/// Reads the first frame on the client's single bidirectional stream. Every
/// failure here is a protocol failure: the peer either never opened the
/// stream, sent something undecodable, or speaks a different schema.
async fn accept_hello(
    connection: &Connection,
) -> Result<(SendStream, RecvStream, RemoteQuicHello), String> {
    let (send, mut recv) = tokio::time::timeout(HANDSHAKE_TIMEOUT, connection.accept_bi())
        .await
        .map_err(|_| "timed out waiting for the QUIC client stream".to_owned())?
        .map_err(|err| format!("failed to accept the QUIC client stream: {err}"))?;
    let hello: RemoteQuicHello = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        read_async_message(&mut recv, MAX_HELLO_SIZE),
    )
    .await
    .map_err(|_| "timed out waiting for the QUIC hello".to_owned())??;
    if hello.schema_version != REMOTE_QUIC_SCHEMA_VERSION {
        return Err(format!(
            "remote QUIC schema mismatch: client {}, server {REMOTE_QUIC_SCHEMA_VERSION}",
            hello.schema_version
        ));
    }
    Ok((send, recv, hello))
}

/// Turns the authenticated connection into an ordinary client of this server:
/// one end of a Unix socketpair goes to the acceptor, and this task copies
/// bytes between the other end and the QUIC stream. Nothing is decoded, so the
/// client and server negotiate their protocol exactly as they do over a local
/// socket.
async fn adapt_connection(
    connection: &Connection,
    mut send: SendStream,
    recv: RecvStream,
    state: &ServerState,
    hello: &RemoteQuicHello,
) -> Result<(), String> {
    write_async_message(
        &mut send,
        &RemoteQuicAccepted {
            schema_version: REMOTE_QUIC_SCHEMA_VERSION,
            connection_generation: hello.connection_generation,
        },
        MAX_FRAME_SIZE,
    )
    .await?;

    let (adapter_end, client_end) = tokio::net::UnixStream::pair()
        .map_err(|err| format!("failed to create the remote QUIC socket pair: {err}"))?;
    let client_end = client_end
        .into_std()
        .map_err(|err| format!("failed to detach the remote QUIC client socket: {err}"))?;
    // The acceptor expects the same blocking socket its own listener yields.
    client_end
        .set_nonblocking(false)
        .map_err(|err| format!("failed to reset the remote QUIC client socket: {err}"))?;
    (state.sink)(client_end);

    let (local_read, local_write) = adapter_end.into_split();
    tokio::select! {
        result = copy_stream(local_read, send) => {
            // The acceptor closed its end: the client's session is over as far
            // as the server is concerned, but the capability is still good.
            connection.close(
                VarInt::from_u32(REMOTE_QUIC_CLOSE_RESYNC),
                b"client connection ended",
            );
            result.map_err(|err| format!("remote QUIC uplink failed: {err}"))
        }
        result = copy_stream(recv, local_write) => {
            // The QUIC side ended; dropping the pair end hands the acceptor an
            // EOF, which is exactly what a local client disconnect looks like.
            result.map_err(|err| format!("remote QUIC downlink failed: {err}"))
        }
    }
}

async fn copy_stream(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
) -> io::Result<()> {
    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let read = from.read(&mut buffer).await?;
        if read == 0 {
            return to.flush().await;
        }
        to.write_all(&buffer[..read]).await?;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapabilityValidationError {
    ServerInstanceChanged,
    UnknownOrRevoked,
    Expired,
    DifferentLogicalClient,
    DifferentSession,
    StaleGeneration,
}

impl std::fmt::Display for CapabilityValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServerInstanceChanged => {
                formatter.write_str("remote server instance changed; SSH rebootstrap required")
            }
            Self::UnknownOrRevoked => {
                formatter.write_str("remote capability is unknown or revoked")
            }
            Self::Expired => {
                formatter.write_str("remote capability expired; SSH rebootstrap required")
            }
            Self::DifferentLogicalClient => {
                formatter.write_str("remote capability belongs to a different logical client")
            }
            Self::DifferentSession => {
                formatter.write_str("remote capability belongs to a different session")
            }
            Self::StaleGeneration => formatter.write_str("stale remote connection generation"),
        }
    }
}

fn validate_capability(
    server_instance_id: [u8; REMOTE_QUIC_ID_BYTES],
    tokens: &HashMap<[u8; REMOTE_QUIC_HASH_BYTES], Capability>,
    hello: &RemoteQuicHello,
    active_session: &str,
    now: u64,
) -> Result<[u8; REMOTE_QUIC_HASH_BYTES], CapabilityValidationError> {
    if hello.server_instance_id != server_instance_id {
        return Err(CapabilityValidationError::ServerInstanceChanged);
    }
    let token_hash = hash_bytes(&hello.capability_token);
    let capability = tokens
        .get(&token_hash)
        .ok_or(CapabilityValidationError::UnknownOrRevoked)?;
    if capability.expires_unix_seconds <= now {
        return Err(CapabilityValidationError::Expired);
    }
    if capability.logical_client_id != hello.logical_client_id {
        return Err(CapabilityValidationError::DifferentLogicalClient);
    }
    if capability.session != active_session {
        return Err(CapabilityValidationError::DifferentSession);
    }
    if hello.connection_generation <= capability.connection_generation {
        return Err(CapabilityValidationError::StaleGeneration);
    }
    Ok(token_hash)
}

/// Identifies one accepted connection inside its capability, so a connection
/// that has since been replaced does not clear the live one's slot.
#[derive(Clone, Copy)]
struct ConnectionFence {
    token_hash: [u8; REMOTE_QUIC_HASH_BYTES],
    connection_generation: u64,
}

fn validate_and_fence(
    state: &ServerState,
    connection: &Connection,
    hello: &RemoteQuicHello,
) -> Result<ConnectionFence, String> {
    let mut tokens = lock(&state.tokens);
    let token_hash = match validate_capability(
        state.server_instance_id,
        &tokens,
        hello,
        &state.active_session,
        unix_seconds(),
    ) {
        Ok(token_hash) => token_hash,
        Err(error) => {
            // Every validation failure means the credential presented cannot
            // be used again, so the client is sent back to SSH bootstrap.
            connection.close(
                VarInt::from_u32(REMOTE_QUIC_CLOSE_AUTH),
                error.to_string().as_bytes(),
            );
            return Err(error.to_string());
        }
    };
    let Some(capability) = tokens.get_mut(&token_hash) else {
        return Err(CapabilityValidationError::UnknownOrRevoked.to_string());
    };
    if let Some(previous) = capability.active_connection.replace(connection.clone()) {
        previous.close(
            VarInt::from_u32(REMOTE_QUIC_CLOSE_REPLACED),
            b"newer connection generation accepted",
        );
    }
    capability.connection_generation = hello.connection_generation;
    Ok(ConnectionFence {
        token_hash,
        connection_generation: hello.connection_generation,
    })
}

fn clear_active_connection(state: &ServerState, fence: ConnectionFence) {
    if let Some(capability) = lock(&state.tokens).get_mut(&fence.token_hash) {
        if capability.connection_generation == fence.connection_generation {
            capability.active_connection = None;
        }
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    const TEST_SESSION: &str = "session-a";

    #[test]
    fn port_range_requires_ascending_unprivileged_ports() {
        assert_eq!(parse_port_range("48000-48100"), Ok((48000, 48100)));
        assert!(parse_port_range("80-81").is_err());
        assert!(parse_port_range("48100-48000").is_err());
        assert!(parse_port_range("invalid").is_err());
    }

    fn capability_fixture() -> (
        [u8; REMOTE_QUIC_ID_BYTES],
        HashMap<[u8; REMOTE_QUIC_HASH_BYTES], Capability>,
        RemoteQuicHello,
    ) {
        let server_instance_id = [2; REMOTE_QUIC_ID_BYTES];
        let capability_token = [3; REMOTE_QUIC_TOKEN_BYTES];
        let logical_client_id = [4; REMOTE_QUIC_ID_BYTES];
        let mut tokens = HashMap::new();
        tokens.insert(
            hash_bytes(&capability_token),
            Capability {
                session: TEST_SESSION.to_owned(),
                logical_client_id,
                expires_unix_seconds: 2_000,
                connection_generation: 0,
                active_connection: None,
                issued_order: 1,
            },
        );
        let hello = RemoteQuicHello {
            schema_version: REMOTE_QUIC_SCHEMA_VERSION,
            server_instance_id,
            logical_client_id,
            capability_token,
            connection_generation: 1,
        };
        (server_instance_id, tokens, hello)
    }

    #[test]
    fn capability_validation_rejects_identity_and_revocation_failures() {
        let (server_instance_id, tokens, hello) = capability_fixture();
        assert_eq!(
            validate_capability(server_instance_id, &tokens, &hello, TEST_SESSION, 1_000),
            Ok(hash_bytes(&hello.capability_token))
        );

        assert_eq!(
            validate_capability(
                [9; REMOTE_QUIC_ID_BYTES],
                &tokens,
                &hello,
                TEST_SESSION,
                1_000
            ),
            Err(CapabilityValidationError::ServerInstanceChanged)
        );
        assert_eq!(
            validate_capability(
                server_instance_id,
                &HashMap::new(),
                &hello,
                TEST_SESSION,
                1_000,
            ),
            Err(CapabilityValidationError::UnknownOrRevoked)
        );
    }

    #[test]
    fn capability_validation_rejects_expiry_cross_scope_and_stale_generation() {
        let (server_instance_id, mut tokens, hello) = capability_fixture();
        assert_eq!(
            validate_capability(server_instance_id, &tokens, &hello, TEST_SESSION, 2_000),
            Err(CapabilityValidationError::Expired)
        );

        let mut wrong_client = hello.clone();
        wrong_client.logical_client_id = [9; REMOTE_QUIC_ID_BYTES];
        assert_eq!(
            validate_capability(
                server_instance_id,
                &tokens,
                &wrong_client,
                TEST_SESSION,
                1_000,
            ),
            Err(CapabilityValidationError::DifferentLogicalClient)
        );
        assert_eq!(
            validate_capability(server_instance_id, &tokens, &hello, "session-b", 1_000),
            Err(CapabilityValidationError::DifferentSession)
        );

        tokens
            .get_mut(&hash_bytes(&hello.capability_token))
            .expect("fixture capability")
            .connection_generation = hello.connection_generation;
        assert_eq!(
            validate_capability(server_instance_id, &tokens, &hello, TEST_SESSION, 1_000),
            Err(CapabilityValidationError::StaleGeneration)
        );
    }

    #[test]
    fn admission_semaphore_refuses_beyond_cap_and_recovers() {
        let admission = Arc::new(Semaphore::new(MAX_PREAUTH_CONNECTIONS));
        let permits: Vec<_> = (0..MAX_PREAUTH_CONNECTIONS)
            .map(|_| {
                Arc::clone(&admission)
                    .try_acquire_owned()
                    .expect("permit within cap")
            })
            .collect();
        assert!(Arc::clone(&admission).try_acquire_owned().is_err());
        drop(permits);
        assert!(Arc::clone(&admission).try_acquire_owned().is_ok());
    }

    #[test]
    fn transport_idle_timeout_is_separate_from_token_lifetime() {
        let config = RemoteConfig::default();
        assert_eq!(token_lifetime(&config), Duration::from_secs(86_400));

        let transport =
            transport_config(config.validated_transport_idle_timeout()).expect("transport config");
        let rendered = format!("{transport:?}");
        let expected_idle = u32::try_from(config.validated_transport_idle_timeout().as_millis())
            .expect("idle timeout fits a VarInt");
        assert!(
            rendered.contains(&format!(
                "max_idle_timeout: {:?}",
                Some(VarInt::from_u32(expected_idle))
            )),
            "transport must idle out on the transport timeout, not the token lifetime: {rendered}"
        );
        assert!(
            rendered.contains("keep_alive_interval: None"),
            "the server sends no keep-alive of its own; the client bridge probes: {rendered}"
        );
    }

    /// Without a server keep-alive the client's probes are the only traffic
    /// on an idle connection, so the shortest idle timeout an operator can
    /// configure must outlast a probe interval plus the fast re-probes that
    /// follow one lost probe, or an idle client would be timed out by its
    /// own silence.
    #[test]
    fn the_minimum_idle_timeout_outlasts_a_lost_client_probe() {
        let minimum = Duration::from_secs(crate::config::REMOTE_TRANSPORT_IDLE_TIMEOUT_MIN_SECONDS);
        let worst_client_silence = crate::remote::quic::WORST_CASE_PROBE_SILENCE;
        assert!(
            minimum >= worst_client_silence + Duration::from_secs(2),
            "minimum idle timeout {minimum:?} must leave a round trip of slack over the client's worst-case probe silence {worst_client_silence:?}"
        );
    }

    /// One server plus the queue of client sockets its acceptor would receive.
    struct TestServer {
        server: RemoteQuicServer,
        accepted: mpsc::UnboundedReceiver<StdUnixStream>,
    }

    fn test_server_on_free_port() -> TestServer {
        let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind port probe");
        let port = probe.local_addr().expect("probe address").port();
        drop(probe);
        let config = RemoteConfig {
            quic_port_range: format!("{port}-{port}"),
            ..Default::default()
        };
        let (accepted_tx, accepted) = mpsc::unbounded_channel();
        let sink: AcceptedClientSink = Arc::new(move |stream| {
            let _ = accepted_tx.send(stream);
        });
        let server = RemoteQuicServer::start(&config, TEST_SESSION.to_owned(), sink)
            .expect("start QUIC server");
        TestServer { server, accepted }
    }

    fn mint(server: &RemoteQuicServer, logical_client_id: u8) -> RemoteBootstrapRecord {
        server
            .bootstrap(&RemoteBootstrapRequest {
                session: TEST_SESSION.to_owned(),
                logical_client_id: [logical_client_id; REMOTE_QUIC_ID_BYTES],
            })
            .expect("mint capability")
    }

    /// Test-only stand-in for the client's own fingerprint verifier: these
    /// tests dial the real endpoint, so they need the real self-signed
    /// certificate to validate.
    #[derive(Debug)]
    struct PinnedTestCert {
        fingerprint: [u8; REMOTE_QUIC_HASH_BYTES],
        provider: Arc<rustls::crypto::CryptoProvider>,
    }

    impl rustls::client::danger::ServerCertVerifier for PinnedTestCert {
        fn verify_server_cert(
            &self,
            end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            if hash_bytes(end_entity.as_ref()) == self.fingerprint {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General("fingerprint mismatch".to_owned()))
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
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
            cert: &rustls::pki_types::CertificateDer<'_>,
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

    /// One real client, connected and past the hello handshake.
    struct LiveTestClient {
        _endpoint: Endpoint,
        connection: Connection,
        send: SendStream,
        recv: RecvStream,
    }

    /// Dials the real endpoint and sends `hello`, without assuming the server
    /// accepts it: rejection tests need exactly this much of the handshake.
    async fn dial_with_hello(
        record: &RemoteBootstrapRecord,
        logical_client_id: u8,
        connection_generation: u64,
    ) -> LiveTestClient {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("enable TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedTestCert {
                fingerprint: record.certificate_fingerprint,
                provider,
            }))
            .with_no_client_auth();
        tls.alpn_protocols = vec![REMOTE_QUIC_ALPN.to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC client crypto");
        let client_config = quinn::ClientConfig::new(Arc::new(crypto));

        let mut endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind test client endpoint");
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(
                SocketAddr::from((Ipv4Addr::LOCALHOST, record.port)),
                "herdr",
            )
            .expect("start QUIC connect")
            .await
            .expect("QUIC handshake");

        let (mut send, recv) = connection.open_bi().await.expect("open client stream");
        let hello = RemoteQuicHello {
            schema_version: REMOTE_QUIC_SCHEMA_VERSION,
            server_instance_id: record.server_instance_id,
            logical_client_id: [logical_client_id; REMOTE_QUIC_ID_BYTES],
            capability_token: record.capability_token,
            connection_generation,
        };
        write_async_message(&mut send, &hello, MAX_FRAME_SIZE)
            .await
            .expect("send hello");
        LiveTestClient {
            _endpoint: endpoint,
            connection,
            send,
            recv,
        }
    }

    async fn connect_live_test_client(
        record: &RemoteBootstrapRecord,
        logical_client_id: u8,
        connection_generation: u64,
    ) -> LiveTestClient {
        let mut client = dial_with_hello(record, logical_client_id, connection_generation).await;
        let accepted: RemoteQuicAccepted = read_async_message(&mut client.recv, MAX_HELLO_SIZE)
            .await
            .expect("read accepted");
        assert_eq!(accepted.schema_version, REMOTE_QUIC_SCHEMA_VERSION);
        assert_eq!(accepted.connection_generation, connection_generation);
        client
    }

    async fn closed_code(connection: &Connection) -> u64 {
        let closed = tokio::time::timeout(Duration::from_secs(5), connection.closed())
            .await
            .expect("the peer learns the connection closed");
        match closed {
            quinn::ConnectionError::ApplicationClosed(frame) => u64::from(frame.error_code),
            other => panic!("expected an application close, got {other}"),
        }
    }

    #[tokio::test]
    async fn bootstrap_tokens_have_bounded_inventory_lifetime_and_session_scope() {
        let TestServer { server, .. } = test_server_on_free_port();
        assert!(server
            .bootstrap(&RemoteBootstrapRequest {
                session: format!("{TEST_SESSION}-wrong"),
                logical_client_id: [0; REMOTE_QUIC_ID_BYTES],
            })
            .is_err());

        let issued_at = unix_seconds();
        let first = mint(&server, 0);
        assert_eq!(first.schema_version, REMOTE_QUIC_SCHEMA_VERSION);
        let lifetime = token_lifetime(&RemoteConfig::default()).as_secs();
        assert!(first.expires_unix_seconds >= issued_at + lifetime);
        assert!(first.expires_unix_seconds <= issued_at + lifetime + 1);

        for index in 1..=MAX_TOKENS {
            mint(&server, index as u8);
        }
        assert_eq!(lock(&server.state.tokens).len(), MAX_TOKENS);
    }

    /// The whole point of the adapter: the acceptor gets an ordinary Unix
    /// client socket, and bytes cross it in both directions untouched.
    #[tokio::test]
    async fn an_accepted_connection_is_an_ordinary_client_socket() {
        let TestServer {
            server,
            mut accepted,
        } = test_server_on_free_port();
        let record = mint(&server, 21);
        let mut client = connect_live_test_client(&record, 21, 1).await;

        let adapted = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("the sink is handed a client socket")
            .expect("sink channel open");
        adapted
            .set_nonblocking(true)
            .expect("adapt the client socket");
        let mut adapted =
            tokio::net::UnixStream::from_std(adapted).expect("register the client socket");

        client
            .send
            .write_all(b"client-to-server")
            .await
            .expect("write uplink");
        client.send.flush().await.expect("flush uplink");
        let mut uplink = [0u8; 16];
        tokio::time::timeout(Duration::from_secs(5), adapted.read_exact(&mut uplink))
            .await
            .expect("uplink arrives")
            .expect("read uplink");
        assert_eq!(&uplink, b"client-to-server");

        adapted
            .write_all(b"server-to-client")
            .await
            .expect("write downlink");
        let mut downlink = [0u8; 16];
        tokio::time::timeout(
            Duration::from_secs(5),
            client.recv.read_exact(&mut downlink),
        )
        .await
        .expect("downlink arrives")
        .expect("read downlink");
        assert_eq!(&downlink, b"server-to-client");

        // The acceptor dropping the client is a resync, not a reason to
        // bootstrap a new credential.
        drop(adapted);
        assert_eq!(
            closed_code(&client.connection).await,
            u64::from(REMOTE_QUIC_CLOSE_RESYNC)
        );
    }

    /// A roamed client re-dials with the next generation of the same
    /// credential; the connection it is replacing must be told, or two clients
    /// would own one session.
    #[tokio::test]
    async fn a_newer_generation_replaces_the_live_connection() {
        let TestServer {
            server,
            mut accepted,
        } = test_server_on_free_port();
        let record = mint(&server, 22);
        let first = connect_live_test_client(&record, 22, 1).await;
        let _first_socket = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("first client reaches the acceptor")
            .expect("sink channel open");

        let second = connect_live_test_client(&record, 22, 2).await;
        assert_eq!(
            closed_code(&first.connection).await,
            u64::from(REMOTE_QUIC_CLOSE_REPLACED)
        );
        let _second_socket = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("second client reaches the acceptor")
            .expect("sink channel open");

        // The replaced connection must not clear the live one's slot.
        let token_hash = hash_bytes(&record.capability_token);
        for _ in 0..50 {
            if lock(&server.state.tokens)
                .get(&token_hash)
                .is_some_and(|capability| capability.connection_generation == 2)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let tokens = lock(&server.state.tokens);
        let capability = tokens.get(&token_hash).expect("capability survives");
        assert_eq!(capability.connection_generation, 2);
        assert!(capability.active_connection.is_some());
        drop(tokens);
        drop(second);
    }

    /// A stale generation cannot be used to take a session over, and it costs
    /// the client its credential: the only way forward is a fresh bootstrap.
    #[tokio::test]
    async fn a_stale_generation_is_rejected_as_an_auth_failure() {
        let TestServer {
            server,
            mut accepted,
        } = test_server_on_free_port();
        let record = mint(&server, 23);
        let first = connect_live_test_client(&record, 23, 2).await;
        // Held: dropping the acceptor's socket would end the live connection
        // for resync, which is not the rejection this test is about.
        let _first_socket = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("first client reaches the acceptor")
            .expect("sink channel open");
        let stale = dial_with_hello(&record, 23, 1).await;
        assert_eq!(
            closed_code(&stale.connection).await,
            u64::from(REMOTE_QUIC_CLOSE_AUTH)
        );
        assert!(first.connection.close_reason().is_none());
    }

    /// Eviction removes the capability itself, so the token the client holds
    /// can never validate again: it has to bootstrap a new one.
    #[tokio::test]
    async fn evicting_a_capability_closes_its_connection_as_evicted() {
        let TestServer {
            server,
            mut accepted,
        } = test_server_on_free_port();
        let record = mint(&server, 24);
        let client = connect_live_test_client(&record, 24, 1).await;
        let _socket = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("client reaches the acceptor")
            .expect("sink channel open");

        // The live client holds the oldest capability, so overflowing the
        // token table evicts exactly that one.
        for index in 0..=MAX_TOKENS {
            mint(&server, index as u8);
        }
        assert!(!lock(&server.state.tokens).contains_key(&hash_bytes(&record.capability_token)));
        assert_eq!(
            closed_code(&client.connection).await,
            u64::from(REMOTE_QUIC_CLOSE_EVICTED)
        );
    }

    #[tokio::test]
    async fn handoff_export_and_import_keep_capabilities_valid() {
        let TestServer { server, .. } = test_server_on_free_port();
        let port = server.port;
        let record = mint(&server, 7);

        let (state, sockets) = server.export_handoff().expect("export handoff");
        assert_eq!(usize::from(state.socket_fd_count), sockets.len());
        assert_eq!(usize::from(state.socket_fd_count), server.endpoints.len());
        assert_eq!(state.port, port);
        assert_eq!(
            state.certificate_fingerprint,
            record.certificate_fingerprint
        );
        assert_eq!(state.server_instance_id, record.server_instance_id);
        assert_eq!(state.tokens.len(), 1);

        server.close_for_handoff();
        drop(server);

        let config = RemoteConfig::default();
        let (accepted_tx, _accepted) = mpsc::unbounded_channel();
        let sink: AcceptedClientSink = Arc::new(move |stream| {
            let _ = accepted_tx.send(stream);
        });
        let resumed =
            RemoteQuicServer::resume(&config, TEST_SESSION.to_owned(), sink, state, sockets)
                .expect("import handoff");
        // Same listening socket, same identity: the client's pinned
        // fingerprint and its capability both still apply.
        assert_eq!(resumed.port, port);
        assert_eq!(
            resumed
                .sockets
                .first()
                .expect("inherited socket")
                .local_addr()
                .expect("inherited address")
                .port(),
            port
        );
        assert_eq!(resumed.identity.fingerprint, record.certificate_fingerprint);

        // The credential minted before the handoff still validates against the
        // successor's inherited table.
        let hello = RemoteQuicHello {
            schema_version: REMOTE_QUIC_SCHEMA_VERSION,
            server_instance_id: record.server_instance_id,
            logical_client_id: [7; REMOTE_QUIC_ID_BYTES],
            capability_token: record.capability_token,
            connection_generation: 1,
        };
        let tokens = lock(&resumed.state.tokens);
        assert_eq!(
            validate_capability(
                resumed.state.server_instance_id,
                &tokens,
                &hello,
                TEST_SESSION,
                unix_seconds(),
            ),
            Ok(hash_bytes(&record.capability_token))
        );
        drop(tokens);

        // Freshly minted capabilities order after the inherited ones.
        let next = mint(&resumed, 8);
        assert_eq!(next.server_instance_id, record.server_instance_id);
        assert_eq!(next.certificate_fingerprint, record.certificate_fingerprint);
        assert_eq!(lock(&resumed.state.tokens).len(), 2);
    }
}
