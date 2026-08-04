//! TCP/TLS connection and Noise handshake for the Tailscale control plane.
//!
//! This module owns the actual network I/O: it opens a TCP connection,
//! wraps it in TLS, performs the HTTP upgrade to switch the connection into
//! the Tailscale Noise protocol, and exposes an [`AsyncControlStream`] for
//! sending/receiving encrypted control messages.
//!
//! # Protocol flow
//!
//! 1. GET `{control_url}/key?v=71` → parse `{"PublicKey":"mkey:hex..."}` → [`MachinePublic`].
//! 2. TCP connect → TLS handshake.
//! 3. POST `/ts2021` with `Upgrade: tailscale-control-protocol` and
//!    `X-Tailscale-Handshake: base64(noise_initiation)`.
//! 4. Read HTTP 101 response headers.
//! 5. The bytes after the headers are the server's Noise response; complete
//!    the Noise IK handshake via [`ControlConnection::complete_handshake`].
//! 6. All subsequent I/O uses [`AsyncControlStream::send_message`] /
//!    [`AsyncControlStream::recv_message`].

use std::sync::Arc;

use base64::Engine;
use hamma_core::config::{Config, WireConfig};
use hamma_core::keys::{KeyError, MachinePrivate, MachinePublic};
use rustls::ClientConfig;
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::noise::NoiseHandshake;
use crate::transport::ControlConnection;

// ---------------------------------------------------------------------------
// Protocol-fixed constants (NOT parameterizable)
// ---------------------------------------------------------------------------
//
// The path, upgrade-header value, key-endpoint version, and frame-type byte
// are wire-contract values: changing any of them breaks compatibility with
// every tailscale-compatible control server. They stay `const` here so the
// intent is syntactically obvious.

/// Noise upgrade path (Tailscale ts2021 wire contract).
const UPGRADE_PATH: &str = "/ts2021";

/// Key endpoint path. `v=71` is the wire version dictyon speaks; bumping
/// it is a protocol break, not a tuning operation.
const KEY_PATH: &str = "/key?v=71";

/// HTTP Upgrade header value for the Tailscale control protocol.
const UPGRADE_HEADER: &str = "tailscale-control-protocol";

/// Transport frame type byte for post-handshake messages.
const FRAME_TYPE_TRANSPORT: u8 = 0x04;

// Tuning knobs (max header bytes, read chunk size, buffer capacity hints)
// live on [`hamma_core::config::WireConfig`]. The free functions below
// accept a `&Config` or fall back to `Config::default()`.

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur in the wire layer.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum WireError {
    /// DNS resolution or TCP connect failed.
    #[snafu(display("TCP connect failed: {source}"))]
    TcpConnect {
        /// The I/O error.
        source: std::io::Error,
    },

    /// TLS handshake or I/O failed.
    #[snafu(display("TLS error: {source}"))]
    Tls {
        /// The I/O error.
        source: std::io::Error,
    },

    /// The control URL is missing a valid host.
    #[snafu(display("invalid control URL (no host): {url}"))]
    InvalidUrl {
        /// The bad URL.
        url: String,
    },

    /// The server returned a non-101 HTTP status.
    #[snafu(display("expected HTTP 101, got: {status_line}"))]
    UnexpectedStatus {
        /// First line of the HTTP response.
        status_line: String,
    },

    /// The HTTP response headers were malformed or truncated.
    #[snafu(display("malformed HTTP headers: {message}"))]
    MalformedHeaders {
        /// Description of the problem.
        message: String,
    },

    /// The `/key` response was not valid JSON or was missing the field.
    #[snafu(display("key endpoint parse error: {message}"))]
    KeyParse {
        /// Description of the problem.
        message: String,
    },

    /// The key returned by the server failed to parse.
    #[snafu(display("server key invalid: {source}"))]
    ServerKey {
        /// The key parse error.
        source: KeyError,
    },

    /// Noise handshake or transport encryption failed.
    #[snafu(display("noise error: {source}"))]
    Noise {
        /// The noise error.
        source: crate::noise::NoiseError,
    },

    /// A message frame was too short or malformed.
    #[snafu(display("frame error: {message}"))]
    Frame {
        /// Description of the problem.
        message: String,
    },

    /// Connection establishment exceeded the configured deadline.
    #[snafu(display("control connection timed out after {millis} ms"))]
    ConnectTimeout {
        /// The deadline that elapsed, in milliseconds.
        millis: u64,
    },
}

/// Apply the configured establishment deadline to `fut`.
///
/// WHY: TCP connect, TLS handshake, HTTP upgrade and the Noise response frame
/// are each an unbounded await against a stalling or blackholing peer, and the
/// task and socket are held for the lifetime of the runtime when one pends
/// forever. Budgeting the whole sequence once — rather than per step — also
/// stops a peer from stalling indefinitely by dribbling each step just under
/// its own deadline.
async fn with_connect_deadline<F, T>(cfg: &WireConfig, fut: F) -> Result<T, WireError>
where
    F: std::future::Future<Output = Result<T, WireError>>,
{
    match cfg.connect_timeout() {
        None => fut.await,
        Some(deadline) => match tokio::time::timeout(deadline, fut).await {
            Ok(result) => result,
            Err(_elapsed) => Err(WireError::ConnectTimeout {
                millis: cfg.connect_timeout_ms,
            }),
        },
    }
}

impl From<crate::noise::NoiseError> for WireError {
    fn from(source: crate::noise::NoiseError) -> Self {
        Self::Noise { source }
    }
}

// ---------------------------------------------------------------------------
// Public configuration type
// ---------------------------------------------------------------------------

/// Configuration for a control-plane connection.
pub struct ControlConfig {
    /// Base URL of the control server (e.g. `https://controlplane.tailscale.com`).
    pub control_url: String,
    /// This machine's private key.
    pub machine_key: MachinePrivate,
    /// Behavioral tuning knobs (buffer sizes, timeouts, framing limits).
    ///
    /// Defaults to [`Config::default`]; override to expose operator-set or
    /// agent-queried values to the wire and Noise layers.
    pub config: Config,
}

impl ControlConfig {
    /// Build a [`ControlConfig`] with default tuning knobs.
    ///
    /// Equivalent to setting `config: Config::default()` in a struct literal
    /// and kept as the one-call-site constructor for callers that only care
    /// about URL + key.
    #[must_use]
    pub fn new(control_url: String, machine_key: MachinePrivate) -> Self {
        Self {
            control_url,
            machine_key,
            config: Config::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// AsyncControlStream
// ---------------------------------------------------------------------------

/// An established, Noise-encrypted control connection over TLS.
///
/// Obtain via [`connect`]. Use [`send_message`](Self::send_message) and
/// [`recv_message`](Self::recv_message) to exchange control-plane messages.
pub struct AsyncControlStream {
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    conn: ControlConnection,
    /// Bytes already read off the stream but not yet consumed by a frame.
    ///
    /// INVARIANT: the header read may over-read past the `\r\n\r\n`
    /// terminator and past the Noise response frame, so any surplus is
    /// parked here and must be drained before touching the stream again.
    pending: Vec<u8>,
}

impl AsyncControlStream {
    /// Fill `out` completely, taking buffered bytes before reading the stream.
    ///
    /// WARNING: reading the stream directly instead of calling this drops any
    /// bytes the handshake over-read, desynchronising every later frame.
    async fn fill_exact(&mut self, out: &mut [u8]) -> Result<(), WireError> {
        let taken = take_pending(&mut self.pending, out);
        if let Some(rest) = out.get_mut(taken..)
            && !rest.is_empty()
        {
            self.stream.read_exact(rest).await.context(TlsSnafu)?;
        }
        Ok(())
    }

    /// Encrypt `payload` and write it to the TLS stream.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Noise`] if encryption fails, or
    /// [`WireError::Tls`] if the write fails.
    pub async fn send_message(&mut self, payload: &[u8]) -> Result<(), WireError> {
        let frame = self.conn.send(payload).map_err(|e| WireError::Noise {
            source: match e {
                crate::transport::TransportError::Noise { source } => source,
                crate::transport::TransportError::InvalidUrl { url } => {
                    crate::noise::NoiseError::InvalidState { message: url }
                }
            },
        })?;
        debug!(
            target: "dictyon::wire",
            payload_len = payload.len(),
            frame_len = frame.len(),
            "writing control message frame",
        );
        self.stream.write_all(&frame).await.context(TlsSnafu)?;
        debug!(
            target: "dictyon::wire",
            frame_len = frame.len(),
            "control message frame written",
        );
        Ok(())
    }

    /// Read one Noise-framed message from the TLS stream and decrypt it.
    ///
    /// Frame format: `[1B type=0x04][2B BE len][ciphertext]`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Frame`] if the header is malformed,
    /// [`WireError::Noise`] if decryption fails, or [`WireError::Tls`]
    /// on I/O errors.
    pub async fn recv_message(&mut self) -> Result<Vec<u8>, WireError> {
        // Read 3-byte frame header.
        let mut header = [0u8; 3];
        self.fill_exact(&mut header).await?;

        let [frame_type, len_hi, len_lo] = header;
        if frame_type != FRAME_TYPE_TRANSPORT {
            return Err(WireError::Frame {
                message: format!("unexpected frame type: 0x{frame_type:02x}"),
            });
        }

        let body_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
        debug!(
            target: "dictyon::wire",
            body_len,
            "reading control message frame",
        );
        let mut ciphertext = vec![0u8; body_len];
        self.fill_exact(&mut ciphertext).await?;

        let plaintext = self
            .conn
            .receive(&ciphertext)
            .map_err(|e| WireError::Noise {
                source: match e {
                    crate::transport::TransportError::Noise { source } => source,
                    crate::transport::TransportError::InvalidUrl { url } => {
                        crate::noise::NoiseError::InvalidState { message: url }
                    }
                },
            })?;
        debug!(
            target: "dictyon::wire",
            ciphertext_len = body_len,
            plaintext_len = plaintext.len(),
            "control message frame decrypted",
        );
        Ok(plaintext)
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Fetch the control server's public machine key from `GET /key?v=71`.
///
/// Uses [`WireConfig::default`] for buffer/limit knobs. For a caller-tuned
/// variant see [`fetch_server_key_with_config`].
///
/// # Errors
///
/// Returns [`WireError`] on TCP/TLS failure, JSON parse failure, or if the
/// returned key cannot be parsed.
pub async fn fetch_server_key(control_url: &str) -> Result<MachinePublic, WireError> {
    fetch_server_key_with_config(control_url, &WireConfig::default()).await
}

/// Fetch the control server's public machine key using a caller-supplied
/// [`WireConfig`] for I/O buffer/limit tuning.
///
/// # Errors
///
/// Returns [`WireError`] on TCP/TLS failure, JSON parse failure, or if the
/// returned key cannot be parsed.
pub async fn fetch_server_key_with_config(
    control_url: &str,
    cfg: &WireConfig,
) -> Result<MachinePublic, WireError> {
    with_connect_deadline(cfg, fetch_server_key_with_config_inner(control_url, cfg)).await
}

async fn fetch_server_key_with_config_inner(
    control_url: &str,
    cfg: &WireConfig,
) -> Result<MachinePublic, WireError> {
    let (host, port) = parse_host_port(control_url)?;
    debug!(
        target: "dictyon::wire",
        host,
        port,
        "fetching control server key",
    );
    let tls = build_tls_config();
    let connector = TlsConnector::from(Arc::new(tls));

    let addr = format!("{host}:{port}");
    let tcp = TcpStream::connect(&addr).await.context(TcpConnectSnafu)?;
    debug!(
        target: "dictyon::wire",
        host,
        port,
        "tcp connection established for server key fetch",
    );

    let server_name =
        rustls::pki_types::ServerName::try_from(host.as_str().to_owned()).map_err(|_| {
            WireError::InvalidUrl {
                url: control_url.to_string(),
            }
        })?;

    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .context(TlsSnafu)?;

    let request = format!("GET {KEY_PATH} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls_stream
        .write_all(request.as_bytes())
        .await
        .context(TlsSnafu)?;

    let response = read_full_response(&mut tls_stream, cfg).await?;
    let server_key = parse_server_key_response(&response)?;
    debug!(
        target: "dictyon::wire",
        response_len = response.len(),
        "control server key fetched",
    );
    Ok(server_key)
}

/// Connect to the control server, complete the Noise IK handshake, and
/// return an [`AsyncControlStream`] ready for control messages.
///
/// Uses the tuning knobs on `config.config`. Default-construct `ControlConfig`
/// with [`Config::default`] to match pre-config behavior.
///
/// # Errors
///
/// Returns [`WireError`] on any I/O, TLS, HTTP, or Noise failure.
pub async fn connect(config: &ControlConfig) -> Result<AsyncControlStream, WireError> {
    debug!(
        target: "dictyon::wire",
        "connecting to control server",
    );
    let server_key = fetch_server_key_with_config(&config.control_url, &config.config.wire).await?;
    connect_with_key(config, server_key).await
}

/// Connect with a custom [`ClientConfig`], bypassing the default webpki roots.
///
/// This is the same as [`connect`] but accepts a caller-supplied TLS
/// configuration. Intended for testing (custom CA) and environments where the
/// caller manages certificate trust.
///
/// # Errors
///
/// Returns [`WireError`] on any I/O, TLS, HTTP, or Noise failure.
pub async fn connect_with_tls(
    config: &ControlConfig,
    tls_config: ClientConfig,
) -> Result<AsyncControlStream, WireError> {
    debug!(
        target: "dictyon::wire",
        "connecting to control server with caller tls config",
    );
    let server_key = fetch_server_key_with_tls_and_config(
        &config.control_url,
        tls_config.clone(),
        &config.config.wire,
    )
    .await?;
    connect_with_key_and_tls(config, server_key, tls_config).await
}

/// Fetch the server key using a caller-supplied TLS config.
///
/// Uses [`WireConfig::default`] for buffer/limit knobs.
///
/// # Errors
///
/// Returns [`WireError`] on TCP/TLS failure, JSON parse failure, or if the
/// returned key cannot be parsed.
pub async fn fetch_server_key_with_tls(
    control_url: &str,
    tls_config: ClientConfig,
) -> Result<MachinePublic, WireError> {
    fetch_server_key_with_tls_and_config(control_url, tls_config, &WireConfig::default()).await
}

/// Fetch the server key using caller-supplied TLS config *and* wire-layer
/// tuning knobs.
///
/// # Errors
///
/// Returns [`WireError`] on TCP/TLS failure, JSON parse failure, or if the
/// returned key cannot be parsed.
pub async fn fetch_server_key_with_tls_and_config(
    control_url: &str,
    tls_config: ClientConfig,
    cfg: &WireConfig,
) -> Result<MachinePublic, WireError> {
    with_connect_deadline(
        cfg,
        fetch_server_key_with_tls_and_config_inner(control_url, tls_config, cfg),
    )
    .await
}

async fn fetch_server_key_with_tls_and_config_inner(
    control_url: &str,
    tls_config: ClientConfig,
    cfg: &WireConfig,
) -> Result<MachinePublic, WireError> {
    let (host, port) = parse_host_port(control_url)?;
    debug!(
        target: "dictyon::wire",
        host,
        port,
        "fetching control server key with caller tls config",
    );
    let connector = TlsConnector::from(Arc::new(tls_config));

    let addr = format!("{host}:{port}");
    let tcp = TcpStream::connect(&addr).await.context(TcpConnectSnafu)?;
    debug!(
        target: "dictyon::wire",
        host,
        port,
        "tcp connection established for server key fetch",
    );

    let server_name =
        rustls::pki_types::ServerName::try_from(host.as_str().to_owned()).map_err(|_| {
            WireError::InvalidUrl {
                url: control_url.to_string(),
            }
        })?;

    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .context(TlsSnafu)?;

    let request = format!("GET {KEY_PATH} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls_stream
        .write_all(request.as_bytes())
        .await
        .context(TlsSnafu)?;

    let response = read_full_response(&mut tls_stream, cfg).await?;
    let server_key = parse_server_key_response(&response)?;
    debug!(
        target: "dictyon::wire",
        response_len = response.len(),
        "control server key fetched",
    );
    Ok(server_key)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Inner connect, separated so tests can inject a server key.
async fn connect_with_key(
    config: &ControlConfig,
    server_key: MachinePublic,
) -> Result<AsyncControlStream, WireError> {
    connect_with_key_and_tls(config, server_key, build_tls_config()).await
}

/// Inner connect with caller-supplied TLS config and a pre-fetched server key.
async fn connect_with_key_and_tls(
    config: &ControlConfig,
    server_key: MachinePublic,
    tls_cfg: ClientConfig,
) -> Result<AsyncControlStream, WireError> {
    with_connect_deadline(
        &config.config.wire,
        connect_with_key_and_tls_inner(config, server_key, tls_cfg),
    )
    .await
}

async fn connect_with_key_and_tls_inner(
    config: &ControlConfig,
    server_key: MachinePublic,
    tls_cfg: ClientConfig,
) -> Result<AsyncControlStream, WireError> {
    let (host, port) = parse_host_port(&config.control_url)?;
    debug!(target: "dictyon::wire", host, port, "opening control wire connection");
    let connector = TlsConnector::from(Arc::new(tls_cfg));

    let addr = format!("{host}:{port}");
    let tcp = TcpStream::connect(&addr).await.context(TcpConnectSnafu)?;
    debug!(target: "dictyon::wire", host, port, "tcp connection established for control wire");

    let server_name =
        rustls::pki_types::ServerName::try_from(host.as_str().to_owned()).map_err(|_| {
            WireError::InvalidUrl {
                url: config.control_url.clone(),
            }
        })?;

    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .context(TlsSnafu)?;
    debug!(target: "dictyon::wire", host, port, "tls connection established for control wire");

    // Build Noise initiation using the handshake/framing knobs.
    let machine_key_copy = MachinePrivate::from_bytes(*config.machine_key.as_bytes());
    let mut handshake =
        NoiseHandshake::with_config(machine_key_copy, server_key, config.config.noise.clone());
    let init_msg = handshake.initiation_message()?;
    let init_b64 = base64::engine::general_purpose::STANDARD.encode(&init_msg);
    debug!(
        target: "dictyon::wire",
        initiation_len = init_msg.len(),
        "noise initiation prepared",
    );

    // Send HTTP upgrade request.
    let request = build_upgrade_request(&host, &init_b64);
    tls_stream
        .write_all(request.as_bytes())
        .await
        .context(TlsSnafu)?;
    debug!(target: "dictyon::wire", "noise upgrade request written");

    // Read HTTP headers; the Noise response frame follows in the stream, and
    // the chunked header read may already have captured part or all of it.
    let (status_line, after_headers) =
        read_upgrade_response(&mut tls_stream, &config.config.wire).await?;

    if !status_line.contains("101") {
        return Err(WireError::UnexpectedStatus { status_line });
    }
    debug!(target: "dictyon::wire", "noise upgrade accepted");

    // Read the Noise response frame from the stream.
    // Frame format: [1B type=0x02][2B BE payload_len][noise_msg]
    let (noise_body, pending) = read_noise_response_frame(&mut tls_stream, after_headers).await?;
    debug!(
        target: "dictyon::wire",
        response_len = noise_body.len(),
        "noise response frame read",
    );

    // Complete the Noise handshake.
    let conn = ControlConnection::complete_handshake(handshake, &noise_body).map_err(|e| {
        WireError::Noise {
            source: match e {
                crate::transport::TransportError::Noise { source } => source,
                crate::transport::TransportError::InvalidUrl { url } => {
                    crate::noise::NoiseError::InvalidState { message: url }
                }
            },
        }
    })?;
    debug!(target: "dictyon::wire", "control wire connection established");

    Ok(AsyncControlStream {
        stream: tls_stream,
        conn,
        pending,
    })
}

/// Build the TLS client config using the webpki root certificates.
fn build_tls_config() -> ClientConfig {
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Extract the hostname and port from a URL like `https://host` or
/// `https://host:port`.
///
/// Only `https://` URLs are accepted; plain HTTP is rejected because all
/// control-plane traffic carries credentials and must be TLS-wrapped.
fn parse_host_port(url: &str) -> Result<(String, u16), WireError> {
    let without_scheme = url
        .trim_end_matches('/')
        .strip_prefix("https://")
        .ok_or_else(|| WireError::InvalidUrl {
            url: url.to_string(),
        })?;

    // Strip any path component.
    let host_port = without_scheme
        .split('/')
        .next()
        .ok_or_else(|| WireError::InvalidUrl {
            url: url.to_string(),
        })?;

    if let Some(bracket_end) = host_port.rfind(']') {
        // IPv6 address: `[::1]:443` or `[::1]`
        let after = host_port
            .get(bracket_end + 1..)
            .ok_or_else(|| WireError::InvalidUrl {
                url: url.to_string(),
            })?;
        let host = host_port
            .get(..=bracket_end)
            .ok_or_else(|| WireError::InvalidUrl {
                url: url.to_string(),
            })?
            .to_string();
        let port = if let Some(port_str) = after.strip_prefix(':') {
            port_str.parse::<u16>().map_err(|_| WireError::InvalidUrl {
                url: url.to_string(),
            })?
        } else {
            443
        };
        return Ok((host, port));
    }

    match host_port.rsplit_once(':') {
        Some((host, port_str)) => {
            let port = port_str.parse::<u16>().map_err(|_| WireError::InvalidUrl {
                url: url.to_string(),
            })?;
            Ok((host.to_string(), port))
        }
        None => Ok((host_port.to_string(), 443)),
    }
}

/// Build the HTTP upgrade request string.
fn build_upgrade_request(host: &str, init_b64: &str) -> String {
    format!(
        "POST {UPGRADE_PATH} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: {UPGRADE_HEADER}\r\n\
         Connection: Upgrade\r\n\
         X-Tailscale-Handshake: {init_b64}\r\n\
         Content-Length: 0\r\n\
         \r\n"
    )
}

/// Move up to `out.len()` bytes off the front of `pending` into `out`.
///
/// Returns the number of bytes moved.
fn take_pending(pending: &mut Vec<u8>, out: &mut [u8]) -> usize {
    let n = pending.len().min(out.len());
    let (Some(dst), Some(src)) = (out.get_mut(..n), pending.get(..n)) else {
        return 0;
    };
    dst.copy_from_slice(src);
    pending.drain(..n);
    n
}

/// Read the Noise response frame, consuming `prefix` before the stream.
///
/// The server sends the Noise response frame directly in the stream after
/// `\r\n\r\n`, so the header read routinely captures some or all of it.
/// Frame format: `[1B type=0x02][2B BE payload_len][noise_msg]`.
///
/// INVARIANT: `prefix` holds the bytes already read past the header
/// terminator. Returns the full framed bytes for
/// `NoiseHandshake::process_response` plus whatever of `prefix` remained
/// beyond the frame; dropping that surplus would desynchronise the first
/// transport frame.
async fn read_noise_response_frame<R>(
    stream: &mut R,
    mut prefix: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>), WireError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 3];
    fill_from(stream, &mut prefix, &mut header).await?;

    let [_msg_type, len_hi, len_lo] = header;
    let payload_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    let mut noise_msg = vec![0u8; payload_len];
    fill_from(stream, &mut prefix, &mut noise_msg).await?;

    let mut framed = Vec::with_capacity(3 + payload_len);
    framed.extend_from_slice(&header);
    framed.extend_from_slice(&noise_msg);
    Ok((framed, prefix))
}

/// Fill `out` from `prefix` first, then from `stream`.
async fn fill_from<R>(stream: &mut R, prefix: &mut Vec<u8>, out: &mut [u8]) -> Result<(), WireError>
where
    R: AsyncRead + Unpin,
{
    let taken = take_pending(prefix, out);
    if let Some(rest) = out.get_mut(taken..)
        && !rest.is_empty()
    {
        stream.read_exact(rest).await.context(TlsSnafu)?;
    }
    Ok(())
}

/// Read until `\r\n\r\n`, returning (`first_line`, `bytes_after_headers`).
///
/// INVARIANT: the second element is not decorative. The header read is
/// chunked, so it routinely captures bytes belonging to the Noise response
/// frame that follows; the caller must feed them to
/// [`read_noise_response_frame`].
async fn read_upgrade_response<R>(
    stream: &mut R,
    cfg: &WireConfig,
) -> Result<(String, Vec<u8>), WireError>
where
    R: AsyncRead + Unpin,
{
    let buf = read_until_header_end(stream, cfg).await?;

    // Split at the header terminator.
    let sep = b"\r\n\r\n";
    let sep_pos =
        buf.windows(4)
            .position(|w| w == sep)
            .ok_or_else(|| WireError::MalformedHeaders {
                message: "header terminator not found".to_string(),
            })?;

    let headers_bytes = buf
        .get(..sep_pos)
        .ok_or_else(|| WireError::MalformedHeaders {
            message: "header separator position out of bounds".to_string(),
        })?;
    let body = buf
        .get(sep_pos + 4..)
        .ok_or_else(|| WireError::MalformedHeaders {
            message: "header body position out of bounds".to_string(),
        })?
        .to_vec();

    let headers_str =
        std::str::from_utf8(headers_bytes).map_err(|_| WireError::MalformedHeaders {
            message: "headers are not valid UTF-8".to_string(),
        })?;

    let first_line = headers_str.lines().next().unwrap_or("").to_string();

    Ok((first_line, body))
}

/// Read from the stream until we see `\r\n\r\n` or hit the size limit.
///
/// Reads in chunks rather than a byte at a time, so the returned buffer may
/// extend past the terminator into the Noise response frame. The size limit
/// applies to the header block itself — the position of the terminator — not
/// to the total number of bytes buffered, or a large frame arriving in the
/// same chunk would be misreported as oversized headers.
async fn read_until_header_end<R>(stream: &mut R, cfg: &WireConfig) -> Result<Vec<u8>, WireError>
where
    R: AsyncRead + Unpin,
{
    let max_header_bytes = cfg.max_header_bytes;
    let mut buf = Vec::with_capacity(cfg.header_read_initial_capacity);
    let mut chunk = vec![0u8; cfg.response_read_chunk_bytes.max(1)];
    // WHY: a terminator can straddle a chunk boundary, so rescan the last
    // three bytes of the previous fill alongside the new ones.
    let mut scanned = 0usize;

    loop {
        if let Some(sep_pos) = find_header_end(&buf, scanned) {
            if sep_pos > max_header_bytes {
                return Err(WireError::MalformedHeaders {
                    message: format!("headers exceeded {max_header_bytes} bytes"),
                });
            }
            return Ok(buf);
        }

        if buf.len() > max_header_bytes {
            return Err(WireError::MalformedHeaders {
                message: format!("headers exceeded {max_header_bytes} bytes"),
            });
        }

        scanned = buf.len();
        let n = stream.read(&mut chunk).await.context(TlsSnafu)?;
        if n == 0 {
            return Err(WireError::MalformedHeaders {
                message: "connection closed before header terminator".to_string(),
            });
        }
        let slice = chunk.get(..n).ok_or_else(|| WireError::MalformedHeaders {
            message: "read returned more bytes than buffer".to_string(),
        })?;
        buf.extend_from_slice(slice);
    }
}

/// Find `\r\n\r\n` in `buf`, resuming three bytes before `scanned`.
fn find_header_end(buf: &[u8], scanned: usize) -> Option<usize> {
    let from = scanned.saturating_sub(3);
    let window = buf.get(from..)?;
    window
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + from)
}

/// Append `slice` to `buf`, refusing the append if it would exceed `max_body`.
///
/// INVARIANT: on error `buf` is left untouched, so the accumulated response
/// never occupies more than `max_body` bytes. Checking after the append would
/// still reject the response, but only once the process had already committed
/// to holding it — a server-controlled overshoot of up to one chunk.
fn push_within_limit(buf: &mut Vec<u8>, slice: &[u8], max_body: usize) -> Result<(), WireError> {
    if buf.len().saturating_add(slice.len()) > max_body {
        return Err(WireError::KeyParse {
            message: "response too large".to_string(),
        });
    }
    buf.extend_from_slice(slice);
    Ok(())
}

/// Read the full HTTP/1.1 response body (for the /key endpoint).
async fn read_full_response(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    cfg: &WireConfig,
) -> Result<Vec<u8>, WireError> {
    let max_body = cfg.key_response_max_bytes();
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; cfg.response_read_chunk_bytes];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                let slice = chunk.get(..n).ok_or_else(|| WireError::KeyParse {
                    message: "read returned more bytes than buffer".to_string(),
                })?;
                push_within_limit(&mut buf, slice, max_body)?;
            }
            Err(e) => return Err(WireError::Tls { source: e }),
        }
    }
    Ok(buf)
}

/// Parse `{"PublicKey":"mkey:hex..."}` from the raw HTTP response bytes.
fn parse_server_key_response(response: &[u8]) -> Result<MachinePublic, WireError> {
    // Find the JSON body after the headers.
    let sep = b"\r\n\r\n";
    let body_start = response
        .windows(4)
        .position(|w| w == sep)
        .map_or(0, |p| p + 4);

    let body = &response[body_start..];
    let json: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| WireError::KeyParse {
            message: e.to_string(),
        })?;

    let key_str = json
        .get("PublicKey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WireError::KeyParse {
            message: "missing 'PublicKey' field".to_string(),
        })?;

    MachinePublic::from_hex(key_str).context(ServerKeySnafu)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "tests use expect() for invariants that must hold"
)]
mod tests {
    use std::collections::VecDeque;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::ReadBuf;
    use tokio::net::TcpListener;

    use super::*;

    /// A reader that yields pre-set chunks, at most one per `poll_read`.
    ///
    /// WHY: the defect under test is dependence on where the stream happens
    /// to split, so a test needs to choose the split points itself. An
    /// exhausted reader reports EOF.
    struct ChunkReader {
        chunks: VecDeque<Vec<u8>>,
    }

    impl ChunkReader {
        fn new<I: IntoIterator<Item = Vec<u8>>>(chunks: I) -> Self {
            Self {
                chunks: chunks.into_iter().filter(|c| !c.is_empty()).collect(),
            }
        }

        fn empty() -> Self {
            Self {
                chunks: VecDeque::new(),
            }
        }
    }

    impl AsyncRead for ChunkReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let Some(front) = self.chunks.front_mut() else {
                return Poll::Ready(Ok(()));
            };
            let n = front.len().min(buf.remaining());
            let taken: Vec<u8> = front.drain(..n).collect();
            buf.put_slice(&taken);
            if front.is_empty() {
                self.chunks.pop_front();
            }
            Poll::Ready(Ok(()))
        }
    }

    /// `[1B type=0x02][2B BE len][payload]` — the Noise response frame shape.
    fn noise_frame(payload: &[u8]) -> Vec<u8> {
        let len = u16::try_from(payload.len()).expect("test payload fits u16");
        let mut f = vec![0x02];
        f.extend_from_slice(&len.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    const HEADERS: &[u8] =
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\n\r\n";

    #[tokio::test]
    async fn read_upgrade_response_returns_the_bytes_after_the_terminator() {
        let frame = noise_frame(b"noise-response");
        let mut wire = HEADERS.to_vec();
        wire.extend_from_slice(&frame);
        // The whole response arrives in one chunk, as a real server sends it.
        let mut stream = ChunkReader::new([wire]);

        let (status_line, after) = read_upgrade_response(&mut stream, &WireConfig::default())
            .await
            .expect("headers should parse");

        assert_eq!(status_line, "HTTP/1.1 101 Switching Protocols");
        assert_eq!(after, frame, "frame bytes must survive the header read");
    }

    #[tokio::test]
    async fn read_noise_response_frame_reads_entirely_from_the_prefix() {
        // The stream is at EOF: every byte of the frame was already captured
        // by the header read. Reading the stream here would fail outright.
        let frame = noise_frame(b"payload");
        let (framed, leftover) =
            read_noise_response_frame(&mut ChunkReader::empty(), frame.clone())
                .await
                .expect("frame should come from the prefix");

        assert_eq!(framed, frame);
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn read_noise_response_frame_preserves_bytes_beyond_the_frame() {
        let frame = noise_frame(b"payload");
        let mut prefix = frame.clone();
        prefix.extend_from_slice(b"first-transport-frame");

        let (framed, leftover) = read_noise_response_frame(&mut ChunkReader::empty(), prefix)
            .await
            .expect("frame should parse");

        assert_eq!(framed, frame);
        assert_eq!(
            leftover, b"first-transport-frame",
            "surplus must be handed back, not dropped"
        );
    }

    #[tokio::test]
    async fn read_noise_response_frame_spans_prefix_and_stream() {
        let frame = noise_frame(b"payload");
        // The header read stopped two bytes into the frame header.
        let split = 2;
        let prefix = frame.get(..split).expect("split within frame").to_vec();
        let rest = frame.get(split..).expect("split within frame").to_vec();
        let mut stream = ChunkReader::new([rest]);

        let (framed, leftover) = read_noise_response_frame(&mut stream, prefix)
            .await
            .expect("frame should parse across the boundary");

        assert_eq!(framed, frame);
        assert!(leftover.is_empty());
    }

    #[tokio::test]
    async fn read_until_header_end_finds_a_terminator_split_across_chunks() {
        // The terminator straddles the boundary: "...\r\n" | "\r\n..."
        let first = b"HTTP/1.1 101 OK\r\nX: y\r\n".to_vec();
        let second = b"\r\nbody".to_vec();
        let mut stream = ChunkReader::new([first, second]);

        let buf = read_until_header_end(&mut stream, &WireConfig::default())
            .await
            .expect("terminator should be found across the boundary");

        assert!(buf.ends_with(b"\r\n\r\nbody"));
    }

    #[tokio::test]
    async fn read_until_header_end_accepts_a_body_larger_than_the_header_cap() {
        // Short headers, then a body far over max_header_bytes in the same
        // chunk. Bounding on buffer length instead of terminator position
        // would reject this valid response.
        let mut cfg = WireConfig::default();
        cfg.max_header_bytes = 64;
        let mut wire = b"HTTP/1.1 101 OK\r\n\r\n".to_vec();
        wire.extend_from_slice(&vec![b'x'; 4096]);
        let mut stream = ChunkReader::new([wire]);

        let buf = read_until_header_end(&mut stream, &cfg)
            .await
            .expect("a large body must not read as oversized headers");

        assert!(
            buf.len() > cfg.max_header_bytes,
            "the cap must bound the header block, not the bytes buffered",
        );
        assert!(buf.starts_with(b"HTTP/1.1 101 OK\r\n\r\n"));
    }

    #[tokio::test]
    async fn read_until_header_end_rejects_headers_over_the_cap() {
        let mut cfg = WireConfig::default();
        cfg.max_header_bytes = 64;
        // No terminator anywhere.
        let mut stream = ChunkReader::new([vec![b'h'; 512]]);

        let err = read_until_header_end(&mut stream, &cfg)
            .await
            .expect_err("oversized headers must be rejected");

        assert!(matches!(err, WireError::MalformedHeaders { .. }));
    }

    #[tokio::test]
    async fn read_until_header_end_errors_on_eof_before_the_terminator() {
        let mut stream = ChunkReader::new([b"HTTP/1.1 101 OK\r\n".to_vec()]);

        let err = read_until_header_end(&mut stream, &WireConfig::default())
            .await
            .expect_err("a truncated header block must error");

        assert!(matches!(err, WireError::MalformedHeaders { .. }));
    }

    #[test]
    fn take_pending_drains_only_what_fits() {
        let mut pending = b"abcdef".to_vec();
        let mut out = [0u8; 4];

        assert_eq!(take_pending(&mut pending, &mut out), 4);
        assert_eq!(&out, b"abcd");
        assert_eq!(pending, b"ef");
    }

    #[test]
    fn take_pending_reports_a_short_fill() {
        let mut pending = b"ab".to_vec();
        let mut out = [0u8; 4];

        assert_eq!(take_pending(&mut pending, &mut out), 2);
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn connect_times_out_against_a_blackholing_peer() {
        // A peer that completes the TCP handshake and then says nothing. The
        // TLS ServerHello never arrives, so without a deadline the dial pends
        // for the lifetime of the runtime holding the task and the socket.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let _blackhole = tokio::spawn(async move {
            let _held = listener.accept().await;
            // INVARIANT: hold the accepted socket open for the test's
            // duration. Dropping it would send a reset and surface a TLS
            // error instead of the hang under test.
            std::future::pending::<()>().await;
        });

        // WireConfig is #[non_exhaustive], so it cannot be built with a struct
        // expression from outside hamma-core.
        let mut cfg = WireConfig::default();
        cfg.connect_timeout_ms = 150;
        let url = format!("https://127.0.0.1:{port}");

        // WHY the outer timeout: it is the falsifier. Without the deadline in
        // `with_connect_deadline` the inner call never returns, and this test
        // fails in five seconds instead of hanging the suite.
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            fetch_server_key_with_config(&url, &cfg),
        )
        .await;

        let Ok(result) = outcome else {
            panic!("dial ignored its own 150 ms deadline");
        };
        match result {
            Err(WireError::ConnectTimeout { millis }) => assert_eq!(millis, 150),
            Err(other) => panic!("expected ConnectTimeout, got: {other}"),
            Ok(_) => panic!("expected ConnectTimeout, got a server key"),
        }
    }

    #[test]
    fn parse_host_port_https_default() {
        let (host, port) =
            parse_host_port("https://controlplane.tailscale.com").expect("should parse");
        assert_eq!(host, "controlplane.tailscale.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_host_port_with_explicit_port() {
        let (host, port) = parse_host_port("https://localhost:8443").expect("should parse");
        assert_eq!(host, "localhost");
        assert_eq!(port, 8443);
    }

    #[test]
    fn parse_host_port_trailing_slash() {
        let (host, port) =
            parse_host_port("https://controlplane.tailscale.com/").expect("should parse");
        assert_eq!(host, "controlplane.tailscale.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn build_upgrade_request_contains_required_headers() {
        let req = build_upgrade_request("controlplane.tailscale.com", "base64data==");
        assert!(req.contains("POST /ts2021"), "should POST to /ts2021");
        assert!(req.contains("Upgrade: tailscale-control-protocol"));
        assert!(req.contains("X-Tailscale-Handshake: base64data=="));
    }

    #[test]
    fn parse_server_key_response_extracts_key() {
        // A known 32-byte all-zeros key in mkey: format.
        let hex = "0".repeat(64);
        let json_body = format!(r#"{{"PublicKey":"mkey:{hex}"}}"#);
        let response =
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{json_body}");

        let key = parse_server_key_response(response.as_bytes()).expect("should parse");
        assert_eq!(key.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn parse_server_key_response_missing_field_errors() {
        let response = b"HTTP/1.1 200 OK\r\n\r\n{}";
        let result = parse_server_key_response(response);
        assert!(result.is_err());
    }

    #[test]
    fn push_within_limit_accepts_up_to_the_limit() {
        let mut buf = vec![0u8; 8];
        let result = push_within_limit(&mut buf, &[1u8; 2], 10);
        assert!(
            result.is_ok(),
            "an append reaching exactly max_body is fine"
        );
        assert_eq!(buf.len(), 10);
    }

    #[test]
    fn push_within_limit_rejects_without_growing_the_buffer() {
        // WHY: the guard must reject *before* appending. Checking after the
        // append also returns an error, so asserting only on the error cannot
        // tell the two apart -- the buffer length at the point of rejection is
        // the observable that separates them.
        let mut buf = vec![0u8; 8];
        let result = push_within_limit(&mut buf, &[1u8; 8], 10);
        assert!(result.is_err(), "8 + 8 exceeds max_body of 10");
        assert_eq!(
            buf.len(),
            8,
            "rejected chunk must not be committed to the buffer"
        );
    }

    #[test]
    fn push_within_limit_rejects_a_single_oversized_chunk() {
        let mut buf = Vec::new();
        let result = push_within_limit(&mut buf, &[1u8; 64], 10);
        assert!(result.is_err());
        assert!(
            buf.is_empty(),
            "nothing is accumulated for an over-limit read"
        );
    }
}
