//! TCP/TLS connection and Noise handshake for the Tailscale control plane.
//!
//! This module owns the actual network I/O: it opens a TCP connection,
//! wraps it in TLS, performs the HTTP upgrade to switch the connection into
//! the Tailscale Noise protocol, and exposes an [`AsyncControlStream`] for
//! sending/receiving encrypted control messages.
//!
//! # Protocol flow
//!
//! 1. GET `{control_url}/key?v={N}` (`N` = [`mitos::capability::CAPABILITY_VERSION`])
//!    → parse `{"PublicKey":"mkey:hex..."}` → [`MachinePublic`].
//! 2. TCP connect → TLS handshake.
//! 3. POST `/ts2021` with `Upgrade: tailscale-control-protocol` and
//!    `X-Tailscale-Handshake: base64(noise_initiation)`.
//! 4. Read HTTP 101 response headers.
//! 5. The bytes after the headers are the server's Noise response; complete
//!    the Noise IK handshake via [`ControlConnection::complete_handshake`].
//! 6. All subsequent I/O uses [`AsyncControlStream::send_message`] /
//!    [`AsyncControlStream::recv_message`].

use std::sync::Arc;

use mitos::capability::CAPABILITY_VERSION;
use mitos::config::{Config, WireConfig};
use mitos::keys::{KeyError, MachinePrivate, MachinePublic};
use rustls::ClientConfig;
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

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

/// Key endpoint path, e.g. `/key?v=71`.
///
/// Wire-format invariant: the query parameter is
/// [`mitos::capability::CAPABILITY_VERSION`], the wire version dictyon
/// speaks. It is a function rather than a `const` because the value is
/// built from a non-`'static` [`std::fmt::Display`] impl; bumping the
/// underlying capability version is a protocol break, not a tuning
/// operation.
fn key_path() -> String {
    format!("/key?v={CAPABILITY_VERSION}")
}

/// HTTP Upgrade header value for the Tailscale control protocol.
const UPGRADE_HEADER: &str = "tailscale-control-protocol";

/// Transport frame type byte for post-handshake messages.
const FRAME_TYPE_TRANSPORT: u8 = 0x04;

// Tuning knobs (max header bytes, read chunk size, buffer capacity hints)
// live on [`mitos::config::WireConfig`]. The free functions below
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
        let taken = support::take_pending(&mut self.pending, out);
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

/// Fetch the control server's public machine key from [`key_path`]
/// (`GET /key?v={N}`, `N` = [`mitos::capability::CAPABILITY_VERSION`]).
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
    let (host, port) = support::parse_host_port(control_url)?;
    debug!(
        target: "dictyon::wire",
        host,
        port,
        "fetching control server key",
    );
    let tls = support::build_tls_config();
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

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        key_path()
    );
    tls_stream
        .write_all(request.as_bytes())
        .await
        .context(TlsSnafu)?;

    let response = support::read_full_response(&mut tls_stream, cfg).await?;
    let server_key = support::parse_server_key_response(&response)?;
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
    support::connect_with_key(config, server_key).await
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
    support::connect_with_key_and_tls(config, server_key, tls_config).await
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
    let (host, port) = support::parse_host_port(control_url)?;
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

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        key_path()
    );
    tls_stream
        .write_all(request.as_bytes())
        .await
        .context(TlsSnafu)?;

    let response = support::read_full_response(&mut tls_stream, cfg).await?;
    let server_key = support::parse_server_key_response(&response)?;
    debug!(
        target: "dictyon::wire",
        response_len = response.len(),
        "control server key fetched",
    );
    Ok(server_key)
}

// ---------------------------------------------------------------------------
// Internal helpers and tests
// ---------------------------------------------------------------------------
//
// NOTE(RUST/file-too-long): split into sibling files — wire.rs + helpers +
// tests together exceeded the 800-line threshold.

mod support;

#[cfg(test)]
mod tests;
