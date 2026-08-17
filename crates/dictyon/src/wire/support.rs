//! Connection-establishment and framing helpers for [`super`].
//!
//! Split into a sibling file because wire.rs + helpers + tests together
//! exceeded the `RUST/file-too-long` threshold.

use std::sync::Arc;

use base64::Engine;
use mitos::config::WireConfig;
use mitos::keys::{MachinePrivate, MachinePublic};
use rustls::ClientConfig;
use snafu::ResultExt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::noise::NoiseHandshake;
use crate::transport::ControlConnection;

use super::{
    AsyncControlStream, ControlConfig, ServerKeySnafu, TcpConnectSnafu, TlsSnafu, UPGRADE_HEADER,
    UPGRADE_PATH, WireError, with_connect_deadline,
};

/// Inner connect, separated so tests can inject a server key.
pub(super) async fn connect_with_key(
    config: &ControlConfig,
    server_key: MachinePublic,
) -> Result<AsyncControlStream, WireError> {
    connect_with_key_and_tls(config, server_key, build_tls_config()).await
}

/// Inner connect with caller-supplied TLS config and a pre-fetched server key.
pub(super) async fn connect_with_key_and_tls(
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
pub(super) fn build_tls_config() -> ClientConfig {
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
pub(super) fn parse_host_port(url: &str) -> Result<(String, u16), WireError> {
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
pub(super) fn build_upgrade_request(host: &str, init_b64: &str) -> String {
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
pub(super) fn take_pending(pending: &mut Vec<u8>, out: &mut [u8]) -> usize {
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
pub(super) async fn read_noise_response_frame<R>(
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
pub(super) async fn read_upgrade_response<R>(
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
pub(super) async fn read_until_header_end<R>(
    stream: &mut R,
    cfg: &WireConfig,
) -> Result<Vec<u8>, WireError>
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
pub(super) fn push_within_limit(
    buf: &mut Vec<u8>,
    slice: &[u8],
    max_body: usize,
) -> Result<(), WireError> {
    if buf.len().saturating_add(slice.len()) > max_body {
        return Err(WireError::KeyParse {
            message: "response too large".to_string(),
        });
    }
    buf.extend_from_slice(slice);
    Ok(())
}

/// Read the full HTTP/1.1 response body (for the /key endpoint).
pub(super) async fn read_full_response(
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
pub(super) fn parse_server_key_response(response: &[u8]) -> Result<MachinePublic, WireError> {
    // Find the JSON body after the headers.
    let sep = b"\r\n\r\n";
    let body_start = response
        .windows(4)
        .position(|w| w == sep)
        .map_or(0, |p| p + 4);

    let body = response
        .get(body_start..)
        .ok_or_else(|| WireError::KeyParse {
            message: "header separator position out of bounds".to_string(),
        })?;
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
