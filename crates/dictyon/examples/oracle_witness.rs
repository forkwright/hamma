//! Independent-oracle witness for the TS2021 capability-version handshake
//! (hamma#122).
//!
//! Drives a real Noise IK initiation + HTTP upgrade against a caller-supplied
//! control-plane endpoint (headscale in CI; tailscale.com via the operator-run
//! canary) and records byte-level artifacts plus a typed receipt under
//! `evidence/phase-a/`. The HTTP upgrade is driven by hand here rather than
//! through `wire::connect`, so the wire's own request construction is also
//! under test instead of self-paired.
//!
//! Usage: `oracle_witness --url <https://127.0.0.1:8089> --ca-cert <ca.pem>
//! --out <evidence/phase-a/oracle> [--mismatch]`
//!
//! `--mismatch` runs the negative case: an initiation built with a wrong
//! capability prologue must NOT complete the handshake.

use std::sync::Arc;

use base64::Engine;
use dictyon::noise::NoiseHandshake;
use dictyon::wire::fetch_server_key_with_tls;
use mitos::keys::MachinePrivate;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Debug)]
struct Args {
    url: String,
    ca_cert: String,
    out: String,
    mismatch: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut url = None;
    let mut ca_cert = None;
    let mut out = None;
    let mut mismatch = false;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--url" => url = Some(it.next().ok_or("--url needs a value")?),
            "--ca-cert" => ca_cert = Some(it.next().ok_or("--ca-cert needs a value")?),
            "--out" => out = Some(it.next().ok_or("--out needs a value")?),
            "--mismatch" => mismatch = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args {
        url: url.ok_or("missing --url")?,
        ca_cert: ca_cert.ok_or("missing --ca-cert")?,
        out: out.ok_or("missing --out")?,
        mismatch,
    })
}

fn tls_config_trusting(ca_pem: &str) -> Result<rustls::ClientConfig, String> {
    let pem = std::fs::read(ca_pem).map_err(|e| format!("read {ca_pem}: {e}"))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<_, _>>()
        .map_err(|e| format!("parse {ca_pem}: {e}"))?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| format!("add root from {ca_pem}: {e}"))?;
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn host_port(url: &str) -> Result<(String, u16), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("only https URLs: {url}"))?;
    match rest.split_once(':') {
        Some((h, p)) => Ok((
            h.to_string(),
            p.parse().map_err(|e| format!("bad port in {url}: {e}"))?,
        )),
        None => Ok((rest.to_string(), 443)),
    }
}

/// Read the upgrade response headers, then capture whatever post-upgrade
/// bytes the server sends within a short window — verbatim. Interpretation
/// happens after capture, never before: the response's framing is one of the
/// things under test.
async fn capture_response(
    tls_stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<(String, bool, Vec<u8>), String> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    let header_end;
    loop {
        let n = tls_stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("read response: {e}"))?;
        if n == 0 {
            return Err("connection closed before headers complete".into());
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(pos) = find_subslice(&raw, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if raw.len() > 64 * 1024 {
            return Err("response headers exceed 64 KiB".into());
        }
    }
    let headers = String::from_utf8_lossy(&raw[..header_end]).to_string();
    let status_line = headers.lines().next().unwrap_or("").to_string();
    eprintln!("status: {status_line}");

    let upgraded = status_line.contains("101");
    let mut noise_response = raw[header_end..].to_vec();
    if upgraded {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() || noise_response.len() >= 64 {
                break;
            }
            match tokio::time::timeout(remaining, tls_stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => noise_response.extend_from_slice(&buf[..n]),
                Ok(Err(e)) => return Err(format!("read noise response: {e}")),
                // EOF or deadline: stop capturing.
                Ok(Ok(_)) | Err(_) => break,
            }
        }
    }
    eprintln!(
        "[witness] raw post-upgrade bytes ({}): {}",
        noise_response.len(),
        hex(&noise_response)
    );
    Ok((status_line, upgraded, noise_response))
}

/// Open the TLS connection and send the HTTP upgrade carrying the Noise
/// initiation; returns the stream positioned at the response.
async fn open_upgrade(
    host: &str,
    port: u16,
    tls: rustls::ClientConfig,
    init_msg: &[u8],
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let tcp = TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("tcp connect: {e}"))?;
    let server_name =
        ServerName::try_from(host.to_owned()).map_err(|_| format!("bad host: {host}"))?;
    let mut tls_stream = TlsConnector::from(Arc::new(tls))
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("tls: {e}"))?;
    let init_b64 = base64::engine::general_purpose::STANDARD.encode(init_msg);
    let request = format!(
        "POST /ts2021 HTTP/1.1\r\nHost: {host}\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\nX-Tailscale-Handshake: {init_b64}\r\nContent-Length: 0\r\n\r\n"
    );
    tls_stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write upgrade: {e}"))?;
    Ok(tls_stream)
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args = parse_args()?;
    let tls = tls_config_trusting(&args.ca_cert)?;
    let (host, port) = host_port(&args.url)?;

    // 1. Server key through dictyon's real fetch path.
    let server_key = fetch_server_key_with_tls(&args.url, tls.clone())
        .await
        .map_err(|e| format!("fetch server key: {e}"))?;
    eprintln!("server key fetched");

    // 2. Build the initiation through dictyon's Noise state machine (the unit
    //    under test), capturing the exact bytes.
    let machine_key = MachinePrivate::generate();
    let mut handshake = NoiseHandshake::new(machine_key, server_key.clone());
    let init_msg = if args.mismatch {
        // Independent construction with a deliberately wrong prologue: the
        // oracle must refuse it.
        tampered_initiation(&server_key)?
    } else {
        handshake
            .initiation_message()
            .map_err(|e| format!("initiation: {e}"))?
    };

    // 3. Hand-driven TLS + HTTP upgrade (not wire::connect, so the witness is
    //    not self-paired at the request-construction layer).
    let mut tls_stream = open_upgrade(&host, port, tls, &init_msg).await?;

    // 4. Read the response and capture whatever post-upgrade bytes arrive.
    let (status_line, upgraded, noise_response) = capture_response(&mut tls_stream).await?;
    eprintln!(
        "[witness] raw post-upgrade bytes ({}): {}",
        noise_response.len(),
        hex(&noise_response)
    );

    // 5. Complete the handshake if the server answered 101. The captured
    //    bytes already carry the server's framing ([type][BE16 len][payload]),
    //    which `process_response` consumes directly — verified against
    //    headscale 2026-09-09.
    let handshake_ok = if upgraded && !noise_response.is_empty() {
        match handshake.process_response(&noise_response) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("process_response failed: {e}");
                false
            }
        }
    } else {
        false
    };

    write_artifacts(
        &args,
        &init_msg,
        &status_line,
        upgraded,
        &noise_response,
        handshake_ok,
    )?;

    if args.mismatch {
        if handshake_ok {
            return Err(
                "MISMATCH CASE COMPLETED THE HANDSHAKE — oracle accepted a wrong prologue".into(),
            );
        }
        println!("mismatch case correctly rejected");
        return Ok(());
    }
    if !handshake_ok {
        return Err(format!(
            "handshake did not complete (status: {status_line})"
        ));
    }
    println!("handshake completed against independent oracle");
    Ok(())
}

/// Build an initiation frame whose prologue carries a wrong capability
/// version, using snow directly (independent of dictyon's [`NoiseHandshake`]).
fn tampered_initiation(server_key: &mitos::keys::MachinePublic) -> Result<Vec<u8>, String> {
    use snow::params::NoiseParams;
    let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .map_err(|e| format!("params: {e}"))?;
    let keypair = snow::Builder::new(params.clone())
        .generate_keypair()
        .map_err(|e| format!("keygen: {e}"))?;
    let wrong_prologue = b"Tailscale Control Protocol v0-mismatch".to_vec();
    let mut hs = snow::Builder::new(params)
        .prologue(&wrong_prologue)
        .map_err(|e| format!("prologue: {e}"))?
        .local_private_key(&keypair.private)
        .map_err(|e| format!("key: {e}"))?
        .remote_public_key(server_key.as_bytes())
        .map_err(|e| format!("remote key: {e}"))?
        .build_initiator()
        .map_err(|e| format!("initiator: {e}"))?;
    let mut msg = vec![0u8; 65535];
    let len = hs
        .write_message(&[], &mut msg)
        .map_err(|e| format!("write: {e}"))?;
    msg.truncate(len);
    Ok(msg)
}

/// Lowercase hex dump without per-byte `format!` allocations.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn write_artifacts(
    args: &Args,
    init_msg: &[u8],
    status_line: &str,
    upgraded: bool,
    noise_response: &[u8],
    handshake_ok: bool,
) -> Result<(), String> {
    std::fs::create_dir_all(&args.out).map_err(|e| format!("mkdir {}: {e}", args.out))?;
    let case = if args.mismatch { "mismatch" } else { "success" };
    let transcript = serde_json::json!({
        "case": case,
        "capability_version": mitos::capability::CAPABILITY_VERSION.as_u64(),
        "prologue": format!("Tailscale Control Protocol v{}", mitos::capability::CAPABILITY_VERSION.as_u64()),
        "initiation_hex": hex(init_msg),
        "upgrade_status_line": status_line,
        "upgrade_accepted": upgraded,
        "noise_response_hex": hex(noise_response),
        "handshake_completed": handshake_ok,
    });
    let path = format!("{}/{case}-transcript.json", args.out);
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&transcript).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("write {path}: {e}"))?;
    eprintln!("wrote {path}");
    Ok(())
}
