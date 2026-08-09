//! Unit tests for the wire layer (TCP/TLS/HTTP upgrade + Noise framing I/O).
//!
//! Split into a sibling file because wire.rs + helpers + tests together
//! exceeded the `RUST/file-too-long` threshold.

#![expect(
    clippy::expect_used,
    reason = "tests use expect() for invariants that must hold"
)]

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, ReadBuf};
use tokio::net::TcpListener;

use super::support::*;
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
    let (framed, leftover) = read_noise_response_frame(&mut ChunkReader::empty(), frame.clone())
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
    // expression from outside mitos.
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
    let (host, port) = parse_host_port("https://controlplane.tailscale.com").expect("should parse");
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
    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{json_body}");

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
