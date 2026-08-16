//! Unit and property tests for the control client.
//!
//! Split into a sibling file because mod.rs + tests exceeded the
//! `RUST/file-too-long` threshold.

#![expect(
    clippy::expect_used,
    reason = "tests use expect() for invariants that must hold"
)]

use mitos::keys::{DiscoPrivate, MachinePrivate, NodePrivate};
use mitos::types::Node;

use super::*;

// WHY: siblings so no one file crosses the file-length limit. `netmap_tests`
// covers `Netmap`/`apply_map_response` merge semantics; `peer_cap_tests`
// covers the `MAX_PEERS` bound specifically.
mod netmap_tests;
mod peer_cap_tests;

/// Build a `ControlClient` with a paired transport for unit testing.
///
/// The transport is not usable for actual communication -- these
/// tests exercise the request building and netmap application logic.
fn paired_client() -> ControlClient {
    let machine_key = MachinePrivate::generate();
    let node_key = NodePrivate::generate();
    let disco_key = DiscoPrivate::generate();

    // Build a paired transport to get a valid ControlConnection.
    let server_key = MachinePrivate::generate();
    let server_pub = server_key.public_key();

    let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("params should parse");
    let prologue = format!("Tailscale Control Protocol v{CAPABILITY_VERSION}").into_bytes();
    let prologue = prologue.as_slice();

    let mut initiator = snow::Builder::new(params)
        .local_private_key(machine_key.as_bytes())
        .expect("set key")
        .remote_public_key(server_pub.as_bytes())
        .expect("set remote key")
        .prologue(prologue)
        .expect("set prologue")
        .build_initiator()
        .expect("build initiator");

    let params2: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("params should parse");

    let mut responder = snow::Builder::new(params2)
        .local_private_key(server_key.as_bytes())
        .expect("set key")
        .prologue(prologue)
        .expect("set prologue")
        .build_responder()
        .expect("build responder");

    let mut buf = vec![0u8; 65535];
    let mut payload_buf = vec![0u8; 65535];

    let len = initiator.write_message(&[], &mut buf).expect("write msg1");
    responder
        .read_message(&buf[..len], &mut payload_buf)
        .expect("read msg1");

    let len = responder.write_message(&[], &mut buf).expect("write msg2");
    initiator
        .read_message(&buf[..len], &mut payload_buf)
        .expect("read msg2");

    let client_transport = crate::noise::NoiseTransport::from_snow(
        initiator
            .into_transport_mode()
            .expect("initiator transport"),
    );

    // Re-generate a fresh machine key for the client (the one above
    // was consumed by the handshake builder).
    let client_machine = MachinePrivate::generate();

    let conn = ControlConnection::from_transport(client_transport);

    ControlClient::new(conn, client_machine, node_key, disco_key)
}

/// Deterministic, valid `nodekey:` hex string for test peer `id`.
///
/// WHY: `Node.key` is validated at netmap ingestion (issue #55), so a test
/// fixture needs a real 64-hex-digit key, not a readable placeholder. `id`
/// is embedded directly so a peer's key and its `Node.id` stay trivially
/// correlated when reading an assertion failure.
fn hex_node_key(id: i64) -> String {
    format!("nodekey:{id:064x}")
}

/// Deterministic, valid `discokey:` hex string, keyed by an arbitrary tag
/// rather than a `Node.id` -- used where the test needs a disco key that
/// does not correspond to any constructed [`Node`] (e.g. a patch that
/// rotates one).
fn hex_disco_key(tag: i64) -> String {
    format!("discokey:{tag:064x}")
}

fn sample_node(id: i64, name: &str) -> Node {
    Node {
        id,
        stable_id: None,
        key: hex_node_key(id),
        machine: None,
        name: name.to_string(),
        cap: None,
        tags: None,
        addresses: vec!["100.64.0.1/32".to_string()],
        allowed_ips: None,
        endpoints: None,
        derp: None,
        disco_key: None,
        key_expiry: None,
        last_seen: None,
        online: None,
    }
}

#[test]
fn netmap_starts_empty() {
    let client = paired_client();
    assert!(client.self_node().is_none());
    assert!(client.peers().is_empty());
}

#[test]
fn register_builds_correct_json() {
    let client = paired_client();
    let payload = client
        .build_register_request(Some("tskey-auth-test123"))
        .expect("build should succeed");

    let json: serde_json::Value =
        serde_json::from_slice(&payload).expect("payload should be valid JSON");

    // Check required fields exist with correct PascalCase names.
    assert!(json.get("NodeKey").is_some(), "missing NodeKey");
    assert!(json.get("OldNodeKey").is_some(), "missing OldNodeKey");
    assert!(json.get("Hostinfo").is_some(), "missing Hostinfo");
    assert_eq!(
        json["Version"].as_u64(),
        Some(CAPABILITY_VERSION.as_u64()),
        "RegisterRequest.Version must derive from the shared CAPABILITY_VERSION"
    );

    // NodeKey should be a proper nodekey: prefixed string.
    let node_key = json["NodeKey"].as_str().expect("NodeKey should be string");
    assert!(
        node_key.starts_with("nodekey:"),
        "NodeKey should have nodekey: prefix: {node_key}"
    );

    // Auth key should be nested.
    let auth = json.get("Auth").expect("Auth should be present");
    let auth_key = auth["AuthKey"].as_str().expect("AuthKey should be string");
    assert_eq!(auth_key, "tskey-auth-test123");

    // Hostinfo should have GoVersion set to dictyon.
    let hostinfo = &json["Hostinfo"];
    assert_eq!(
        hostinfo["GoVersion"].as_str(),
        Some("dictyon/0.1.0"),
        "GoVersion should identify dictyon"
    );
}

#[test]
fn map_request_advertises_zstd_compression() {
    let client = paired_client();
    let payload = client
        .build_map_request()
        .expect("map request should serialize");

    let json: serde_json::Value =
        serde_json::from_slice(&payload).expect("payload should be valid JSON");

    assert_eq!(
        json["Version"].as_u64(),
        Some(CAPABILITY_VERSION.as_u64()),
        "MapRequest.Version must derive from the shared CAPABILITY_VERSION"
    );
    assert_eq!(json["Stream"].as_bool(), Some(true));
    assert_eq!(json["OmitPeers"].as_bool(), Some(false));
    assert_eq!(json["Compress"].as_str(), Some("zstd"));
}

/// WHY: the defect this issue fixes was three call sites each restating the
/// capability version as an independent literal (1, 68, 71) that had
/// silently drifted apart. A future regression that reintroduces a
/// hardcoded literal at *one* call site while the others still derive from
/// [`CAPABILITY_VERSION`] would pass every other test in this file --
/// each one only checks its own request against the shared constant, not
/// against its sibling. This test compares the two live JSON payloads to
/// each other, so a one-sided hardcode fails it even if that hardcoded
/// value happens to equal the current [`CAPABILITY_VERSION`] by coincidence
/// today.
#[test]
fn register_and_map_requests_advertise_the_same_capability_version() {
    let client = paired_client();

    let register_payload = client
        .build_register_request(None)
        .expect("register request should build");
    let register_json: serde_json::Value =
        serde_json::from_slice(&register_payload).expect("register payload should be JSON");

    let map_payload = client
        .build_map_request()
        .expect("map request should build");
    let map_json: serde_json::Value =
        serde_json::from_slice(&map_payload).expect("map payload should be JSON");

    let register_version = register_json["Version"]
        .as_u64()
        .expect("RegisterRequest.Version should be a JSON number");
    let map_version = map_json["Version"]
        .as_u64()
        .expect("MapRequest.Version should be a JSON number");

    assert_eq!(
        register_version, map_version,
        "RegisterRequest and MapRequest must advertise identical capability versions"
    );
    assert_eq!(
        register_version,
        CAPABILITY_VERSION.as_u64(),
        "the shared version must equal CAPABILITY_VERSION, not merely agree with itself"
    );
}

#[test]
fn parse_map_response_extracts_json() {
    let json_body = br#"{"KeepAlive":true}"#;
    let size = u32::try_from(json_body.len()).expect("test payload fits u32");

    let mut frame = Vec::new();
    frame.extend_from_slice(&size.to_le_bytes());
    frame.extend_from_slice(json_body);

    let resp = ControlClient::parse_map_response(&frame).expect("parse should succeed");

    assert_eq!(resp.keep_alive, Some(true));
}

#[test]
fn parse_map_response_extracts_zstd_json() {
    let json_body = br#"{"KeepAlive":true}"#;
    let compressed =
        zstd::stream::encode_all(&json_body[..], 0).expect("test payload should compress");
    let size = u32::try_from(compressed.len()).expect("test payload fits u32");

    let mut frame = Vec::new();
    frame.extend_from_slice(&size.to_le_bytes());
    frame.extend_from_slice(&compressed);

    let resp = ControlClient::parse_map_response(&frame).expect("parse should succeed");

    assert_eq!(resp.keep_alive, Some(true));
}

#[test]
fn parse_map_response_rejects_truncated_frame() {
    // Frame header says 100 bytes but only 10 available.
    let mut frame = Vec::new();
    frame.extend_from_slice(&100u32.to_le_bytes());
    frame.extend_from_slice(&[0u8; 10]);

    let result = ControlClient::parse_map_response(&frame);
    assert!(result.is_err());
}

#[test]
fn frame_len_accepts_the_largest_representable_payload() {
    let max = usize::try_from(u32::MAX).expect("u32::MAX fits usize on supported targets");
    assert_eq!(frame_len(max).expect("u32::MAX is representable"), u32::MAX);
}

// WHY: on a 32-bit target `usize` cannot exceed `u32::MAX`, so the rejection is
// unreachable and the test would assert nothing.
#[cfg(target_pointer_width = "64")]
#[test]
fn frame_len_rejects_a_payload_that_cannot_be_framed() {
    // WHY(#55): this previously clamped to u32::MAX, writing a length prefix
    // that disagreed with the bytes after it and desynchronising the peer.
    let over = usize::try_from(u32::MAX).expect("u32::MAX fits usize on 64-bit") + 1;
    let err = frame_len(over).expect_err("a payload above u32::MAX must not be framed");
    assert!(
        matches!(err, ControlError::PayloadTooLarge { len } if len == over),
        "expected PayloadTooLarge naming the offending length, got {err:?}"
    );
}
