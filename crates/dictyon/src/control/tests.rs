//! Unit and property tests for the control client.
//!
//! Split into a sibling file because mod.rs + tests exceeded the
//! `RUST/file-too-long` threshold.

#![expect(
    clippy::expect_used,
    reason = "tests use expect() for invariants that must hold"
)]

use hamma_core::keys::{DiscoPrivate, MachinePrivate, NodePrivate};
use hamma_core::types::{DnsConfig, DnsResolver, MapResponse, Node};

use super::*;

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
    let prologue = b"Tailscale Control Protocol v1";

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

fn sample_node(id: i64, key: &str, name: &str) -> Node {
    Node {
        id,
        key: key.to_string(),
        name: name.to_string(),
        addresses: vec!["100.64.0.1/32".to_string()],
        allowed_ips: None,
        endpoints: None,
        derp: None,
        disco_key: None,
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
fn apply_map_response_sets_initial_peers() {
    let mut client = paired_client();

    let resp = MapResponse {
        node: Some(sample_node(1, "nodekey:self", "self.ts.net.")),
        peers: Some(vec![
            sample_node(2, "nodekey:peer1", "peer1.ts.net."),
            sample_node(3, "nodekey:peer2", "peer2.ts.net."),
        ]),
        peers_changed: None,
        peers_removed: None,
        dns_config: Some(DnsConfig {
            resolvers: Some(vec![DnsResolver {
                addr: "100.100.100.100".to_string(),
            }]),
            domains: Some(vec!["example.ts.net".to_string()]),
        }),
        derp_map: None,
        keep_alive: None,
    };

    client.apply_map_response(resp);

    let self_node = client.self_node().expect("self_node should be set");
    assert_eq!(self_node.key, "nodekey:self");
    assert_eq!(client.peers().len(), 2);
    assert_eq!(client.peers()[0].key, "nodekey:peer1");
    assert_eq!(client.peers()[1].key, "nodekey:peer2");

    let netmap = client.netmap.as_ref().expect("netmap should exist");
    let dns = netmap.dns_config.as_ref().expect("dns_config should exist");
    let resolvers = dns.resolvers.as_ref().expect("resolvers should exist");
    assert_eq!(resolvers[0].addr, "100.100.100.100");
}

#[test]
fn apply_map_response_delta_adds_peers() {
    let mut client = paired_client();

    // Initial full response.
    let initial = MapResponse {
        node: Some(sample_node(1, "nodekey:self", "self.ts.net.")),
        peers: Some(vec![sample_node(2, "nodekey:peer1", "peer1.ts.net.")]),
        peers_changed: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client.apply_map_response(initial);
    assert_eq!(client.peers().len(), 1);

    // Delta: add a new peer and update existing one.
    let mut updated_peer1 = sample_node(2, "nodekey:peer1", "peer1-updated.ts.net.");
    updated_peer1.online = Some(true);

    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: Some(vec![
            updated_peer1,
            sample_node(4, "nodekey:peer3", "peer3.ts.net."),
        ]),
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client.apply_map_response(delta);

    assert_eq!(client.peers().len(), 2);
    // Existing peer should be updated.
    assert_eq!(client.peers()[0].name, "peer1-updated.ts.net.");
    assert_eq!(client.peers()[0].online, Some(true));
    // New peer should be appended.
    assert_eq!(client.peers()[1].key, "nodekey:peer3");
}

#[test]
fn apply_map_response_removes_peers() {
    let mut client = paired_client();

    // Initial full response with three peers.
    let initial = MapResponse {
        node: Some(sample_node(1, "nodekey:self", "self.ts.net.")),
        peers: Some(vec![
            sample_node(2, "nodekey:peer1", "peer1.ts.net."),
            sample_node(3, "nodekey:peer2", "peer2.ts.net."),
            sample_node(4, "nodekey:peer3", "peer3.ts.net."),
        ]),
        peers_changed: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client.apply_map_response(initial);
    assert_eq!(client.peers().len(), 3);

    // Delta: remove peer2.
    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: None,
        peers_removed: Some(vec!["nodekey:peer2".to_string()]),
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client.apply_map_response(delta);

    assert_eq!(client.peers().len(), 2);
    assert_eq!(client.peers()[0].key, "nodekey:peer1");
    assert_eq!(client.peers()[1].key, "nodekey:peer3");
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
fn parse_map_response_rejects_truncated_frame() {
    // Frame header says 100 bytes but only 10 available.
    let mut frame = Vec::new();
    frame.extend_from_slice(&100u32.to_le_bytes());
    frame.extend_from_slice(&[0u8; 10]);

    let result = ControlClient::parse_map_response(&frame);
    assert!(result.is_err());
}

#[test]
fn keepalive_does_not_modify_netmap() {
    let mut client = paired_client();

    // Initialize with a peer.
    let initial = MapResponse {
        node: Some(sample_node(1, "nodekey:self", "self.ts.net.")),
        peers: Some(vec![sample_node(2, "nodekey:peer1", "peer1.ts.net.")]),
        peers_changed: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client.apply_map_response(initial);
    assert_eq!(client.peers().len(), 1);

    // Keepalive should not change anything.
    let keepalive = MapResponse {
        node: None,
        peers: None,
        peers_changed: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: Some(true),
    };
    client.apply_map_response(keepalive);

    assert_eq!(client.peers().len(), 1);
    assert_eq!(client.peers()[0].key, "nodekey:peer1");
}

// -----------------------------------------------------------------------
// Property tests
// -----------------------------------------------------------------------

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    /// After any sequence of delta updates the peer list has no duplicate
    /// keys and every explicitly removed key is absent.
    #[test]
    fn netmap_delta_sequence_is_consistent(
        // Number of initial peers: 1..=8
        n_initial in 1usize..=8,
        // Number of additional peers to add via peers_changed: 0..=4
        n_add in 0usize..=4,
        // Number of peers to remove (capped at n_initial): 0..=4
        n_remove in 0usize..=4,
    ) {
        let mut client = paired_client();

        // Build the initial full map response.
        let initial_peers: Vec<Node> = (0..n_initial)
            .map(|i| {
                let id = i64::try_from(i).expect("test index fits i64") + 2;
                sample_node(id, &format!("nodekey:peer{i}"), &format!("peer{i}.ts.net."))
            })
            .collect();

        let initial = MapResponse {
            node: Some(sample_node(1, "nodekey:self", "self.ts.net.")),
            peers: Some(initial_peers),
            peers_changed: None,
            peers_removed: None,
            dns_config: None,
            derp_map: None,
            keep_alive: None,
        };
        client.apply_map_response(initial);
        assert_eq!(client.peers().len(), n_initial);

        // Add new peers via peers_changed.
        if n_add > 0 {
            let new_peers: Vec<Node> = (0..n_add)
                .map(|i| {
                    let idx = n_initial + i;
                    let id = i64::try_from(idx).expect("test index fits i64") + 2;
                    sample_node(
                        id,
                        &format!("nodekey:newpeer{idx}"),
                        &format!("newpeer{idx}.ts.net."),
                    )
                })
                .collect();
            let delta = MapResponse {
                node: None,
                peers: None,
                peers_changed: Some(new_peers),
                peers_removed: None,
                dns_config: None,
                derp_map: None,
                keep_alive: None,
            };
            client.apply_map_response(delta);
            assert_eq!(client.peers().len(), n_initial + n_add);
        }

        // Remove up to n_remove of the original peers.
        let n_to_remove = n_remove.min(n_initial);
        let removed_keys: Vec<String> = (0..n_to_remove)
            .map(|i| format!("nodekey:peer{i}"))
            .collect();

        if n_to_remove > 0 {
            let delta = MapResponse {
                node: None,
                peers: None,
                peers_changed: None,
                peers_removed: Some(removed_keys.clone()),
                dns_config: None,
                derp_map: None,
                keep_alive: None,
            };
            client.apply_map_response(delta);
        }

        let final_peers = client.peers();
        let expected_count = n_initial + n_add - n_to_remove;
        assert_eq!(
            final_peers.len(),
            expected_count,
            "peer count after add={n_add} remove={n_to_remove} should be {expected_count}"
        );

        // Invariant: no duplicate keys.
        let mut seen_keys = std::collections::HashSet::new();
        for peer in final_peers {
            let is_new = seen_keys.insert(peer.key.clone());
            assert!(is_new, "duplicate peer key found: {}", peer.key);
        }

        // Invariant: all removed keys are absent.
        for removed_key in &removed_keys {
            assert!(
                !seen_keys.contains(removed_key),
                "removed key should not be present: {removed_key}"
            );
        }
    }
}
