//! Unit tests for the control-protocol wire types.
//!
//! Split into a sibling file because types.rs + tests together exceeded the
//! `RUST/file-too-long` threshold.

#![expect(
    clippy::expect_used,
    reason = "tests use expect() for invariants that must hold"
)]

use super::*;

/// WHY(#54): the failure this guards is not a wrong value but a refusal to
/// decode at all, and it takes the entire `MapResponse` down with it — so
/// the assertion that matters is that a peer *without* the key parses,
/// alongside its sibling proving a peer *with* the key still round-trips.
#[test]
fn node_without_addresses_deserializes_to_an_empty_vec() {
    let json = r#"{"ID":1,"Key":"nodekey:abc","Name":"peer.example.ts.net."}"#;

    let node: Node = serde_json::from_str(json).expect("a node with no Addresses must decode");

    assert!(
        node.addresses.is_empty(),
        "absent Addresses must decode as empty, got {:?}",
        node.addresses
    );
    assert_eq!(node.id, 1);
}

#[test]
fn node_with_addresses_still_decodes_them() {
    let json = r#"{"ID":1,"Key":"nodekey:abc","Name":"peer.example.ts.net.","Addresses":["100.64.0.1/32"]}"#;

    let node: Node = serde_json::from_str(json).expect("a node with Addresses must decode");

    assert_eq!(node.addresses, vec!["100.64.0.1/32".to_string()]);
}

#[test]
fn register_request_serializes_to_json() {
    let req = RegisterRequest {
        node_key: "nodekey:abc123".to_string(),
        old_node_key: String::new(),
        auth: Some(AuthInfo {
            auth_key: Some("tskey-auth-test".to_string()),
        }),
        hostinfo: Hostinfo {
            backend_log_id: BackendLogId::new("log123"),
            os: "linux".to_string(),
            hostname: "testhost".to_string(),
            go_version: "dictyon/0.1.0".to_string(),
        },
        followup: None,
    };

    let json = serde_json::to_string(&req).expect("serialization should succeed");

    // Verify PascalCase field names from the Tailscale protocol
    assert!(json.contains("\"NodeKey\""), "missing NodeKey: {json}");
    assert!(
        json.contains("\"OldNodeKey\""),
        "missing OldNodeKey: {json}"
    );
    assert!(
        json.contains("\"BackendLogID\""),
        "missing BackendLogID: {json}"
    );
    assert!(json.contains("\"OS\""), "missing OS: {json}");
    assert!(json.contains("\"Hostname\""), "missing Hostname: {json}");
    assert!(json.contains("\"GoVersion\""), "missing GoVersion: {json}");

    // Verify values round-trip
    assert!(
        json.contains("\"nodekey:abc123\""),
        "NodeKey value wrong: {json}"
    );
    assert!(
        json.contains("\"dictyon/0.1.0\""),
        "GoVersion value wrong: {json}"
    );

    // Followup should be omitted when None
    assert!(
        !json.contains("\"Followup\""),
        "Followup should be omitted when None: {json}"
    );
}

#[test]
fn map_response_deserializes_full() {
    let json = r#"{
        "Node": {
            "ID": 12345,
            "StableID": "node-12345",
            "Key": "nodekey:self000",
            "Machine": "mkey:machine000",
            "Name": "myhost.tail1234.ts.net.",
            "Cap": 68,
            "Tags": ["tag:lab"],
            "Addresses": ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"],
            "DERP": "127.3.3.40:1",
            "DiscoKey": "discokey:abc123",
            "KeyExpiry": "2026-11-01T00:00:00Z",
            "LastSeen": "2026-05-25T09:00:00Z",
            "Online": true
        },
        "Peers": [
            {
                "ID": 67890,
                "Key": "nodekey:peer001",
                "Name": "peerhost.tail1234.ts.net.",
                "Addresses": ["100.64.0.2/32"],
                "AllowedIPs": ["100.64.0.2/32"],
                "Endpoints": ["1.2.3.4:41641"],
                "DERP": "127.3.3.40:2",
                "DiscoKey": "discokey:def456",
                "Online": true
            }
        ],
        "DNSConfig": {
            "Resolvers": [{"Addr": "100.100.100.100"}],
            "Domains": ["tail1234.ts.net"]
        },
        "DERPMap": {
            "Regions": {"1": {"RegionID": 1, "RegionCode": "nyc"}}
        }
    }"#;

    let resp: MapResponse = serde_json::from_str(json).expect("deserialization should succeed");

    let node = resp.node.as_ref().expect("node should be present");
    assert_eq!(node.id, 12345);
    assert_eq!(node.stable_id.as_deref(), Some("node-12345"));
    assert_eq!(node.key, "nodekey:self000");
    assert_eq!(node.machine.as_deref(), Some("mkey:machine000"));
    assert_eq!(node.name, "myhost.tail1234.ts.net.");
    assert_eq!(node.cap, Some(68));
    assert_eq!(
        node.tags.as_ref().expect("tags present"),
        &["tag:lab".to_string()]
    );
    assert_eq!(node.addresses.len(), 2);
    assert_eq!(node.derp.as_deref(), Some("127.3.3.40:1"));
    assert_eq!(node.key_expiry.as_deref(), Some("2026-11-01T00:00:00Z"));
    assert_eq!(node.last_seen.as_deref(), Some("2026-05-25T09:00:00Z"));
    assert_eq!(node.online, Some(true));

    let peers = resp.peers.as_ref().expect("peers should be present");
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].id, 67890);
    assert_eq!(peers[0].key, "nodekey:peer001");
    assert_eq!(
        peers[0].endpoints.as_ref().expect("endpoints present"),
        &["1.2.3.4:41641"]
    );

    let dns = resp
        .dns_config
        .as_ref()
        .expect("dns_config should be present");
    let resolvers = dns.resolvers.as_ref().expect("resolvers present");
    assert_eq!(resolvers[0].addr, "100.100.100.100");
    let domains = dns.domains.as_ref().expect("domains present");
    assert_eq!(domains[0], "tail1234.ts.net");

    assert!(resp.derp_map.is_some());
    assert!(resp.keep_alive.is_none());
}

#[test]
fn map_response_deserializes_keepalive() {
    let json = r#"{"KeepAlive": true}"#;
    let resp: MapResponse = serde_json::from_str(json).expect("keepalive should parse");

    assert_eq!(resp.keep_alive, Some(true));
    assert!(resp.node.is_none());
    assert!(resp.peers.is_none());
    assert!(resp.peers_changed.is_none());
    assert!(resp.peers_changed_patch.is_none());
    assert!(resp.peers_removed.is_none());
    assert!(resp.dns_config.is_none());
    assert!(resp.derp_map.is_none());
}

#[test]
fn node_deserializes_with_optional_fields() {
    let json = r#"{
        "ID": 1,
        "Key": "nodekey:minimal",
        "Name": "bare.example.ts.net.",
        "Addresses": ["100.64.0.99/32"]
    }"#;

    let node: Node = serde_json::from_str(json).expect("minimal node should parse");

    assert_eq!(node.id, 1);
    assert_eq!(node.key, "nodekey:minimal");
    assert_eq!(node.name, "bare.example.ts.net.");
    assert_eq!(node.addresses, vec!["100.64.0.99/32"]);
    assert!(node.stable_id.is_none());
    assert!(node.machine.is_none());
    assert!(node.cap.is_none());
    assert!(node.tags.is_none());
    assert!(node.allowed_ips.is_none());
    assert!(node.endpoints.is_none());
    assert!(node.derp.is_none());
    assert!(node.disco_key.is_none());
    assert!(node.key_expiry.is_none());
    assert!(node.last_seen.is_none());
    assert!(node.online.is_none());
}

#[test]
fn map_response_deserializes_peer_changed_patch() {
    let json = r#"{
        "PeersChangedPatch": [
            {
                "NodeID": 67890,
                "DERPRegion": 2,
                "Endpoints": ["1.2.3.4:41641"],
                "Key": "nodekey:peer001",
                "DiscoKey": "discokey:def456",
                "Online": true,
                "LastSeen": "2026-05-25T09:00:00Z",
                "KeyExpiry": "2026-11-01T00:00:00Z",
                "Cap": 68,
                "CapMap": {"https://tailscale.com/cap/is-admin": null}
            }
        ]
    }"#;

    let resp: MapResponse = serde_json::from_str(json).expect("patch frame should parse");
    let patch = resp
        .peers_changed_patch
        .as_ref()
        .expect("patch should be present");

    assert_eq!(patch.len(), 1);
    assert_eq!(patch[0].node_id, 67890);
    assert_eq!(patch[0].derp_region, Some(2));
    assert_eq!(
        patch[0].endpoints.as_ref().expect("endpoints present")[0],
        "1.2.3.4:41641"
    );
    assert_eq!(patch[0].key.as_deref(), Some("nodekey:peer001"));
    assert_eq!(patch[0].disco_key.as_deref(), Some("discokey:def456"));
    assert_eq!(patch[0].online, Some(true));
    assert_eq!(patch[0].last_seen.as_deref(), Some("2026-05-25T09:00:00Z"));
    assert_eq!(patch[0].key_expiry.as_deref(), Some("2026-11-01T00:00:00Z"));
    assert_eq!(patch[0].cap, Some(68));
    assert!(patch[0].cap_map.is_some());
}

#[test]
fn map_response_deserializes_peer_removals_by_node_id_and_key() {
    let json = r#"{
        "PeersRemoved": [
            67890,
            {"NodeID": 67891},
            "nodekey:legacy"
        ]
    }"#;

    let resp: MapResponse = serde_json::from_str(json).expect("removal frame should parse");
    let removals = resp.peers_removed.expect("removals should be present");

    assert_eq!(removals.len(), 3);
    assert_eq!(removals[0], PeerRemoval::NodeId(67890));
    assert_eq!(removals[1], PeerRemoval::NodeId(67891));
    assert_eq!(
        removals[2],
        PeerRemoval::NodeKey("nodekey:legacy".to_string())
    );
}
/// WHY: a derived `Debug` on `AuthInfo` printed the pre-auth key verbatim,
/// so any `{:?}` of a `RegisterRequest` leaked a credential into logs. This
/// fails if the manual impl is dropped or a derive is reinstated.
#[test]
fn auth_info_debug_redacts_the_pre_auth_key() {
    let info = AuthInfo {
        auth_key: Some("tskey-auth-kSeCrEtValue".to_string()),
    };

    let rendered = format!("{info:?}");

    assert!(
        !rendered.contains("tskey-auth-kSeCrEtValue"),
        "Debug leaked the pre-auth key: {rendered}"
    );
    assert!(
        rendered.contains("REDACTED"),
        "Debug should mark the field redacted: {rendered}"
    );
}

/// The leak path that matters is transitive — nothing formats a bare
/// `AuthInfo`, but `RegisterRequest` derives `Debug` and owns one.
#[test]
fn register_request_debug_does_not_leak_the_nested_pre_auth_key() {
    let request = RegisterRequest {
        node_key: "nodekey:abc".to_string(),
        old_node_key: String::new(),
        auth: Some(AuthInfo {
            auth_key: Some("tskey-auth-kSeCrEtValue".to_string()),
        }),
        hostinfo: Hostinfo {
            backend_log_id: BackendLogId::new("log-id"),
            os: "linux".to_string(),
            hostname: "test-host".to_string(),
            go_version: String::new(),
        },
        followup: None,
    };

    let rendered = format!("{request:?}");

    assert!(
        !rendered.contains("tskey-auth-kSeCrEtValue"),
        "RegisterRequest Debug leaked the nested pre-auth key: {rendered}"
    );
}

/// An absent key must stay distinguishable from a redacted one, or the
/// redaction destroys the only thing the field was useful for in a log.
#[test]
fn auth_info_debug_distinguishes_absent_from_redacted() {
    let absent = format!("{:?}", AuthInfo { auth_key: None });

    assert!(
        absent.contains("None"),
        "an absent key should read as None: {absent}"
    );
    assert!(
        !absent.contains("REDACTED"),
        "an absent key must not claim to be redacted: {absent}"
    );
}
