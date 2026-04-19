//! Integration smoke tests for the `hamma-core` public API.
//!
//! Unit tests live alongside the implementation in `src/keys.rs` and
//! `src/types.rs`. These integration tests exercise the crate from an
//! external-consumer perspective (mirroring how `dictyon` imports it) so
//! regressions in the public surface are caught even when an internal
//! refactor leaves `cargo test --lib` green.

#![expect(
    clippy::expect_used,
    reason = "tests use expect() for invariants that must hold"
)]

use hamma_core::keys::{
    DiscoPrivate, DiscoPublic, KeyError, MachinePrivate, MachinePublic, NodePrivate, NodePublic,
};
use hamma_core::types::{
    AuthInfo, DerpMap, DnsConfig, DnsResolver, Hostinfo, MapRequest, MapResponse, Node,
    RegisterRequest, RegisterResponse,
};

#[test]
fn key_hierarchy_types_are_constructible() {
    let machine = MachinePrivate::generate();
    let node = NodePrivate::generate();
    let disco = DiscoPrivate::generate();

    let mpub: MachinePublic = machine.public_key();
    let npub: NodePublic = node.public_key();
    let dpub: DiscoPublic = disco.public_key();

    assert!(mpub.to_hex().starts_with("mkey:"));
    assert!(npub.to_hex().starts_with("nodekey:"));
    assert!(dpub.to_hex().starts_with("discokey:"));
}

#[test]
fn machine_public_round_trips_through_hex() {
    let key = MachinePrivate::generate();
    let pub_key = key.public_key();
    let hex = pub_key.to_hex();
    let recovered = MachinePublic::from_hex(&hex).expect("valid mkey round-trip");
    assert_eq!(pub_key, recovered);
}

#[test]
fn machine_public_from_hex_rejects_missing_prefix() {
    let err = MachinePublic::from_hex("nodekey:deadbeef").expect_err("wrong prefix rejected");
    assert!(matches!(err, KeyError::MissingPrefix { .. }));
}

#[test]
fn machine_public_from_hex_rejects_wrong_length() {
    let err = MachinePublic::from_hex("mkey:abcd").expect_err("short hex rejected");
    assert!(matches!(err, KeyError::WrongLength { .. }));
}

#[test]
fn map_request_round_trips_through_json() {
    let req = MapRequest {
        version: 68,
        node_key: "nodekey:abc".to_string(),
        disco_key: "discokey:def".to_string(),
        endpoints: vec!["1.2.3.4:41641".to_string()],
        stream: true,
        omit_peers: false,
        hostinfo: Hostinfo {
            backend_log_id: String::new(),
            os: "linux".to_string(),
            hostname: "host".to_string(),
            go_version: "dictyon/0.1.0".to_string(),
        },
    };
    let json = serde_json::to_string(&req).expect("MapRequest serializes");
    assert!(json.contains("\"NodeKey\":\"nodekey:abc\""));
    assert!(json.contains("\"Version\":68"));
}

#[test]
fn register_request_omits_none_fields() {
    let req = RegisterRequest {
        node_key: "nodekey:abc".to_string(),
        old_node_key: String::new(),
        auth: Some(AuthInfo {
            auth_key: Some("tskey-auth-test".to_string()),
        }),
        hostinfo: Hostinfo {
            backend_log_id: "log".to_string(),
            os: "linux".to_string(),
            hostname: "h".to_string(),
            go_version: "dictyon/0.1.0".to_string(),
        },
        followup: None,
    };
    let json = serde_json::to_string(&req).expect("RegisterRequest serializes");
    assert!(
        !json.contains("\"Followup\""),
        "None Followup should be omitted: {json}"
    );
    assert!(
        json.contains("\"Auth\""),
        "Some Auth should be present: {json}"
    );
}

#[test]
fn map_response_deserializes_keepalive_only_frame() {
    let frame = r#"{"KeepAlive":true}"#;
    let resp: MapResponse = serde_json::from_str(frame).expect("keepalive frame parses");
    assert_eq!(resp.keep_alive, Some(true));
    assert!(resp.node.is_none());
    assert!(resp.peers.is_none());
}

#[test]
fn node_deserializes_minimal_fields() {
    let json = r#"{
        "ID": 7,
        "Key": "nodekey:self",
        "Name": "self.tail.net.",
        "Addresses": ["100.64.0.1/32"]
    }"#;
    let node: Node = serde_json::from_str(json).expect("minimal Node parses");
    assert_eq!(node.id, 7);
    assert_eq!(node.addresses, vec!["100.64.0.1/32"]);
    assert!(node.allowed_ips.is_none());
}

#[test]
fn dns_and_derp_types_reachable_through_public_api() {
    let dns = DnsConfig {
        resolvers: Some(vec![DnsResolver {
            addr: "100.100.100.100".to_string(),
        }]),
        domains: Some(vec!["tailnet.example".to_string()]),
    };
    let json = serde_json::to_string(&dns).expect("DnsConfig serializes");
    assert!(json.contains("100.100.100.100"));

    let derp = DerpMap {
        regions: Some(serde_json::json!({"1": {"RegionID": 1}})),
    };
    let json = serde_json::to_string(&derp).expect("DerpMap serializes");
    assert!(json.contains("RegionID"));
}

#[test]
fn register_response_parses_auth_url_variant() {
    let json = r#"{
        "AuthURL": "https://login.tailscale.com/a/abc",
        "MachineAuthorized": false
    }"#;
    let resp: RegisterResponse = serde_json::from_str(json).expect("auth-url variant parses");
    assert_eq!(
        resp.auth_url.as_deref(),
        Some("https://login.tailscale.com/a/abc")
    );
    assert!(!resp.machine_authorized);
    assert!(resp.node_key_expiry.is_none());
}
