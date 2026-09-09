//! Tests for `Netmap`/`apply_map_response` merge semantics: initial
//! population, deltas, patches, removals, and the validation added by
//! issue #55.
//!
//! Split into a sibling file because tests.rs + these exceeded the
//! `RUST/file-too-long` threshold.

use mitos::types::{DnsConfig, DnsResolver, MapResponse, PeerChange, PeerRemoval};

use super::*;

#[test]
fn apply_map_response_sets_initial_peers() {
    let mut client = paired_client();

    let resp = MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![
            sample_node(2, "peer1.ts.net."),
            sample_node(3, "peer2.ts.net."),
        ]),
        peers_changed: None,
        peers_changed_patch: None,
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

    client
        .apply_map_response(resp)
        .expect("initial map response should apply");

    let self_node = client.self_node().expect("self_node should be set");
    assert_eq!(self_node.key, hex_node_key(1));
    assert_eq!(client.peers().len(), 2);
    assert_eq!(client.peers()[0].key, hex_node_key(2));
    assert_eq!(client.peers()[1].key, hex_node_key(3));

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
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![sample_node(2, "peer1.ts.net.")]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(initial)
        .expect("initial map response should apply");
    assert_eq!(client.peers().len(), 1);

    // Delta: add a new peer and update existing one.
    let mut updated_peer1 = sample_node(2, "peer1-updated.ts.net.");
    updated_peer1.online = Some(true);

    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: Some(vec![updated_peer1, sample_node(4, "peer3.ts.net.")]),
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("delta should apply");

    assert_eq!(client.peers().len(), 2);
    // Existing peer should be updated.
    assert_eq!(client.peers()[0].name, "peer1-updated.ts.net.");
    assert_eq!(client.peers()[0].online, Some(true));
    // New peer should be appended.
    assert_eq!(client.peers()[1].key, hex_node_key(4));
}

#[test]
fn apply_map_response_removes_peers() {
    let mut client = paired_client();

    // Initial full response with three peers.
    let initial = MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![
            sample_node(2, "peer1.ts.net."),
            sample_node(3, "peer2.ts.net."),
            sample_node(4, "peer3.ts.net."),
        ]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(initial)
        .expect("initial map response should apply");
    assert_eq!(client.peers().len(), 3);

    // Delta: remove peer2 (id 3).
    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: Some(vec![PeerRemoval::NodeKey(hex_node_key(3))]),
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("delta should apply");

    assert_eq!(client.peers().len(), 2);
    assert_eq!(client.peers()[0].key, hex_node_key(2));
    assert_eq!(client.peers()[1].key, hex_node_key(4));
}

#[test]
fn apply_map_response_removes_peers_by_node_id() {
    let mut client = paired_client();

    let initial = MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![
            sample_node(2, "peer1.ts.net."),
            sample_node(3, "peer2.ts.net."),
            sample_node(4, "peer3.ts.net."),
        ]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(initial)
        .expect("initial map response should apply");

    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: Some(vec![PeerRemoval::NodeId(3)]),
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("delta should apply");

    assert_eq!(client.peers().len(), 2);
    assert_eq!(client.peers()[0].id, 2);
    assert_eq!(client.peers()[1].id, 4);
}

#[test]
fn apply_map_response_applies_peer_patch_to_known_peer() {
    let mut client = paired_client();

    let initial = MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![sample_node(2, "peer1.ts.net.")]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(initial)
        .expect("initial map response should apply");

    // A rotated key/disco_key for peer id 2. Tag 1_002 is arbitrary -- it
    // does not correspond to any constructed Node, it just needs to be a
    // distinct, well-formed key so the patch's validation passes.
    let rotated_key = hex_node_key(1_002);
    let rotated_disco_key = hex_disco_key(1_002);

    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: None,
        peers_changed_patch: Some(vec![PeerChange {
            node_id: 2,
            derp_region: Some(7),
            cap: Some(69),
            cap_map: None,
            endpoints: Some(vec!["203.0.113.10:41641".to_string()]),
            key: Some(rotated_key.clone()),
            disco_key: Some(rotated_disco_key.clone()),
            online: Some(true),
            last_seen: Some("2026-05-25T12:00:00Z".to_string()),
            key_expiry: Some("2026-06-25T12:00:00Z".to_string()),
        }]),
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("delta should apply");

    let peer = &client.peers()[0];
    assert_eq!(peer.id, 2);
    assert_eq!(peer.derp.as_deref(), Some("127.3.3.40:7"));
    assert_eq!(peer.cap, Some(69));
    assert_eq!(
        peer.endpoints.as_deref(),
        Some(["203.0.113.10:41641".to_string()].as_slice())
    );
    assert_eq!(peer.key, rotated_key);
    assert_eq!(peer.disco_key.as_deref(), Some(rotated_disco_key.as_str()));
    assert_eq!(peer.online, Some(true));
    assert_eq!(peer.last_seen.as_deref(), Some("2026-05-25T12:00:00Z"));
    assert_eq!(peer.key_expiry.as_deref(), Some("2026-06-25T12:00:00Z"));
}

#[test]
fn apply_map_response_ignores_peer_patch_for_unknown_peer() {
    let mut client = paired_client();

    let initial = MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![sample_node(2, "peer1.ts.net.")]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(initial)
        .expect("initial map response should apply");

    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: None,
        peers_changed_patch: Some(vec![PeerChange {
            node_id: 99,
            derp_region: Some(7),
            cap: Some(69),
            cap_map: None,
            endpoints: Some(vec!["203.0.113.10:41641".to_string()]),
            key: Some("nodekey:unknown".to_string()),
            disco_key: Some("discokey:unknown".to_string()),
            online: Some(true),
            last_seen: Some("2026-05-25T12:00:00Z".to_string()),
            key_expiry: Some("2026-06-25T12:00:00Z".to_string()),
        }]),
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("delta should apply");

    assert_eq!(client.peers().len(), 1);
    let peer = &client.peers()[0];
    assert_eq!(peer.id, 2);
    assert_eq!(peer.key, hex_node_key(2));
    assert!(peer.derp.is_none());
    assert!(peer.endpoints.is_none());
    assert!(peer.disco_key.is_none());
    assert!(peer.online.is_none());
}

#[test]
fn apply_map_response_rejects_malformed_peer_patch_key() {
    // WHY(negative fixture, issue #55): a patch's key/disco_key/endpoints go
    // through `apply_peer_change`, a third ingestion path distinct from the
    // ones `from_full_response`/`apply_delta` filter directly -- this pins
    // that path is guarded too, not just the full-list and peers_changed
    // paths.
    let mut client = paired_client();

    let initial = MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![sample_node(2, "peer1.ts.net.")]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(initial)
        .expect("initial map response should apply");
    let original_key = client.peers()[0].key.clone();

    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: None,
        peers_changed_patch: Some(vec![PeerChange {
            node_id: 2,
            derp_region: None,
            cap: None,
            cap_map: None,
            endpoints: Some(vec!["not-a-socket-addr".to_string()]),
            key: Some("not-hex-at-all".to_string()),
            disco_key: Some("discokey:zz".to_string()),
            online: None,
            last_seen: None,
            key_expiry: None,
        }]),
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("delta should apply");

    let peer = &client.peers()[0];
    assert_eq!(
        peer.key, original_key,
        "a malformed patch key must not overwrite the existing valid key"
    );
    assert!(
        peer.disco_key.is_none(),
        "a malformed patch disco_key must not be applied"
    );
    assert!(
        peer.endpoints.is_none(),
        "malformed patch endpoints must not be applied"
    );
}

#[test]
fn apply_map_response_drops_malformed_peer_from_initial_list() {
    // WHY(negative fixture, issue #55): before validation was wired into
    // `Netmap::from_full_response`, any string in `Key`/`Addresses` was
    // accepted verbatim. Watched failing (peer count == 2) before the fix
    // and passing (== 1) after.
    let mut client = paired_client();

    let mut malformed = sample_node(3, "peer2.ts.net.");
    malformed.key = "not-a-hex-key".to_string();

    let resp = MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![sample_node(2, "peer1.ts.net."), malformed]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(resp)
        .expect("initial map response should apply");

    assert_eq!(
        client.peers().len(),
        1,
        "a peer with a malformed key must not enter the initial netmap"
    );
    assert_eq!(client.peers()[0].key, hex_node_key(2));
}

#[test]
fn apply_map_response_drops_peer_with_malformed_routing_data_from_delta() {
    // WHY(negative fixture, issue #55): `addresses`/`allowed_ips`/`endpoints`
    // are server-controlled routing data (audit finding, issue #55) that
    // previously reached the netmap as raw, unvalidated strings. Watched
    // failing (peer count == 2, garbage address present) before the fix and
    // passing (== 1) after.
    let mut client = paired_client();
    client
        .apply_map_response(full_response_seed())
        .expect("seed response should initialize the netmap");

    let mut bad_routing = sample_node(4, "peer3.ts.net.");
    bad_routing.addresses = vec!["definitely-not-an-ip/32".to_string()];

    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: Some(vec![bad_routing]),
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("delta should apply");

    assert_eq!(
        client.peers().len(),
        1,
        "a peer with a malformed address must not be admitted via peers_changed"
    );
}

#[test]
fn apply_map_response_rejects_initial_map_with_malformed_self_node() {
    // WHY(negative fixture, issue #127): before the fix, a malformed initial
    // self node silently initialized the netmap with a fabricated
    // zero-value identity (ID 0, empty key). The self node anchors identity,
    // addressing, and key-expiry state for everything downstream, so the
    // initial map must fail closed instead.
    let mut client = paired_client();

    let mut malformed_self = sample_node(1, "self.ts.net.");
    malformed_self.key = "garbage".to_string();

    let resp = MapResponse {
        node: Some(malformed_self),
        peers: Some(vec![sample_node(2, "peer1.ts.net.")]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    let err = client
        .apply_map_response(resp)
        .expect_err("an initial map without a valid self node must be rejected");

    assert!(
        matches!(err, ControlError::InvalidInitialSelfNode { node_id: 1 }),
        "expected InvalidInitialSelfNode naming the rejected node, got {err:?}"
    );
    assert!(
        client.self_node().is_none(),
        "a rejected initial map must leave the client uninitialized"
    );
    assert!(
        client.peers().is_empty(),
        "a rejected initial map must not admit its peers either"
    );
}

#[test]
fn apply_map_response_rejects_initial_map_without_self_node() {
    // WHY(negative fixture, issue #127): an omitted `Node` is the other
    // shape of "no valid self node" and must fail the same way rather than
    // initialize a placeholder identity.
    let mut client = paired_client();

    let resp = MapResponse {
        node: None,
        peers: Some(vec![sample_node(2, "peer1.ts.net.")]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    let err = client
        .apply_map_response(resp)
        .expect_err("an initial map with no self node must be rejected");

    assert!(
        matches!(err, ControlError::MissingInitialSelfNode),
        "expected MissingInitialSelfNode, got {err:?}"
    );
    assert!(
        client.self_node().is_none(),
        "a rejected initial map must leave the client uninitialized"
    );
    assert!(
        client.peers().is_empty(),
        "a rejected initial map must not admit its peers either"
    );
}

#[test]
fn apply_map_response_preserves_self_node_when_delta_self_is_malformed() {
    // WHY(issue #127): delta semantics intentionally differ from the initial
    // map -- once a valid identity exists, a malformed later self update is
    // dropped with that identity preserved, rather than failing the update.
    let mut client = paired_client();
    client
        .apply_map_response(full_response_seed())
        .expect("seed response should initialize the netmap");

    let mut malformed_self = sample_node(1, "self-renamed.ts.net.");
    malformed_self.key = "garbage".to_string();

    let delta = MapResponse {
        node: Some(malformed_self),
        peers: None,
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("a malformed delta self node is dropped, not an error");

    let self_node = client.self_node().expect("netmap should stay initialized");
    assert_eq!(
        self_node.key,
        hex_node_key(1),
        "the previously validated self node must survive a malformed delta update"
    );
    assert_eq!(
        self_node.name, "self.ts.net.",
        "no field of the malformed delta self node may leak into the stored identity"
    );
}

#[test]
fn apply_map_response_peers_changed_replaces_rotated_key_without_duplicating() {
    // WHY(issue #126): a key rotation delivered as a full PeersChanged
    // record carries the same node ID with a new key. Matching by key would
    // append a second record and retain the stale key; matching by node ID
    // replaces the one canonical record, as the reference implementation's
    // NodeID-keyed peer map does.
    let mut client = paired_client();
    client
        .apply_map_response(full_response_seed())
        .expect("seed response should initialize the netmap");
    assert_eq!(client.peers().len(), 1);

    let mut rotated = sample_node(2, "peer1.ts.net.");
    rotated.key = hex_node_key(1_002);

    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: Some(vec![rotated]),
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("delta should apply");

    assert_eq!(
        client.peers().len(),
        1,
        "a key rotation must replace the peer record, not add a duplicate"
    );
    assert_eq!(client.peers()[0].id, 2);
    assert_eq!(
        client.peers()[0].key,
        hex_node_key(1_002),
        "the rotated key must replace the stale key on the same record"
    );

    // The rotated peer stays addressable by node ID for a later removal.
    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: Some(vec![PeerRemoval::NodeId(2)]),
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("delta should apply");
    assert!(
        client.peers().is_empty(),
        "the rotated peer must be removable by node ID"
    );
}

#[test]
fn apply_map_response_peer_patch_with_empty_endpoints_clears_them() {
    // WHY(issue #126): an explicitly empty `Endpoints` list is the control
    // plane revoking every previously advertised direct endpoint -- it must
    // clear the stored list, not collapse into "unchanged".
    let mut client = paired_client();

    let mut peer = sample_node(2, "peer1.ts.net.");
    peer.endpoints = Some(vec!["203.0.113.10:41641".to_string()]);
    let initial = MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![peer]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(initial)
        .expect("initial map response should apply");
    assert_eq!(
        client.peers()[0].endpoints.as_deref(),
        Some(["203.0.113.10:41641".to_string()].as_slice()),
        "the fixture must start with an advertised endpoint"
    );

    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: None,
        peers_changed_patch: Some(vec![PeerChange {
            node_id: 2,
            derp_region: None,
            cap: None,
            cap_map: None,
            endpoints: Some(Vec::new()),
            key: None,
            disco_key: None,
            online: None,
            last_seen: None,
            key_expiry: None,
        }]),
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("delta should apply");

    assert_eq!(
        client.peers()[0].endpoints,
        Some(Vec::new()),
        "an explicitly empty endpoint list must clear the stored endpoints"
    );
}

#[test]
fn apply_map_response_peer_patch_without_endpoints_preserves_them() {
    // WHY(issue #126): tri-state patch semantics -- an omitted `Endpoints`
    // field means "unchanged" and is distinct from an explicitly empty list.
    let mut client = paired_client();

    let mut peer = sample_node(2, "peer1.ts.net.");
    peer.endpoints = Some(vec!["203.0.113.10:41641".to_string()]);
    let initial = MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![peer]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(initial)
        .expect("initial map response should apply");

    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: None,
        peers_changed_patch: Some(vec![PeerChange {
            node_id: 2,
            derp_region: None,
            cap: None,
            cap_map: None,
            endpoints: None,
            key: None,
            disco_key: None,
            online: Some(true),
            last_seen: None,
            key_expiry: None,
        }]),
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("delta should apply");

    assert_eq!(
        client.peers()[0].endpoints.as_deref(),
        Some(["203.0.113.10:41641".to_string()].as_slice()),
        "an omitted endpoint field must leave the stored endpoints unchanged"
    );
    assert_eq!(
        client.peers()[0].online,
        Some(true),
        "the rest of the patch must still apply"
    );
}

#[test]
fn apply_map_response_drops_malformed_dns_resolver() {
    let mut client = paired_client();

    let resp = MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: None,
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: Some(DnsConfig {
            resolvers: Some(vec![
                DnsResolver {
                    addr: "100.100.100.100".to_string(),
                },
                DnsResolver {
                    addr: "not-an-address".to_string(),
                },
            ]),
            domains: None,
        }),
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(resp)
        .expect("initial map response should apply");

    let netmap = client.netmap.as_ref().expect("netmap should exist");
    let resolvers = netmap
        .dns_config
        .as_ref()
        .expect("dns_config should exist")
        .resolvers
        .as_ref()
        .expect("resolvers should exist");
    assert_eq!(
        resolvers.len(),
        1,
        "the malformed resolver address must be dropped, the valid one kept"
    );
    assert_eq!(resolvers[0].addr, "100.100.100.100");
}

/// A minimal valid initial [`MapResponse`] carrying just a self node -- used
/// by tests that only need the netmap initialized before applying a delta.
fn full_response_seed() -> MapResponse {
    MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![sample_node(2, "peer1.ts.net.")]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    }
}

#[test]
fn keepalive_does_not_modify_netmap() {
    let mut client = paired_client();

    // Initialize with a peer.
    let initial = MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![sample_node(2, "peer1.ts.net.")]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(initial)
        .expect("initial map response should apply");
    assert_eq!(client.peers().len(), 1);

    // Keepalive should not change anything.
    let keepalive = MapResponse {
        node: None,
        peers: None,
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: Some(true),
    };
    client
        .apply_map_response(keepalive)
        .expect("keepalive should apply");

    assert_eq!(client.peers().len(), 1);
    assert_eq!(client.peers()[0].key, hex_node_key(2));
}

// -----------------------------------------------------------------------
// Property tests
// -----------------------------------------------------------------------

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    /// After any sequence of delta updates the peer list has no duplicate
    /// keys, no duplicate node IDs, and every explicitly removed key is
    /// absent.
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
                sample_node(id, &format!("peer{i}.ts.net."))
            })
            .collect();

        let initial = MapResponse {
            node: Some(sample_node(1, "self.ts.net.")),
            peers: Some(initial_peers),
            peers_changed: None,
            peers_changed_patch: None,
            peers_removed: None,
            dns_config: None,
            derp_map: None,
            keep_alive: None,
        };
        client.apply_map_response(initial).expect("initial map response should apply");
        assert_eq!(client.peers().len(), n_initial);

        // Add new peers via peers_changed.
        if n_add > 0 {
            let new_peers: Vec<Node> = (0..n_add)
                .map(|i| {
                    let idx = n_initial + i;
                    let id = i64::try_from(idx).expect("test index fits i64") + 2;
                    sample_node(id, &format!("newpeer{idx}.ts.net."))
                })
                .collect();
            let delta = MapResponse {
                node: None,
                peers: None,
                peers_changed: Some(new_peers),
                peers_changed_patch: None,
                peers_removed: None,
                dns_config: None,
                derp_map: None,
                keep_alive: None,
            };
            client.apply_map_response(delta).expect("delta should apply");
            assert_eq!(client.peers().len(), n_initial + n_add);
        }

        // Remove up to n_remove of the original peers.
        let n_to_remove = n_remove.min(n_initial);
        let removed_keys: Vec<String> = (0..n_to_remove)
            .map(|i| hex_node_key(i64::try_from(i).expect("test index fits i64") + 2))
            .collect();
        let removals: Vec<PeerRemoval> = removed_keys
            .iter()
            .cloned()
            .map(PeerRemoval::NodeKey)
            .collect();

        if n_to_remove > 0 {
            let delta = MapResponse {
                node: None,
                peers: None,
                peers_changed: None,
                peers_changed_patch: None,
                peers_removed: Some(removals),
                dns_config: None,
                derp_map: None,
                keep_alive: None,
            };
            client.apply_map_response(delta).expect("delta should apply");
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

        // Invariant (issue #126): no duplicate node IDs -- the netmap keeps
        // one live record per node ID, the identity patches and removals
        // address.
        let mut seen_ids = std::collections::HashSet::new();
        for peer in final_peers {
            let is_new = seen_ids.insert(peer.id);
            assert!(is_new, "duplicate peer node ID found: {}", peer.id);
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

#[test]
fn apply_map_response_removes_peers_named_by_either_identifier_in_one_delta() {
    // WHY(#55): the removal sweep now indexes the removal list instead of
    // rescanning it per peer. Both identifier kinds, and a removal naming a
    // peer that is not present, must behave exactly as the linear scan did.
    let mut client = paired_client();

    let initial = MapResponse {
        node: Some(sample_node(1, "self.ts.net.")),
        peers: Some(vec![
            sample_node(2, "peer1.ts.net."),
            sample_node(3, "peer2.ts.net."),
            sample_node(4, "peer3.ts.net."),
            sample_node(5, "peer4.ts.net."),
        ]),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(initial)
        .expect("initial map response should apply");
    assert_eq!(client.peers().len(), 4);

    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: Some(vec![
            PeerRemoval::NodeId(3),
            PeerRemoval::NodeKey(hex_node_key(5)),
            PeerRemoval::NodeId(3),
            PeerRemoval::NodeId(999),
            PeerRemoval::NodeKey("nodekey:absent".to_string()),
        ]),
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client
        .apply_map_response(delta)
        .expect("delta should apply");

    let remaining: Vec<String> = client.peers().iter().map(|p| p.key.clone()).collect();
    assert_eq!(
        remaining,
        vec![hex_node_key(2), hex_node_key(4)],
        "removals by id and by key must both apply, and unmatched removals must be inert"
    );
}
