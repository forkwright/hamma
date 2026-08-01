//! Tests for the bound on peers retained from a map response.
//!
//! Split into a sibling file because tests.rs + these exceeded the
//! `RUST/file-too-long` threshold.

use super::*;

/// Build `count` distinct peers, numbered from `first_id`.
fn sample_peers(first_id: i64, count: usize) -> Vec<Node> {
    (0..count)
        .map(|offset| {
            let id = first_id + i64::try_from(offset).expect("peer count fits i64");
            sample_node(
                id,
                &format!("nodekey:peer{id}"),
                &format!("peer{id}.ts.net."),
            )
        })
        .collect()
}

/// A full [`MapResponse`] carrying `peers` and nothing else of interest.
fn full_response_with(peers: Vec<Node>) -> MapResponse {
    MapResponse {
        node: Some(sample_node(1, "nodekey:self", "self.ts.net.")),
        peers: Some(peers),
        peers_changed: None,
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    }
}

#[test]
fn apply_map_response_caps_the_initial_peer_list() {
    let mut client = paired_client();

    client.apply_map_response(full_response_with(sample_peers(2, MAX_PEERS + 25)));

    assert_eq!(
        client.peers().len(),
        MAX_PEERS,
        "an over-cap first map response must be truncated to the cap"
    );
}

#[test]
fn apply_map_response_caps_a_full_peer_replacement() {
    let mut client = paired_client();
    client.apply_map_response(full_response_with(sample_peers(2, 1)));

    // Delta re-sending the whole list, this time over the cap.
    let mut delta = full_response_with(sample_peers(2, MAX_PEERS + 25));
    delta.node = None;
    client.apply_map_response(delta);

    assert_eq!(
        client.peers().len(),
        MAX_PEERS,
        "an over-cap full replacement must be truncated to the cap"
    );
}

#[test]
fn apply_map_response_refuses_peer_additions_at_the_cap() {
    let mut client = paired_client();
    client.apply_map_response(full_response_with(sample_peers(2, MAX_PEERS)));

    // Every peer here is new, so each one is growth.
    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: Some(sample_peers(
            i64::try_from(MAX_PEERS).expect("fits") + 100,
            25,
        )),
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client.apply_map_response(delta);

    assert_eq!(
        client.peers().len(),
        MAX_PEERS,
        "peer additions past the cap must be refused, not appended"
    );
}

#[test]
fn apply_map_response_updates_a_known_peer_at_the_cap() {
    let mut client = paired_client();
    client.apply_map_response(full_response_with(sample_peers(2, MAX_PEERS)));

    // WHY: an update to a peer already held is not growth. Refusing it would
    // freeze the netmap's contents for as long as it sits at the cap, so this
    // pins that the cap bounds length alone.
    let mut updated = sample_node(2, "nodekey:peer2", "peer2-updated.ts.net.");
    updated.online = Some(true);

    let delta = MapResponse {
        node: None,
        peers: None,
        peers_changed: Some(vec![updated]),
        peers_changed_patch: None,
        peers_removed: None,
        dns_config: None,
        derp_map: None,
        keep_alive: None,
    };
    client.apply_map_response(delta);

    assert_eq!(client.peers().len(), MAX_PEERS);
    assert_eq!(
        client.peers()[0].name,
        "peer2-updated.ts.net.",
        "an update to a held peer must still apply at the cap"
    );
    assert_eq!(client.peers()[0].online, Some(true));
}
