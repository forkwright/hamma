//! The local [`Netmap`] and the logic that merges server-sent
//! [`MapResponse`] updates into it.
//!
//! Split into a sibling of `mod.rs` because the two together exceeded the
//! `RUST/file-too-long` threshold.

use std::collections::HashSet;

use mitos::types::{DerpMap, DnsConfig, MapResponse, Node, PeerChange, PeerRemoval};
use tracing::warn;

use super::ControlError;
use super::validate::{
    dns_resolver_is_valid, endpoints_are_valid, is_valid_disco_key, is_valid_node_key,
    node_is_valid,
};

/// Upper bound on the peers a netmap retains from a coordination server.
///
/// WHY: every peer-bearing field of a [`MapResponse`] is server-controlled and
/// unbounded on the wire, so a misbehaving or hostile server can grow
/// [`Netmap::peers`] without limit across a single connection. The cap sits far
/// above any realistic tailnet, so it is unreachable in normal operation and
/// only bounds the memory one connection can commit.
// WHY(pub(crate) not pub(super)): `control::tests` re-exports this via
// `control/mod.rs` for its descendant test modules to reach through
// `use super::*` -- a `pub(crate) use` re-export cannot exceed the source
// item's own visibility (E0364), so the source must be `pub(crate)` too.
pub(crate) const MAX_PEERS: usize = 10_000;

/// The local view of the network map, maintained by applying
/// [`MapResponse`] updates.
///
/// Starts empty and is populated by the first full map response.
/// Subsequent delta responses update it incrementally.
#[derive(Debug)]
pub struct Netmap {
    /// This node's own information.
    pub self_node: Node,
    /// Known peers in the tailnet.
    pub peers: Vec<Node>,
    /// Current DNS configuration.
    pub dns_config: Option<DnsConfig>,
    /// Current DERP relay topology.
    pub derp_map: Option<DerpMap>,
}

impl Netmap {
    /// Build a netmap from the first full [`MapResponse`].
    ///
    /// The response must carry a self [`Node`] that passes
    /// [`node_is_valid`]: the self node anchors this machine's identity,
    /// addresses, and key-expiry state, so initializing without one would
    /// publish a fabricated identity as if it were real (issue #127).
    /// Missing peers default to an empty list, and a peer failing that same
    /// check is dropped rather than admitted to the initial list.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::MissingInitialSelfNode`] when the response
    /// omits `Node`, or [`ControlError::InvalidInitialSelfNode`] when the
    /// self node fails validation. Delta responses are handled differently
    /// -- see [`Netmap::apply_delta`].
    pub(super) fn from_full_response(resp: MapResponse) -> Result<Self, ControlError> {
        let self_node = match resp.node {
            Some(node) if node_is_valid(&node) => node,
            Some(node) => {
                return Err(ControlError::InvalidInitialSelfNode { node_id: node.id });
            }
            None => return Err(ControlError::MissingInitialSelfNode),
        };

        let mut peers = resp.peers.unwrap_or_default();
        let before = peers.len();
        peers.retain(node_is_valid);
        if peers.len() < before {
            warn!(
                rejected = before - peers.len(),
                "rejected malformed peers in the initial map response"
            );
        }
        dedupe_peers_by_id(&mut peers);
        cap_peers(&mut peers);

        Ok(Self {
            self_node,
            peers,
            dns_config: resp.dns_config.map(sanitize_dns_config),
            derp_map: resp.derp_map,
        })
    }

    /// Apply a delta [`MapResponse`] onto an already-initialized netmap.
    ///
    /// See [`ControlClient::apply_map_response`](super::ControlClient::apply_map_response)
    /// for the merge semantics.
    pub(super) fn apply_delta(&mut self, resp: MapResponse) {
        if let Some(node) = resp.node {
            if node_is_valid(&node) {
                self.self_node = node;
            } else {
                warn!(node_id = node.id, "rejected malformed self node update");
            }
        }

        // Full peer replacement (if server sends full list again).
        if let Some(mut peers) = resp.peers {
            let before = peers.len();
            peers.retain(node_is_valid);
            if peers.len() < before {
                warn!(
                    rejected = before - peers.len(),
                    "rejected malformed peers in a full peer-list replacement"
                );
            }
            dedupe_peers_by_id(&mut peers);
            cap_peers(&mut peers);
            self.peers = peers;
        }

        // Incremental peer additions/changes.
        if let Some(changed) = resp.peers_changed {
            // WHY: counted rather than warned per peer, so a server sending a
            // large over-cap or malformed-heavy delta costs one log line
            // each, not one per peer.
            let mut refused = 0usize;
            let mut rejected = 0usize;
            for changed_peer in changed {
                if !node_is_valid(&changed_peer) {
                    rejected += 1;
                    continue;
                }
                // WHY: peers are indexed by the server-assigned node ID --
                // the same identity patches and removals address. Matching
                // by key instead would treat a key rotation delivered as a
                // full record as a new peer and retain the stale-key record
                // alongside it (issue #126); the reference implementation
                // keys its peer map by node ID for the same reason.
                if let Some(existing) = self.peers.iter_mut().find(|p| p.id == changed_peer.id) {
                    // WHY: an update to a peer already held is not growth, so it
                    // still applies once the netmap has reached the cap.
                    *existing = changed_peer;
                } else if self.peers.len() < MAX_PEERS {
                    self.peers.push(changed_peer);
                } else {
                    refused += 1;
                }
            }
            if refused > 0 {
                warn!(
                    cap = MAX_PEERS,
                    refused, "netmap is at the peer cap; refused new peers from a map response"
                );
            }
            if rejected > 0 {
                warn!(
                    rejected,
                    "rejected malformed peers from a map response delta"
                );
            }
        }

        // Peer removals.
        if let Some(removals) = resp.peers_removed {
            let index = PeerRemovalIndex::build(&removals);
            self.peers.retain(|peer| !index.removes(peer));
        }

        if let Some(changes) = resp.peers_changed_patch {
            for change in changes {
                apply_peer_change(&mut self.peers, change);
            }
        }

        if let Some(dns) = resp.dns_config {
            self.dns_config = Some(sanitize_dns_config(dns));
        }

        if let Some(derp) = resp.derp_map {
            self.derp_map = Some(derp);
        }
    }
}

fn apply_peer_change(peers: &mut [Node], change: PeerChange) {
    let Some(peer) = peers.iter_mut().find(|peer| peer.id == change.node_id) else {
        return;
    };

    if let Some(region) = change.derp_region.filter(|region| *region > 0) {
        peer.derp = Some(format!("127.3.3.40:{region}"));
    }

    if let Some(cap) = change.cap.filter(|cap| *cap > 0) {
        peer.cap = Some(cap);
    }

    // WHY: tri-state patch semantics (issue #126) -- an omitted field
    // leaves the stored endpoints untouched, while an explicitly empty list
    // revokes every previously advertised direct endpoint. Collapsing the
    // two would keep the client dialing an address the server deliberately
    // removed.
    match change.endpoints {
        Some(endpoints) if endpoints.is_empty() => peer.endpoints = Some(Vec::new()),
        Some(endpoints) => {
            if endpoints_are_valid(&endpoints) {
                peer.endpoints = Some(endpoints);
            } else {
                warn!(
                    node_id = peer.id,
                    "rejected malformed endpoints in a peer patch"
                );
            }
        }
        None => {}
    }

    if let Some(key) = change.key {
        if is_valid_node_key(&key) {
            peer.key = key;
        } else {
            warn!(node_id = peer.id, "rejected malformed key in a peer patch");
        }
    }

    if let Some(disco_key) = change.disco_key {
        if is_valid_disco_key(&disco_key) {
            peer.disco_key = Some(disco_key);
        } else {
            warn!(
                node_id = peer.id,
                "rejected malformed disco_key in a peer patch"
            );
        }
    }

    if let Some(online) = change.online {
        peer.online = Some(online);
    }

    if let Some(last_seen) = change.last_seen {
        peer.last_seen = Some(last_seen);
    }

    if let Some(key_expiry) = change.key_expiry {
        peer.key_expiry = Some(key_expiry);
    }
}

/// Drop records after the first that repeat a node ID already present in a
/// server-supplied peer list.
///
/// WHY: the netmap keeps one live record per node ID (issue #126) -- the
/// same identity that patches and removals address. A full list naming one
/// ID twice is a server protocol violation; keeping the first record is a
/// deterministic resolution that cannot leave two divergent records for one
/// peer.
///
/// Shared by both paths that accept a whole list from the server, so the
/// invariant cannot be enforced on one and forgotten on the other.
fn dedupe_peers_by_id(peers: &mut Vec<Node>) {
    let mut seen = HashSet::new();
    let before = peers.len();
    peers.retain(|peer| seen.insert(peer.id));
    if peers.len() < before {
        warn!(
            dropped = before - peers.len(),
            "map response listed a peer node ID more than once; kept the first record"
        );
    }
}

/// Drop resolver entries whose `addr` does not parse, in place.
///
/// WHY: `DnsConfig` is a wire DTO passed straight through by
/// [`Netmap::from_full_response`]/[`Netmap::apply_delta`] otherwise -- this
/// is the one point both paths route through before it is stored, so a
/// malformed resolver address cannot reach a consumer that trusts it.
fn sanitize_dns_config(mut dns: DnsConfig) -> DnsConfig {
    if let Some(resolvers) = &mut dns.resolvers {
        let before = resolvers.len();
        resolvers.retain(dns_resolver_is_valid);
        if resolvers.len() < before {
            warn!(
                rejected = before - resolvers.len(),
                "rejected malformed DNS resolver addresses in a map response"
            );
        }
    }
    dns
}

/// Truncate a server-supplied peer list to [`MAX_PEERS`].
///
/// WHY: shared by both paths that accept a whole list from the server, so the
/// cap cannot be enforced on one and forgotten on the other.
fn cap_peers(peers: &mut Vec<Node>) {
    if peers.len() > MAX_PEERS {
        let dropped = peers.len() - MAX_PEERS;
        warn!(
            cap = MAX_PEERS,
            dropped, "map response exceeded the peer cap; dropped the excess peers"
        );
        peers.truncate(MAX_PEERS);
    }
}

/// O(1) membership test over a server-supplied peer-removal list.
///
/// WHY: both the peer list and the removal list arrive from the coordination
/// server, so scanning the removals once per peer is O(n*m) work a server can
/// demand at will by sending a large delta. Indexing the removals first makes
/// the sweep linear in the peer count regardless of how many removals arrive.
struct PeerRemovalIndex<'a> {
    node_ids: HashSet<i64>,
    node_keys: HashSet<&'a str>,
}

impl<'a> PeerRemovalIndex<'a> {
    /// Index a removal list by the two identifiers it can name a peer with.
    fn build(removals: &'a [PeerRemoval]) -> Self {
        let mut node_ids = HashSet::new();
        let mut node_keys = HashSet::new();
        for removal in removals {
            match removal {
                PeerRemoval::NodeId(node_id) => {
                    node_ids.insert(*node_id);
                }
                PeerRemoval::NodeKey(key) => {
                    node_keys.insert(key.as_str());
                }
                // WHY: PeerRemoval is #[non_exhaustive]; an unrecognized
                // variant names a peer this client cannot index by ID or key.
                _ => {} // skipped rather than treated as a match failure
            }
        }
        Self {
            node_ids,
            node_keys,
        }
    }

    /// Whether this removal set names `peer`, by node ID or by node key.
    fn removes(&self, peer: &Node) -> bool {
        self.node_ids.contains(&peer.id) || self.node_keys.contains(peer.key.as_str())
    }
}
