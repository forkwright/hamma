//! Control protocol types for the Tailscale control plane.
//!
//! These structures match the JSON wire format used by the tailscale.com
//! control server. Field names use `serde(rename)` to match Tailscale's
//! `PascalCase` convention while keeping Rust-idiomatic `snake_case` locally.
//!
//! References: `tailcfg/tailcfg.go` in the Tailscale Go source.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// Request sent to `POST /machine/register` to register this node with
/// the control plane.
///
/// The control server associates the node key with the machine key
/// (established during the Noise handshake) and either authorizes
/// immediately or returns an [`RegisterResponse::auth_url`] for
/// interactive login.
#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    /// The current node key, serialized as `"nodekey:hex..."`.
    ///
    /// This is the *public* key half of the node keypair (typed hex
    /// identifier). Not a secret; the control server returns and logs it
    /// freely. `SecretString` would lose Serialize semantics used by
    /// `serde_json` for the wire format.
    #[serde(rename = "NodeKey")]
    pub node_key: String, // kanon:ignore RUST/plain-string-secret -- public key hex, not a secret

    /// The previous node key, if rotating due to expiry. Empty string on
    /// first registration. Also a public key hex, not a secret.
    #[serde(rename = "OldNodeKey")]
    pub old_node_key: String, // kanon:ignore RUST/plain-string-secret -- public key hex, not a secret

    /// Pre-authentication key for headless registration. `None` triggers
    /// the interactive auth flow.
    #[serde(rename = "Auth", skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthInfo>,

    /// Host information describing this machine.
    #[serde(rename = "Hostinfo")]
    pub hostinfo: Hostinfo,

    /// Follow-up URL for long-polling after the user visits the auth URL.
    /// Set to the `auth_url` from the initial [`RegisterResponse`].
    #[serde(rename = "Followup", skip_serializing_if = "Option::is_none")]
    pub followup: Option<String>,
}

/// Authentication information included in [`RegisterRequest`].
#[derive(Debug, Serialize)]
pub struct AuthInfo {
    /// Pre-auth key value (e.g. `tskey-auth-...`).
    #[serde(rename = "AuthKey", skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<String>,
}

/// Host information describing this machine to the control server.
///
/// The control server uses this for display in the admin console and
/// for capability negotiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hostinfo {
    /// Opaque identifier for correlating backend logs.
    #[serde(rename = "BackendLogID")]
    pub backend_log_id: String,

    /// Operating system name (e.g. `"linux"`, `"darwin"`).
    #[serde(rename = "OS")]
    pub os: String,

    /// Machine hostname.
    #[serde(rename = "Hostname")]
    pub hostname: String,

    /// Client implementation version. Tailscale sends a Go version string;
    /// dictyon sends `"dictyon/0.1.0"`.
    #[serde(rename = "GoVersion")]
    pub go_version: String,
}

/// Response from `POST /machine/register`.
#[derive(Debug, Deserialize)]
pub struct RegisterResponse {
    /// URL the user must visit to authorize this machine. `None` if the
    /// machine is already authorized (e.g. via pre-auth key).
    #[serde(rename = "AuthURL")]
    pub auth_url: Option<String>,

    /// Whether the machine is now authorized.
    #[serde(rename = "MachineAuthorized")]
    pub machine_authorized: bool,

    /// ISO 8601 expiry timestamp for the node key. `None` if the key does
    /// not expire.
    #[serde(rename = "NodeKeyExpiry")]
    pub node_key_expiry: Option<String>,
}

// ---------------------------------------------------------------------------
// Map request / response
// ---------------------------------------------------------------------------

/// Request sent to `POST /machine/map` to receive the network map.
///
/// When `stream` is true the server holds the connection open and pushes
/// delta updates.
#[derive(Debug, Serialize)]
pub struct MapRequest {
    /// Protocol capability version.
    #[serde(rename = "Version")]
    pub version: u64,

    /// Optional response compression requested from the control server.
    ///
    /// Tailscale-compatible servers accept `"zstd"` to send each map response
    /// payload as an independently compressed zstandard frame.
    #[serde(rename = "Compress", skip_serializing_if = "Option::is_none")]
    pub compress: Option<String>,

    /// This node's public key, serialized as `"nodekey:hex..."`. Public
    /// identifier, not a secret.
    #[serde(rename = "NodeKey")]
    pub node_key: String, // kanon:ignore RUST/plain-string-secret -- public key hex, not a secret

    /// This node's disco public key, serialized as `"discokey:hex..."`.
    /// Public identifier used for NAT traversal; not a secret.
    #[serde(rename = "DiscoKey")]
    pub disco_key: String, // kanon:ignore RUST/plain-string-secret -- public key hex, not a secret

    /// Locally discovered endpoints.
    #[serde(rename = "Endpoints")]
    pub endpoints: Vec<String>,

    /// Whether to hold the connection open for streaming updates.
    #[serde(rename = "Stream")]
    pub stream: bool,

    /// Whether to omit peers from the response (used for initial registration
    /// polling before the node is fully authorized).
    #[serde(rename = "OmitPeers")]
    pub omit_peers: bool,

    /// Host information.
    #[serde(rename = "Hostinfo")]
    pub hostinfo: Hostinfo,
}

/// A response frame from the `/machine/map` streaming endpoint.
///
/// The first response contains the full network map (`node` + `peers`).
/// Subsequent responses are deltas: `peers_changed`, `peers_removed`,
/// and/or `peers_changed_patch` indicate incremental updates. If
/// `keep_alive` is `true`, all other fields should be ignored (liveness
/// probe).
#[derive(Debug, Deserialize)]
pub struct MapResponse {
    /// This node's own information. `None` means unchanged from the
    /// previous response.
    #[serde(rename = "Node")]
    pub node: Option<Node>,

    /// Full peer list (first response only). `None` on deltas.
    #[serde(rename = "Peers")]
    pub peers: Option<Vec<Node>>,

    /// Peers that were added or changed since the last response.
    #[serde(rename = "PeersChanged")]
    pub peers_changed: Option<Vec<Node>>,

    /// Lightweight peer mutations sent instead of full [`Node`] records.
    ///
    /// Parsing these keeps the wire type aligned with newer control servers;
    /// application semantics live in the control client.
    #[serde(rename = "PeersChangedPatch")]
    pub peers_changed_patch: Option<Vec<PeerChange>>,

    /// Peers that were removed.
    #[serde(rename = "PeersRemoved")]
    pub peers_removed: Option<Vec<PeerRemoval>>,

    /// DNS configuration for `MagicDNS` and split DNS.
    #[serde(rename = "DNSConfig")]
    pub dns_config: Option<DnsConfig>,

    /// DERP relay server topology.
    #[serde(rename = "DERPMap")]
    pub derp_map: Option<DerpMap>,

    /// If `true`, this is a keep-alive probe. All other fields should be
    /// ignored.
    #[serde(rename = "KeepAlive")]
    pub keep_alive: Option<bool>,
}

/// Peer removal marker from [`MapResponse::peers_removed`].
///
/// Newer control servers identify removed peers by numeric node ID. The string
/// variant preserves compatibility with older key-string frames.
// WHY: variant names match Tailscale control-protocol wire identifiers;
// renaming would diverge from protocol documentation and break serde mappings.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "PeerRemovalWire")]
pub enum PeerRemoval {
    /// Server-assigned numeric node identifier.
    NodeId(i64),

    /// Node public key string, serialized as `"nodekey:hex..."`.
    NodeKey(String),
}

// WHY: variant names mirror the public PeerRemoval wire identifiers for serde symmetry.
#[allow(clippy::enum_variant_names)]
#[derive(Deserialize)]
#[serde(untagged)]
enum PeerRemovalWire {
    NodeId(i64),
    NodeKey(String),
    NodeIdObject {
        #[serde(rename = "NodeID")]
        node_id: i64,
    },
}

impl From<PeerRemovalWire> for PeerRemoval {
    fn from(value: PeerRemovalWire) -> Self {
        match value {
            PeerRemovalWire::NodeId(node_id) | PeerRemovalWire::NodeIdObject { node_id } => {
                Self::NodeId(node_id)
            }
            PeerRemovalWire::NodeKey(key) => Self::NodeKey(key),
        }
    }
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

/// A node in the tailnet, representing either this machine or a peer.
///
/// Fields are optional where the control server may omit them (e.g. on
/// delta updates or for peers with limited visibility).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Node {
    /// Server-assigned numeric identifier.
    #[serde(rename = "ID")]
    pub id: i64,

    /// Stable cross-process node identifier, when sent by the control plane.
    #[serde(rename = "StableID", skip_serializing_if = "Option::is_none")]
    pub stable_id: Option<String>,

    /// The node's public key, serialized as `"nodekey:hex..."`. Public
    /// identifier, not a secret.
    #[serde(rename = "Key")]
    pub key: String, // kanon:ignore RUST/plain-string-secret -- public key hex, not a secret

    /// The node's machine public key, serialized as `"mkey:hex..."`.
    #[serde(rename = "Machine", skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,

    /// The node's FQDN (trailing dot in Tailscale convention).
    #[serde(rename = "Name")]
    pub name: String,

    /// Capability version advertised for this node.
    #[serde(rename = "Cap", skip_serializing_if = "Option::is_none")]
    pub cap: Option<u64>,

    /// ACL tags applied to this node.
    #[serde(rename = "Tags", skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,

    /// Assigned IP addresses in CIDR notation (e.g. `"100.64.0.1/32"`).
    #[serde(rename = "Addresses")]
    pub addresses: Vec<String>,

    /// Routable CIDRs for this node (may include subnet routes).
    #[serde(rename = "AllowedIPs", skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<Vec<String>>,

    /// Network endpoints where this node can be reached directly.
    #[serde(rename = "Endpoints", skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<String>>,

    /// DERP home region in `"127.3.3.40:N"` format, where N is the
    /// region ID.
    #[serde(rename = "DERP", skip_serializing_if = "Option::is_none")]
    pub derp: Option<String>,

    /// The node's disco key for NAT traversal.
    #[serde(rename = "DiscoKey", skip_serializing_if = "Option::is_none")]
    pub disco_key: Option<String>,

    /// ISO 8601 expiry timestamp for the node key.
    #[serde(rename = "KeyExpiry", skip_serializing_if = "Option::is_none")]
    pub key_expiry: Option<String>,

    /// ISO 8601 timestamp for the last time this node was seen online.
    #[serde(rename = "LastSeen", skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,

    /// Whether the node is currently online according to the control
    /// server.
    #[serde(rename = "Online", skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
}

/// Lightweight mutation for one peer in [`MapResponse::peers_changed_patch`].
///
/// The control server sends these after a full map to avoid resending an
/// entire [`Node`] when only endpoint, key, capability, or presence metadata
/// changed.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerChange {
    /// Server-assigned numeric identifier of the peer being mutated.
    #[serde(rename = "NodeID")]
    pub node_id: i64,

    /// Updated DERP home region ID.
    #[serde(rename = "DERPRegion", skip_serializing_if = "Option::is_none")]
    pub derp_region: Option<i64>,

    /// Updated capability version for this peer.
    #[serde(rename = "Cap", skip_serializing_if = "Option::is_none")]
    pub cap: Option<u64>,

    /// Opaque capability map until hamma-core has a typed capability model.
    #[serde(rename = "CapMap", skip_serializing_if = "Option::is_none")]
    pub cap_map: Option<serde_json::Value>,

    /// Updated direct UDP endpoints.
    #[serde(rename = "Endpoints", skip_serializing_if = "Option::is_none")]
    pub endpoints: Option<Vec<String>>,

    /// Updated node public key.
    #[serde(rename = "Key", skip_serializing_if = "Option::is_none")]
    pub key: Option<String>, // kanon:ignore RUST/plain-string-secret -- public key hex, not a secret

    /// Updated disco public key.
    #[serde(rename = "DiscoKey", skip_serializing_if = "Option::is_none")]
    pub disco_key: Option<String>,

    /// Updated online status.
    #[serde(rename = "Online", skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,

    /// Updated last-seen timestamp.
    #[serde(rename = "LastSeen", skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,

    /// Updated node-key expiry timestamp.
    #[serde(rename = "KeyExpiry", skip_serializing_if = "Option::is_none")]
    pub key_expiry: Option<String>,
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

/// DNS configuration received in [`MapResponse`].
///
/// Controls `MagicDNS` behavior, split DNS routes, and upstream resolvers.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsConfig {
    /// Upstream DNS resolvers.
    #[serde(rename = "Resolvers", skip_serializing_if = "Option::is_none")]
    pub resolvers: Option<Vec<DnsResolver>>,

    /// DNS search domains.
    #[serde(rename = "Domains", skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
}

/// A single DNS resolver entry.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsResolver {
    /// Resolver address (e.g. `"1.1.1.1:53"` or `"100.100.100.100"`).
    #[serde(rename = "Addr")]
    pub addr: String,
}

// ---------------------------------------------------------------------------
// DERP
// ---------------------------------------------------------------------------

/// DERP relay server topology received in [`MapResponse`].
///
/// The `regions` field contains the full DERP region map, which is a
/// complex nested structure. We defer full typing and parse it as
/// opaque JSON for now.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DerpMap {
    /// Region definitions. Complex nested structure; parsed as opaque
    /// JSON until full typing is needed.
    #[serde(rename = "Regions", skip_serializing_if = "Option::is_none")]
    pub regions: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "tests use expect() for invariants that must hold"
)]
mod tests {
    use super::*;

    #[test]
    fn register_request_serializes_to_json() {
        let req = RegisterRequest {
            node_key: "nodekey:abc123".to_string(),
            old_node_key: String::new(),
            auth: Some(AuthInfo {
                auth_key: Some("tskey-auth-test".to_string()),
            }),
            hostinfo: Hostinfo {
                backend_log_id: "log123".to_string(),
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
}
