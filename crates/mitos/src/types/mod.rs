//! Control protocol types for the Tailscale control plane.
//!
//! These structures match the JSON wire format used by the tailscale.com
//! control server. Field names use `serde(rename)` to match Tailscale's
//! `PascalCase` convention while keeping Rust-idiomatic `snake_case` locally.
//!
//! References: `tailcfg/tailcfg.go` in the Tailscale Go source.

use std::fmt;

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
///
/// NOTE: `node_key`/`old_node_key` are public key hex (see the field-level
/// `plain-string-secret` ignores below); `auth` is the only sensitive field
/// and its type ([`AuthInfo`]) already carries a manual, redacting `Debug`
/// impl that this derive calls into.
#[derive(Debug, Serialize)] // kanon:ignore RUST/no-debug-derive-on-public-types -- see NOTE
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

    /// Continuation URL for long-polling after the user visits the auth URL.
    /// Set to the `auth_url` from the initial [`RegisterResponse`].
    #[serde(rename = "Followup", skip_serializing_if = "Option::is_none")]
    pub followup: Option<String>,
}

/// Authentication information included in [`RegisterRequest`].
///
/// WARNING: `Debug` is implemented manually because `auth_key` is a credential.
/// A derived `Debug` puts it verbatim into anything that formats this type, or
/// the [`RegisterRequest`] that owns it — a log line, an error context, a panic
/// payload. The redaction mirrors the one on private key types in
/// [`crate::keys`].
#[derive(Serialize)]
pub struct AuthInfo {
    /// Pre-auth key value (e.g. `tskey-auth-...`).
    #[serde(rename = "AuthKey", skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<String>,
}

impl fmt::Debug for AuthInfo {
    /// WHY the presence is kept: whether a pre-auth key was supplied is the
    /// question worth debugging, and it is answerable without the value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthInfo")
            .field("auth_key", &self.auth_key.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Opaque identifier for correlating backend logs.
///
/// The control server treats this as an untyped correlation token: no format
/// is documented or enforced. The newtype exists to keep it from being mixed
/// with any other identifier field, not to validate its shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BackendLogId(String);

impl BackendLogId {
    /// Wrap a raw backend-log correlation string.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrow the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Host information describing this machine to the control server.
///
/// The control server uses this for display in the admin console and
/// for capability negotiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hostinfo {
    /// Opaque identifier for correlating backend logs.
    #[serde(rename = "BackendLogID")]
    pub backend_log_id: BackendLogId,

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
///
/// NOTE: `node_key`/`disco_key` are public key hex (see the field-level
/// `plain-string-secret` ignores below) — nothing here is an unredacted
/// secret.
#[derive(Debug, Serialize)] // kanon:ignore RUST/no-debug-derive-on-public-types -- see NOTE
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "PeerRemovalWire")]
#[non_exhaustive]
pub enum PeerRemoval {
    /// Server-assigned numeric node identifier.
    NodeId(i64),

    /// Node public key string, serialized as `"nodekey:hex..."`.
    NodeKey(String),
}

// WHY: variant names mirror the public PeerRemoval wire identifiers for serde symmetry.
#[expect(
    clippy::enum_variant_names,
    reason = "PeerRemovalWire variants mirror Tailscale control-protocol wire names"
)]
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
///
/// NOTE: `key`/`machine`/`disco_key` are public key hex, not secrets (see
/// the field-level `plain-string-secret` ignores below).
#[derive(Debug, Clone, Deserialize, Serialize)] // kanon:ignore RUST/no-debug-derive-on-public-types -- see NOTE
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

    /// Assigned IP addresses in CIDR notation (Tailscale CGNAT range, RFC 6598).
    ///
    /// WHY(#54) `default`: a node the control plane has not yet assigned
    /// addresses to — a freshly registered peer, or any Tailscale-compatible
    /// server that omits an empty list — sends no `Addresses` key at all.
    /// Without a default that omission is a missing-field error, and because
    /// peers are decoded as part of one `MapResponse`, a single address-less
    /// peer fails the whole map update. Absent and empty mean the same thing
    /// here, so they decode the same way.
    #[serde(rename = "Addresses", default)]
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
///
/// NOTE: `key`/`disco_key` are public key hex, not secrets (see the
/// field-level `plain-string-secret` ignores below).
#[derive(Debug, Clone, Deserialize, Serialize)] // kanon:ignore RUST/no-debug-derive-on-public-types -- see NOTE
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

    /// Opaque capability map until mitos has a typed capability model.
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
///
/// NOTE: this mirrors the wire protocol's `DNSConfig` (a server-sent
/// response type, not a local operator config file — `RUST/config-deny-unknown-fields`
/// targets the latter). Denying unknown fields here would make dictyon
/// reject a `MapResponse` outright the day a conforming server adds a new
/// DNS field, trading forward compatibility for a typo-catcher this type
/// does not need.
#[derive(Debug, Clone, Deserialize, Serialize)] // kanon:ignore RUST/config-deny-unknown-fields -- see NOTE
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
    /// Resolver address (e.g. `"1.1.1.1:53"` for a public DNS server, or the `MagicDNS` resolver).
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
//
// NOTE(RUST/file-too-long): split into a sibling file — types.rs + tests
// together exceeded the 800-line threshold.

#[cfg(test)]
mod tests;
