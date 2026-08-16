//! Control protocol client for the Tailscale control plane.
//!
//! Implements registration and map polling over an established
//! [`ControlConnection`]. The control client manages the node's identity,
//! sends registration and map requests, and maintains a local [`Netmap`]
//! by applying full and delta [`MapResponse`] updates.
//!
//! # Wire format
//!
//! Control plane messages are JSON, framed as `[4-byte LE size][payload]`.
//! Payloads may be zstd-compressed (indicated by `Compress: "zstd"` in the
//! request). Map response parsing accepts both compressed and uncompressed
//! payloads.
//!
//! # References
//!
//! - `control/controlclient/direct.go` in the Tailscale Go source
//! - `tailcfg/tailcfg.go` for type definitions

use std::collections::HashSet;

use mitos::capability::CAPABILITY_VERSION;
use mitos::keys::{DiscoPrivate, MachinePrivate, NodePrivate};
use mitos::types::{
    AuthInfo, BackendLogId, DerpMap, DnsConfig, Hostinfo, MapRequest, MapResponse, Node,
    PeerChange, PeerRemoval, RegisterRequest, RegisterResponse,
};
use snafu::Snafu;
use tracing::{debug, warn};

use crate::transport::ControlConnection;
use crate::wire::AsyncControlStream;

mod register;

use register::classify_register_response;
pub use register::{NonEmptyUrl, RegisterFault, RegisterOutcome};

/// Upper bound on the peers a netmap retains from a coordination server.
///
/// WHY: every peer-bearing field of a [`MapResponse`] is server-controlled and
/// unbounded on the wire, so a misbehaving or hostile server can grow
/// [`Netmap::peers`] without limit across a single connection. The cap sits far
/// above any realistic tailnet, so it is unreachable in normal operation and
/// only bounds the memory one connection can commit.
const MAX_PEERS: usize = 10_000;

/// Errors from control protocol operations.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ControlError {
    /// JSON serialization or deserialization failed.
    #[snafu(display("json error: {message}"))]
    Json {
        /// Description of the JSON error.
        message: String,
    },

    /// The transport layer returned an error.
    #[snafu(display("transport error: {source}"))]
    Transport {
        /// The underlying transport error.
        source: crate::transport::TransportError,
    },

    /// The response frame was malformed.
    #[snafu(display("malformed response: {message}"))]
    MalformedResponse {
        /// Description of the framing error.
        message: String,
    },

    /// A wire (TCP/TLS) I/O error.
    #[snafu(display("wire error: {source}"))]
    Wire {
        /// The underlying wire error.
        source: crate::wire::WireError,
    },

    /// The payload does not fit the control frame's 4-byte length prefix.
    #[snafu(display("payload of {len} bytes exceeds the u32 frame length prefix"))]
    PayloadTooLarge {
        /// Length of the payload that could not be framed.
        len: usize,
    },
}

impl From<crate::transport::TransportError> for ControlError {
    fn from(source: crate::transport::TransportError) -> Self {
        Self::Transport { source }
    }
}

impl From<serde_json::Error> for ControlError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json {
            message: err.to_string(),
        }
    }
}

impl From<crate::wire::WireError> for ControlError {
    fn from(source: crate::wire::WireError) -> Self {
        Self::Wire { source }
    }
}

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
    /// A missing self node falls back to a zero-value [`Node`]; missing
    /// peers default to an empty list.
    fn from_full_response(resp: MapResponse) -> Self {
        let self_node = resp.node.unwrap_or_else(|| Node {
            id: 0,
            stable_id: None,
            key: String::new(), // kanon:ignore RUST/plain-string-secret -- public key hex, not a secret
            machine: None,
            name: String::new(),
            cap: None,
            tags: None,
            addresses: Vec::new(),
            allowed_ips: None,
            endpoints: None,
            derp: None,
            disco_key: None,
            key_expiry: None,
            last_seen: None,
            online: None,
        });

        let mut peers = resp.peers.unwrap_or_default();
        cap_peers(&mut peers);

        Self {
            self_node,
            peers,
            dns_config: resp.dns_config,
            derp_map: resp.derp_map,
        }
    }

    /// Apply a delta [`MapResponse`] onto an already-initialized netmap.
    ///
    /// See [`ControlClient::apply_map_response`] for the merge semantics.
    fn apply_delta(&mut self, resp: MapResponse) {
        if let Some(node) = resp.node {
            self.self_node = node;
        }

        // Full peer replacement (if server sends full list again).
        if let Some(mut peers) = resp.peers {
            cap_peers(&mut peers);
            self.peers = peers;
        }

        // Incremental peer additions/changes.
        if let Some(changed) = resp.peers_changed {
            // WHY: counted rather than warned per peer, so a server sending a
            // large over-cap delta costs one log line instead of one per peer.
            let mut refused = 0usize;
            for changed_peer in changed {
                if let Some(existing) = self.peers.iter_mut().find(|p| p.key == changed_peer.key) {
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
            self.dns_config = Some(dns);
        }

        if let Some(derp) = resp.derp_map {
            self.derp_map = Some(derp);
        }
    }
}

/// Client for the Tailscale control protocol.
///
/// Wraps a [`ControlConnection`] and the node's identity keys. Provides
/// methods for registration, map polling, and netmap maintenance.
///
/// # Usage
///
/// ```ignore
/// let client = ControlClient::new(conn, machine_key, node_key, disco_key);
/// let reg_resp = client.register(None)?;
/// let map_resp = client.map_request()?;
/// client.apply_map_response(map_resp);
/// ```
pub struct ControlClient {
    #[expect(
        dead_code,
        reason = "transport reserved for synchronous API, not yet wired (#57)"
    )]
    transport: ControlConnection,
    #[expect(
        dead_code,
        reason = "machine_key reserved for future rotation logic (#57)"
    )]
    machine_key: MachinePrivate,
    node_key: NodePrivate,
    disco_key: DiscoPrivate,
    netmap: Option<Netmap>,
}

impl ControlClient {
    /// Create a new control client.
    ///
    /// The `transport` must already have completed the Noise handshake.
    /// The netmap starts empty and is populated by
    /// [`apply_map_response`](Self::apply_map_response).
    pub fn new(
        transport: ControlConnection,
        machine_key: MachinePrivate,
        node_key: NodePrivate,
        disco_key: DiscoPrivate,
    ) -> Self {
        Self {
            transport,
            machine_key,
            node_key,
            disco_key,
            netmap: None,
        }
    }

    /// Build a [`RegisterRequest`] and serialize it to JSON.
    ///
    /// This produces the JSON payload for `POST /machine/register`. The
    /// caller is responsible for framing and sending it over the
    /// transport.
    ///
    /// # Arguments
    ///
    /// * `auth_key` - Optional pre-auth key for headless registration.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Json`] if serialization fails.
    ///
    /// Time: O(n) — dominated by `serde_json::to_vec` over the request,
    /// where `n` is the serialized payload size.
    /// Space: O(n) — the returned buffer plus the intermediate
    /// [`RegisterRequest`].
    pub fn build_register_request(&self, auth_key: Option<&str>) -> Result<Vec<u8>, ControlError> {
        let req = RegisterRequest {
            version: CAPABILITY_VERSION.as_u64(),
            node_key: self.node_key.public_key().to_hex(),
            old_node_key: String::new(), // kanon:ignore RUST/plain-string-secret -- public key hex, not a secret
            auth: auth_key.map(AuthInfo::new),
            hostinfo: self.hostinfo(),
            followup: None,
        };

        let json = serde_json::to_vec(&req)?;
        Ok(json)
    }

    /// Register this node asynchronously using an [`AsyncControlStream`].
    ///
    /// Serializes a [`RegisterRequest`], sends it over the stream, and
    /// validates the response into a [`RegisterOutcome`] -- every field
    /// combination the server can send, including ones the protocol does
    /// not allow, lands in a variant of that type.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] on serialization, I/O, or a JSON payload
    /// that fails to parse. A syntactically valid response the protocol
    /// still rejects -- an explicit rejection, contradictory fields, an
    /// expired key -- is not an error here; it is a [`RegisterOutcome`]
    /// variant, because the request itself succeeded.
    pub async fn register(
        &mut self,
        stream: &mut AsyncControlStream,
        auth_key: Option<&str>,
    ) -> Result<RegisterOutcome, ControlError> {
        debug!(
            target: "dictyon::control",
            has_auth_key = auth_key.is_some(),
            "sending register request",
        );
        let payload = self.build_register_request(auth_key)?;
        let framed = frame_message(&payload)?;
        stream.send_message(&framed).await?;

        let raw = stream.recv_message().await?;
        let resp = parse_register_response(&raw)?;
        let outcome = classify_register_response(resp);
        log_register_outcome(&outcome);
        Ok(outcome)
    }

    /// Poll for registration completion after the user has visited the auth URL.
    ///
    /// Sends a new [`RegisterRequest`] with the `followup` field set to the
    /// URL returned in the initial response, and validates the response
    /// into a [`RegisterOutcome`] via the same rules [`Self::register`]
    /// uses -- a followup poll can be rejected or come back contradictory
    /// exactly as the initial request can.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] on serialization, I/O, or parse failure.
    pub async fn poll_registration(
        &mut self,
        stream: &mut AsyncControlStream,
        followup_url: &str,
    ) -> Result<RegisterOutcome, ControlError> {
        debug!(
            target: "dictyon::control",
            followup_url,
            "polling registration followup",
        );
        let req = RegisterRequest {
            version: CAPABILITY_VERSION.as_u64(),
            node_key: self.node_key.public_key().to_hex(),
            old_node_key: String::new(), // kanon:ignore RUST/plain-string-secret -- public key hex, not a secret
            auth: None,
            hostinfo: self.hostinfo(),
            followup: Some(followup_url.to_string()),
        };
        let payload = serde_json::to_vec(&req)?;
        let framed = frame_message(&payload)?;
        stream.send_message(&framed).await?;

        let raw = stream.recv_message().await?;
        let resp = parse_register_response(&raw)?;
        let outcome = classify_register_response(resp);
        log_register_outcome(&outcome);
        Ok(outcome)
    }

    /// Send the initial map request and start streaming map updates.
    ///
    /// Serializes a streaming [`MapRequest`] and sends it. Call
    /// [`recv_map_update`](Self::recv_map_update) in a loop to receive
    /// responses.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] on serialization or I/O failure.
    pub async fn start_map_stream(
        &mut self,
        stream: &mut AsyncControlStream,
    ) -> Result<(), ControlError> {
        debug!(
            target: "dictyon::control",
            "sending streaming map request",
        );
        let payload = self.build_map_request()?;
        let framed = frame_message(&payload)?;
        stream.send_message(&framed).await?;
        Ok(())
    }

    /// Receive one map update frame from the server and apply it.
    ///
    /// Returns `true` if the update was a keep-alive (no netmap change),
    /// `false` if the netmap was modified.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] on I/O or parse failure.
    pub async fn recv_map_update(
        &mut self,
        stream: &mut AsyncControlStream,
    ) -> Result<bool, ControlError> {
        let raw = stream.recv_message().await?;
        let resp = Self::parse_map_response(&raw)?;
        let is_keepalive = resp.keep_alive == Some(true);
        debug!(
            target: "dictyon::control",
            is_keepalive,
            "received map update",
        );
        self.apply_map_response(resp);
        Ok(is_keepalive)
    }

    /// Build a [`MapRequest`] and serialize it to JSON.
    ///
    /// This produces the JSON payload for `POST /machine/map`. The caller
    /// is responsible for framing and sending it over the transport.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::Json`] if serialization fails.
    pub fn build_map_request(&self) -> Result<Vec<u8>, ControlError> {
        let req = MapRequest {
            version: CAPABILITY_VERSION.as_u64(),
            compress: Some("zstd".to_string()),
            node_key: self.node_key.public_key().to_hex(),
            disco_key: self.disco_key.public_key().to_hex(),
            endpoints: Vec::new(),
            stream: true,
            omit_peers: false,
            hostinfo: self.hostinfo(),
        };

        let json = serde_json::to_vec(&req)?;
        Ok(json)
    }

    /// Parse a map response frame.
    ///
    /// The wire format is `[4-byte LE size][JSON payload]`. This method
    /// extracts and deserializes the JSON payload.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError::MalformedResponse`] if the frame is too
    /// short or the declared size exceeds the available data, or
    /// [`ControlError::Json`] if the payload is not valid JSON.
    pub fn parse_map_response(frame: &[u8]) -> Result<MapResponse, ControlError> {
        let header: &[u8; 4] = frame
            .get(..4)
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| ControlError::MalformedResponse {
                message: format!("frame too short: {} bytes, need at least 4", frame.len()),
            })?;

        let size = usize::try_from(u32::from_le_bytes(*header)).map_err(|_| {
            ControlError::MalformedResponse {
                message: "declared size exceeds usize::MAX".to_string(),
            }
        })?;

        let payload = frame
            .get(4..4 + size)
            .ok_or_else(|| ControlError::MalformedResponse {
                message: format!(
                    "frame declares {size} bytes but only {} available",
                    frame.len() - 4
                ),
            })?;

        let payload = decode_map_payload(payload)?;
        let resp: MapResponse = serde_json::from_slice(&payload)?;
        Ok(resp)
    }

    /// Apply a [`MapResponse`] to the local netmap.
    ///
    /// On the first response (when `netmap` is `None`), the full peer
    /// list and self node are set. On subsequent delta responses:
    ///
    /// - `peers_changed`: each changed/added peer replaces the existing
    ///   entry with the same key, or is appended if new.
    /// - `peers_changed_patch`: lightweight mutations are applied to known
    ///   peers with matching node IDs.
    /// - `peers_removed`: peers with matching node IDs or keys are removed.
    /// - `node`: updates the self node if present.
    /// - `dns_config` and `derp_map`: replace the previous values if
    ///   present.
    ///
    /// The retained peer list is bounded by [`MAX_PEERS`]: an over-cap list is
    /// truncated and additions past the cap are refused. Updates to peers
    /// already held still apply, since they do not grow the list.
    pub fn apply_map_response(&mut self, resp: MapResponse) {
        if resp.keep_alive == Some(true) {
            return;
        }

        match &mut self.netmap {
            None => self.netmap = Some(Netmap::from_full_response(resp)),
            Some(netmap) => netmap.apply_delta(resp),
        }
    }

    /// Returns a slice of the current peers, or an empty slice if the
    /// netmap has not been initialized.
    pub fn peers(&self) -> &[Node] {
        match &self.netmap {
            Some(netmap) => &netmap.peers,
            None => &[],
        }
    }

    /// Returns this node's own information, or `None` if the netmap has
    /// not been initialized.
    pub fn self_node(&self) -> Option<&Node> {
        self.netmap.as_ref().map(|nm| &nm.self_node)
    }

    /// Build the [`Hostinfo`] for requests.
    ///
    /// Takes `&self` because future versions will include machine-specific
    /// data (backend log ID, capability version).
    #[expect(
        clippy::unused_self,
        reason = "signature reserves &self for future machine-specific fields (backend log ID, capability version)"
    )]
    fn hostinfo(&self) -> Hostinfo {
        let hostname = gethostname();
        Hostinfo {
            backend_log_id: BackendLogId::new(String::new()),
            os: std::env::consts::OS.to_string(),
            hostname,
            go_version: "dictyon/0.1.0".to_string(),
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

    if let Some(endpoints) = change.endpoints.filter(|endpoints| !endpoints.is_empty()) {
        peer.endpoints = Some(endpoints);
    }

    if let Some(key) = change.key {
        peer.key = key;
    }

    if let Some(disco_key) = change.disco_key {
        peer.disco_key = Some(disco_key);
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

/// Returns the system hostname, falling back to `"unknown"`.
fn gethostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Frame a JSON payload as `[4B LE size][payload]` for the control wire format.
///
/// # Errors
///
/// Returns [`ControlError::PayloadTooLarge`] if the payload does not fit the
/// 4-byte length prefix. Clamping instead would write a length that disagrees
/// with the bytes that follow, desynchronising the peer's framing for the rest
/// of the connection.
fn frame_message(payload: &[u8]) -> Result<Vec<u8>, ControlError> {
    let size = frame_len(payload.len())?;
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&size.to_le_bytes());
    framed.extend_from_slice(payload);
    Ok(framed)
}

/// Narrow a payload length to the frame's 4-byte length prefix.
///
/// WHY: split out from [`frame_message`] so the rejection path is reachable in
/// a test - exercising it through `frame_message` would mean allocating a
/// payload larger than `u32::MAX`.
///
/// # Errors
///
/// Returns [`ControlError::PayloadTooLarge`] if `len` exceeds `u32::MAX`.
fn frame_len(len: usize) -> Result<u32, ControlError> {
    u32::try_from(len).map_err(|_| ControlError::PayloadTooLarge { len })
}

fn decode_map_payload(payload: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>, ControlError> {
    if !is_zstd_frame(payload) {
        return Ok(std::borrow::Cow::Borrowed(payload));
    }

    zstd::stream::decode_all(payload)
        .map(std::borrow::Cow::Owned)
        .map_err(|err| ControlError::MalformedResponse {
            message: format!("zstd decode failed: {err}"),
        })
}

fn is_zstd_frame(payload: &[u8]) -> bool {
    matches!(payload.get(..4), Some([0x28, 0xb5, 0x2f, 0xfd]))
}

/// Deserialize a [`RegisterResponse`] from raw (decrypted) bytes.
fn parse_register_response(raw: &[u8]) -> Result<RegisterResponse, ControlError> {
    serde_json::from_slice(raw).map_err(|e| ControlError::Json {
        message: e.to_string(),
    })
}

/// Log a validated [`RegisterOutcome`] at a level matching how much it
/// deserves operator attention.
///
/// WHY: [`RegisterOutcome::Rejected`], `RotateNodeKey`, and `Contradictory`
/// are exactly the shapes this issue exists to stop silently tolerating, so
/// they log at `warn` -- a caller polling in a loop should not need to
/// inspect every outcome to notice the control server is sending something
/// it shouldn't.
fn log_register_outcome(outcome: &RegisterOutcome) {
    match outcome {
        RegisterOutcome::Authorized(_) => {
            debug!(target: "dictyon::control", outcome = "authorized", "register authorized");
        }
        RegisterOutcome::NeedsAuth(url) => {
            debug!(
                target: "dictyon::control",
                outcome = "needs_auth",
                auth_url = %url,
                "register requires interactive auth",
            );
        }
        RegisterOutcome::RotateNodeKey => {
            warn!(target: "dictyon::control", outcome = "rotate_node_key", "server reports the node key has expired");
        }
        RegisterOutcome::Rejected { reason } => {
            warn!(target: "dictyon::control", outcome = "rejected", reason = %reason, "server rejected the registration request");
        }
        RegisterOutcome::Contradictory(fault) => {
            warn!(
                target: "dictyon::control",
                outcome = "contradictory",
                fault = ?fault,
                "server sent a registration response the protocol does not allow",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
