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
//! request). This implementation handles uncompressed JSON; zstd support
//! is deferred.
//!
//! # References
//!
//! - `control/controlclient/direct.go` in the Tailscale Go source
//! - `tailcfg/tailcfg.go` for type definitions

use hamma_core::keys::{DiscoPrivate, MachinePrivate, NodePrivate};
use hamma_core::types::{
    AuthInfo, DerpMap, DnsConfig, Hostinfo, MapRequest, MapResponse, Node, RegisterRequest,
    RegisterResponse,
};
use snafu::Snafu;

use crate::transport::ControlConnection;
use crate::wire::AsyncControlStream;

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

/// Outcome of an async registration attempt.
///
/// When the machine already has a valid pre-auth key, the server
/// authorizes it immediately ([`RegisterOutcome::Authorized`]). Otherwise,
/// the user must visit an auth URL ([`RegisterOutcome::NeedsAuth`]).
#[non_exhaustive]
pub enum RegisterOutcome {
    /// The node was authorized; contains the server's registration response.
    Authorized(RegisterResponse),
    /// Interactive auth is required; the user must visit this URL.
    NeedsAuth {
        /// URL the user must visit to authorize this node.
        auth_url: String,
    },
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
        reason = "transport reserved for synchronous API, not yet wired"
    )]
    transport: ControlConnection,
    #[expect(dead_code, reason = "machine_key reserved for future rotation logic")]
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
    pub fn build_register_request(&self, auth_key: Option<&str>) -> Result<Vec<u8>, ControlError> {
        let req = RegisterRequest {
            node_key: self.node_key.public_key().to_hex(),
            old_node_key: String::new(), // kanon:ignore RUST/plain-string-secret -- public key hex, not a secret
            auth: auth_key.map(|k| AuthInfo {
                auth_key: Some(k.to_string()),
            }),
            hostinfo: self.hostinfo(),
            followup: None,
        };

        let json = serde_json::to_vec(&req)?;
        Ok(json)
    }

    /// Register this node asynchronously using an [`AsyncControlStream`].
    ///
    /// Serializes a [`RegisterRequest`], sends it over the stream, and parses
    /// the response. Returns either an authorized [`RegisterResponse`] or the
    /// auth URL the user must visit.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] on serialization, I/O, or parse failure.
    pub async fn register(
        &mut self,
        stream: &mut AsyncControlStream,
        auth_key: Option<&str>,
    ) -> Result<RegisterOutcome, ControlError> {
        let payload = self.build_register_request(auth_key)?;
        let framed = frame_message(&payload);
        stream.send_message(&framed).await?;

        let raw = stream.recv_message().await?;
        let resp = parse_register_response(&raw)?;

        if let Some(url) = resp.auth_url.clone() {
            Ok(RegisterOutcome::NeedsAuth { auth_url: url })
        } else {
            Ok(RegisterOutcome::Authorized(resp))
        }
    }

    /// Poll for registration completion after the user has visited the auth URL.
    ///
    /// Sends a new [`RegisterRequest`] with the `followup` field set to the
    /// URL returned in the initial response, and waits for authorization.
    ///
    /// # Errors
    ///
    /// Returns [`ControlError`] on serialization, I/O, or parse failure.
    pub async fn poll_registration(
        &mut self,
        stream: &mut AsyncControlStream,
        followup_url: &str,
    ) -> Result<RegisterResponse, ControlError> {
        let req = RegisterRequest {
            node_key: self.node_key.public_key().to_hex(),
            old_node_key: String::new(), // kanon:ignore RUST/plain-string-secret -- public key hex, not a secret
            auth: None,
            hostinfo: self.hostinfo(),
            followup: Some(followup_url.to_string()),
        };
        let payload = serde_json::to_vec(&req)?;
        let framed = frame_message(&payload);
        stream.send_message(&framed).await?;

        let raw = stream.recv_message().await?;
        parse_register_response(&raw)
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
        let payload = self.build_map_request()?;
        let framed = frame_message(&payload);
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
            version: 68,
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

        let resp: MapResponse = serde_json::from_slice(payload)?;
        Ok(resp)
    }

    /// Apply a [`MapResponse`] to the local netmap.
    ///
    /// On the first response (when `netmap` is `None`), the full peer
    /// list and self node are set. On subsequent delta responses:
    ///
    /// - `peers_changed`: each changed/added peer replaces the existing
    ///   entry with the same key, or is appended if new.
    /// - `peers_removed`: peers with matching keys are removed.
    /// - `node`: updates the self node if present.
    /// - `dns_config` and `derp_map`: replace the previous values if
    ///   present.
    pub fn apply_map_response(&mut self, resp: MapResponse) {
        if resp.keep_alive == Some(true) {
            return;
        }

        match &mut self.netmap {
            None => {
                // First response: full initialization.
                let self_node = resp.node.unwrap_or_else(|| Node {
                    id: 0,
                    key: String::new(), // kanon:ignore RUST/plain-string-secret -- public key hex, not a secret
                    name: String::new(),
                    addresses: Vec::new(),
                    allowed_ips: None,
                    endpoints: None,
                    derp: None,
                    disco_key: None,
                    online: None,
                });

                let peers = resp.peers.unwrap_or_default();

                self.netmap = Some(Netmap {
                    self_node,
                    peers,
                    dns_config: resp.dns_config,
                    derp_map: resp.derp_map,
                });
            }
            Some(netmap) => {
                // Delta update on existing netmap.
                if let Some(node) = resp.node {
                    netmap.self_node = node;
                }

                // Full peer replacement (if server sends full list again).
                if let Some(peers) = resp.peers {
                    netmap.peers = peers;
                }

                // Incremental peer additions/changes.
                if let Some(changed) = resp.peers_changed {
                    for changed_peer in changed {
                        if let Some(existing) =
                            netmap.peers.iter_mut().find(|p| p.key == changed_peer.key)
                        {
                            *existing = changed_peer;
                        } else {
                            netmap.peers.push(changed_peer);
                        }
                    }
                }

                // Peer removals.
                if let Some(removed_keys) = resp.peers_removed {
                    netmap.peers.retain(|p| !removed_keys.contains(&p.key));
                }

                if let Some(dns) = resp.dns_config {
                    netmap.dns_config = Some(dns);
                }

                if let Some(derp) = resp.derp_map {
                    netmap.derp_map = Some(derp);
                }
            }
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
            backend_log_id: String::new(),
            os: std::env::consts::OS.to_string(),
            hostname,
            go_version: "dictyon/0.1.0".to_string(),
        }
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
fn frame_message(payload: &[u8]) -> Vec<u8> {
    let size = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&size.to_le_bytes());
    framed.extend_from_slice(payload);
    framed
}

/// Deserialize a [`RegisterResponse`] from raw (decrypted) bytes.
fn parse_register_response(raw: &[u8]) -> Result<RegisterResponse, ControlError> {
    serde_json::from_slice(raw).map_err(|e| ControlError::Json {
        message: e.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
