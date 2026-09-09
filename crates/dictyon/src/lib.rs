//! # Dictyon
//!
//! *δίκτυον - a net, a cast net, a thing woven to catch.*
//!
//! Peer-side client for the hamma mesh networking stack. It is building toward
//! Tailscale control-protocol interoperability with an upstream coordination
//! server. HTTP/2-over-Noise interoperability and authoritative effective-ACL
//! policy remain explicit gates before data-plane activation; see
//! `contracts/phase-a.toml` at the repository root.
//!
//! ## Status
//!
//! Noise IK handshake and key types implemented. TCP/TLS connection,
//! HTTP upgrade, Noise handshake completion, registration, and map
//! streaming implemented in [`wire`] and the async extension of [`control`].
//!
//! ## Scope
//!
//! - Gated peer data plane (not yet activated)
//! - Noise-framed control protocol client
//! - DERP relay client for NAT traversal fallback
//! - `MagicDNS` resolver
//! - Route / exit-node configuration
//!
//! Not implemented, by design: Taildrop, Tailscale SSH, Funnel, app
//! connectors. Those are opinionated product features of tailscale.com, not
//! part of hamma's mesh-networking target.

#![deny(missing_docs)]

/// Client version string advertised to the control plane as
/// `Hostinfo.GoVersion` (e.g. `"dictyon/0.3.0"`).
///
/// Derived from the crate version at build time so the advertised version
/// always matches the release -- never restate the version as a literal at
/// a call site.
pub const ADVERTISED_VERSION: &str = concat!("dictyon/", env!("CARGO_PKG_VERSION"));

pub mod control;
pub mod error;
pub mod noise;
pub mod transport;
pub mod wire;
