//! # Hamma Core
//!
//! Shared types for the hamma mesh networking stack. Consumed by `dictyon`
//! (client) and, eventually, `histos` (coordination server). Holds the
//! cross-crate vocabulary: `WireGuard` key wrappers, peer identity types,
//! behavioral configuration, and protocol constants. Noise framing lives in
//! `dictyon`; effective-ACL policy is gated (see `contracts/phase-a.toml`).
//!
//! This crate has no network I/O and minimal dependencies. It must compile
//! fast and stay boring - types, not behavior.

#![deny(missing_docs)]

pub mod capability;
pub mod config;
pub mod keys;
pub mod types;

pub use capability::CAPABILITY_VERSION;
pub use config::Config;
