//! Behavioral configuration for the hamma stack.
//!
//! Every field in [`Config`] is a **tuning knob** - a value that a reasonable
//! operator (or an agent, via aletheia's parameter registry, forkwright/hamma#7)
//! might want to change without recompiling. Values documented here match the
//! current hard-coded defaults; changing the default here changes the default
//! everywhere.
//!
//! # What is NOT here
//!
//! Cryptographic invariants (key lengths, AEAD tag sizes, Noise handshake
//! parameters) and protocol-fixed constants (message type bytes, HTTP upgrade
//! path, wire-format version numbers) are **not** exposed as config. Changing
//! them is a protocol-break, not a tuning operation, so they remain `const`
//! next to the code that relies on their immutability.
//!
//! # Discoverability
//!
//! The doc-comment on each field is the agent-facing description. It should
//! explain:
//! 1. What the value controls,
//! 2. The unit (bytes, count, ms, …),
//! 3. A reasonable range,
//! 4. What symptom would motivate changing it.
//!
//! # Extensibility
//!
//! [`Config`] and its nested sub-configs are marked `#[non_exhaustive]` so
//! adding new knobs is not a breaking change. Construct instances through the
//! `Default` impl (and then mutate fields) or by using [`serde`] to load from
//! a file.

use serde::{Deserialize, Serialize};
use snafu::{Snafu, ensure};

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------
//
// Named constants so the defaults are inspectable from code and the comments
// double as the canonical rationale.

/// Default cap on HTTP response header block size (8 KiB).
///
/// Large enough for typical `GET /key` and `101 Switching Protocols`
/// responses, small enough to bound memory if the peer misbehaves.
pub const DEFAULT_MAX_HEADER_BYTES: usize = 8 * 1024;

/// Default cap on total `/key` response body size, expressed as a multiple
/// of the header cap. 4× the header cap accommodates large JSON responses
/// without permitting unbounded reads.
pub const DEFAULT_KEY_RESPONSE_BODY_MULTIPLIER: usize = 4;

/// Default initial capacity for the header-scan buffer (512 bytes).
///
/// A single-hint allocation; the buffer grows as needed up to the cap.
pub const DEFAULT_HEADER_READ_INITIAL_CAPACITY: usize = 512;

/// Default read chunk size when draining an HTTP response body (4 KiB).
///
/// Matches a common page size and plays well with TLS record sizes.
pub const DEFAULT_RESPONSE_READ_CHUNK_BYTES: usize = 4096;

/// Default cap on a single Noise transport frame payload (4 KiB plaintext).
///
/// This bounds the size of a control-protocol message; larger messages must
/// be split by the caller. Must not exceed `u16::MAX - TAG_LEN` because the
/// wire framing uses a `u16` length.
pub const DEFAULT_MAX_FRAME_PAYLOAD: usize = 4096;

/// Default scratch-buffer size for serialising/deserialising Noise handshake
/// messages (256 bytes).
///
/// An IK `msg1`/`msg2` is ≤ 96 bytes; 256 gives headroom for payload-bearing
/// handshakes without over-allocating.
pub const DEFAULT_HANDSHAKE_SCRATCH_BYTES: usize = 256;

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------
//
// NOTE: the **Range:** line on each field doc is the contract; these constants
// make it executable. Prose bounds that nothing enforces are how a persisted
// config comes to claim a value the code cannot honour.

/// Bytes the Noise AEAD tag adds to every transport frame.
///
/// WHY: `dictyon::noise` owns the tag itself - this crate owns only the bound
/// the tag imposes on configuration, because the bound must be checkable
/// without depending on `dictyon`. `dictyon::noise::tests` pins the two
/// together so they cannot drift apart silently.
const NOISE_FRAME_TAG_OVERHEAD: usize = 16;

/// Largest plaintext payload a `u16` Noise frame length can describe.
///
/// The frame header carries a `u16` covering plaintext plus AEAD tag, so the
/// plaintext ceiling is `u16::MAX - NOISE_FRAME_TAG_OVERHEAD`.
// kanon:ignore RUST/as-cast -- widening u16 -> usize, infallible by construction;
// `usize::from` is not callable in a const item on stable.
pub const MAX_FRAME_PAYLOAD_CEILING: usize = u16::MAX as usize - NOISE_FRAME_TAG_OVERHEAD;

/// Smallest Noise frame payload that leaves room for a control message.
pub const MIN_FRAME_PAYLOAD: usize = 256;

/// Inclusive bounds on [`NoiseConfig::handshake_scratch_bytes`].
const HANDSHAKE_SCRATCH_BOUNDS: (usize, usize) = (128, 4096);

/// Inclusive bounds on [`WireConfig::max_header_bytes`].
const MAX_HEADER_BYTES_BOUNDS: (usize, usize) = (1024, 65_536);

/// Inclusive bounds on [`WireConfig::key_response_body_multiplier`].
const KEY_RESPONSE_BODY_MULTIPLIER_BOUNDS: (usize, usize) = (1, 16);

/// Inclusive lower bound on [`WireConfig::header_read_initial_capacity`]; the
/// upper bound is `max_header_bytes`, so it is not a constant.
const HEADER_READ_INITIAL_CAPACITY_MIN: usize = 64;

/// Inclusive bounds on [`WireConfig::response_read_chunk_bytes`].
const RESPONSE_READ_CHUNK_BYTES_BOUNDS: (usize, usize) = (512, 65_536);

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced when a configuration value violates its documented range.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[non_exhaustive]
pub enum ConfigError {
    /// A tuning knob fell outside its documented inclusive range.
    #[snafu(display("{field} must be in [{min}, {max}], got {value}"))]
    OutOfRange {
        /// Name of the offending field, as written in [`Config`].
        field: &'static str,
        /// Inclusive lower bound.
        min: usize,
        /// Inclusive upper bound.
        max: usize,
        /// The rejected value.
        value: usize,
    },
}

/// Reject `value` unless it lies within the inclusive range `[min, max]`.
fn check_range(
    field: &'static str,
    value: usize,
    (min, max): (usize, usize),
) -> Result<(), ConfigError> {
    ensure!(
        (min..=max).contains(&value),
        OutOfRangeSnafu {
            field,
            min,
            max,
            value
        }
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// WireConfig
// ---------------------------------------------------------------------------

/// Tuning knobs for the wire layer (TCP/TLS/HTTP upgrade I/O).
///
/// Applies to [`dictyon::wire`](../../dictyon/wire/index.html) - the module
/// that owns raw socket I/O and the HTTP upgrade handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WireConfigFields", deny_unknown_fields)]
#[non_exhaustive]
pub struct WireConfig {
    /// Maximum HTTP response header block we will buffer, in bytes.
    ///
    /// **Controls:** memory bound for header parsing; attacker-resilience.
    /// **Range:** `[1024, 65_536]` - below 1 KiB breaks legitimate control
    /// servers; above 64 KiB is wasted memory per connection.
    /// **Default:** 8 KiB. Raise if a control server sends very large
    /// header blocks (e.g. many cookies); lower to harden against abuse.
    pub max_header_bytes: usize,

    /// Multiplier applied to `max_header_bytes` to cap the total
    /// `/key` endpoint response size.
    ///
    /// **Controls:** upper bound on untrusted JSON body size before parse.
    /// **Range:** `[1, 16]`.
    /// **Default:** 4 (= 32 KiB at default header cap). Raise only if a
    /// control server ships a very large key-discovery JSON body.
    pub key_response_body_multiplier: usize,

    /// Initial capacity hint for the header-scan buffer, in bytes.
    ///
    /// **Controls:** number of allocations during header read on small
    /// responses. Does not cap size - that is `max_header_bytes`.
    /// **Range:** `[64, max_header_bytes]`.
    /// **Default:** 512.
    pub header_read_initial_capacity: usize,

    /// Chunk size for reads while draining an HTTP response body, in bytes.
    ///
    /// **Controls:** syscall/read granularity while collecting body bytes.
    /// **Range:** `[512, 65_536]`.
    /// **Default:** 4 KiB. Increase for high-throughput links; decrease for
    /// memory-constrained environments.
    pub response_read_chunk_bytes: usize,
}

impl Default for WireConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            key_response_body_multiplier: DEFAULT_KEY_RESPONSE_BODY_MULTIPLIER,
            header_read_initial_capacity: DEFAULT_HEADER_READ_INITIAL_CAPACITY,
            response_read_chunk_bytes: DEFAULT_RESPONSE_READ_CHUNK_BYTES,
        }
    }
}

impl WireConfig {
    /// Return the maximum permitted `/key` response body size in bytes.
    ///
    /// Derived as `max_header_bytes * key_response_body_multiplier`.
    #[must_use]
    pub fn key_response_max_bytes(&self) -> usize {
        self.max_header_bytes
            .saturating_mul(self.key_response_body_multiplier)
    }

    /// Check every field against its documented range.
    ///
    /// Deserialization runs this automatically; call it directly after
    /// mutating a [`WireConfig`] built from [`Default`].
    ///
    /// # Errors
    ///
    /// [`ConfigError::OutOfRange`] naming the first field that violates its
    /// documented bounds.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range(
            "wire.max_header_bytes",
            self.max_header_bytes,
            MAX_HEADER_BYTES_BOUNDS,
        )?;
        check_range(
            "wire.key_response_body_multiplier",
            self.key_response_body_multiplier,
            KEY_RESPONSE_BODY_MULTIPLIER_BOUNDS,
        )?;
        // NOTE: the upper bound is cross-field - a scan buffer larger than the
        // cap it feeds is a config the reader can never honour.
        check_range(
            "wire.header_read_initial_capacity",
            self.header_read_initial_capacity,
            (HEADER_READ_INITIAL_CAPACITY_MIN, self.max_header_bytes),
        )?;
        check_range(
            "wire.response_read_chunk_bytes",
            self.response_read_chunk_bytes,
            RESPONSE_READ_CHUNK_BYTES_BOUNDS,
        )
    }
}

/// Deserialization mirror of [`WireConfig`].
///
/// WHY: serde cannot run a validator on a derived `Deserialize`, so the derive
/// lives here and the public type is reached through [`TryFrom`]. A field added
/// to [`WireConfig`] and not to this mirror is caught by
/// `config_roundtrips_through_json` - serialization emits it and
/// `deny_unknown_fields` here rejects it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConfigFields {
    max_header_bytes: usize,
    key_response_body_multiplier: usize,
    header_read_initial_capacity: usize,
    response_read_chunk_bytes: usize,
}

impl TryFrom<WireConfigFields> for WireConfig {
    type Error = ConfigError;

    fn try_from(fields: WireConfigFields) -> Result<Self, Self::Error> {
        let config = Self {
            max_header_bytes: fields.max_header_bytes,
            key_response_body_multiplier: fields.key_response_body_multiplier,
            header_read_initial_capacity: fields.header_read_initial_capacity,
            response_read_chunk_bytes: fields.response_read_chunk_bytes,
        };
        config.validate()?;
        Ok(config)
    }
}

// ---------------------------------------------------------------------------
// NoiseConfig
// ---------------------------------------------------------------------------

/// Tuning knobs for the Noise transport framing layer.
///
/// These are **framing** limits, not cryptographic parameters. The Noise
/// pattern, AEAD tag length, and message-type bytes are protocol invariants
/// and remain `const` inside `dictyon::noise`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "NoiseConfigFields", deny_unknown_fields)]
#[non_exhaustive]
pub struct NoiseConfig {
    /// Maximum plaintext payload per Noise transport frame, in bytes.
    ///
    /// **Controls:** largest single control-plane message that can be sent
    /// without caller-side chunking.
    /// **Range:** `[256, 65_519]` - the wire format uses a `u16` length;
    /// the 16-byte Poly1305 tag is added on top, so the absolute ceiling is
    /// `u16::MAX - 16 = 65_519`.
    /// **Default:** 4 KiB - matches the reference implementation and most
    /// control-plane message sizes.
    pub max_frame_payload: usize,

    /// Scratch buffer size for Noise IK handshake serialisation, in bytes.
    ///
    /// **Controls:** size of the temporary buffer passed to `snow` during
    /// `write_message`/`read_message`. Must be ≥ the largest handshake
    /// message (≤ 96 bytes for IK without payload).
    /// **Range:** `[128, 4096]`.
    /// **Default:** 256 - leaves headroom for payload-bearing IK variants.
    pub handshake_scratch_bytes: usize,
}

impl Default for NoiseConfig {
    fn default() -> Self {
        Self {
            max_frame_payload: DEFAULT_MAX_FRAME_PAYLOAD,
            handshake_scratch_bytes: DEFAULT_HANDSHAKE_SCRATCH_BYTES,
        }
    }
}

impl NoiseConfig {
    /// Check every field against its documented range.
    ///
    /// Deserialization runs this automatically; call it directly after
    /// mutating a [`NoiseConfig`] built from [`Default`].
    ///
    /// # Errors
    ///
    /// [`ConfigError::OutOfRange`] naming the first field that violates its
    /// documented bounds. `max_frame_payload` above
    /// [`MAX_FRAME_PAYLOAD_CEILING`] is the case that matters: the framing
    /// layer cannot describe such a frame, so every send would fail at
    /// runtime rather than at load.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_range(
            "noise.max_frame_payload",
            self.max_frame_payload,
            (MIN_FRAME_PAYLOAD, MAX_FRAME_PAYLOAD_CEILING),
        )?;
        check_range(
            "noise.handshake_scratch_bytes",
            self.handshake_scratch_bytes,
            HANDSHAKE_SCRATCH_BOUNDS,
        )
    }
}

/// Deserialization mirror of [`NoiseConfig`]; see [`WireConfigFields`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoiseConfigFields {
    max_frame_payload: usize,
    handshake_scratch_bytes: usize,
}

impl TryFrom<NoiseConfigFields> for NoiseConfig {
    type Error = ConfigError;

    fn try_from(fields: NoiseConfigFields) -> Result<Self, Self::Error> {
        let config = Self {
            max_frame_payload: fields.max_frame_payload,
            handshake_scratch_bytes: fields.handshake_scratch_bytes,
        };
        config.validate()?;
        Ok(config)
    }
}

// ---------------------------------------------------------------------------
// Top-level Config
// ---------------------------------------------------------------------------

/// Top-level hamma configuration - a flat, persistable snapshot of every
/// behavioral tuning knob across the stack.
///
/// Construct via [`Config::default`] and mutate individual fields, or load
/// from TOML/JSON through [`serde`]. All sub-configs are independently
/// defaulted so partial construction is always valid.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct Config {
    /// Wire-layer (TCP/TLS/HTTP) tuning knobs.
    pub wire: WireConfig,

    /// Noise transport framing knobs.
    pub noise: NoiseConfig,
}

impl Config {
    /// Construct a new [`Config`] with all defaults.
    ///
    /// Equivalent to [`Config::default`], provided for fluent call sites.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check every sub-config against its documented ranges.
    ///
    /// Deserialization runs this automatically; call it directly after
    /// mutating a [`Config`] built from [`Default`].
    ///
    /// # Errors
    ///
    /// [`ConfigError::OutOfRange`] naming the first offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.wire.validate()?;
        self.noise.validate()
    }
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
    fn default_values_match_documented_constants() {
        let c = Config::default();
        assert_eq!(c.wire.max_header_bytes, DEFAULT_MAX_HEADER_BYTES);
        assert_eq!(
            c.wire.key_response_body_multiplier,
            DEFAULT_KEY_RESPONSE_BODY_MULTIPLIER
        );
        assert_eq!(
            c.wire.header_read_initial_capacity,
            DEFAULT_HEADER_READ_INITIAL_CAPACITY
        );
        assert_eq!(
            c.wire.response_read_chunk_bytes,
            DEFAULT_RESPONSE_READ_CHUNK_BYTES
        );
        assert_eq!(c.noise.max_frame_payload, DEFAULT_MAX_FRAME_PAYLOAD);
        assert_eq!(
            c.noise.handshake_scratch_bytes,
            DEFAULT_HANDSHAKE_SCRATCH_BYTES
        );
    }

    #[test]
    fn key_response_max_bytes_is_derived() {
        let c = WireConfig::default();
        assert_eq!(
            c.key_response_max_bytes(),
            DEFAULT_MAX_HEADER_BYTES * DEFAULT_KEY_RESPONSE_BODY_MULTIPLIER
        );
    }

    #[test]
    fn key_response_max_bytes_saturates_on_overflow() {
        let c = WireConfig {
            max_header_bytes: usize::MAX,
            key_response_body_multiplier: 4,
            ..Default::default()
        };
        // Saturating multiplication must not panic.
        assert_eq!(c.key_response_max_bytes(), usize::MAX);
    }

    #[test]
    fn config_roundtrips_through_json() {
        let original = Config {
            wire: WireConfig {
                max_header_bytes: 16_384,
                key_response_body_multiplier: 2,
                header_read_initial_capacity: 1024,
                response_read_chunk_bytes: 8192,
            },
            noise: NoiseConfig {
                max_frame_payload: 8192,
                handshake_scratch_bytes: 512,
            },
        };
        let json = serde_json::to_string(&original).expect("serialise");
        let back: Config = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(original, back);
    }

    #[test]
    fn absent_sub_table_falls_back_to_default() {
        // NOTE: `#[serde(default)]` on `Config` defaults an absent *sub-table*
        // only. It does not reach inside a sub-table that is present - see
        // `present_sub_table_must_be_complete`.
        let partial = r#"{"wire": {"max_header_bytes": 2048,
            "key_response_body_multiplier": 4,
            "header_read_initial_capacity": 512,
            "response_read_chunk_bytes": 4096}}"#;
        let c: Config = serde_json::from_str(partial).expect("partial config");
        assert_eq!(c.wire.max_header_bytes, 2048);
        assert_eq!(c.noise, NoiseConfig::default());
    }

    #[test]
    fn present_sub_table_must_be_complete() {
        // WHY: this pins the half of the behaviour the old comment on
        // `absent_sub_table_falls_back_to_default` got wrong. Neither
        // `WireConfig` nor its fields carry `#[serde(default)]`, so a `wire`
        // table that omits a field is an error, not a defaulted value.
        let missing_field = r#"{"wire": {"max_header_bytes": 2048}}"#;
        let result: Result<Config, _> = serde_json::from_str(missing_field);
        assert!(
            result.is_err(),
            "a present sub-table missing a field must be rejected, not defaulted"
        );
    }

    #[test]
    fn config_rejects_unknown_fields() {
        // Guards against silently-ignored typos in persisted configs.
        let bad = r#"{"wire": {"max_header_bytes": 2048,
            "key_response_body_multiplier": 4,
            "header_read_initial_capacity": 512,
            "response_read_chunk_bytes": 4096,
            "unexpected": 1}}"#;
        let result: Result<Config, _> = serde_json::from_str(bad);
        assert!(result.is_err(), "unknown field must be rejected");
    }

    // -----------------------------------------------------------------------
    // Bounds
    // -----------------------------------------------------------------------

    /// Build a `Config` JSON document with one `noise.max_frame_payload` value.
    fn noise_json(max_frame_payload: usize) -> String {
        format!(
            r#"{{"noise": {{"max_frame_payload": {max_frame_payload},
                "handshake_scratch_bytes": 256}}}}"#
        )
    }

    #[test]
    fn defaults_validate() {
        assert!(
            Config::default().validate().is_ok(),
            "the shipped defaults must satisfy their own documented ranges"
        );
    }

    #[test]
    fn frame_payload_ceiling_leaves_room_for_the_tag() {
        assert_eq!(
            MAX_FRAME_PAYLOAD_CEILING + NOISE_FRAME_TAG_OVERHEAD,
            usize::from(u16::MAX),
            "a full frame must fit the u16 length field exactly"
        );
    }

    #[test]
    fn max_frame_payload_above_wire_ceiling_is_rejected() {
        // WHY(#55): the documented ceiling was prose only, so a config one byte
        // over it loaded clean and failed on every send instead of at load.
        let over = NoiseConfig {
            max_frame_payload: MAX_FRAME_PAYLOAD_CEILING + 1,
            handshake_scratch_bytes: DEFAULT_HANDSHAKE_SCRATCH_BYTES,
        };
        assert_eq!(
            over.validate(),
            Err(ConfigError::OutOfRange {
                field: "noise.max_frame_payload",
                min: MIN_FRAME_PAYLOAD,
                max: MAX_FRAME_PAYLOAD_CEILING,
                value: MAX_FRAME_PAYLOAD_CEILING + 1,
            })
        );
    }

    #[test]
    fn max_frame_payload_at_the_ceiling_is_accepted() {
        let at = NoiseConfig {
            max_frame_payload: MAX_FRAME_PAYLOAD_CEILING,
            handshake_scratch_bytes: DEFAULT_HANDSHAKE_SCRATCH_BYTES,
        };
        assert!(
            at.validate().is_ok(),
            "the ceiling itself must be a legal value"
        );
    }

    #[test]
    fn deserialization_enforces_bounds() {
        // WHY: validation reachable only through an explicit call is validation
        // nothing runs. The untrusted entry point is deserialization.
        let over: Result<Config, _> =
            serde_json::from_str(&noise_json(MAX_FRAME_PAYLOAD_CEILING + 1));
        assert!(over.is_err(), "out-of-range value must not deserialize");

        let at: Config = serde_json::from_str(&noise_json(MAX_FRAME_PAYLOAD_CEILING))
            .expect("the ceiling itself must deserialize");
        assert_eq!(at.noise.max_frame_payload, MAX_FRAME_PAYLOAD_CEILING);
    }

    #[test]
    fn out_of_range_error_names_the_field_and_bounds() {
        let err = NoiseConfig {
            max_frame_payload: DEFAULT_MAX_FRAME_PAYLOAD,
            handshake_scratch_bytes: 1,
        }
        .validate()
        .expect_err("1 is below the scratch-buffer floor");
        assert_eq!(
            err.to_string(),
            "noise.handshake_scratch_bytes must be in [128, 4096], got 1"
        );
    }

    #[test]
    fn wire_bounds_are_enforced_at_both_ends() {
        let below = WireConfig {
            max_header_bytes: MAX_HEADER_BYTES_BOUNDS.0 - 1,
            ..Default::default()
        };
        assert!(
            below.validate().is_err(),
            "max_header_bytes below the floor must be rejected"
        );

        let above = WireConfig {
            max_header_bytes: MAX_HEADER_BYTES_BOUNDS.1 + 1,
            ..Default::default()
        };
        assert!(
            above.validate().is_err(),
            "max_header_bytes above the ceiling must be rejected"
        );

        let multiplier = WireConfig {
            key_response_body_multiplier: KEY_RESPONSE_BODY_MULTIPLIER_BOUNDS.1 + 1,
            ..Default::default()
        };
        assert!(
            multiplier.validate().is_err(),
            "key_response_body_multiplier above its ceiling must be rejected"
        );

        let chunk = WireConfig {
            response_read_chunk_bytes: RESPONSE_READ_CHUNK_BYTES_BOUNDS.0 - 1,
            ..Default::default()
        };
        assert!(
            chunk.validate().is_err(),
            "response_read_chunk_bytes below its floor must be rejected"
        );
    }

    #[test]
    fn header_scan_buffer_may_not_exceed_the_cap_it_feeds() {
        // WHY: this bound is cross-field, so a per-field range check cannot see
        // it - the scan buffer is documented as `[64, max_header_bytes]`.
        let over = WireConfig {
            max_header_bytes: 2048,
            header_read_initial_capacity: 4096,
            ..Default::default()
        };
        assert_eq!(
            over.validate(),
            Err(ConfigError::OutOfRange {
                field: "wire.header_read_initial_capacity",
                min: HEADER_READ_INITIAL_CAPACITY_MIN,
                max: 2048,
                value: 4096,
            })
        );
    }

    #[test]
    fn saturating_overflow_config_is_now_rejected() {
        // WHY: `key_response_max_bytes_saturates_on_overflow` above documents
        // that the arithmetic saturates rather than panics. That remains true,
        // but such a config can no longer be loaded - the saturation guard is
        // the second line of defence, not the first.
        let absurd = WireConfig {
            max_header_bytes: usize::MAX,
            key_response_body_multiplier: 4,
            ..Default::default()
        };
        assert!(
            absurd.validate().is_err(),
            "a usize::MAX header cap must not survive validation"
        );
    }
}
