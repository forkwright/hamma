//! Unit tests for [`super::Config`] and its sub-configs.
//!
//! Split into a sibling file because config.rs + tests exceeded the
//! `RUST/file-too-long` threshold.

#![expect(
    clippy::expect_used,
    reason = "tests use expect() for invariants that must hold"
)]

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
            connect_timeout_ms: 30_000,
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
fn connect_timeout_is_some_by_default() {
    assert_eq!(
        WireConfig::default().connect_timeout(),
        Some(Duration::from_millis(DEFAULT_CONNECT_TIMEOUT_MS))
    );
}

#[test]
fn connect_timeout_zero_disables_the_deadline() {
    let c = WireConfig {
        connect_timeout_ms: 0,
        ..Default::default()
    };
    // A zero-length timeout would fail every dial instantly, so zero must
    // mean "no deadline" rather than "expire immediately".
    assert_eq!(c.connect_timeout(), None);
}

#[test]
fn wire_table_written_before_the_timeout_field_still_loads() {
    // A `wire` table persisted before #52 has no `connect_timeout_ms`.
    // With `deny_unknown_fields` and no serde default it would be
    // rejected outright.
    let pre_52 = r#"{"wire": {"max_header_bytes": 2048,
        "key_response_body_multiplier": 4,
        "header_read_initial_capacity": 512,
        "response_read_chunk_bytes": 4096}}"#;
    let c: Config = serde_json::from_str(pre_52).expect("pre-#52 config must still parse");
    assert_eq!(c.wire.connect_timeout_ms, DEFAULT_CONNECT_TIMEOUT_MS);
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
    let over: Result<Config, _> = serde_json::from_str(&noise_json(MAX_FRAME_PAYLOAD_CEILING + 1));
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

#[test]
fn connect_timeout_ms_bounds_are_enforced_at_both_ends() {
    // WHY(#55): `check_connect_timeout_ms` is wired into `WireConfig::validate`
    // but nothing asserted on it - the range could regress silently.
    let (min, max) = CONNECT_TIMEOUT_MS_BOUNDS;
    let min_usize = usize::try_from(min).expect("bound fits usize");
    let max_usize = usize::try_from(max).expect("bound fits usize");

    let below = WireConfig {
        connect_timeout_ms: min - 1,
        ..Default::default()
    };
    assert_eq!(
        below.validate(),
        Err(ConfigError::OutOfRange {
            field: "wire.connect_timeout_ms",
            min: min_usize,
            max: max_usize,
            value: min_usize - 1,
        })
    );

    let above = WireConfig {
        connect_timeout_ms: max + 1,
        ..Default::default()
    };
    assert_eq!(
        above.validate(),
        Err(ConfigError::OutOfRange {
            field: "wire.connect_timeout_ms",
            min: min_usize,
            max: max_usize,
            value: max_usize + 1,
        })
    );
}

#[test]
fn connect_timeout_ms_at_the_bounds_is_accepted() {
    let (min, max) = CONNECT_TIMEOUT_MS_BOUNDS;

    let at_min = WireConfig {
        connect_timeout_ms: min,
        ..Default::default()
    };
    assert!(
        at_min.validate().is_ok(),
        "the floor itself must be a legal value"
    );

    let at_max = WireConfig {
        connect_timeout_ms: max,
        ..Default::default()
    };
    assert!(
        at_max.validate().is_ok(),
        "the ceiling itself must be a legal value"
    );
}

#[test]
fn connect_timeout_ms_zero_is_admissible_as_the_disabled_sentinel() {
    // `0` is not "below the floor" - it selects the disabled-deadline path
    // in `WireConfig::connect_timeout` and is deliberately excluded from
    // `CONNECT_TIMEOUT_MS_BOUNDS`, so validation must accept it.
    let disabled = WireConfig {
        connect_timeout_ms: 0,
        ..Default::default()
    };
    assert!(
        disabled.validate().is_ok(),
        "0 selects the disabled-deadline sentinel, not a value in the range"
    );
}
