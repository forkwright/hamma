//! Typed key wrappers for the Tailscale/WireGuard key hierarchy.
//!
//! All keys are Curve25519, 32 bytes. Each key type is a newtype that enforces
//! correct usage: private keys are non-cloneable and zeroized on drop, public
//! keys are freely cloneable and derive the standard traits.
//!
//! Serialization uses Tailscale's typed hex prefixes (`mkey:`, `nodekey:`,
//! `discokey:`, `privkey:`).

use core::fmt;

use snafu::Snafu;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when parsing or handling keys.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum KeyError {
    /// The key string is missing the expected prefix.
    #[snafu(display("key missing prefix '{prefix}': got '{input}'"))]
    MissingPrefix {
        /// The expected prefix.
        prefix: String,
        /// The leading bytes of the input, truncated to [`MAX_REPORTED_INPUT`].
        input: String,
    },

    /// The hex portion of the key has an odd number of digits.
    #[snafu(display("invalid hex in key: odd number of hex digits ({len})"))]
    OddHexLength {
        /// The digit count that could not be split into byte pairs.
        len: usize,
    },

    /// The hex portion of the key contains a character that is not a hex digit.
    #[snafu(display("invalid hex in key: invalid hex digit {digit:?} at offset {offset}"))]
    InvalidHexDigit {
        /// The offending character.
        digit: char,
        /// Its zero-based offset within the hex portion.
        offset: usize,
    },

    /// The decoded key is not the expected length.
    #[snafu(display("key length wrong: expected {expected}, got {actual}"))]
    WrongLength {
        /// Expected byte count.
        expected: usize,
        /// Actual byte count.
        actual: usize,
    },
}

/// Upper bound on how many characters of caller-supplied text a [`KeyError`]
/// retains.
///
/// WHY: `from_hex` is called with server-supplied strings, so the error value
/// must not clone an input of unbounded size. A well-formed key is a prefix of
/// at most nine characters plus `KEY_LEN * 2` hex digits, so this bound keeps
/// every legitimate input intact while capping a hostile one.
const MAX_REPORTED_INPUT: usize = 80;

/// Copy at most [`MAX_REPORTED_INPUT`] characters of `s` for use in an error.
fn truncate_for_report(s: &str) -> String {
    s.chars().take(MAX_REPORTED_INPUT).collect()
}

/// Length of all Curve25519 keys in bytes.
const KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Macro for reducing boilerplate across the three key pairs
// ---------------------------------------------------------------------------

macro_rules! key_pair {
    (
        private_name = $Priv:ident,
        public_name  = $Pub:ident,
        private_prefix = $priv_prefix:expr,
        public_prefix  = $pub_prefix:expr,
        doc_private    = $doc_priv:expr,
        doc_public     = $doc_pub:expr,
    ) => {
        #[doc = $doc_priv]
        pub struct $Priv([u8; KEY_LEN]);

        // Manual Debug: redact private key material.
        impl fmt::Debug for $Priv {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($Priv))
                    .field(&"[REDACTED]")
                    .finish()
            }
        }

        // Zeroize on drop for private keys.
        impl Drop for $Priv {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        impl ZeroizeOnDrop for $Priv {}

        impl $Priv {
            /// Generate a new random private key.
            #[must_use]
            pub fn generate() -> Self {
                let secret = StaticSecret::from(rand::random::<[u8; KEY_LEN]>());
                Self(secret.to_bytes())
            }

            /// Create a private key from raw bytes.
            #[must_use]
            pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw key bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }

            /// Derive the corresponding public key.
            #[must_use]
            pub fn public_key(&self) -> $Pub {
                let secret = StaticSecret::from(self.0);
                let public = PublicKey::from(&secret);
                $Pub(*public.as_bytes())
            }

            /// Serialize to hex with the Tailscale private-key prefix.
            #[must_use]
            pub fn to_hex(&self) -> String {
                let hex = hex_encode(&self.0);
                format!("{}{hex}", $priv_prefix)
            }
        }

        #[doc = $doc_pub]
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $Pub([u8; KEY_LEN]);

        impl fmt::Debug for $Pub {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($Pub))
                    .field(&self.to_hex())
                    .finish()
            }
        }

        impl $Pub {
            /// Create a public key from raw bytes.
            #[must_use]
            pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(bytes)
            }

            /// Borrow the raw key bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }

            /// Serialize to hex with the Tailscale public-key prefix.
            #[must_use]
            pub fn to_hex(&self) -> String {
                let hex = hex_encode(&self.0);
                format!("{}{hex}", $pub_prefix)
            }

            /// Parse from the Tailscale prefixed-hex format for this key type.
            ///
            /// The inverse of [`Self::to_hex`]. Used to validate the
            /// server-supplied key strings carried in control-plane JSON at
            /// the point they are read, rather than passing them on as text.
            ///
            /// # Errors
            ///
            /// Returns [`KeyError`] if the prefix is missing, the hex portion
            /// is malformed, or it does not decode to exactly 32 bytes.
            pub fn from_hex(s: &str) -> Result<Self, KeyError> {
                let hex = s
                    .strip_prefix($pub_prefix)
                    .ok_or_else(|| KeyError::MissingPrefix {
                        prefix: $pub_prefix.to_string(),
                        input: truncate_for_report(s),
                    })?;
                Ok(Self(hex_decode_exact(hex)?))
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Key pair definitions
// ---------------------------------------------------------------------------

key_pair! {
    private_name   = MachinePrivate,
    public_name    = MachinePublic,
    private_prefix = "privkey:",
    public_prefix  = "mkey:",
    doc_private    = "Machine identity private key -- persisted to disk, never rotates.\n\nUsed for the Noise IK handshake with the control server.",
    doc_public     = "Machine identity public key.\n\nSerialized with the `mkey:` prefix in the Tailscale protocol.",
}

key_pair! {
    private_name   = NodePrivate,
    public_name    = NodePublic,
    private_prefix = "privkey:",
    public_prefix  = "nodekey:",
    doc_private    = "Node identity private key -- `WireGuard` identity. Rotates on expiry.\n\nUsed for `WireGuard` tunnels and DERP communication.",
    doc_public     = "Node identity public key.\n\nSerialized with the `nodekey:` prefix in the Tailscale protocol.",
}

key_pair! {
    private_name   = DiscoPrivate,
    public_name    = DiscoPublic,
    private_prefix = "privkey:",
    public_prefix  = "discokey:",
    doc_private    = "Disco ephemeral private key -- regenerated per process.\n\nUsed for NAT traversal via the disco protocol.",
    doc_public     = "Disco ephemeral public key.\n\nSerialized with the `discokey:` prefix in the Tailscale protocol.",
}

// ---------------------------------------------------------------------------
// Hex encoding helper (avoids pulling in the `hex` crate for one function)
// ---------------------------------------------------------------------------

/// Lowercase hex digits, indexed by nibble value (0..=15).
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        // WHY not `write!`: formatting into a `String` cannot fail, which
        // left the previous `write!` + `let _ =` looking like a discarded
        // fallible result. A lookup table sidesteps the `Result` entirely
        // instead of asserting away an error that can never occur.
        let hi = HEX_DIGITS.get(usize::from(b >> 4)).unwrap_or(&b'0');
        let lo = HEX_DIGITS.get(usize::from(b & 0x0f)).unwrap_or(&b'0');
        s.push(char::from(*hi));
        s.push(char::from(*lo));
    }
    s
}

/// Decode `s` into exactly `N` bytes of hex.
///
/// WHY: the digit count is checked against `N` before anything is allocated,
/// so a server-supplied string cannot make the caller reserve memory
/// proportional to its own length before being rejected.
fn hex_decode_exact<const N: usize>(s: &str) -> Result<[u8; N], KeyError> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(KeyError::OddHexLength { len: s.len() });
    }
    if pairs.len() != N {
        return Err(KeyError::WrongLength {
            expected: N,
            actual: pairs.len(),
        });
    }

    let mut out = [0u8; N];
    for (index, (byte, &[hi_digit, lo_digit])) in out.iter_mut().zip(pairs).enumerate() {
        let hi = hex_nibble(hi_digit, index * 2)?;
        let lo = hex_nibble(lo_digit, (index * 2) + 1)?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8, offset: usize) -> Result<u8, KeyError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(KeyError::InvalidHexDigit {
            digit: b as char,
            offset,
        }),
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
    fn generate_machine_key_produces_32_bytes() {
        let key = MachinePrivate::generate();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn public_key_derivation_is_deterministic() {
        let priv_key = MachinePrivate::generate();
        let pub1 = priv_key.public_key();
        let pub2 = priv_key.public_key();
        assert_eq!(pub1, pub2);
    }

    #[test]
    fn private_key_debug_redacts() {
        let key = MachinePrivate::generate();
        let debug = format!("{key:?}");
        assert!(
            debug.contains("[REDACTED]"),
            "debug output should redact key material: {debug}"
        );
        // The output should be like `MachinePrivate("[REDACTED]")` --
        // no raw hex bytes or byte arrays leaked.
        assert!(
            !debug.contains("0x"),
            "debug output should not contain raw hex: {debug}"
        );
    }

    #[test]
    fn from_bytes_round_trips() {
        let original = MachinePrivate::generate();
        let bytes = *original.as_bytes();
        let restored = MachinePrivate::from_bytes(bytes);
        assert_eq!(original.as_bytes(), restored.as_bytes());

        let pub_original = original.public_key();
        let pub_bytes = *pub_original.as_bytes();
        let pub_restored = MachinePublic::from_bytes(pub_bytes);
        assert_eq!(pub_original, pub_restored);
    }

    #[test]
    fn to_hex_includes_prefix() {
        let priv_key = MachinePrivate::generate();
        let pub_key = priv_key.public_key();

        let priv_hex = priv_key.to_hex();
        assert!(priv_hex.starts_with("privkey:"), "private hex: {priv_hex}");
        // prefix + 64 hex chars
        assert_eq!(priv_hex.len(), "privkey:".len() + 64);

        let pub_hex = pub_key.to_hex();
        assert!(pub_hex.starts_with("mkey:"), "public hex: {pub_hex}");
        assert_eq!(pub_hex.len(), "mkey:".len() + 64);

        // Node key prefix
        let node_priv = NodePrivate::generate();
        let node_pub = node_priv.public_key();
        assert!(node_pub.to_hex().starts_with("nodekey:"));

        // Disco key prefix
        let disco_priv = DiscoPrivate::generate();
        let disco_pub = disco_priv.public_key();
        assert!(disco_pub.to_hex().starts_with("discokey:"));
    }

    #[test]
    fn different_keys_produce_different_public_keys() {
        let key1 = MachinePrivate::generate();
        let key2 = MachinePrivate::generate();
        assert_ne!(key1.public_key(), key2.public_key());
    }

    #[test]
    fn node_key_round_trips() {
        let priv_key = NodePrivate::generate();
        let bytes = *priv_key.as_bytes();
        let restored = NodePrivate::from_bytes(bytes);
        assert_eq!(priv_key.public_key(), restored.public_key());
    }

    #[test]
    fn disco_key_round_trips() {
        let priv_key = DiscoPrivate::generate();
        let bytes = *priv_key.as_bytes();
        let restored = DiscoPrivate::from_bytes(bytes);
        assert_eq!(priv_key.public_key(), restored.public_key());
    }

    // -----------------------------------------------------------------------
    // Parsing: prefix, digit and length rejection
    // -----------------------------------------------------------------------

    #[test]
    fn wrong_length_is_rejected_before_any_digit_is_examined() {
        // A long run of non-hex digits at a length that cannot be a key. The
        // length verdict must win, which is only true if the count is checked
        // before the decode loop runs.
        let input = format!("mkey:{}", "zz".repeat(1000));
        let err = MachinePublic::from_hex(&input).expect_err("wrong length rejected");
        assert!(
            matches!(
                err,
                KeyError::WrongLength {
                    expected: KEY_LEN,
                    actual: 1000
                }
            ),
            "expected a length verdict, got {err:?}"
        );
    }

    #[test]
    fn missing_prefix_error_bounds_the_input_it_retains() {
        let input = format!("bogus:{}", "a".repeat(10_000));
        let err = MachinePublic::from_hex(&input).expect_err("bad prefix rejected");
        let KeyError::MissingPrefix { input: kept, .. } = err else {
            panic!("expected MissingPrefix, got {err:?}");
        };
        assert_eq!(
            kept.chars().count(),
            MAX_REPORTED_INPUT,
            "error retained {} chars of a 10006-char input",
            kept.chars().count()
        );
    }

    #[test]
    fn invalid_hex_digit_reports_the_character_and_its_offset() {
        let input = format!("mkey:{}0z", "0".repeat(62));
        let err = MachinePublic::from_hex(&input).expect_err("bad digit rejected");
        assert!(
            matches!(
                err,
                KeyError::InvalidHexDigit {
                    digit: 'z',
                    offset: 63
                }
            ),
            "expected a located digit error, got {err:?}"
        );
    }

    #[test]
    fn odd_digit_count_is_its_own_variant() {
        let err = MachinePublic::from_hex("mkey:abc").expect_err("odd length rejected");
        assert!(
            matches!(err, KeyError::OddHexLength { len: 3 }),
            "expected an odd-length verdict, got {err:?}"
        );
    }

    #[test]
    fn every_public_key_type_parses_its_own_prefixed_hex() {
        let machine = MachinePrivate::generate().public_key();
        let node = NodePrivate::generate().public_key();
        let disco = DiscoPrivate::generate().public_key();

        assert_eq!(
            MachinePublic::from_hex(&machine.to_hex()).expect("mkey round-trip"),
            machine
        );
        assert_eq!(
            NodePublic::from_hex(&node.to_hex()).expect("nodekey round-trip"),
            node
        );
        assert_eq!(
            DiscoPublic::from_hex(&disco.to_hex()).expect("discokey round-trip"),
            disco
        );
    }

    #[test]
    fn a_public_key_type_rejects_another_types_prefix() {
        let node_hex = NodePrivate::generate().public_key().to_hex();

        let err = DiscoPublic::from_hex(&node_hex).expect_err("nodekey is not a discokey");
        assert!(
            matches!(err, KeyError::MissingPrefix { ref prefix, .. } if prefix == "discokey:"),
            "expected a discokey prefix demand, got {err:?}"
        );

        let err = MachinePublic::from_hex(&node_hex).expect_err("nodekey is not an mkey");
        assert!(
            matches!(err, KeyError::MissingPrefix { ref prefix, .. } if prefix == "mkey:"),
            "expected an mkey prefix demand, got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Property tests
    // -----------------------------------------------------------------------

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Any 32-byte value round-trips through `MachinePublic` hex serialization.
        #[test]
        fn machine_key_hex_round_trips(bytes in proptest::array::uniform32(0u8..=255)) {
            let key = MachinePublic::from_bytes(bytes);
            let hex = key.to_hex();
            let recovered = MachinePublic::from_hex(&hex)
                .expect("from_hex should succeed for a key we just serialized");
            assert_eq!(key, recovered);
        }

        /// The hex representation always has the expected length and prefix.
        #[test]
        fn machine_key_hex_has_correct_format(bytes in proptest::array::uniform32(0u8..=255)) {
            let key = MachinePublic::from_bytes(bytes);
            let hex = key.to_hex();
            assert!(hex.starts_with("mkey:"), "hex should start with mkey: prefix");
            // "mkey:" (5 chars) + 64 hex chars for 32 bytes
            assert_eq!(hex.len(), 5 + 64);
        }
    }
}
