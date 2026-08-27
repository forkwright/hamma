//! Single source of truth for the control-plane capability version.
//!
//! Wire-format invariant: every control-plane surface that names a protocol
//! or capability version -- the `/key` endpoint query parameter, the TS2021
//! initiation frame's 2-byte version field, the Noise prologue, and the
//! `Version` field on both `RegisterRequest` and `MapRequest` -- derives from
//! [`CAPABILITY_VERSION`]. A second, independently-declared version number
//! anywhere in the crate graph is the defect this module exists to make
//! impossible.
//!
//! Reference behavior: `control/controlclient/direct.go` builds the `/key`
//! URL as `fmt.Sprintf("%v/key?v=%d", serverURL, tailcfg.CurrentCapabilityVersion)`
//! and threads the same `tailcfg.CurrentCapabilityVersion` into the
//! `controlhttp.Dialer.ProtocolVersion` used for the TS2021 handshake, and
//! into `RegisterRequest.Version` / `MapRequest.Version`. One value, four
//! surfaces -- this module is that one value for hamma.

use std::fmt;

/// The control-plane capability version this client advertises.
///
/// WHY 71, not upstream-current: `tailcfg.CurrentCapabilityVersion` is a
/// moving target (well past 100 as of this writing) that gates features --
/// node attributes, DNS extensions, admin-console behaviors -- hamma does
/// not implement. Advertising it would be a false claim of support. 71 is
/// the value this client already spoke at its most-implemented call site
/// (the `/key` endpoint) before the three control-plane version numbers
/// were unified here; it is a compatibility target for the currently
/// implemented registration and map-stream prototype, not proof that every
/// upstream capability through 71 is implemented.
/// Bumping it is a protocol claim -- "hamma implements everything through
/// vN" -- not a tuning knob: pair any change with the feature that earns it.
pub const CAPABILITY_VERSION: CapabilityVersion = CapabilityVersion(71);

/// Typed wrapper for the control-plane capability version.
///
/// WHY a newtype instead of a bare `u16`: every construction site funnels
/// through [`CAPABILITY_VERSION`], so a wire-format consumer can only ever
/// name a version by importing that one constant -- there is no bare
/// integer literal for a second call site to invent independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityVersion(u16);

impl CapabilityVersion {
    /// Big-endian wire encoding for the TS2021 initiation frame's 2-byte
    /// version field.
    ///
    /// WARNING: the field is 2 bytes on the wire and MUST be big-endian
    /// (`control/controlbase/messages.go` in the Tailscale Go source writes
    /// it via `binary.BigEndian.PutUint16`). A little-endian encoding swaps
    /// the two bytes, so a conforming peer decodes a different capability
    /// version than the one this client believes it advertised -- the two
    /// sides then mix different prologues into the Noise handshake hash and
    /// the transcript cannot authenticate.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// Widened value for the JSON `Version` fields on `RegisterRequest` and
    /// `MapRequest`, which the control-plane wire format encodes as a bare
    /// JSON number with no fixed width.
    #[must_use]
    pub fn as_u64(self) -> u64 {
        u64::from(self.0)
    }
}

impl fmt::Display for CapabilityVersion {
    /// Decimal rendering for the `/key?v=N` query parameter and the Noise
    /// prologue string (`Tailscale Control Protocol v{N}`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned wire encoding -- if this ever fails, either
    /// [`CAPABILITY_VERSION`] changed (update the pin deliberately) or
    /// [`CapabilityVersion::to_be_bytes`] regressed to little-endian.
    #[test]
    fn capability_version_encodes_big_endian() {
        assert_eq!(CAPABILITY_VERSION.to_be_bytes(), [0x00, 0x47]);
    }

    #[test]
    fn capability_version_displays_as_decimal() {
        assert_eq!(CAPABILITY_VERSION.to_string(), "71");
    }

    #[test]
    fn capability_version_widens_to_u64_losslessly() {
        assert_eq!(CAPABILITY_VERSION.as_u64(), 71u64);
    }

    /// A big-endian encoding must not be interpretable as the little-endian
    /// encoding of a different, well-known-wrong value. Guards against a
    /// future change re-introducing a byte-order regression that happens to
    /// still equal the correct bytes by coincidence.
    #[test]
    fn big_endian_bytes_are_not_the_little_endian_encoding() {
        let be = CAPABILITY_VERSION.to_be_bytes();
        let misread_as_le = u16::from_le_bytes(be);
        assert_ne!(
            misread_as_le, 71,
            "0x00 0x47 must not also decode to 71 under the wrong byte order"
        );
    }
}
