//! Top-level error type for the dictyon crate.
//!
//! [`DictyonError`] is a unified error that wraps all sub-layer errors:
//! wire I/O errors, control-protocol errors, Noise handshake errors, and
//! control-connection transport errors. It is the error type returned by the
//! public async API: [`crate::wire::connect`] and the
//! [`crate::control::ControlClient`] register/map streaming entry points.
//!
//! Callers driving the connect/register/map flow match on [`DictyonError`].
//! The layer-specific error types stay public for callers that use the
//! lower-level modules ([`crate::wire`], [`crate::control`],
//! [`crate::noise`], [`crate::transport`]) directly.

use snafu::Snafu;

use crate::control::ControlError;
use crate::noise::NoiseError;
use crate::transport::TransportError;
use crate::wire::WireError;

/// Unified error for all dictyon operations.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum DictyonError {
    /// A wire-layer I/O or TLS error.
    #[snafu(display("wire error: {source}"))]
    Wire {
        /// The underlying wire error.
        source: WireError,
    },

    /// A control-protocol error.
    #[snafu(display("control error: {source}"))]
    Control {
        /// The underlying control error.
        source: ControlError,
    },

    /// A Noise handshake or transport error.
    #[snafu(display("noise error: {source}"))]
    Noise {
        /// The underlying noise error.
        source: NoiseError,
    },

    /// A control-connection transport error.
    #[snafu(display("transport error: {source}"))]
    Transport {
        /// The underlying transport error.
        source: TransportError,
    },
}

impl From<WireError> for DictyonError {
    fn from(source: WireError) -> Self {
        Self::Wire { source }
    }
}

impl From<ControlError> for DictyonError {
    fn from(source: ControlError) -> Self {
        Self::Control { source }
    }
}

impl From<NoiseError> for DictyonError {
    fn from(source: NoiseError) -> Self {
        Self::Noise { source }
    }
}

impl From<TransportError> for DictyonError {
    fn from(source: TransportError) -> Self {
        Self::Transport { source }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every layer error reachable through the public async API lands in its
    /// own [`DictyonError`] variant, so a caller matching the facade sees
    /// exactly one variant per layer.
    #[test]
    fn each_layer_error_converts_into_its_own_variant() {
        let wire = DictyonError::from(WireError::InvalidUrl {
            url: "http://insecure".to_string(),
        });
        assert!(matches!(wire, DictyonError::Wire { .. }));

        let control = DictyonError::from(ControlError::PayloadTooLarge { len: 1 });
        assert!(matches!(control, DictyonError::Control { .. }));

        let noise = DictyonError::from(NoiseError::InvalidState {
            message: "handshake incomplete".to_string(),
        });
        assert!(matches!(noise, DictyonError::Noise { .. }));

        let transport = DictyonError::from(TransportError::InvalidUrl { url: String::new() });
        assert!(matches!(transport, DictyonError::Transport { .. }));
    }

    /// The facade's `Display` prefixes each layer so logs name the failing
    /// layer without a downcast.
    #[test]
    fn display_names_the_failing_layer() {
        let err = DictyonError::from(ControlError::Json {
            message: "unexpected eof".to_string(),
        });
        assert_eq!(err.to_string(), "control error: json error: unexpected eof");
    }

    /// The crate-root re-export and the module path name the same type, so
    /// `dictyon::DictyonError` is usable as the documented facade.
    #[test]
    fn crate_root_reexport_is_the_same_type() {
        fn accepts_reexport(_: crate::DictyonError) {}
        accepts_reexport(DictyonError::from(NoiseError::InvalidState {
            message: "handshake incomplete".to_string(),
        }));
    }
}
