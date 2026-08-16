//! Domain validation for `POST /machine/register` responses.
//!
//! [`classify_register_response`] is the single point where a wire
//! [`RegisterResponse`] becomes a caller-facing [`RegisterOutcome`]. Every
//! reachable combination of `Error`, `NodeKeyExpired`, `MachineAuthorized`,
//! and `AuthURL` maps to exactly one variant, including combinations the
//! control server should never send. Nothing is inferred from a single
//! field in isolation, and nothing is silently coerced into a variant its
//! fields do not support.

use std::fmt;

use mitos::types::RegisterResponse;

/// Domain-validated outcome of a registration attempt.
///
/// Every [`RegisterResponse`] classifies into exactly one variant via
/// [`classify_register_response`]: there is no wire response this type
/// cannot represent, and no variant that tolerates a response shape it
/// should reject.
#[derive(Debug)]
#[non_exhaustive]
pub enum RegisterOutcome {
    /// The node is authorized. Carries the full response for callers that
    /// need node-key or other server-reported detail.
    Authorized(RegisterResponse),
    /// Interactive auth is required at a server-supplied, non-empty URL.
    NeedsAuth(NonEmptyUrl),
    /// The node key has expired; a fresh key must be registered before any
    /// authorization claim in this response can be trusted.
    RotateNodeKey,
    /// The server explicitly rejected the request.
    Rejected {
        /// The server-supplied rejection reason.
        reason: String,
    },
    /// The response combined fields in a way the protocol does not allow.
    /// See [`RegisterFault`] for which combination.
    Contradictory(RegisterFault),
}

/// The specific way a [`RegisterResponse`] failed to validate into a
/// non-contradictory [`RegisterOutcome`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegisterFault {
    /// `MachineAuthorized: true` alongside a non-empty `AuthURL`: the
    /// server cannot claim the node is authorized while also demanding
    /// interactive auth for it.
    AuthorizedWithPendingUrl,
    /// `MachineAuthorized: false` with no `AuthURL`, `Error`, or
    /// `NodeKeyExpired` set: the server declined to authorize the node
    /// without stating why or what the caller should do next.
    UnauthorizedWithoutExplanation,
}

/// An `AuthURL` value validated to be non-empty.
///
/// WHY: an empty `AuthURL` is not a URL the user can visit. The reference
/// server marshals "no URL" as `""` rather than omitting the field, so a
/// naive `Option<String>` check tolerates that case as if it were a real
/// URL. Wrapping the validated string keeps [`RegisterOutcome::NeedsAuth`]
/// from ever representing the empty-string case -- the type itself is the
/// proof the value was checked, and there is no public constructor, so a
/// [`NonEmptyUrl`] can only exist by having passed
/// [`classify_register_response`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonEmptyUrl(String);

impl NonEmptyUrl {
    /// Borrow the validated URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NonEmptyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validate a wire [`RegisterResponse`] into an exhaustive [`RegisterOutcome`].
///
/// Precedence, first match wins:
///
/// 1. A non-empty `Error` always rejects, regardless of the other fields --
///    an explicit rejection reason is never shadowed by a stray
///    `MachineAuthorized` or `AuthURL` value.
/// 2. `NodeKeyExpired` requires rotation before any authorization claim in
///    the same response can be trusted.
/// 3. Otherwise `MachineAuthorized` and a non-empty `AuthURL` combine:
///    authorized-with-no-url is [`RegisterOutcome::Authorized`],
///    unauthorized-with-a-url is [`RegisterOutcome::NeedsAuth`], and the two
///    remaining combinations -- authorized-with-a-url and
///    unauthorized-with-no-url -- are [`RegisterOutcome::Contradictory`].
///
/// A present but empty `Error` or `AuthURL` is treated as absent: the
/// reference control server marshals both as `""` rather than omitting
/// them, so an empty string carries no information distinct from the field
/// being unset.
pub(super) fn classify_register_response(resp: RegisterResponse) -> RegisterOutcome {
    if let Some(reason) = non_empty(resp.error.as_deref()) {
        return RegisterOutcome::Rejected {
            reason: reason.to_string(),
        };
    }

    if resp.node_key_expired {
        return RegisterOutcome::RotateNodeKey;
    }

    let url = non_empty(resp.auth_url.as_deref()).map(|url| NonEmptyUrl(url.to_string()));
    match (resp.machine_authorized, url) {
        (true, None) => RegisterOutcome::Authorized(resp),
        (true, Some(_)) => RegisterOutcome::Contradictory(RegisterFault::AuthorizedWithPendingUrl),
        (false, Some(url)) => RegisterOutcome::NeedsAuth(url),
        (false, None) => {
            RegisterOutcome::Contradictory(RegisterFault::UnauthorizedWithoutExplanation)
        }
    }
}

/// Returns `s` unless it is empty.
fn non_empty(s: Option<&str>) -> Option<&str> {
    s.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A [`RegisterResponse`] with every field at its "nothing set" value,
    /// so each test overrides only the fields its case is about.
    fn blank_response() -> RegisterResponse {
        RegisterResponse {
            auth_url: None,
            machine_authorized: false,
            node_key_expired: false,
            error: None,
        }
    }

    #[test]
    fn authorized_with_no_url_is_authorized() {
        let resp = RegisterResponse {
            machine_authorized: true,
            ..blank_response()
        };

        let outcome = classify_register_response(resp);

        assert!(
            matches!(outcome, RegisterOutcome::Authorized(_)),
            "expected Authorized, got {outcome:?}"
        );
    }

    /// WHY(#66): the empty-string `AuthURL` case is the exact shape a
    /// PascalCase Go server sends alongside `MachineAuthorized: true` --
    /// the field is present because the struct has no `omitempty` tag, not
    /// because interactive auth is actually needed. It must classify
    /// identically to the field being absent.
    #[test]
    fn authorized_with_empty_url_is_authorized_not_needs_auth() {
        let resp = RegisterResponse {
            machine_authorized: true,
            auth_url: Some(String::new()),
            ..blank_response()
        };

        let outcome = classify_register_response(resp);

        assert!(
            matches!(outcome, RegisterOutcome::Authorized(_)),
            "an empty AuthURL alongside MachineAuthorized:true must not become NeedsAuth, got {outcome:?}"
        );
    }

    #[test]
    fn unauthorized_with_url_needs_auth() {
        let resp = RegisterResponse {
            machine_authorized: false,
            auth_url: Some("https://login.tailscale.com/a/abc".to_string()),
            ..blank_response()
        };

        let outcome = classify_register_response(resp);

        match outcome {
            RegisterOutcome::NeedsAuth(url) => {
                assert_eq!(url.as_str(), "https://login.tailscale.com/a/abc");
            }
            other => panic!("expected NeedsAuth, got {other:?}"),
        }
    }

    /// WHY(#66): this used to discard the rejection and fall into the
    /// empty-URL auth flow. `Error` must win over `MachineAuthorized` and
    /// `AuthURL` unconditionally.
    #[test]
    fn error_rejects_even_with_empty_url_and_unauthorized() {
        let resp = RegisterResponse {
            machine_authorized: false,
            auth_url: Some(String::new()),
            error: Some("invalid auth key".to_string()),
            ..blank_response()
        };

        let outcome = classify_register_response(resp);

        match outcome {
            RegisterOutcome::Rejected { reason } => assert_eq!(reason, "invalid auth key"),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    /// Error takes precedence even over a claimed authorization -- a
    /// contradictory server should never have the "good" half of its
    /// response believed.
    #[test]
    fn error_rejects_even_when_machine_authorized_is_true() {
        let resp = RegisterResponse {
            machine_authorized: true,
            error: Some("account suspended".to_string()),
            ..blank_response()
        };

        let outcome = classify_register_response(resp);

        match outcome {
            RegisterOutcome::Rejected { reason } => assert_eq!(reason, "account suspended"),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    /// A present-but-empty `Error` carries no information, matching how the
    /// reference server marshals its zero value.
    #[test]
    fn empty_error_string_does_not_reject() {
        let resp = RegisterResponse {
            machine_authorized: true,
            error: Some(String::new()),
            ..blank_response()
        };

        let outcome = classify_register_response(resp);

        assert!(
            matches!(outcome, RegisterOutcome::Authorized(_)),
            "an empty Error string must not reject, got {outcome:?}"
        );
    }

    #[test]
    fn node_key_expired_requests_rotation() {
        let resp = RegisterResponse {
            node_key_expired: true,
            ..blank_response()
        };

        let outcome = classify_register_response(resp);

        assert!(
            matches!(outcome, RegisterOutcome::RotateNodeKey),
            "expected RotateNodeKey, got {outcome:?}"
        );
    }

    /// Rotation is required before an authorization claim in the same
    /// response can be trusted, so it takes precedence over
    /// `MachineAuthorized: true`.
    #[test]
    fn node_key_expired_wins_over_machine_authorized() {
        let resp = RegisterResponse {
            node_key_expired: true,
            machine_authorized: true,
            ..blank_response()
        };

        let outcome = classify_register_response(resp);

        assert!(
            matches!(outcome, RegisterOutcome::RotateNodeKey),
            "expected RotateNodeKey, got {outcome:?}"
        );
    }

    /// WHY(#66): this used to become `Authorized` by inferring success from
    /// an absent `AuthURL` alone, discarding `MachineAuthorized: false`.
    #[test]
    fn unauthorized_with_no_signal_is_contradictory_not_authorized() {
        let resp = blank_response();

        let outcome = classify_register_response(resp);

        assert!(
            matches!(
                outcome,
                RegisterOutcome::Contradictory(RegisterFault::UnauthorizedWithoutExplanation)
            ),
            "expected Contradictory(UnauthorizedWithoutExplanation), got {outcome:?}"
        );
    }

    /// A server cannot claim both "already authorized" and "here is a URL
    /// to authorize at" -- neither half of that claim should be believed
    /// silently.
    #[test]
    fn authorized_with_pending_url_is_contradictory() {
        let resp = RegisterResponse {
            machine_authorized: true,
            auth_url: Some("https://login.tailscale.com/a/abc".to_string()),
            ..blank_response()
        };

        let outcome = classify_register_response(resp);

        assert!(
            matches!(
                outcome,
                RegisterOutcome::Contradictory(RegisterFault::AuthorizedWithPendingUrl)
            ),
            "expected Contradictory(AuthorizedWithPendingUrl), got {outcome:?}"
        );
    }

    #[test]
    fn non_empty_url_display_matches_as_str() {
        let resp = RegisterResponse {
            machine_authorized: false,
            auth_url: Some("https://login.tailscale.com/a/xyz".to_string()),
            ..blank_response()
        };

        let RegisterOutcome::NeedsAuth(url) = classify_register_response(resp) else {
            panic!("expected NeedsAuth");
        };

        assert_eq!(url.to_string(), url.as_str());
    }
}
