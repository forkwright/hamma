//! Validation for server-supplied identity and routing-data fields.
//!
//! `mitos::types` deliberately keeps its wire DTOs unvalidated -- see the
//! module-level NOTE on [`mitos::types::RegisterResponse`], which states the
//! rule for the whole crate: rejecting a malformed field is "the consuming
//! client's job". [`register::classify_register_response`](super::register)
//! is that job for a register response; this module is the same job for the
//! key-hex and routing-data fields a [`MapResponse`](mitos::types::MapResponse)
//! carries on every [`Node`] and [`DnsResolver`] -- the single point where
//! those fields are checked before entering the local
//! [`Netmap`](super::Netmap).

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use mitos::keys::{DiscoPublic, MachinePublic, NodePublic};
use mitos::types::{DnsResolver, Node};

/// Whether every key-hex and routing-data field on `node` is well-formed.
///
/// A [`Node`] fails validation if any of the following does not parse:
/// `key` as [`NodePublic`]; `machine`, if present, as [`MachinePublic`];
/// `disco_key`, if present, as [`DiscoPublic`]; every `addresses` and
/// `allowed_ips` entry as a CIDR (see [`is_valid_cidr`]); every `endpoints`
/// entry as an `ip:port` socket address.
pub(super) fn node_is_valid(node: &Node) -> bool {
    is_valid_node_key(&node.key)
        && node
            .machine
            .as_deref()
            .is_none_or(|k| MachinePublic::from_hex(k).is_ok())
        && node.disco_key.as_deref().is_none_or(is_valid_disco_key)
        && node.addresses.iter().all(|a| is_valid_cidr(a))
        && node
            .allowed_ips
            .as_deref()
            .is_none_or(|ips| ips.iter().all(|a| is_valid_cidr(a)))
        && node.endpoints.as_deref().is_none_or(endpoints_are_valid)
}

/// Whether `s` parses as [`NodePublic`] hex.
pub(super) fn is_valid_node_key(s: &str) -> bool {
    NodePublic::from_hex(s).is_ok()
}

/// Whether `s` parses as [`DiscoPublic`] hex.
pub(super) fn is_valid_disco_key(s: &str) -> bool {
    DiscoPublic::from_hex(s).is_ok()
}

/// Whether every entry in `endpoints` is a valid `ip:port` socket address.
pub(super) fn endpoints_are_valid(endpoints: &[String]) -> bool {
    endpoints.iter().all(|e| SocketAddr::from_str(e).is_ok())
}

/// Whether `s` is a valid CIDR string: an IP address, `/`, and a prefix
/// length within the address family's bit width.
///
/// `std` has no CIDR parser, so this is hand-rolled rather than pulling in a
/// dependency for one check: split on the first `/`, parse the address half
/// with [`IpAddr::from_str`], and bound the prefix half by the address
/// family's bit width (32 for IPv4, 128 for IPv6). Splitting on the first
/// `/` rather than the last is safe here because neither a valid `IpAddr`
/// nor a valid `u8` prefix can itself contain a `/`, so a second `/`
/// anywhere in `s` always lands in the prefix half and fails
/// `prefix.parse::<u8>()` -- it cannot relocate into the address half and
/// produce a false accept.
fn is_valid_cidr(s: &str) -> bool {
    let Some((addr, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(addr) = IpAddr::from_str(addr) else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    let max_prefix = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    prefix <= max_prefix
}

/// Whether `resolver.addr` is a valid resolver address: a bare IP, or
/// `ip:port`.
pub(super) fn dns_resolver_is_valid(resolver: &DnsResolver) -> bool {
    IpAddr::from_str(&resolver.addr).is_ok() || SocketAddr::from_str(&resolver.addr).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_node() -> Node {
        Node {
            id: 1,
            stable_id: None,
            key: "nodekey:1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            machine: None,
            name: "n.ts.net.".to_string(),
            cap: None,
            tags: None,
            addresses: vec!["100.64.0.1/32".to_string()],
            allowed_ips: None,
            endpoints: None,
            derp: None,
            disco_key: None,
            key_expiry: None,
            last_seen: None,
            online: None,
        }
    }

    #[test]
    fn valid_node_passes() {
        assert!(node_is_valid(&valid_node()));
    }

    // WHY(negative fixture, issue #55): this is the check that would have
    // let a malformed `key` field reach the netmap silently. Watched
    // failing before the fix existed (the check was `true` unconditionally,
    // i.e. `node_is_valid` did not exist) and passing after.
    #[test]
    fn malformed_key_fails() {
        let mut node = valid_node();
        node.key = "not-a-key".to_string();
        assert!(!node_is_valid(&node), "a non-hex key must not validate");
    }

    #[test]
    fn malformed_disco_key_fails() {
        let mut node = valid_node();
        node.disco_key = Some("discokey:zz".to_string());
        assert!(
            !node_is_valid(&node),
            "an odd-length, non-hex disco key must not validate"
        );
    }

    #[test]
    fn malformed_machine_key_fails() {
        let mut node = valid_node();
        node.machine = Some("mkey:not-hex-at-all".to_string());
        assert!(
            !node_is_valid(&node),
            "a malformed machine key must not validate"
        );
    }

    #[test]
    fn missing_prefix_length_fails() {
        // No `/prefix` at all -- a bare IP is not a CIDR.
        let mut node = valid_node();
        node.addresses = vec!["100.64.0.1".to_string()];
        assert!(
            !node_is_valid(&node),
            "an address with no prefix length must not validate"
        );
    }

    #[test]
    fn prefix_length_out_of_range_fails() {
        let mut node = valid_node();
        node.addresses = vec!["100.64.0.1/99".to_string()];
        assert!(
            !node_is_valid(&node),
            "an IPv4 prefix length above 32 must not validate"
        );
    }

    #[test]
    fn garbage_address_fails() {
        let mut node = valid_node();
        node.addresses = vec!["not-an-ip/32".to_string()];
        assert!(!node_is_valid(&node), "a non-IP address must not validate");
    }

    #[test]
    fn valid_ipv6_cidr_passes() {
        assert!(is_valid_cidr("fd7a:115c:a1e0::1/128"));
    }

    // WHY(negative fixture, prefix-length boundary): the guard is
    // `prefix <= max_prefix`. Off-by-one on that comparison (`<` instead of
    // `<=`, or `max_prefix` computed as 31/127) is exactly the class of bug
    // this file exists to catch. These four pin all four corners: each
    // family's exact max (must pass) and exact max-plus-one (must fail) --
    // a value far past the max, like `/99` below, cannot distinguish an
    // off-by-one from correct behavior.
    #[test]
    fn ipv4_cidr_at_max_prefix_passes() {
        assert!(
            is_valid_cidr("100.64.0.1/32"),
            "/32 is a valid IPv4 host route"
        );
    }

    #[test]
    fn ipv4_cidr_one_past_max_prefix_fails() {
        assert!(
            !is_valid_cidr("100.64.0.1/33"),
            "/33 exceeds IPv4's 32-bit width by exactly one"
        );
    }

    #[test]
    fn ipv6_cidr_at_max_prefix_passes() {
        assert!(
            is_valid_cidr("fd7a:115c:a1e0::1/128"),
            "/128 is a valid IPv6 host route"
        );
    }

    // WHY: `prefix_length_out_of_range_fails` above only covers IPv4 --
    // an IPv6 `max_prefix` miscomputed as anything below 128 or above 128
    // needs its own boundary fixture on the V6 arm specifically.
    #[test]
    fn ipv6_cidr_one_past_max_prefix_fails() {
        assert!(
            !is_valid_cidr("fd7a:115c:a1e0::1/129"),
            "/129 exceeds IPv6's 128-bit width by exactly one"
        );
    }

    #[test]
    fn zero_prefix_passes() {
        assert!(
            is_valid_cidr("0.0.0.0/0"),
            "/0 is the valid default-route prefix"
        );
    }

    #[test]
    fn non_numeric_prefix_fails() {
        assert!(!is_valid_cidr("100.64.0.1/abc"));
    }

    #[test]
    fn empty_prefix_fails() {
        assert!(!is_valid_cidr("100.64.0.1/"));
    }

    #[test]
    fn negative_prefix_fails() {
        assert!(!is_valid_cidr("100.64.0.1/-1"));
    }

    // WHY: pins the split-on-first-slash behavior documented above --
    // a second `/` must land in the prefix half and fail parse::<u8>,
    // never get reinterpreted as part of a still-valid address.
    #[test]
    fn double_slash_fails() {
        assert!(!is_valid_cidr("100.64.0.1/32/1"));
    }

    #[test]
    fn allowed_ips_entry_is_checked() {
        let mut node = valid_node();
        node.allowed_ips = Some(vec!["10.0.0.0/8".to_string(), "garbage".to_string()]);
        assert!(
            !node_is_valid(&node),
            "every allowed_ips entry must be validated, not just addresses"
        );
    }

    #[test]
    fn endpoint_missing_port_fails() {
        let mut node = valid_node();
        node.endpoints = Some(vec!["203.0.113.10".to_string()]);
        assert!(
            !node_is_valid(&node),
            "an endpoint with no port is not a socket address"
        );
    }

    #[test]
    fn valid_endpoint_passes() {
        assert!(endpoints_are_valid(&["203.0.113.10:41641".to_string()]));
    }

    #[test]
    fn dns_resolver_bare_ip_passes() {
        assert!(dns_resolver_is_valid(&DnsResolver {
            addr: "100.100.100.100".to_string(),
        }));
    }

    #[test]
    fn dns_resolver_ip_port_passes() {
        assert!(dns_resolver_is_valid(&DnsResolver {
            addr: "1.1.1.1:53".to_string(),
        }));
    }

    #[test]
    fn dns_resolver_garbage_fails() {
        assert!(!dns_resolver_is_valid(&DnsResolver {
            addr: "not-an-address".to_string(),
        }));
    }
}
