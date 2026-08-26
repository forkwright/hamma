# Hamma

*ἅμμα  -  a knot, a tie, a fastening*

A clean-room Rust mesh networking stack targeting Tailscale compatibility. Pre-alpha, actively implementing the peer client.

## Status

<!-- phase-a:generated:start -->
Phase A declares the prerequisite order for future independent control-plane validation; completion and data-plane activation are unavailable until authenticated independent-oracle authority lands.

| Order | Gate | Tracker | State | Requires | Evidence |
|---:|---|---|---|---|---|
| 1 | `http2-over-noise` — HTTP/2 over Noise interoperability | [#65](https://github.com/forkwright/hamma/issues/65) | `blocked` | — | — |
| 2 | `effective-acl` — Authoritative effective ACL policy | [#67](https://github.com/forkwright/hamma/issues/67) | `blocked` | `http2-over-noise` | — |
| 3 | `data-plane` — WireGuard data-plane activation | — | `blocked` | `http2-over-noise`, `effective-acl` | — |

Completion authority is `unavailable` pending [#122](https://github.com/forkwright/hamma/issues/122). No node may transition to `complete`, and data-plane activation remains unavailable, until an authenticated independent-oracle verifier lands.
While `data-plane` is blocked, the checker rejects every listed reserved activation path, dependency identity, and source token, and contract validation refuses to shrink those minimum guard sets. This bounded enforcement does not replace review for other ways a change could introduce a data plane.
The public contract, not private planning prose, owns this producer order.
Evidence artifacts and typed receipt/provenance groundwork may land while nodes remain blocked, but metadata does not authorize completion. Every complete transition fails closed until #122 lands an authenticated independent-oracle verifier.

Source: [`contracts/phase-a.toml`](contracts/phase-a.toml). Regenerate with `python3 tools/render_phase_a.py --apply`; CI runs `--check`.
<!-- phase-a:generated:end -->

## What this is

Hamma is a Rust-native mesh networking stack  -  the pieces needed to knot a set of devices into a single flat network, speak WireGuard peer-to-peer, traverse NATs via DERP relays, and name each other via MagicDNS. It targets wire-compatibility with Tailscale's existing control plane so that devices running hamma can join the same tailnet as devices running the reference Tailscale client.

**Why it exists.** A production-grade Rust implementation of the Tailscale client/server protocol does not exist. Hamma fills that gap, initially as the networking layer for the [forkwright](https://github.com/forkwright) ecosystem  -  [aletheia](https://github.com/forkwright/aletheia) (cognitive runtime), [akroasis](https://github.com/forkwright/akroasis) (signals intelligence), [harmonia](https://github.com/forkwright/harmonia) (media platform), and [thumos](https://github.com/forkwright/thumos) (mobile OS)  -  and openly as an option for anyone who wants a memory-safe, auditable mesh client.

## Crates

| Crate | Role | Status |
|---|---|---|
| `dictyon` (δίκτυον, "net") | Peer client: control transport, registration, map streaming, and the gated data-plane target | Phase A |
| `mitos` | Shared types: Noise framing, WireGuard key types, peer identity, ACL types, protocol constants | Phase A |
| `histos` (ἱστός, "loom")  -  **planned** | Coordination server: peer registry, ACL enforcement, preauth keys, DERP coordination. Replaces Headscale/tailscale.com when sovereignty is wanted | Not started |
| `hamma-derp`  -  **planned** | DERP relay server (optional  -  can reuse Tailscale's DERP for Phase A) | Not started |

## Design principles

1. **Clean-room Rust, not a port.** No C, no unsafe in Hamma, and no vendor blobs. An eventual data-plane engine remains an audited external boundary rather than locally reimplemented cryptography.
2. **Wire-compatible first.** Phase A targets interop with tailscale.com's control plane so dictyon can be validated against a reference server before histos exists. Protocol extensions are opt-in, layered on top, never break compat.
3. **Small feature target.** Peer WG, MagicDNS, exit nodes, ACLs. Not Taildrop, Tailscale SSH, Funnel, or app connectors. Those can be added later if anyone wants them.
4. **Hardware-attestation extensions.** Future `histos` will add forkwright-specific extensions: hardware-key-signed admin operations (FIDO2 attestation), tamper-evident peer enrollment, measured-boot attestation hooks. Upstream-incompatible, opt-in.
5. **Shared standards.** Built against the internal linting, formatting, and testing standards. Same quality floor as the rest of forkwright.

## Phases

The public Phase A contract above owns implementation sequencing. Private fleet planning consumes
that contract and may add coordination context, but cannot redefine Hamma's producer order.

- **Phase A  -  dictyon client against tailscale.com**. Targets validation of the Rust client against a production reference server. No histos scope.
- **Phase B  -  histos coordination server, wire-compatible**. Matches Headscale's feature surface for forkwright self-hosting.
- **Phase C  -  histos hardware-attestation extensions**. Titan-signed admin ops, attestation hooks, canary integration.
- **Phase D  -  DERP relay**. Optional own-relay for full-stack independence.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Contributing

Not yet accepting external contributions while the initial architecture stabilizes. Watch the repo for status updates.

<!-- kanon:auto-start -->
## Repository Metadata

- Registry name: `hamma`
- Description: Kanon-managed forkwright repository `hamma`.
- Forge repo: `forkwright/hamma`
- Kanon prefix: `ha`
- Config source: `workflow/kanon.toml [projects.hamma]`
- Planning state: `projects/hamma/STATE.md`
- Last state update: `2026-05-22`

Run `kanon docs sync --check --repo hamma` to verify this generated
section and `kanon docs sync --apply --repo hamma` to refresh it.

## Blast zone

- Paths explicitly named by the rendered prompt, role, or template input.

## Acceptance verifier

```bash
kanon gate
```
<!-- kanon:auto-end -->
