<!--
scope: hamma repo — agent onboarding and dispatch conventions
defers_to: CLAUDE.md for full repo conventions; kanon standards for universal engineering policy
tightens: gate discipline (truthful Gate-Passed trailers, no AI indicators)
-->

# Agents — hamma

Clean-room Rust Tailscale-compatible mesh networking stack.

Phase A builds the `dictyon` peer client against the tailscale.com control plane.

## Phase A dependency order

<!-- phase-a:generated:start -->
A self-paired registration and map-stream prototype must pass independent control-plane gates before data-plane activation.

| Order | Gate | Tracker | State | Requires | Evidence |
|---:|---|---|---|---|---|
| 1 | `http2-over-noise` — HTTP/2 over Noise interoperability | [#65](https://github.com/forkwright/hamma/issues/65) | `blocked` | — | — |
| 2 | `effective-acl` — Authoritative effective ACL policy | [#67](https://github.com/forkwright/hamma/issues/67) | `blocked` | `http2-over-noise` | — |
| 3 | `data-plane` — WireGuard data-plane activation | — | `blocked` | `http2-over-noise`, `effective-acl` | — |

While `data-plane` is blocked, the checker rejects every listed reserved activation path, dependency identity, and source token, and contract validation refuses to shrink those minimum guard sets. This bounded enforcement does not replace review for other ways a change could introduce a data plane.
The public contract, not private planning prose, owns this producer order.

Source: [`contracts/phase-a.toml`](contracts/phase-a.toml). Regenerate with `python3 tools/render_phase_a.py --apply`; CI runs `--check`.
<!-- phase-a:generated:end -->

## Crates

| Name | Role | Status |
|---|---|---|
| `dictyon` | Peer client: control transport, registration, map streaming, and eventually the gated data plane | Phase A |
| `mitos` | Shared types: Noise framing, WireGuard key types, peer identity, ACL, protocol constants | Phase A |
| `histos` | Coordination server (planned) | Not started |
| `hamma-derp` | DERP relay server (planned) | Not started |

## Build

```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check
kanon lint . --summary
```

## Standards

Kanon standards in `standards/README.md` — kanon repo covers: RUST.md, TESTING.md, SECURITY.md, WRITING.md, ARCHITECTURE.md, REPO-SETUP.md.

## Key patterns

- **Error handling**: `snafu` with `.context()` propagation. No `anyhow`, no `thiserror`.
- **Async**: `tokio` actor-per-component. No shared mutable state across async boundaries.
- **No `unwrap()`/`expect()` in library code** — workspace-level deny. Tests may use `.expect("msg")` for assertions.
- **No `unsafe`** — workspace-level deny.
- **Identity types are newtypes**: `MachinePrivate`, `NodePrivate`, `DiscoPrivate`, `MachinePublic`, `NodePublic`. The type system prevents accidental key mixing.
- **Logging**: `tracing` with structured fields. Never `println!` in library code.

## Before PR

- [ ] `cargo check --workspace` clean
- [ ] `cargo test --workspace` all passing
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` zero warnings
- [ ] `cargo fmt --all -- --check` clean
- [ ] `cargo deny check` clean
- [ ] `kanon lint .` zero violations
- [ ] Conventional commit message (`type(scope): description`)
- [ ] No `unwrap()`/`expect()` in library code
- [ ] Public APIs have doc comments with `# Errors` sections for fallible functions
