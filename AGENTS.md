# Agents — hamma

Clean-room Rust Tailscale-compatible mesh networking stack.

Phase A: `dictyon` peer client against tailscale.com control plane.

## Crates

| Name | Role | Status |
|---|---|---|
| `dictyon` | Peer client: Noise IK handshake, TCP/TLS control channel, registration, map streaming, zstd frame support | Phase A active |
| `hamma-core` | Shared types: Noise framing, WireGuard key types, peer identity, ACL, protocol constants | Phase A active |
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
