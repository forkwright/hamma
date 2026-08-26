<!--
scope: hamma repo conventions (Tailscale-compatible mesh networking in pure Rust: dictyon, mitos, future histos)
defers_to: ~/menos-ops/CLAUDE.md for machine topology; ~/.claude/CLAUDE.md for operator principles; kanon standards for universal engineering policy
tightens: no-unsafe/no-unwrap discipline, boringtun as the only audited unsafe boundary
-->

# CLAUDE.md

Project orientation for AI coding agents working on hamma.

## What hamma is

A clean-room Rust Tailscale-compatible mesh networking stack. Phase A builds the `dictyon` peer
client as the networking layer for the forkwright ecosystem and as an OSS contribution to the
Rust networking ecosystem.

See [README.md](README.md) for the public-facing description and
[`contracts/phase-a.toml`](contracts/phase-a.toml) for the typed producer dependency graph.
Private Kanon planning consumes that public contract for fleet coordination.

## Standards

All work must comply with [kanon standards](https://github.com/forkwright/kanon):

- `RUST.md`  -  language-specific rules, dependency policy, banned crates
- `TESTING.md`  -  test naming (`verb_condition`), error path coverage
- `SECURITY.md`  -  secret handling, input validation, unsafe justification
- `WRITING.md`  -  doc comment style, commit message voice
- `ARCHITECTURE.md`  -  crate boundary discipline, dependency direction
- `REPO-SETUP.md`  -  workspace configuration, lints, CI gates

Lint before committing: `kanon lint . --summary`. Gate: `kanon gate`.

## Structure

```
hamma/
├── crates/
│   ├── dictyon/        # peer client (headline crate, ships first)
│   └── mitos/    # shared types (Noise framing, keys, ACL, protocol consts)
├── .github/workflows/  # CI gates (installed by kanon init)
├── Cargo.toml          # workspace root
├── deny.toml           # dependency policy
├── clippy.toml         # lint configuration
├── rustfmt.toml        # format configuration
├── flake.nix           # reproducible dev shell
├── LICENSE-MIT         # dual-license: MIT
└── LICENSE-APACHE      # dual-license: Apache-2.0
```

Planned but not yet scaffolded:
- `crates/histos/`  -  coordination server (Phase B)
- `crates/hamma-derp/`  -  DERP relay server (Phase D, optional)

## Commands

```bash
cargo check --workspace          # fast compile check
cargo test --workspace           # run all tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo deny check                 # dependency audit
kanon lint . --summary           # full kanon lint
```

## Key patterns

- **Error handling**: `snafu` with `.context()` propagation and `Location` tracking. No `anyhow`, no `thiserror`. See the RUST.md error handling section.
- **Async runtime**: `tokio` with the actor-per-component pattern. No shared mutable state across async boundaries. `tokio::sync::Mutex` for async-locked data; `parking_lot::Mutex` for sync-only (never `std::sync::Mutex`  -  it deadlocks held across `.await`).
- **Time**: `std::time::Instant` for monotonic time and `jiff` for wall-clock values when displayed to humans. Wall clock is never a dependency of correctness.
- **Networking primitives**: `tokio::net` for TCP/UDP, `boringtun` (Cloudflare) for WireGuard data plane. No raw sockets, no nix crate, no libc. No reimplementation of WireGuard crypto  -  use the audited reference.
- **Identity types**: ed25519 for node identity, Curve25519 for WireGuard tunnel keys, X25519 for Noise handshakes. Wrap each in a newtype to prevent accidental mixing. Types live in `mitos`.
- **Configuration**: TOML files parsed via `figment` with env-var override cascade. See TOML.md in kanon standards.
- **Logging**: `tracing` with structured fields. Never `println!` in library code. `tracing-subscriber` for the binary.
- **No `unwrap()`, no `expect()` in library code**. Deny at workspace level. Tests may use `.expect("msg")` for clear assertion.
- **No `unsafe`**. Workspace-wide deny. If a specific crate needs unsafe (unlikely until low-level protocol work), it goes in a clearly named module with per-block `// SAFETY:` comments and an allow attribute.

## Current phase

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

## License

Dual MIT / Apache-2.0 (idiomatic Rust ecosystem standard). See `LICENSE-MIT` and `LICENSE-APACHE` at the repo root. Contributions are dual-licensed under the same terms per the Rust convention.

## Dependencies on other forkwright projects

- **kanon**: standards, lint engine. Dev-time dependency.
- **koinon**: standalone shared crate used only as a `dictyon` development dependency; the root
  Cargo manifest is the dependency authority.

Hamma does NOT depend on aletheia, thumos, harmonia, or akroasis at runtime. Those projects depend on hamma, not the reverse.

## Before submitting a PR

1. `cargo check --workspace` clean
2. `cargo test --workspace` all passing
3. `cargo clippy --workspace --all-targets -- -D warnings` clean
4. `cargo fmt --all -- --check` clean
5. `cargo deny check` clean
6. `kanon lint .` zero violations (or justified ignores in `.kanon-lint-ignore`)
7. Conventional commit messages
8. No `unwrap()` / `expect()` in library code
9. Public APIs have doc comments with `# Errors` sections for fallible functions

## Git

Conventional commits: `type(scope): description`. Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `ci`, `perf`, `build`. Present tense imperative, first line no longer than 72 chars.

One logical change per commit. Rebase before pushing to keep history linear.

Never commit directly to main once branch protection is set up. Never push to any upstream that isn't `origin`.

<!-- kanon:auto-start -->
## Generated kanon context

- Registry name: `hamma`
- Forge repo: `forkwright/hamma`
- Kanon prefix: `ha`
- Config source: `workflow/kanon.toml [projects.hamma]`
- Standards source: `crates/basanos/standards/STANDARDS.md`
- MCP routing catalog: `workflow/AGENTS-mcp-tools.md`

Run `kanon docs sync --check --repo hamma` to verify this generated
section and `kanon docs sync --apply --repo hamma` to refresh it.

## Blast zone

- Paths explicitly named by the rendered prompt, role, or template input.

## Acceptance verifier

```bash
kanon gate
```
<!-- kanon:auto-end -->
