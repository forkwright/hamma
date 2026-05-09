# Contributing to Hamma

Hamma is a clean-room Rust implementation of a Tailscale-compatible mesh networking stack (see [README.md](README.md)). The authoritative PR surface is the self-hosted kanon forge; GitHub stays bidirectionally mirrored for external discoverability but PRs live on the forge.

## Push target

```
origin = http://kanon.lan/forkwright/hamma.git   (authoritative)
github = git@github.com:forkwright/hamma.git     (mirror)
```

Push to `origin`. The forge post-receive hook runs the CI pipeline defined in `.kanon-ci.toml` and mirrors merge commits to GitHub via the pr-sync worker.

## Opening a PR

Two paths, same effect:

**Stoa UI.** Open `http://kanon.lan/prs/forkwright/hamma`, click "New PR", pick base + head refs, review diff, submit.

**CLI.**

```bash
git push origin HEAD:refs/heads/<branch>
kanon pr open <branch> --title "..." --body "..."
```

`kanon pr open` prints the new PR number and its forge URL.

## Review

Comments and approvals land through stoa. The merge button activates when all gates report green:

- CI status `Pass` (every stage in `.kanon-ci.toml` exits zero).
- Independent verifier `Ok` (reproduces the headline claims from a fresh checkout of the head sha).
- A `Gate-Passed: kanon <version>` trailer is present on the tip commit of the PR branch, or the merge will append one.

## Merging

```bash
kanon pr merge <pr_number>
```

or the forge merge button. Default strategy is `squash`; `--strategy ff` or `--strategy rebase` are supported. The merge commit carries the `Gate-Passed` trailer.

Do not merge via GitHub. The GitHub mirror is read-only from the contributor's perspective: any merge performed there races the forge pr-sync worker and drops the trailer.

## External contributors

The GitHub mirror at `github.com/forkwright/hamma` works as before. A PR opened on GitHub is ingested into the forge via the 05d bidirectional sync and then follows the normal review path above. The merge still happens on the forge; GitHub closes when the mirror sync observes the merge commit on `main`.

## Fallback

If the forge is unreachable, push to `github` and open a GitHub PR. When the forge is back, its pr-sync worker picks up the PR and continues from there. This is an escape hatch, not a preferred path - use it only when kanon.lan is actually down.

## CI configuration

`.kanon-ci.toml` at the repo root defines the pipeline. Hamma is a Rust workspace, so the pipeline runs the full Rust gate:

1. `cargo fmt --all -- --check`
2. `cargo check --workspace --all-targets`
3. `cargo clippy --workspace --all-targets -- -D warnings`
4. `cargo nextest run --workspace`
5. `kanon lint . --summary`

Per-stage `--jobs` / `--test-threads` are pinned to 8 so parallel rustc + nextest processes stay under ~25GB RSS - low enough to keep the forge host healthy when other fleet work is resident. Keep `.kanon-ci.toml` in sync with `archeion`'s hardcoded default Rust gate when the upstream default changes; only the concurrency flags should differ.

## Standards

All work must pass the internal standards corpus: `RUST.md`, `TESTING.md`, `SECURITY.md`, `WRITING.md`, `ARCHITECTURE.md`, `REPO-SETUP.md`. Run `kanon lint . --summary` before committing and `kanon gate` before pushing.

## Branch naming and commit format

Per `CLAUDE.md`: `feat/`, `fix/`, `docs/`, `refactor/`, `test/`, `chore/`, `cleanup/`. Commit messages are `category(scope): description`. Squash merges keep `main` linear.

## Cutover lineage

This CONTRIBUTING.md landed as the hamma Phase 05e cutover (2026-04-19), adopting the forge-native PR flow proven on `forkwright/dioptron#1` (2026-04-19) and the forkwright profile README. See `projects/kanon/phases/05-forge-prs/subphases/05e-cutover/PLAN.md` in kanon for the full phase scope.
