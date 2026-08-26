# Contributing to Hamma

Hamma is a clean-room Rust mesh networking stack targeting Tailscale
compatibility. GitHub is the authoritative repository, pull-request, CI, and
merge surface.

## Proposing a change

Create a focused branch and open a pull request against
`forkwright/hamma:main`. Maintainers with repository access push branches to
`origin`; external contributors may use a GitHub fork. Keep commits
conventional (`type(scope): description`) and avoid unrelated changes.

Every pull request must pass the checks required by GitHub branch protection.
The executable workflow definitions under `.github/workflows/` own that check
topology; do not copy their current job list into contributor prose. Hamma uses
normal squash merges after review and green required checks.

## Phase A contract changes

[`contracts/phase-a.toml`](contracts/phase-a.toml) is the public typed authority
for Phase A ordering and evidence. Regenerate its bounded projections with:

```bash
python3 -B tools/render_phase_a.py --apply
```

The result must then be a fixed point under `--check`. Evidence completion is a
two-stage process: first land immutable producer artifacts on `main` while the
node remains blocked, then open a later completion pull request whose typed
receipt cites that already-landed producer commit. Do not combine those stages
in one pull request or push.

## Validation authority

GitHub's required workflows are the merge verdict. `.kanon-ci.toml` carries a
secondary local/forge validation recipe for environments that provide Kanon and
the required toolchain; it is not a copy of every GitHub check or a second
pull-request authority. Run the relevant project commands from
[AGENTS.md](AGENTS.md) while iterating, and let the public GitHub workflows
produce the final clean-checkout result.

All changes remain subject to the Kanon engineering standards referenced by
[CLAUDE.md](CLAUDE.md). Never bypass CI, weaken the Phase A contract, add an AI
attribution trailer, or push to a third-party upstream.
