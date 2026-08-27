"""Topology checks for the required Phase A GitHub gate context."""

from __future__ import annotations

from pathlib import Path
import re
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / ".github/workflows/gate-attestation.yml"
REUSABLE = ROOT / ".github/workflows/phase-a-gate.yml"
FORGE_PIPELINE = ROOT / ".kanon-ci.toml"
TRUSTED_GITHUB_BOUNDARY = (
    "${{ github.event_name == 'pull_request' && "
    "github.event.pull_request.base.sha || github.event.before }}"
)
TRUSTED_FORGE_COMMAND = (
    'producer_boundary="$(git merge-base HEAD origin/main)" && '
    'test -n "$producer_boundary" && '
    'HAMMA_PRODUCER_BOUNDARY="$producer_boundary" '
    "python3 -B tools/render_phase_a.py --check && "
    "python3 -B -m unittest tools/test_render_phase_a.py "
    "tools/test_phase_a_workflow.py"
)


def job_block(document: str, job_id: str) -> str:
    """Return one two-space-indented job block from a workflow document."""

    match = re.search(
        rf"(?ms)^  {re.escape(job_id)}:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        document,
    )
    if match is None:
        raise AssertionError(f"workflow has no {job_id!r} job")
    return match.group("body")


def validate_trusted_boundaries(reusable: str, forge_pipeline: str) -> None:
    contract = job_block(reusable, "phase-a-contract")
    assignments = re.findall(
        r"(?m)^\s+HAMMA_PRODUCER_BOUNDARY:\s*(?P<value>.+)$",
        contract,
    )
    if assignments != [TRUSTED_GITHUB_BOUNDARY]:
        raise AssertionError(
            "Phase A GitHub boundary must use the exact PR-base/push-before expression"
        )

    pipeline = tomllib.loads(forge_pipeline)
    command = pipeline["stages"]["phase-a contract"]["cmd"]
    if command != TRUSTED_FORGE_COMMAND:
        raise AssertionError(
            "Phase A forge boundary must fail closed around the exact origin/main merge base"
        )


class PhaseAWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
        self.reusable = REUSABLE.read_text(encoding="utf-8")
        self.forge_pipeline = FORGE_PIPELINE.read_text(encoding="utf-8")

    def test_required_context_routes_through_local_wrapper(self) -> None:
        gate = job_block(self.entrypoint, "gate")
        self.assertIn("uses: ./.github/workflows/phase-a-gate.yml", gate)
        self.assertNotRegex(gate, r"(?m)^    needs:")
        self.assertNotRegex(gate, r"(?m)^    if:")

    def test_contract_check_cannot_be_bypassed_by_docs_or_credentials(self) -> None:
        contract = job_block(self.reusable, "phase-a-contract")
        self.assertRegex(contract, r"actions/checkout@[0-9a-f]{40}")
        self.assertIn("fetch-depth: 0", contract)
        self.assertIn("persist-credentials: false", contract)
        self.assertIn("python3 -B tools/render_phase_a.py --check", contract)
        self.assertIn(
            "python3 -B -m unittest tools/test_render_phase_a.py "
            "tools/test_phase_a_workflow.py",
            contract,
        )

    def test_receipt_boundary_uses_stable_event_and_forge_revisions(self) -> None:
        validate_trusted_boundaries(self.reusable, self.forge_pipeline)

    def test_receipt_boundary_rejects_synthetic_head_with_decoy_comment(self) -> None:
        mutated = self.reusable.replace(
            f"HAMMA_PRODUCER_BOUNDARY: {TRUSTED_GITHUB_BOUNDARY}",
            "# github.event.pull_request.base.sha remains documented here only\n"
            "          HAMMA_PRODUCER_BOUNDARY: ${{ github.sha }}",
            1,
        )
        self.assertNotEqual(mutated, self.reusable)
        self.assertIn("github.event.pull_request.base.sha", mutated)
        with self.assertRaisesRegex(AssertionError, "exact PR-base/push-before"):
            validate_trusted_boundaries(mutated, self.forge_pipeline)

    def test_terminal_gate_runs_after_every_predecessor_result(self) -> None:
        terminal = job_block(self.reusable, "gate")
        self.assertIn("name: gate", terminal)
        self.assertIn("needs: [phase-a-contract, shared-gate]", terminal)
        self.assertIn("if: always()", terminal)
        self.assertIn("${{ needs.phase-a-contract.result }}", terminal)
        self.assertIn("${{ needs.shared-gate.result }}", terminal)

    def test_shared_policy_remains_centralized(self) -> None:
        shared = job_block(self.reusable, "shared-gate")
        self.assertIn(
            "uses: forkwright/.github/.github/workflows/hybrid-gate.yml@main",
            shared,
        )
        self.assertIn("docs_only_exemption: true", shared)
        self.assertIn("ai_attribution_check: true", shared)


if __name__ == "__main__":
    unittest.main()
