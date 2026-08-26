"""Topology checks for the required Phase A GitHub gate context."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / ".github/workflows/gate-attestation.yml"
REUSABLE = ROOT / ".github/workflows/phase-a-gate.yml"


def job_block(document: str, job_id: str) -> str:
    """Return one two-space-indented job block from a workflow document."""

    match = re.search(
        rf"(?ms)^  {re.escape(job_id)}:\n(?P<body>.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        document,
    )
    if match is None:
        raise AssertionError(f"workflow has no {job_id!r} job")
    return match.group("body")


class PhaseAWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
        self.reusable = REUSABLE.read_text(encoding="utf-8")

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
