"""Negative regression matrix for Hamma's Phase A contract."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools/render_phase_a.py"


class PhaseAContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "contracts").mkdir()
        (self.root / "_llm").mkdir()
        shutil.copy2(ROOT / "contracts/phase-a.toml", self.root / "contracts/phase-a.toml")
        for name in ("README.md", "AGENTS.md", "CLAUDE.md", "llms.txt"):
            shutil.copy2(ROOT / name, self.root / name)
        shutil.copy2(ROOT / "_llm/current_state.toml", self.root / "_llm/current_state.toml")
        (self.root / "Cargo.toml").write_text(
            "[workspace]\nmembers = []\n\n[workspace.dependencies]\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_check(self) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["HAMMA_CONTRACT_ROOT"] = str(self.root)
        return subprocess.run(
            ["python3", str(CHECKER), "--check"],
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def mutate_contract(self, old: str, new: str) -> None:
        path = self.root / "contracts/phase-a.toml"
        content = path.read_text(encoding="utf-8")
        self.assertIn(old, content)
        path.write_text(content.replace(old, new, 1), encoding="utf-8")

    def mutate_projection(self, name: str, old: str, new: str) -> None:
        path = self.root / name
        content = path.read_text(encoding="utf-8")
        self.assertIn(old, content)
        path.write_text(content.replace(old, new, 1), encoding="utf-8")

    def assert_rejected(self, expected: str) -> None:
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stderr)

    def test_current_contract_is_a_fixed_point(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_tracker_identity_cannot_be_removed(self) -> None:
        self.mutate_contract("issue = 65\n", "")
        self.assert_rejected("http2-over-noise.issue")

    def test_data_plane_cannot_claim_an_implementation_issue(self) -> None:
        self.mutate_contract(
            'id = "data-plane"\ntitle = "WireGuard data-plane activation"',
            'id = "data-plane"\ntitle = "WireGuard data-plane activation"\nissue = 118',
        )
        self.assert_rejected("data-plane.issue must remain absent")

    def test_predecessor_kind_cannot_be_weakened(self) -> None:
        self.mutate_contract('kind = "gate"\nissue = 65', 'kind = "activation"\nissue = 65')
        self.assert_rejected("http2-over-noise.kind")

    def test_required_edge_cannot_be_removed(self) -> None:
        self.mutate_contract(
            'requires = ["http2-over-noise"]',
            "requires = []",
        )
        self.assert_rejected("effective-acl.requires")

    def test_graph_cycle_is_rejected(self) -> None:
        self.mutate_contract(
            'requires = []\nevidence = []\nreceipt = "evidence/phase-a/http2-over-noise.toml"',
            'requires = ["data-plane"]\nevidence = []\nreceipt = "evidence/phase-a/http2-over-noise.toml"',
        )
        self.assert_rejected("contains a cycle")

    def test_complete_node_cannot_pass_an_incomplete_predecessor(self) -> None:
        self.mutate_contract(
            'state = "blocked"\nrequires = ["http2-over-noise"]\nevidence = []',
            'state = "complete"\nrequires = ["http2-over-noise"]\n'
            'evidence = ["evidence/phase-a/effective-acl.toml"]',
        )
        self.assert_rejected("cannot be complete while http2-over-noise is incomplete")

    def test_extra_node_is_rejected(self) -> None:
        path = self.root / "contracts/phase-a.toml"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                '\n[[nodes]]\nid = "shadow"\ntitle = "Shadow gate"\n'
                'kind = "gate"\nstate = "blocked"\nrequires = []\nevidence = []\n'
            )
        self.assert_rejected("node identities must be exactly")

    def test_absolute_evidence_path_is_rejected(self) -> None:
        self.mutate_contract('evidence = []', 'evidence = ["/tmp/outside"]')
        self.assert_rejected("must not be absolute")

    def test_traversing_evidence_path_is_rejected(self) -> None:
        self.mutate_contract(
            'evidence = []',
            'evidence = ["evidence/phase-a/../outside"]',
        )
        self.assert_rejected("must not contain traversal or normalization")

    def test_symlinked_evidence_path_is_rejected(self) -> None:
        outside = self.root.parent / f"{self.root.name}-outside.txt"
        outside.write_text("not repository evidence\n", encoding="utf-8")
        self.addCleanup(outside.unlink, missing_ok=True)
        evidence = self.root / "evidence/phase-a"
        evidence.mkdir(parents=True)
        (evidence / "escape.txt").symlink_to(outside)
        self.mutate_contract(
            'evidence = []',
            'evidence = ["evidence/phase-a/escape.txt"]',
        )
        self.assert_rejected("must not use a symlink")

    def test_required_artifact_roles_cannot_shrink(self) -> None:
        self.mutate_contract('    "mismatch-transcript",\n', "")
        self.assert_rejected("cannot remove minimum values: mismatch-transcript")

    def test_reserved_path_floor_cannot_shrink(self) -> None:
        self.mutate_contract('    "crates/dictyon/src/dataplane.rs",\n', "")
        self.assert_rejected("data-plane.reserved_paths cannot remove minimum values")

    def test_forbidden_package_floor_cannot_shrink(self) -> None:
        self.mutate_contract('    "rtnetlink",\n', "")
        self.assert_rejected("data-plane.forbidden_packages cannot remove minimum values")

    def test_forbidden_source_floor_cannot_shrink(self) -> None:
        self.mutate_contract('    "TUNSETIFF",\n', "")
        self.assert_rejected("data-plane.forbidden_source_tokens cannot remove minimum values")

    def test_cargo_alias_cannot_hide_a_data_plane_dependency(self) -> None:
        with (self.root / "Cargo.toml").open("a", encoding="utf-8") as handle:
            handle.write(
                '\n[workspace.dependencies.wg-engine]\npackage = "boringtun"\nversion = "0.6"\n'
            )
        self.assert_rejected("activates boringtun")

    def test_reserved_source_token_cannot_activate_early(self) -> None:
        source = self.root / "crates/dictyon/src/runtime.rs"
        source.parent.mkdir(parents=True)
        source.write_text("fn early() { let _ = boringtun::noise::Tunn::new; }\n", encoding="utf-8")
        self.assert_rejected("contains 'boringtun::'")

    def test_reserved_module_path_cannot_activate_early(self) -> None:
        source = self.root / "crates/dictyon/src/data_plane.rs"
        source.parent.mkdir(parents=True)
        source.write_text("// premature data plane\n", encoding="utf-8")
        self.assert_rejected("reserved activation path exists")

    def test_stale_projection_is_rejected(self) -> None:
        self.mutate_projection("README.md", "public contract", "stale public contract")
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("README.md (generated)", result.stdout)


if __name__ == "__main__":
    unittest.main()
