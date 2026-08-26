"""Positive and negative regression matrix for Hamma's Phase A contract."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "tools/render_phase_a.py"
SUBJECTS = ("http2-over-noise", "effective-acl", "data-plane")
ORACLE_REVISION = "1" * 40


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
        self.run_git("init", "-b", "main")
        self.run_git("config", "user.name", "Phase A fixture")
        self.run_git("config", "user.email", "phase-a@example.invalid")
        self.base_commit = self.commit_all("fixture baseline")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_git(
        self, *arguments: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", *arguments],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
        )
        if check and result.returncode != 0:
            self.fail(
                f"git {' '.join(arguments)} failed:\n{result.stdout}{result.stderr}"
            )
        return result

    def commit_all(self, message: str) -> str:
        self.run_git("add", "--all")
        self.run_git("commit", "-m", message)
        return self.run_git("rev-parse", "HEAD").stdout.strip()

    def renderer_environment(self, producer_boundary: str | None) -> dict[str, str]:
        environment = os.environ.copy()
        environment["HAMMA_CONTRACT_ROOT"] = str(self.root)
        environment.pop("HAMMA_PRODUCER_BOUNDARY", None)
        if producer_boundary is not None:
            environment["HAMMA_PRODUCER_BOUNDARY"] = producer_boundary
        return environment

    def run_renderer(
        self, mode: str, producer_boundary: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", "-B", str(CHECKER), mode],
            env=self.renderer_environment(producer_boundary),
            check=False,
            capture_output=True,
            text=True,
        )

    def run_check(
        self, producer_boundary: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return self.run_renderer("--check", producer_boundary)

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

    def complete_node(self, node_id: str, evidence: str | None = None) -> None:
        path = self.root / "contracts/phase-a.toml"
        content = path.read_text(encoding="utf-8")
        start = content.index(f'id = "{node_id}"')
        end = content.find("\n[[nodes]]", start)
        if end < 0:
            end = len(content)
        section = content[start:end]
        self.assertIn('state = "blocked"', section)
        self.assertIn("evidence = []", section)
        receipt = evidence or f"evidence/phase-a/{node_id}.toml"
        section = section.replace('state = "blocked"', 'state = "complete"', 1)
        section = section.replace("evidence = []", f'evidence = ["{receipt}"]', 1)
        path.write_text(content[:start] + section + content[end:], encoding="utf-8")

    def artifact_roles(self, subject: str) -> list[str]:
        contract = tomllib.loads(
            (self.root / "contracts/phase-a.toml").read_text(encoding="utf-8")
        )
        for node in contract["nodes"]:
            if node["id"] == subject:
                return list(node["required_artifact_roles"])
        self.fail(f"contract has no subject {subject!r}")

    def write_artifacts(self, subjects: tuple[str, ...]) -> None:
        for subject in subjects:
            directory = self.root / "evidence/phase-a" / subject
            directory.mkdir(parents=True, exist_ok=True)
            for role in self.artifact_roles(subject):
                (directory / f"{role}.txt").write_text(
                    f"{subject}:{role}\n",
                    encoding="utf-8",
                )

    def land_artifacts(self, subjects: tuple[str, ...]) -> str:
        self.write_artifacts(subjects)
        return self.commit_all("land immutable evidence artifacts")

    def write_receipt(
        self,
        subject: str,
        producer_commit: str,
        *,
        schema_literal: str = "1",
        receipt_subject: str | None = None,
        roles: list[str] | None = None,
        hash_overrides: dict[str, str] | None = None,
    ) -> None:
        selected_roles = roles if roles is not None else self.artifact_roles(subject)
        overrides = hash_overrides or {}
        lines = [
            f"schema = {schema_literal}",
            f'subject = "{receipt_subject or subject}"',
            f'producer_commit = "{producer_commit}"',
            "",
            "[oracle]",
            'name = "independent fixture oracle"',
            'repository = "https://example.invalid/phase-a-oracle"',
            f'revision = "{ORACLE_REVISION}"',
        ]
        for role in selected_roles:
            relative = Path("evidence/phase-a") / subject / f"{role}.txt"
            digest = hashlib.sha256((self.root / relative).read_bytes()).hexdigest()
            lines.extend(
                [
                    "",
                    "[[artifacts]]",
                    f'role = "{role}"',
                    f'path = "{relative.as_posix()}"',
                    f'sha256 = "{overrides.get(role, digest)}"',
                ]
            )
        receipt = self.root / "evidence/phase-a" / f"{subject}.toml"
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.run_git("add", receipt.relative_to(self.root).as_posix())

    def prepare_completion(
        self,
        producer_commit: str,
        *,
        data_evidence: str | None = None,
        data_subject: str | None = None,
        data_roles: list[str] | None = None,
        data_hashes: dict[str, str] | None = None,
    ) -> None:
        for subject in SUBJECTS:
            self.write_receipt(
                subject,
                producer_commit,
                receipt_subject=data_subject if subject == "data-plane" else None,
                roles=data_roles if subject == "data-plane" else None,
                hash_overrides=data_hashes if subject == "data-plane" else None,
            )
            self.complete_node(
                subject,
                data_evidence if subject == "data-plane" else None,
            )
        self.run_git("add", "contracts/phase-a.toml")

    def assert_rejected(
        self, expected: str, producer_boundary: str | None = None
    ) -> None:
        result = self.run_check(producer_boundary)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stderr)

    def test_current_contract_is_a_fixed_point(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_contract_schema_rejects_toml_boolean(self) -> None:
        self.mutate_contract("schema = 1", "schema = true")
        self.assert_rejected("contracts/phase-a.toml schema must be the integer 1")

    def test_contract_schema_rejects_toml_float(self) -> None:
        self.mutate_contract("schema = 1", "schema = 1.0")
        self.assert_rejected("contracts/phase-a.toml schema must be the integer 1")

    def test_completed_data_plane_survives_synthetic_and_squash_topologies(self) -> None:
        producer = self.land_artifacts(SUBJECTS)
        self.run_git("switch", "-c", "completion")
        self.prepare_completion(producer)
        applied = self.run_renderer("--apply", producer)
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        completion = self.commit_all("complete Phase A from landed evidence")

        self.run_git("switch", "main")
        self.run_git("merge", "--no-ff", "--no-edit", completion)
        synthetic = self.run_check(producer)
        self.assertEqual(synthetic.returncode, 0, synthetic.stdout + synthetic.stderr)

        self.run_git("switch", "-c", "squash-stable", producer)
        self.run_git("merge", "--squash", completion)
        self.commit_all("squash Phase A completion")
        pushed = self.run_check(producer)
        self.assertEqual(pushed.returncode, 0, pushed.stdout + pushed.stderr)

    def test_same_push_cannot_land_producer_and_completion(self) -> None:
        prior_main = self.base_commit
        self.run_git("switch", "-c", "single-push-completion")
        producer = self.land_artifacts(SUBJECTS)
        self.prepare_completion(producer)
        applied = self.run_renderer("--apply", producer)
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        completion = self.commit_all("complete Phase A in the same push")
        self.assertEqual(
            self.run_git(
                "merge-base",
                "--is-ancestor",
                producer,
                completion,
                check=False,
            ).returncode,
            0,
        )
        self.assert_rejected("ancestor of stable producer boundary", prior_main)

    def test_feature_only_producer_fails_on_synthetic_merge(self) -> None:
        stable_base = self.base_commit
        self.run_git("switch", "-c", "feature-only-evidence")
        producer = self.land_artifacts(("http2-over-noise",))
        self.write_receipt("http2-over-noise", producer)
        self.complete_node("http2-over-noise")
        self.commit_all("claim completion from feature-only evidence")

        self.run_git("switch", "main")
        self.run_git("merge", "--no-ff", "--no-edit", "feature-only-evidence")
        self.run_git("merge-base", "--is-ancestor", producer, "HEAD")
        self.assertNotEqual(
            self.run_git(
                "merge-base",
                "--is-ancestor",
                producer,
                stable_base,
                check=False,
            ).returncode,
            0,
        )
        self.assert_rejected("ancestor of stable producer boundary", stable_base)

    def test_completed_receipt_requires_explicit_producer_boundary(self) -> None:
        producer = self.land_artifacts(("http2-over-noise",))
        self.write_receipt("http2-over-noise", producer)
        self.complete_node("http2-over-noise")
        self.assert_rejected("completed receipts require HAMMA_PRODUCER_BOUNDARY")

    def test_receipt_schema_rejects_toml_boolean(self) -> None:
        producer = self.land_artifacts(("http2-over-noise",))
        self.write_receipt("http2-over-noise", producer, schema_literal="true")
        self.complete_node("http2-over-noise")
        self.assert_rejected("schema must be the integer 1", producer)

    def test_receipt_schema_rejects_toml_float(self) -> None:
        producer = self.land_artifacts(("http2-over-noise",))
        self.write_receipt("http2-over-noise", producer, schema_literal="1.0")
        self.complete_node("http2-over-noise")
        self.assert_rejected("schema must be the integer 1", producer)

    def test_data_plane_cannot_reuse_predecessor_receipt(self) -> None:
        producer = self.land_artifacts(SUBJECTS)
        self.prepare_completion(
            producer,
            data_evidence="evidence/phase-a/http2-over-noise.toml",
        )
        self.assert_rejected(
            "complete node 'data-plane' must cite only its typed receipt",
            producer,
        )

    def test_data_plane_receipt_cannot_name_a_predecessor_subject(self) -> None:
        producer = self.land_artifacts(SUBJECTS)
        self.prepare_completion(producer, data_subject="effective-acl")
        self.assert_rejected("subject='data-plane'", producer)

    def test_data_plane_receipt_rejects_hash_mismatch(self) -> None:
        producer = self.land_artifacts(SUBJECTS)
        role = self.artifact_roles("data-plane")[0]
        self.prepare_completion(producer, data_hashes={role: "0" * 64})
        self.assert_rejected("receipt artifact hash mismatch", producer)

    def test_data_plane_receipt_rejects_producer_artifact_drift(self) -> None:
        producer = self.land_artifacts(SUBJECTS)
        role = self.artifact_roles("data-plane")[0]
        artifact = self.root / "evidence/phase-a/data-plane" / f"{role}.txt"
        artifact.write_text("changed after the producer commit\n", encoding="utf-8")
        self.run_git("add", artifact.relative_to(self.root).as_posix())
        self.prepare_completion(producer)
        self.assert_rejected("receipt artifact provenance mismatch", producer)

    def test_data_plane_receipt_requires_every_activation_role(self) -> None:
        producer = self.land_artifacts(SUBJECTS)
        roles = self.artifact_roles("data-plane")[:-1]
        self.prepare_completion(producer, data_roles=roles)
        self.assert_rejected("data-plane artifact roles must be", producer)

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

    def test_data_plane_activation_role_floor_cannot_shrink(self) -> None:
        self.mutate_contract('    "missing-effective-policy-capability-rejection",\n', "")
        self.assert_rejected(
            "data-plane.required_artifact_roles cannot remove minimum values"
        )

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
