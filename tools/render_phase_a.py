#!/usr/bin/env python3
"""Validate Hamma's Phase A contract and render every public projection."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import tomllib
from typing import Any


ROOT = Path(os.environ.get("HAMMA_CONTRACT_ROOT", Path(__file__).resolve().parents[1])).resolve()
CONTRACT = ROOT / "contracts/phase-a.toml"
MARKER_START = "<!-- phase-a:generated:start -->"
MARKER_END = "<!-- phase-a:generated:end -->"
DOC_TARGETS = (
    ROOT / "README.md",
    ROOT / "AGENTS.md",
    ROOT / "CLAUDE.md",
    ROOT / "llms.txt",
)
STATE_TARGET = ROOT / "_llm/current_state.toml"
EVIDENCE_PREFIX = PurePosixPath("evidence/phase-a")
VALID_STATES = frozenset({"blocked", "complete"})
PHASE_A_NODE_IDS = frozenset({"http2-over-noise", "effective-acl", "data-plane"})
EXPECTED_PHASE = {
    "id": "phase-a",
    "title": "Peer-client interoperability validation",
    "summary": (
        "A self-paired registration and map-stream prototype must pass independent "
        "control-plane gates before data-plane activation."
    ),
}
EXPECTED_NODES = {
    "http2-over-noise": {
        "title": "HTTP/2 over Noise interoperability",
        "kind": "gate",
        "issue": 65,
        "requires": [],
    },
    "effective-acl": {
        "title": "Authoritative effective ACL policy",
        "kind": "gate",
        "issue": 67,
        "requires": ["http2-over-noise"],
    },
    "data-plane": {
        "title": "WireGuard data-plane activation",
        "kind": "activation",
        "issue": None,
        "requires": ["http2-over-noise", "effective-acl"],
    },
}
MINIMUM_RECEIPT_ROLES = {
    "http2-over-noise": frozenset(
        {
            "initiation-frame",
            "noise-prologue",
            "success-transcript",
            "mismatch-transcript",
        }
    ),
    "effective-acl": frozenset(
        {
            "policy-input",
            "deny-all-transcript",
            "allow-transcript",
            "deny-transcript",
        }
    ),
}
MINIMUM_RESERVED_PATHS = frozenset(
    {
        "crates/dictyon-data-plane",
        "crates/dictyon/src/data_plane.rs",
        "crates/dictyon/src/dataplane.rs",
    }
)
MINIMUM_FORBIDDEN_PACKAGES = frozenset(
    {"boringtun", "wireguard-control", "wireguard-rs", "tun", "rtnetlink"}
)
MINIMUM_FORBIDDEN_SOURCE_TOKENS = frozenset(
    {"boringtun::", "wireguard_control::", "/dev/net/tun", "TUNSETIFF"}
)


class ContractError(RuntimeError):
    """The typed Phase A contract is malformed or internally inconsistent."""


def require_table(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{name} must be a TOML table")
    return value


def require_string(table: dict[str, Any], key: str, owner: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise ContractError(f"{owner}.{key} must be a non-empty string")
    return value


def require_string_list(table: dict[str, Any], key: str, owner: str) -> list[str]:
    value = table.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ContractError(f"{owner}.{key} must be an array of non-empty strings")
    return value


def require_unique_string_list(table: dict[str, Any], key: str, owner: str) -> list[str]:
    values = require_string_list(table, key, owner)
    if len(values) != len(set(values)):
        raise ContractError(f"{owner}.{key} must not contain duplicates")
    return values


def require_minimum(values: list[str], minimum: frozenset[str], description: str) -> None:
    missing = minimum - set(values)
    if missing:
        raise ContractError(
            f"{description} cannot remove minimum values: {', '.join(sorted(missing))}"
        )


def canonical_relative_path(raw: str, description: str) -> PurePosixPath:
    if "\\" in raw:
        raise ContractError(f"{description} must use canonical POSIX separators: {raw!r}")
    relative = PurePosixPath(raw)
    if relative.is_absolute():
        raise ContractError(f"{description} must not be absolute: {raw!r}")
    if relative.as_posix() != raw or any(part in {".", ".."} for part in relative.parts):
        raise ContractError(f"{description} must not contain traversal or normalization: {raw!r}")
    if not relative.parts:
        raise ContractError(f"{description} must not be empty")
    return relative


def evidence_path(
    raw: str,
    description: str,
    *,
    must_exist: bool,
    must_be_tracked: bool,
    subtree: PurePosixPath = EVIDENCE_PREFIX,
) -> Path:
    relative = canonical_relative_path(raw, description)
    if not relative.is_relative_to(subtree):
        raise ContractError(f"{description} must live under {subtree.as_posix()}/: {raw}")

    candidate = ROOT
    for part in relative.parts:
        candidate /= part
        if candidate.is_symlink():
            raise ContractError(f"{description} must not use a symlink: {raw}")

    try:
        resolved_root = ROOT.resolve()
        resolved_subtree = ROOT.joinpath(*subtree.parts).resolve()
        resolved_candidate = candidate.resolve()
    except RuntimeError as error:
        raise ContractError(f"{description} contains a symlink loop: {raw}") from error
    if not resolved_subtree.is_relative_to(resolved_root):
        raise ContractError(f"{description} evidence subtree escapes the repository: {raw}")
    if not resolved_candidate.is_relative_to(resolved_root):
        raise ContractError(f"{description} escapes the repository: {raw}")
    if not resolved_candidate.is_relative_to(resolved_subtree):
        raise ContractError(f"{description} escapes {subtree.as_posix()}/: {raw}")
    if must_exist and not candidate.is_file():
        raise ContractError(f"{description} does not exist: {raw}")
    if must_be_tracked:
        tracked_repository_path(candidate, description)
    return candidate


def validate_graph(
    nodes: list[dict[str, Any]], by_id: dict[str, dict[str, Any]]
) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in visiting:
            raise ContractError(f"Phase A graph contains a cycle through {node_id!r}")
        if node_id in visited:
            return
        visiting.add(node_id)
        for dependency in by_id[node_id]["requires"]:
            if dependency not in by_id:
                raise ContractError(f"{node_id} requires unknown node {dependency!r}")
            if dependency == node_id:
                raise ContractError(f"{node_id} cannot require itself")
            visit(dependency)
        visiting.remove(node_id)
        visited.add(node_id)

    for node in nodes:
        visit(node["id"])

    order = {node["id"]: index for index, node in enumerate(nodes)}
    for node in nodes:
        node_id = node["id"]
        for dependency in node["requires"]:
            if order[dependency] >= order[node_id]:
                raise ContractError(
                    f"{node_id} must appear after dependency {dependency!r}; "
                    "the declared order is executable"
                )
            if node["state"] == "complete" and by_id[dependency]["state"] != "complete":
                raise ContractError(f"{node_id} cannot be complete while {dependency} is incomplete")


def read_contract() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw = tomllib.loads(CONTRACT.read_text(encoding="utf-8"))
    if raw.get("schema") != 1:
        raise ContractError("contracts/phase-a.toml schema must equal 1")

    phase = require_table(raw.get("phase"), "phase")
    for field, expected in EXPECTED_PHASE.items():
        actual = require_string(phase, field, "phase")
        if actual != expected:
            raise ContractError(f"phase.{field} must remain {expected!r}, got {actual!r}")

    nodes_value = raw.get("nodes")
    if not isinstance(nodes_value, list) or not nodes_value:
        raise ContractError("contracts/phase-a.toml must contain [[nodes]]")

    nodes: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for index, raw_node in enumerate(nodes_value):
        node = require_table(raw_node, f"nodes[{index}]")
        node_id = require_string(node, "id", f"nodes[{index}]")
        if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in node_id):
            raise ContractError(f"node id {node_id!r} must be lowercase kebab-case")
        if node_id in by_id:
            raise ContractError(f"duplicate node id {node_id!r}")
        require_string(node, "title", node_id)
        kind = require_string(node, "kind", node_id)
        if kind not in {"gate", "activation"}:
            raise ContractError(f"{node_id}.kind must be gate or activation")
        state = require_string(node, "state", node_id)
        if state not in VALID_STATES:
            raise ContractError(f"{node_id}.state must be one of {sorted(VALID_STATES)}")
        require_unique_string_list(node, "requires", node_id)
        evidence = require_unique_string_list(node, "evidence", node_id)
        issue = node.get("issue")
        if issue is not None and (not isinstance(issue, int) or isinstance(issue, bool) or issue < 1):
            raise ContractError(f"{node_id}.issue must be a positive integer when present")
        if state == "complete" and not evidence:
            raise ContractError(f"complete node {node_id!r} must cite repository evidence")
        nodes.append(node)
        by_id[node_id] = node

    if set(by_id) != PHASE_A_NODE_IDS:
        raise ContractError(
            "Phase A node identities must be exactly http2-over-noise, effective-acl, and data-plane"
        )

    validate_graph(nodes, by_id)

    for node_id, expected in EXPECTED_NODES.items():
        node = by_id[node_id]
        for field, expected_value in expected.items():
            if field == "issue" and expected_value is None and field in node:
                raise ContractError(
                    "data-plane.issue must remain absent; #118 tracks the producer contract, "
                    "not data-plane implementation"
                )
            if node.get(field) != expected_value:
                raise ContractError(
                    f"{node_id}.{field} must remain {expected_value!r}, got {node.get(field)!r}"
                )

    for node in nodes:
        for raw_evidence in node["evidence"]:
            evidence_path(
                raw_evidence,
                f"{node['id']} evidence",
                must_exist=True,
                must_be_tracked=True,
            )

    for gate_id in ("http2-over-noise", "effective-acl"):
        gate = by_id[gate_id]
        receipt = require_string(gate, "receipt", gate_id)
        receipt_path = evidence_path(
            receipt,
            f"{gate_id} receipt",
            must_exist=gate["state"] == "complete",
            must_be_tracked=gate["state"] == "complete",
        )
        expected_receipt = f"evidence/phase-a/{gate_id}.toml"
        if receipt != expected_receipt:
            raise ContractError(f"{gate_id}.receipt must remain {expected_receipt!r}")
        required_roles = require_unique_string_list(
            gate, "required_artifact_roles", gate_id
        )
        require_minimum(
            required_roles,
            MINIMUM_RECEIPT_ROLES[gate_id],
            f"{gate_id}.required_artifact_roles",
        )
        if gate["state"] == "complete":
            if gate["evidence"] != [receipt]:
                raise ContractError(f"complete gate {gate_id!r} must cite only its typed receipt")
            validate_receipt(gate_id, receipt_path, required_roles)

    data_plane = by_id["data-plane"]
    reserved_paths = require_unique_string_list(data_plane, "reserved_paths", "data-plane")
    forbidden_packages = require_unique_string_list(
        data_plane, "forbidden_packages", "data-plane"
    )
    forbidden_tokens = require_unique_string_list(
        data_plane, "forbidden_source_tokens", "data-plane"
    )
    require_minimum(reserved_paths, MINIMUM_RESERVED_PATHS, "data-plane.reserved_paths")
    require_minimum(
        forbidden_packages,
        MINIMUM_FORBIDDEN_PACKAGES,
        "data-plane.forbidden_packages",
    )
    require_minimum(
        forbidden_tokens,
        MINIMUM_FORBIDDEN_SOURCE_TOKENS,
        "data-plane.forbidden_source_tokens",
    )
    for raw_path in reserved_paths:
        relative = canonical_relative_path(raw_path, "data-plane reserved path")
        if not relative.is_relative_to(PurePosixPath("crates")):
            raise ContractError(f"data-plane reserved path must live under crates/: {raw_path}")

    if data_plane["state"] != "complete":
        validate_blocked_data_plane(data_plane)

    return phase, nodes


def tracked_repository_path(path: Path, description: str) -> Path:
    resolved = path.resolve()
    if not resolved.is_relative_to(ROOT):
        raise ContractError(f"{description} escapes the repository: {path}")
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    top_level = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    if top_level.returncode != 0 or Path(top_level.stdout.strip()).resolve() != ROOT:
        raise ContractError(f"{description} must belong to this Hamma git worktree")
    relative = resolved.relative_to(ROOT).as_posix()
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", relative],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if tracked.returncode != 0:
        raise ContractError(f"{description} must be tracked by git: {relative}")
    return resolved


def validate_commit(commit: str, description: str) -> None:
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if exists.returncode != 0:
        raise ContractError(f"{description} does not identify a commit in this Hamma repository")
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if ancestor.returncode != 0:
        raise ContractError(f"{description} must be an ancestor of the checked Hamma revision")


def artifact_at_commit(commit: str, relative: str, description: str) -> bytes:
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    blob = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
    )
    if blob.returncode != 0:
        raise ContractError(
            f"{description} must be tracked at producer_commit {commit}: {relative}"
        )
    return blob.stdout


def dependency_identities(manifest: dict[str, Any]) -> set[str]:
    identities: set[str] = set()

    def collect(table: object) -> None:
        if not isinstance(table, dict):
            return
        for alias, raw_spec in table.items():
            identities.add(str(alias))
            if isinstance(raw_spec, dict):
                package = raw_spec.get("package")
                if isinstance(package, str):
                    identities.add(package)

    for key in ("dependencies", "dev-dependencies", "build-dependencies"):
        collect(manifest.get(key))
    targets = manifest.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if isinstance(target, dict):
                for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                    collect(target.get(key))
    workspace = manifest.get("workspace")
    if isinstance(workspace, dict):
        collect(workspace.get("dependencies"))
    return identities


def validate_blocked_data_plane(data_plane: dict[str, Any]) -> None:
    reserved_paths = require_string_list(data_plane, "reserved_paths", "data-plane")
    forbidden_packages = set(
        require_string_list(data_plane, "forbidden_packages", "data-plane")
    )
    forbidden_tokens = require_string_list(
        data_plane, "forbidden_source_tokens", "data-plane"
    )

    for relative in reserved_paths:
        if os.path.lexists(ROOT / relative):
            raise ContractError(
                f"data-plane is blocked but reserved activation path exists: {relative}"
            )

    for manifest_path in ROOT.rglob("Cargo.toml"):
        relative_manifest = manifest_path.relative_to(ROOT)
        if any(part in {".git", "target"} for part in relative_manifest.parts):
            continue
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        forbidden = dependency_identities(manifest) & forbidden_packages
        if forbidden:
            names = ", ".join(sorted(forbidden))
            raise ContractError(
                f"data-plane is blocked but {relative_manifest} activates {names}"
            )

    for source_path in ROOT.rglob("*.rs"):
        relative_source = source_path.relative_to(ROOT)
        if any(part in {".git", "target"} for part in relative_source.parts):
            continue
        source = source_path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            if token in source:
                raise ContractError(
                    f"data-plane is blocked but {relative_source} contains {token!r}"
                )


def validate_receipt(gate_id: str, path: Path, required_roles: list[str]) -> None:
    if not path.is_file():
        raise ContractError(f"complete gate {gate_id!r} has no receipt at {path.relative_to(ROOT)}")
    path = tracked_repository_path(path, f"{gate_id} receipt")
    receipt = tomllib.loads(path.read_text(encoding="utf-8"))
    if receipt.get("schema") != 1 or receipt.get("gate") != gate_id:
        raise ContractError(f"{path.relative_to(ROOT)} must have schema=1 and gate={gate_id!r}")
    producer_commit = receipt.get("producer_commit")
    if (
        not isinstance(producer_commit, str)
        or len(producer_commit) != 40
        or any(character not in "0123456789abcdef" for character in producer_commit)
    ):
        raise ContractError(f"{path.relative_to(ROOT)} producer_commit must be a lowercase 40-hex SHA")
    validate_commit(producer_commit, f"{path.relative_to(ROOT)} producer_commit")
    oracle = receipt.get("oracle")
    if not isinstance(oracle, dict):
        raise ContractError(f"{path.relative_to(ROOT)} must contain an [oracle] table")
    oracle_name = require_string(oracle, "name", "oracle")
    oracle_repository = require_string(oracle, "repository", "oracle")
    oracle_revision = require_string(oracle, "revision", "oracle")
    if "forkwright/hamma" in oracle_repository.lower():
        raise ContractError(f"{path.relative_to(ROOT)} oracle must be independent of Hamma")
    if (
        len(oracle_revision) != 40
        or any(character not in "0123456789abcdef" for character in oracle_revision)
    ):
        raise ContractError(f"{path.relative_to(ROOT)} oracle revision must be lowercase 40-hex")
    if not oracle_name.strip():
        raise ContractError(f"{path.relative_to(ROOT)} oracle name cannot be blank")
    artifacts = receipt.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ContractError(f"{path.relative_to(ROOT)} must contain [[artifacts]]")
    observed_roles: list[str] = []
    observed_paths: set[str] = set()
    for index, raw_artifact in enumerate(artifacts):
        artifact = require_table(raw_artifact, f"{path.relative_to(ROOT)} artifacts[{index}]")
        role = require_string(artifact, "role", f"artifacts[{index}]")
        if role in observed_roles:
            raise ContractError(f"receipt contains duplicate artifact role {role!r}")
        observed_roles.append(role)
        raw_artifact_path = require_string(artifact, "path", f"artifacts[{index}]")
        if raw_artifact_path in observed_paths:
            raise ContractError(f"receipt contains duplicate artifact path {raw_artifact_path!r}")
        observed_paths.add(raw_artifact_path)
        expected_sha = require_string(artifact, "sha256", f"artifacts[{index}]")
        if len(expected_sha) != 64 or any(character not in "0123456789abcdef" for character in expected_sha):
            raise ContractError(f"artifact {raw_artifact_path!r} sha256 must be lowercase 64-hex")
        resolved = evidence_path(
            raw_artifact_path,
            f"{gate_id} artifact {role}",
            must_exist=True,
            must_be_tracked=True,
            subtree=PurePosixPath(f"evidence/phase-a/{gate_id}"),
        )
        actual_sha = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if actual_sha != expected_sha:
            raise ContractError(
                f"receipt artifact hash mismatch for {raw_artifact_path}: "
                f"{actual_sha} != {expected_sha}"
            )
        producer_bytes = artifact_at_commit(
            producer_commit,
            raw_artifact_path,
            f"{gate_id} artifact {role}",
        )
        producer_sha = hashlib.sha256(producer_bytes).hexdigest()
        if producer_sha != expected_sha:
            raise ContractError(
                f"receipt artifact provenance mismatch for {raw_artifact_path}: "
                f"producer_commit has {producer_sha}, receipt names {expected_sha}"
            )
    if set(observed_roles) != set(required_roles):
        raise ContractError(
            f"{gate_id} artifact roles must be {sorted(required_roles)!r}, "
            f"got {sorted(observed_roles)!r}"
        )


def markdown_projection(phase: dict[str, Any], nodes: list[dict[str, Any]]) -> str:
    lines = [
        MARKER_START,
        phase["summary"],
        "",
        "| Order | Gate | Tracker | State | Requires | Evidence |",
        "|---:|---|---|---|---|---|",
    ]
    for index, node in enumerate(nodes, start=1):
        issue = node.get("issue")
        tracker = (
            f"[#{issue}](https://github.com/forkwright/hamma/issues/{issue})" if issue else "—"
        )
        requires = ", ".join(f"`{item}`" for item in node["requires"]) or "—"
        evidence = ", ".join(f"[`{item}`]({item})" for item in node["evidence"]) or "—"
        lines.append(
            f"| {index} | `{node['id']}` — {node['title']} | {tracker} | "
            f"`{node['state']}` | {requires} | {evidence} |"
        )
    lines.extend(
        [
            "",
            "While `data-plane` is blocked, the checker rejects every listed reserved activation "
            "path, dependency identity, and source token, and contract validation refuses to "
            "shrink those minimum guard sets. This bounded enforcement does not replace review "
            "for other ways a change could introduce a data plane.",
            "The public contract, not private planning prose, owns this producer order.",
            "",
            "Source: [`contracts/phase-a.toml`](contracts/phase-a.toml). Regenerate with "
            "`python3 tools/render_phase_a.py --apply`; CI runs `--check`.",
            MARKER_END,
        ]
    )
    return "\n".join(lines)


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def state_projection(phase: dict[str, Any], nodes: list[dict[str, Any]]) -> str:
    lines = [
        "# Generated by tools/render_phase_a.py from contracts/phase-a.toml.",
        "# Do not edit this file directly.",
        "",
        "[meta]",
        'name = "hamma"',
        'repo = "forkwright/hamma"',
        "generated = true",
        'source = "contracts/phase-a.toml"',
        "",
        "[state]",
        f"summary = {toml_string(phase['summary'])}",
        f"current_phase = {toml_string(phase['title'])}",
    ]
    for node in nodes:
        lines.extend(
            [
                "",
                "[[gates]]",
                f"id = {toml_string(node['id'])}",
                f"title = {toml_string(node['title'])}",
                f"kind = {toml_string(node['kind'])}",
                f"state = {toml_string(node['state'])}",
                "requires = ["
                + ", ".join(toml_string(item) for item in node["requires"])
                + "]",
                "evidence = ["
                + ", ".join(toml_string(item) for item in node["evidence"])
                + "]",
            ]
        )
        if "issue" in node:
            lines.append(f"issue = {node['issue']}")
    return "\n".join(lines) + "\n"


def replace_block(path: Path, rendered: str) -> str:
    current = path.read_text(encoding="utf-8")
    start = current.find(MARKER_START)
    end = current.find(MARKER_END)
    if start < 0 or end < 0 or end < start:
        raise ContractError(f"{path.relative_to(ROOT)} must contain one bounded Phase A block")
    if current.find(MARKER_START, start + 1) >= 0 or current.find(MARKER_END, end + 1) >= 0:
        raise ContractError(f"{path.relative_to(ROOT)} contains duplicate Phase A markers")
    end += len(MARKER_END)
    return current[:start] + rendered + current[end:]


def desired_files() -> dict[Path, str]:
    phase, nodes = read_contract()
    rendered = markdown_projection(phase, nodes)
    desired = {path: replace_block(path, rendered) for path in DOC_TARGETS}
    desired[STATE_TARGET] = state_projection(phase, nodes)
    return desired


def check(desired: dict[Path, str]) -> int:
    drifted = False
    for path, expected in desired.items():
        actual = path.read_text(encoding="utf-8")
        if actual == expected:
            continue
        drifted = True
        relative = path.relative_to(ROOT).as_posix()
        sys.stdout.writelines(
            difflib.unified_diff(
                actual.splitlines(keepends=True),
                expected.splitlines(keepends=True),
                fromfile=relative,
                tofile=f"{relative} (generated)",
            )
        )
    return 1 if drifted else 0


def apply(desired: dict[Path, str]) -> None:
    staged: list[tuple[Path, Path]] = []
    try:
        for path, content in desired.items():
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=path.parent,
                prefix=f".{path.name}.",
                delete=False,
            ) as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
                staged.append((Path(handle.name), path))
        for temporary, destination in staged:
            os.replace(temporary, destination)
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)


def main() -> int:
    if sys.argv[1:] not in (["--check"], ["--apply"]):
        print("usage: tools/render_phase_a.py --check|--apply", file=sys.stderr)
        return 2
    try:
        desired = desired_files()
        if sys.argv[1] == "--check":
            return check(desired)
        apply(desired)
        return check(desired_files())
    except (ContractError, OSError, tomllib.TOMLDecodeError) as error:
        print(f"phase-a contract error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
