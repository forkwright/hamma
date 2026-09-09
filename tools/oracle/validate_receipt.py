#!/usr/bin/env python3
"""Validate an oracle receipt: schema fields present, artifact hashes match,
outcome invariants hold. Runs in CI so a stale or fabricated receipt fails."""
import hashlib
import sys
import tomllib
from pathlib import Path


def main() -> int:
    out_dir = Path(sys.argv[1])
    receipt_path = out_dir / "receipt.toml"
    if not receipt_path.exists():
        print(f"missing receipt: {receipt_path}", file=sys.stderr)
        return 1
    receipt = tomllib.loads(receipt_path.read_text())

    errors = []
    for field in ("schema", "producer_commit", "created_at"):
        if field not in receipt:
            errors.append(f"missing field: {field}")
    oracle = receipt.get("oracle", {})
    for field in ("identity", "digest", "independence"):
        if field not in oracle:
            errors.append(f"missing oracle field: {field}")
    outcome = receipt.get("outcome", {})
    if outcome.get("success_case_completed") is not True:
        errors.append("outcome.success_case_completed is not true")
    if outcome.get("mismatch_case_refused") is not True:
        errors.append("outcome.mismatch_case_refused is not true")

    artifacts = receipt.get("artifacts", {})
    for role in ("success_transcript", "mismatch_transcript"):
        entry = artifacts.get(role)
        if not entry:
            errors.append(f"missing artifact role: {role}")
            continue
        artifact_path = out_dir / entry["path"]
        if not artifact_path.exists():
            errors.append(f"artifact file missing: {entry['path']}")
            continue
        actual = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            errors.append(f"hash mismatch on {entry['path']}: {actual} != {entry['sha256']}")

    if errors:
        for error in errors:
            print(f"INVALID: {error}", file=sys.stderr)
        return 1
    print(f"receipt valid: {receipt_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
