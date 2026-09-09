# Phase A evidence

Hash-bound receipts proving hamma's protocol claims against an independent
oracle. Nothing in this directory is hand-authored: artifacts and receipts are
written by `tools/oracle/run.sh` (headscale harness) and validated by
`tools/oracle/validate_receipt.py` in CI.

## Receipt schema (`receipt.toml`, schema = 1)

| Field | Meaning |
|---|---|
| `created_at` | ISO-8601 generation time |
| `producer_commit` | the exact hamma commit that produced the artifacts |
| `oracle.identity` / `oracle.digest` | the oracle image and its content digest |
| `oracle.independence` | why this oracle shares no code with the producer |
| `artifacts.*` | per-artifact path + SHA-256; validator recomputes |
| `outcome.*` | the invariants the run proved (e.g. success completed, mismatch refused) |

Regenerate evidence on any capability-version, prologue, or handshake-path
change; a stale receipt is worse than none.
