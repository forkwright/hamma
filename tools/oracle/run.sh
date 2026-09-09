#!/usr/bin/env bash
# Drive the hamma TS2021 oracle harness: boot headscale in a container, run the
# witness (success + mismatch cases), validate and place the receipt.
#
# Usage: tools/oracle/run.sh [out-dir]   (default: evidence/phase-a/oracle)
set -euo pipefail

OUT="${1:-evidence/phase-a/oracle}"
# WHY 0.23: headscale 0.26 rejects clients below tailscale v1.62's capability
# version, and dictyon deliberately pins CAPABILITY_VERSION=71 (see
# mitos/src/capability.rs's WHY). 0.23 accepts v71; the 0.26 rejection is real
# wire truth worth capturing separately, but the success witness needs 0.23.
IMAGE="${HAMMA_ORACLE_IMAGE:-docker.io/headscale/headscale:0.23}"
# GitHub runners carry docker; menos carries podman. Both speak the same run/
# rm/logs CLI subset used here.
OCI="${HAMMA_ORACLE_ENGINE:-$(command -v podman >/dev/null && echo podman || echo docker)}"
# SELinux-enforcing hosts (menos) need the :Z volume label; docker on CI
# runners tolerates it, but only add it when actually enforcing.
VOL_LABEL=""
if command -v getenforce >/dev/null && [ "$(getenforce)" = "Enforcing" ]; then
  VOL_LABEL=",Z"
fi
# WHY 18089: 8089 is menos's llama-server; pick a port nothing else owns.
PORT="${HAMMA_ORACLE_PORT:-18089}"
NAME="hamma-oracle-$$"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# WHY not /tmp: tmpfs bind-mounts come up EMPTY inside rootless podman
# containers on this box (measured 2026-09-09); the workspace must live on a
# real filesystem.
mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}"
WORK="$(mktemp -d -p "${XDG_CACHE_HOME:-$HOME/.cache}" hamma-oracle.XXXXXX)"
chmod 755 "$WORK"
trap '"$OCI" rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

echo "== oracle harness: $IMAGE on 127.0.0.1:$PORT, evidence -> $OUT"

# 1. Harness CA + server cert (SAN IP:127.0.0.1) via openssl.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=hamma-oracle-ca" \
  -keyout "$WORK/ca.key" -out "$WORK/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" \
  -keyout "$WORK/server.key" -out "$WORK/server.csr" 2>/dev/null
printf "subjectAltName=IP:127.0.0.1,DNS:localhost\n" > "$WORK/san.cnf"
openssl x509 -req -in "$WORK/server.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
  -CAcreateserial -days 1 -extfile "$WORK/san.cnf" -out "$WORK/server.crt" 2>/dev/null

# 2. config first: even `headscale generate private-key` loads the config in
#    its CLI pre-run, so the config mount must exist for every invocation.
cp "$ROOT/tools/oracle/headscale-config.yaml" "$WORK/config.yaml"
cp "$ROOT/tools/oracle/derpmap.yaml" "$WORK/derpmap.yaml"
mkdir -p "$WORK/db"
"$OCI" run --rm -v "$WORK:/etc/headscale:ro$VOL_LABEL" "$IMAGE" generate private-key 2>/dev/null \
  | grep '^privkey:' > "$WORK/noise_private.key"
[ -s "$WORK/noise_private.key" ] || { echo "noise key generation failed" >&2; exit 1; }

# 3. Boot headscale.
"$OCI" run -d --name "$NAME" -p 127.0.0.1:$PORT:8080 \
  -v "$WORK:/etc/headscale:ro$VOL_LABEL" -v "$WORK/db:/var/lib/headscale:rw$VOL_LABEL" \
  "$IMAGE" serve >/dev/null

# 4. Wait for the key endpoint to answer over TLS.
for i in $(seq 1 60); do
  if curl -sf --cacert "$WORK/ca.pem" "https://127.0.0.1:$PORT/key?v=71" >/dev/null 2>&1; then
    break
  fi
  sleep 1
  if [ "$i" = 60 ]; then
    echo "oracle never became ready" >&2
    "$OCI" logs "$NAME" 2>&1 | tail -20 >&2 || true
    exit 1
  fi
done
echo "== oracle ready"

# 5. Witness: success case.
cargo run -p dictyon --example oracle_witness -- \
  --url "https://127.0.0.1:$PORT" --ca-cert "$WORK/ca.pem" \
  --out "$ROOT/$OUT"
# 6. Witness: mismatch case (wrong capability prologue must be refused).
cargo run -p dictyon --example oracle_witness -- \
  --url "https://127.0.0.1:$PORT" --ca-cert "$WORK/ca.pem" \
  --out "$ROOT/$OUT" --mismatch

# 7. Receipt: hash artifacts, bind oracle identity + producer commit.
python3 "$ROOT/tools/oracle/write_receipt.py" "$ROOT/$OUT" "$IMAGE"
python3 "$ROOT/tools/oracle/validate_receipt.py" "$ROOT/$OUT"
echo "== oracle harness done: $OUT"
