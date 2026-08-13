#!/usr/bin/env bash
# Fire a synthetic Attribute alert, either at the adapter or straight at the
# CloudFlow webhook. Use this to prove the trigger path works before Attribute
# is wired up.
#
#   # straight at CloudFlow (no adapter yet) -- posts the contract sample
#   DOIT_API_TOKEN=... ./tools/simulate-alert.sh --cloudflow "$WEBHOOK_URL"
#
#   # at the adapter, HMAC-signed like Attribute would
#   ATTRIBUTE_SIGNING_SECRET=... ./tools/simulate-alert.sh --adapter "$ADAPTER_URL"
#
#   # pick a signal to exercise a different tier
#   ... --adapter "$URL" --signal token_spike --severity warning
#
# Secrets come from the environment only, never argv, so they stay out of the
# process list and shell history.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MODE=""
TARGET_URL=""
SIGNAL="runaway_agent"
SEVERITY="critical"
CREDENTIAL=""
DRY_RUN=0

die() { printf 'error: %s\n' "$1" >&2; exit 1; }

usage() {
  sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cloudflow) MODE=cloudflow; TARGET_URL="${2:-}"; shift 2 ;;
    --adapter)   MODE=adapter;   TARGET_URL="${2:-}"; shift 2 ;;
    --signal)    SIGNAL="${2:-}"; shift 2 ;;
    --severity)  SEVERITY="${2:-}"; shift 2 ;;
    --credential) CREDENTIAL="${2:-}"; shift 2 ;;
    --dry-run)   DRY_RUN=1; shift ;;
    -h|--help)   usage 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[[ -n "$MODE" ]]       || usage 1
[[ -n "$TARGET_URL" ]] || die "no target URL given"
command -v curl >/dev/null || die "curl not found"
command -v python3 >/dev/null || die "python3 not found"

# ULID-ish unique id so repeated runs are not deduped by idempotency_key.
ALERT_ID="atr_sim_$(date -u +%Y%m%dT%H%M%SZ)_$RANDOM"
DETECTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [[ "$MODE" == cloudflow ]]; then
  # Post the contract sample verbatim: it is exactly the shape the adapter
  # produces, so a 2xx here proves the trigger's Sample JSON is configured
  # correctly and downstream field references will resolve.
  [[ -n "${DOIT_API_TOKEN:-}" ]] || die "DOIT_API_TOKEN is not set"

  BODY="$(python3 - "$REPO_ROOT" "$ALERT_ID" "$DETECTED_AT" <<'PY'
import json, pathlib, sys
root, alert_id, detected_at = sys.argv[1], sys.argv[2], sys.argv[3]
sample = json.loads(
    (pathlib.Path(root) / "contracts" / "cloudflow-trigger.v1.sample.json").read_text()
)
payload = {k: v for k, v in sample.items() if not k.startswith("_")}
payload["alert_id"] = alert_id
payload["idempotency_key"] = f"{alert_id}:tier{payload['tier']}"
payload["detected_at"] = detected_at
payload["reason"] = "SIMULATED alert from tools/simulate-alert.sh -- not a real incident"
print(json.dumps(payload))
PY
)"

  if (( DRY_RUN )); then printf '%s\n' "$BODY" | python3 -m json.tool; exit 0; fi

  printf 'POST %s (alert_id=%s)\n' "$TARGET_URL" "$ALERT_ID" >&2
  curl -sS -X POST "$TARGET_URL" \
    -H "Authorization: Bearer ${DOIT_API_TOKEN}" \
    -H "Content-Type: application/json" \
    -w '\nHTTP %{http_code}\n' \
    --data-binary "$BODY"
  exit $?
fi

# --- adapter mode: build an inbound Attribute alert and HMAC-sign it ---------

[[ -n "${ATTRIBUTE_SIGNING_SECRET:-}" ]] || die "ATTRIBUTE_SIGNING_SECRET is not set"

if [[ -z "$CREDENTIAL" ]]; then
  # Synthetic ABSK key for a throwaway identity. Resolves to IAM user
  # "BedrockAPIKey-simulated" in account 000000000000, which will not exist --
  # so the flow's lookup fails safely rather than touching a real credential.
  CREDENTIAL="$(python3 - <<'PY'
import base64
raw = b"BedrockAPIKey-simulated+1-at-000000000000:" + b"S" * 44
print("ABSK" + base64.b64encode(raw).decode().rstrip("="))
PY
)"
fi

BODY="$(python3 - "$ALERT_ID" "$DETECTED_AT" "$SIGNAL" "$SEVERITY" "$CREDENTIAL" <<'PY'
import json, sys
alert_id, detected_at, signal, severity, credential = sys.argv[1:6]
print(json.dumps({
    "alert_id": alert_id,
    "detected_at": detected_at,
    "severity": severity,
    "signal": signal,
    "reason": "SIMULATED alert from tools/simulate-alert.sh -- not a real incident",
    "provider": "bedrock",
    "credential": credential,
    "workload_name": "simulated-workload",
    "principal_type": "non_human",
    "observed_spend_usd": 4820.5,
    "observed_window_minutes": 5,
}))
PY
)"

SIGNATURE="$(
  REPO_ROOT="$REPO_ROOT" \
  ATTRIBUTE_SIGNING_SECRET="$ATTRIBUTE_SIGNING_SECRET" \
  SIM_BODY="$BODY" \
  python3 -c '
import os, sys, time
sys.path.insert(0, os.environ["REPO_ROOT"])
from adapter.signature import sign
print(sign(os.environ["SIM_BODY"].encode(), os.environ["ATTRIBUTE_SIGNING_SECRET"], int(time.time())))
'
)"

if (( DRY_RUN )); then
  printf '%s\n' "$BODY" | python3 -m json.tool
  printf 'X-Attribute-Signature: %s\n' "$SIGNATURE"
  exit 0
fi

printf 'POST %s (alert_id=%s signal=%s/%s)\n' "$TARGET_URL" "$ALERT_ID" "$SIGNAL" "$SEVERITY" >&2
curl -sS -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -H "X-Attribute-Signature: ${SIGNATURE}" \
  -w '\nHTTP %{http_code}\n' \
  --data-binary "$BODY"
