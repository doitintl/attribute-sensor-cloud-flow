#!/usr/bin/env bash
# Fire Bedrock traffic on demand from inside the cluster, one Job per key.
#
# Uniform load:
#   ./eks/generate-load.sh --workload checkout-agent --requests 300
#   ./eks/generate-load.sh --all --requests 100
#
# Non-uniform -- five keys at baseline, one spiking (the threshold scenario):
#   ./eks/generate-load.sh --baseline 50 --spike fraud-scorer:3000
#   ./eks/generate-load.sh --baseline 50 --spike fraud-scorer:3000 --spike chat-assistant:800
#
# Explicit per-key counts:
#   ./eks/generate-load.sh --mix "checkout-agent=40,fraud-scorer=2500,doc-indexer=60"
#
#   ./eks/generate-load.sh --logs fraud-scorer
#   ./eks/generate-load.sh --clean
#
# Baseline keys get +/- jitter by default so the five "normal" workloads are not
# suspiciously identical -- real baselines never are, and an anomaly detector
# tuned against identical traffic is not being tested honestly.
#
# Jobs are one-shot: the cluster sits idle between tests, which matters because
# a t3.small node caps at ~11 pods and kube-system plus the Attribute DaemonSet
# already take about five.
set -euo pipefail

NAMESPACE="bedrock-load"
IMAGE="public.ecr.aws/docker/library/python:3.12-alpine"
WORKLOADS="checkout-agent support-summarizer doc-indexer fraud-scorer chat-assistant batch-enricher"

WORKLOAD=""
REQUESTS=100
CONCURRENCY=4
SPIKE_CONCURRENCY=8
MAX_TOKENS=64
DELAY_MS=0
BASELINE=""
JITTER_PCT=20
MIX=""
SPIKES=""
MODEL="amazon.nova-micro-v1:0"
ALL=0
CLEAN=0
DRY_RUN=0
FOLLOW_LOGS=""

die()  { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32mOK\033[0m %s\n' "$1"; }
info() { printf '  %s\n' "$1"; }

known_workload() {
  for w in $WORKLOADS; do [ "$w" = "$1" ] && return 0; done
  return 1
}

# base +/- pct, minimum 1
jitter() {
  local base="$1" pct="$2"
  if [ "$pct" -le 0 ]; then printf '%s' "$base"; return; fi
  local span=$(( 2 * pct ))
  local factor=$(( 100 - pct + (RANDOM % (span + 1)) ))
  local out=$(( (base * factor + 50) / 100 ))
  [ "$out" -lt 1 ] && out=1
  printf '%s' "$out"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --workload)          WORKLOAD="${2:-}"; shift 2 ;;
    --requests)          REQUESTS="${2:-}"; shift 2 ;;
    --concurrency)       CONCURRENCY="${2:-}"; shift 2 ;;
    --spike-concurrency) SPIKE_CONCURRENCY="${2:-}"; shift 2 ;;
    --baseline)          BASELINE="${2:-}"; shift 2 ;;
    --spike)             SPIKES="${SPIKES} ${2:-}"; shift 2 ;;
    --jitter-pct)        JITTER_PCT="${2:-}"; shift 2 ;;
    --mix)               MIX="${2:-}"; shift 2 ;;
    --max-tokens)        MAX_TOKENS="${2:-}"; shift 2 ;;
    --delay-ms)          DELAY_MS="${2:-}"; shift 2 ;;
    --model)             MODEL="${2:-}"; shift 2 ;;
    --namespace)         NAMESPACE="${2:-}"; shift 2 ;;
    --all)               ALL=1; shift ;;
    --clean)             CLEAN=1; shift ;;
    --dry-run)           DRY_RUN=1; shift ;;
    --logs)              FOLLOW_LOGS="${2:-}"; shift 2 ;;
    -h|--help)           sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

command -v kubectl >/dev/null || die "kubectl not found"

if [ "$CLEAN" -eq 1 ]; then
  step "Removing load jobs"
  kubectl delete jobs -n "$NAMESPACE" -l app.kubernetes.io/part-of=attribute-bedrock-test --ignore-not-found=true
  ok "cleaned"
  exit 0
fi

if [ -n "$FOLLOW_LOGS" ]; then
  pod="$(kubectl get pods -n "$NAMESPACE" -l workload="$FOLLOW_LOGS" \
    --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}' 2>/dev/null || true)"
  [ -n "$pod" ] || die "no pod found for workload '$FOLLOW_LOGS'"
  exec kubectl logs -n "$NAMESPACE" -f "$pod"
fi

if [ "$DRY_RUN" -eq 0 ]; then
  kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 \
    || die "namespace '$NAMESPACE' not found -- run ./eks/provision-keys.sh first"
  kubectl get configmap bedrock-load-script -n "$NAMESPACE" >/dev/null 2>&1 \
    || die "ConfigMap missing -- run: kubectl apply -f eks/load-generator.yaml"
fi

# --- build the plan: one "workload|requests|concurrency" record per line -----

PLAN=""
add_plan() { PLAN="${PLAN}${1}|${2}|${3}
"; }

if [ -n "$MIX" ]; then
  # Explicit counts. Only the named workloads run.
  OLD_IFS="$IFS"; IFS=','
  for pair in $MIX; do
    IFS="$OLD_IFS"
    w="${pair%%=*}"; n="${pair#*=}"
    w="$(printf '%s' "$w" | tr -d ' ')"; n="$(printf '%s' "$n" | tr -d ' ')"
    [ -n "$w" ] && [ -n "$n" ] || die "bad --mix entry '$pair' (want workload=count)"
    known_workload "$w" || die "unknown workload '$w' (known: $WORKLOADS)"
    case "$n" in (*[!0-9]*|"") die "bad count '$n' for '$w'" ;; esac
    c="$CONCURRENCY"; [ "$n" -ge 500 ] && c="$SPIKE_CONCURRENCY"
    add_plan "$w" "$n" "$c"
    IFS=','
  done
  IFS="$OLD_IFS"

elif [ -n "$BASELINE" ] || [ -n "$SPIKES" ]; then
  # Baseline for everyone, overridden for spiked workloads.
  [ -n "$BASELINE" ] || BASELINE=50
  case "$BASELINE" in (*[!0-9]*|"") die "--baseline must be a number" ;; esac

  for spec in $SPIKES; do
    w="${spec%%:*}"; n="${spec#*:}"
    [ "$w" != "$spec" ] || die "bad --spike '$spec' (want workload:count)"
    known_workload "$w" || die "unknown workload '$w' (known: $WORKLOADS)"
    case "$n" in (*[!0-9]*|"") die "bad spike count '$n' for '$w'" ;; esac
  done

  for w in $WORKLOADS; do
    n=""
    for spec in $SPIKES; do
      [ "${spec%%:*}" = "$w" ] && n="${spec#*:}"
    done
    if [ -n "$n" ]; then
      add_plan "$w" "$n" "$SPIKE_CONCURRENCY"
    else
      add_plan "$w" "$(jitter "$BASELINE" "$JITTER_PCT")" "$CONCURRENCY"
    fi
  done

elif [ "$ALL" -eq 1 ]; then
  for w in $WORKLOADS; do add_plan "$w" "$REQUESTS" "$CONCURRENCY"; done

elif [ -n "$WORKLOAD" ]; then
  known_workload "$WORKLOAD" || die "unknown workload '$WORKLOAD' (known: $WORKLOADS)"
  add_plan "$WORKLOAD" "$REQUESTS" "$CONCURRENCY"

else
  die "specify --workload <name>, --all, --baseline/--spike, or --mix (known: $WORKLOADS)"
fi

# --- show the plan before spending anything ---------------------------------

step "Plan"
printf '  %-22s %10s %8s %10s\n' WORKLOAD REQUESTS CONCUR "VS MIN"
printf '  %-22s %10s %8s %10s\n' "----------------------" "--------" "------" "--------"

MIN=""
while IFS='|' read -r w n c; do
  [ -n "$w" ] || continue
  if [ -z "$MIN" ] || [ "$n" -lt "$MIN" ]; then MIN="$n"; fi
done <<EOF
$PLAN
EOF

TOTAL=0
while IFS='|' read -r w n c; do
  [ -n "$w" ] || continue
  TOTAL=$(( TOTAL + n ))
  mult=$(( (n * 10 + MIN / 2) / MIN ))
  printf '  %-22s %10s %8s %8s.%sx\n' "$w" "$n" "$c" "$(( mult / 10 ))" "$(( mult % 10 ))"
done <<EOF
$PLAN
EOF

printf '\n  total API calls this run: %s\n' "$TOTAL"
printf '  each call is ~45 input tokens + up to %s output\n' "$MAX_TOKENS"
printf '  approx tokens: %s\n' "$(( TOTAL * (45 + MAX_TOKENS) ))"

if [ "$DRY_RUN" -eq 1 ]; then
  printf '\n  (dry run -- nothing launched)\n'
  exit 0
fi

# --- launch ------------------------------------------------------------------

launch() {
  w="$1"; n="$2"; c="$3"
  kubectl get secret "bedrock-key-${w}" -n "$NAMESPACE" >/dev/null 2>&1 \
    || die "no secret for workload '$w' -- run ./eks/provision-keys.sh"

  job="load-${w}-$(date +%H%M%S)-$$"
  job="$(printf '%s' "$job" | cut -c1-63)"

  kubectl apply -f - >/dev/null <<YAML
apiVersion: batch/v1
kind: Job
metadata:
  name: ${job}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/part-of: attribute-bedrock-test
    workload: ${w}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 3600
  template:
    metadata:
      labels:
        app.kubernetes.io/part-of: attribute-bedrock-test
        workload: ${w}
    spec:
      restartPolicy: Never
      containers:
        - name: load
          image: ${IMAGE}
          command: ["python3", "/script/load.py"]
          env:
            - name: REQUESTS
              value: "${n}"
            - name: CONCURRENCY
              value: "${c}"
            - name: MAX_TOKENS
              value: "${MAX_TOKENS}"
            - name: DELAY_MS
              value: "${DELAY_MS}"
            - name: MODEL_ID
              value: "${MODEL}"
            - name: AWS_REGION
              value: "us-east-1"
          envFrom:
            - secretRef:
                name: bedrock-key-${w}
          volumeMounts:
            - name: script
              mountPath: /script
          resources:
            requests: { cpu: "50m",  memory: "64Mi" }
            limits:   { cpu: "300m", memory: "192Mi" }
      volumes:
        - name: script
          configMap:
            name: bedrock-load-script
YAML
  ok "$w -> job/${job}"
}

step "Launching"
FIRST=""
while IFS='|' read -r w n c; do
  [ -n "$w" ] || continue
  [ -n "$FIRST" ] || FIRST="$w"
  launch "$w" "$n" "$c"
done <<EOF
$PLAN
EOF

printf '\n  Watch:   kubectl get pods -n %s -w\n' "$NAMESPACE"
printf '  Logs:    ./eks/generate-load.sh --logs %s\n' "$FIRST"
printf '  Clean:   ./eks/generate-load.sh --clean\n'
