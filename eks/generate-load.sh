#!/usr/bin/env bash
# Fire Bedrock traffic on demand from inside the cluster, one Job per key.
#
#   ./eks/generate-load.sh --workload checkout-agent --requests 300
#   ./eks/generate-load.sh --all --requests 100
#   ./eks/generate-load.sh --workload fraud-scorer --requests 2000 --concurrency 8   # threshold burst
#   ./eks/generate-load.sh --logs checkout-agent
#   ./eks/generate-load.sh --clean
#
# Jobs are one-shot: the cluster sits idle between tests, which matters because
# a t3.small node caps at ~11 pods and kube-system plus the Attribute DaemonSet
# already take about five.
set -euo pipefail

NAMESPACE="bedrock-load"
IMAGE="public.ecr.aws/docker/library/python:3.12-alpine"
WORKLOADS=(checkout-agent support-summarizer doc-indexer fraud-scorer chat-assistant batch-enricher)

WORKLOAD=""
REQUESTS=100
CONCURRENCY=4
MAX_TOKENS=64
DELAY_MS=0
MODEL="amazon.nova-micro-v1:0"
ALL=0
CLEAN=0
FOLLOW_LOGS=""

die()  { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32mOK\033[0m %s\n' "$1"; }
info() { printf '  %s\n' "$1"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workload)    WORKLOAD="${2:-}"; shift 2 ;;
    --requests)    REQUESTS="${2:-}"; shift 2 ;;
    --concurrency) CONCURRENCY="${2:-}"; shift 2 ;;
    --max-tokens)  MAX_TOKENS="${2:-}"; shift 2 ;;
    --delay-ms)    DELAY_MS="${2:-}"; shift 2 ;;
    --model)       MODEL="${2:-}"; shift 2 ;;
    --namespace)   NAMESPACE="${2:-}"; shift 2 ;;
    --all)         ALL=1; shift ;;
    --clean)       CLEAN=1; shift ;;
    --logs)        FOLLOW_LOGS="${2:-}"; shift 2 ;;
    -h|--help)     sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

command -v kubectl >/dev/null || die "kubectl not found"
kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 \
  || die "namespace '$NAMESPACE' not found -- run ./eks/provision-keys.sh first"

if (( CLEAN )); then
  step "Removing load jobs"
  kubectl delete jobs -n "$NAMESPACE" -l app.kubernetes.io/part-of=attribute-bedrock-test --ignore-not-found=true
  ok "cleaned"
  exit 0
fi

if [[ -n "$FOLLOW_LOGS" ]]; then
  pod="$(kubectl get pods -n "$NAMESPACE" -l workload="$FOLLOW_LOGS" \
    --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}' 2>/dev/null)"
  [[ -n "$pod" ]] || die "no pod found for workload '$FOLLOW_LOGS'"
  exec kubectl logs -n "$NAMESPACE" -f "$pod"
fi

kubectl get configmap bedrock-load-script -n "$NAMESPACE" >/dev/null 2>&1 \
  || die "ConfigMap missing -- run: kubectl apply -f eks/load-generator.yaml"

targets=()
if (( ALL )); then
  targets=("${WORKLOADS[@]}")
elif [[ -n "$WORKLOAD" ]]; then
  targets=("$WORKLOAD")
else
  die "specify --workload <name> or --all (known: ${WORKLOADS[*]})"
fi

launch() {
  local w="$1"
  kubectl get secret "bedrock-key-${w}" -n "$NAMESPACE" >/dev/null 2>&1 \
    || die "no secret for workload '$w' -- run ./eks/provision-keys.sh"

  # Unique suffix so repeated runs do not collide.
  local job="load-${w}-$(date +%H%M%S)"

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
              value: "${REQUESTS}"
            - name: CONCURRENCY
              value: "${CONCURRENCY}"
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
  ok "$w -> job/${job}  (${REQUESTS} requests, concurrency ${CONCURRENCY})"
}

step "Launching load"
for w in "${targets[@]}"; do launch "$w"; done

printf '\n  Watch:   kubectl get pods -n %s -w\n' "$NAMESPACE"
printf '  Logs:    ./eks/generate-load.sh --logs %s\n' "${targets[0]}"
printf '  Clean:   ./eks/generate-load.sh --clean\n'
