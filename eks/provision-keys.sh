#!/usr/bin/env bash
# Mint six Bedrock API keys, one per simulated workload, and load them into the
# cluster as Kubernetes Secrets.
#
#   ./eks/provision-keys.sh --profile attrb-admin
#   ./eks/provision-keys.sh --profile attrb-admin --destroy
#
# Each key belongs to its own IAM user so the enforcement flow can contain one
# workload without touching the other five -- which is the whole scenario.
#
# Key values are written straight into Kubernetes Secrets and never printed,
# echoed, or saved to disk. IAM returns a key value only at creation; if you
# lose it you must reset the credential.
set -euo pipefail

PROFILE=""
REGION="us-east-1"
NAMESPACE="bedrock-load"
USER_PREFIX="attrb-load"
DESTROY=0

# Personas, so spend in Attribute reads as recognisable workloads rather than
# six identical rows. Keep the names DNS-safe: they become Secret names.
WORKLOADS=(
  "checkout-agent"
  "support-summarizer"
  "doc-indexer"
  "fraud-scorer"
  "chat-assistant"
  "batch-enricher"
)

die()  { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32mOK\033[0m %s\n' "$1"; }
info() { printf '  %s\n' "$1"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)   PROFILE="${2:-}"; shift 2 ;;
    --region)    REGION="${2:-}"; shift 2 ;;
    --namespace) NAMESPACE="${2:-}"; shift 2 ;;
    --destroy)   DESTROY=1; shift ;;
    -h|--help)   sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$PROFILE" ]] || die "--profile is required"
command -v aws >/dev/null     || die "aws CLI not found"
command -v kubectl >/dev/null || die "kubectl not found"
command -v jq >/dev/null      || die "jq not found"

AWS=(aws --profile "$PROFILE" --region "$REGION" --output json)

ACCOUNT="$("${AWS[@]}" sts get-caller-identity --query Account --output text)" \
  || die "cannot authenticate; try: aws sso login --profile $PROFILE"
info "account: $ACCOUNT   region: $REGION   namespace: $NAMESPACE"

# --- destroy -----------------------------------------------------------------

if (( DESTROY )); then
  step "Removing Bedrock keys and IAM users"
  for w in "${WORKLOADS[@]}"; do
    user="${USER_PREFIX}-${w}"
    creds="$("${AWS[@]}" iam list-service-specific-credentials --user-name "$user" \
      --service-name bedrock.amazonaws.com \
      --query 'ServiceSpecificCredentials[].ServiceSpecificCredentialId' --output text 2>/dev/null || true)"
    for c in $creds; do
      "${AWS[@]}" iam delete-service-specific-credential --user-name "$user" \
        --service-specific-credential-id "$c" >/dev/null 2>&1 || true
    done
    "${AWS[@]}" iam delete-user-policy --user-name "$user" --policy-name allow-bedrock-invoke >/dev/null 2>&1 || true
    # Detach anything the enforcement flow may have attached during a test.
    for p in $("${AWS[@]}" iam list-attached-user-policies --user-name "$user" \
                --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null || true); do
      "${AWS[@]}" iam detach-user-policy --user-name "$user" --policy-arn "$p" >/dev/null 2>&1 || true
    done
    if "${AWS[@]}" iam delete-user --user-name "$user" >/dev/null 2>&1; then
      ok "deleted $user"
    else
      info "$user not present"
    fi
  done
  kubectl delete namespace "$NAMESPACE" --ignore-not-found=true >/dev/null 2>&1 || true
  ok "namespace $NAMESPACE removed"
  exit 0
fi

# --- create ------------------------------------------------------------------

kubectl get nodes >/dev/null 2>&1 \
  || die "kubectl cannot reach a cluster. Run: aws eks update-kubeconfig --name attribute-bedrock-test --region $REGION --profile $PROFILE"

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
ok "namespace $NAMESPACE ready"

# Least privilege: invoke only, and only the two cheap models the load
# generator uses. A leaked key from this cluster cannot reach anything else.
INVOKE_POLICY=$(cat <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["bedrock:InvokeModel", "bedrock:CallWithBearerToken", "bedrock-mantle:CallWithBearerToken"],
    "Resource": [
      "arn:aws:bedrock:*::foundation-model/amazon.nova-micro-v1:0",
      "arn:aws:bedrock:*::foundation-model/amazon.nova-lite-v1:0"
    ]
  }]
}
JSON
)

step "Minting ${#WORKLOADS[@]} Bedrock API keys"
for i in "${!WORKLOADS[@]}"; do
  w="${WORKLOADS[$i]}"
  user="${USER_PREFIX}-${w}"
  n=$((i + 1))

  if "${AWS[@]}" iam get-user --user-name "$user" >/dev/null 2>&1; then
    info "[$n] $user already exists -- rotating its key"
    for c in $("${AWS[@]}" iam list-service-specific-credentials --user-name "$user" \
                --service-name bedrock.amazonaws.com \
                --query 'ServiceSpecificCredentials[].ServiceSpecificCredentialId' --output text 2>/dev/null || true); do
      "${AWS[@]}" iam delete-service-specific-credential --user-name "$user" \
        --service-specific-credential-id "$c" >/dev/null 2>&1 || true
    done
  else
    "${AWS[@]}" iam create-user --user-name "$user" \
      --tags Key=project,Value=attribute-sensor-cloud-flow \
             Key=workload,Value="$w" \
             Key=purpose,Value=bedrock-load-test >/dev/null
  fi

  "${AWS[@]}" iam put-user-policy --user-name "$user" \
    --policy-name allow-bedrock-invoke --policy-document "$INVOKE_POLICY" >/dev/null

  CRED="$("${AWS[@]}" iam create-service-specific-credential \
    --user-name "$user" --service-name bedrock.amazonaws.com)"
  KEY="$(jq -r '.ServiceSpecificCredential.ServiceCredentialSecret' <<<"$CRED")"
  ALIAS="$(jq -r '.ServiceSpecificCredential.ServiceCredentialAlias' <<<"$CRED")"
  CRED_ID="$(jq -r '.ServiceSpecificCredential.ServiceSpecificCredentialId' <<<"$CRED")"
  [[ -n "$KEY" && "$KEY" != "null" ]] || die "no key value returned for $user"

  # Key goes straight into the Secret; never printed or written to disk.
  kubectl create secret generic "bedrock-key-${w}" \
    --namespace "$NAMESPACE" \
    --from-literal=BEDROCK_API_KEY="$KEY" \
    --from-literal=WORKLOAD_NAME="$w" \
    --from-literal=IAM_USER="$user" \
    --from-literal=CREDENTIAL_ID="$CRED_ID" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  kubectl label secret "bedrock-key-${w}" --namespace "$NAMESPACE" \
    --overwrite app.kubernetes.io/part-of=attribute-bedrock-test workload="$w" >/dev/null

  ok "[$n] $w -> $CRED_ID  (${KEY:0:4}...[${#KEY} chars])"
  info "     alias: $ALIAS"
done

step "Done"
info "Secrets in namespace '$NAMESPACE':"
kubectl get secrets -n "$NAMESPACE" -l app.kubernetes.io/part-of=attribute-bedrock-test \
  -o custom-columns=NAME:.metadata.name,WORKLOAD:.metadata.labels.workload --no-headers | sed 's/^/    /'
printf '\n  Generate load:  ./eks/generate-load.sh --workload checkout-agent --requests 200\n'
printf '  Tear down keys: ./eks/provision-keys.sh --profile %s --destroy\n' "$PROFILE"
