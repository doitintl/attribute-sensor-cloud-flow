#!/usr/bin/env bash
# Delete everything this scenario created: the six IAM users and their Bedrock
# keys, then the EKS cluster.
#
#   ./eks/teardown.sh --profile attrb-admin           # keys + cluster
#   ./eks/teardown.sh --profile attrb-admin --keys-only
#
# The EKS control plane bills ~$0.10/hr whether or not anything runs on it, so
# run this when you are done rather than leaving the cluster idle.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER="attribute-bedrock-test"
REGION="us-east-1"
PROFILE=""
KEYS_ONLY=0
ASSUME_YES=0

die()  { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32mOK\033[0m %s\n' "$1"; }
info() { printf '  %s\n' "$1"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)   PROFILE="${2:-}"; shift 2 ;;
    --region)    REGION="${2:-}"; shift 2 ;;
    --cluster)   CLUSTER="${2:-}"; shift 2 ;;
    --keys-only) KEYS_ONLY=1; shift ;;
    --yes)       ASSUME_YES=1; shift ;;
    -h|--help)   sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$PROFILE" ]] || die "--profile is required"

ACCOUNT="$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)" \
  || die "cannot authenticate; try: aws sso login --profile $PROFILE"
info "account: $ACCOUNT   cluster: $CLUSTER   region: $REGION"

if (( ! ASSUME_YES )); then
  printf '\n\033[33mThis deletes the six IAM users with their Bedrock keys'
  (( KEYS_ONLY )) || printf ' AND the EKS cluster'
  printf '.\033[0m\n'
  read -r -p "Type 'delete' to continue: " confirm
  [[ "$confirm" == "delete" ]] || die "aborted"
fi

step "Removing Bedrock keys and IAM users"
"$REPO_ROOT/eks/provision-keys.sh" --profile "$PROFILE" --region "$REGION" --destroy || \
  info "key teardown reported problems -- check for leftover attrb-load-* users"

if (( KEYS_ONLY )); then
  step "Done (cluster left running)"
  info "the control plane is still billing ~\$0.10/hr"
  exit 0
fi

step "Deleting the EKS cluster (this takes several minutes)"
AWS_PROFILE="$PROFILE" eksctl delete cluster --name "$CLUSTER" --region "$REGION" --wait \
  || die "cluster deletion failed -- check CloudFormation stacks named eksctl-${CLUSTER}-*"
ok "cluster deleted"

step "Verifying nothing is left billing"
leftover_users="$(aws iam list-users --profile "$PROFILE" \
  --query "Users[?starts_with(UserName, 'attrb-load-')].UserName" --output text)"
[[ -z "$leftover_users" ]] && ok "no attrb-load-* IAM users remain" \
  || info "leftover users: $leftover_users"

stacks="$(aws cloudformation list-stacks --profile "$PROFILE" --region "$REGION" \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE DELETE_FAILED \
  --query "StackSummaries[?starts_with(StackName, 'eksctl-${CLUSTER}')].StackName" --output text)"
[[ -z "$stacks" ]] && ok "no eksctl stacks remain" || info "leftover stacks: $stacks"

step "Done"
