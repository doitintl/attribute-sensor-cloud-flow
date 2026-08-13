#!/usr/bin/env bash
# Validate the resolver against a REAL Bedrock API key, end to end.
#
# This is the test that matters: it confirms the one assumption the resolver is
# built on (the ABSK layout, taken from published research rather than a live
# sample) and proves the containment primitive actually stops the key.
#
#   ./tools/verify-against-aws.sh --profile piyush --region us-east-1
#   ./tools/verify-against-aws.sh --profile piyush --cleanup   # remove leftovers
#
# What it does, in order:
#   1. create a throwaway IAM user  (prefix below -- nothing pre-existing touched)
#   2. create a Bedrock long-term API key for it
#   3. run the resolver on the real key value
#   4. compare the resolver's answer to what IAM actually reports   <-- the check
#   5. deactivate the key, confirm Status==Inactive
#   6. reactivate, confirm Status==Active
#   7. delete the key and the user
#
# Never run this against a production account. The key value is never printed
# and never written to disk.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USER_PREFIX="BedrockAPIKey-resolvertest"

PROFILE=""
REGION="us-east-1"
ASSUME_YES=0
CLEANUP_ONLY=0
CREATED_USER=""
CREATED_CRED_ID=""

die()  { printf '\033[31merror:\033[0m %s\n' "$1" >&2; exit 1; }
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILURES=$((FAILURES+1)); }
info() { printf '  %s\n' "$1"; }

FAILURES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --region)  REGION="${2:-}"; shift 2 ;;
    --yes)     ASSUME_YES=1; shift ;;
    --cleanup) CLEANUP_ONLY=1; shift ;;
    -h|--help) sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$PROFILE" ]] || die "--profile is required"
command -v aws >/dev/null     || die "aws CLI not found"
command -v python3 >/dev/null || die "python3 not found"
command -v jq >/dev/null      || die "jq not found (brew install jq)"

AWS=(aws --profile "$PROFILE" --region "$REGION" --output json)

# --- cleanup -----------------------------------------------------------------

cleanup_user() {
  local user="$1"
  local creds
  creds="$("${AWS[@]}" iam list-service-specific-credentials \
      --user-name "$user" --service-name bedrock.amazonaws.com \
      --query 'ServiceSpecificCredentials[].ServiceSpecificCredentialId' \
      --output text 2>/dev/null || true)"
  for cred in $creds; do
    info "deleting credential $cred"
    "${AWS[@]}" iam delete-service-specific-credential \
      --user-name "$user" --service-specific-credential-id "$cred" >/dev/null 2>&1 || true
  done
  info "deleting user $user"
  "${AWS[@]}" iam delete-user --user-name "$user" >/dev/null 2>&1 || true
}

on_exit() {
  local rc=$?
  if [[ -n "$CREATED_USER" ]]; then
    step "Cleaning up"
    cleanup_user "$CREATED_USER"
    ok "removed $CREATED_USER"
  fi
  exit "$rc"
}
trap on_exit EXIT

# --- identity + confirmation -------------------------------------------------

step "Checking AWS identity"
IDENTITY="$("${AWS[@]}" sts get-caller-identity 2>&1)" \
  || die "could not authenticate with profile '$PROFILE'. If it is SSO: aws sso login --profile $PROFILE"
ACCOUNT="$(jq -r .Account <<<"$IDENTITY")"
ARN="$(jq -r .Arn <<<"$IDENTITY")"
info "account: $ACCOUNT"
info "arn:     $ARN"
info "region:  $REGION"

if (( CLEANUP_ONLY )); then
  step "Removing leftover test users"
  leftovers="$("${AWS[@]}" iam list-users \
    --query "Users[?starts_with(UserName, '${USER_PREFIX}')].UserName" --output text)"
  [[ -n "$leftovers" ]] || { info "none found"; CREATED_USER=""; exit 0; }
  for user in $leftovers; do cleanup_user "$user"; done
  CREATED_USER=""
  ok "cleanup complete"
  exit 0
fi

if (( ! ASSUME_YES )); then
  printf '\n\033[33mThis creates a throwaway IAM user and a real Bedrock API key in account %s,\n' "$ACCOUNT"
  printf 'then deletes both. Do NOT run this against production.\033[0m\n'
  read -r -p "Type the account id to continue: " confirm
  [[ "$confirm" == "$ACCOUNT" ]] || die "confirmation did not match; aborting"
fi

# --- 1. create the throwaway identity ---------------------------------------

SUFFIX="$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
TEST_USER="${USER_PREFIX}-${SUFFIX}"

step "Creating throwaway IAM user"
"${AWS[@]}" iam create-user --user-name "$TEST_USER" \
  --tags Key=purpose,Value=resolver-verification Key=delete-after,Value=immediately >/dev/null
CREATED_USER="$TEST_USER"
ok "created $TEST_USER (no policies attached -- it can do nothing)"

# --- 2. mint a real Bedrock API key -----------------------------------------

step "Creating a Bedrock long-term API key"
CRED_JSON="$("${AWS[@]}" iam create-service-specific-credential \
  --user-name "$TEST_USER" --service-name bedrock.amazonaws.com)" \
  || die "create-service-specific-credential failed -- does this account/role allow it?"

CREATED_CRED_ID="$(jq -r '.ServiceSpecificCredential.ServiceSpecificCredentialId' <<<"$CRED_JSON")"
IAM_SERVICE_USER="$(jq -r '.ServiceSpecificCredential.ServiceUserName // empty' <<<"$CRED_JSON")"
# Field name differs by API version; try both.
KEY_VALUE="$(jq -r '.ServiceSpecificCredential.ServiceApiKeyValue
                    // .ServiceSpecificCredential.ServicePassword
                    // empty' <<<"$CRED_JSON")"

[[ -n "$KEY_VALUE" ]] || die "no key value in the response; fields present: $(jq -r '.ServiceSpecificCredential | keys | join(", ")' <<<"$CRED_JSON")"
ok "credential id: $CREATED_CRED_ID"
info "IAM reports ServiceUserName: ${IAM_SERVICE_USER:-(absent from create response)}"
info "key value:   ${KEY_VALUE:0:4}...[redacted, ${#KEY_VALUE} chars]"

# --- 3. run the resolver on the real key ------------------------------------

step "Running the resolver on the real key"
RESOLVED="$(cd "$REPO_ROOT" && printf '%s' "$KEY_VALUE" | python3 -m resolver.cli --stdin 2>&1 | tail -n +2)" \
  || die "resolver failed: $RESOLVED"

R_KIND="$(jq -r .kind <<<"$RESOLVED")"
R_USER="$(jq -r .iam_user_name <<<"$RESOLVED")"
R_ACCOUNT="$(jq -r .account_id <<<"$RESOLVED")"
R_SERVICE_USER="$(jq -r .service_user_name <<<"$RESOLVED")"
R_INDEX="$(jq -r .key_index <<<"$RESOLVED")"

info "kind:              $R_KIND"
info "iam_user_name:     $R_USER"
info "account_id:        $R_ACCOUNT"
info "service_user_name: $R_SERVICE_USER"
info "key_index:         $R_INDEX"

# --- 4. THE CHECK: resolver vs. what IAM actually reports --------------------

step "Comparing resolver output against IAM"
LIST_JSON="$("${AWS[@]}" iam list-service-specific-credentials \
  --user-name "$TEST_USER" --service-name bedrock.amazonaws.com)"
ACTUAL_SERVICE_USER="$(jq -r --arg id "$CREATED_CRED_ID" \
  '.ServiceSpecificCredentials[] | select(.ServiceSpecificCredentialId==$id) | .ServiceUserName' <<<"$LIST_JSON")"

[[ "$R_KIND" == "bedrock_long_term_api_key" ]] \
  && ok "classified as a long-term Bedrock API key" \
  || bad "classified as '$R_KIND'"

[[ "$R_USER" == "$TEST_USER" ]] \
  && ok "iam_user_name matches the real IAM user" \
  || bad "iam_user_name '$R_USER' != actual '$TEST_USER'  <-- the +N split is wrong"

[[ "$R_ACCOUNT" == "$ACCOUNT" ]] \
  && ok "account_id matches" \
  || bad "account_id '$R_ACCOUNT' != actual '$ACCOUNT'"

# The join key: the resolver's ServiceUserName must equal IAM's exactly, or the
# lookup's JMESPath filter will match nothing and containment will silently fail.
if [[ "$R_SERVICE_USER" == "$ACTUAL_SERVICE_USER" ]]; then
  ok "service_user_name matches IAM exactly (the join key holds)"
else
  bad "service_user_name '$R_SERVICE_USER' != IAM '$ACTUAL_SERVICE_USER'"
  info "     ^ the lookup filter would match nothing; fix _split_service_user_name"
fi

# Resolve the credential id the way the flow would, and check it is the right one.
SELECTED="$(jq -r --arg sun "$R_SERVICE_USER" \
  '.ServiceSpecificCredentials[] | select(.ServiceUserName==$sun) | .ServiceSpecificCredentialId' <<<"$LIST_JSON")"
[[ "$SELECTED" == "$CREATED_CRED_ID" ]] \
  && ok "the flow's lookup selects the correct credential id" \
  || bad "lookup selected '$SELECTED', expected '$CREATED_CRED_ID'"

# --- 5. containment ----------------------------------------------------------

step "Deactivating the key (tier 2 containment)"
"${AWS[@]}" iam update-service-specific-credential \
  --user-name "$TEST_USER" \
  --service-specific-credential-id "$CREATED_CRED_ID" \
  --status Inactive >/dev/null

STATUS="$("${AWS[@]}" iam list-service-specific-credentials \
  --user-name "$TEST_USER" --service-name bedrock.amazonaws.com \
  --query "ServiceSpecificCredentials[?ServiceSpecificCredentialId=='${CREATED_CRED_ID}'].Status" \
  --output text)"
[[ "$STATUS" == "Inactive" ]] \
  && ok "status is Inactive (verified by re-listing, not by trusting the 200)" \
  || bad "status is '$STATUS', expected Inactive"

# --- 6. reversibility --------------------------------------------------------

step "Reactivating (proving tier 2 is reversible)"
"${AWS[@]}" iam update-service-specific-credential \
  --user-name "$TEST_USER" \
  --service-specific-credential-id "$CREATED_CRED_ID" \
  --status Active >/dev/null

STATUS="$("${AWS[@]}" iam list-service-specific-credentials \
  --user-name "$TEST_USER" --service-name bedrock.amazonaws.com \
  --query "ServiceSpecificCredentials[?ServiceSpecificCredentialId=='${CREATED_CRED_ID}'].Status" \
  --output text)"
[[ "$STATUS" == "Active" ]] \
  && ok "status is Active again -- containment is reversible" \
  || bad "status is '$STATUS', expected Active"

# --- summary -----------------------------------------------------------------

step "Result"
if (( FAILURES == 0 )); then
  printf '  \033[32mAll checks passed.\033[0m The ABSK layout and the containment\n'
  printf '  primitive are confirmed against a real key. You can drop the\n'
  printf '  UNVERIFIED_AGAINST_REAL_KEY caveat in resolver/README.md.\n'
else
  printf '  \033[31m%d check(s) failed.\033[0m Do not wire this to a real flow until\n' "$FAILURES"
  printf '  the resolver agrees with IAM -- a wrong join key means containment\n'
  printf '  silently does nothing.\n'
fi
exit "$FAILURES"
