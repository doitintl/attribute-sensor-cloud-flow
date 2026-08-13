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

command -v aws >/dev/null     || die "aws CLI not found"
command -v python3 >/dev/null || die "python3 not found"
command -v jq >/dev/null      || die "jq not found (brew install jq)"

# Without --profile, fall back to ambient credentials (env vars / default
# profile). Lets a short-lived SSO role be used for one run without adding a
# standing admin profile to ~/.aws/config.
AWS=(aws --region "$REGION" --output json)
[[ -n "$PROFILE" ]] && AWS=(aws --profile "$PROFILE" --region "$REGION" --output json)

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

# Bedrock service-specific credentials return ServiceCredentialAlias /
# ServiceCredentialSecret. The classic SSH/CodeCommit shape used
# ServiceUserName / ServicePassword. Accept either.
IAM_ALIAS="$(jq -r '.ServiceSpecificCredential.ServiceCredentialAlias
                    // .ServiceSpecificCredential.ServiceUserName
                    // empty' <<<"$CRED_JSON")"
KEY_VALUE="$(jq -r '.ServiceSpecificCredential.ServiceCredentialSecret
                    // .ServiceSpecificCredential.ServiceApiKeyValue
                    // .ServiceSpecificCredential.ServicePassword
                    // empty' <<<"$CRED_JSON")"

info "create response fields: $(jq -r '.ServiceSpecificCredential | keys | join(", ")' <<<"$CRED_JSON")"
[[ -n "$KEY_VALUE" ]] || die "no key value found in the create response"
ok "credential id: $CREATED_CRED_ID"
info "alias reported by IAM: ${IAM_ALIAS:-(none)}"
info "key value:             ${KEY_VALUE:0:4}...[redacted, ${#KEY_VALUE} chars]"

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
info "list response fields: $(jq -r '.ServiceSpecificCredentials[0] | keys | join(", ")' <<<"$LIST_JSON")"

# Whichever of the two field names this API version uses is the join key the
# flow's lookup must filter on.
ALIAS_FIELD="$(jq -r '.ServiceSpecificCredentials[0]
  | if has("ServiceCredentialAlias") then "ServiceCredentialAlias"
    elif has("ServiceUserName") then "ServiceUserName"
    else "" end' <<<"$LIST_JSON")"
[[ -n "$ALIAS_FIELD" ]] || die "list response has neither ServiceCredentialAlias nor ServiceUserName"
info "join key field:       $ALIAS_FIELD"

ACTUAL_SERVICE_USER="$(jq -r --arg id "$CREATED_CRED_ID" --arg f "$ALIAS_FIELD" \
  '.ServiceSpecificCredentials[] | select(.ServiceSpecificCredentialId==$id) | .[$f]' <<<"$LIST_JSON")"
info "join key value:       $ACTUAL_SERVICE_USER"

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

# Check the resolver emits a lookup filtering on the field IAM actually returns.
R_SELECT="$(jq -r '.lookups[0].select // ""' <<<"$RESOLVED")"
if [[ "$R_SELECT" == *"$ALIAS_FIELD"* ]]; then
  ok "the resolver's lookup filters on $ALIAS_FIELD"
else
  bad "the resolver's lookup does not reference $ALIAS_FIELD"
  info "     select: $R_SELECT"
  info "     ^ filtering on a field IAM does not return matches nothing, so"
  info "       containment would report success while doing nothing"
fi

# Resolve the credential id the way the flow would, and check it is the right one.
SELECTED="$(jq -r --arg sun "$R_SERVICE_USER" --arg f "$ALIAS_FIELD" \
  '.ServiceSpecificCredentials[] | select(.[$f]==$sun) | .ServiceSpecificCredentialId' <<<"$LIST_JSON")"
[[ "$SELECTED" == "$CREATED_CRED_ID" ]] \
  && ok "the flow's lookup selects the correct credential id" \
  || bad "lookup selected '$SELECTED', expected '$CREATED_CRED_ID'"

# --- 4b. two keys on one user: does the join key pick the right one? ---------
#
# The dangerous case. A user may hold a primary and a secondary Bedrock key. If
# the alias does not disambiguate them, containment deactivates the wrong key --
# leaving the leaked one live while the audit log says the incident is closed.

step "Creating a SECOND key on the same user (disambiguation test)"
CRED2_JSON="$("${AWS[@]}" iam create-service-specific-credential \
  --user-name "$TEST_USER" --service-name bedrock.amazonaws.com 2>&1)" || CRED2_JSON=""

if [[ -z "$CRED2_JSON" || "$CRED2_JSON" != *ServiceSpecificCredentialId* ]]; then
  info "could not create a second key (quota or policy); skipping"
  info "the primary/secondary disambiguation path remains unverified"
else
  CRED2_ID="$(jq -r '.ServiceSpecificCredential.ServiceSpecificCredentialId' <<<"$CRED2_JSON")"
  CRED2_ALIAS="$(jq -r '.ServiceSpecificCredential.ServiceCredentialAlias // empty' <<<"$CRED2_JSON")"
  CRED2_KEY="$(jq -r '.ServiceSpecificCredential.ServiceCredentialSecret // empty' <<<"$CRED2_JSON")"
  info "second credential id: $CRED2_ID"
  info "second alias:         $CRED2_ALIAS"

  [[ "$CRED2_ALIAS" != "$ACTUAL_SERVICE_USER" ]] \
    && ok "the two keys have distinct aliases" \
    || bad "both keys share the alias '$CRED2_ALIAS' -- they cannot be told apart"

  R2="$(cd "$REPO_ROOT" && printf '%s' "$CRED2_KEY" | python3 -m resolver.cli --stdin 2>&1 | tail -n +2)"
  R2_ALIAS="$(jq -r .service_user_name <<<"$R2")"
  R2_USER="$(jq -r .iam_user_name <<<"$R2")"
  R2_INDEX="$(jq -r .key_index <<<"$R2")"
  info "resolver on key 2 -> alias=$R2_ALIAS user=$R2_USER index=$R2_INDEX"

  [[ "$R2_ALIAS" == "$CRED2_ALIAS" ]] \
    && ok "resolver reads the second key's alias correctly" \
    || bad "resolver said '$R2_ALIAS', IAM says '$CRED2_ALIAS'"

  [[ "$R2_USER" == "$TEST_USER" ]] \
    && ok "second key still resolves to the right IAM user" \
    || bad "second key resolved to user '$R2_USER', expected '$TEST_USER'"

  # The decisive check: each key's alias must select its OWN credential id.
  LIST2_JSON="$("${AWS[@]}" iam list-service-specific-credentials \
    --user-name "$TEST_USER" --service-name bedrock.amazonaws.com)"
  PICK1="$(jq -r --arg a "$R_SERVICE_USER" --arg f "$ALIAS_FIELD" \
    '.ServiceSpecificCredentials[] | select(.[$f]==$a) | .ServiceSpecificCredentialId' <<<"$LIST2_JSON")"
  PICK2="$(jq -r --arg a "$R2_ALIAS" --arg f "$ALIAS_FIELD" \
    '.ServiceSpecificCredentials[] | select(.[$f]==$a) | .ServiceSpecificCredentialId' <<<"$LIST2_JSON")"

  [[ "$PICK1" == "$CREATED_CRED_ID" && "$PICK2" == "$CRED2_ID" ]] \
    && ok "with two keys present, each alias selects its own credential id" \
    || bad "disambiguation failed: key1 -> '$PICK1' (want $CREATED_CRED_ID), key2 -> '$PICK2' (want $CRED2_ID)"

  info "deleting the second key"
  "${AWS[@]}" iam delete-service-specific-credential \
    --user-name "$TEST_USER" --service-specific-credential-id "$CRED2_ID" >/dev/null 2>&1 || true
fi

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
