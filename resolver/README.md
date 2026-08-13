# Bedrock credential resolver

Turns a credential *as observed on the wire* by the Attribute sensor into the IAM
identifiers needed to stop it. Pure functions — no network, no SDKs, no secrets
retained. Stdlib only, so it drops unchanged into a CloudFlow **Code node**.

```bash
python3 -m unittest discover -s tests -t .
python3 -m resolver.cli --stdin < key.txt
```

## Why Bedrock resolves without a fingerprint registry

A long-term Bedrock API key carries its own owner. `ABSK` + base64, decoding to
`<ServiceUserName>:<secret>`, where the ServiceUserName is:

```
BedrockAPIKey-abcd+1-at-123456789012
|___ iam user ___|++|___ account ___|
                 `- optional key index (secondary key)
```

So `ABSK…` → IAM user → `ListServiceSpecificCredentials` → credential ID →
`UpdateServiceSpecificCredential(Status=Inactive)`. No hash database, no periodic
key-listing sync. That is why Bedrock is the first provider implemented.

## Credential shapes

| Observed | Kind | Identity from the credential alone? | Tier 2 containment |
|---|---|---|---|
| `ABSK…` | `bedrock_long_term_api_key` | ✅ user + account | `UpdateServiceSpecificCredential` → `Inactive` |
| `ACCA…` | `service_specific_credential_id` | ✅ already the ID | same, no lookup needed |
| SigV4 `AKIA…` | `iam_access_key` | ⚠️ key ID only | `UpdateAccessKey` → `Inactive` |
| SigV4 `ASIA…` | `iam_temporary_credential` | ❌ nothing | quarantine policy on the issuing role |

## Two gaps the resolver reports rather than hides

**`AKIA` → owning user is not derivable.** No IAM API maps an access key ID to
its user; `sts:GetAccessKeyInfo` returns only the account. The resolver emits an
`iam:ListAccessKeys` enumeration lookup and a warning. Cache that map in a
CloudFlow Datastore, or resolve via CloudTrail. (This is a correction to the
initial design sketch, which assumed the cleartext AKID was sufficient — it
identifies the *key*, not the *user* that `UpdateAccessKey` requires.)

**`ASIA` cannot be deactivated at all.** Temporary credentials have no status to
flip. The only lever is a policy on the role that minted them, and the role is
not in the access key ID — hence the `cloudtrail:LookupEvents` step (5–15 min
lag) or the `aws:TokenIssueTime` session-invalidation policy.

Check `needs_external_lookup` before assuming an alert is immediately actionable.

## Output contract

`ResolvedCredential.to_dict()` is JSON for downstream CloudFlow nodes. Params of
the form `${lookup.Field}` must be filled from the matching `LookupStep` result
before the call is made.

Actions are tiered: **tier 2 is always reversible** (`reversible: true`, with an
`undo`), **tier 3 never is** — gate it behind the AWS node's approval. Both
invariants are asserted in the tests.

## Two things not to break

- **`bedrock-mantle`.** The quarantine policy must deny both
  `bedrock:CallWithBearerToken` *and* `bedrock-mantle:CallWithBearerToken`.
  Denying only the first leaves the key spending through the Mantle endpoint
  while your audit log says "contained".
- **Strict base64.** `_b64decode_strict` normalises the URL-safe alphabet and
  validates. The permissive decoder *discards* `-`/`_`, which would silently
  corrupt an IAM user name instead of failing. Covered by
  `test_urlsafe_base64_alphabet_is_decoded_correctly`.

## Verification status

**Verified against a real key** — account 641260351119, 2026-08-13, via
`tools/verify-against-aws.sh`. All checks passed:

| Confirmed | Value |
|---|---|
| `ABSK` prefix, base64 payload decoding to `<alias>:<secret>` | ✅ |
| Alias embeds IAM user + account | `BedrockAPIKey-…-at-641260351119` |
| `iam_user_name` matches the real IAM `UserName` | ✅ |
| Resolver's alias matches IAM **exactly** (the join key) | ✅ |
| The flow's lookup selects the correct credential ID | ✅ |
| Credential ID prefix | `ACCA…` |
| `UpdateServiceSpecificCredential` → `Inactive`, then back to `Active` | ✅ reversible |

### What the live run corrected

The create/list responses carry **`ServiceCredentialAlias`** and
**`ServiceCredentialSecret`** — there is **no `ServiceUserName` field** on
Bedrock credentials. The resolver originally emitted a lookup filtering on
`ServiceUserName`; a JMESPath filter on an absent field matches nothing
*silently*, so containment would have reported success while the key kept
spending. The emitted filter now tries `ServiceCredentialAlias` first and falls
back to `ServiceUserName` for the legacy SSH/CodeCommit shape.

Two smaller corrections from the same run:

- The real key was **156 characters**, not the 132 in the published teardown.
  Nothing assumes a length, which is why this was a non-event.
- A **primary** key's alias carries **no `+N`** (`key_index` is `null`).
  The `+N` suffix appears only on a secondary key.
- The **list** response omits `ServiceCredentialSecret` — the secret is returned
  only at create time. Expected, and worth knowing: you cannot recover a key
  value from IAM later.

### Still unverified

- **Primary/secondary disambiguation.** A user may hold two Bedrock keys. If the
  alias does not distinguish them, containment deactivates the wrong one and
  leaves the leaked key live. `verify-against-aws.sh` now creates a second key
  and asserts each alias selects its own credential ID — rerun it to close this.
- **That the quarantine policy actually blocks calls.** Denying
  `bedrock:CallWithBearerToken` and `bedrock-mantle:CallWithBearerToken` is
  documented but untested here; it needs a real Bedrock invocation before and
  after attaching the policy.
- **The `AKIA` and `ASIA` paths**, which depend on enumeration and CloudTrail
  rather than on the credential itself.

Deliberately **not** assumed anywhere: total key length, that the IAM user is
always named `BedrockAPIKey-*` (keys can be minted for existing users), or that
absence of `+N` means primary.

## Secret handling

The secret half is dropped at parse time and never returned, logged, or included
in exception messages — `redact()` keeps a 4-char prefix and discards the tail
(the secret for `ABSK`, the signature for SigV4). Asserted in
`SecretHandlingTests` against a distinctive sentinel.

`resolver.cli` reads from stdin or an unechoed prompt by default so live
credentials stay out of shell history.
