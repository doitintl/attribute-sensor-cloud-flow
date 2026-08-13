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

Everything about the IAM and Bedrock **APIs** is from AWS documentation:
[revoking Bedrock keys](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-revoke.html),
`UpdateServiceSpecificCredential`, `UpdateAccessKey`.

The **`ABSK` key layout** is from
[Wiz's teardown](https://www.wiz.io/blog/a-new-type-of-long-lived-key-on-aws-bedrock-api-keys),
not a live sample. Tests depending on it are tagged
`UNVERIFIED_AGAINST_REAL_KEY`. Confirm by minting a throwaway key on a sandbox
account and running `python3 -m resolver.cli`, checking that:

1. The decoded ServiceUserName matches `ServiceUserName` in
   `aws iam list-service-specific-credentials --service-name bedrock.amazonaws.com`
   **exactly** — that string is the join key.
2. `iam_user_name` matches the real `UserName`, i.e. the `+N` split is right.
3. Key length is not assumed anywhere (the published 132 chars is not hardcoded).

Deliberately **not** assumed: total key length, that the IAM user is always
named `BedrockAPIKey-*` (keys can be minted for existing users), or that `+N`
absence means primary.

## Secret handling

The secret half is dropped at parse time and never returned, logged, or included
in exception messages — `redact()` keeps a 4-char prefix and discards the tail
(the secret for `ABSK`, the signature for SigV4). Asserted in
`SecretHandlingTests` against a distinctive sentinel.

`resolver.cli` reads from stdin or an unechoed prompt by default so live
credentials stay out of shell history.
