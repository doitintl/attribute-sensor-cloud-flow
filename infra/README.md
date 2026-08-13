# IAM for the enforcement flow

`enforcement-iam.yaml` creates three managed policies and, optionally, two roles.

```bash
aws cloudformation deploy \
  --template-file infra/enforcement-iam.yaml \
  --stack-name attribute-enforcement-iam \
  --capabilities CAPABILITY_NAMED_IAM \
  --profile attrb-admin
```

By default it creates **policies only** — attach them to a role you control.
Pass `CloudFlowPrincipalArn` (and ideally `ExternalId`) to have it create the
roles too.

| Output | Use |
|---|---|
| `QuarantinePolicyArn` | set as `QUARANTINE_POLICY_ARN` on the adapter |
| `ContainmentPolicyArn` | attach to the role the CloudFlow AWS node assumes (tier 2) |
| `DestructionPolicyArn` | attach to a **separate**, approval-gated role (tier 3) |

## Why the quarantine policy denies `bedrock:*`

Earlier drafts denied only `bedrock:CallWithBearerToken` and
`bedrock-mantle:CallWithBearerToken`. That is incomplete. Two distinct call
paths reach Bedrock:

- **API keys (`ABSK`)** go through `CallWithBearerToken` — and there are *two*
  such actions. [Denying only the first](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-revoke.html)
  leaves the Mantle endpoint spending.
- **SigV4 (`AKIA`/`ASIA`)** does not use `CallWithBearerToken` at all. It calls
  `InvokeModel`, `Converse`, and friends directly, so a bearer-token-only deny
  does **nothing** against a leaked access key.

A quarantine should stop the identity using Bedrock entirely. The wildcard also
survives AWS adding new Bedrock API surface later — a curated action list
silently develops gaps as the service grows.

Detach the policy to restore access; that is what makes tier 2 reversible.

## Why `AttachUserPolicy` is conditioned

This is the one control that must not be relaxed:

```yaml
Condition:
  ArnEquals:
    iam:PolicyARN: !Ref QuarantinePolicy
```

Unconditioned `iam:AttachUserPolicy` is a **privilege-escalation primitive** —
anyone who can reach the webhook could attach `AdministratorAccess` to an
identity they control. With the condition, the worst a compromised trigger can
do is deny Bedrock to somebody.

## Other guards

- **Tier 3 is a separate role.** The containment policy carries an explicit
  `Deny` on every `Delete*`, so even if someone wires a delete action into the
  tier 2 path, it fails. Destruction requires assuming a different role behind
  CloudFlow's approval step.
- **Protected identities.** `ProtectedIdentityArns` gets an explicit `Deny`,
  which overrides every `Allow`. Put break-glass identities here, and anything
  whose loss would be worse than the spend it is burning.
- **No self-modification.** The role cannot edit the policies that constrain it.

## Known rough edge

`iam:ListUsers` has no resource-level scoping, so it is granted on `*`. It is
needed only for the `AKIA` → owning-user enumeration, because no IAM API maps an
access key ID to its owner. Once that map is cached in a CloudFlow Datastore,
drop the `EnumerateUsersForAccessKeyLookup` statement — it is the loosest grant
in the policy and it buys only a lookup.

## Verified

The containment primitive itself is confirmed against a real Bedrock key in
641260351119 (see `tools/verify-against-aws.sh`): deactivate, verify by
re-listing, reactivate. What is **not** yet tested is whether attaching the
quarantine policy actually blocks a live Bedrock call — that needs a real
`InvokeModel` before and after the attach.
