# Wiring Attribute to the CloudFlow webhook

## The path

```
zprobe (eBPF, on the box)
   │  OTel → otel-endpoint.app.attrb.io:443
   ▼
Attribute platform  ── detects: leaked key / runaway agent / spike / overrun
   │  POST + X-Attribute-Signature (HMAC-SHA256)
   ▼
enforcement adapter (Lambda Function URL)
   │  verify signature · reject replays · resolve credential · DISCARD secret
   │  dedupe on idempotency_key · inject DoiT token from Secrets Manager
   │  POST + Authorization: Bearer $DOIT_API_TOKEN
   ▼
CloudFlow webhook trigger → branch on tier → AWS node (IAM) → Threads audit
```

`zprobe` is an OTel exporter with no webhook egress — it ships telemetry and
nothing else. The component that calls CloudFlow is Attribute's **alerting
layer**, not the sensor on the host.

## Why the adapter is not optional

You *can* point Attribute straight at the CloudFlow webhook. Four reasons not to:

1. **The DoiT API token is a kill switch.** Configuring it as a header in a
   third-party SaaS notification stores a credential-revoking token in that
   vendor's database. With the adapter, Attribute holds only an HMAC secret whose
   sole capability is talking to your endpoint.
2. **CloudFlow's webhook has no HMAC and no replay protection** — bearer token
   only. Anyone with the token can revoke production credentials, repeatedly.
3. **Live credentials would cross into the DoiT platform.** The adapter resolves
   locally and forwards only the derived identity (IAM user, account,
   ServiceUserName) plus a redacted hint. `assert_no_secret` enforces this on
   every request.
4. **A runaway agent emits many alerts.** Dedupe has to happen before the flow
   fires, or you get N revoke attempts for one incident.

## Setup

### 1. Configure the CloudFlow trigger

Paste [`contracts/cloudflow-trigger.v1.sample.json`](../contracts/cloudflow-trigger.v1.sample.json)
as the trigger's **Sample JSON**, minus the `_`-prefixed comment keys. CloudFlow
derives the payload schema from this sample — **a field absent from it is
invisible to every downstream filter, branch, and action node.** Adding a field
later means updating the sample and republishing the flow.

`tests/test_adapter.py::test_matches_contract_sample_fields` fails if the builder
ever emits a field the sample lacks. (It already caught one: `tier_rationale`.)

Generate the DoiT API token from the trigger node, then copy the webhook URL.

### 2. Prove the trigger works — before touching Attribute

```bash
DOIT_API_TOKEN=... ./tools/simulate-alert.sh --cloudflow "$WEBHOOK_URL"
```

This posts the contract sample verbatim. A 2xx plus an execution in the CloudFlow
run history means the trigger and its Sample JSON are right. Do this first — it
isolates trigger problems from adapter and Attribute problems.

Add `--dry-run` to print the payload without sending.

### 3. Deploy the adapter

Environment:

| Variable | Required | Purpose |
|---|---|---|
| `CLOUDFLOW_WEBHOOK_URL` | ✅ | from step 1 |
| `DOIT_API_TOKEN_SECRET_ID` | ✅ | Secrets Manager id — never a plain env var |
| `ATTRIBUTE_SIGNING_SECRET_ID` | ✅ | HMAC secret; JSON list or comma-separated for rotation |
| `QUARANTINE_POLICY_ARN` | ✅ | the deny policy the flow attaches |
| `IDEMPOTENCY_TABLE` | ⚠️ | DynamoDB, PK `idempotency_key`, TTL `expires_at`. Unset ⇒ **no dedupe**, logged as a warning |
| `PROTECTED_IAM_USERS` | — | comma-separated; downgraded to observe, never auto-contained |
| `SIGNATURE_TOLERANCE_SECONDS` | — | replay window, default 300 |

The Function URL uses `AuthType: NONE` — **HMAC is the gate**. Verification never
fails open: an unconfigured secret raises rather than allowing the request
(`test_unconfigured_secret_does_not_fail_open`).

The adapter needs `secretsmanager:GetSecretValue` on the two secrets and
`dynamodb:PutItem` on the table. It needs **no IAM permissions at all** — it
never touches credentials; the flow does that with the role you're creating.

### 4. Point Attribute at the adapter

Configure Attribute's webhook notification to POST the
[inbound schema](../contracts/attribute-alert.v1.schema.json) to the Function URL
with `X-Attribute-Signature: t=<unix>,v1=<hex>`, where the digest is
`HMAC-SHA256(secret, "<t>.<raw body>")`. Signed over the **raw bytes** —
re-serialising parsed JSON changes the digest and fails verification.

Test the hop end-to-end:

```bash
ATTRIBUTE_SIGNING_SECRET=... ./tools/simulate-alert.sh --adapter "$ADAPTER_URL"
```

The synthetic key resolves to `BedrockAPIKey-simulated` in account
`000000000000`, which won't exist — so the flow's lookup fails safely instead of
touching anything real.

**If Attribute can't send a custom header**, HMAC is impossible and this becomes
a real decision: either put a query-string shared secret on the Function URL
(weaker — secrets in URLs get logged) or have Attribute write alerts somewhere
the adapter polls. Confirm Attribute's webhook capabilities before building
further; this is the one open dependency.

## Tier policy

| Signal | info | warning | critical | Approval |
|---|---|---|---|---|
| `leaked_key` | 2 | 2 | 2 | auto |
| `runaway_agent` | 1 | 2 | 2 | auto |
| `budget_overrun` | 1 | 1 | 2 | **required** |
| `token_spike` | 1 | 1 | 1 | — |
| `anomalous_workload` | 1 | 1 | 1 | — |

Tier 1 observes (notify + audit, no mutation). Tier 2 is reversible containment.
**Tier 3 is unreachable from an inbound payload** — the adapter caps at 2, so
destruction always needs a human in CloudFlow.

Guardrails, all asserted in tests:

- `requested_action` can only **lower** a tier, never raise it — a spoofed alert
  must not be able to escalate.
- Unknown signals observe only.
- `PROTECTED_IAM_USERS` are downgraded to observe.
- Unactionable credentials (nothing to contain) are downgraded to observe.

Edit `TIER_POLICY` in [`adapter/policy.py`](../adapter/policy.py), not the flow —
policy in code is reviewable and survives UI edits.

## Still to build

- The quarantine policy and the scoped CloudFlow role (yours). Condition
  `iam:AttachUserPolicy` on that **single** policy ARN, or the webhook becomes a
  privilege-escalation path.
- The flow itself: branch on `tier` → AWS node → **re-list and assert
  `Status == Inactive`** before recording as contained (IAM is eventually
  consistent; a 200 is not proof) → Threads audit record.
- A circuit breaker: halt and page if more than N containments fire in an hour.
  That is a bug or a compromised webhook, not an incident.
