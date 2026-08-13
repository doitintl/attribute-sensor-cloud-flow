# attribute-sensor-cloud-flow

Turns a DoiT **Attribute** detection into an automatic, reversible, audited
credential containment via a **DoiT CloudFlow** enforcement flow.

## The problem

AI adoption multiplies long-lived credentials: OpenAI admin and project keys,
Anthropic organization keys, Amazon Bedrock API keys, Gemini API keys. Each can
drive real spend and real exposure — a leaked key, an agent stuck in a retry
loop, or a workload that quietly outgrows its budget can burn thousands of
dollars before anyone opens a dashboard.

Attribute solves the **visibility** half: it separates human from non-human
traffic at runtime, allocates every token to the API key and workload that spent
it, and catches token spikes, runaway agents, and budget overruns in near real
time.

Detection alone doesn't stop the burn. Acting on an alert by hand means finding
the right provider console, holding standing credentials for four different
provider APIs, and hoping the on-call engineer follows the runbook. There is
rarely an approval step, and rarely a consistent record of who revoked what,
when, and why. Every minute between alert and revocation is money and exposure.

## The path

```
zprobe (eBPF sensor, on the host)
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

`zprobe` is an OTel exporter with no webhook egress — the component that calls
CloudFlow is Attribute's **alerting layer**, not the sensor on the host.

### Why an adapter sits in the middle

Pointing Attribute straight at the CloudFlow webhook is possible. Four reasons
not to:

1. **The DoiT API token is a kill switch.** Putting it in a third-party SaaS
   notification config stores a credential-revoking token in that vendor's
   database. With the adapter, Attribute holds only an HMAC secret whose one
   capability is talking to your endpoint.
2. **CloudFlow's webhook has no HMAC and no replay protection** — bearer token
   only.
3. **Live credentials would cross into the DoiT platform.** The adapter resolves
   locally and forwards only the derived identity plus a redacted hint.
4. **A runaway agent emits many alerts.** Dedupe must happen before the flow
   fires, or one incident becomes N revoke attempts.

## Layout

| Path | What |
|---|---|
| [`resolver/`](resolver/) | Observed credential → containable IAM identity. Pure, stdlib-only. [Details](resolver/README.md) |
| [`adapter/`](adapter/) | HMAC verify, tier policy, payload builder, Lambda handler |
| [`contracts/`](contracts/) | Inbound JSON Schema + the Sample JSON for the CloudFlow trigger |
| [`tools/`](tools/) | Local adapter runner and alert simulator |
| [`docs/WIRING.md`](docs/WIRING.md) | Setup, tier policy, open questions |

## Quickstart

No dependencies beyond Python 3.12+; nothing to install.

```bash
python3 -m unittest discover -s tests -t .
```

Resolve a credential without sending it anywhere:

```bash
python3 -m resolver.cli --stdin < key.txt
```

Run the whole adapter path locally — no AWS, no deploy, nothing sent:

```bash
ATTRIBUTE_SIGNING_SECRET=devsecret python3 tools/run-adapter-local.py
```

```bash
ATTRIBUTE_SIGNING_SECRET=devsecret ./tools/simulate-alert.sh --adapter http://127.0.0.1:8080
```

## Containment tiers

| Signal | info | warning | critical | Approval |
|---|---|---|---|---|
| `leaked_key` | 2 | 2 | 2 | auto |
| `runaway_agent` | 1 | 2 | 2 | auto |
| `budget_overrun` | 1 | 1 | 2 | **required** |
| `token_spike` | 1 | 1 | 1 | — |
| `anomalous_workload` | 1 | 1 | 1 | — |

Tier 1 observes (notify + audit, no mutation). Tier 2 is **reversible**
containment. **Tier 3 is unreachable from an inbound payload** — the adapter caps
at 2, so destruction always requires a human inside CloudFlow.

Guardrails, all test-asserted: `requested_action` can only *lower* a tier, never
raise it, so a spoofed alert cannot escalate; unknown signals observe only;
protected IAM identities and unactionable credentials downgrade to observe;
signature verification never fails open on an unconfigured secret.

## Provider status

| Provider | State | Why |
|---|---|---|
| **Bedrock** | implemented | The credential carries its own owner — `ABSK` base64-decodes to `<iam-user>+N-at-<account>:<secret>`, so resolution needs no fingerprint registry |
| OpenAI | not started | No key-level disable exists; only `DELETE`, which errors on service-account-owned keys. Containment must be project rate limits or archive |
| Anthropic | not started | `updateApiKey` → `status: "inactive"` is clean and reversible; needs a `partial_key_hint` registry to resolve |
| Gemini | not started | API Keys v2 has no disable; `keys.patch` restrictions, or `delete` with 30-day undelete |

Bedrock is first precisely because it is the only one that resolves
deterministically from the credential alone.

## Two things not to break

- **`bedrock-mantle`.** The quarantine policy must deny both
  `bedrock:CallWithBearerToken` *and* `bedrock-mantle:CallWithBearerToken`.
  [Denying only the first](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-revoke.html)
  leaves the key spending through the Mantle endpoint while the audit log says
  "contained".
- **`iam:AttachUserPolicy` must be scoped.** Condition it on the single
  quarantine policy ARN (`ArnEquals` on `iam:PolicyARN`), or a webhook-triggered
  flow becomes a privilege-escalation primitive.

## Verification status

The IAM and Bedrock **API** behaviour is from AWS documentation. The **`ABSK` key
layout** is from
[Wiz's teardown](https://www.wiz.io/blog/a-new-type-of-long-lived-key-on-aws-bedrock-api-keys),
not a live sample — tests depending on it are tagged
`UNVERIFIED_AGAINST_REAL_KEY`. Confirm against a throwaway key on a sandbox
account before this touches anything real; see
[`resolver/README.md`](resolver/README.md).

**Open dependency:** whether Attribute's webhook can send a custom
`X-Attribute-Signature` header. If not, HMAC is impossible and the transport
needs rethinking. Confirm before building the flow.

## Still to build

- Quarantine policy + scoped CloudFlow IAM role
- The flow itself: branch on `tier` → AWS node → **re-list and assert
  `Status == Inactive`** before recording as contained (IAM is eventually
  consistent; a 200 is not proof) → Threads audit record
- Circuit breaker: halt and page if more than N containments fire in an hour —
  that is a bug or a compromised webhook, not an incident
