# Bedrock enforcement test cluster

Six Bedrock API keys driving traffic from inside EKS, so Attribute can attribute
spend per key and the CloudFlow flow can contain one of them while the other
five keep working.

## Cost

The EKS control plane bills **~$0.10/hr (~$73/mo)** whether or not anything
runs on it, plus ~$0.02/hr for the t3.small node — about **$0.12/hr, $88/mo**.
It does not idle down. Run `./eks/teardown.sh` when you are done.

Bedrock spend during tests is negligible: `nova-micro` at 64 max tokens is
fractions of a cent per request.

## Setup

```bash
aws eks update-kubeconfig --name attribute-bedrock-test --region us-east-1 --profile attrb-admin
kubectl apply -f eks/load-generator.yaml
./eks/provision-keys.sh --profile attrb-admin
```

That mints six IAM users, one Bedrock key each, and loads them into the cluster
as Secrets. Key values are never printed or written to disk — IAM returns a key
only at creation, so a lost key must be reset rather than recovered.

| Workload | IAM user |
|---|---|
| `checkout-agent` | `attrb-load-checkout-agent` |
| `support-summarizer` | `attrb-load-support-summarizer` |
| `doc-indexer` | `attrb-load-doc-indexer` |
| `fraud-scorer` | `attrb-load-fraud-scorer` |
| `chat-assistant` | `attrb-load-chat-assistant` |
| `batch-enricher` | `attrb-load-batch-enricher` |

Each key is scoped to `InvokeModel` on `nova-micro` and `nova-lite` only, so a
key leaking out of this cluster reaches nothing else.

## Generating load

```bash
./eks/generate-load.sh --workload checkout-agent --requests 300
./eks/generate-load.sh --all --requests 100
./eks/generate-load.sh --logs checkout-agent
```

To push one key over a threshold while the others stay at baseline:

```bash
./eks/generate-load.sh --all --requests 50 --delay-ms 500
./eks/generate-load.sh --workload fraud-scorer --requests 3000 --concurrency 8
```

## What the load generator shows you

It is built to make containment visible. When the flow disables a key mid-run
the job prints the exact request where 200 became 403:

```
  *** KEY STOPPED WORKING at request 412 (37.4s into the run) ***

CONTAINMENT OBSERVED
  key served 411 requests, then began failing
  it stayed usable for 37.4s after this run started
  that window is the money and exposure the flow did not prevent
```

That last number is the metric the whole project exists to shrink.

Jobs exit 0 even when the key is revoked — containment is the expected outcome
of the scenario, not a job failure.

## Design notes

**EC2 nodes, not Fargate.** Attribute's sensor is eBPF and runs as a privileged
DaemonSet. Fargate gives no node-level access, so the sensor cannot run there.

**Jobs, not Deployments.** A t3.small caps at 11 pods (ENI limit); kube-system
plus the Attribute DaemonSet take about five. One-shot Jobs keep the cluster
idle between tests and leave room for all six to run at once.

**No IRSA for Bedrock.** The node role has no Bedrock permissions on purpose.
Workloads authenticate only with their API key, so revoking that key genuinely
stops them — with IRSA in play, a "contained" workload might keep working
through the node role and the test would prove nothing.

**No image build.** Bedrock API keys are bearer tokens, so a stock
`python:3.12-alpine` plus a ConfigMap covers it — no SigV4, no SDK, no Docker,
no ECR.

## The Attribute sensor is not installed here

`attributesensor.sh` is a **systemd** installer for a VM — it writes
`/etc/systemd/system/zprobe.service`. It will not work on EKS, which needs
Attribute's DaemonSet or Helm chart plus a workload token. Get those from the
Attribute team and install into this cluster; everything else here is ready.

Until then the cluster generates real, attributable Bedrock traffic — it just
is not being observed by Attribute yet.

## Teardown

```bash
./eks/teardown.sh --profile attrb-admin
./eks/teardown.sh --profile attrb-admin --keys-only   # keep the cluster
```

Verifies no `attrb-load-*` users and no `eksctl-attribute-bedrock-test-*` stacks
remain, so nothing keeps billing quietly.
