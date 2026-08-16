# Bedrock enforcement test cluster

Six Bedrock API keys driving traffic from inside EKS, so Attribute can attribute
spend per key and the CloudFlow flow can contain one of them while the other
five keep working.

## Cost

The EKS control plane bills **~$0.10/hr (~$73/mo)** whether or not anything
runs on it, plus ~$0.02/hr for the t3.small node — about **$0.12/hr, $88/mo**.
It does not idle down. Run `./eks/teardown.sh` when you are done.

**Stay on a standard-support Kubernetes version.** Once a version reaches
extended support AWS bills the cluster at **$0.60/hr instead of $0.10/hr** —
six times the cost, for an idle test cluster. This bit us: the cluster was
first built on 1.31, which had already left standard support, and ran at
~$0.62/hr until it was rebuilt on 1.36. Check before pinning a version:

```bash
aws eks describe-cluster-versions --region us-east-1
```

Bedrock spend during tests is negligible: `nova-micro` at 64 max tokens is
fractions of a cent per request.

## Upgrading

EKS upgrades one minor version at a time, so a cluster several versions behind
takes hours of sequential control-plane upgrades — all billed at the extended
support rate if that is why you are upgrading.

For this cluster, **rebuilding is faster and cheaper than upgrading**. Nothing
here is precious: the IAM users and Bedrock keys live in IAM and survive, and
the only in-cluster state is six Secrets and a ConfigMap.

```bash
eksctl delete cluster --name attribute-bedrock-test --region us-east-1 --wait
eksctl create cluster -f eks/cluster.yaml
kubectl apply -f eks/load-generator.yaml
./eks/provision-keys.sh --profile attrb-admin
```

`provision-keys.sh` rotates each user's key rather than creating duplicates, so
re-running it after a rebuild is safe.

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

## Installing the Attribute sensor

`attributesensor.sh` is a **systemd** installer for a VM and will not work on
EKS. The cluster install is the Helm chart:

```bash
cp eks/attribute-values.example.yaml eks/attribute-values.yaml
# paste the token from Attribute into eks/attribute-values.yaml
helm install attribute oci://quay.io/attribute/operator-chart \
  -f eks/attribute-values.yaml -n attribute --create-namespace
```

`eks/attribute-values.yaml` is **gitignored** — it carries a live organization
token. Only the sanitised example belongs in the repo.

### Blocked: 401 registering this AWS account

The install currently fails. The `attrb-pre-install-hook` Job correctly detects
EKS, then calls Attribute's registration API and is rejected:

```
Getting sensor token
  url=https://sensor.app.attrb.io/api/v1/register/aws/641260351119/attribute-bedrock-test
Failed to get sensor token: 401 Unauthorized ()
```

The token is **valid and unexpired** — the 401 is authorisation, not expiry.
Registration is keyed on the **AWS account ID**, and the supplied token
(`values-doit-fe-payer.yaml`) appears scoped to the DoiT FE payer, not to the
playground account 641260351119.

Resolving it needs Attribute to either issue a token valid for 641260351119 or
onboard that account. Nothing in this repo can work around it.

Two operational notes while it is failing:

- **The failed hook Job retries and each attempt leaves a pod behind.** On a
  t3.small that filled all 11 pod slots in minutes and blocked everything else.
  Clean up with `helm uninstall attribute -n attribute` and
  `kubectl delete namespace attribute` before doing anything else.
- **The init container prints the full token in its pod logs.** Anyone with
  `kubectl logs` on that namespace can read an organization credential. Worth
  raising with Attribute.

Until this is resolved the cluster still generates real, attributable Bedrock
traffic — it is simply not being observed yet.

## Teardown

```bash
./eks/teardown.sh --profile attrb-admin
./eks/teardown.sh --profile attrb-admin --keys-only   # keep the cluster
```

Verifies no `attrb-load-*` users and no `eksctl-attribute-bedrock-test-*` stacks
remain, so nothing keeps billing quietly.
