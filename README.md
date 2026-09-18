# CloudWaste Autopilot

**Find waste. Understand why. Fix it safely.**

An AI-powered FinOps control plane for AWS. It combines AWS-native cost signals
with its own detection, explains every finding from evidence, and carries a
change through policy, approval, execution, verification and rollback.

```
                    ┌──────────────┐
                    │  AWS ACCOUNT │
                    └──────┬───────┘
                           │
      Cost Explorer · Cost Optimization Hub · Compute Optimizer
      Cost Anomaly Detection · CloudWatch · CloudTrail · Tags
                           │
                    ┌──────▼───────┐
                    │ WASTE ENGINE │  detect · score · confidence
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ RISK ENGINE  │  what could go wrong
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │    POLICY    │  deny · approve · automate
                    └──────┬───────┘
                           │
                 ┌─────────┴─────────┐
              DENY              APPROVAL / AUTO
                                     │
                              ┌──────▼───────┐
                              │ REMEDIATION  │  preflight · checkpoint
                              └──────┬───────┘  execute · verify
                                     │
                            ┌────────┴────────┐
                         VERIFIED          ROLLBACK
```

---

## Quick start

No AWS account or credentials needed. The API ships with a deterministic
synthetic account so the entire pipeline runs locally.

```bash
# API
cd apps/api
python -m venv .venv && ./.venv/Scripts/pip install -e ".[dev]"   # Windows
# python -m venv .venv && ./.venv/bin/pip install -e ".[dev]"     # macOS/Linux
./.venv/Scripts/uvicorn cloudwaste.main:app --reload

# Console (separate terminal)
cd apps/web
npm install
npm run dev
```

Open <http://localhost:3000> and press **Run scan**. The API alone is at
<http://localhost:8000/docs>.

```bash
cd apps/api && ./.venv/Scripts/pytest -q      # 72 tests
```

---

## What it does

Twenty-two synthetic resources produce fifteen findings worth **$2,587/month**
against **$4,410/month** of spend, including several that are deliberately
*not* flagged.

| Detector | Finds | Refuses to flag |
|---|---|---|
| EC2 | Idle, underutilized, oversized — one finding each, never overlapping | Batch workloads with low average but high p95 CPU |
| EBS | Unattached volumes, gp2 that should be gp3, volumes on stopped instances | Volumes serving real IOPS |
| RDS | Databases with no connections, oversized instances | Anything where CPU, IOPS and connections don't all agree |
| Lambda | Over-provisioned memory, never-invoked functions | Changes where the duration increase eats the saving |
| S3 | Missing cold-storage lifecycle | Buckets where monitoring fees or payback period kill the saving |
| NAT Gateway | Near-zero throughput — **reported, never auto-remediated** | — |
| Elastic IP | Unassociated addresses | Addresses in use |
| Cost anomaly | AWS-detected deviations, attributed to resources | — (carries no remediation) |

### Two scores, deliberately separate

**Waste score** (0–100) is how much of the spend looks wasted.
**Confidence** (0–100) is how strong the evidence is.

A resource can score 90 for waste and 40 for confidence — "looks bad, can't
prove it". Collapsing these into one number is how FinOps tools lose trust:
a $4 idle IP and a $900 oversized production database both read "high" and the
operator stops looking.

### Every claim is sourced

No finding asserts anything without naming where it came from:

```
cloudwatch          CPUUtilization averaged 8.71% over 14 days (336 datapoints)
cloudwatch          MemoryUtilization is not published (no CloudWatch agent), so a
                    memory-bound workload cannot be ruled out
compute_optimizer   AWS finding 'OVER_PROVISIONED': m5.2xlarge → m5.large,
                    est. $210.24/month
cloudtrail          Last configuration change 23 days ago, by priya.raman
tags                environment=development, criticality=low, owner=data-platform
cost_explorer       $283.58/month (observed unblended cost)
```

---

## What AWS provides vs what this builds

AWS already does the hard measurement work, and this project says so:

- **Cost Optimization Hub** aggregates optimization recommendations with savings estimates
- **Compute Optimizer** analyzes utilization and recommends rightsizing
- **Cost Explorer** answers cost and usage queries
- **Cost Anomaly Detection** flags deviations from forecast

CloudWaste Autopilot does not reimplement any of that. It is the **control
plane above it**: correlating those signals with CloudWatch, CloudTrail and
tags; scoring waste separately from confidence; assessing the risk of a
*specific action on a specific resource*; enforcing policy; running approval;
executing through a checkpointed state machine; verifying against a pre-change
baseline; and rolling back when verification fails.

The gap it fills is the one between "AWS says this instance is oversized" and
"someone safely resized it and can prove nothing broke."

---

## Safety model

This is the part that matters. An automated remediation engine pointed at a
production AWS account is a liability unless each of these holds.

**1. The agent cannot mutate AWS.** All 16 agent tools are read-only except
`propose_action`, which creates a *pending* action. There is no approve tool and
no execute tool. A prompt injection in a resource tag can at worst cause a
badly-reasoned proposal, which still has to clear policy and a human.

**2. Risk floors cannot be mitigated away.** Production, unknown environment,
high criticality, irreversibility and low confidence each set a floor no
combination of mitigations can lower.

**3. Untagged means production.** A resource with no environment tag is treated
as production, because the alternative is discovering its environment by
breaking it.

**4. Owner opt-out is absolute.** `AutoRemediation=false` blocks every action,
including trivially safe ones.

**5. Destructive actions require a proven backup.** Deleting a volume is refused
unless a *completed* snapshot of *that* volume covering its *current size*
exists, checked against live AWS at execution time.

**6. Policy is deny-biased.** No matching rule means approval required. A
matching deny beats every allow regardless of priority. Deployment ceilings
(`autopilot_enabled`, `autopilot_max_risk`) override any rule — a policy file
cannot grant itself more authority than the deployment allows.

**7. Preflight re-checks reality.** A recommendation comes from a scan that may
be hours old. Before mutating, the executor re-reads live AWS and refuses if the
volume was reattached, the instance was re-tagged production, or the database
now has pending modifications.

**8. Approvals expire and are bound to the plan.** An approval is fingerprinted
against the target, risk and savings. Change any of them and it no longer
applies.

**9. Rollback failure is escalated, not swallowed.** Failed change *plus* failed
undo is its own terminal state (`ROLLBACK_FAILED`) on its own SNS topic, with the
pre-execution checkpoint attached.

**10. Nothing claims a rollback it doesn't have.** Releasing an Elastic IP
reports `rollback_possible: false`. Restoring a deleted volume creates a *new*
volume with a new id and says so — that's recovery, not undo.

Defaults: `dry_run=true`, `autopilot_enabled=false`. Out of the box it cannot
change anything.

---

## Honest about the numbers

- Savings prefer **observed billing** (Cost Explorer) and fall back to list
  pricing, which is labelled as such. List prices ignore Savings Plans and
  Reserved Instances and will overstate savings for committed workloads.
- Resizes project by **scaling the observed bill by the list-price ratio**, so
  existing discounts carry through rather than being erased.
- Lambda savings **subtract the duration increase** that less memory causes,
  using a pessimistic model. Some "over-provisioned" functions correctly produce
  no recommendation because the change would cost more.
- S3 savings are **net of Intelligent-Tiering monitoring fees and one-off
  transition costs**, and are dropped if payback exceeds six months.
- Cost anomalies report **$0 potential savings** — the excess is real money but
  not *recoverable* money until a human says the spend was unintended.
- Cost verification is **deferred, not skipped**: AWS billing lags up to 24
  hours, so a post-execution cost check would fail for every successful action.

---

## Layout

```
apps/api/cloudwaste/
├── adapters/          AWS API clients (boto3) + pricing + tag interpretation
│   ├── base.py        Provider protocols — live and demo are interchangeable
│   └── aws/           cost, metrics, inventory, recommendations, activity
├── intelligence/      The core. No I/O, fully unit-testable.
│   ├── detectors/     One per service; pure functions of a prepared context
│   ├── waste_score.py     Weighted, renormalized over available signals
│   ├── confidence_engine.py  Evidence quality, separate from waste
│   ├── risk_engine.py     Additive scoring with hard floors
│   ├── impact_analyzer.py Simulation: cost, downtime, rollback
│   └── recommendation_engine.py  Finding → concrete action
├── policy/            Rule engine + validator + default_policies.yaml
├── actions/           Executors (4-phase), approval, verification, orchestrator
├── agent/             Bedrock tool loop + deterministic fallback analyst
├── repositories/      In-memory and DynamoDB behind one interface
├── seed/              The synthetic account
└── api/routes/        FastAPI

apps/web/              Next.js 15 console
infra/                 CloudFormation + Step Functions ASL
```

### Running against a real account

1. Deploy `infra/cloudformation/cloudwaste.yaml` in the account that runs CloudWaste.
2. Deploy `infra/cloudformation/customer-account.yaml` in each account to scan.
   Read permissions are unconditional; `EnableRemediation` and
   `EnableDestructiveRemediation` are separate opt-ins, both default `false`.
3. Register it: `POST /api/v1/accounts` with `mode: "live"` and the role ARN.

The customer template also denies writes to production-tagged resources **at the
IAM layer**, so a policy-engine bug still cannot reach production.

### Configuration

Environment variables, all prefixed `CLOUDWASTE_`:

| Setting | Default | Meaning |
|---|---|---|
| `DRY_RUN_DEFAULT` | `true` | Every phase runs except the AWS mutation |
| `AUTOPILOT_ENABLED` | `false` | Master switch for unattended execution |
| `AUTOPILOT_MAX_RISK` | `low` | Ceiling no policy rule can raise |
| `STORAGE_BACKEND` | `memory` | or `dynamodb` |
| `BEDROCK_ENABLED` | `false` | Falls back to a deterministic local analyst |
| `BEDROCK_MODEL_ID` | `anthropic.claude-sonnet-4-5-...` | Converse API model |
| `METRIC_WINDOW_DAYS` | `14` | Utilization observation window |

---

## Agent

Sixteen tools over cost, anomalies, AWS recommendations, inventory, CloudWatch,
CloudTrail and CloudWaste's own findings. Runs either as a direct Bedrock
Converse loop or through **Bedrock AgentCore** — `tool_definitions()` and
`invoke_tool()` are the integration points, and the safety properties live in
the tools rather than the loop, so they hold either way.

With `BEDROCK_ENABLED=false` a deterministic local analyst answers from the same
tools. It is keyword routing, not understanding, and says so when it doesn't
recognize a question. It exists so the product demos without model access and so
tests never touch the network.
