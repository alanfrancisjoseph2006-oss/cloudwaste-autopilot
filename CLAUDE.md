# CloudWaste Autopilot — working notes

Context for anyone (human or agent) changing this codebase.

## Commands

```bash
cd apps/api
./.venv/Scripts/pytest -q                       # full suite (72 tests)
./.venv/Scripts/pytest tests/test_safety.py -q   # safety properties only
./.venv/Scripts/uvicorn cloudwaste.main:app --reload

cd apps/web
npm run dev
npm run typecheck
```

On Windows the venv binaries are under `.venv/Scripts/`, elsewhere `.venv/bin/`.

## Architecture rules

**The intelligence layer does no I/O.** Everything under `intelligence/` is a
pure function of data handed to it. Detectors receive a prepared
`DetectionContext` and never call AWS. This is what makes the detection layer
testable without a network, and it should stay that way — if a detector needs
a new signal, add it to the context in the orchestrator, don't fetch it in the
detector.

**Live and demo data planes are interchangeable.** Both satisfy the protocols in
`adapters/base.py`. Any new provider method must be implemented in both
`adapters/aws/` and `seed/demo_provider.py`, or the demo account silently
diverges from reality and tests stop meaning anything.

**Risk belongs to the action, not the resource.** `risk_engine.assess()` takes
an action *and* a resource. Deleting an unattached volume in dev and in
production are different risks. Don't add a `resource.risk` field.

**Waste score, confidence and risk are three different numbers.** Never merge
them. See the README for why.

## Things that will bite you

- **A missing metric is not zero.** `DetectionContext.series()` returns `None`
  for a series with no datapoints. EC2 memory and disk only exist where the
  CloudWatch agent is installed. Treating absence as 0% utilization would flag
  every unmonitored instance as idle.
- **Cost Explorer is us-east-1 only**, as is Cost Optimization Hub.
  `adapters/aws/clients.py` pins them via `GLOBAL_SERVICES`.
- **`get_cost_by_resource` returns `None`, not `0.0`,** when resource-level
  granularity is off (the default, and only 14 days of retention). `None` means
  "ask the price book"; `0.0` would mean "this was free" and would zero out
  every savings figure.
- **DynamoDB has no float type.** `repositories/dynamodb.py` converts to
  `Decimal` on write and back on read. Skipping that fails the first time a
  saving lands on a non-integer.
- **CloudTrail `LookupEvents` covers 90 days** and is rate-limited to roughly
  2 req/s. The scan only queries it for resources that already produced a
  finding — see step 5 in `waste_detector.scan()`. Don't move it earlier.
- **`ApplyImmediately=True` is mandatory on RDS modifications.** Without it the
  change defers to the next maintenance window and the action reports success
  having changed nothing today.
- **Multi-AZ RDS resizes are a failover, not a restart** (~120s vs ~900s), and
  the instance passes through `modifying`/`rebooting` before returning to
  `available`. A naive wait returns immediately because it's still `available`
  for a moment after the API accepts the call.
- **Lambda: less memory means less CPU.** Halving memory can more than double
  duration, and billing is memory × duration, so a naive downsize *increases*
  cost. `lambda_.py::_project_duration` models this pessimistically on purpose.
- **AWS allows one EBS volume modification per six hours.** Rollback of a
  gp2→gp3 conversion may be rejected if the original change was recent.

## Adding a detector

1. Write it in `intelligence/detectors/`, implementing `detect(context)`.
2. Register it in `waste_detector.DETECTORS`.
3. Add its metrics to `adapters/aws/metrics.METRIC_CATALOG`.
4. Add fixtures to `seed/demo_provider._SPECS` — including at least one that
   must **not** be flagged.
5. Map its `WasteType` in `recommendation_engine.build()`, or deliberately leave
   it unmapped if there is no safe generic action.
6. Add positive *and* negative tests to `tests/test_detection.py`.

## Adding an executor

Subclass `actions/executors/base.Executor` and implement all five phases:
`capture`, `preflight`, `_apply`, `verify`, `rollback`. Register it in
`actions/registry.py`. `test_every_executor_defines_all_four_phases` enforces
completeness.

Do not override `execute()` — the base class enforces dry-run there so a new
executor cannot forget to honour it.

`preflight` is not optional. It re-reads live AWS and refuses if anything
material changed since the recommendation was produced. Without it the system
acts on a memory of the account rather than the account.

If an action genuinely cannot be rolled back, set `rollback_description = "none"`
and have `rollback()` return `ExecutionOutcome(succeeded=False, ...)` explaining
why. Never describe a manual recovery procedure as a rollback.

## Changing policy

`cloudwaste/policy/default_policies.yaml` is validated at startup and the app
refuses to run if validation produces errors. `policy_loader.validate()` rejects
auto-executing rules that are unscoped, target production, or permit HIGH+ risk.

`test_shipped_policy_set_has_no_errors` fails if the default set stops being
safe. If you need to change it, change the test's expectations deliberately and
say why in the commit.

## The Step Functions definition mirrors the orchestrator

`infra/stepfunctions/remediation.asl.json` and `actions/orchestrator.py` run the
same states in the same order. Change one, change the other — what's tested
locally is what runs in production, and that only holds if they stay in step.

## The demo account is a test fixture, not decoration

`seed/demo_provider.py` is seeded (`SEED = 20260918`) and deterministic. Tests
assert exact resources and exact numbers against it. Changing a spec will break
tests, which is the intended behaviour — the alternative is tests that pass
regardless of what the detectors do.

It includes resources that must produce **no** finding (a busy production
instance, a hot S3 bucket, an in-use Elastic IP). Keep them.
