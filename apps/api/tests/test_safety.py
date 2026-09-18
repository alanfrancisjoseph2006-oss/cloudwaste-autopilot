"""Safety properties.

These are the tests that matter. Everything else in this repository is a
convenience; these encode the promises that make it responsible to point an
automated remediation engine at an AWS account. If one of these fails, the
correct response is to stop shipping, not to adjust the assertion.
"""

from __future__ import annotations

import pytest

from cloudwaste.actions.approval import ApprovalEngine, plan_fingerprint
from cloudwaste.actions.registry import get_executor, is_executable
from cloudwaste.config import Settings
from cloudwaste.intelligence import risk_engine
from cloudwaste.models.domain import Recommendation, Resource
from cloudwaste.models.enums import (
    ActionType,
    ApprovalStatus,
    Criticality,
    Environment,
    ExecutionStatus,
    PolicyDecision,
    ResourceType,
    RiskLevel,
)
from cloudwaste.policy.policy_engine import PolicyEngine


def _resource(**overrides) -> Resource:
    defaults = dict(
        resource_id="i-test",
        resource_type=ResourceType.EC2,
        account_id="123456789012",
        region="us-east-1",
        environment=Environment.DEVELOPMENT,
        criticality=Criticality.LOW,
        monthly_cost=100.0,
        configuration={"instance_type": "m5.large"},
    )
    defaults.update(overrides)
    return Resource(**defaults)


def _recommendation(resource: Resource, **overrides) -> Recommendation:
    defaults = dict(
        finding_id="F-test",
        resource_id=resource.resource_id,
        resource_type=resource.resource_type,
        account_id=resource.account_id,
        region=resource.region,
        action_type=ActionType.STOP_EC2,
        current_configuration="m5.large",
        recommended_configuration="stopped",
        monthly_savings=100.0,
        confidence=95.0,
        risk=RiskLevel.LOW,
        rollback_possible=True,
    )
    defaults.update(overrides)
    return Recommendation(**defaults)


# ==========================================================================
# The agent cannot mutate AWS
# ==========================================================================


def test_no_agent_tool_mutates_aws(service, account):
    """The agent's entire tool surface is read-only plus one proposal tool.

    This is the property that makes it safe to let a language model drive
    this system. If a tool that mutates AWS is ever added, this fails.
    """
    from cloudwaste.agent.runtime import CloudWasteAgent

    agent = CloudWasteAgent(service, account, service.settings)
    names = set(agent.registry.names())

    mutating_verbs = ("delete", "stop", "start", "resize", "modify", "release", "execute",
                      "approve", "terminate", "create_snapshot", "put", "update")
    offenders = [
        name
        for name in names
        if any(name.startswith(verb) for verb in mutating_verbs)
    ]
    assert offenders == [], f"Agent has tools that look mutating: {offenders}"
    assert "propose_action" in names
    assert not any("approve" in n or "execute" in n for n in names)


def test_agent_proposal_never_executes(scanned):
    """propose_action creates a pending action and nothing more."""
    from cloudwaste.agent.runtime import CloudWasteAgent

    service, account, result = scanned
    agent = CloudWasteAgent(service, account, service.settings)

    recommendation = result["recommendations"][0]
    response = agent.invoke_tool(
        "propose_action",
        {"recommendation_id": recommendation.recommendation_id, "reason": "test"},
    )
    assert response["ok"]

    action = service.repos.actions.get(response["result"]["action_id"])
    assert action.execution_status is ExecutionStatus.NOT_STARTED
    assert action.started_at is None
    assert action.approval_status in (
        ApprovalStatus.PENDING,
        ApprovalStatus.REJECTED,
    )


# ==========================================================================
# Risk floors cannot be mitigated away
# ==========================================================================


def test_production_is_never_below_high_risk():
    """No combination of mitigations drags a production action below HIGH."""
    resource = _resource(
        environment=Environment.PRODUCTION,
        criticality=Criticality.LOW,
        auto_remediation_allowed=True,  # maximum mitigation
    )
    assessment = risk_engine.assess(
        risk_engine.RiskInputs(
            action_type=ActionType.CREATE_EBS_SNAPSHOT,  # lowest-risk action
            resource=resource,
            confidence=99.0,
            rollback_possible=True,
            restart_required=False,
            downtime_seconds=0,
            has_recent_backup=True,
        )
    )
    assert assessment.level.rank >= RiskLevel.HIGH.rank


def test_untagged_resource_is_treated_as_production():
    """An unknown environment must not be treated as safe."""
    assessment = risk_engine.assess(
        risk_engine.RiskInputs(
            action_type=ActionType.STOP_EC2,
            resource=_resource(environment=Environment.UNKNOWN, criticality=Criticality.UNKNOWN),
            confidence=99.0,
        )
    )
    assert assessment.level.rank >= RiskLevel.HIGH.rank
    assert any("unknown" in note.lower() for note in assessment.floors_applied)


def test_owner_opt_out_blocks_everything():
    """AutoRemediation=false is absolute, even for a trivial action."""
    resource = _resource(auto_remediation_allowed=False)
    assessment = risk_engine.assess(
        risk_engine.RiskInputs(
            action_type=ActionType.CREATE_EBS_SNAPSHOT,
            resource=resource,
            confidence=99.0,
        )
    )
    assert assessment.is_blocked
    assert assessment.level is RiskLevel.CRITICAL


def test_destructive_action_without_backup_is_blocked():
    """Deleting data with no snapshot is refused outright."""
    resource = _resource(
        resource_type=ResourceType.EBS,
        resource_id="vol-test",
        configuration={"size_gb": 100, "volume_type": "gp3"},
    )
    assessment = risk_engine.assess(
        risk_engine.RiskInputs(
            action_type=ActionType.DELETE_EBS,
            resource=resource,
            confidence=99.0,
            data_bearing=True,
            has_recent_backup=False,
        )
    )
    assert assessment.is_blocked
    assert any("backup" in reason.lower() for reason in assessment.blocking_reasons)


def test_low_confidence_is_never_below_high_risk():
    assessment = risk_engine.assess(
        risk_engine.RiskInputs(
            action_type=ActionType.CREATE_EBS_SNAPSHOT,
            resource=_resource(),
            confidence=40.0,
        )
    )
    assert assessment.level.rank >= RiskLevel.HIGH.rank


# ==========================================================================
# Policy is deny-biased
# ==========================================================================


def test_unmatched_action_requires_approval(policy_rules, settings):
    """No rule means no pre-authorization."""
    engine = PolicyEngine([], settings)  # empty rule set
    resource = _resource()
    evaluation = engine.evaluate(_recommendation(resource), resource)
    assert evaluation.decision is PolicyDecision.REQUIRE_APPROVAL
    assert not evaluation.auto_execute


def test_deny_beats_allow_regardless_of_priority(settings):
    """A protection rule cannot be outvoted by a narrower allow."""
    from cloudwaste.models.domain import PolicyRule

    rules = [
        PolicyRule(
            name="narrow-allow",
            priority=1,
            resource_type=ResourceType.EC2,
            action=ActionType.STOP_EC2,
            effect="allow",
            auto_execute=True,
            require_approval=False,
        ),
        PolicyRule(
            name="broad-deny",
            priority=500,
            environment=Environment.PRODUCTION,
            effect="deny",
        ),
    ]
    engine = PolicyEngine(rules, settings)
    resource = _resource(environment=Environment.PRODUCTION)
    evaluation = engine.evaluate(_recommendation(resource), resource)
    assert evaluation.decision is PolicyDecision.DENY
    assert evaluation.matched_rule == "broad-deny"


def test_autopilot_disabled_overrides_auto_execute_rules(policy_rules):
    """A policy file cannot grant more authority than the deployment allows."""
    settings = Settings(autopilot_enabled=False, autopilot_max_risk="critical")
    engine = PolicyEngine(policy_rules, settings)
    resource = _resource(environment=Environment.DEVELOPMENT)
    recommendation = _recommendation(resource, risk=RiskLevel.LOW, confidence=99.0)

    evaluation = engine.evaluate(recommendation, resource)
    assert evaluation.decision is not PolicyDecision.AUTO_EXECUTE
    assert any("autopilot is disabled" in r.lower() for r in evaluation.reasons)


def test_risk_ceiling_overrides_auto_execute(policy_rules):
    settings = Settings(autopilot_enabled=True, autopilot_max_risk="low")
    engine = PolicyEngine(policy_rules, settings)
    resource = _resource(environment=Environment.DEVELOPMENT)
    recommendation = _recommendation(resource, risk=RiskLevel.HIGH, confidence=99.0)

    evaluation = engine.evaluate(recommendation, resource)
    assert evaluation.decision is not PolicyDecision.AUTO_EXECUTE


def test_irreversible_action_never_auto_executes(policy_rules):
    settings = Settings(autopilot_enabled=True, autopilot_max_risk="critical")
    engine = PolicyEngine(policy_rules, settings)
    resource = _resource(environment=Environment.DEVELOPMENT)
    recommendation = _recommendation(
        resource, risk=RiskLevel.LOW, confidence=99.0, rollback_possible=False
    )
    evaluation = engine.evaluate(recommendation, resource)
    assert evaluation.decision is not PolicyDecision.AUTO_EXECUTE


def test_shipped_policy_set_has_no_errors(policy_rules):
    """The default policy file must be safe as shipped."""
    from cloudwaste.policy.policy_loader import validate

    problems = validate(policy_rules)
    errors = [p for p in problems if p["severity"] == "error"]
    assert errors == [], f"Shipped policy set has errors: {errors}"


def test_policy_loader_rejects_unknown_fields(tmp_path):
    """A misspelled key must fail loudly, not silently widen a rule."""
    from cloudwaste.policy.policy_loader import PolicyError, load_rules

    path = tmp_path / "bad.yaml"
    path.write_text(
        "rules:\n"
        "  - name: typo\n"
        "    enviroment: production\n"  # misspelled
        "    effect: deny\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="unknown field"):
        load_rules(path)


# ==========================================================================
# Approval integrity
# ==========================================================================


def test_approval_is_bound_to_the_plan(service, account, scanned):
    """Changing the plan invalidates an approval given for the old one."""
    from cloudwaste.actions.approval import ApprovalError

    service, account, result = scanned

    # Find a recommendation that actually reaches PENDING. Picking the first
    # one would skip whenever policy happens to deny it, which would quietly
    # stop testing this property at all.
    for candidate in result["recommendations"]:
        resource = service.repos.resources.get(candidate.resource_id)
        action, _ = service.create_action(candidate, resource, requested_by="a@example.com")
        if action.approval_status is ApprovalStatus.PENDING:
            recommendation = candidate
            break
    else:
        pytest.fail("No recommendation in the demo account reaches PENDING approval")

    # The plan changes underneath the approval.
    recommendation.monthly_savings += 500
    recommendation.recommended_configuration = "something-else"

    with pytest.raises(ApprovalError, match="changed"):
        service.approvals.approve(action, "b@example.com", recommendation)


def test_expired_approval_cannot_execute():
    """A yes given weeks ago is not a yes today."""
    from datetime import datetime, timedelta, timezone

    from cloudwaste.models.domain import Action

    action = Action(
        recommendation_id="REC-1", finding_id="F-1", resource_id="i-1",
        resource_type=ResourceType.EC2, account_id="1", region="us-east-1",
        action_type=ActionType.STOP_EC2, risk=RiskLevel.LOW,
        approval_required=True, approval_status=ApprovalStatus.PENDING,
        approval_expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    engine = ApprovalEngine()
    allowed, reason = engine.can_execute(action)
    assert not allowed
    assert action.approval_status is ApprovalStatus.EXPIRED
    assert "expired" in reason.lower()


def test_action_executes_at_most_once():
    from cloudwaste.models.domain import Action

    action = Action(
        recommendation_id="REC-1", finding_id="F-1", resource_id="i-1",
        resource_type=ResourceType.EC2, account_id="1", region="us-east-1",
        action_type=ActionType.STOP_EC2, risk=RiskLevel.LOW,
        approval_required=False, approval_status=ApprovalStatus.NOT_REQUIRED,
        execution_status=ExecutionStatus.COMPLETED,
    )
    allowed, reason = ApprovalEngine().can_execute(action)
    assert not allowed
    assert "already" in reason.lower()


def test_plan_fingerprint_ignores_ids_but_catches_material_change():
    resource = _resource()
    a = _recommendation(resource)
    b = _recommendation(resource)  # different recommendation_id
    assert plan_fingerprint(a) == plan_fingerprint(b)

    c = _recommendation(resource, recommended_configuration="t3.micro")
    assert plan_fingerprint(a) != plan_fingerprint(c)

    d = _recommendation(resource, risk=RiskLevel.CRITICAL)
    assert plan_fingerprint(a) != plan_fingerprint(d)


# ==========================================================================
# Dry run and execution guards
# ==========================================================================


def test_dry_run_makes_no_aws_call(scanned):
    """In dry run there is no client factory at all, so any AWS call raises.

    The action still completes, which proves the mutation was skipped rather
    than merely failing silently.
    """
    service, account, result = scanned
    recommendation = next(
        r for r in result["recommendations"] if r.action_type is ActionType.STOP_EC2
    )
    resource = service.repos.resources.get(recommendation.resource_id)
    action, _ = service.create_action(recommendation, resource, dry_run=True)

    if action.approval_required:
        action.approval_status = ApprovalStatus.APPROVED
        action.approved_by = "test"
        service.repos.actions.put(action)

    outcome = service.execute_action(action, account, settle_seconds=0)
    assert outcome.succeeded
    assert outcome.action.dry_run
    assert any("DRY RUN" in s["detail"] for s in outcome.states)


def test_every_executor_defines_all_four_phases():
    """A partially implemented executor must not be registrable."""
    from cloudwaste.actions.registry import executable_actions

    for action_type in executable_actions():
        executor = get_executor(action_type)
        for phase in ("capture", "preflight", "_apply", "verify", "rollback"):
            assert callable(getattr(executor, phase, None)), (
                f"{action_type.value} executor is missing {phase}"
            )


def test_unimplemented_actions_refuse_rather_than_stub():
    from cloudwaste.actions.registry import NoExecutorError

    assert not is_executable(ActionType.SCHEDULE_RESOURCE)
    with pytest.raises(NoExecutorError):
        get_executor(ActionType.SCHEDULE_RESOURCE)


def test_irreversible_executor_reports_no_rollback():
    """Releasing an Elastic IP must not claim a rollback it does not have."""
    from cloudwaste.intelligence.impact_analyzer import ROLLBACK_METHODS

    assert ROLLBACK_METHODS[ActionType.RELEASE_ELASTIC_IP] is None


# ==========================================================================
# Audit completeness
# ==========================================================================


def test_every_action_outcome_writes_audit(scanned):
    """Including the ones that are refused before anything happens."""
    service, account, result = scanned
    recommendation = result["recommendations"][0]
    resource = service.repos.resources.get(recommendation.resource_id)

    action, _ = service.create_action(recommendation, resource, requested_by="a@example.com")
    created = [
        e for e in service.repos.audit.list() if e.action_id == action.action_id
    ]
    assert created, "Creating an action wrote no audit record"
    assert created[0].event == "action.created"
    assert created[0].detail["policy_decision"]

    # Executing without approval must still leave a trace.
    outcome = service.execute_action(action, account, settle_seconds=0)
    entries = [e for e in service.repos.audit.list() if e.action_id == action.action_id]
    assert len(entries) >= 2
    assert not outcome.succeeded or outcome.action.execution_status is ExecutionStatus.COMPLETED
