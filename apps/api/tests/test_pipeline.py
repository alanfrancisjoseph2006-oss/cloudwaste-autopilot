"""End-to-end pipeline, simulation and HTTP API."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cloudwaste.intelligence import impact_analyzer
from cloudwaste.models.enums import (
    ActionType,
    ApprovalStatus,
    ExecutionStatus,
    FindingStatus,
    ResourceType,
    RiskLevel,
)


# ==========================================================================
# Scan pipeline
# ==========================================================================


def test_scan_produces_findings_and_recommendations(scanned):
    service, account, result = scanned
    assert result["scan"].status == "COMPLETED"
    assert result["scan"].resources_scanned == 22
    assert result["findings"]
    assert result["recommendations"]
    assert result["scan"].errors == []


def test_rescan_is_idempotent(service, account):
    first = service.scan_account(account)
    second = service.scan_account(account)

    stored = service.repos.findings.list(account_id=account.account_id)
    assert len(stored) == len(first["findings"])
    assert {f.finding_id for f in first["findings"]} == {
        f.finding_id for f in second["findings"]
    }


def test_suppressed_finding_survives_a_rescan(service, account):
    """A human decision must not be undone by the next scan."""
    result = service.scan_account(account)
    finding = result["findings"][0]
    finding.status = FindingStatus.SUPPRESSED
    service.repos.findings.put(finding)

    service.scan_account(account)
    reloaded = service.repos.findings.get(finding.finding_id)
    assert reloaded.status is FindingStatus.SUPPRESSED


def test_dashboard_totals_match_the_scan(scanned):
    service, account, result = scanned
    dashboard = service.dashboard(account)
    assert dashboard["potential_monthly_savings"] == pytest.approx(
        result["scan"].total_potential_savings, rel=0.001
    )
    assert dashboard["monthly_spend"] == pytest.approx(
        result["scan"].total_monthly_cost, rel=0.001
    )
    assert 0 <= dashboard["waste_score"] <= 100


def test_savings_never_exceed_spend(scanned):
    """A basic sanity bound that catches double-counting."""
    service, account, result = scanned
    dashboard = service.dashboard(account)
    assert dashboard["potential_monthly_savings"] <= dashboard["monthly_spend"]


# ==========================================================================
# Simulation
# ==========================================================================


def test_resize_simulation_scales_observed_cost(data_plane):
    resource = data_plane.inventory.get_resource("i-0a1b2c3d4e5f60001")
    result = impact_analyzer.simulate(
        resource,
        ActionType.RESIZE_EC2,
        {"target_instance_type": "m5.large"},
        current_monthly_cost=280.32,
        confidence=99.0,
    )
    # m5.2xlarge -> m5.large is a 4x reduction.
    assert result.projected_monthly_cost == pytest.approx(70.08, rel=0.01)
    assert result.monthly_savings == pytest.approx(210.24, rel=0.01)
    assert result.annual_savings == pytest.approx(result.monthly_savings * 12, rel=0.001)
    assert result.restart_required
    assert result.rollback_possible
    assert result.assumptions


def test_stop_simulation_excludes_volume_cost(data_plane):
    """Stopping recovers compute only, and the assumption says so."""
    resource = data_plane.inventory.get_resource("i-0a1b2c3d4e5f60002")
    result = impact_analyzer.simulate(
        resource, ActionType.STOP_EC2, {}, current_monthly_cost=121.47
    )
    assert result.projected_monthly_cost == 0.0
    assert any("volume" in a.lower() for a in result.assumptions)


def test_delete_ebs_simulation_retains_snapshot_cost(data_plane):
    """Deleting is not free: the retained snapshot still bills."""
    resource = data_plane.inventory.get_resource("vol-0a1b2c3d4e5f60006")
    result = impact_analyzer.simulate(
        resource, ActionType.DELETE_EBS, {}, current_monthly_cost=50.0
    )
    assert result.projected_monthly_cost > 0
    assert result.monthly_savings < 50.0


def test_lambda_simulation_accounts_for_duration_increase(data_plane):
    """Halving memory doubles duration, so the saving is not half the cost."""
    resource = data_plane.inventory.get_resource("image-thumbnailer")
    naive_ratio = 1024 / 3008
    result = impact_analyzer.simulate(
        resource,
        ActionType.MODIFY_LAMBDA_MEMORY,
        {
            "target_memory_mb": 1024,
            "projected_duration_ms": 285,
            "monthly_invocations": 4_200_000,
        },
        current_monthly_cost=50.92,
    )
    naive_projection = 50.92 * naive_ratio
    assert result.projected_monthly_cost > naive_projection, (
        "Projection must be worse than a naive memory-ratio estimate, because "
        "less memory means less CPU and longer duration"
    )
    assert result.monthly_savings > 0
    assert any("duration" in a.lower() for a in result.assumptions)


def test_multi_az_rds_resize_is_a_failover_not_a_restart(data_plane):
    resource = data_plane.inventory.get_resource("payments-prod-db")
    result = impact_analyzer.simulate(
        resource,
        ActionType.RESIZE_RDS,
        {"target_instance_class": "db.r6g.large"},
        current_monthly_cost=1260.0,
    )
    assert result.downtime_estimate_seconds == 120
    assert "failover" in result.performance_impact.lower()


def test_elastic_ip_release_reports_no_rollback(data_plane):
    resource = data_plane.inventory.get_resource("eipalloc-0demo000000001")
    result = impact_analyzer.simulate(
        resource, ActionType.RELEASE_ELASTIC_IP, {}, current_monthly_cost=3.65
    )
    assert not result.rollback_possible
    assert result.rollback_method is None
    assert result.risk.rank >= RiskLevel.HIGH.rank


# ==========================================================================
# Recommendation chaining
# ==========================================================================


def test_unbacked_volume_gets_snapshot_before_delete(service, account):
    """A destructive action on unbacked data is decomposed, never bare."""
    result = service.scan_account(account)
    recommendations = [
        r for r in result["recommendations"] if r.resource_id == "vol-0a1b2c3d4e5f60007"
    ]
    assert len(recommendations) == 2
    assert recommendations[0].action_type is ActionType.CREATE_EBS_SNAPSHOT
    assert recommendations[1].action_type is ActionType.DELETE_EBS
    assert (
        recommendations[1].action_parameters["depends_on"]
        == recommendations[0].recommendation_id
    )


def test_backed_volume_gets_a_single_delete(service, account):
    result = service.scan_account(account)
    recommendations = [
        r for r in result["recommendations"] if r.resource_id == "vol-0a1b2c3d4e5f60006"
    ]
    assert len(recommendations) == 1
    assert recommendations[0].action_type is ActionType.DELETE_EBS


def test_idle_rds_gets_no_automatic_recommendation(service, account):
    """An abandoned database needs a human who knows what the data is."""
    result = service.scan_account(account)
    assert not [
        r for r in result["recommendations"] if r.resource_id == "analytics-dev-db"
        and r.action_type is ActionType.DELETE_EBS
    ]


# ==========================================================================
# Execution and rollback
# ==========================================================================


def _approved_action(service, account, action_type=ActionType.STOP_EC2):
    result = service.scan_account(account)
    recommendation = next(
        r for r in result["recommendations"] if r.action_type is action_type
    )
    resource = service.repos.resources.get(recommendation.resource_id)
    action, _ = service.create_action(recommendation, resource, requested_by="tester")
    if action.approval_required:
        action.approval_status = ApprovalStatus.APPROVED
        action.approved_by = "approver@example.com"
        service.repos.actions.put(action)
    return action, recommendation


def test_execution_runs_every_state(service, account):
    action, _ = _approved_action(service, account)
    outcome = service.execute_action(action, account, settle_seconds=0)

    assert outcome.succeeded
    states = [s["state"] for s in outcome.states]
    for expected in (
        "ValidateAction", "ValidatePolicy", "CaptureBaseline", "CreateCheckpoint",
        "ExecuteAction", "Settle", "VerifyHealth", "RecordSavings", "Audit",
    ):
        assert expected in states, f"State {expected} did not run"


def test_execution_records_a_usable_checkpoint(service, account):
    action, _ = _approved_action(service, account)
    outcome = service.execute_action(action, account, settle_seconds=0)
    checkpoint = outcome.action.checkpoint

    assert checkpoint is not None
    assert checkpoint.rollback_method == "start_instance"
    assert checkpoint.rollback_data["instance_id"] == action.resource_id
    assert checkpoint.rollback_data["original_state"] == "running"


def test_completed_action_can_be_rolled_back(service, account):
    action, _ = _approved_action(service, account)
    outcome = service.execute_action(action, account, settle_seconds=0)
    assert outcome.action.can_rollback

    rollback = service.rollback_action(outcome.action, account)
    assert rollback.action.execution_status is ExecutionStatus.ROLLED_BACK
    events = [e.event for e in service.repos.audit.list()]
    assert "action.rolled_back" in events


def test_verification_failure_triggers_rollback(service, account, monkeypatch):
    """A failed health check must undo the change, not report success."""
    from cloudwaste.actions.executors.compute import StopEc2Executor
    from cloudwaste.models.domain import VerificationResult

    def failing_verify(self, context):
        return [
            VerificationResult(
                check="instance_state", passed=False, detail="Injected failure"
            )
        ]

    monkeypatch.setattr(StopEc2Executor, "verify", failing_verify)

    action, _ = _approved_action(service, account)
    outcome = service.execute_action(action, account, settle_seconds=0)

    assert not outcome.succeeded
    assert outcome.action.execution_status is ExecutionStatus.ROLLED_BACK
    assert "Rollback" in [s["state"] for s in outcome.states]


def test_rollback_failure_is_escalated_not_swallowed(service, account, monkeypatch):
    """Failed change plus failed undo is its own state, and it pages someone."""
    from cloudwaste.actions.executors.base import ExecutionOutcome
    from cloudwaste.actions.executors.compute import StopEc2Executor
    from cloudwaste.models.domain import VerificationResult

    monkeypatch.setattr(
        StopEc2Executor,
        "verify",
        lambda self, ctx: [
            VerificationResult(check="x", passed=False, detail="Injected failure")
        ],
    )
    monkeypatch.setattr(
        StopEc2Executor,
        "rollback",
        lambda self, ctx, cp: ExecutionOutcome(False, "Injected rollback failure"),
    )

    action, _ = _approved_action(service, account)
    outcome = service.execute_action(action, account, settle_seconds=0)

    assert outcome.action.execution_status is ExecutionStatus.ROLLBACK_FAILED
    assert "Manual intervention required" in outcome.action.error
    events = [e.event for e in service.repos.audit.list()]
    assert "action.rollback_failed" in events


# ==========================================================================
# HTTP API
# ==========================================================================


@pytest.fixture
def client():
    from cloudwaste.main import app
    from cloudwaste.services import get_service

    get_service.cache_clear()
    service = get_service()
    service.repos.clear()
    from cloudwaste.models.domain import Account
    from cloudwaste.seed.demo_provider import DEMO_ACCOUNT_ID, DEMO_REGION

    service.repos.accounts.put(
        Account(
            account_id=DEMO_ACCOUNT_ID, name="Demo",
            regions=[DEMO_REGION], mode="demo",
        )
    )
    with TestClient(app) as test_client:
        yield test_client
    get_service.cache_clear()


def test_api_health_and_root(client):
    assert client.get("/health").json()["status"] == "ok"
    root = client.get("/").json()
    assert root["safety"]["dry_run_default"] is True
    assert root["safety"]["autopilot_enabled"] is False


def test_api_scan_then_dashboard(client):
    scan = client.post("/api/v1/findings/scan").json()
    assert scan["findings_created"] > 0

    dashboard = client.get("/api/v1/dashboard").json()
    assert dashboard["potential_monthly_savings"] == pytest.approx(
        scan["total_potential_monthly_savings"], rel=0.001
    )


def test_api_finding_detail_carries_evidence(client):
    client.post("/api/v1/findings/scan")
    findings = client.get("/api/v1/findings?limit=1").json()
    finding_id = findings["findings"][0]["finding_id"]

    detail = client.get(f"/api/v1/findings/{finding_id}").json()
    assert detail["finding"]["evidence"]
    assert detail["score_contributions"]
    assert detail["resource"] is not None


def test_api_execute_requires_approval(client):
    client.post("/api/v1/findings/scan")
    recommendations = client.get("/api/v1/recommendations?risk=low").json()
    recommendation_id = recommendations["recommendations"][0]["recommendation_id"]

    created = client.post(
        "/api/v1/actions",
        json={"recommendation_id": recommendation_id},
        headers={"X-User": "requester@example.com"},
    ).json()
    action_id = created["action"]["action_id"]

    refused = client.post(f"/api/v1/actions/{action_id}/execute")
    assert refused.status_code == 409
    assert "approval" in refused.json()["detail"].lower()

    client.post(
        f"/api/v1/actions/{action_id}/approve",
        json={"note": "reviewed"},
        headers={"X-User": "approver@example.com"},
    )
    executed = client.post(f"/api/v1/actions/{action_id}/execute?settle_seconds=0")
    assert executed.status_code == 200
    assert executed.json()["succeeded"]


def test_api_rejected_action_cannot_execute(client):
    client.post("/api/v1/findings/scan")
    recommendations = client.get("/api/v1/recommendations?risk=low").json()
    recommendation_id = recommendations["recommendations"][0]["recommendation_id"]
    created = client.post(
        "/api/v1/actions", json={"recommendation_id": recommendation_id}
    ).json()
    action_id = created["action"]["action_id"]

    client.post(
        f"/api/v1/actions/{action_id}/reject",
        json={"reason": "not now"},
        headers={"X-User": "approver@example.com"},
    )
    refused = client.post(f"/api/v1/actions/{action_id}/execute")
    assert refused.status_code == 409


def test_api_policy_explain(client):
    client.post("/api/v1/findings/scan")
    recommendations = client.get("/api/v1/recommendations?limit=1").json()
    recommendation_id = recommendations["recommendations"][0]["recommendation_id"]

    explanation = client.get(f"/api/v1/policies/explain/{recommendation_id}").json()
    assert explanation["rules_considered"]
    assert "deployment_ceilings" in explanation


def test_api_agent_tools_are_all_read_only(client):
    tools = client.get("/api/v1/agent/tools").json()
    assert tools["count"] > 0
    assert all(not t["mutates_aws"] for t in tools["tools"])


def test_api_audit_trail_is_queryable(client):
    client.post("/api/v1/findings/scan")
    audit = client.get("/api/v1/audit").json()
    assert audit["count"] > 0
    assert any(e["event"] == "scan.completed" for e in audit["entries"])
