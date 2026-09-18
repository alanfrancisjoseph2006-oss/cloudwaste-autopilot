"""Detection correctness.

The hardest requirement for a waste detector is not finding waste, it is *not*
finding waste that is not there. A tool that flags a busy production database
gets switched off after one incident, so the negative cases below are as
important as the positive ones.
"""

from __future__ import annotations

import pytest

from cloudwaste.intelligence import confidence_engine, waste_score
from cloudwaste.intelligence.waste_detector import WasteDetector
from cloudwaste.models.enums import ResourceType, WasteType


@pytest.fixture
def findings(data_plane, settings):
    result = WasteDetector(data_plane, settings).scan()
    return {(f.resource_id, f.waste_type): f for f in result.findings}


def by_resource(findings, resource_id):
    return [f for (rid, _), f in findings.items() if rid == resource_id]


# ==========================================================================
# Negative cases: these must NOT be flagged
# ==========================================================================


def test_busy_production_instance_is_not_flagged(findings):
    """61% average CPU, 84% p95, heavy network. Correctly sized."""
    assert by_resource(findings, "i-0a1b2c3d4e5f60003") == []


def test_busy_production_volume_is_not_flagged(findings):
    """An io2 volume serving millions of IOPS is not waste."""
    assert by_resource(findings, "vol-0a1b2c3d4e5f60003") == []


def test_hot_s3_bucket_is_not_flagged(findings):
    """A bucket serving 41M GETs/month would cost more in a colder tier."""
    assert by_resource(findings, "acme-app-assets") == []


def test_low_traffic_lambda_is_not_flagged(findings):
    """30 invocations a month is too little for a memory change to be worth it."""
    assert by_resource(findings, "nightly-report-builder") == []


def test_associated_elastic_ip_is_not_flagged(findings):
    """An in-use address is free and not waste."""
    assert by_resource(findings, "eipalloc-0demo000000002") == []


# ==========================================================================
# Positive cases
# ==========================================================================


def test_underutilized_instance_is_detected(findings):
    finding = findings.get(
        ("i-0a1b2c3d4e5f60001", WasteType.UNDERUTILIZED_RESOURCE)
    )
    assert finding is not None
    assert finding.potential_monthly_savings > 200
    assert finding.confidence > 90
    sources = {e.source for e in finding.evidence}
    assert "cloudwatch" in sources
    assert any("compute_optimizer" in s or "cost_optimization_hub" in s for s in sources)


def test_idle_instance_is_detected_as_idle_not_underutilized(findings):
    """An instance at 0.9% CPU with no traffic is idle, and only idle.

    Reporting it as both idle and oversized would double-count the same
    dollars in the savings total.
    """
    resource_findings = by_resource(findings, "i-0a1b2c3d4e5f60002")
    assert len(resource_findings) == 1
    assert resource_findings[0].waste_type is WasteType.IDLE_RESOURCE


def test_unattached_volume_with_snapshot_is_detected(findings):
    finding = findings.get(("vol-0a1b2c3d4e5f60006", WasteType.UNATTACHED_STORAGE))
    assert finding is not None
    snapshot_evidence = [e for e in finding.evidence if e.metric == "latest_snapshot"]
    assert snapshot_evidence and snapshot_evidence[0].value == "snap-0demo0001"


def test_unattached_volume_without_snapshot_says_so(findings):
    finding = findings.get(("vol-0a1b2c3d4e5f60007", WasteType.UNATTACHED_STORAGE))
    assert finding is not None
    snapshot_evidence = [e for e in finding.evidence if e.metric == "latest_snapshot"]
    assert snapshot_evidence and snapshot_evidence[0].value is None
    assert "snapshot" in snapshot_evidence[0].detail.lower()


def test_volume_on_stopped_instance_is_detected(findings):
    """A stopped instance costs nothing but its volumes bill in full."""
    finding = findings.get(
        ("vol-0a1b2c3d4e5f60005", WasteType.SCHEDULED_RUNTIME_WASTE)
    )
    assert finding is not None
    assert finding.potential_monthly_savings > 100


def test_gp2_volume_is_recommended_for_gp3(findings):
    finding = findings.get(
        ("vol-0a1b2c3d4e5f60002", WasteType.CONFIGURATION_INEFFICIENCY)
    )
    assert finding is not None
    assert 1.5 < finding.potential_monthly_savings < 3.0


def test_s3_lifecycle_saving_is_net_of_monitoring_and_transition(findings):
    """The reported saving must survive Intelligent-Tiering monitoring fees."""
    finding = findings.get(
        ("acme-analytics-raw-events", WasteType.STORAGE_LIFECYCLE_WASTE)
    )
    assert finding is not None
    payback = [e for e in finding.evidence if e.metric == "payback_period"]
    assert payback, "S3 finding must state its payback period"
    assert payback[0].value <= 6.0


def test_nat_gateway_is_reported_but_no_action_proposed(findings, data_plane):
    """Low throughput is not sufficient evidence to delete a NAT gateway."""
    from cloudwaste.intelligence.recommendation_engine import RecommendationEngine

    finding = findings.get(
        ("nat-0demo00000000001", WasteType.UNUSED_NETWORK_RESOURCE)
    )
    assert finding is not None
    investigation = [e for e in finding.evidence if e.metric == "investigation_required"]
    assert investigation, "NAT finding must name the manual checks required"

    resource = data_plane.inventory.get_resource("nat-0demo00000000001")
    assert RecommendationEngine().build(finding, resource) == []


def test_cost_anomaly_is_detected_with_attribution(findings):
    anomalies = [f for (_, wt), f in findings.items() if wt is WasteType.COST_ANOMALY]
    assert len(anomalies) == 1
    anomaly = anomalies[0]
    assert anomaly.potential_monthly_savings == 0.0, (
        "An anomaly has no remediation, so it must not inflate the savings total"
    )
    root_causes = [e for e in anomaly.evidence if e.metric == "root_cause"]
    assert root_causes


# ==========================================================================
# Evidence quality
# ==========================================================================


def test_every_finding_carries_evidence(findings):
    for finding in findings.values():
        assert finding.evidence, f"{finding.finding_id} has no evidence"
        for item in finding.evidence:
            assert item.source, "evidence must name its source"
            assert item.detail, "evidence must be explainable in prose"


def test_missing_memory_metric_lowers_confidence(findings):
    """The untagged instance has no CloudWatch agent, so memory is unmeasured."""
    resource_findings = by_resource(findings, "i-0a1b2c3d4e5f60005")
    assert resource_findings
    finding = resource_findings[0]
    assert finding.confidence < 70
    assert any("memory" in reason.lower() for reason in finding.confidence_reasons)


def test_untagged_resource_lowers_confidence(findings):
    finding = by_resource(findings, "i-0a1b2c3d4e5f60005")[0]
    assert any("untagged" in reason.lower() for reason in finding.confidence_reasons)


def test_configuration_based_findings_are_not_penalized_for_absent_metrics(findings):
    """An unassociated Elastic IP publishes no metrics, and should not be
    marked low-confidence for metrics that cannot exist."""
    finding = findings.get(
        ("eipalloc-0demo000000001", WasteType.UNUSED_NETWORK_RESOURCE)
    )
    assert finding is not None
    assert finding.confidence >= 65


# ==========================================================================
# Scoring
# ==========================================================================


def test_waste_score_and_confidence_are_independent():
    """A resource can look very wasteful on thin evidence."""
    breakdown = waste_score.compute(
        waste_score.ScoreInputs(utilization_ratio=0.01, monthly_cost=800.0, idle_days=30)
    )
    confidence = confidence_engine.compute(
        confidence_engine.ConfidenceInputs(
            observation_days=2, expected_observation_days=14,
            datapoint_count=10, expected_datapoint_count=336,
            memory_metric_missing=True, resource_untagged=True,
        )
    )
    assert breakdown.total > 70
    assert confidence.score < 50


def test_absent_score_components_are_not_counted_as_zero():
    """A resource with no CloudTrail history must not be penalized for it."""
    with_age = waste_score.compute(
        waste_score.ScoreInputs(utilization_ratio=0.05, monthly_cost=100.0, age_days=90)
    )
    without_age = waste_score.compute(
        waste_score.ScoreInputs(utilization_ratio=0.05, monthly_cost=100.0)
    )
    # Both are dominated by utilization and cost; omitting age renormalizes
    # rather than scoring it zero.
    assert without_age.total > 0
    assert abs(with_age.total - without_age.total) < 25


def test_cost_impact_is_log_scaled():
    """$5 and $50 must be distinguishable, and $900 must not peg the scale."""
    small = waste_score.score_cost_impact(5.0)
    medium = waste_score.score_cost_impact(50.0)
    large = waste_score.score_cost_impact(900.0)
    assert 0 < small < medium < large < 100


def test_scan_is_deterministic(data_plane, settings):
    """Same account, same seed, same numbers."""
    first = WasteDetector(data_plane, settings).scan()
    second = WasteDetector(data_plane, settings).scan()
    assert len(first.findings) == len(second.findings)
    assert first.total_potential_savings == pytest.approx(
        second.total_potential_savings, rel=0.01
    )
