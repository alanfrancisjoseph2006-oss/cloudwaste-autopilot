"""Confidence scoring.

Waste score says "this looks wasteful". Confidence says "and we have enough
evidence to act on it". Keeping them apart is what lets the policy engine
auto-execute a 62-point finding with 97% confidence while holding a 91-point
finding at 40% confidence for a human.

Confidence starts at a base and is adjusted by evidence quality. The penalties
matter more than the bonuses: the failure mode that destroys trust in this
product is confidently deleting something that was in use, and every penalty
below corresponds to a real way that happens.
"""

from __future__ import annotations

from dataclasses import dataclass, field

BASE_CONFIDENCE = 55.0


@dataclass(slots=True)
class ConfidenceInputs:
    observation_days: float = 0.0
    expected_observation_days: float = 14.0
    datapoint_count: int = 0
    expected_datapoint_count: int = 0
    # Some findings rest on configuration facts, not telemetry: an Elastic IP
    # with no association, a volume in state 'available'. CloudWatch publishes
    # nothing for those, and penalizing them for absent metrics would be
    # punishing a finding for evidence that could not exist.
    metrics_not_applicable: bool = False

    # Corroboration
    aws_recommendation_present: bool = False
    aws_performance_risk: float | None = None  # Compute Optimizer, 0..4
    corroborating_signals: int = 0  # independent metrics agreeing

    # Known blind spots
    memory_metric_missing: bool = False
    cost_is_estimated: bool = False
    cloudtrail_gap: bool = False
    resource_untagged: bool = False

    # Contradictions
    recent_activity_detected: bool = False
    metric_variance_high: bool = False
    seasonal_pattern_suspected: bool = False


@dataclass(slots=True)
class ConfidenceResult:
    score: float
    reasons: list[str] = field(default_factory=list)


def compute(inputs: ConfidenceInputs) -> ConfidenceResult:
    score = BASE_CONFIDENCE
    reasons: list[str] = []

    # --- observation window -------------------------------------------
    if inputs.metrics_not_applicable:
        # The finding rests on resource state, which is read directly from the
        # AWS API and is exact. Telemetry adds nothing here.
        score += 15
        reasons.append(
            "Finding rests on resource configuration read directly from the AWS "
            "API rather than on sampled telemetry"
        )
    elif inputs.expected_observation_days > 0:
        coverage = min(1.0, inputs.observation_days / inputs.expected_observation_days)
        if coverage >= 0.95:
            score += 12
            reasons.append(
                f"Full {inputs.observation_days:.0f}-day observation window available"
            )
        elif coverage >= 0.5:
            score += 4
            reasons.append(
                f"Partial observation window ({inputs.observation_days:.0f} of "
                f"{inputs.expected_observation_days:.0f} days)"
            )
        else:
            score -= 18
            reasons.append(
                f"Short observation window ({inputs.observation_days:.0f} days) "
                "limits certainty"
            )

    # --- metric density ------------------------------------------------
    if inputs.metrics_not_applicable:
        pass
    elif inputs.expected_datapoint_count > 0:
        density = inputs.datapoint_count / inputs.expected_datapoint_count
        if density >= 0.9:
            score += 8
            reasons.append("Metric coverage is complete")
        elif density < 0.5:
            score -= 12
            reasons.append(
                f"Sparse metrics ({inputs.datapoint_count} of "
                f"{inputs.expected_datapoint_count} expected datapoints)"
            )
    elif inputs.datapoint_count == 0:
        score -= 25
        reasons.append("No CloudWatch datapoints returned for this resource")

    # --- corroboration -------------------------------------------------
    if inputs.aws_recommendation_present:
        score += 15
        reasons.append("AWS independently recommends a change for this resource")
        if inputs.aws_performance_risk is not None:
            if inputs.aws_performance_risk <= 1.0:
                score += 5
                reasons.append("AWS rates the performance risk of the change as very low")
            elif inputs.aws_performance_risk >= 3.0:
                score -= 10
                reasons.append("AWS rates the performance risk of the change as elevated")

    if inputs.corroborating_signals >= 3:
        score += 10
        reasons.append(f"{inputs.corroborating_signals} independent signals agree")
    elif inputs.corroborating_signals == 2:
        score += 5
        reasons.append("Two independent signals agree")

    # --- blind spots ---------------------------------------------------
    if inputs.memory_metric_missing:
        score -= 12
        reasons.append(
            "Memory utilization unavailable (no CloudWatch agent), so a "
            "memory-bound workload cannot be ruled out"
        )
    if inputs.cost_is_estimated:
        score -= 6
        reasons.append(
            "Cost is estimated from list pricing, not observed billing data"
        )
    if inputs.cloudtrail_gap:
        score -= 5
        reasons.append("No CloudTrail history within the 90-day lookup window")
    if inputs.resource_untagged:
        score -= 8
        reasons.append("Resource is untagged, so its owner and environment are unverified")

    # --- contradictions ------------------------------------------------
    if inputs.recent_activity_detected:
        score -= 20
        reasons.append("Recent activity contradicts the idle assessment")
    if inputs.metric_variance_high:
        score -= 10
        reasons.append("Utilization is highly variable, so averages are misleading")
    if inputs.seasonal_pattern_suspected:
        score -= 15
        reasons.append(
            "Usage pattern suggests periodic workload that the window may have missed"
        )

    return ConfidenceResult(score=round(max(5.0, min(99.0, score)), 1), reasons=reasons)


def is_actionable(confidence: float, threshold: float = 70.0) -> bool:
    """Below the threshold a finding is reported but never auto-executed.

    The policy engine enforces this independently; this helper exists so the
    detectors and the UI agree on the same word.
    """
    return confidence >= threshold
