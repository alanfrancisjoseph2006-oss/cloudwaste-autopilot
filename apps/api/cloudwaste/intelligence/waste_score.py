"""Waste scoring.

The score answers one question: how much of what this resource costs is being
wasted, weighted by how much that matters. It is deliberately *not* a
probability and *not* a risk rating -- those are `confidence_engine` and
`risk_engine`. Conflating the three is the classic FinOps-tool failure: a $4
idle IP and a $900 oversized production database both score "high" and the
operator stops trusting the list.

Every component is normalized to 0-100 and combined with fixed weights, and the
per-component contribution is kept on the finding so the UI can show the
arithmetic rather than asking anyone to trust a number.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from ..models.domain import ScoreBreakdown

# Weights sum to 1.0. Utilization and cost dominate because they are the two
# signals that are always measured; the rest are corroborating.
WASTE_SCORE_WEIGHTS: dict[str, float] = {
    "utilization_waste": 0.30,
    "cost_impact": 0.25,
    "inactivity": 0.15,
    "age": 0.10,
    "recommendation_confidence": 0.10,
    "anomaly_signal": 0.10,
}

# Monthly spend at which cost_impact saturates at 100. Chosen so that the
# midpoint of the log curve sits near a few hundred dollars, which is where a
# human starts caring.
COST_SATURATION_USD = 1000.0


@dataclass(slots=True)
class ScoreInputs:
    """Raw signals, each optional. Absent signals are excluded from the mix
    and the remaining weights are renormalized, so a resource with no CloudTrail
    history is not silently penalized for it."""

    utilization_ratio: float | None = None   # 0.0 unused .. 1.0 fully used
    monthly_cost: float | None = None
    idle_days: float | None = None
    age_days: float | None = None
    aws_recommendation_savings_percent: float | None = None
    anomaly_impact_ratio: float | None = None  # excess spend / expected spend


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def score_utilization(utilization_ratio: float) -> float:
    """Unused fraction, as a percentage. 8% CPU -> 92 points of waste."""
    return _clamp((1.0 - _clamp(utilization_ratio, 0.0, 1.0)) * 100.0)


def score_cost_impact(monthly_cost: float) -> float:
    """Log-scaled so the difference between $5 and $50 registers, while $900
    and $9000 do not both simply peg at 100.

    Linear scaling makes every small finding invisible; raw dollars make the
    score a duplicate of the savings column. Log is the compromise.
    """
    if monthly_cost <= 0:
        return 0.0
    return _clamp(math.log10(1.0 + monthly_cost) / math.log10(1.0 + COST_SATURATION_USD) * 100.0)


def score_inactivity(idle_days: float) -> float:
    """Saturates at 30 days. Beyond a month, longer adds no information."""
    return _clamp(idle_days / 30.0 * 100.0)


def score_age(age_days: float) -> float:
    """Age is weak evidence on its own -- a 400-day-old production database is
    not waste -- so it saturates early, at 90 days, and carries only 10%.
    """
    return _clamp(age_days / 90.0 * 100.0)


def score_recommendation(savings_percent: float) -> float:
    """AWS's own estimated savings percentage, taken at face value."""
    return _clamp(savings_percent)


def score_anomaly(impact_ratio: float) -> float:
    """A 100% overshoot scores 100; anything beyond that pegs."""
    return _clamp(impact_ratio * 100.0)


def compute(inputs: ScoreInputs) -> ScoreBreakdown:
    """Combine available components, renormalizing over the weights present."""
    components: dict[str, float] = {}

    if inputs.utilization_ratio is not None:
        components["utilization_waste"] = score_utilization(inputs.utilization_ratio)
    if inputs.monthly_cost is not None:
        components["cost_impact"] = score_cost_impact(inputs.monthly_cost)
    if inputs.idle_days is not None:
        components["inactivity"] = score_inactivity(inputs.idle_days)
    if inputs.age_days is not None:
        components["age"] = score_age(inputs.age_days)
    if inputs.aws_recommendation_savings_percent is not None:
        components["recommendation_confidence"] = score_recommendation(
            inputs.aws_recommendation_savings_percent
        )
    if inputs.anomaly_impact_ratio is not None:
        components["anomaly_signal"] = score_anomaly(inputs.anomaly_impact_ratio)

    available_weight = sum(WASTE_SCORE_WEIGHTS[name] for name in components)
    if available_weight <= 0:
        return ScoreBreakdown()

    total = sum(
        value * WASTE_SCORE_WEIGHTS[name] for name, value in components.items()
    ) / available_weight

    return ScoreBreakdown(
        utilization_waste=round(components.get("utilization_waste", 0.0), 2),
        cost_impact=round(components.get("cost_impact", 0.0), 2),
        inactivity=round(components.get("inactivity", 0.0), 2),
        age=round(components.get("age", 0.0), 2),
        recommendation_confidence=round(components.get("recommendation_confidence", 0.0), 2),
        anomaly_signal=round(components.get("anomaly_signal", 0.0), 2),
        total=round(_clamp(total), 1),
    )


def account_waste_score(findings_cost: float, total_cost: float) -> float:
    """Account-level score for the dashboard: the share of spend sitting under
    an open finding. Directly interpretable -- 68 means 68% of this account's
    spend is attached to something CloudWaste has flagged.
    """
    if total_cost <= 0:
        return 0.0
    return round(_clamp(findings_cost / total_cost * 100.0), 1)
