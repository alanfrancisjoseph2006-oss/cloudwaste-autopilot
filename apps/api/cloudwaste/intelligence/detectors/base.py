"""Detector framework.

A detector answers one question about one resource: is this wasteful, and what
is the evidence? Detectors never decide risk, never propose an action and never
touch AWS -- they receive a prepared `DetectionContext` and return zero or more
`Finding` objects with evidence attached.

That separation is what makes the pipeline testable: every detector is a pure
function of its context, so the entire detection layer can be exercised without
a network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from ...config import Settings
from ...models.domain import Evidence, Finding, Resource, ScoreBreakdown
from ...models.enums import FindingStatus, ResourceType, WasteType
from ...adapters.base import ActivityEvent, MetricSeries, OptimizerRecommendation
from .. import confidence_engine, waste_score


@dataclass(slots=True)
class DetectionContext:
    """Everything a detector needs, gathered once by the orchestrator."""

    resource: Resource
    settings: Settings
    metrics: dict[str, MetricSeries] = field(default_factory=dict)
    optimizer: OptimizerRecommendation | None = None
    activity: list[ActivityEvent] = field(default_factory=list)
    days_since_last_write: float | None = None
    observed_monthly_cost: float | None = None
    scan_id: str | None = None
    window_days: int = 14
    # Other resources in the same account, by id. A volume needs to know
    # whether the instance it hangs off is stopped; an instance needs to know
    # what it drags along. Populated by the orchestrator.
    related_resources: dict[str, Resource] = field(default_factory=dict)

    # --- convenience -----------------------------------------------------

    @property
    def monthly_cost(self) -> float:
        """Observed billing beats list pricing whenever we have it."""
        if self.observed_monthly_cost is not None:
            return self.observed_monthly_cost
        return self.resource.monthly_cost

    @property
    def cost_is_estimated(self) -> bool:
        return self.observed_monthly_cost is None

    def series(self, key: str) -> MetricSeries | None:
        """A series that exists but has no datapoints counts as missing: an
        unpublished metric must never read as a measured zero."""
        found = self.metrics.get(key)
        if found is None or found.datapoint_count == 0:
            return None
        return found

    def has_metric(self, key: str) -> bool:
        return self.series(key) is not None

    def observation_days(self) -> float:
        spans = [s.span_days for s in self.metrics.values() if s.datapoint_count > 1]
        return max(spans) if spans else 0.0

    def total_datapoints(self) -> int:
        return sum(s.datapoint_count for s in self.metrics.values())

    def expected_datapoints(self) -> int:
        return len(self.metrics) * self.window_days * 24


class Detector(Protocol):
    """Implemented by every per-service detector."""

    name: str
    resource_type: ResourceType

    def detect(self, context: DetectionContext) -> list[Finding]: ...


# --------------------------------------------------------------------------
# Shared construction helpers
# --------------------------------------------------------------------------


def build_finding(
    context: DetectionContext,
    *,
    waste_type: WasteType,
    title: str,
    summary: str,
    evidence: list[Evidence],
    potential_monthly_savings: float,
    detector: str,
    score_inputs: waste_score.ScoreInputs,
    confidence_inputs: confidence_engine.ConfidenceInputs,
    action_context: dict | None = None,
) -> Finding:
    """Assemble a scored, confidence-rated finding.

    Risk is deliberately left at its default here. A finding's risk is the risk
    of the action proposed for it, which the recommendation engine decides, so
    filling it in at detection time would be guessing.
    """
    resource = context.resource
    breakdown: ScoreBreakdown = waste_score.compute(score_inputs)
    confidence = confidence_engine.compute(confidence_inputs)

    return Finding(
        account_id=resource.account_id,
        region=resource.region,
        resource_id=resource.resource_id,
        resource_type=resource.resource_type,
        waste_type=waste_type,
        waste_score=breakdown.total,
        score_breakdown=breakdown,
        confidence=confidence.score,
        confidence_reasons=confidence.reasons,
        monthly_cost=round(context.monthly_cost, 2),
        potential_monthly_savings=round(max(0.0, potential_monthly_savings), 2),
        status=FindingStatus.OPEN,
        title=title,
        summary=summary,
        evidence=evidence,
        detector=detector,
        cost_source="price_book" if context.cost_is_estimated else "cost_explorer",
        action_context=action_context or {},
        scan_id=context.scan_id,
    )


def standard_confidence_inputs(
    context: DetectionContext,
    *,
    corroborating_signals: int = 1,
    memory_metric_missing: bool | None = None,
    recent_activity_detected: bool = False,
    metric_variance_high: bool = False,
    seasonal_pattern_suspected: bool = False,
    metrics_not_applicable: bool = False,
) -> confidence_engine.ConfidenceInputs:
    """The evidence-quality facts that are the same for every detector."""
    resource = context.resource
    if memory_metric_missing is None:
        memory_metric_missing = (
            resource.resource_type is ResourceType.EC2 and not context.has_metric("memory")
        )
    return confidence_engine.ConfidenceInputs(
        observation_days=context.observation_days(),
        expected_observation_days=float(context.window_days),
        datapoint_count=context.total_datapoints(),
        expected_datapoint_count=context.expected_datapoints(),
        aws_recommendation_present=context.optimizer is not None,
        aws_performance_risk=context.optimizer.performance_risk if context.optimizer else None,
        corroborating_signals=corroborating_signals,
        memory_metric_missing=memory_metric_missing,
        cost_is_estimated=context.cost_is_estimated,
        cloudtrail_gap=context.days_since_last_write is None and not context.activity,
        resource_untagged=not resource.tags,
        recent_activity_detected=recent_activity_detected,
        metric_variance_high=metric_variance_high,
        seasonal_pattern_suspected=seasonal_pattern_suspected,
        metrics_not_applicable=metrics_not_applicable,
    )


def metric_evidence(
    series: MetricSeries,
    label: str,
    *,
    statistic: str = "average",
    unit: str | None = None,
    window_days: int | None = None,
    scale: float = 1.0,
    detail: str | None = None,
) -> Evidence:
    value = {
        "average": series.average,
        "maximum": series.maximum,
        "minimum": series.minimum,
        "total": series.total,
        "p95": series.percentile(95),
    }[statistic] * scale
    return Evidence(
        source="cloudwatch",
        metric=label,
        value=round(value, 3),
        unit=unit or series.unit,
        window_days=window_days or int(series.span_days) or None,
        detail=detail
        or (
            f"{label} {statistic} of {value:,.2f} {unit or series.unit} over "
            f"{series.span_days:.0f} days ({series.datapoint_count} datapoints)"
        ),
    )


def optimizer_evidence(rec: OptimizerRecommendation) -> Evidence:
    return Evidence(
        source=rec.source,
        metric="aws_recommendation",
        value=rec.estimated_monthly_savings,
        unit="USD/month",
        window_days=rec.lookback_days,
        detail=(
            f"AWS finding '{rec.finding}': change {rec.current_configuration} to "
            f"{rec.recommended_configuration} for an estimated "
            f"${rec.estimated_monthly_savings:,.2f}/month "
            f"({rec.estimated_savings_percent:.0f}%)"
        ),
    )


def cost_evidence(context: DetectionContext) -> Evidence:
    source = "cost_explorer" if not context.cost_is_estimated else "price_book"
    qualifier = (
        "observed unblended cost"
        if not context.cost_is_estimated
        else "estimated from on-demand list pricing"
    )
    return Evidence(
        source=source,
        metric="monthly_cost",
        value=round(context.monthly_cost, 2),
        unit="USD/month",
        detail=f"${context.monthly_cost:,.2f}/month ({qualifier})",
    )


def activity_evidence(context: DetectionContext) -> Evidence | None:
    """Turn CloudTrail history into a sentence a human can act on."""
    if context.days_since_last_write is not None:
        creator = next(
            (e.username for e in context.activity if not e.read_only), None
        )
        detail = (
            f"Last configuration change was "
            f"{context.days_since_last_write:.0f} days ago"
        )
        if creator:
            detail += f", by {creator.rsplit('/', 1)[-1]}"
        return Evidence(
            source="cloudtrail",
            metric="days_since_last_write",
            value=context.days_since_last_write,
            unit="days",
            detail=detail,
        )
    if context.resource.age_days > 90:
        return Evidence(
            source="cloudtrail",
            metric="days_since_last_write",
            value=None,
            detail=(
                "No configuration change recorded in the 90-day CloudTrail "
                "window, so the resource has been untouched for at least that long"
            ),
        )
    return None


def tag_evidence(resource: Resource) -> Evidence:
    if not resource.tags:
        return Evidence(
            source="tags",
            metric="tags",
            value="none",
            detail=(
                "Resource carries no tags, so its environment and owner are "
                "unknown and it is treated as production for risk purposes"
            ),
        )
    return Evidence(
        source="tags",
        metric="tags",
        value=f"{resource.environment.value}/{resource.criticality.value}",
        detail=(
            f"Tagged environment={resource.environment.value}, "
            f"criticality={resource.criticality.value}"
            + (f", owner={resource.owner}" if resource.owner else "")
        ),
    )


def default_window(settings: Settings) -> tuple[datetime, datetime]:
    end = datetime.now(timezone.utc)
    return end - timedelta(days=settings.metric_window_days), end
