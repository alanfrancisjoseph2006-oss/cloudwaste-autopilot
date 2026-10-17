"""Provider interfaces and the normalized shapes that cross them.

The detectors, the intelligence engines and the agent tools only ever see these
shapes. Two implementations satisfy them:

  * `adapters.aws.*`  -- real boto3 calls against a real account
  * `seed.demo_provider` -- a deterministic synthetic account

That split is what lets the whole pipeline (detect -> score -> risk -> policy ->
simulate -> execute -> verify) run end to end with no AWS credentials, and then
switch to a real account by changing one field on the Account record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from ..models.domain import Resource
from ..models.enums import ResourceType


# --------------------------------------------------------------------------
# Normalized shapes
# --------------------------------------------------------------------------


@dataclass(slots=True)
class MetricPoint:
    timestamp: datetime
    value: float


@dataclass(slots=True)
class MetricSeries:
    """A CloudWatch series reduced to the statistics the detectors need."""

    namespace: str
    metric_name: str
    dimensions: dict[str, str]
    unit: str
    statistic: str
    period_seconds: int
    points: list[MetricPoint] = field(default_factory=list)

    @property
    def datapoint_count(self) -> int:
        return len(self.points)

    @property
    def average(self) -> float:
        return sum(p.value for p in self.points) / len(self.points) if self.points else 0.0

    @property
    def maximum(self) -> float:
        return max((p.value for p in self.points), default=0.0)

    @property
    def minimum(self) -> float:
        return min((p.value for p in self.points), default=0.0)

    @property
    def total(self) -> float:
        return sum(p.value for p in self.points)

    def percentile(self, pct: float) -> float:
        """Nearest-rank percentile. p95 CPU is what decides a rightsizing call,
        so an average alone is never enough."""
        if not self.points:
            return 0.0
        ordered = sorted(p.value for p in self.points)
        idx = min(len(ordered) - 1, max(0, int(round(pct / 100.0 * len(ordered))) - 1))
        return ordered[idx]

    @property
    def span_days(self) -> float:
        if len(self.points) < 2:
            return 0.0
        lo = min(p.timestamp for p in self.points)
        hi = max(p.timestamp for p in self.points)
        return (hi - lo).total_seconds() / 86400.0


@dataclass(slots=True)
class CostPoint:
    start: datetime
    end: datetime
    amount: float
    unit: str = "USD"
    dimensions: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class CostAnomaly:
    anomaly_id: str
    service: str
    start: datetime
    end: datetime | None
    total_impact: float
    max_impact: float
    expected_spend: float
    actual_spend: float
    root_causes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def increase_percent(self) -> float:
        if self.expected_spend <= 0:
            return 0.0
        return round((self.actual_spend - self.expected_spend) / self.expected_spend * 100, 1)


@dataclass(slots=True)
class OptimizerRecommendation:
    """Normalized from Compute Optimizer or Cost Optimization Hub.

    Both AWS services answer the same question in different shapes; the
    detectors treat them as one signal and record which one spoke.
    """

    source: str  # "compute_optimizer" | "cost_optimization_hub"
    resource_id: str
    resource_arn: str | None
    resource_type: ResourceType
    finding: str  # e.g. OVER_PROVISIONED, NotOptimized, Idle
    current_configuration: str
    recommended_configuration: str
    estimated_monthly_savings: float
    estimated_savings_percent: float
    performance_risk: float | None = None
    lookback_days: int | None = None
    action_type: str | None = None  # Rightsize, Stop, Delete, MigrateToGraviton
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ActivityEvent:
    event_id: str
    event_name: str
    event_time: datetime
    username: str | None
    source_ip: str | None
    resource_id: str | None
    read_only: bool
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DependencyFacts:
    """What a provider could establish about a resource's relationships.

    `checked` lists the categories that were actually inspected, including
    those where nothing was found. A category absent from `checked` was not
    looked at (or could not be), and callers must treat it as unknown -- never
    as "no dependency".
    """

    relationships: list[dict[str, Any]] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)
    unknown: list[dict[str, str]] = field(default_factory=list)


# --------------------------------------------------------------------------
# Provider protocols
# --------------------------------------------------------------------------


@runtime_checkable
class InventoryProvider(Protocol):
    """Resource discovery across the services CloudWaste understands."""

    def list_resources(
        self, resource_types: list[ResourceType] | None = None
    ) -> list[Resource]: ...

    def get_resource(self, resource_id: str) -> Resource | None: ...

    def describe_dependencies(self, resource: Resource) -> DependencyFacts:
        """Read-only relationship lookup for one resource, on demand.

        Never called during a scan: it costs API calls per resource and is only
        needed when someone is looking at a specific change.
        """
        ...


@runtime_checkable
class MetricsProvider(Protocol):
    def get_metric(
        self,
        namespace: str,
        metric_name: str,
        dimensions: dict[str, str],
        start: datetime,
        end: datetime,
        statistic: str = "Average",
        period_seconds: int = 3600,
        unit: str | None = None,
    ) -> MetricSeries: ...


@runtime_checkable
class CostProvider(Protocol):
    def get_cost_and_usage(
        self,
        start: datetime,
        end: datetime,
        granularity: str = "DAILY",
        group_by: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[CostPoint]: ...

    def get_cost_by_resource(
        self, resource_id: str, start: datetime, end: datetime
    ) -> float | None:
        """None means "no resource-level billing", never "free"."""
        ...

    def get_forecast(self, days: int = 30) -> float | None:
        """None means "AWS has no forecast", never "$0"."""
        ...

    def get_anomalies(self, start: datetime, end: datetime) -> list[CostAnomaly]: ...


@runtime_checkable
class RecommendationProvider(Protocol):
    """Compute Optimizer + Cost Optimization Hub, normalized."""

    def list_recommendations(
        self, resource_types: list[ResourceType] | None = None
    ) -> list[OptimizerRecommendation]: ...

    def get_recommendation(self, resource_id: str) -> OptimizerRecommendation | None: ...


@runtime_checkable
class ActivityProvider(Protocol):
    def lookup_events(
        self,
        resource_id: str | None = None,
        event_names: list[str] | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 50,
    ) -> list[ActivityEvent]: ...


class DataPlane(Protocol):
    """The five providers an account exposes, bundled."""

    account_id: str
    region: str
    inventory: InventoryProvider
    metrics: MetricsProvider
    cost: CostProvider
    recommendations: RecommendationProvider
    activity: ActivityProvider
