"""Pydantic domain models: Resource, Finding, Recommendation, Action, Audit.

These are the persisted shapes. Every table in `repositories/` stores one of
these, and every API response is built from them.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field

from .enums import (
    ActionType,
    ApprovalStatus,
    Criticality,
    Environment,
    ExecutionStatus,
    FindingStatus,
    PolicyDecision,
    ResourceType,
    RiskLevel,
    SavingsStatus,
    WasteType,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class Base(BaseModel):
    model_config = ConfigDict(use_enum_values=False, populate_by_name=True)


def resource_key(account_id: str, region: str, resource_id: str) -> str:
    """Storage key for a resource.

    AWS ids are not globally unique: an RDS identifier or a Lambda function name
    is unique only within one account and region. Keying storage on the bare id
    would let a second account's `payments-db` silently overwrite the first's,
    and an action planned against one could then resolve to the other.
    """
    return f"{account_id}:{region}:{resource_id}"


#: Price sources that mean "we do not actually know what this costs".
UNKNOWN_COST_SOURCES = frozenset({"unpriced", "unavailable"})


# --------------------------------------------------------------------------
# Resource
# --------------------------------------------------------------------------


class Resource(Base):
    """A discovered AWS resource, normalized across services."""

    resource_id: str
    resource_arn: str | None = None
    resource_type: ResourceType
    account_id: str
    region: str
    name: str | None = None

    # Tag-derived context, populated by adapters.tags.classify().
    environment: Environment = Environment.UNKNOWN
    owner: str | None = None
    criticality: Criticality = Criticality.UNKNOWN
    auto_remediation_allowed: bool | None = None

    tags: dict[str, str] = Field(default_factory=dict)
    configuration: dict[str, Any] = Field(default_factory=dict)
    state: str | None = None
    created_at: datetime | None = None

    monthly_cost: float = 0.0
    discovered_at: datetime = Field(default_factory=_now)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def resource_key(self) -> str:
        return resource_key(self.account_id, self.region, self.resource_id)

    @property
    def cost_known(self) -> bool:
        """False when `monthly_cost` is a placeholder rather than a price.

        `monthly_cost` stays a float for compatibility, so an unpriced instance
        type or a bucket whose size CloudWatch has not published carries 0.0
        there. This is how callers tell that apart from a genuinely free
        resource, and they must exclude it from totals rather than add a zero.
        """
        return self.configuration.get("price_source") not in UNKNOWN_COST_SOURCES

    @property
    def age_days(self) -> float:
        if self.created_at is None:
            return 0.0
        return (_now() - self.created_at).total_seconds() / 86400.0

    @property
    def is_production(self) -> bool:
        return self.environment is Environment.PRODUCTION


# --------------------------------------------------------------------------
# Evidence -- every finding must cite the signals that produced it
# --------------------------------------------------------------------------


class Evidence(Base):
    """One observed signal supporting a finding.

    `source` is always a real system of record so the UI and the model can
    attribute every claim: cloudwatch, compute_optimizer, cost_optimization_hub,
    cost_explorer, cost_anomaly, cloudtrail, resource_config, tags.
    """

    source: str
    metric: str
    value: float | str | None = None
    unit: str | None = None
    window_days: int | None = None
    detail: str
    observed_at: datetime = Field(default_factory=_now)


class ScoreBreakdown(Base):
    """Per-component contributions to the waste score, kept for explainability."""

    utilization_waste: float = 0.0
    cost_impact: float = 0.0
    inactivity: float = 0.0
    age: float = 0.0
    recommendation_confidence: float = 0.0
    anomaly_signal: float = 0.0
    total: float = 0.0

    def as_contributions(self) -> dict[str, float]:
        from ..intelligence.waste_score import WASTE_SCORE_WEIGHTS

        return {
            name: round(getattr(self, name) * weight, 2)
            for name, weight in WASTE_SCORE_WEIGHTS.items()
        }


# --------------------------------------------------------------------------
# Finding
# --------------------------------------------------------------------------


class Finding(Base):
    finding_id: str = Field(default_factory=lambda: _uid("F"))
    account_id: str
    region: str
    resource_id: str
    resource_type: ResourceType
    waste_type: WasteType

    waste_score: float = 0.0
    score_breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    confidence: float = 0.0
    confidence_reasons: list[str] = Field(default_factory=list)

    monthly_cost: float = 0.0
    potential_monthly_savings: float = 0.0

    risk: RiskLevel = RiskLevel.MEDIUM
    status: FindingStatus = FindingStatus.OPEN

    title: str = ""
    summary: str = ""
    evidence: list[Evidence] = Field(default_factory=list)

    detector: str = ""
    # Where `monthly_cost` came from: "cost_explorer" (observed billing) or
    # "price_book" (list-price estimate). Simulation must price from the same
    # source, or the saving is part saving and part accounting artifact.
    cost_source: str = "price_book"
    # Values the detector already computed that the recommendation engine needs
    # to size the action -- a Lambda duration projection, an S3 target class.
    # Carried on the finding so the two stages never have to agree twice.
    action_context: dict[str, Any] = Field(default_factory=dict)
    scan_id: str | None = None
    first_seen_at: datetime = Field(default_factory=_now)
    last_seen_at: datetime = Field(default_factory=_now)

    @property
    def annual_savings(self) -> float:
        return round(self.potential_monthly_savings * 12, 2)


# --------------------------------------------------------------------------
# Recommendation and simulation
# --------------------------------------------------------------------------


class SimulationResult(Base):
    current_monthly_cost: float
    projected_monthly_cost: float
    monthly_savings: float
    annual_savings: float
    savings_percent: float
    restart_required: bool
    downtime_estimate_seconds: int
    rollback_possible: bool
    rollback_method: str | None = None
    risk: RiskLevel
    performance_impact: str
    assumptions: list[str] = Field(default_factory=list)
    priced_from: str = "static_price_book"


class Recommendation(Base):
    recommendation_id: str = Field(default_factory=lambda: _uid("REC"))
    finding_id: str
    resource_id: str
    resource_type: ResourceType
    account_id: str
    region: str

    action_type: ActionType
    current_configuration: str
    recommended_configuration: str
    action_parameters: dict[str, Any] = Field(default_factory=dict)

    monthly_savings: float = 0.0
    annual_savings: float = 0.0
    confidence: float = 0.0
    risk: RiskLevel = RiskLevel.MEDIUM

    restart_required: bool = False
    rollback_possible: bool = True

    rationale: str = ""
    source: str = "cloudwaste"
    simulation: SimulationResult | None = None
    created_at: datetime = Field(default_factory=_now)


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------


class PolicyRule(Base):
    name: str
    description: str = ""
    enabled: bool = True
    priority: int = 100  # lower number wins

    # Match criteria. Every criterion that is set must match.
    resource_type: ResourceType | None = None
    environment: Environment | None = None
    action: ActionType | None = None
    criticality: Criticality | None = None
    tag_equals: dict[str, str] = Field(default_factory=dict)
    max_risk: RiskLevel | None = None
    min_confidence: float | None = None
    max_monthly_savings: float | None = None
    min_monthly_savings: float | None = None

    # Outcome
    effect: Literal["allow", "deny"] = "allow"
    auto_execute: bool = False
    require_approval: bool = True
    approval_ttl_hours: int = 72


class PolicyEvaluation(Base):
    decision: PolicyDecision
    matched_rule: str | None = None
    reasons: list[str] = Field(default_factory=list)
    auto_execute: bool = False
    approval_ttl_hours: int = 72


# --------------------------------------------------------------------------
# Action, approval, audit
# --------------------------------------------------------------------------


class Checkpoint(Base):
    """State captured immediately before mutation, used to roll back."""

    captured_at: datetime = Field(default_factory=_now)
    resource_state: dict[str, Any] = Field(default_factory=dict)
    rollback_method: str
    rollback_data: dict[str, Any] = Field(default_factory=dict)
    rollback_timeout_seconds: int = 900
    artifacts: dict[str, str] = Field(default_factory=dict)


class VerificationResult(Base):
    check: str
    passed: bool
    detail: str
    observed_at: datetime = Field(default_factory=_now)


class Action(Base):
    action_id: str = Field(default_factory=lambda: _uid("ACT"))
    recommendation_id: str
    finding_id: str
    resource_id: str
    resource_type: ResourceType
    account_id: str
    region: str

    action_type: ActionType
    parameters: dict[str, Any] = Field(default_factory=dict)

    risk: RiskLevel
    policy_decision: PolicyDecision = PolicyDecision.REQUIRE_APPROVAL
    policy_rule: str | None = None
    approval_required: bool = True
    approval_status: ApprovalStatus = ApprovalStatus.PENDING
    approval_expires_at: datetime | None = None
    approved_by: str | None = None
    approved_at: datetime | None = None
    rejection_reason: str | None = None

    execution_status: ExecutionStatus = ExecutionStatus.NOT_STARTED
    execution_arn: str | None = None
    dry_run: bool = True
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None

    checkpoint: Checkpoint | None = None
    verifications: list[VerificationResult] = Field(default_factory=list)

    # --- savings lifecycle ------------------------------------------------
    # Estimated at planning time, verified against billing afterwards. The two
    # are kept apart because AWS billing lags and resource-level cost data is
    # often unavailable: a saving is only "verified" once Cost Explorer shows it.
    savings_status: SavingsStatus = SavingsStatus.ESTIMATED
    estimated_monthly_savings: float | None = None
    baseline_monthly_cost: float | None = None
    baseline_cost_source: str | None = None
    projected_monthly_cost: float | None = None
    observed_monthly_cost_after: float | None = None
    verified_monthly_savings: float | None = None
    savings_variance: float | None = None
    savings_checked_at: datetime | None = None
    savings_verified_at: datetime | None = None
    savings_detail: str | None = None
    # Kept for API compatibility. Only ever set from verified billing, never
    # from a simulation; None means "not proven", not "zero".
    realized_monthly_savings: float | None = None

    requested_by: str = "system"
    agent_id: str | None = None
    reason: str = ""
    created_at: datetime = Field(default_factory=_now)

    @property
    def can_rollback(self) -> bool:
        return (
            self.checkpoint is not None
            and self.execution_status is ExecutionStatus.COMPLETED
        )


class AuditLog(Base):
    audit_id: str = Field(default_factory=lambda: _uid("AUD"))
    timestamp: datetime = Field(default_factory=_now)
    action_id: str | None = None
    resource_id: str | None = None
    account_id: str | None = None
    actor: str = "system"
    agent_id: str | None = None
    event: str
    outcome: str = "SUCCESS"
    risk: RiskLevel | None = None
    approved: bool | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class Scan(Base):
    scan_id: str = Field(default_factory=lambda: _uid("SCAN"))
    account_id: str
    regions: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=_now)
    completed_at: datetime | None = None
    status: Literal["RUNNING", "COMPLETED", "FAILED"] = "RUNNING"
    resources_scanned: int = 0
    findings_created: int = 0
    total_monthly_cost: float = 0.0
    total_potential_savings: float = 0.0
    errors: list[str] = Field(default_factory=list)


class Account(Base):
    account_id: str
    name: str
    # Free-form labels for the multi-account view. Not used for risk: risk
    # comes from each resource's own tags, never from an account-wide label.
    environment: str | None = None
    owner: str | None = None
    role_arn: str | None = None
    external_id: str | None = None
    regions: list[str] = Field(default_factory=lambda: ["us-east-1"])
    mode: Literal["live", "demo"] = "demo"
    enabled: bool = True
    created_at: datetime = Field(default_factory=_now)


# --------------------------------------------------------------------------
# Optimization goals and plans
# --------------------------------------------------------------------------


class PlanItem(Base):
    """One selected opportunity. A chain (snapshot, then delete) is one item."""

    recommendation_ids: list[str]
    finding_id: str
    resource_id: str
    resource_type: ResourceType
    region: str
    action_types: list[ActionType]
    title: str
    service: str
    monthly_savings: float
    risk: RiskLevel
    confidence: float
    rollback_possible: bool
    downtime_seconds: int = 0
    policy_decision: PolicyDecision
    policy_reasons: list[str] = Field(default_factory=list)
    rank_score: float
    reason: str
    # Filled in when the plan is proposed; each is an ordinary PENDING action.
    action_ids: list[str] = Field(default_factory=list)


class PlanExclusion(Base):
    recommendation_ids: list[str]
    resource_id: str
    monthly_savings: float
    reason: str


class OptimizationPlan(Base):
    """A savings goal and the set of recommendations chosen to approach it.

    A plan is a document, not an authorization. Proposing it creates ordinary
    actions through the same policy and approval path as any other request;
    nothing in a plan ever executes on its own.
    """

    plan_id: str = Field(default_factory=lambda: _uid("PLAN"))
    account_id: str
    goal_type: Literal["amount", "percent"]
    goal_value: float
    target_monthly_savings: float
    baseline_monthly_spend: float | None = None
    baseline_basis: str | None = None
    max_risk: RiskLevel = RiskLevel.HIGH
    min_confidence: float = 0.0
    items: list[PlanItem] = Field(default_factory=list)
    excluded: list[PlanExclusion] = Field(default_factory=list)
    total_monthly_savings: float = 0.0
    target_met: bool = False
    shortfall: float = 0.0
    risk_summary: dict[str, int] = Field(default_factory=dict)
    savings_by_service: dict[str, float] = Field(default_factory=dict)
    ranking_method: str = ""
    notes: list[str] = Field(default_factory=list)
    status: Literal["DRAFT", "PROPOSED"] = "DRAFT"
    created_by: str = "system"
    created_at: datetime = Field(default_factory=_now)
    proposed_at: datetime | None = None
