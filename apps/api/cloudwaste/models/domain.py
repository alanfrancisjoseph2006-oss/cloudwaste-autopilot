"""Pydantic domain models: Resource, Finding, Recommendation, Action, Audit.

These are the persisted shapes. Every table in `repositories/` stores one of
these, and every API response is built from them.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

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
    WasteType,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class Base(BaseModel):
    model_config = ConfigDict(use_enum_values=False, populate_by_name=True)


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
    role_arn: str | None = None
    external_id: str | None = None
    regions: list[str] = Field(default_factory=lambda: ["us-east-1"])
    mode: Literal["live", "demo"] = "demo"
    enabled: bool = True
    created_at: datetime = Field(default_factory=_now)
