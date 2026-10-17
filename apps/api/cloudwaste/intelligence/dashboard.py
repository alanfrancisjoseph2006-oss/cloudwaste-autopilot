"""Dashboard aggregation.

A pure function of stored entities plus the few cost signals the service
fetched, so the arithmetic behind every headline number can be tested without
a data plane.

Every figure carries a basis, because the four kinds of dollar this product
shows are not interchangeable:

  OBSERVED  -- billed, from Cost Explorer
  ESTIMATED -- computed by CloudWaste from list prices or simulation
  FORECAST  -- a projection of future spend
  VERIFIED  -- an estimated saving later confirmed by observed billing

A missing input produces `None` and a status, never a zero.
"""

from __future__ import annotations

from typing import Any

from ..models.domain import Account, Action, Finding, Resource, Scan
from ..models.enums import ExecutionStatus, RiskLevel, SavingsStatus
from .waste_score import account_waste_score

OBSERVED, ESTIMATED, FORECAST, VERIFIED = "OBSERVED", "ESTIMATED", "FORECAST", "VERIFIED"

SERVICE_LABELS = {
    "EC2": "EC2",
    "EBS": "EBS",
    "RDS": "RDS",
    "LAMBDA": "Lambda",
    "S3": "S3",
    "NAT_GATEWAY": "NAT Gateway",
    "ELASTIC_IP": "Elastic IP",
    "ELB": "Load Balancing",
}

PENDING_SAVINGS = frozenset(
    {
        SavingsStatus.EXECUTED_PENDING_BILLING,
        SavingsStatus.VERIFICATION_PENDING,
        SavingsStatus.VERIFICATION_FAILED,
    }
)
PROVEN_SAVINGS = frozenset({SavingsStatus.VERIFIED, SavingsStatus.PARTIALLY_VERIFIED})

_SCORE_BUCKETS = ((0, 20), (20, 40), (40, 60), (60, 80), (80, 101))


def _r(value: float) -> float:
    return round(value, 2)


def build_dashboard(
    account: Account,
    *,
    findings: list[Finding],
    resources: list[Resource],
    actions: list[Action],
    scans: list[Scan],
    settings: Any,
    aws_forecast_30d: float | None = None,
    forecast_error: str | None = None,
    cost_by_service: dict[str, float] | None = None,
    cost_error: str | None = None,
) -> dict:
    open_findings = [f for f in findings if f.status.value == "OPEN"]

    priced = [r for r in resources if r.cost_known]
    unpriced = [r for r in resources if not r.cost_known]
    tracked_cost = _r(sum(r.monthly_cost for r in priced))
    potential = _r(sum(f.potential_monthly_savings for f in open_findings))

    flagged_ids = {f.resource_id for f in open_findings}
    flagged_cost = _r(sum(r.monthly_cost for r in priced if r.resource_id in flagged_ids))

    observed_spend = _r(sum(cost_by_service.values())) if cost_by_service is not None else None

    # --- savings lifecycle --------------------------------------------------
    verified = _r(
        sum(
            a.verified_monthly_savings or 0.0
            for a in actions
            if a.savings_status in PROVEN_SAVINGS
        )
    )
    pending_estimated = _r(
        sum(
            a.estimated_monthly_savings or 0.0
            for a in actions
            if a.savings_status in PENDING_SAVINGS
        )
    )
    savings_states: dict[str, int] = {}
    for action in actions:
        savings_states[action.savings_status.value] = (
            savings_states.get(action.savings_status.value, 0) + 1
        )

    # --- findings ------------------------------------------------------------
    by_type: dict[str, dict] = {}
    by_risk: dict[str, int] = {}
    by_service: dict[str, dict] = {}
    distribution = {f"{lo}-{min(hi, 100)}": 0 for lo, hi in _SCORE_BUCKETS}
    for finding in open_findings:
        bucket = by_type.setdefault(finding.waste_type.value, {"count": 0, "monthly_savings": 0.0})
        bucket["count"] += 1
        bucket["monthly_savings"] = _r(bucket["monthly_savings"] + finding.potential_monthly_savings)

        by_risk[finding.risk.value] = by_risk.get(finding.risk.value, 0) + 1

        label = SERVICE_LABELS.get(finding.resource_type.value, finding.resource_type.value)
        service = by_service.setdefault(
            label, {"count": 0, "monthly_savings": 0.0, "monthly_cost_flagged": 0.0}
        )
        service["count"] += 1
        service["monthly_savings"] = _r(service["monthly_savings"] + finding.potential_monthly_savings)
        service["monthly_cost_flagged"] = _r(service["monthly_cost_flagged"] + finding.monthly_cost)

        for lo, hi in _SCORE_BUCKETS:
            if lo <= finding.waste_score < hi:
                distribution[f"{lo}-{min(hi, 100)}"] += 1
                break

    high_risk = sum(1 for f in open_findings if f.risk.rank >= RiskLevel.HIGH.rank)

    # --- actions --------------------------------------------------------------
    def status(a: Action) -> ExecutionStatus:
        return a.execution_status

    executed = [a for a in actions if a.started_at is not None]
    successful = [
        a for a in actions if status(a) is ExecutionStatus.COMPLETED and not a.dry_run
    ]
    dry_runs = [a for a in actions if status(a) is ExecutionStatus.COMPLETED and a.dry_run]
    rollbacks = [a for a in actions if status(a) is ExecutionStatus.ROLLED_BACK]
    rollback_failures = [a for a in actions if status(a) is ExecutionStatus.ROLLBACK_FAILED]

    recent = sorted(actions, key=lambda a: a.created_at, reverse=True)[:8]

    # --- trend ----------------------------------------------------------------
    trend = [
        {
            "date": s.started_at.strftime("%Y-%m-%d %H:%M"),
            "scan_id": s.scan_id,
            "potential_monthly_savings": s.total_potential_savings,
            "tracked_monthly_cost": s.total_monthly_cost,
            "findings": s.findings_created,
        }
        for s in sorted(scans, key=lambda s: s.started_at)
        if s.status == "COMPLETED"
    ][-30:]

    if forecast_error:
        forecast_status = "ERROR"
    elif aws_forecast_30d is None:
        forecast_status = "UNAVAILABLE"
    else:
        forecast_status = "AVAILABLE"

    return {
        "account_id": account.account_id,
        "account_name": account.name,
        "account_mode": account.mode,
        # --- spend --------------------------------------------------------
        "monthly_spend": tracked_cost,
        "monthly_spend_basis": ESTIMATED,
        "monthly_spend_note": (
            "Sum of tracked resources priced from on-demand list prices. "
            + (
                f"{len(unpriced)} resource(s) could not be priced and are excluded, "
                "so this is a lower bound."
                if unpriced
                else "Every tracked resource was priced."
            )
        ),
        "unpriced_resources": len(unpriced),
        "observed_monthly_spend": observed_spend,
        "observed_monthly_spend_basis": OBSERVED,
        "observed_monthly_spend_status": (
            "ERROR" if cost_error else ("AVAILABLE" if observed_spend is not None else "UNAVAILABLE")
        ),
        "cost_by_service": cost_by_service,
        "cost_by_service_basis": OBSERVED,
        # --- forecast -----------------------------------------------------
        "forecast_next_30_days": aws_forecast_30d,
        "forecast_status": forecast_status,
        "forecast_basis": FORECAST,
        "forecast_source": "aws_cost_explorer",
        # --- savings ------------------------------------------------------
        "potential_monthly_savings": potential,
        "potential_annual_savings": _r(potential * 12),
        "potential_savings_basis": ESTIMATED,
        "verified_monthly_savings": verified,
        "verified_savings_basis": VERIFIED,
        "pending_verification_monthly_savings": pending_estimated,
        "pending_verification_basis": ESTIMATED,
        # Compatibility: only ever billing-verified, never an estimate.
        "realized_monthly_savings": verified,
        "savings_status_counts": savings_states,
        # --- findings -----------------------------------------------------
        "waste_score": account_waste_score(flagged_cost, tracked_cost),
        "waste_score_distribution": distribution,
        "active_findings": len(open_findings),
        "high_risk_findings": high_risk,
        "resources_tracked": len(resources),
        "findings_by_type": by_type,
        "findings_by_risk": by_risk,
        "waste_by_service": dict(
            sorted(by_service.items(), key=lambda kv: kv[1]["monthly_savings"], reverse=True)
        ),
        # --- actions ------------------------------------------------------
        "pending_approvals": sum(1 for a in actions if a.approval_status.value == "PENDING"),
        "executed_actions": len(executed),
        "successful_remediations": len(successful),
        "dry_run_completions": len(dry_runs),
        "rollbacks": len(rollbacks),
        "rollback_failures": len(rollback_failures),
        "recent_actions": [
            {
                "action_id": a.action_id,
                "action_type": a.action_type.value,
                "resource_id": a.resource_id,
                "finding_id": a.finding_id,
                "risk": a.risk.value,
                "approval_status": a.approval_status.value,
                "execution_status": a.execution_status.value,
                "savings_status": a.savings_status.value,
                "dry_run": a.dry_run,
                "estimated_monthly_savings": a.estimated_monthly_savings,
                "verified_monthly_savings": a.verified_monthly_savings,
                "created_at": a.created_at.isoformat(),
            }
            for a in recent
        ],
        "savings_trend": trend,
        "savings_trend_basis": ESTIMATED,
        "last_scan_at": trend[-1]["date"] if trend else None,
        # --- safety -------------------------------------------------------
        "autopilot_enabled": settings.autopilot_enabled,
        "dry_run": settings.dry_run_default,
    }
