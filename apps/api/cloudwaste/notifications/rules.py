"""What deserves a notification. Pure functions over domain objects.

Every threshold comes from settings (`notify_*`, `monthly_budget`), and every
event type can be switched off through `notify_events`, so alerting behaviour
is configuration, not code.

Scan-time alerts fire only for findings seen for the first time. A daily scan
that re-announces the same idle instance every morning teaches people to
filter the channel, and then the rollback-failure page gets filtered too.
"""

from __future__ import annotations

from ..models.domain import Action, Finding, Recommendation
from ..models.enums import ExecutionStatus, RiskLevel, WasteType
from .publisher import Notification, NotificationEvent


def _money(value: float | None) -> str:
    return "unknown" if value is None else f"${value:,.2f}"


def scan_notifications(
    account_id: str,
    *,
    new_findings: list[Finding],
    recommendations: list[Recommendation],
    monthly_spend: float | None,
    settings,
) -> list[Notification]:
    out: list[Notification] = []
    min_risk = RiskLevel(settings.notify_min_finding_risk)
    recs_by_finding: dict[str, list[Recommendation]] = {}
    for rec in recommendations:
        recs_by_finding.setdefault(rec.finding_id, []).append(rec)

    for finding in new_findings:
        if finding.waste_type is WasteType.COST_ANOMALY:
            excess = next(
                (
                    e.value
                    for e in finding.evidence
                    if e.metric == "spend_deviation" and isinstance(e.value, (int, float))
                ),
                None,
            )
            if excess is not None and excess >= settings.notify_anomaly_min_impact:
                out.append(
                    Notification(
                        NotificationEvent.COST_ANOMALY,
                        "warning",
                        f"CloudWaste: cost anomaly in {account_id}",
                        f"{finding.title}. Excess spend {_money(excess)} over the "
                        f"anomaly window (AWS Cost Anomaly Detection). An anomaly is a "
                        f"deviation from forecast, not proof of waste.",
                        account_id,
                        data={"finding_id": finding.finding_id, "excess": excess},
                    )
                )
            continue

        if finding.risk.rank >= min_risk.rank:
            out.append(
                Notification(
                    NotificationEvent.HIGH_RISK_FINDING,
                    "warning",
                    f"CloudWaste: {finding.risk.value.upper()}-risk finding on {finding.resource_id}",
                    f"{finding.title}. Estimated saving "
                    f"{_money(finding.potential_monthly_savings)}/month, confidence "
                    f"{finding.confidence:.0f}%. Any change requires human approval.",
                    account_id,
                    data={
                        "finding_id": finding.finding_id,
                        "resource_id": finding.resource_id,
                        "risk": finding.risk.value,
                    },
                )
            )

        recs = recs_by_finding.get(finding.finding_id, [])
        if (
            finding.confidence >= settings.notify_high_confidence_threshold
            and recs
            and all(r.risk.rank <= RiskLevel.MEDIUM.rank for r in recs)
            and finding.potential_monthly_savings >= settings.min_monthly_savings_to_report
        ):
            out.append(
                Notification(
                    NotificationEvent.HIGH_CONFIDENCE_OPPORTUNITY,
                    "info",
                    f"CloudWaste: new opportunity on {finding.resource_id}",
                    f"{finding.title}. Estimated {_money(finding.potential_monthly_savings)}"
                    f"/month at {finding.confidence:.0f}% confidence, "
                    f"{max(recs, key=lambda r: r.risk.rank).risk.value} risk. Nothing has "
                    f"been changed; propose it from the console to start approval.",
                    account_id,
                    data={"finding_id": finding.finding_id, "resource_id": finding.resource_id},
                )
            )

    if settings.monthly_budget and monthly_spend is not None:
        threshold = settings.monthly_budget * settings.budget_alert_threshold_percent / 100.0
        if monthly_spend >= threshold:
            out.append(
                Notification(
                    NotificationEvent.BUDGET_THRESHOLD,
                    "warning",
                    f"CloudWaste: {account_id} is at "
                    f"{monthly_spend / settings.monthly_budget * 100:.0f}% of budget",
                    f"Tracked monthly spend {_money(monthly_spend)} against a budget of "
                    f"{_money(settings.monthly_budget)} (alert at "
                    f"{settings.budget_alert_threshold_percent:.0f}%). Spend is estimated "
                    f"from list prices of tracked resources.",
                    account_id,
                    data={"monthly_spend": monthly_spend, "budget": settings.monthly_budget},
                )
            )
    return out


def approval_notification(action: Action, recommendation: Recommendation | None) -> Notification:
    saving = action.estimated_monthly_savings
    return Notification(
        NotificationEvent.APPROVAL_REQUESTED,
        "info",
        f"CloudWaste: approval requested for {action.action_type.value} on {action.resource_id}",
        f"{action.requested_by} proposed {action.action_type.value} on "
        f"{action.resource_id} ({action.risk.value} risk, estimated "
        f"{_money(saving)}/month). Approval expires at "
        f"{action.approval_expires_at.isoformat() if action.approval_expires_at else 'n/a'}.",
        action.account_id,
        data={
            "action_id": action.action_id,
            "resource_id": action.resource_id,
            "risk": action.risk.value,
            "recommended": recommendation.recommended_configuration if recommendation else None,
        },
    )


def execution_notification(action: Action) -> Notification | None:
    status = action.execution_status
    if status is ExecutionStatus.ROLLBACK_FAILED:
        return Notification(
            NotificationEvent.ROLLBACK_FAILURE,
            "critical",
            f"CloudWaste ESCALATION: {action.action_type.value} on {action.resource_id} "
            f"failed AND rollback failed",
            f"{action.error} The resource may be in an intermediate state. The "
            f"checkpoint captured before execution is attached.",
            action.account_id,
            escalation=True,
            data={
                "action_id": action.action_id,
                "resource_id": action.resource_id,
                "checkpoint": action.checkpoint.model_dump(mode="json") if action.checkpoint else None,
            },
        )
    started = action.started_at is not None
    if status is ExecutionStatus.ROLLED_BACK or (status is ExecutionStatus.FAILED and started):
        return Notification(
            NotificationEvent.REMEDIATION_FAILURE,
            "warning",
            f"CloudWaste: {action.action_type.value} on {action.resource_id} "
            f"{'rolled back' if status is ExecutionStatus.ROLLED_BACK else 'failed'}",
            f"{action.error or 'No detail recorded.'}",
            action.account_id,
            data={"action_id": action.action_id, "status": status.value},
        )
    return None
