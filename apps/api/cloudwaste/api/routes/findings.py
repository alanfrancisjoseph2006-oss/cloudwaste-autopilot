"""Findings, recommendations, simulation and scan triggering."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ...models.domain import Account, AuditLog
from ...models.enums import FindingStatus
from ...services import CloudWasteService
from ..deps import current_user, ensure_owned, optional_account, resolve_account, service

router = APIRouter()


@router.post("/findings/scan", tags=["findings"])
def run_scan(
    region: str | None = None,
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    """Run a full scan. Synchronous: a demo account takes under a second and a
    real account a few minutes. A production deployment runs this on an
    EventBridge schedule rather than over HTTP."""
    if region and region not in account.regions:
        raise HTTPException(
            400, f"Region {region} is not configured for account {account.account_id}"
        )
    result = svc.scan_account(account, region)
    return {
        "account_id": account.account_id,
        "scan": result["scan"],
        "findings_created": len(result["findings"]),
        "recommendations_created": len(result["recommendations"]),
        "total_potential_monthly_savings": result["scan"].total_potential_savings,
        "savings_reconciled": len(result["reconciled_actions"]),
    }


@router.get("/findings", tags=["findings"])
def list_findings(
    status: str | None = Query(None, description="OPEN, SUPPRESSED, REMEDIATED, STALE, or ALL"),
    resource_type: str | None = None,
    waste_type: str | None = None,
    risk: str | None = None,
    min_savings: float | None = None,
    min_confidence: float | None = Query(None, ge=0, le=100),
    min_age_days: float | None = Query(
        None, ge=0, description="Only findings first detected at least this many days ago"
    ),
    search: str | None = Query(None, max_length=200),
    limit: int = Query(100, ge=1, le=500),
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    from datetime import datetime, timezone

    findings = [
        f
        for f in svc.repos.findings.list(account_id=account.account_id, limit=5000)
        if f.account_id == account.account_id
    ]

    if status and status.upper() != "ALL":
        findings = [f for f in findings if f.status.value == status.upper()]
    elif not status:
        findings = [f for f in findings if f.status is FindingStatus.OPEN]
    if resource_type:
        findings = [f for f in findings if f.resource_type.value == resource_type.upper()]
    if waste_type:
        findings = [f for f in findings if f.waste_type.value == waste_type.lower()]
    if risk:
        wanted = {r.strip().lower() for r in risk.split(",")}
        findings = [f for f in findings if f.risk.value in wanted]
    if min_savings is not None:
        findings = [f for f in findings if f.potential_monthly_savings >= min_savings]
    if min_confidence is not None:
        findings = [f for f in findings if f.confidence >= min_confidence]
    if min_age_days is not None:
        now = datetime.now(timezone.utc)
        findings = [
            f for f in findings if (now - f.first_seen_at).total_seconds() / 86400 >= min_age_days
        ]
    if search:
        needle = search.lower()
        findings = [
            f
            for f in findings
            if needle in f.resource_id.lower() or needle in f.title.lower()
        ]

    findings.sort(key=lambda f: f.potential_monthly_savings, reverse=True)
    return {
        "account_id": account.account_id,
        "count": len(findings),
        "total_potential_monthly_savings": round(
            sum(f.potential_monthly_savings for f in findings), 2
        ),
        "savings_basis": "ESTIMATED",
        "findings": findings[:limit],
    }


@router.get("/findings/{finding_id}", tags=["findings"])
def get_finding(
    finding_id: str,
    account: Account | None = Depends(optional_account),
    svc: CloudWasteService = Depends(service),
):
    finding = svc.repos.findings.get(finding_id)
    ensure_owned(finding, account, "Finding", finding_id)

    recommendations = [
        r
        for r in svc.repos.recommendations.list(account_id=finding.account_id, limit=5000)
        if r.finding_id == finding_id
    ]
    return {
        "finding": finding,
        "score_contributions": finding.score_breakdown.as_contributions(),
        "resource": svc.resource_for(finding),
        "recommendations": recommendations,
    }


@router.get("/findings/{finding_id}/explanation", tags=["findings"])
def explain_finding(
    finding_id: str,
    account: Account | None = Depends(optional_account),
    svc: CloudWasteService = Depends(service),
):
    """Structured, deterministic explanation built only from stored evidence.

    Missing evidence is listed as missing. Nothing here comes from a model.
    """
    finding = svc.repos.findings.get(finding_id)
    ensure_owned(finding, account, "Finding", finding_id)
    return svc.explain_finding(finding)


class FindingPatch(BaseModel):
    status: str


@router.patch("/findings/{finding_id}", tags=["findings"])
def update_finding(
    finding_id: str,
    payload: FindingPatch,
    user: str = Depends(current_user),
    account: Account | None = Depends(optional_account),
    svc: CloudWasteService = Depends(service),
):
    finding = svc.repos.findings.get(finding_id)
    ensure_owned(finding, account, "Finding", finding_id)
    try:
        new_status = FindingStatus(payload.status.upper())
    except ValueError:
        raise HTTPException(
            400,
            f"Unknown status '{payload.status}'. Valid: "
            + ", ".join(s.value for s in FindingStatus),
        ) from None

    previous = finding.status
    finding.status = new_status
    svc.repos.findings.put(finding)
    svc.repos.audit.put(
        AuditLog(
            resource_id=finding.resource_id,
            account_id=finding.account_id,
            actor=user,
            event="finding.status_changed",
            detail={
                "finding_id": finding_id,
                "from": previous.value,
                "to": new_status.value,
            },
        )
    )
    return finding


@router.get("/recommendations", tags=["recommendations"])
def list_recommendations(
    risk: str | None = None,
    action_type: str | None = None,
    resource_type: str | None = None,
    open_only: bool = Query(False, description="Only recommendations whose finding is OPEN"),
    limit: int = Query(100, ge=1, le=500),
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    recommendations = [
        r
        for r in svc.repos.recommendations.list(account_id=account.account_id, limit=5000)
        if r.account_id == account.account_id
    ]
    if risk:
        wanted = {r.strip().lower() for r in risk.split(",")}
        recommendations = [r for r in recommendations if r.risk.value in wanted]
    if action_type:
        recommendations = [
            r for r in recommendations if r.action_type.value == action_type.upper()
        ]
    if resource_type:
        recommendations = [
            r for r in recommendations if r.resource_type.value == resource_type.upper()
        ]
    if open_only:
        open_ids = {
            f.finding_id
            for f in svc.repos.findings.list(account_id=account.account_id, limit=5000)
            if f.status is FindingStatus.OPEN
        }
        recommendations = [r for r in recommendations if r.finding_id in open_ids]
    recommendations.sort(key=lambda r: r.monthly_savings, reverse=True)
    return {
        "account_id": account.account_id,
        "count": len(recommendations),
        "total_monthly_savings": round(
            sum(r.monthly_savings for r in recommendations), 2
        ),
        "savings_basis": "ESTIMATED",
        "recommendations": recommendations[:limit],
    }


@router.get("/recommendations/{recommendation_id}", tags=["recommendations"])
def get_recommendation(
    recommendation_id: str,
    account: Account | None = Depends(optional_account),
    svc: CloudWasteService = Depends(service),
):
    recommendation = svc.repos.recommendations.get(recommendation_id)
    ensure_owned(recommendation, account, "Recommendation", recommendation_id)
    return {
        "recommendation": recommendation,
        "finding": svc.repos.findings.get(recommendation.finding_id),
        "resource": svc.resource_for(recommendation),
    }


@router.post("/recommendations/{recommendation_id}/simulate", tags=["recommendations"])
def simulate(
    recommendation_id: str,
    account: Account | None = Depends(optional_account),
    svc: CloudWasteService = Depends(service),
):
    """What-if simulation: current state against proposed state.

    Read-only. Reads stored inventory, findings and pricing; calls no AWS API
    and creates no action.
    """
    recommendation = svc.repos.recommendations.get(recommendation_id)
    ensure_owned(recommendation, account, "Recommendation", recommendation_id)
    try:
        return svc.what_if(recommendation)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
