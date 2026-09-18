"""Findings, recommendations and scan triggering."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ...models.domain import Account
from ...models.enums import FindingStatus
from ...services import CloudWasteService
from ..deps import current_user, default_account, service

router = APIRouter()


@router.post("/findings/scan", tags=["findings"])
def run_scan(
    region: str | None = None,
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    """Run a full scan. Synchronous: a demo account takes under a second and a
    real account a few minutes. A production deployment runs this on an
    EventBridge schedule into Step Functions rather than over HTTP."""
    result = svc.scan_account(account, region)
    return {
        "scan": result["scan"],
        "findings_created": len(result["findings"]),
        "recommendations_created": len(result["recommendations"]),
        "total_potential_monthly_savings": result["scan"].total_potential_savings,
    }


@router.get("/findings", tags=["findings"])
def list_findings(
    status: str | None = Query(None, description="OPEN, SUPPRESSED, REMEDIATED, STALE, or ALL"),
    resource_type: str | None = None,
    waste_type: str | None = None,
    risk: str | None = None,
    min_savings: float | None = None,
    limit: int = Query(100, ge=1, le=500),
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    findings = svc.repos.findings.list(account_id=account.account_id, limit=1000)

    if status and status.upper() != "ALL":
        findings = [f for f in findings if f.status.value == status.upper()]
    elif not status:
        findings = [f for f in findings if f.status is FindingStatus.OPEN]
    if resource_type:
        findings = [f for f in findings if f.resource_type.value == resource_type.upper()]
    if waste_type:
        findings = [f for f in findings if f.waste_type.value == waste_type.lower()]
    if risk:
        findings = [f for f in findings if f.risk.value == risk.lower()]
    if min_savings is not None:
        findings = [f for f in findings if f.potential_monthly_savings >= min_savings]

    findings.sort(key=lambda f: f.potential_monthly_savings, reverse=True)
    return {
        "count": len(findings),
        "total_potential_monthly_savings": round(
            sum(f.potential_monthly_savings for f in findings), 2
        ),
        "findings": findings[:limit],
    }


@router.get("/findings/{finding_id}", tags=["findings"])
def get_finding(finding_id: str, svc: CloudWasteService = Depends(service)):
    finding = svc.repos.findings.get(finding_id)
    if finding is None:
        raise HTTPException(404, f"Finding {finding_id} not found")

    recommendations = [
        r
        for r in svc.repos.recommendations.list(limit=1000)
        if r.finding_id == finding_id
    ]
    return {
        "finding": finding,
        "score_contributions": finding.score_breakdown.as_contributions(),
        "resource": svc.repos.resources.get(finding.resource_id),
        "recommendations": recommendations,
    }


class FindingPatch(BaseModel):
    status: str


@router.patch("/findings/{finding_id}", tags=["findings"])
def update_finding(
    finding_id: str,
    payload: FindingPatch,
    user: str = Depends(current_user),
    svc: CloudWasteService = Depends(service),
):
    finding = svc.repos.findings.get(finding_id)
    if finding is None:
        raise HTTPException(404, f"Finding {finding_id} not found")
    try:
        new_status = FindingStatus(payload.status.upper())
    except ValueError:
        raise HTTPException(
            400,
            f"Unknown status '{payload.status}'. Valid: "
            + ", ".join(s.value for s in FindingStatus),
        ) from None

    from ...models.domain import AuditLog

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
    limit: int = Query(100, ge=1, le=500),
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    recommendations = svc.repos.recommendations.list(
        account_id=account.account_id, limit=1000
    )
    if risk:
        recommendations = [r for r in recommendations if r.risk.value == risk.lower()]
    if action_type:
        recommendations = [
            r for r in recommendations if r.action_type.value == action_type.upper()
        ]
    recommendations.sort(key=lambda r: r.monthly_savings, reverse=True)
    return {
        "count": len(recommendations),
        "total_monthly_savings": round(
            sum(r.monthly_savings for r in recommendations), 2
        ),
        "recommendations": recommendations[:limit],
    }


@router.get("/recommendations/{recommendation_id}", tags=["recommendations"])
def get_recommendation(recommendation_id: str, svc: CloudWasteService = Depends(service)):
    recommendation = svc.repos.recommendations.get(recommendation_id)
    if recommendation is None:
        raise HTTPException(404, f"Recommendation {recommendation_id} not found")
    return {
        "recommendation": recommendation,
        "finding": svc.repos.findings.get(recommendation.finding_id),
        "resource": svc.repos.resources.get(recommendation.resource_id),
    }


@router.post("/recommendations/{recommendation_id}/simulate", tags=["recommendations"])
def simulate(recommendation_id: str, svc: CloudWasteService = Depends(service)):
    """Re-run the simulation against current state. Changes nothing."""
    recommendation = svc.repos.recommendations.get(recommendation_id)
    if recommendation is None:
        raise HTTPException(404, f"Recommendation {recommendation_id} not found")
    resource = svc.repos.resources.get(recommendation.resource_id)
    if resource is None:
        raise HTTPException(404, f"Resource {recommendation.resource_id} not found")

    from ...intelligence import impact_analyzer

    result = impact_analyzer.simulate(
        resource,
        recommendation.action_type,
        recommendation.action_parameters,
        current_monthly_cost=resource.monthly_cost,
        confidence=recommendation.confidence,
    )
    return {
        "recommendation_id": recommendation_id,
        "resource_id": resource.resource_id,
        "action_type": recommendation.action_type.value,
        "simulation": result,
    }
