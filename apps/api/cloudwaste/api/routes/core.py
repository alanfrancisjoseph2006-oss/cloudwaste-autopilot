"""Accounts, costs, dashboard, resources, scans and policy endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ...models.domain import Account
from ...services import CloudWasteService
from ..deps import default_account, get_account, service

router = APIRouter()


# --------------------------------------------------------------------------
# Accounts
# --------------------------------------------------------------------------


class AccountCreate(BaseModel):
    account_id: str = Field(description="12-digit AWS account id")
    name: str
    role_arn: str | None = Field(
        default=None,
        description="Cross-account role CloudWaste assumes. Omit for a demo account.",
    )
    external_id: str | None = None
    regions: list[str] = ["us-east-1"]
    mode: str = Field(
        default="live",
        description="'live' uses boto3 against the real account; 'demo' serves synthetic data.",
    )


@router.get("/accounts", tags=["accounts"])
def list_accounts(svc: CloudWasteService = Depends(service)):
    return {"accounts": svc.repos.accounts.list()}


@router.post("/accounts", tags=["accounts"], status_code=201)
def create_account(payload: AccountCreate, svc: CloudWasteService = Depends(service)):
    if svc.repos.accounts.get(payload.account_id):
        raise HTTPException(409, f"Account {payload.account_id} is already registered")
    if payload.mode == "live" and not payload.role_arn:
        raise HTTPException(
            400,
            "A live account needs role_arn: CloudWaste reaches customer accounts "
            "by assuming a cross-account role.",
        )
    account = Account(**payload.model_dump())
    svc.repos.accounts.put(account)
    return account


@router.get("/accounts/{account_id}", tags=["accounts"])
def get_one_account(account: Account = Depends(get_account)):
    return account


@router.delete("/accounts/{account_id}", tags=["accounts"], status_code=204)
def delete_account(account_id: str, svc: CloudWasteService = Depends(service)):
    if not svc.repos.accounts.delete(account_id):
        raise HTTPException(404, f"Account {account_id} is not registered")
    return None


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------


@router.get("/dashboard", tags=["dashboard"])
def dashboard(
    account: Account = Depends(default_account), svc: CloudWasteService = Depends(service)
):
    return svc.dashboard(account)


# --------------------------------------------------------------------------
# Costs
# --------------------------------------------------------------------------


def _window(days: int):
    end = datetime.now(timezone.utc)
    return end - timedelta(days=days), end


@router.get("/costs", tags=["costs"])
def costs(
    days: int = Query(30, ge=1, le=365),
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    plane = svc.data_plane(account)
    start, end = _window(days)
    by_service = plane.cost.cost_by_service(start, end)
    return {
        "period_days": days,
        "currency": "USD",
        "total": round(sum(by_service.values()), 2),
        "forecast_next_30_days": plane.cost.get_forecast(30),
        "by_service": by_service,
        "by_region": plane.cost.cost_by_region(start, end),
    }


@router.get("/costs/daily", tags=["costs"])
def daily_costs(
    days: int = Query(30, ge=1, le=365),
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    plane = svc.data_plane(account)
    start, end = _window(days)
    points = plane.cost.get_cost_and_usage(start, end, "DAILY")
    return {
        "period_days": days,
        "series": [
            {"date": p.start.strftime("%Y-%m-%d"), "cost": round(p.amount, 2)}
            for p in points
        ],
    }


@router.get("/costs/services", tags=["costs"])
def service_costs(
    days: int = Query(30, ge=1, le=365),
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    start, end = _window(days)
    return {"by_service": svc.data_plane(account).cost.cost_by_service(start, end)}


@router.get("/costs/trend", tags=["costs"])
def cost_trend(
    window_days: int = Query(7, ge=1, le=90),
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    plane = svc.data_plane(account)
    end = datetime.now(timezone.utc)
    return plane.cost.compare_periods(end - timedelta(days=window_days), end, window_days)


@router.get("/costs/anomalies", tags=["costs"])
def anomalies(
    days: int = Query(30, ge=1, le=90),
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    start, end = _window(days)
    found = svc.data_plane(account).cost.get_anomalies(start, end)
    return {
        "count": len(found),
        "anomalies": [
            {
                "anomaly_id": a.anomaly_id,
                "service": a.service,
                "start": a.start.isoformat(),
                "end": a.end.isoformat() if a.end else None,
                "expected_spend": a.expected_spend,
                "actual_spend": a.actual_spend,
                "excess": round(a.actual_spend - a.expected_spend, 2),
                "increase_percent": a.increase_percent,
                "root_causes": a.root_causes,
            }
            for a in found
        ],
    }


# --------------------------------------------------------------------------
# Resources and scans
# --------------------------------------------------------------------------


@router.get("/resources", tags=["resources"])
def list_resources(
    resource_type: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    resources = svc.repos.resources.list(account_id=account.account_id, limit=1000)
    if resource_type:
        resources = [
            r for r in resources if r.resource_type.value == resource_type.upper()
        ]
    resources.sort(key=lambda r: r.monthly_cost, reverse=True)
    return {"count": len(resources), "resources": resources[:limit]}


@router.get("/resources/{resource_id}", tags=["resources"])
def get_resource(resource_id: str, svc: CloudWasteService = Depends(service)):
    resource = svc.repos.resources.get(resource_id)
    if resource is None:
        raise HTTPException(404, f"Resource {resource_id} is not in the inventory")
    findings = [
        f
        for f in svc.repos.findings.list(limit=1000)
        if f.resource_id == resource_id
    ]
    return {"resource": resource, "findings": findings}


@router.get("/scans", tags=["scans"])
def list_scans(
    account: Account = Depends(default_account), svc: CloudWasteService = Depends(service)
):
    return {"scans": svc.repos.scans.list(account_id=account.account_id, limit=50)}


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------


@router.get("/policies", tags=["policy"])
def list_policies(svc: CloudWasteService = Depends(service)):
    return {
        "rules": svc.policy_rules,
        "validation_problems": svc.policy_problems,
        "deployment_ceilings": {
            "autopilot_enabled": svc.settings.autopilot_enabled,
            "autopilot_max_risk": svc.settings.autopilot_max_risk,
            "dry_run_default": svc.settings.dry_run_default,
            "note": (
                "These override any policy rule. A rule with auto_execute=true "
                "still requires approval unless autopilot is enabled and the "
                "action's risk is at or below the ceiling."
            ),
        },
    }


@router.get("/policies/explain/{recommendation_id}", tags=["policy"])
def explain_policy(recommendation_id: str, svc: CloudWasteService = Depends(service)):
    recommendation = svc.repos.recommendations.get(recommendation_id)
    if recommendation is None:
        raise HTTPException(404, f"Recommendation {recommendation_id} not found")
    resource = svc.repos.resources.get(recommendation.resource_id)
    if resource is None:
        raise HTTPException(404, f"Resource {recommendation.resource_id} not found")
    return svc.policy.explain(recommendation, resource)


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------


@router.get("/audit", tags=["audit"])
def audit_log(
    limit: int = Query(100, ge=1, le=1000),
    action_id: str | None = None,
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    entries = svc.repos.audit.list(account_id=account.account_id, limit=1000)
    if action_id:
        entries = [e for e in entries if e.action_id == action_id]
    return {"count": len(entries), "entries": entries[:limit]}
