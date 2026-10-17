"""Accounts, costs, dashboard, resources, scans, policy and audit endpoints.

Every account-specific endpoint takes `account_id`. It may be omitted only
when exactly one account is registered; see `deps.resolve_account`.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from ...models.domain import Account
from ...services import CloudWasteService
from ..deps import ensure_owned, get_account, optional_account, resolve_account, service

router = APIRouter()


# --------------------------------------------------------------------------
# Accounts
# --------------------------------------------------------------------------

_ROLE_ARN = re.compile(r"^arn:aws(-[a-z]+)*:iam::(\d{12}):role/[\w+=,.@/-]+$")


class AccountCreate(BaseModel):
    account_id: str = Field(description="12-digit AWS account id")
    name: str = Field(min_length=1, max_length=120)
    role_arn: str | None = Field(
        default=None,
        description="Cross-account role CloudWaste assumes. Omit for a demo account.",
    )
    external_id: str | None = None
    regions: list[str] = ["us-east-1"]
    mode: Literal["live", "demo"] = Field(
        default="live",
        description="'live' uses boto3 against the real account; 'demo' serves synthetic data.",
    )
    environment: str | None = Field(default=None, max_length=40)
    owner: str | None = Field(default=None, max_length=120)

    @field_validator("account_id")
    @classmethod
    def _twelve_digits(cls, value: str) -> str:
        if not re.fullmatch(r"\d{12}", value):
            raise ValueError("account_id must be a 12-digit AWS account id")
        return value

    @field_validator("regions")
    @classmethod
    def _regions(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("at least one region is required")
        for region in value:
            if not re.fullmatch(r"[a-z]{2}(-gov)?-[a-z]+-\d", region):
                raise ValueError(f"'{region}' is not an AWS region name")
        return value


@router.get("/accounts", tags=["accounts"])
def list_accounts(svc: CloudWasteService = Depends(service)):
    return {"accounts": svc.repos.accounts.list()}


@router.get("/accounts/summary", tags=["accounts"])
def accounts_summary(svc: CloudWasteService = Depends(service)):
    """Per-account spend, savings and workload, for the multi-account view.

    Each row is computed only from that account's own records.
    """
    rows = svc.accounts_summary()
    return {"count": len(rows), "accounts": rows}


@router.post("/accounts", tags=["accounts"], status_code=201)
def create_account(payload: AccountCreate, svc: CloudWasteService = Depends(service)):
    if svc.repos.accounts.get(payload.account_id):
        raise HTTPException(409, f"Account {payload.account_id} is already registered")
    if payload.mode == "live":
        if not payload.role_arn:
            raise HTTPException(
                400,
                "A live account needs role_arn: CloudWaste reaches customer accounts "
                "by assuming a cross-account role.",
            )
        match = _ROLE_ARN.match(payload.role_arn)
        if not match:
            raise HTTPException(400, "role_arn is not an IAM role ARN")
        if match.group(2) != payload.account_id:
            raise HTTPException(
                400,
                f"role_arn belongs to account {match.group(2)}, not {payload.account_id}. "
                f"The role must live in the account being registered.",
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
    account: Account = Depends(resolve_account), svc: CloudWasteService = Depends(service)
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
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    plane = svc.data_plane(account)
    start, end = _window(days)
    by_service = plane.cost.cost_by_service(start, end)
    forecast = plane.cost.get_forecast(30)
    return {
        "account_id": account.account_id,
        "period_days": days,
        "currency": "USD",
        "basis": "OBSERVED",
        "total": round(sum(by_service.values()), 2),
        "forecast_next_30_days": forecast,
        "forecast_status": "AVAILABLE" if forecast is not None else "UNAVAILABLE",
        "by_service": by_service,
        "by_region": plane.cost.cost_by_region(start, end),
    }


@router.get("/costs/daily", tags=["costs"])
def daily_costs(
    days: int = Query(30, ge=1, le=365),
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    plane = svc.data_plane(account)
    start, end = _window(days)
    points = plane.cost.get_cost_and_usage(start, end, "DAILY")
    return {
        "account_id": account.account_id,
        "period_days": days,
        "basis": "OBSERVED",
        "series": [
            {"date": p.start.strftime("%Y-%m-%d"), "cost": round(p.amount, 2)}
            for p in points
        ],
    }


@router.get("/costs/services", tags=["costs"])
def service_costs(
    days: int = Query(30, ge=1, le=365),
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    start, end = _window(days)
    return {
        "account_id": account.account_id,
        "basis": "OBSERVED",
        "by_service": svc.data_plane(account).cost.cost_by_service(start, end),
    }


@router.get("/costs/trend", tags=["costs"])
def cost_trend(
    window_days: int = Query(7, ge=1, le=90),
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    plane = svc.data_plane(account)
    end = datetime.now(timezone.utc)
    return {
        "account_id": account.account_id,
        "basis": "OBSERVED",
        **plane.cost.compare_periods(end - timedelta(days=window_days), end, window_days),
    }


@router.get("/costs/forecast", tags=["costs"])
def cost_forecast(
    history_days: int = Query(90, ge=14, le=365),
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    """7, 30 and 90-day spend forecast from observed daily billing.

    Returns status INSUFFICIENT_DATA with null forecasts when there is not
    enough history; never a zero standing in for "unknown".
    """
    return svc.cost_forecast(account, history_days=history_days)


@router.get("/costs/anomalies", tags=["costs"])
def anomalies(
    days: int = Query(30, ge=1, le=90),
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    start, end = _window(days)
    found = svc.data_plane(account).cost.get_anomalies(start, end)
    return {
        "account_id": account.account_id,
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
    environment: str | None = None,
    search: str | None = Query(None, max_length=200),
    limit: int = Query(200, ge=1, le=1000),
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    resources = [
        r
        for r in svc.repos.resources.list(account_id=account.account_id, limit=5000)
        if r.account_id == account.account_id
    ]
    if resource_type:
        resources = [r for r in resources if r.resource_type.value == resource_type.upper()]
    if environment:
        resources = [r for r in resources if r.environment.value == environment.lower()]
    if search:
        needle = search.lower()
        resources = [
            r
            for r in resources
            if needle in r.resource_id.lower() or needle in (r.name or "").lower()
        ]
    resources.sort(key=lambda r: r.monthly_cost, reverse=True)

    open_by_resource: dict[str, list] = {}
    for finding in svc.repos.findings.list(account_id=account.account_id, limit=5000):
        if finding.account_id == account.account_id and finding.status.value == "OPEN":
            open_by_resource.setdefault(finding.resource_id, []).append(finding.finding_id)

    return {
        "account_id": account.account_id,
        "count": len(resources),
        "resources": [
            {
                **r.model_dump(mode="json"),
                "cost_known": r.cost_known,
                "open_finding_ids": open_by_resource.get(r.resource_id, []),
            }
            for r in resources[:limit]
        ],
    }


@router.get("/resources/{resource_id}", tags=["resources"])
def get_resource(
    resource_id: str,
    region: str | None = None,
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    resource = svc.find_resource(account.account_id, resource_id, region)
    if resource is None:
        raise HTTPException(404, f"Resource {resource_id} is not in the inventory")
    findings = [
        f
        for f in svc.repos.findings.list(account_id=account.account_id, limit=5000)
        if f.account_id == account.account_id
        and f.resource_id == resource_id
        and f.region == resource.region
    ]
    return {"resource": resource, "cost_known": resource.cost_known, "findings": findings}


@router.get("/resources/{resource_id}/dependencies", tags=["resources"])
def resource_dependencies(
    resource_id: str,
    region: str | None = None,
    action_type: str | None = Query(None, description="Frame warnings for this action"),
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    """Advisory dependency analysis. Read-only; never changes risk or policy."""
    from ...models.enums import ActionType

    resource = svc.find_resource(account.account_id, resource_id, region)
    if resource is None:
        raise HTTPException(404, f"Resource {resource_id} is not in the inventory")
    action = None
    if action_type:
        try:
            action = ActionType(action_type.upper())
        except ValueError:
            raise HTTPException(400, f"Unknown action_type '{action_type}'") from None
    return svc.dependencies(resource, action)


@router.get("/scans", tags=["scans"])
def list_scans(
    account: Account = Depends(resolve_account), svc: CloudWasteService = Depends(service)
):
    return {
        "account_id": account.account_id,
        "scans": [
            s
            for s in svc.repos.scans.list(account_id=account.account_id, limit=50)
            if s.account_id == account.account_id
        ],
    }


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
def explain_policy(
    recommendation_id: str,
    account: Account | None = Depends(optional_account),
    svc: CloudWasteService = Depends(service),
):
    recommendation = svc.repos.recommendations.get(recommendation_id)
    ensure_owned(recommendation, account, "Recommendation", recommendation_id)
    resource = svc.resource_for(recommendation)
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
    event: str | None = Query(None, description="Prefix match, e.g. 'action.' or 'notification.'"),
    actor: str | None = None,
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    entries = [
        e
        for e in svc.repos.audit.list(account_id=account.account_id, limit=5000)
        if e.account_id == account.account_id
    ]
    if action_id:
        entries = [e for e in entries if e.action_id == action_id]
    if event:
        entries = [e for e in entries if e.event.startswith(event)]
    if actor:
        entries = [e for e in entries if e.actor == actor]
    return {"account_id": account.account_id, "count": len(entries), "entries": entries[:limit]}
