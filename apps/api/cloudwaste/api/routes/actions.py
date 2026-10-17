"""Action lifecycle: create, approve, reject, execute, rollback, history.

Execute and rollback always act in the account that owns the action. An
`account_id` query parameter, if given, is a cross-check only: a mismatch is
refused, never resolved.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ...actions.approval import ApprovalError
from ...models.domain import Account
from ...services import AccountMismatchError, CloudWasteService
from ..deps import current_user, ensure_owned, optional_account, resolve_account, service

router = APIRouter()


class ActionCreate(BaseModel):
    recommendation_id: str
    dry_run: bool | None = Field(
        default=None,
        description=(
            "Override the deployment default. Dry run runs every phase except "
            "the AWS mutation itself."
        ),
    )


@router.post("/actions", tags=["actions"], status_code=201)
def create_action(
    payload: ActionCreate,
    user: str = Depends(current_user),
    account: Account | None = Depends(optional_account),
    svc: CloudWasteService = Depends(service),
):
    recommendation = svc.repos.recommendations.get(payload.recommendation_id)
    ensure_owned(recommendation, account, "Recommendation", payload.recommendation_id)
    resource = svc.resource_for(recommendation)
    if resource is None:
        raise HTTPException(404, f"Resource {recommendation.resource_id} not found")

    action, context = svc.create_action(
        recommendation, resource, requested_by=user, dry_run=payload.dry_run
    )
    return {"action": action, **context}


@router.get("/actions", tags=["actions"])
def list_actions(
    approval_status: str | None = None,
    execution_status: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    actions = [
        a
        for a in svc.repos.actions.list(account_id=account.account_id, limit=5000)
        if a.account_id == account.account_id
    ]

    # Expire stale approvals on read, so a list never shows a pending approval
    # that is in fact no longer valid.
    for action in actions:
        if svc.approvals.expire_if_due(action):
            svc.repos.actions.put(action)

    if approval_status:
        actions = [a for a in actions if a.approval_status.value == approval_status.upper()]
    if execution_status:
        actions = [
            a for a in actions if a.execution_status.value == execution_status.upper()
        ]
    return {"account_id": account.account_id, "count": len(actions), "actions": actions[:limit]}


@router.get("/actions/history", tags=["actions"])
def action_history(
    limit: int = Query(200, ge=1, le=1000),
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    """Optimization history: actions joined with their approvals, checkpoints,
    verifications, savings reconciliation and audit trail. Nothing new is
    stored; this is a view over the existing records."""
    rows = svc.action_history(account)
    return {"account_id": account.account_id, "count": len(rows), "history": rows[:limit]}


@router.post("/actions/reconcile", tags=["actions"])
def reconcile_savings(
    account: Account = Depends(resolve_account),
    svc: CloudWasteService = Depends(service),
):
    """Check executed actions' savings against observed billing now.

    Also runs after every scan. Read-only against AWS: it queries Cost
    Explorer and changes nothing but CloudWaste's own records.
    """
    changed = svc.reconcile_savings(account)
    return {
        "account_id": account.account_id,
        "updated": len(changed),
        "actions": [
            {
                "action_id": a.action_id,
                "savings_status": a.savings_status.value,
                "estimated_monthly_savings": a.estimated_monthly_savings,
                "verified_monthly_savings": a.verified_monthly_savings,
                "detail": a.savings_detail,
            }
            for a in changed
        ],
    }


@router.get("/actions/{action_id}", tags=["actions"])
def get_action(
    action_id: str,
    account: Account | None = Depends(optional_account),
    svc: CloudWasteService = Depends(service),
):
    action = svc.repos.actions.get(action_id)
    ensure_owned(action, account, "Action", action_id)
    if svc.approvals.expire_if_due(action):
        svc.repos.actions.put(action)

    can_execute, reason = svc.approvals.can_execute(action)
    return {
        "action": action,
        "recommendation": svc.repos.recommendations.get(action.recommendation_id),
        "resource": svc.resource_for(action),
        "can_execute": can_execute,
        "can_execute_reason": reason,
        "audit": [
            e
            for e in svc.repos.audit.list(account_id=action.account_id, limit=5000)
            if e.action_id == action_id
        ],
    }


class ApprovalPayload(BaseModel):
    note: str | None = None


@router.post("/actions/{action_id}/approve", tags=["actions"])
def approve_action(
    action_id: str,
    payload: ApprovalPayload | None = None,
    user: str = Depends(current_user),
    account: Account | None = Depends(optional_account),
    svc: CloudWasteService = Depends(service),
):
    action = svc.repos.actions.get(action_id)
    ensure_owned(action, account, "Action", action_id)
    recommendation = svc.repos.recommendations.get(action.recommendation_id)

    try:
        action, audit = svc.approvals.approve(
            action, user, recommendation, (payload.note if payload else None)
        )
    except ApprovalError as exc:
        svc.repos.actions.put(action)  # persist an expiry the check may have recorded
        raise HTTPException(409, str(exc)) from exc

    svc.repos.actions.put(action)
    svc.repos.audit.put(audit)
    return {"action": action, "approved_by": user}


class RejectionPayload(BaseModel):
    reason: str = Field(min_length=1, description="Why this is being rejected")


@router.post("/actions/{action_id}/reject", tags=["actions"])
def reject_action(
    action_id: str,
    payload: RejectionPayload,
    user: str = Depends(current_user),
    account: Account | None = Depends(optional_account),
    svc: CloudWasteService = Depends(service),
):
    action = svc.repos.actions.get(action_id)
    ensure_owned(action, account, "Action", action_id)
    try:
        action, audit = svc.approvals.reject(action, user, payload.reason)
    except ApprovalError as exc:
        raise HTTPException(409, str(exc)) from exc
    svc.repos.actions.put(action)
    svc.repos.audit.put(audit)
    return {"action": action, "rejected_by": user}


@router.post("/actions/{action_id}/execute", tags=["actions"])
def execute_action(
    action_id: str,
    settle_seconds: int | None = Query(
        None, ge=0, le=900, description="Override the post-execution settle wait"
    ),
    account: Account | None = Depends(optional_account),
    svc: CloudWasteService = Depends(service),
):
    from ...actions.step_functions import RemediationAlreadySubmitted

    action = svc.repos.actions.get(action_id)
    if action is None:
        raise HTTPException(404, f"Action {action_id} not found")
    if account is not None and account.account_id != action.account_id:
        raise HTTPException(
            409,
            f"Action {action_id} belongs to account {action.account_id}, not "
            f"{account.account_id}. Refusing to execute across accounts.",
        )

    allowed, reason = svc.approvals.can_execute(action)
    if not allowed:
        svc.repos.actions.put(action)  # persist an expiry the check may have recorded
        # 409, not 403: the request is well-formed and the caller may be
        # entitled to it; the action's own state is what forbids it.
        raise HTTPException(409, reason)

    try:
        result = svc.execute_action(action, account, settle_seconds=settle_seconds)
    except (AccountMismatchError, RemediationAlreadySubmitted) as exc:
        raise HTTPException(409, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {
        "action": result.action,
        "succeeded": result.succeeded,
        "message": result.message,
        "states": result.states,
        "verifications": result.action.verifications,
        "orchestration": "step_functions" if svc.settings.use_step_functions else "local",
    }


@router.post("/actions/{action_id}/rollback", tags=["actions"])
def rollback_action(
    action_id: str,
    user: str = Depends(current_user),
    account: Account | None = Depends(optional_account),
    svc: CloudWasteService = Depends(service),
):
    action = svc.repos.actions.get(action_id)
    if action is None:
        raise HTTPException(404, f"Action {action_id} not found")
    if account is not None and account.account_id != action.account_id:
        raise HTTPException(
            409,
            f"Action {action_id} belongs to account {action.account_id}, not "
            f"{account.account_id}. Refusing to roll back across accounts.",
        )
    if not action.can_rollback:
        raise HTTPException(
            409,
            f"Action {action_id} cannot be rolled back: "
            + (
                "no checkpoint was recorded"
                if action.checkpoint is None
                else f"its status is {action.execution_status.value}, not COMPLETED"
            ),
        )
    try:
        result = svc.rollback_action(action, account, operator=user)
    except AccountMismatchError as exc:
        raise HTTPException(409, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {
        "action": result.action,
        "message": result.message,
        "states": result.states,
    }
