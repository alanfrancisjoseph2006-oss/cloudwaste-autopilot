"""Action lifecycle: create, approve, reject, execute, rollback."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ...actions.approval import ApprovalError
from ...models.domain import Account
from ...services import CloudWasteService
from ..deps import current_user, default_account, service

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
    svc: CloudWasteService = Depends(service),
):
    recommendation = svc.repos.recommendations.get(payload.recommendation_id)
    if recommendation is None:
        raise HTTPException(404, f"Recommendation {payload.recommendation_id} not found")
    resource = svc.repos.resources.get(recommendation.resource_id)
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
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    actions = svc.repos.actions.list(account_id=account.account_id, limit=1000)

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
    return {"count": len(actions), "actions": actions[:limit]}


@router.get("/actions/{action_id}", tags=["actions"])
def get_action(action_id: str, svc: CloudWasteService = Depends(service)):
    action = svc.repos.actions.get(action_id)
    if action is None:
        raise HTTPException(404, f"Action {action_id} not found")
    svc.approvals.expire_if_due(action)
    svc.repos.actions.put(action)

    can_execute, reason = svc.approvals.can_execute(action)
    return {
        "action": action,
        "recommendation": svc.repos.recommendations.get(action.recommendation_id),
        "resource": svc.repos.resources.get(action.resource_id),
        "can_execute": can_execute,
        "can_execute_reason": reason,
        "audit": [
            e
            for e in svc.repos.audit.list(limit=1000)
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
    svc: CloudWasteService = Depends(service),
):
    action = svc.repos.actions.get(action_id)
    if action is None:
        raise HTTPException(404, f"Action {action_id} not found")
    recommendation = svc.repos.recommendations.get(action.recommendation_id)

    try:
        action, audit = svc.approvals.approve(
            action, user, recommendation, (payload.note if payload else None)
        )
    except ApprovalError as exc:
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
    svc: CloudWasteService = Depends(service),
):
    action = svc.repos.actions.get(action_id)
    if action is None:
        raise HTTPException(404, f"Action {action_id} not found")
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
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    action = svc.repos.actions.get(action_id)
    if action is None:
        raise HTTPException(404, f"Action {action_id} not found")

    allowed, reason = svc.approvals.can_execute(action)
    if not allowed:
        # 409, not 403: the request is well-formed and the caller may be
        # entitled to it; the action's own state is what forbids it.
        raise HTTPException(409, reason)

    result = svc.execute_action(action, account, settle_seconds=settle_seconds)
    return {
        "action": result.action,
        "succeeded": result.succeeded,
        "message": result.message,
        "states": result.states,
        "verifications": result.action.verifications,
    }


@router.post("/actions/{action_id}/rollback", tags=["actions"])
def rollback_action(
    action_id: str,
    user: str = Depends(current_user),
    account: Account = Depends(default_account),
    svc: CloudWasteService = Depends(service),
):
    action = svc.repos.actions.get(action_id)
    if action is None:
        raise HTTPException(404, f"Action {action_id} not found")
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
    action.requested_by = user
    result = svc.rollback_action(action, account)
    return {
        "action": result.action,
        "message": result.message,
        "states": result.states,
    }
