"""AWS Step Functions execution path.

When `use_step_functions` is on, executing an action starts the state machine
in `infra/stepfunctions/remediation.asl.json` instead of running the
orchestrator in-process. Each Task state in that definition invokes one of the
`*_handler` functions below, and each handler calls the *same*
`RemediationOrchestrator.phase_*` method that the in-process `run()` calls. The
two paths therefore share every guard: approval is re-checked, preflight
re-reads live AWS, a checkpoint precedes the mutation, and a failed rollback is
escalated.

State passes between Lambda invocations through the action record in
DynamoDB, which is why Step Functions mode requires DynamoDB storage (enforced
by `config.validate_settings`).

Every handler re-derives the account from the stored action and refuses if the
execution input names a different one.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from ..models.domain import Account, Action, AuditLog
from ..models.enums import ExecutionStatus
from .executors.base import PreflightFailure  # noqa: F401 - re-raised by name for the ASL Catch
from .orchestrator import RemediationResult
from .verification import HealthBaseline

logger = logging.getLogger(__name__)


class RemediationAlreadySubmitted(RuntimeError):
    """The action already has a running or finished state machine execution."""


# --------------------------------------------------------------------------
# Starting an execution (API side)
# --------------------------------------------------------------------------


def _sfn_client(settings):
    import boto3

    region = settings.state_machine_arn.split(":")[3]
    return boto3.client("stepfunctions", region_name=region)


def start_remediation(service, action: Action, account: Account, client=None) -> RemediationResult:
    """Start the state machine for one action, in its owning account's context."""
    result = RemediationResult(action=action)
    now = datetime.now(timezone.utc).isoformat()

    if action.execution_arn:
        raise RemediationAlreadySubmitted(
            f"Action {action.action_id} was already submitted as {action.execution_arn}."
        )
    if action.account_id != account.account_id:
        raise ValueError("Refusing to start an execution for another account's action.")

    # The state machine re-checks this in ValidatePolicy. Checking here as well
    # means a refused action never produces a state machine execution at all.
    allowed, reason = service.approvals.can_execute(action)
    if not allowed:
        orchestrator = service._orchestrator(account, action.region)
        orchestrator.mark_aborted(action, reason)
        result.states.append({"state": "ValidatePolicy", "ok": False, "detail": reason, "at": now})
        result.audit.append(
            orchestrator.abort_audit(action, "ValidatePolicy", reason, result.states)
        )
        result.message = f"Aborted at ValidatePolicy: {reason}"
        service._persist_result(result)
        return result

    client = client or _sfn_client(service.settings)
    payload = execution_input(action)
    response = client.start_execution(
        stateMachineArn=service.settings.state_machine_arn,
        name=f"{action.action_id}-{uuid.uuid4().hex[:8]}",
        input=json.dumps(payload),
    )
    action.execution_arn = response["executionArn"]
    result.states.append(
        {
            "state": "Submitted",
            "ok": True,
            "detail": f"Started state machine execution {action.execution_arn}",
            "at": now,
        }
    )
    result.audit.append(
        AuditLog(
            action_id=action.action_id,
            resource_id=action.resource_id,
            account_id=action.account_id,
            actor=action.approved_by or action.requested_by,
            event="action.submitted",
            risk=action.risk,
            detail={"execution_arn": action.execution_arn, "input": payload},
        )
    )
    result.message = (
        f"Submitted to Step Functions. Progress is recorded on the action and in "
        f"the audit trail as each state completes."
    )
    service._persist_result(result)
    return result


def execution_input(action: Action) -> dict:
    """The state machine's input. Identifiers only; handlers reload the rest."""
    return {
        "action_id": action.action_id,
        "account_id": action.account_id,
        "resource_id": action.resource_id,
        "region": action.region,
        "action": {
            "action_id": action.action_id,
            "account_id": action.account_id,
            "resource_id": action.resource_id,
            "action_type": action.action_type.value,
        },
    }


# --------------------------------------------------------------------------
# Lambda handlers (state machine side)
# --------------------------------------------------------------------------


class _Loaded:
    def __init__(self, service, action, resource, recommendation, account, orchestrator):
        self.service = service
        self.action = action
        self.resource = resource
        self.recommendation = recommendation
        self.account = account
        self.orchestrator = orchestrator

    def save(self) -> None:
        self.service.repos.actions.put(self.action)


def _identifiers(event: dict) -> tuple[str, str]:
    source = event.get("action") if isinstance(event.get("action"), dict) else event
    action_id = source.get("action_id") or event.get("action_id")
    account_id = source.get("account_id") or event.get("account_id")
    if not action_id or not account_id:
        raise ValueError("State machine input must carry action_id and account_id")
    return action_id, account_id


def _load(event: dict, service=None) -> _Loaded:
    from ..services import AccountMismatchError, get_service

    service = service or get_service()
    action_id, account_id = _identifiers(event)
    action = service.repos.actions.get(action_id)
    if action is None:
        raise LookupError(f"Action {action_id} not found")
    if action.account_id != account_id:
        raise AccountMismatchError(
            f"Execution input names account {account_id} but action {action_id} "
            f"belongs to {action.account_id}"
        )
    account = service.get_account(action.account_id)
    resource = service.resource_for(action)
    if resource is None:
        raise LookupError(f"Resource {action.resource_id} is not in the inventory")
    recommendation = service.repos.recommendations.get(action.recommendation_id)
    orchestrator = service._orchestrator(account, action.region)
    return _Loaded(service, action, resource, recommendation, account, orchestrator)


def _executor(loaded: _Loaded):
    return loaded.orchestrator.phase_validate_action(loaded.action, loaded.resource)


def validate_action_handler(event: dict, context: Any = None, *, service=None) -> dict:
    loaded = _load(event, service)
    _executor(loaded)  # raises ValidationFailure -> AuditAborted
    return {"ok": True, "action_type": loaded.action.action_type.value}


def validate_policy_handler(event: dict, context: Any = None, *, service=None) -> dict:
    loaded = _load(event, service)
    allowed, reason = loaded.orchestrator.phase_validate_policy(loaded.action)
    loaded.save()  # can_execute may have expired the approval
    return {"allowed": allowed, "reason": reason}


def preflight_handler(event: dict, context: Any = None, *, service=None) -> dict:
    loaded = _load(event, service)
    executor = _executor(loaded)
    ctx = loaded.orchestrator.context_for(loaded.action, loaded.resource)
    detail = loaded.orchestrator.phase_preflight(executor, ctx)  # PreflightFailure propagates
    return {"ok": True, "detail": detail}


def capture_baseline_handler(event: dict, context: Any = None, *, service=None) -> dict:
    loaded = _load(event, service)
    return loaded.orchestrator.phase_capture_baseline(loaded.resource).to_dict()


def create_checkpoint_handler(event: dict, context: Any = None, *, service=None) -> dict:
    loaded = _load(event, service)
    executor = _executor(loaded)
    ctx = loaded.orchestrator.context_for(loaded.action, loaded.resource)
    baseline = HealthBaseline.from_dict(event.get("baseline") or {})
    checkpoint = loaded.orchestrator.phase_create_checkpoint(executor, ctx, baseline)
    loaded.save()
    return {"rollback_method": checkpoint.rollback_method}


def execute_action_handler(event: dict, context: Any = None, *, service=None) -> dict:
    loaded = _load(event, service)
    executor = _executor(loaded)
    ctx = loaded.orchestrator.context_for(loaded.action, loaded.resource)
    try:
        outcome = loaded.orchestrator.phase_execute(executor, ctx)
    except Exception as exc:
        loaded.action.execution_status = ExecutionStatus.FAILED
        loaded.action.error = str(exc)
        loaded.action.completed_at = datetime.now(timezone.utc)
        loaded.save()
        raise  # the state machine routes this to Rollback
    loaded.save()
    return {
        "detail": outcome.detail,
        "dry_run": outcome.dry_run,
        "settle_seconds": loaded.orchestrator.settle_seconds_for(loaded.action, loaded.resource),
    }


def verify_health_handler(event: dict, context: Any = None, *, service=None) -> dict:
    loaded = _load(event, service)
    executor = _executor(loaded)
    ctx = loaded.orchestrator.context_for(loaded.action, loaded.resource)
    baseline = HealthBaseline.from_dict(event.get("baseline") or {})
    passed, summary = loaded.orchestrator.phase_verify(executor, ctx, loaded.resource, baseline)
    loaded.save()
    return {"passed": passed, "summary": summary}


def record_savings_handler(event: dict, context: Any = None, *, service=None) -> dict:
    loaded = _load(event, service)
    detail = loaded.orchestrator.phase_record_savings(
        loaded.action, loaded.resource, loaded.recommendation
    )
    loaded.save()
    return {"detail": detail, "savings_status": loaded.action.savings_status.value}


def rollback_handler(event: dict, context: Any = None, *, service=None) -> dict:
    loaded = _load(event, service)
    if loaded.action.checkpoint is None:
        # Nothing was captured, so nothing can be restored. Say so explicitly.
        loaded.action.execution_status = ExecutionStatus.ROLLBACK_FAILED
        loaded.action.error = "Rollback requested but no checkpoint was recorded."
        loaded.save()
        return {"succeeded": False, "detail": loaded.action.error}
    executor = _executor(loaded)
    ctx = loaded.orchestrator.context_for(loaded.action, loaded.resource)
    cause = _cause(event)
    succeeded, detail = loaded.orchestrator.phase_rollback(
        executor, ctx, loaded.action.checkpoint, cause
    )
    loaded.save()
    return {"succeeded": succeeded, "detail": detail}


def audit_handler(event: dict, context: Any = None, *, service=None) -> dict:
    """Writes the terminal audit record. Aborted actions are marked FAILED."""
    from ..services import get_service

    service = service or get_service()
    action_id, account_id = _identifiers(event)
    action = service.repos.actions.get(action_id)
    outcome = event.get("outcome", "UNKNOWN")
    if action is not None and action.account_id == account_id and outcome == "ABORTED":
        if action.execution_status in (ExecutionStatus.NOT_STARTED, ExecutionStatus.EXECUTING):
            orchestrator = service._orchestrator(service.get_account(account_id), action.region)
            orchestrator.mark_aborted(action, _cause(event.get("detail") or {}))
            service.repos.actions.put(action)
    detail = event.get("detail") or {}
    service.repos.audit.put(
        AuditLog(
            action_id=action_id,
            resource_id=action.resource_id if action else None,
            account_id=account_id,
            actor=(action.approved_by or action.requested_by) if action else "system",
            event=event.get("event", "action.audit"),
            outcome=outcome,
            risk=action.risk if action else None,
            detail={
                "source": "step_functions",
                "state_results": {
                    k: v for k, v in detail.items() if k not in ("action",)
                } if isinstance(detail, dict) else detail,
            },
        )
    )
    if action is not None:
        service.notifications.after_execution(action)
    return {"written": True}


def _cause(event: dict) -> str:
    error = event.get("error") or {}
    if isinstance(error, dict) and (error.get("Cause") or error.get("Error")):
        return f"{error.get('Error', 'Error')}: {error.get('Cause', '')}".strip()
    verification = event.get("verification") or {}
    if isinstance(verification, dict) and verification.get("summary"):
        return verification["summary"]
    policy = event.get("policy") or {}
    if isinstance(policy, dict) and policy.get("reason"):
        return policy["reason"]
    return "State machine routed to this state without a recorded cause"


#: ASL placeholder -> handler. Used by the CloudFormation template and checked
#: by the test suite, so a Task state cannot point at a handler that is missing.
HANDLERS = {
    "ValidateActionFunctionArn": "cloudwaste.actions.step_functions.validate_action_handler",
    "ValidatePolicyFunctionArn": "cloudwaste.actions.step_functions.validate_policy_handler",
    "PreflightFunctionArn": "cloudwaste.actions.step_functions.preflight_handler",
    "CaptureBaselineFunctionArn": "cloudwaste.actions.step_functions.capture_baseline_handler",
    "CreateCheckpointFunctionArn": "cloudwaste.actions.step_functions.create_checkpoint_handler",
    "ExecuteActionFunctionArn": "cloudwaste.actions.step_functions.execute_action_handler",
    "VerifyHealthFunctionArn": "cloudwaste.actions.step_functions.verify_health_handler",
    "RecordSavingsFunctionArn": "cloudwaste.actions.step_functions.record_savings_handler",
    "RollbackFunctionArn": "cloudwaste.actions.step_functions.rollback_handler",
    "AuditFunctionArn": "cloudwaste.actions.step_functions.audit_handler",
}
