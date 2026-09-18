"""Remediation orchestration.

This runs the state sequence that `infra/stepfunctions/remediation.asl.json`
defines. The two implementations are deliberately identical in structure: in
production Step Functions drives the states and calls Lambdas that call into
this module's phases, and locally this module runs them in-process. Same order,
same guards, same audit records, so what you test locally is what runs.

    ValidateAction -> ValidatePolicy -> Preflight -> CaptureBaseline
      -> CreateCheckpoint -> ExecuteAction -> Settle -> VerifyHealth
      -> [pass] RecordSavings -> Audit -> done
      -> [fail] Rollback -> VerifyRollback -> Audit -> done

Two properties are load-bearing:

  * **Every exit path writes an audit record.** Including the ones that fail
    before anything happened. An action that vanished without trace is worse
    than one that failed.
  * **A rollback failure is escalated, never swallowed.** If the change broke
    something and the undo also failed, that is the state a human must be
    paged into, and the action is left in ROLLBACK_FAILED rather than being
    quietly marked FAILED.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..config import Settings, get_settings
from ..models.domain import Action, AuditLog, Recommendation, Resource
from ..models.enums import ApprovalStatus, ExecutionStatus
from .approval import ApprovalEngine
from .executors.base import (
    ExecutionContext,
    ExecutionFailure,
    PreflightFailure,
)
from .registry import NoExecutorError, get_executor
from .verification import HealthBaseline, VerificationEngine, summarize

logger = logging.getLogger(__name__)


@dataclass
class RemediationResult:
    action: Action
    audit: list[AuditLog] = field(default_factory=list)
    states: list[dict] = field(default_factory=list)
    message: str = ""

    @property
    def succeeded(self) -> bool:
        return self.action.execution_status is ExecutionStatus.COMPLETED


class RemediationOrchestrator:
    def __init__(
        self,
        data_plane,
        client_factory=None,
        settings: Settings | None = None,
        approval_engine: ApprovalEngine | None = None,
    ) -> None:
        self.data = data_plane
        self.client_factory = client_factory
        self.settings = settings or get_settings()
        self.approvals = approval_engine or ApprovalEngine(self.settings)
        self.verifier = VerificationEngine(data_plane)

    # ------------------------------------------------------------------

    def run(
        self,
        action: Action,
        resource: Resource,
        recommendation: Recommendation | None = None,
        settle_seconds: int | None = None,
    ) -> RemediationResult:
        result = RemediationResult(action=action)
        started = datetime.now(timezone.utc)

        def state(name: str, ok: bool, detail: str) -> None:
            result.states.append(
                {
                    "state": name,
                    "ok": ok,
                    "detail": detail,
                    "at": datetime.now(timezone.utc).isoformat(),
                }
            )
            logger.info("[%s] %s: %s", action.action_id, name, detail)

        # --- ValidateAction ------------------------------------------
        try:
            executor = get_executor(action.action_type)
        except NoExecutorError as exc:
            return self._abort(result, "ValidateAction", str(exc), state)

        if action.resource_id != resource.resource_id:
            return self._abort(
                result,
                "ValidateAction",
                f"Action targets {action.resource_id} but was given resource "
                f"{resource.resource_id}",
                state,
            )
        state("ValidateAction", True, f"Executor found for {action.action_type.value}")

        # --- ValidatePolicy / approval --------------------------------
        allowed, reason = self.approvals.can_execute(action)
        if not allowed:
            return self._abort(result, "ValidatePolicy", reason, state)
        state("ValidatePolicy", True, reason)

        dry_run = action.dry_run or self.settings.dry_run_default
        context = ExecutionContext(
            action=action,
            resource=resource,
            dry_run=dry_run,
            client_factory=self.client_factory,
            settings=self.settings,
        )
        if dry_run:
            state(
                "DryRunNotice",
                True,
                "Running in dry-run mode: every phase executes except the AWS "
                "mutation itself.",
            )

        # --- Preflight -------------------------------------------------
        if not dry_run:
            try:
                executor.preflight(context)
            except PreflightFailure as exc:
                return self._abort(
                    result,
                    "Preflight",
                    f"Refused: {exc}",
                    state,
                    detail={"phase": "preflight"},
                )
            except Exception as exc:  # noqa: BLE001
                return self._abort(
                    result, "Preflight", f"Preflight check errored: {exc}", state
                )
            state(
                "Preflight",
                True,
                "Live state still matches the plan"
                + (f"; {'; '.join(context.notes)}" if context.notes else ""),
            )
        else:
            state("Preflight", True, "Skipped in dry run (no live AWS state to check)")

        # --- CaptureBaseline -------------------------------------------
        baseline = self.verifier.capture_baseline(resource)
        state(
            "CaptureBaseline",
            True,
            f"Health baseline captured: {baseline.to_dict()}",
        )

        # --- CreateCheckpoint ------------------------------------------
        try:
            checkpoint = executor.capture(context)
            checkpoint.rollback_data["health_baseline"] = baseline.to_dict()
            action.checkpoint = checkpoint
        except Exception as exc:  # noqa: BLE001
            return self._abort(
                result, "CreateCheckpoint", f"Could not capture rollback state: {exc}", state
            )
        state(
            "CreateCheckpoint",
            True,
            f"Rollback recorded via '{checkpoint.rollback_method}'",
        )

        # --- ExecuteAction ----------------------------------------------
        action.execution_status = ExecutionStatus.EXECUTING
        action.started_at = datetime.now(timezone.utc)
        try:
            outcome = executor.execute(context)
        except (ExecutionFailure, Exception) as exc:  # noqa: BLE001
            action.execution_status = ExecutionStatus.FAILED
            action.error = str(exc)
            action.completed_at = datetime.now(timezone.utc)
            state("ExecuteAction", False, f"Execution failed: {exc}")
            # The mutation may have partially applied, so attempt rollback.
            return self._rollback(
                result, executor, context, checkpoint, state, cause=str(exc)
            )

        if outcome.artifacts:
            checkpoint.artifacts.update(outcome.artifacts)
        state("ExecuteAction", True, outcome.detail)

        # --- Settle -------------------------------------------------------
        wait = settle_seconds if settle_seconds is not None else (0 if dry_run else 30)
        if wait:
            time.sleep(wait)
        state("Settle", True, f"Waited {wait}s before verifying")

        # --- VerifyHealth --------------------------------------------------
        checks = []
        try:
            checks.extend(executor.verify(context))
            checks.extend(
                self.verifier.verify_health(resource, baseline, action.started_at)
            )
        except Exception as exc:  # noqa: BLE001
            # A verification that could not run is not a verification that
            # passed. Treat the error as a failed check so the rollback path
            # engages rather than silently declaring success.
            checks.append(
                executor.failed("verification", f"Verification errored: {exc}")
            )
        action.verifications = checks
        ok, summary = summarize(checks)
        state("VerifyHealth", ok, summary)

        if not ok:
            return self._rollback(
                result, executor, context, checkpoint, state, cause=summary
            )

        # --- RecordSavings ---------------------------------------------------
        if recommendation and recommendation.simulation:
            action.realized_monthly_savings = recommendation.simulation.monthly_savings
            cost_check = self.verifier.verify_cost(
                action, resource, recommendation.simulation.projected_monthly_cost
            )
            action.verifications.append(cost_check)
            state("RecordSavings", True, cost_check.detail)
        else:
            state("RecordSavings", True, "No simulation attached; no saving recorded")

        action.execution_status = ExecutionStatus.COMPLETED
        action.completed_at = datetime.now(timezone.utc)

        result.audit.append(
            AuditLog(
                action_id=action.action_id,
                resource_id=action.resource_id,
                account_id=action.account_id,
                actor=action.approved_by or action.requested_by,
                agent_id=action.agent_id,
                event="action.completed",
                outcome="SUCCESS",
                risk=action.risk,
                approved=(
                    action.approval_status is ApprovalStatus.APPROVED
                    if action.approval_required
                    else None
                ),
                detail={
                    "action_type": action.action_type.value,
                    "dry_run": dry_run,
                    "duration_seconds": round(
                        (datetime.now(timezone.utc) - started).total_seconds(), 1
                    ),
                    "realized_monthly_savings": action.realized_monthly_savings,
                    "verifications": [v.model_dump(mode="json") for v in checks],
                    "states": result.states,
                },
            )
        )
        result.message = (
            f"{'[DRY RUN] ' if dry_run else ''}{action.action_type.value} completed "
            f"on {action.resource_id}. {summary}"
        )
        state("Audit", True, "Audit record written")
        return result

    # ------------------------------------------------------------------

    def _rollback(
        self, result, executor, context, checkpoint, state, cause: str
    ) -> RemediationResult:
        action = result.action
        state("Rollback", True, f"Rolling back because: {cause}")

        try:
            outcome = executor.rollback(context, checkpoint)
        except Exception as exc:  # noqa: BLE001
            outcome = None
            rollback_error = str(exc)
        else:
            rollback_error = None if outcome.succeeded else outcome.detail

        if rollback_error:
            # The change failed AND the undo failed. This is the state that
            # needs a human immediately, and it must not be flattened into a
            # generic failure.
            action.execution_status = ExecutionStatus.ROLLBACK_FAILED
            action.error = (
                f"Action failed ({cause}) and rollback also failed "
                f"({rollback_error}). Manual intervention required."
            )
            action.completed_at = datetime.now(timezone.utc)
            state("VerifyRollback", False, action.error)
            result.audit.append(
                AuditLog(
                    action_id=action.action_id,
                    resource_id=action.resource_id,
                    account_id=action.account_id,
                    actor=action.approved_by or action.requested_by,
                    agent_id=action.agent_id,
                    event="action.rollback_failed",
                    outcome="ROLLBACK_FAILED",
                    risk=action.risk,
                    detail={
                        "action_type": action.action_type.value,
                        "cause": cause,
                        "rollback_error": rollback_error,
                        "checkpoint": checkpoint.model_dump(mode="json"),
                        "escalation": (
                            "The resource may be in an intermediate state. The "
                            "checkpoint above records what it looked like before "
                            "the action began."
                        ),
                        "states": result.states,
                    },
                )
            )
            result.message = action.error
            return result

        action.execution_status = ExecutionStatus.ROLLED_BACK
        action.completed_at = datetime.now(timezone.utc)
        action.error = cause
        state("VerifyRollback", True, outcome.detail)
        result.audit.append(
            AuditLog(
                action_id=action.action_id,
                resource_id=action.resource_id,
                account_id=action.account_id,
                actor=action.approved_by or action.requested_by,
                agent_id=action.agent_id,
                event="action.rolled_back",
                outcome="ROLLED_BACK",
                risk=action.risk,
                detail={
                    "action_type": action.action_type.value,
                    "cause": cause,
                    "rollback_detail": outcome.detail,
                    "states": result.states,
                },
            )
        )
        result.message = (
            f"{action.action_type.value} on {action.resource_id} was rolled back: "
            f"{cause}"
        )
        return result

    def _abort(self, result, state_name, reason, state, detail: dict | None = None):
        action = result.action
        action.execution_status = ExecutionStatus.FAILED
        action.error = reason
        action.completed_at = datetime.now(timezone.utc)
        state(state_name, False, reason)
        result.audit.append(
            AuditLog(
                action_id=action.action_id,
                resource_id=action.resource_id,
                account_id=action.account_id,
                actor=action.requested_by,
                agent_id=action.agent_id,
                event=f"action.aborted.{state_name.lower()}",
                outcome="ABORTED",
                risk=action.risk,
                detail={
                    "action_type": action.action_type.value,
                    "reason": reason,
                    **(detail or {}),
                    "states": result.states,
                },
            )
        )
        result.message = f"Aborted at {state_name}: {reason}"
        return result

    # ------------------------------------------------------------------

    def rollback_completed_action(
        self, action: Action, resource: Resource
    ) -> RemediationResult:
        """Operator-initiated rollback of an action that already succeeded."""
        result = RemediationResult(action=action)

        def state(name, ok, detail):
            result.states.append({"state": name, "ok": ok, "detail": detail})

        if action.checkpoint is None:
            return self._abort(
                result, "ValidateRollback", "No checkpoint was recorded for this action", state
            )
        if action.execution_status is not ExecutionStatus.COMPLETED:
            return self._abort(
                result,
                "ValidateRollback",
                f"Action is {action.execution_status.value}; only COMPLETED "
                f"actions can be rolled back on request",
                state,
            )

        executor = get_executor(action.action_type)
        context = ExecutionContext(
            action=action,
            resource=resource,
            dry_run=action.dry_run or self.settings.dry_run_default,
            client_factory=self.client_factory,
            settings=self.settings,
        )
        return self._rollback(
            result,
            executor,
            context,
            action.checkpoint,
            state,
            cause="Rollback requested by operator",
        )
