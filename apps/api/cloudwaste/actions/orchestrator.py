"""Remediation orchestration.

This runs the state sequence that `infra/stepfunctions/remediation.asl.json`
defines. The two implementations share their phase logic: each state is a
method on `RemediationOrchestrator`, `run()` calls them in order in-process,
and `actions/step_functions.py` exposes the same methods as the Lambda tasks
the state machine invokes. Same order, same guards, same audit records, so
what you test locally is what runs.

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

RecordSavings records an *estimate*. A saving becomes verified only when the
reconciler later sees it in Cost Explorer; see intelligence/savings_reconciliation.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..config import Settings, get_settings
from ..models.domain import Action, AuditLog, Checkpoint, Recommendation, Resource
from ..models.enums import ApprovalStatus, ExecutionStatus, SavingsStatus
from .approval import ApprovalEngine
from .executors.base import (
    ExecutionContext,
    ExecutionFailure,
    ExecutionOutcome,
    Executor,
    PreflightFailure,
)
from .registry import NoExecutorError, get_executor
from .verification import SETTLE_SECONDS, HealthBaseline, VerificationEngine, summarize

logger = logging.getLogger(__name__)

#: The states both implementations must run, in order. The ASL definition is
#: checked against this list by the test suite.
STATE_SEQUENCE = (
    "ValidateAction",
    "ValidatePolicy",
    "Preflight",
    "CaptureBaseline",
    "CreateCheckpoint",
    "ExecuteAction",
    "Settle",
    "VerifyHealth",
    "RecordSavings",
    "Rollback",
    "VerifyRollback",
    "Audit",
)


class ValidationFailure(Exception):
    """The action cannot run: no executor, or it targets the wrong resource."""


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

    # ==================================================================
    # Phases. Each is one state of the state machine.
    # ==================================================================

    def is_dry_run(self, action: Action) -> bool:
        return action.dry_run or self.settings.dry_run_default

    def context_for(self, action: Action, resource: Resource) -> ExecutionContext:
        return ExecutionContext(
            action=action,
            resource=resource,
            dry_run=self.is_dry_run(action),
            client_factory=self.client_factory,
            settings=self.settings,
        )

    def phase_validate_action(self, action: Action, resource: Resource) -> Executor:
        try:
            executor = get_executor(action.action_type)
        except NoExecutorError as exc:
            raise ValidationFailure(str(exc)) from exc
        if (action.resource_id, action.account_id) != (resource.resource_id, resource.account_id):
            raise ValidationFailure(
                f"Action targets {action.account_id}/{action.resource_id} but was "
                f"given resource {resource.account_id}/{resource.resource_id}"
            )
        return executor

    def phase_validate_policy(self, action: Action) -> tuple[bool, str]:
        return self.approvals.can_execute(action)

    def phase_preflight(self, executor: Executor, context: ExecutionContext) -> str:
        """Re-read live AWS. Raises PreflightFailure if the world changed."""
        if context.dry_run:
            return "Skipped in dry run (no live AWS state to check)"
        executor.preflight(context)
        return "Live state still matches the plan" + (
            f"; {'; '.join(context.notes)}" if context.notes else ""
        )

    def phase_capture_baseline(self, resource: Resource) -> HealthBaseline:
        return self.verifier.capture_baseline(resource)

    def phase_create_checkpoint(
        self, executor: Executor, context: ExecutionContext, baseline: HealthBaseline
    ) -> Checkpoint:
        checkpoint = executor.capture(context)
        checkpoint.rollback_data["health_baseline"] = baseline.to_dict()
        context.action.checkpoint = checkpoint
        return checkpoint

    def phase_execute(self, executor: Executor, context: ExecutionContext) -> ExecutionOutcome:
        action = context.action
        action.execution_status = ExecutionStatus.EXECUTING
        action.started_at = datetime.now(timezone.utc)
        outcome = executor.execute(context)
        if outcome.artifacts and action.checkpoint is not None:
            action.checkpoint.artifacts.update(outcome.artifacts)
        return outcome

    def settle_seconds_for(self, action: Action, resource: Resource, override: int | None = None) -> int:
        if override is not None:
            return override
        if self.is_dry_run(action):
            return 0
        return SETTLE_SECONDS.get(resource.resource_type, 30)

    def phase_verify(
        self,
        executor: Executor,
        context: ExecutionContext,
        resource: Resource,
        baseline: HealthBaseline,
    ) -> tuple[bool, str]:
        action = context.action
        checks = []
        try:
            checks.extend(executor.verify(context))
            checks.extend(self.verifier.verify_health(resource, baseline, action.started_at))
        except Exception as exc:  # noqa: BLE001
            # A verification that could not run is not a verification that
            # passed. Treat the error as a failed check so the rollback path
            # engages rather than silently declaring success.
            checks.append(executor.failed("verification", f"Verification errored: {exc}"))
        action.verifications = checks
        return summarize(checks)

    def phase_record_savings(
        self,
        action: Action,
        resource: Resource,
        recommendation: Recommendation | None,
    ) -> str:
        """Record the *estimated* saving and mark the action COMPLETED.

        Nothing here claims the saving happened. A dry run changed nothing and
        has no saving; a real change waits for billing reconciliation.
        """
        dry_run = self.is_dry_run(action)
        if recommendation and recommendation.simulation:
            simulation = recommendation.simulation
            action.estimated_monthly_savings = simulation.monthly_savings
            action.baseline_monthly_cost = simulation.current_monthly_cost
            action.baseline_cost_source = simulation.priced_from
            action.projected_monthly_cost = simulation.projected_monthly_cost
            action.realized_monthly_savings = None
            if dry_run:
                action.savings_status = SavingsStatus.NOT_APPLICABLE
                action.savings_detail = (
                    "Dry run: AWS was not changed, so there is no saving to verify."
                )
            elif simulation.monthly_savings <= 0:
                action.savings_status = SavingsStatus.NOT_APPLICABLE
                action.savings_detail = "This action was not expected to reduce cost."
            else:
                action.savings_status = SavingsStatus.EXECUTED_PENDING_BILLING
                action.savings_detail = (
                    f"Estimated ${simulation.monthly_savings:,.2f}/month, pending "
                    f"billing verification. AWS billing lags by up to 24 hours; the "
                    f"reconciler compares observed cost once enough days exist."
                )
            cost_check = self.verifier.verify_cost(
                action, resource, simulation.projected_monthly_cost
            )
            action.verifications.append(cost_check)
            detail = f"{action.savings_detail} {cost_check.detail}"
        else:
            action.savings_status = SavingsStatus.NOT_APPLICABLE
            action.savings_detail = "No simulation attached; no saving recorded."
            detail = action.savings_detail

        action.execution_status = ExecutionStatus.COMPLETED
        action.completed_at = datetime.now(timezone.utc)
        return detail

    def phase_rollback(
        self,
        executor: Executor,
        context: ExecutionContext,
        checkpoint: Checkpoint,
        cause: str,
    ) -> tuple[bool, str]:
        """Restore the checkpoint. Returns (succeeded, detail); never raises."""
        action = context.action
        try:
            outcome = executor.rollback(context, checkpoint)
        except Exception as exc:  # noqa: BLE001
            rollback_error = str(exc)
        else:
            rollback_error = None if outcome.succeeded else outcome.detail

        action.completed_at = datetime.now(timezone.utc)
        action.savings_status = SavingsStatus.NOT_APPLICABLE
        action.realized_monthly_savings = None
        if rollback_error:
            # The change failed AND the undo failed. This is the state that
            # needs a human immediately, and it must not be flattened into a
            # generic failure.
            action.execution_status = ExecutionStatus.ROLLBACK_FAILED
            action.error = (
                f"Action failed ({cause}) and rollback also failed "
                f"({rollback_error}). Manual intervention required."
            )
            action.savings_detail = "Rollback failed; the resource may be in an intermediate state."
            return False, rollback_error

        action.execution_status = ExecutionStatus.ROLLED_BACK
        action.error = cause
        action.savings_detail = "Rolled back; the change was undone, so there is no saving."
        return True, outcome.detail

    # --- audit records ------------------------------------------------------

    def completion_audit(self, action: Action, states: list[dict], duration: float) -> AuditLog:
        return AuditLog(
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
                "dry_run": self.is_dry_run(action),
                "duration_seconds": round(duration, 1),
                "estimated_monthly_savings": action.estimated_monthly_savings,
                "savings_status": action.savings_status.value,
                "verifications": [v.model_dump(mode="json") for v in action.verifications],
                "states": states,
            },
        )

    def rollback_audit(
        self,
        action: Action,
        succeeded: bool,
        cause: str,
        detail: str,
        checkpoint: Checkpoint,
        states: list[dict],
    ) -> AuditLog:
        if not succeeded:
            return AuditLog(
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
                    "rollback_error": detail,
                    "checkpoint": checkpoint.model_dump(mode="json"),
                    "escalation": (
                        "The resource may be in an intermediate state. The "
                        "checkpoint above records what it looked like before "
                        "the action began."
                    ),
                    "states": states,
                },
            )
        return AuditLog(
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
                "rollback_detail": detail,
                "states": states,
            },
        )

    def abort_audit(
        self, action: Action, state_name: str, reason: str, states: list[dict], detail: dict | None = None
    ) -> AuditLog:
        return AuditLog(
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
                "states": states,
            },
        )

    def mark_aborted(self, action: Action, reason: str) -> None:
        action.execution_status = ExecutionStatus.FAILED
        action.error = reason
        action.completed_at = datetime.now(timezone.utc)
        action.savings_status = SavingsStatus.NOT_APPLICABLE

    # ==================================================================
    # In-process run: the phases above, in state-machine order
    # ==================================================================

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
            executor = self.phase_validate_action(action, resource)
        except ValidationFailure as exc:
            return self._abort(result, "ValidateAction", str(exc), state)
        state("ValidateAction", True, f"Executor found for {action.action_type.value}")

        # --- ValidatePolicy / approval --------------------------------
        allowed, reason = self.phase_validate_policy(action)
        if not allowed:
            return self._abort(result, "ValidatePolicy", reason, state)
        state("ValidatePolicy", True, reason)

        context = self.context_for(action, resource)
        if context.dry_run:
            state(
                "DryRunNotice",
                True,
                "Running in dry-run mode: every phase executes except the AWS "
                "mutation itself.",
            )

        # --- Preflight -------------------------------------------------
        try:
            detail = self.phase_preflight(executor, context)
        except PreflightFailure as exc:
            return self._abort(
                result, "Preflight", f"Refused: {exc}", state, detail={"phase": "preflight"}
            )
        except Exception as exc:  # noqa: BLE001
            return self._abort(result, "Preflight", f"Preflight check errored: {exc}", state)
        state("Preflight", True, detail)

        # --- CaptureBaseline -------------------------------------------
        baseline = self.phase_capture_baseline(resource)
        state("CaptureBaseline", True, f"Health baseline captured: {baseline.to_dict()}")

        # --- CreateCheckpoint ------------------------------------------
        try:
            checkpoint = self.phase_create_checkpoint(executor, context, baseline)
        except Exception as exc:  # noqa: BLE001
            return self._abort(
                result, "CreateCheckpoint", f"Could not capture rollback state: {exc}", state
            )
        state("CreateCheckpoint", True, f"Rollback recorded via '{checkpoint.rollback_method}'")

        # --- ExecuteAction ----------------------------------------------
        try:
            outcome = self.phase_execute(executor, context)
        except (ExecutionFailure, Exception) as exc:  # noqa: BLE001
            action.execution_status = ExecutionStatus.FAILED
            action.error = str(exc)
            action.completed_at = datetime.now(timezone.utc)
            state("ExecuteAction", False, f"Execution failed: {exc}")
            # The mutation may have partially applied, so attempt rollback.
            return self._rollback(result, executor, context, checkpoint, state, cause=str(exc))
        state("ExecuteAction", True, outcome.detail)

        # --- Settle -------------------------------------------------------
        wait = settle_seconds if settle_seconds is not None else (0 if context.dry_run else 30)
        if wait:
            time.sleep(wait)
        state("Settle", True, f"Waited {wait}s before verifying")

        # --- VerifyHealth --------------------------------------------------
        ok, summary = self.phase_verify(executor, context, resource, baseline)
        state("VerifyHealth", ok, summary)
        if not ok:
            return self._rollback(result, executor, context, checkpoint, state, cause=summary)

        # --- RecordSavings ---------------------------------------------------
        state("RecordSavings", True, self.phase_record_savings(action, resource, recommendation))

        result.audit.append(
            self.completion_audit(
                action, result.states, (datetime.now(timezone.utc) - started).total_seconds()
            )
        )
        result.message = (
            f"{'[DRY RUN] ' if context.dry_run else ''}{action.action_type.value} completed "
            f"on {action.resource_id}. {summary}"
        )
        state("Audit", True, "Audit record written")
        return result

    # ------------------------------------------------------------------

    def _rollback(self, result, executor, context, checkpoint, state, cause: str) -> RemediationResult:
        action = result.action
        state("Rollback", True, f"Rolling back because: {cause}")
        succeeded, detail = self.phase_rollback(executor, context, checkpoint, cause)
        if not succeeded:
            state("VerifyRollback", False, action.error)
            result.message = action.error
        else:
            state("VerifyRollback", True, detail)
            result.message = (
                f"{action.action_type.value} on {action.resource_id} was rolled back: {cause}"
            )
        result.audit.append(
            self.rollback_audit(action, succeeded, cause, detail, checkpoint, result.states)
        )
        return result

    def _abort(self, result, state_name, reason, state, detail: dict | None = None):
        action = result.action
        self.mark_aborted(action, reason)
        state(state_name, False, reason)
        result.audit.append(self.abort_audit(action, state_name, reason, result.states, detail))
        result.message = f"Aborted at {state_name}: {reason}"
        return result

    # ------------------------------------------------------------------

    def rollback_completed_action(self, action: Action, resource: Resource) -> RemediationResult:
        """Operator-initiated rollback of an action that already succeeded."""
        result = RemediationResult(action=action)

        def state(name, ok, detail):
            result.states.append({"state": name, "ok": ok, "detail": detail})

        refusal = None
        if action.checkpoint is None:
            refusal = "No checkpoint was recorded for this action"
        elif action.execution_status is not ExecutionStatus.COMPLETED:
            refusal = (
                f"Action is {action.execution_status.value}; only COMPLETED "
                f"actions can be rolled back on request"
            )
        elif (action.resource_id, action.account_id) != (
            resource.resource_id,
            resource.account_id,
        ):
            refusal = (
                f"Action targets {action.account_id}/{action.resource_id} but was "
                f"given resource {resource.account_id}/{resource.resource_id}"
            )
        if refusal:
            # Refusing a rollback changes nothing, so the action keeps its
            # status: a COMPLETED action is still completed.
            state("ValidateRollback", False, refusal)
            result.audit.append(
                self.abort_audit(action, "ValidateRollback", refusal, result.states)
            )
            result.message = f"Rollback refused: {refusal}"
            return result

        executor = get_executor(action.action_type)
        return self._rollback(
            result,
            executor,
            self.context_for(action, resource),
            action.checkpoint,
            state,
            cause="Rollback requested by operator",
        )
