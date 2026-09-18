"""Executor contract.

An executor is the only code in CloudWaste permitted to call a mutating AWS
API. Every executor implements the same four-phase lifecycle, and the
orchestrator runs them in this order, always:

    capture()  -> record enough state to undo this
    preflight()-> re-check, against live AWS, that the action is still correct
    execute()  -> make the change
    verify()   -> confirm the change took and nothing broke
    rollback() -> only if verify failed

`preflight` is the phase that stops the class of incident this system could
otherwise cause. A recommendation is produced from a scan that may be hours
old. In between, someone may have attached the volume, tagged the instance
production, or started using the database. Preflight re-reads the live resource
and refuses if the world has changed. Without it, CloudWaste would be acting on
a memory of the account rather than the account.

Dry run is enforced here in the base class rather than in each executor, so a
new executor cannot forget to honour it.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ...models.domain import Action, Checkpoint, Resource, VerificationResult
from ...models.enums import ActionType

logger = logging.getLogger(__name__)


class PreflightFailure(Exception):
    """The world changed since the recommendation was produced."""


class ExecutionFailure(Exception):
    """The AWS call failed."""


@dataclass(slots=True)
class ExecutionContext:
    """What an executor is given. `clients` is a callable returning a boto3
    client, so the demo mode can supply a fake without the executor knowing."""

    action: Action
    resource: Resource
    dry_run: bool
    client_factory: Any = None
    settings: Any = None
    notes: list[str] = field(default_factory=list)

    def client(self, service: str):
        if self.client_factory is None:
            raise ExecutionFailure(
                f"No AWS client factory configured; cannot call {service}"
            )
        return self.client_factory(service, self.resource.region)


@dataclass(slots=True)
class ExecutionOutcome:
    succeeded: bool
    detail: str
    artifacts: dict[str, str] = field(default_factory=dict)
    dry_run: bool = False


class Executor(ABC):
    """Base class for every action executor."""

    action_type: ActionType
    #: Human-readable description of what rollback does, shown to approvers.
    rollback_description: str = "No rollback available."

    # --- phases ---------------------------------------------------------

    @abstractmethod
    def capture(self, context: ExecutionContext) -> Checkpoint:
        """Record the state needed to undo this action."""

    @abstractmethod
    def preflight(self, context: ExecutionContext) -> None:
        """Re-validate against live AWS. Raise PreflightFailure to abort."""

    @abstractmethod
    def _apply(self, context: ExecutionContext) -> ExecutionOutcome:
        """Perform the mutation. Only called when not in dry run."""

    @abstractmethod
    def verify(self, context: ExecutionContext) -> list[VerificationResult]:
        """Confirm the change took effect and the resource is healthy."""

    @abstractmethod
    def rollback(self, context: ExecutionContext, checkpoint: Checkpoint) -> ExecutionOutcome:
        """Restore the captured state."""

    # --- orchestration entry point ---------------------------------------

    def execute(self, context: ExecutionContext) -> ExecutionOutcome:
        """Run the mutation, honouring dry run.

        Dry run is checked here, once, so no executor can accidentally mutate
        while the deployment believes it is in a safe mode.
        """
        if context.dry_run:
            return ExecutionOutcome(
                succeeded=True,
                detail=(
                    f"DRY RUN: would {self.describe(context)}. No AWS call was made."
                ),
                dry_run=True,
            )
        logger.info(
            "executing %s on %s", self.action_type.value, context.resource.resource_id
        )
        return self._apply(context)

    def describe(self, context: ExecutionContext) -> str:
        """One line describing the intended change, used in dry-run output."""
        return (
            f"{self.action_type.value} on {context.resource.resource_id} "
            f"with {context.action.parameters}"
        )

    # --- helpers ----------------------------------------------------------

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def passed(check: str, detail: str) -> VerificationResult:
        return VerificationResult(check=check, passed=True, detail=detail)

    @staticmethod
    def failed(check: str, detail: str) -> VerificationResult:
        return VerificationResult(check=check, passed=False, detail=detail)

    def _guard_tags_unchanged(self, context: ExecutionContext, live_tags: dict[str, str]) -> None:
        """Refuse if the resource has been re-tagged into a protected state.

        Someone tagging a resource `Environment=production` between the scan
        and the execution is telling us something, and it is the one signal we
        must honour even mid-flight.
        """
        from ...adapters import tags as tagging

        live = tagging.classify(live_tags, context.resource.name)
        if live["auto_remediation_allowed"] is False:
            raise PreflightFailure(
                "Resource is now tagged AutoRemediation=false, which is an "
                "explicit owner opt-out. Aborting."
            )
        original_env = context.resource.environment
        if live["environment"] != original_env and live["environment"].value == "production":
            raise PreflightFailure(
                f"Resource has been re-tagged from {original_env.value} to "
                f"production since this action was planned. Aborting."
            )
