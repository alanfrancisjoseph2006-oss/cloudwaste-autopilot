"""Approval lifecycle.

An approval is a human taking responsibility for a specific action on a
specific resource at a specific moment. Three properties make that meaningful
rather than ceremonial:

  * **Approvals expire.** A yes given three weeks ago was given about an
    account that no longer exists in that form.
  * **Approvals are bound to the plan.** If the recommendation changes -- a
    different target size, a larger saving, a higher risk -- the approval no
    longer covers it and must be sought again. This is enforced by fingerprint,
    not by trust.
  * **Self-approval is recorded.** The system does not forbid it (small teams
    exist) but it is marked in the audit trail.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone

from ..config import Settings, get_settings
from ..models.domain import Action, AuditLog, Recommendation
from ..models.enums import ApprovalStatus, ExecutionStatus, PolicyDecision

logger = logging.getLogger(__name__)


class ApprovalError(Exception):
    """The approval state does not permit what was asked."""


def plan_fingerprint(recommendation: Recommendation) -> str:
    """Stable hash of the parts of a plan a human would care about.

    Deliberately excludes ids and timestamps, and includes anything that
    changes what actually happens or what it is worth.
    """
    material = {
        "resource_id": recommendation.resource_id,
        "action_type": recommendation.action_type.value,
        "current": recommendation.current_configuration,
        "recommended": recommendation.recommended_configuration,
        "parameters": {
            k: v
            for k, v in sorted(recommendation.action_parameters.items())
            if k != "depends_on"
        },
        "risk": recommendation.risk.value,
        # Rounded: a few cents of drift between scans should not invalidate an
        # approval, but a materially different saving should.
        "monthly_savings": round(recommendation.monthly_savings, 0),
        "restart_required": recommendation.restart_required,
    }
    encoded = json.dumps(material, sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()[:16]


class ApprovalEngine:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    # ------------------------------------------------------------------

    def initialize(self, action: Action, evaluation) -> Action:
        """Set the approval state a fresh action starts in."""
        if evaluation.decision is PolicyDecision.DENY:
            action.approval_required = True
            action.approval_status = ApprovalStatus.REJECTED
            action.rejection_reason = "; ".join(evaluation.reasons)
            return action

        if evaluation.decision is PolicyDecision.AUTO_EXECUTE:
            action.approval_required = False
            action.approval_status = ApprovalStatus.NOT_REQUIRED
            return action

        ttl = evaluation.approval_ttl_hours or self.settings.approval_ttl_hours
        action.approval_required = True
        action.approval_status = ApprovalStatus.PENDING
        action.approval_expires_at = datetime.now(timezone.utc) + timedelta(hours=ttl)
        return action

    def approve(
        self,
        action: Action,
        approver: str,
        recommendation: Recommendation | None = None,
        note: str | None = None,
    ) -> tuple[Action, AuditLog]:
        self._require_pending(action)
        self._require_unexpired(action)

        if recommendation is not None:
            expected = action.parameters.get("_plan_fingerprint")
            actual = plan_fingerprint(recommendation)
            if expected and expected != actual:
                raise ApprovalError(
                    "The recommendation has changed since this approval was "
                    "requested (target, risk or savings differ). Approval must be "
                    "sought again for the current plan."
                )

        action.approval_status = ApprovalStatus.APPROVED
        action.approved_by = approver
        action.approved_at = datetime.now(timezone.utc)

        self_approved = approver == action.requested_by and approver != "system"
        audit = AuditLog(
            action_id=action.action_id,
            resource_id=action.resource_id,
            account_id=action.account_id,
            actor=approver,
            event="action.approved",
            risk=action.risk,
            approved=True,
            detail={
                "action_type": action.action_type.value,
                "requested_by": action.requested_by,
                "self_approved": self_approved,
                "note": note,
                "expires_at": (
                    action.approval_expires_at.isoformat()
                    if action.approval_expires_at
                    else None
                ),
            },
        )
        if self_approved:
            logger.warning(
                "action %s was approved by its requester (%s)", action.action_id, approver
            )
        return action, audit

    def reject(self, action: Action, approver: str, reason: str) -> tuple[Action, AuditLog]:
        self._require_pending(action)
        action.approval_status = ApprovalStatus.REJECTED
        action.approved_by = approver
        action.approved_at = datetime.now(timezone.utc)
        action.rejection_reason = reason
        return action, AuditLog(
            action_id=action.action_id,
            resource_id=action.resource_id,
            account_id=action.account_id,
            actor=approver,
            event="action.rejected",
            outcome="REJECTED",
            risk=action.risk,
            approved=False,
            detail={"action_type": action.action_type.value, "reason": reason},
        )

    def expire_if_due(self, action: Action) -> bool:
        """Mark a pending approval expired if its TTL has passed."""
        if action.approval_status is not ApprovalStatus.PENDING:
            return False
        if action.approval_expires_at is None:
            return False
        if datetime.now(timezone.utc) < action.approval_expires_at:
            return False
        action.approval_status = ApprovalStatus.EXPIRED
        logger.info("approval for action %s expired", action.action_id)
        return True

    def can_execute(self, action: Action) -> tuple[bool, str]:
        """The single gate the orchestrator consults before doing anything."""
        self.expire_if_due(action)

        if action.execution_status is not ExecutionStatus.NOT_STARTED:
            return False, (
                f"Action is already in state {action.execution_status.value}; "
                f"actions execute at most once."
            )
        if action.policy_decision is PolicyDecision.DENY:
            return False, f"Denied by policy: {action.rejection_reason or 'no reason recorded'}"

        if not action.approval_required:
            return True, "Action was authorized for unattended execution by policy."

        if action.approval_status is ApprovalStatus.APPROVED:
            return True, f"Approved by {action.approved_by}."
        if action.approval_status is ApprovalStatus.PENDING:
            return False, "Action is awaiting approval."
        if action.approval_status is ApprovalStatus.EXPIRED:
            return False, (
                "The approval window expired. The account may have changed since "
                "approval was given, so it must be requested again."
            )
        if action.approval_status is ApprovalStatus.REJECTED:
            return False, f"Rejected: {action.rejection_reason}"

        return False, f"Approval status is {action.approval_status.value}."

    # ------------------------------------------------------------------

    @staticmethod
    def _require_pending(action: Action) -> None:
        if action.approval_status is not ApprovalStatus.PENDING:
            raise ApprovalError(
                f"Action is {action.approval_status.value}, not PENDING, so it "
                f"cannot be approved or rejected."
            )

    @staticmethod
    def _require_unexpired(action: Action) -> None:
        if (
            action.approval_expires_at
            and datetime.now(timezone.utc) >= action.approval_expires_at
        ):
            action.approval_status = ApprovalStatus.EXPIRED
            raise ApprovalError(
                "The approval window for this action has expired. Re-scan and "
                "request approval against the current state of the account."
            )
