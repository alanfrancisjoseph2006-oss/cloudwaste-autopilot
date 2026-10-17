"""Savings reconciliation: estimated saving against observed billing.

After an action executes, its saving is an *estimate* until Cost Explorer
shows the resource's bill actually fell. This module decides, from observed
cost figures handed to it, which state the saving is in. It does no I/O.

The rules, in the order they are applied:

  1. Nothing that did not change AWS has a saving to verify: dry runs, failed
     and rolled-back actions are NOT_APPLICABLE.
  2. Billing lags by up to a day and a single day is noisy, so a saving is not
     judged until `min_billing_days` full days of post-change billing exist.
     Before that it is EXECUTED_PENDING_BILLING (under a day) or
     VERIFICATION_PENDING.
  3. If resource-level billing is unavailable the saving cannot be attributed
     to this resource at all: UNVERIFIABLE. The account-level bill may well
     have fallen, but claiming that fall for this action would be asserting a
     causality the data cannot establish.
  4. Otherwise the observed saving (baseline minus post-change cost) is
     compared with the estimate: VERIFIED, PARTIALLY_VERIFIED or NO_SAVINGS.

Both numbers are always kept. An action estimated at $210 and observed at $196
reports both and a variance of -$14; it does not quietly become "$210 saved".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ..models.domain import Action
from ..models.enums import ActionType, ExecutionStatus, SavingsStatus

#: States the reconciler will look at again. Terminal states are left alone.
RECONCILABLE_STATES = frozenset(
    {
        SavingsStatus.EXECUTED_PENDING_BILLING,
        SavingsStatus.VERIFICATION_PENDING,
        SavingsStatus.VERIFICATION_FAILED,
    }
)

#: Actions after which the resource no longer exists, so "no billing rows" can
#: mean "no charges" -- but only when rows demonstrably existed beforehand.
_REMOVES_RESOURCE = frozenset({ActionType.DELETE_EBS, ActionType.RELEASE_ELASTIC_IP})

CAUSALITY_NOTE = (
    "Attributed from this resource's own Cost Explorer line item. Any other "
    "change to the same resource in the window would also appear here."
)


@dataclass(slots=True)
class ReconciliationPolicy:
    min_billing_days: int = 3
    verified_ratio: float = 0.85
    no_savings_ratio: float = 0.10

    @classmethod
    def from_settings(cls, settings) -> "ReconciliationPolicy":
        return cls(
            min_billing_days=settings.savings_min_billing_days,
            verified_ratio=settings.savings_verified_ratio,
            no_savings_ratio=settings.savings_no_savings_ratio,
        )


@dataclass(slots=True)
class ReconciliationOutcome:
    status: SavingsStatus
    detail: str
    estimated_monthly_savings: float | None = None
    baseline_monthly_cost: float | None = None
    baseline_source: str | None = None
    observed_monthly_cost_after: float | None = None
    verified_monthly_savings: float | None = None
    variance: float | None = None
    billing_days_observed: int = 0

    def as_dict(self) -> dict:
        return {
            "status": self.status.value,
            "detail": self.detail,
            "estimated_monthly_savings": self.estimated_monthly_savings,
            "baseline_monthly_cost": self.baseline_monthly_cost,
            "baseline_source": self.baseline_source,
            "observed_monthly_cost_after": self.observed_monthly_cost_after,
            "verified_monthly_savings": self.verified_monthly_savings,
            "variance": self.variance,
            "billing_days_observed": self.billing_days_observed,
        }


def _day_start(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def observation_window(
    action: Action, now: datetime, policy: ReconciliationPolicy | None = None
) -> tuple[datetime, datetime] | None:
    """Full UTC days of post-change billing, or None if there are too few.

    Starts at the first midnight after the change (the change day is part
    before, part after) and ends at today's midnight (today is incomplete).
    """
    policy = policy or ReconciliationPolicy()
    if action.completed_at is None:
        return None
    start = _day_start(action.completed_at) + timedelta(days=1)
    end = _day_start(now)
    if (end - start).days < policy.min_billing_days:
        return None
    return start, end


def baseline_window(action: Action) -> tuple[datetime, datetime] | None:
    """The seven full days before the change, for an observed baseline."""
    if action.completed_at is None:
        return None
    end = _day_start(action.completed_at)
    return end - timedelta(days=7), end


def reconcile(
    action: Action,
    observed_after: float | None,
    now: datetime,
    *,
    observed_before: float | None = None,
    error: str | None = None,
    policy: ReconciliationPolicy | None = None,
) -> ReconciliationOutcome:
    policy = policy or ReconciliationPolicy()
    estimated = action.estimated_monthly_savings

    if action.dry_run or action.execution_status is not ExecutionStatus.COMPLETED:
        return ReconciliationOutcome(
            SavingsStatus.NOT_APPLICABLE,
            "The action did not change AWS (dry run, failed or rolled back), so "
            "there is no saving to verify.",
            estimated_monthly_savings=estimated,
        )
    if estimated is None or estimated <= 0:
        return ReconciliationOutcome(
            SavingsStatus.NOT_APPLICABLE,
            "This action was not expected to reduce cost, so there is no saving to verify.",
            estimated_monthly_savings=estimated,
        )

    window = observation_window(action, now, policy)
    if window is None:
        hours = (now - action.completed_at).total_seconds() / 3600 if action.completed_at else 0
        status = (
            SavingsStatus.EXECUTED_PENDING_BILLING
            if hours < 24
            else SavingsStatus.VERIFICATION_PENDING
        )
        return ReconciliationOutcome(
            status,
            f"Pending billing verification: {policy.min_billing_days} full days of "
            f"post-change billing are needed and AWS billing lags by up to 24 hours.",
            estimated_monthly_savings=estimated,
        )
    days = (window[1] - window[0]).days

    if error is not None:
        return ReconciliationOutcome(
            SavingsStatus.VERIFICATION_FAILED,
            f"Billing could not be read ({error}). The saving remains an estimate "
            f"and will be checked again.",
            estimated_monthly_savings=estimated,
            billing_days_observed=days,
        )

    if observed_after is None and action.action_type in _REMOVES_RESOURCE:
        if observed_before is not None:
            # Resource-level billing demonstrably works on this account (it has
            # rows for this resource before the change) and has none after:
            # the resource stopped billing.
            observed_after = 0.0

    if observed_after is None:
        return ReconciliationOutcome(
            SavingsStatus.UNVERIFIABLE,
            "Resource-level billing is not available for this resource, so the "
            "saving cannot be attributed to this action. The account-level bill "
            "is the only signal, and it cannot establish causality.",
            estimated_monthly_savings=estimated,
            billing_days_observed=days,
        )

    if observed_before is not None:
        baseline, baseline_source = observed_before, "cost_explorer_pre_change"
    elif action.baseline_monthly_cost is not None:
        baseline = action.baseline_monthly_cost
        baseline_source = action.baseline_cost_source or "simulation"
    else:
        return ReconciliationOutcome(
            SavingsStatus.UNVERIFIABLE,
            "No pre-change cost was recorded, so there is nothing to compare "
            "the observed bill against.",
            estimated_monthly_savings=estimated,
            observed_monthly_cost_after=observed_after,
            billing_days_observed=days,
        )

    actual = round(baseline - observed_after, 2)
    variance = round(actual - estimated, 2)
    ratio = actual / estimated

    if ratio >= policy.verified_ratio:
        status = SavingsStatus.VERIFIED
        verdict = "Observed saving matches the estimate"
    elif ratio < policy.no_savings_ratio:
        status = SavingsStatus.NO_SAVINGS
        verdict = "Billing shows no material reduction"
    else:
        status = SavingsStatus.PARTIALLY_VERIFIED
        verdict = "Observed saving is real but smaller than estimated"

    return ReconciliationOutcome(
        status,
        f"{verdict}: estimated ${estimated:,.2f}/month, observed ${actual:,.2f}/month "
        f"(variance {variance:+,.2f}) over {days} days of billing. {CAUSALITY_NOTE}",
        estimated_monthly_savings=estimated,
        baseline_monthly_cost=round(baseline, 2),
        baseline_source=baseline_source,
        observed_monthly_cost_after=round(observed_after, 2),
        verified_monthly_savings=actual,
        variance=variance,
        billing_days_observed=days,
    )


def apply(action: Action, outcome: ReconciliationOutcome, now: datetime) -> Action:
    """Write an outcome onto the action. Only proven savings become 'realized'."""
    action.savings_status = outcome.status
    action.savings_detail = outcome.detail
    action.savings_checked_at = now
    if outcome.observed_monthly_cost_after is not None:
        action.observed_monthly_cost_after = outcome.observed_monthly_cost_after
    if outcome.verified_monthly_savings is not None:
        action.verified_monthly_savings = outcome.verified_monthly_savings
        action.savings_variance = outcome.variance
        action.savings_verified_at = now
    if outcome.status in (SavingsStatus.VERIFIED, SavingsStatus.PARTIALLY_VERIFIED):
        action.realized_monthly_savings = outcome.verified_monthly_savings
    else:
        action.realized_monthly_savings = None
    return action
