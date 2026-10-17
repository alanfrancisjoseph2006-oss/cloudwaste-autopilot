"""Optimization planning: choose recommendations that approach a savings goal.

Pure. The service hands in candidates that have already been through the risk
engine and a read-only policy evaluation; this module ranks and selects them.
It produces a plan document and nothing else. A plan cannot authorize,
approve or execute anything: proposing one creates ordinary actions through
`CloudWasteService.create_action`, each of which is policy-checked and
approval-gated like any other.

Ranking, documented because an operator will ask why item 3 beat item 4:

    value = monthly_savings x (confidence / 100) x risk_weight x reversibility

    risk_weight    LOW 1.0, MEDIUM 0.75, HIGH 0.4, CRITICAL 0 (never selected)
    reversibility  1.0 when every step has a rollback path, 0.8 otherwise

So a certain, reversible, low-risk $150 outranks a speculative high-risk $300.
Candidates are taken in value order until the target is met, then any item
whose removal still leaves the target met is dropped, lowest value first, so
the plan does not carry risk it does not need.

Exclusions are reported with their reason, never dropped silently:
policy denials, risk above the plan's ceiling, confidence below its floor,
non-positive savings, and a second opportunity on a resource that already has
one selected (two changes to one resource would double-count its savings).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..models.domain import Finding, PlanExclusion, PlanItem, Recommendation
from ..models.enums import PolicyDecision, RiskLevel
from .dashboard import SERVICE_LABELS

RISK_WEIGHT = {
    RiskLevel.LOW: 1.0,
    RiskLevel.MEDIUM: 0.75,
    RiskLevel.HIGH: 0.4,
    RiskLevel.CRITICAL: 0.0,
}
IRREVERSIBLE_FACTOR = 0.8

RANKING_METHOD = (
    "value = monthly savings x confidence x risk weight (LOW 1.0, MEDIUM 0.75, "
    "HIGH 0.4, CRITICAL 0) x reversibility (1.0, or 0.8 if any step cannot be "
    "rolled back). Highest value first until the target is met; surplus items "
    "removed lowest value first."
)

_DECISION_ORDER = {
    PolicyDecision.AUTO_EXECUTE: 0,
    PolicyDecision.REQUIRE_APPROVAL: 1,
    PolicyDecision.DENY: 2,
}


@dataclass(slots=True)
class Candidate:
    """One opportunity: a finding's recommendation chain, already assessed."""

    finding: Finding
    recommendations: list[Recommendation]
    risk: RiskLevel
    decision: PolicyDecision
    policy_reasons: list[str] = field(default_factory=list)

    @property
    def savings(self) -> float:
        return round(sum(r.monthly_savings for r in self.recommendations), 2)

    @property
    def confidence(self) -> float:
        return min(r.confidence for r in self.recommendations)

    @property
    def rollback_possible(self) -> bool:
        return all(r.rollback_possible for r in self.recommendations)

    @property
    def downtime(self) -> int:
        return sum(
            r.simulation.downtime_estimate_seconds if r.simulation else 0
            for r in self.recommendations
        )

    @property
    def value(self) -> float:
        factor = 1.0 if self.rollback_possible else IRREVERSIBLE_FACTOR
        return round(self.savings * self.confidence / 100.0 * RISK_WEIGHT[self.risk] * factor, 4)


def worst_decision(decisions: list[PolicyDecision]) -> PolicyDecision:
    return max(decisions, key=lambda d: _DECISION_ORDER[d])


def parse_goal(text: str) -> tuple[str, float] | None:
    """Read "save $1,000/month" or "reduce spend by 20%" into (type, value).

    Returns None when the text names no amount; the caller then asks rather
    than guessing a target.
    """
    cleaned = text.replace(",", "")
    percent = re.search(r"(\d+(?:\.\d+)?)\s*(%|percent)", cleaned, re.IGNORECASE)
    if percent:
        return "percent", float(percent.group(1))
    amount = re.search(r"\$\s*(\d+(?:\.\d+)?)\s*(k)?", cleaned, re.IGNORECASE)
    if not amount:
        amount = re.search(
            r"(\d+(?:\.\d+)?)\s*(k)?\s*(?:usd|dollars|/\s*mo|per month|a month|/month)",
            cleaned,
            re.IGNORECASE,
        )
    if amount:
        value = float(amount.group(1)) * (1000 if amount.group(2) else 1)
        return "amount", value
    return None


def plan(
    candidates: list[Candidate],
    *,
    target_monthly_savings: float,
    max_risk: RiskLevel = RiskLevel.HIGH,
    min_confidence: float = 0.0,
) -> dict:
    """Select candidates toward the target. Returns fields for OptimizationPlan."""
    excluded: list[PlanExclusion] = []
    eligible: list[Candidate] = []

    def exclude(candidate: Candidate, reason: str) -> None:
        excluded.append(
            PlanExclusion(
                recommendation_ids=[r.recommendation_id for r in candidate.recommendations],
                resource_id=candidate.finding.resource_id,
                monthly_savings=candidate.savings,
                reason=reason,
            )
        )

    for candidate in candidates:
        if candidate.decision is PolicyDecision.DENY:
            exclude(
                candidate,
                "Denied by policy: " + ("; ".join(candidate.policy_reasons) or "no reason recorded"),
            )
        elif candidate.risk is RiskLevel.CRITICAL:
            exclude(candidate, "CRITICAL risk is never included in a plan.")
        elif candidate.risk.rank > max_risk.rank:
            exclude(
                candidate,
                f"{candidate.risk.value.upper()} risk exceeds this plan's "
                f"{max_risk.value.upper()} ceiling.",
            )
        elif candidate.confidence < min_confidence:
            exclude(
                candidate,
                f"Confidence {candidate.confidence:.0f}% is below this plan's "
                f"{min_confidence:.0f}% floor.",
            )
        elif candidate.savings <= 0:
            exclude(candidate, "No positive saving.")
        else:
            eligible.append(candidate)

    # One opportunity per resource: two changes to the same resource would
    # count the same dollars twice.
    best_by_resource: dict[tuple[str, str], Candidate] = {}
    for candidate in sorted(eligible, key=lambda c: c.value, reverse=True):
        key = (candidate.finding.region, candidate.finding.resource_id)
        if key in best_by_resource:
            exclude(
                candidate,
                "Another opportunity on the same resource ranked higher; both would "
                "double-count its cost.",
            )
        else:
            best_by_resource[key] = candidate
    ranked = sorted(best_by_resource.values(), key=lambda c: c.value, reverse=True)

    selected: list[Candidate] = []
    total = 0.0
    for candidate in ranked:
        if total >= target_monthly_savings:
            break
        selected.append(candidate)
        total += candidate.savings

    # Drop surplus: anything whose removal still meets the target, lowest
    # value first.
    if total >= target_monthly_savings:
        for candidate in sorted(selected, key=lambda c: c.value):
            if total - candidate.savings >= target_monthly_savings:
                selected.remove(candidate)
                total -= candidate.savings

    unused = [c for c in ranked if c not in selected]
    for candidate in unused:
        exclude(candidate, "Not needed: the target is met without it.")

    items: list[PlanItem] = []
    for position, candidate in enumerate(
        sorted(selected, key=lambda c: c.value, reverse=True), start=1
    ):
        recs = candidate.recommendations
        first = recs[0]
        service = SERVICE_LABELS.get(first.resource_type.value, first.resource_type.value)
        steps = " then ".join(r.action_type.value for r in recs)
        reason = (
            f"Ranked #{position} of {len(ranked)} eligible by risk-adjusted value "
            f"({candidate.value:,.2f}): {steps} saves ${candidate.savings:,.2f}/month "
            f"at {candidate.confidence:.0f}% confidence, {candidate.risk.value.upper()} risk, "
            + ("reversible" if candidate.rollback_possible else "NOT reversible")
            + f". Policy: {candidate.decision.value.replace('_', ' ').lower()}."
        )
        items.append(
            PlanItem(
                recommendation_ids=[r.recommendation_id for r in recs],
                finding_id=candidate.finding.finding_id,
                resource_id=candidate.finding.resource_id,
                resource_type=first.resource_type,
                region=first.region,
                action_types=[r.action_type for r in recs],
                title=candidate.finding.title,
                service=service,
                monthly_savings=candidate.savings,
                risk=candidate.risk,
                confidence=candidate.confidence,
                rollback_possible=candidate.rollback_possible,
                downtime_seconds=candidate.downtime,
                policy_decision=candidate.decision,
                policy_reasons=candidate.policy_reasons,
                rank_score=candidate.value,
                reason=reason,
            )
        )

    total = round(sum(i.monthly_savings for i in items), 2)
    risk_summary: dict[str, int] = {}
    by_service: dict[str, float] = {}
    for item in items:
        risk_summary[item.risk.value] = risk_summary.get(item.risk.value, 0) + 1
        by_service[item.service] = round(by_service.get(item.service, 0.0) + item.monthly_savings, 2)

    notes = [
        "Savings are estimates. Each becomes verified only after execution and billing "
        "reconciliation.",
        "Proposing this plan creates pending actions. Every one still goes through policy, "
        "approval, live preflight, checkpoint and verification. Nothing executes from a plan.",
    ]
    met = total >= target_monthly_savings
    if not met:
        notes.insert(
            0,
            f"The target cannot be met within this plan's limits: eligible opportunities "
            f"total ${total:,.2f}/month against a ${target_monthly_savings:,.2f} target.",
        )
    return {
        "items": items,
        "excluded": excluded,
        "total_monthly_savings": total,
        "target_met": met,
        "shortfall": round(max(0.0, target_monthly_savings - total), 2),
        "risk_summary": risk_summary,
        "savings_by_service": dict(sorted(by_service.items(), key=lambda kv: kv[1], reverse=True)),
        "ranking_method": RANKING_METHOD,
        "notes": notes,
    }
