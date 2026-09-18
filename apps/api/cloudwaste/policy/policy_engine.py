"""Policy evaluation.

Given a proposed action, decide: run it unattended, ask a human, or refuse.

The engine is deny-biased by construction, in four ways that each exist because
the opposite default is how automated remediation tools cause outages:

  1. **No match means approval, never execution.** An action nobody wrote a
     rule for is not pre-authorized.
  2. **Deny wins.** A matching deny rule beats every allow rule regardless of
     priority, so a protection rule cannot be outvoted by a narrower allow.
  3. **Global ceilings are applied after rules.** Autopilot being off, or the
     configured maximum risk, overrides any rule that says auto_execute. A
     policy file cannot grant itself more authority than the deployment allows.
  4. **The risk engine's blocks are absolute.** An owner opt-out or an unbacked
     destructive action is refused before rules are even consulted.

Rules are matched most-specific-first by priority, and every decision records
which rule produced it so an operator can answer "why did this run?".
"""

from __future__ import annotations

import logging

from ..config import Settings, get_settings
from ..intelligence.risk_engine import RiskAssessment
from ..models.domain import PolicyEvaluation, PolicyRule, Recommendation, Resource
from ..models.enums import ActionType, PolicyDecision, RiskLevel

logger = logging.getLogger(__name__)


class PolicyEngine:
    def __init__(
        self, rules: list[PolicyRule] | None = None, settings: Settings | None = None
    ) -> None:
        self.settings = settings or get_settings()
        self.rules = sorted(
            [r for r in (rules or []) if r.enabled], key=lambda r: r.priority
        )

    # ------------------------------------------------------------------

    def evaluate(
        self,
        recommendation: Recommendation,
        resource: Resource,
        risk: RiskAssessment | None = None,
    ) -> PolicyEvaluation:
        reasons: list[str] = []

        # --- 1. Risk-engine blocks are absolute -------------------------
        if risk and risk.is_blocked:
            return PolicyEvaluation(
                decision=PolicyDecision.DENY,
                matched_rule=None,
                reasons=[f"Blocked by risk engine: {reason}" for reason in risk.blocking_reasons],
                auto_execute=False,
            )

        matching = [r for r in self.rules if self._matches(r, recommendation, resource)]

        # --- 2. Any matching deny wins ----------------------------------
        denials = [r for r in matching if r.effect == "deny"]
        if denials:
            rule = denials[0]
            return PolicyEvaluation(
                decision=PolicyDecision.DENY,
                matched_rule=rule.name,
                reasons=[
                    f"Denied by policy '{rule.name}'"
                    + (f": {rule.description}" if rule.description else "")
                ],
                auto_execute=False,
            )

        # --- 3. No match means a human decides --------------------------
        allows = [r for r in matching if r.effect == "allow"]
        if not allows:
            return PolicyEvaluation(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                matched_rule=None,
                reasons=[
                    "No policy rule authorizes this action unattended, so it "
                    "requires approval. Actions are not pre-authorized by default."
                ],
                auto_execute=False,
                approval_ttl_hours=self.settings.approval_ttl_hours,
            )

        rule = allows[0]  # already priority-ordered
        reasons.append(
            f"Matched policy '{rule.name}'"
            + (f": {rule.description}" if rule.description else "")
        )

        if not rule.auto_execute or rule.require_approval:
            return PolicyEvaluation(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                matched_rule=rule.name,
                reasons=reasons + ["This rule requires human approval before execution."],
                auto_execute=False,
                approval_ttl_hours=rule.approval_ttl_hours,
            )

        # --- 4. Deployment-level ceilings override the rule -------------
        ceiling_reasons = self._ceiling_violations(recommendation)
        if ceiling_reasons:
            return PolicyEvaluation(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                matched_rule=rule.name,
                reasons=reasons + ceiling_reasons,
                auto_execute=False,
                approval_ttl_hours=rule.approval_ttl_hours,
            )

        reasons.append(
            f"Risk is {recommendation.risk.value.upper()} and confidence is "
            f"{recommendation.confidence:.0f}%, within the limits this rule sets."
        )
        return PolicyEvaluation(
            decision=PolicyDecision.AUTO_EXECUTE,
            matched_rule=rule.name,
            reasons=reasons,
            auto_execute=True,
            approval_ttl_hours=rule.approval_ttl_hours,
        )

    # ------------------------------------------------------------------

    def _ceiling_violations(self, recommendation: Recommendation) -> list[str]:
        """Deployment-wide limits that no policy file can raise."""
        reasons: list[str] = []
        settings = self.settings

        if not settings.autopilot_enabled:
            reasons.append(
                "Autopilot is disabled for this deployment, so nothing executes "
                "without approval regardless of policy."
            )

        ceiling = RiskLevel(settings.autopilot_max_risk)
        if recommendation.risk.rank > ceiling.rank:
            reasons.append(
                f"Action risk is {recommendation.risk.value.upper()}, above the "
                f"{ceiling.value.upper()} ceiling this deployment allows for "
                f"unattended execution."
            )

        if not recommendation.rollback_possible:
            reasons.append(
                "Action has no automated rollback path, so it is never executed "
                "unattended."
            )

        return reasons

    def _matches(
        self, rule: PolicyRule, recommendation: Recommendation, resource: Resource
    ) -> bool:
        """Every criterion the rule sets must hold. Unset criteria match anything."""
        if rule.resource_type is not None and rule.resource_type != resource.resource_type:
            return False
        if rule.environment is not None and rule.environment != resource.environment:
            return False
        if rule.action is not None and rule.action != recommendation.action_type:
            return False
        if rule.criticality is not None and rule.criticality != resource.criticality:
            return False
        if rule.max_risk is not None and recommendation.risk.rank > rule.max_risk.rank:
            return False
        if rule.min_confidence is not None and recommendation.confidence < rule.min_confidence:
            return False
        if (
            rule.min_monthly_savings is not None
            and recommendation.monthly_savings < rule.min_monthly_savings
        ):
            return False
        if (
            rule.max_monthly_savings is not None
            and recommendation.monthly_savings > rule.max_monthly_savings
        ):
            return False
        for key, expected in rule.tag_equals.items():
            actual = next(
                (v for k, v in resource.tags.items() if k.lower() == key.lower()), None
            )
            if actual is None or actual.lower() != expected.lower():
                return False
        return True

    # ------------------------------------------------------------------

    def explain(self, recommendation: Recommendation, resource: Resource) -> dict:
        """Every rule considered and why it did or did not apply.

        Exposed on the API so an operator can debug a policy without reading
        the YAML and guessing.
        """
        considered = []
        for rule in self.rules:
            matched = self._matches(rule, recommendation, resource)
            considered.append(
                {
                    "rule": rule.name,
                    "priority": rule.priority,
                    "effect": rule.effect,
                    "matched": matched,
                    "reason": (
                        "all criteria matched"
                        if matched
                        else self._first_mismatch(rule, recommendation, resource)
                    ),
                }
            )
        return {
            "action": recommendation.action_type.value,
            "resource": resource.resource_id,
            "rules_considered": considered,
            "deployment_ceilings": {
                "autopilot_enabled": self.settings.autopilot_enabled,
                "autopilot_max_risk": self.settings.autopilot_max_risk,
            },
        }

    def _first_mismatch(
        self, rule: PolicyRule, recommendation: Recommendation, resource: Resource
    ) -> str:
        if rule.resource_type is not None and rule.resource_type != resource.resource_type:
            return (
                f"resource type is {resource.resource_type.value}, rule wants "
                f"{rule.resource_type.value}"
            )
        if rule.environment is not None and rule.environment != resource.environment:
            return (
                f"environment is {resource.environment.value}, rule wants "
                f"{rule.environment.value}"
            )
        if rule.action is not None and rule.action != recommendation.action_type:
            return f"action is {recommendation.action_type.value}, rule wants {rule.action.value}"
        if rule.criticality is not None and rule.criticality != resource.criticality:
            return (
                f"criticality is {resource.criticality.value}, rule wants "
                f"{rule.criticality.value}"
            )
        if rule.max_risk is not None and recommendation.risk.rank > rule.max_risk.rank:
            return (
                f"risk is {recommendation.risk.value}, above the rule's maximum of "
                f"{rule.max_risk.value}"
            )
        if rule.min_confidence is not None and recommendation.confidence < rule.min_confidence:
            return (
                f"confidence is {recommendation.confidence:.0f}%, below the rule's "
                f"minimum of {rule.min_confidence:.0f}%"
            )
        if (
            rule.min_monthly_savings is not None
            and recommendation.monthly_savings < rule.min_monthly_savings
        ):
            return (
                f"savings of ${recommendation.monthly_savings:,.2f} are below the "
                f"rule's minimum of ${rule.min_monthly_savings:,.2f}"
            )
        if (
            rule.max_monthly_savings is not None
            and recommendation.monthly_savings > rule.max_monthly_savings
        ):
            return (
                f"savings of ${recommendation.monthly_savings:,.2f} exceed the "
                f"rule's maximum of ${rule.max_monthly_savings:,.2f}"
            )
        for key, expected in rule.tag_equals.items():
            actual = next(
                (v for k, v in resource.tags.items() if k.lower() == key.lower()), None
            )
            if actual is None:
                return f"resource has no '{key}' tag"
            if actual.lower() != expected.lower():
                return f"tag {key} is '{actual}', rule wants '{expected}'"
        return "no mismatch found"
