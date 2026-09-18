"""Policy loading and validation.

A malformed policy file must fail loudly at startup, never silently. The worst
outcome here is a typo that turns a deny rule into no rule at all, so unknown
keys are rejected rather than ignored, and `validate()` additionally reports
rules that parse correctly but are dangerous or unreachable.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from ..config import Settings, get_settings
from ..models.domain import PolicyRule
from ..models.enums import ActionType, Criticality, Environment, ResourceType, RiskLevel

logger = logging.getLogger(__name__)

_ALLOWED_KEYS = set(PolicyRule.model_fields) | {"enabled"}


class PolicyError(ValueError):
    """Raised when a policy file cannot be trusted."""


def load_rules(path: str | Path | None = None, settings: Settings | None = None) -> list[PolicyRule]:
    settings = settings or get_settings()
    resolved = Path(path or settings.resolved_policy_file)

    if not resolved.exists():
        raise PolicyError(f"Policy file not found: {resolved}")

    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"Policy file {resolved} is not valid YAML: {exc}") from exc

    entries = raw.get("rules")
    if not isinstance(entries, list):
        raise PolicyError(f"Policy file {resolved} must contain a top-level 'rules' list")

    rules: list[PolicyRule] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise PolicyError(f"Rule at index {index} is not a mapping")
        name = entry.get("name", f"<unnamed rule {index}>")

        unknown = set(entry) - _ALLOWED_KEYS
        if unknown:
            # Silently ignoring an unknown key is how a misspelled `enviroment`
            # turns a production protection into a rule that matches everything.
            raise PolicyError(
                f"Rule '{name}' has unknown field(s): {', '.join(sorted(unknown))}. "
                f"Valid fields are: {', '.join(sorted(_ALLOWED_KEYS))}"
            )

        try:
            rules.append(PolicyRule(**_coerce(entry)))
        except ValidationError as exc:
            raise PolicyError(f"Rule '{name}' is invalid: {exc}") from exc

    names = [r.name for r in rules]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise PolicyError(f"Duplicate rule name(s): {', '.join(sorted(duplicates))}")

    logger.info("loaded %d policy rules from %s", len(rules), resolved)
    return rules


def _coerce(entry: dict[str, Any]) -> dict[str, Any]:
    """Accept the human-friendly spellings a YAML author will actually write."""
    out = dict(entry)
    coercions = {
        "resource_type": lambda v: ResourceType(str(v).upper()),
        "environment": lambda v: Environment(str(v).lower()),
        "action": lambda v: ActionType(str(v).upper()),
        "criticality": lambda v: Criticality(str(v).lower()),
        "max_risk": lambda v: RiskLevel(str(v).lower()),
    }
    for key, coerce in coercions.items():
        if out.get(key) is not None:
            try:
                out[key] = coerce(out[key])
            except ValueError as exc:
                raise PolicyError(
                    f"Rule '{entry.get('name')}' has invalid {key}={out[key]!r}: {exc}"
                ) from exc
    return out


def validate(rules: list[PolicyRule]) -> list[dict[str, str]]:
    """Report rules that parse but are dangerous or pointless.

    Returns a list of {severity, rule, message}. Severity 'error' means the set
    should not be deployed; 'warning' means it probably does not do what its
    author intended.
    """
    problems: list[dict[str, str]] = []
    enabled = [r for r in rules if r.enabled]

    for rule in enabled:
        if rule.effect != "allow" or not rule.auto_execute:
            continue

        # An auto-executing rule with no narrowing criteria authorizes
        # everything, which is never what anybody means.
        criteria = [
            rule.resource_type, rule.environment, rule.action,
            rule.criticality, rule.max_risk,
        ]
        if not any(c is not None for c in criteria) and not rule.tag_equals:
            problems.append({
                "severity": "error",
                "rule": rule.name,
                "message": (
                    "Rule auto-executes with no matching criteria, so it "
                    "authorizes every action on every resource unattended."
                ),
            })

        if rule.environment is Environment.PRODUCTION:
            problems.append({
                "severity": "error",
                "rule": rule.name,
                "message": "Rule auto-executes against production resources.",
            })

        if rule.max_risk is None:
            problems.append({
                "severity": "warning",
                "rule": rule.name,
                "message": (
                    "Rule auto-executes with no max_risk, so it would permit "
                    "CRITICAL actions if the deployment ceiling allowed them."
                ),
            })
        elif rule.max_risk.rank >= RiskLevel.HIGH.rank:
            problems.append({
                "severity": "error",
                "rule": rule.name,
                "message": f"Rule auto-executes up to {rule.max_risk.value} risk.",
            })

        if rule.min_confidence is None:
            problems.append({
                "severity": "warning",
                "rule": rule.name,
                "message": (
                    "Rule auto-executes with no min_confidence, so a weakly "
                    "evidenced finding could trigger it."
                ),
            })

        if rule.action is not None and rule.action.is_destructive and rule.auto_execute:
            problems.append({
                "severity": "warning",
                "rule": rule.name,
                "message": (
                    f"Rule auto-executes the destructive action "
                    f"{rule.action.value}. The risk engine independently blocks "
                    f"this without a backup, but confirm that is intended."
                ),
            })

    # Unreachable allow rules: a broader deny at a lower priority shadows them.
    for rule in enabled:
        if rule.effect != "allow":
            continue
        for denial in enabled:
            if denial.effect != "deny" or denial.priority >= rule.priority:
                continue
            if _shadows(denial, rule):
                problems.append({
                    "severity": "warning",
                    "rule": rule.name,
                    "message": (
                        f"Rule can never take effect: deny rule "
                        f"'{denial.name}' (priority {denial.priority}) matches "
                        f"everything this rule matches."
                    ),
                })
                break

    return problems


def _shadows(denial: PolicyRule, allow: PolicyRule) -> bool:
    """True when every resource matching `allow` also matches `denial`."""
    pairs = [
        (denial.resource_type, allow.resource_type),
        (denial.environment, allow.environment),
        (denial.action, allow.action),
        (denial.criticality, allow.criticality),
    ]
    for deny_value, allow_value in pairs:
        if deny_value is None:
            continue  # deny matches anything on this axis
        if deny_value != allow_value:
            return False
    return True


def load_and_validate(
    path: str | Path | None = None, settings: Settings | None = None, strict: bool = True
) -> tuple[list[PolicyRule], list[dict[str, str]]]:
    rules = load_rules(path, settings)
    problems = validate(rules)
    errors = [p for p in problems if p["severity"] == "error"]
    if errors and strict:
        detail = "; ".join(f"{p['rule']}: {p['message']}" for p in errors)
        raise PolicyError(f"Policy set rejected: {detail}")
    for problem in problems:
        logger.warning("policy %s [%s]: %s", problem["severity"], problem["rule"], problem["message"])
    return rules, problems
