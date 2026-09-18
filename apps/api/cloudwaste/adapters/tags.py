"""Tag interpretation.

Tags are the only place the customer tells us what a resource *means*, so the
risk engine leans on them heavily. Real accounts tag inconsistently, so this
module normalizes aggressively and -- critically -- distinguishes "tagged as
development" from "not tagged at all". An untagged resource is treated as
potentially production, never as safe.
"""

from __future__ import annotations

from ..models.enums import Criticality, Environment

ENVIRONMENT_KEYS = ("environment", "env", "stage", "tier", "lifecycle")
OWNER_KEYS = ("owner", "team", "owneremail", "contact", "costcenter", "cost-center")
CRITICALITY_KEYS = ("criticality", "severity", "importance", "businessimpact")
AUTO_REMEDIATION_KEYS = ("autoremediation", "auto-remediation", "cloudwaste:autoremediation")

_ENVIRONMENT_VALUES: dict[str, Environment] = {
    "prod": Environment.PRODUCTION, "production": Environment.PRODUCTION,
    "prd": Environment.PRODUCTION, "live": Environment.PRODUCTION,
    "stage": Environment.STAGING, "staging": Environment.STAGING,
    "stg": Environment.STAGING, "preprod": Environment.STAGING,
    "pre-prod": Environment.STAGING, "uat": Environment.STAGING,
    "dev": Environment.DEVELOPMENT, "development": Environment.DEVELOPMENT,
    "develop": Environment.DEVELOPMENT, "sandbox": Environment.DEVELOPMENT,
    "sbx": Environment.DEVELOPMENT, "scratch": Environment.DEVELOPMENT,
    "test": Environment.TEST, "testing": Environment.TEST,
    "qa": Environment.TEST, "ci": Environment.TEST,
}

_CRITICALITY_VALUES: dict[str, Criticality] = {
    "high": Criticality.HIGH, "critical": Criticality.HIGH, "tier0": Criticality.HIGH,
    "tier1": Criticality.HIGH, "p0": Criticality.HIGH, "p1": Criticality.HIGH,
    "medium": Criticality.MEDIUM, "moderate": Criticality.MEDIUM,
    "tier2": Criticality.MEDIUM, "p2": Criticality.MEDIUM,
    "low": Criticality.LOW, "tier3": Criticality.LOW, "p3": Criticality.LOW,
    "none": Criticality.LOW,
}

_TRUE = {"true", "yes", "1", "enabled", "allow", "on"}
_FALSE = {"false", "no", "0", "disabled", "deny", "off"}


def _normalize(tags: dict[str, str]) -> dict[str, str]:
    return {k.strip().lower().replace("_", ""): (v or "").strip() for k, v in tags.items()}


def _lookup(norm: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        candidate = key.replace("_", "").replace("-", "")
        for actual, value in norm.items():
            if actual.replace("-", "") == candidate and value:
                return value
    return None


def classify_environment(tags: dict[str, str], resource_name: str | None = None) -> Environment:
    """Resolve the environment, falling back to name heuristics.

    Returns UNKNOWN when nothing indicates an environment. Callers must treat
    UNKNOWN as production-equivalent for risk purposes.
    """
    raw = _lookup(_normalize(tags), ENVIRONMENT_KEYS)
    if raw:
        hit = _ENVIRONMENT_VALUES.get(raw.strip().lower())
        if hit:
            return hit
    if resource_name:
        lowered = resource_name.lower()
        # Ordered so that "prod" is not matched inside "non-prod".
        if any(token in lowered for token in ("non-prod", "nonprod")):
            return Environment.STAGING
        for token, env in (
            ("prod", Environment.PRODUCTION),
            ("staging", Environment.STAGING),
            ("dev", Environment.DEVELOPMENT),
            ("test", Environment.TEST),
            ("qa", Environment.TEST),
        ):
            if token in lowered:
                return env
    return Environment.UNKNOWN


def classify_criticality(tags: dict[str, str], environment: Environment) -> Criticality:
    raw = _lookup(_normalize(tags), CRITICALITY_KEYS)
    if raw:
        hit = _CRITICALITY_VALUES.get(raw.strip().lower())
        if hit:
            return hit
    # No explicit criticality: infer conservatively from environment.
    if environment is Environment.PRODUCTION:
        return Criticality.HIGH
    if environment is Environment.STAGING:
        return Criticality.MEDIUM
    if environment in (Environment.DEVELOPMENT, Environment.TEST):
        return Criticality.LOW
    return Criticality.UNKNOWN


def classify_owner(tags: dict[str, str]) -> str | None:
    return _lookup(_normalize(tags), OWNER_KEYS)


def auto_remediation_flag(tags: dict[str, str]) -> bool | None:
    """Explicit opt-in/opt-out. None means the owner said nothing."""
    raw = _lookup(_normalize(tags), AUTO_REMEDIATION_KEYS)
    if raw is None:
        return None
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    return None


def classify(tags: dict[str, str], resource_name: str | None = None) -> dict:
    """Everything the risk engine needs from tags, in one pass."""
    environment = classify_environment(tags, resource_name)
    return {
        "environment": environment,
        "criticality": classify_criticality(tags, environment),
        "owner": classify_owner(tags),
        "auto_remediation_allowed": auto_remediation_flag(tags),
    }
