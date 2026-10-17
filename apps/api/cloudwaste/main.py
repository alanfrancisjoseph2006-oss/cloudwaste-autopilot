"""FastAPI application entry point.

Run locally with:

    uvicorn cloudwaste.main:app --reload

With no configuration it serves the seeded demo account from in-memory storage
in dry-run mode, so it starts with no AWS credentials and mutates nothing.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .adapters.aws.clients import AssumeRoleError
from .api.routes import actions, agent, core, findings, optimization
from .config import get_settings, validate_settings
from .policy.policy_loader import PolicyError
from .services import AccountMismatchError, CustomerRoleRequired

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

settings = get_settings()

app = FastAPI(
    title="CloudWaste Autopilot",
    version="1.0.0",
    description=(
        "AI-powered autonomous AWS FinOps control plane. Combines AWS-native "
        "FinOps signals with contextual investigation, risk policy, explainable "
        "recommendations, approval workflow, remediation, verification and "
        "rollback."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

prefix = settings.api_prefix
app.include_router(core.router, prefix=prefix)
app.include_router(findings.router, prefix=prefix)
app.include_router(actions.router, prefix=prefix)
app.include_router(agent.router, prefix=prefix)
app.include_router(optimization.router, prefix=prefix)


@app.exception_handler(PolicyError)
def policy_error_handler(request: Request, exc: PolicyError):
    """A bad policy file is a configuration error, not a server fault."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "policy_configuration_invalid",
            "detail": str(exc),
            "hint": "Fix the policy YAML and restart. CloudWaste refuses to run "
            "with a policy set it cannot validate.",
        },
    )


@app.exception_handler(AssumeRoleError)
def assume_role_error_handler(request: Request, exc: AssumeRoleError):
    """The customer role could not be assumed. Nothing was read or changed."""
    return JSONResponse(
        status_code=502,
        content={"error": "customer_role_unavailable", "detail": str(exc)},
    )


@app.exception_handler(CustomerRoleRequired)
def customer_role_required_handler(request: Request, exc: CustomerRoleRequired):
    return JSONResponse(
        status_code=409,
        content={"error": "customer_role_required", "detail": str(exc)},
    )


@app.exception_handler(AccountMismatchError)
def account_mismatch_handler(request: Request, exc: AccountMismatchError):
    return JSONResponse(
        status_code=409,
        content={"error": "account_mismatch", "detail": str(exc)},
    )


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "version": "1.0.0"}


@app.get("/", tags=["meta"])
def root():
    """What this deployment is currently configured to do.

    Deliberately explicit about the safety switches: whether CloudWaste can
    execute anything right now is the first thing anyone should be able to see.
    """
    from .actions.registry import executable_actions

    return {
        "name": "CloudWaste Autopilot",
        "version": "1.0.0",
        "tagline": "Find waste. Understand why. Fix it safely.",
        "docs": "/docs",
        "api": prefix,
        "safety": {
            "dry_run_default": settings.dry_run_default,
            "autopilot_enabled": settings.autopilot_enabled,
            "autopilot_max_risk": settings.autopilot_max_risk,
            "summary": (
                "Dry run is on and autopilot is off: nothing mutates AWS."
                if settings.dry_run_default or not settings.autopilot_enabled
                else f"Autopilot is ON for actions at or below "
                f"{settings.autopilot_max_risk.upper()} risk."
            ),
        },
        "configuration": {
            "storage_backend": settings.storage_backend,
            "default_account_mode": settings.default_account_mode,
            "bedrock_enabled": settings.bedrock_enabled,
            "bedrock_model_id": settings.bedrock_model_id if settings.bedrock_enabled else None,
            "metric_window_days": settings.metric_window_days,
            # What is actually active, not merely configured.
            "orchestration": "step_functions" if settings.use_step_functions else "local",
            "state_machine_arn": settings.state_machine_arn if settings.use_step_functions else None,
            "notifications": _notification_status(),
            "allow_host_credentials": settings.allow_host_credentials,
            "monthly_budget": settings.monthly_budget,
        },
        "configuration_problems": validate_settings(settings),
        "executable_actions": [a.value for a in executable_actions()],
    }


def _notification_status() -> dict:
    from .services import get_service

    return get_service().notifications.status()


@app.on_event("startup")
def on_startup():
    from .services import get_service

    problems = validate_settings(settings)
    for problem in problems:
        log = logger.error if problem["severity"] == "error" else logger.warning
        log("config %s [%s]: %s", problem["severity"], problem["setting"], problem["message"])
    errors = [p for p in problems if p["severity"] == "error"]
    if errors:
        # Refuse to start rather than run with a feature that looks enabled
        # but cannot work.
        raise RuntimeError(
            "CloudWaste configuration is invalid: "
            + "; ".join(f"{p['setting']}: {p['message']}" for p in errors)
        )

    service = get_service()
    logger.info(
        "CloudWaste Autopilot ready: %d policy rules, storage=%s, dry_run=%s, "
        "autopilot=%s",
        len(service.policy_rules),
        settings.storage_backend,
        settings.dry_run_default,
        settings.autopilot_enabled,
    )
    for problem in service.policy_problems:
        logger.warning(
            "policy %s [%s]: %s", problem["severity"], problem["rule"], problem["message"]
        )
    logger.info(
        "orchestration=%s notifications=%s",
        "step_functions" if settings.use_step_functions else "local",
        service.notifications.status()["channel"],
    )
