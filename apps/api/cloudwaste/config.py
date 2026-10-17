"""Runtime configuration.

Everything that differs between a laptop, the hackathon demo and a real AWS
account lives here. Defaults are chosen so `uvicorn cloudwaste.main:app` works
with no AWS credentials at all: storage falls back to in-memory and the data
plane serves the seeded demo account.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CLOUDWASTE_", env_file=".env", extra="ignore"
    )

    # --- deployment -------------------------------------------------------
    environment: Literal["local", "dev", "prod"] = "local"
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = ["http://localhost:3000"]

    # --- data plane -------------------------------------------------------
    # "demo" serves the seeded synthetic account and never touches AWS.
    # "live" uses boto3 against real credentials.
    default_account_mode: Literal["demo", "live"] = "demo"
    aws_region: str = "us-east-1"
    scan_regions: list[str] = ["us-east-1"]
    # Seed the synthetic demo account when no account is registered.
    seed_demo_account: bool = True
    # Live accounts are reached by assuming their cross-account role. Setting
    # this lets a live account with no role_arn use the host's credentials --
    # only appropriate for a single-account deployment scanning itself, because
    # it bypasses the customer role's IAM restrictions.
    allow_host_credentials: bool = False

    # --- storage ----------------------------------------------------------
    # "memory" keeps everything in-process, "dynamodb" uses real tables.
    storage_backend: Literal["memory", "dynamodb"] = "memory"
    dynamodb_table_prefix: str = "CloudWaste"
    dynamodb_endpoint_url: str | None = None  # set for DynamoDB Local
    reports_bucket: str | None = None

    # --- safety -----------------------------------------------------------
    # Global kill switch. While true, no executor ever calls a mutating AWS API.
    dry_run_default: bool = True
    # Autopilot must be switched on deliberately, even for LOW-risk actions.
    autopilot_enabled: bool = False
    # Actions above this risk can never auto-execute regardless of policy.
    autopilot_max_risk: Literal["low", "medium", "high", "critical"] = "low"
    approval_ttl_hours: int = 72
    policy_file: str | None = None  # defaults to policy/default_policies.yaml

    # --- analysis windows -------------------------------------------------
    metric_window_days: int = 14
    idle_cpu_threshold: float = 5.0
    underutilized_cpu_threshold: float = 20.0
    idle_network_bytes_per_day: float = 5_000_000.0  # 5 MB/day
    min_observation_days: int = 7
    min_monthly_savings_to_report: float = 1.0

    # --- AI ---------------------------------------------------------------
    bedrock_region: str = "us-east-1"
    bedrock_model_id: str = "anthropic.claude-sonnet-4-5-20250929-v1:0"
    bedrock_max_tokens: int = 4096
    agent_max_turns: int = 12
    # When false the agent is served by a deterministic local narrator instead
    # of Bedrock, so the UI and demo work without model access.
    bedrock_enabled: bool = False

    # --- remediation ------------------------------------------------------
    state_machine_arn: str | None = None
    # When false the orchestrator runs the same state sequence in-process.
    # Identical states, identical audit records. When true, execution starts
    # the configured state machine instead, which requires DynamoDB storage
    # because the state machine's Lambdas run in other processes.
    use_step_functions: bool = False

    # --- notifications ------------------------------------------------------
    # Routine notifications. Unset means notifications are disabled and
    # nothing is published anywhere.
    sns_topic_arn: str | None = None
    # Rollback failures page a human; they go to their own topic. Falls back
    # to sns_topic_arn when unset.
    sns_escalation_topic_arn: str | None = None
    # Which events publish. Every event type is on by default; remove one to
    # silence it without code changes.
    notify_events: list[str] = [
        "high_risk_finding",
        "approval_requested",
        "cost_anomaly",
        "budget_threshold",
        "rollback_failure",
        "remediation_failure",
        "high_confidence_opportunity",
    ]
    notify_min_finding_risk: Literal["low", "medium", "high", "critical"] = "high"
    notify_high_confidence_threshold: float = 90.0
    notify_anomaly_min_impact: float = 100.0
    # Monthly budget in USD. Unset disables the budget alert.
    monthly_budget: float | None = None
    budget_alert_threshold_percent: float = 90.0

    # --- savings verification ----------------------------------------------
    # Full days of post-change billing required before a saving is judged.
    savings_min_billing_days: int = 3
    # Observed saving at or above this share of the estimate counts as VERIFIED.
    savings_verified_ratio: float = 0.85
    # Below this share of the estimate the saving counts as NO_SAVINGS.
    savings_no_savings_ratio: float = 0.10

    @property
    def resolved_policy_file(self) -> str:
        if self.policy_file:
            return self.policy_file
        from pathlib import Path

        return str(Path(__file__).parent / "policy" / "default_policies.yaml")


def validate_settings(settings: Settings) -> list[dict]:
    """Configuration problems, each {"severity", "setting", "message"}.

    Errors stop the application from starting. The point is that a feature is
    never advertised as active when the configuration cannot make it work.
    """
    problems: list[dict] = []

    def error(setting: str, message: str) -> None:
        problems.append({"severity": "error", "setting": setting, "message": message})

    def warning(setting: str, message: str) -> None:
        problems.append({"severity": "warning", "setting": setting, "message": message})

    if settings.use_step_functions:
        if not settings.state_machine_arn:
            error(
                "use_step_functions",
                "use_step_functions=true requires state_machine_arn.",
            )
        elif not settings.state_machine_arn.startswith("arn:aws:states:"):
            error("state_machine_arn", "state_machine_arn is not a Step Functions ARN.")
        if settings.storage_backend != "dynamodb":
            error(
                "use_step_functions",
                "Step Functions runs remediation phases in Lambda, which cannot see "
                "this process's memory. Set storage_backend=dynamodb.",
            )
    elif settings.state_machine_arn:
        warning(
            "state_machine_arn",
            "state_machine_arn is set but use_step_functions=false, so remediation "
            "runs in-process and the state machine is not used.",
        )

    for name in ("sns_topic_arn", "sns_escalation_topic_arn"):
        value = getattr(settings, name)
        if value and not value.startswith("arn:aws:sns:"):
            error(name, f"{name} is not an SNS topic ARN.")
    if settings.sns_escalation_topic_arn and not settings.sns_topic_arn:
        warning(
            "sns_topic_arn",
            "Only the escalation topic is configured: rollback failures are "
            "published, routine notifications are not.",
        )

    if settings.monthly_budget is not None and settings.monthly_budget <= 0:
        error("monthly_budget", "monthly_budget must be positive when set.")
    if not 0 < settings.savings_no_savings_ratio < settings.savings_verified_ratio <= 1:
        error(
            "savings_verified_ratio",
            "Require 0 < savings_no_savings_ratio < savings_verified_ratio <= 1.",
        )
    if settings.allow_host_credentials:
        warning(
            "allow_host_credentials",
            "Live accounts without a role_arn will use this host's credentials, "
            "bypassing the customer role's IAM restrictions.",
        )
    if not settings.dry_run_default:
        warning("dry_run_default", "Dry run is disabled: approved actions change AWS.")
    return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
