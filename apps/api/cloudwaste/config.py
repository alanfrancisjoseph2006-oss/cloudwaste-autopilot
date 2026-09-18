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
    sns_topic_arn: str | None = None
    # When no Step Functions ARN is configured the orchestrator runs the same
    # state sequence in-process. Identical states, identical audit records.
    use_step_functions: bool = False

    @property
    def resolved_policy_file(self) -> str:
        if self.policy_file:
            return self.policy_file
        from pathlib import Path

        return str(Path(__file__).parent / "policy" / "default_policies.yaml")


@lru_cache
def get_settings() -> Settings:
    return Settings()
