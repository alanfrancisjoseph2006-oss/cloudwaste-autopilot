"""Domain enumerations shared across the intelligence, policy and action layers."""

from __future__ import annotations

from enum import Enum


class ResourceType(str, Enum):
    EC2 = "EC2"
    EBS = "EBS"
    S3 = "S3"
    RDS = "RDS"
    LAMBDA = "LAMBDA"
    NAT_GATEWAY = "NAT_GATEWAY"
    ELASTIC_IP = "ELASTIC_IP"
    ELB = "ELB"


class WasteType(str, Enum):
    IDLE_RESOURCE = "idle_resource"
    UNDERUTILIZED_RESOURCE = "underutilized_resource"
    OVERPROVISIONED_RESOURCE = "overprovisioned_resource"
    UNATTACHED_STORAGE = "unattached_storage"
    UNUSED_NETWORK_RESOURCE = "unused_network_resource"
    COST_ANOMALY = "cost_anomaly"
    SCHEDULED_RUNTIME_WASTE = "scheduled_runtime_waste"
    STORAGE_LIFECYCLE_WASTE = "storage_lifecycle_waste"
    DUPLICATE_RESOURCE = "duplicate_resource"
    CONFIGURATION_INEFFICIENCY = "configuration_inefficiency"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    def __ge__(self, other: "RiskLevel") -> bool:  # type: ignore[override]
        return self.rank >= other.rank

    def __gt__(self, other: "RiskLevel") -> bool:  # type: ignore[override]
        return self.rank > other.rank

    def __le__(self, other: "RiskLevel") -> bool:  # type: ignore[override]
        return self.rank <= other.rank

    def __lt__(self, other: "RiskLevel") -> bool:  # type: ignore[override]
        return self.rank < other.rank


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    UNKNOWN = "unknown"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    SUPPRESSED = "SUPPRESSED"
    IN_PROGRESS = "IN_PROGRESS"
    REMEDIATED = "REMEDIATED"
    STALE = "STALE"


class ActionType(str, Enum):
    STOP_EC2 = "STOP_EC2"
    START_EC2 = "START_EC2"
    RESIZE_EC2 = "RESIZE_EC2"
    DELETE_EBS = "DELETE_EBS"
    CREATE_EBS_SNAPSHOT = "CREATE_EBS_SNAPSHOT"
    MODIFY_EBS_VOLUME_TYPE = "MODIFY_EBS_VOLUME_TYPE"
    RESIZE_RDS = "RESIZE_RDS"
    CHANGE_S3_STORAGE_CLASS = "CHANGE_S3_STORAGE_CLASS"
    CREATE_S3_LIFECYCLE_POLICY = "CREATE_S3_LIFECYCLE_POLICY"
    MODIFY_LAMBDA_MEMORY = "MODIFY_LAMBDA_MEMORY"
    RELEASE_ELASTIC_IP = "RELEASE_ELASTIC_IP"
    SCHEDULE_RESOURCE = "SCHEDULE_RESOURCE"
    ROLLBACK_ACTION = "ROLLBACK_ACTION"

    @property
    def is_destructive(self) -> bool:
        return self in _DESTRUCTIVE_ACTIONS

    @property
    def requires_restart(self) -> bool:
        return self in _RESTART_ACTIONS


_DESTRUCTIVE_ACTIONS = frozenset(
    {ActionType.DELETE_EBS, ActionType.RELEASE_ELASTIC_IP}
)
_RESTART_ACTIONS = frozenset(
    {ActionType.RESIZE_EC2, ActionType.RESIZE_RDS, ActionType.STOP_EC2}
)


class ApprovalStatus(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class ExecutionStatus(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"


class SavingsStatus(str, Enum):
    """Where an action's saving sits between "estimated" and "proven".

    A saving is never reported as realized on the strength of a simulation.
    AWS billing lags by up to a day, and resource-level cost data may not exist
    at all, so the lifecycle has explicit waiting and unprovable states rather
    than collapsing everything into a single number.
    """

    ESTIMATED = "ESTIMATED"                          # proposed, not executed
    NOT_APPLICABLE = "NOT_APPLICABLE"                # dry run, rolled back, or failed
    EXECUTED_PENDING_BILLING = "EXECUTED_PENDING_BILLING"  # executed, billing not yet observable
    VERIFICATION_PENDING = "VERIFICATION_PENDING"    # some billing, not enough to judge
    VERIFIED = "VERIFIED"                            # observed saving matches the estimate
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"        # observed saving is real but smaller
    NO_SAVINGS = "NO_SAVINGS"                        # billing shows no material reduction
    UNVERIFIABLE = "UNVERIFIABLE"                    # no resource-level billing to attribute
    VERIFICATION_FAILED = "VERIFICATION_FAILED"      # the reconciliation itself errored


class PolicyDecision(str, Enum):
    AUTO_EXECUTE = "AUTO_EXECUTE"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"
