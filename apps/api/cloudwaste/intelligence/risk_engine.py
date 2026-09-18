"""Risk scoring for a proposed action.

Risk is a property of the *action on this resource*, never of the resource
alone: deleting an unattached volume in dev and deleting one in production are
different risks, and stopping an instance is not the same as resizing it.

The engine is additive with hard floors. Additive scoring alone is unsafe --
enough small mitigations could in principle drag "delete the production
database" down into MEDIUM -- so certain facts set a floor that no amount of
mitigation can lower. Those floors are the real safety property here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models.domain import Resource
from ..models.enums import ActionType, Criticality, Environment, RiskLevel


@dataclass(slots=True)
class RiskInputs:
    action_type: ActionType
    resource: Resource
    confidence: float = 100.0
    rollback_possible: bool = True
    restart_required: bool = False
    downtime_seconds: int = 0
    has_recent_backup: bool = False
    has_dependents: bool = False
    dependent_count: int = 0
    data_bearing: bool = False


@dataclass(slots=True)
class RiskAssessment:
    level: RiskLevel
    score: float
    factors: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    floors_applied: list[str] = field(default_factory=list)
    blocking_reasons: list[str] = field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return bool(self.blocking_reasons)


# Inherent risk of the action itself, before any context.
_ACTION_BASE_RISK: dict[ActionType, float] = {
    ActionType.CREATE_EBS_SNAPSHOT: 2.0,      # additive, reversible, costs a little
    ActionType.CREATE_S3_LIFECYCLE_POLICY: 8.0,
    ActionType.CHANGE_S3_STORAGE_CLASS: 14.0,
    ActionType.MODIFY_LAMBDA_MEMORY: 12.0,
    # gp2 to gp3 happens online with no downtime and converts back the
    # same way, which makes it the lowest-risk mutating action available.
    ActionType.MODIFY_EBS_VOLUME_TYPE: 10.0,
    ActionType.START_EC2: 5.0,
    ActionType.SCHEDULE_RESOURCE: 10.0,
    ActionType.RELEASE_ELASTIC_IP: 30.0,       # the address is gone for good
    ActionType.STOP_EC2: 32.0,
    ActionType.RESIZE_EC2: 38.0,
    ActionType.RESIZE_RDS: 55.0,
    ActionType.DELETE_EBS: 60.0,
    ActionType.ROLLBACK_ACTION: 20.0,
}

_THRESHOLDS = ((75.0, RiskLevel.CRITICAL), (50.0, RiskLevel.HIGH), (25.0, RiskLevel.MEDIUM))


def assess(inputs: RiskInputs) -> RiskAssessment:
    resource = inputs.resource
    action = inputs.action_type
    score = _ACTION_BASE_RISK.get(action, 40.0)
    factors: list[str] = [f"Base risk for {action.value}"]
    mitigations: list[str] = []
    floors: list[RiskLevel] = []
    floor_notes: list[str] = []
    blocking: list[str] = []

    # --- environment ---------------------------------------------------
    if resource.environment is Environment.PRODUCTION:
        score += 25
        factors.append("Resource is tagged as production")
        floors.append(RiskLevel.HIGH)
        floor_notes.append("Production resources are never below HIGH risk")
    elif resource.environment is Environment.STAGING:
        score += 10
        factors.append("Resource is in staging")
    elif resource.environment is Environment.UNKNOWN:
        # The single most important default in this file. An untagged resource
        # is treated as production, because the alternative is discovering the
        # environment by breaking it.
        score += 20
        factors.append("Environment is unknown, so the resource is treated as production")
        floors.append(RiskLevel.HIGH)
        floor_notes.append("Unknown environment is treated as production")
    elif resource.environment in (Environment.DEVELOPMENT, Environment.TEST):
        score -= 10
        mitigations.append(f"Resource is tagged {resource.environment.value}")

    # --- criticality ----------------------------------------------------
    if resource.criticality is Criticality.HIGH:
        score += 18
        factors.append("Resource is tagged high criticality")
        floors.append(RiskLevel.HIGH)
        floor_notes.append("High-criticality resources are never below HIGH risk")
    elif resource.criticality is Criticality.LOW:
        score -= 6
        mitigations.append("Resource is tagged low criticality")

    # --- explicit owner opt-out ------------------------------------------
    if resource.auto_remediation_allowed is False:
        blocking.append(
            "Owner set AutoRemediation=false on this resource, which is an "
            "explicit opt-out that CloudWaste never overrides"
        )
        floors.append(RiskLevel.CRITICAL)
        floor_notes.append("Owner opted out of automated remediation")
    elif resource.auto_remediation_allowed is True:
        mitigations.append("Owner explicitly opted this resource into auto-remediation")
        score -= 8

    # --- destructiveness and data ----------------------------------------
    if action.is_destructive:
        score += 15
        factors.append("Action is destructive and cannot be undone by re-running it")
        if inputs.data_bearing:
            score += 20
            factors.append("Resource holds data")
            if not inputs.has_recent_backup:
                blocking.append(
                    "Destructive action on a data-bearing resource with no recent "
                    "backup or snapshot"
                )
                floors.append(RiskLevel.CRITICAL)
                floor_notes.append("Data-bearing deletion without a backup")
            else:
                mitigations.append("A recent snapshot exists and will be retained")
                score -= 12

    # --- availability impact ---------------------------------------------
    if inputs.restart_required:
        score += 12
        factors.append("Change requires a restart")
    if inputs.downtime_seconds > 0:
        score += min(20.0, inputs.downtime_seconds / 60.0 * 2.0)
        factors.append(f"Estimated downtime of about {inputs.downtime_seconds}s")

    # --- dependencies ------------------------------------------------------
    if inputs.has_dependents:
        score += 10 + min(15, inputs.dependent_count * 3)
        factors.append(
            f"{inputs.dependent_count} dependent resource(s) may be affected"
            if inputs.dependent_count
            else "Other resources depend on this one"
        )

    # --- reversibility -----------------------------------------------------
    if inputs.rollback_possible:
        score -= 10
        mitigations.append("Action is reversible through a recorded rollback path")
    else:
        score += 18
        factors.append("Action has no automated rollback path")
        floors.append(RiskLevel.HIGH)
        floor_notes.append("Irreversible actions are never below HIGH risk")

    # --- evidence quality ---------------------------------------------------
    if inputs.confidence < 60:
        score += 15
        factors.append(f"Low evidence confidence ({inputs.confidence:.0f}%)")
        floors.append(RiskLevel.HIGH)
        floor_notes.append("Confidence below 60% is never below HIGH risk")
    elif inputs.confidence < 80:
        score += 6
        factors.append(f"Moderate evidence confidence ({inputs.confidence:.0f}%)")
    else:
        mitigations.append(f"High evidence confidence ({inputs.confidence:.0f}%)")
        score -= 5

    level = _level_for(max(0.0, min(100.0, score)))

    applied_notes: list[str] = []
    for floor, note in zip(floors, floor_notes):
        if floor.rank > level.rank:
            level = floor
            applied_notes.append(note)
        elif floor.rank == level.rank:
            applied_notes.append(note)

    return RiskAssessment(
        level=level,
        score=round(max(0.0, min(100.0, score)), 1),
        factors=factors,
        mitigations=mitigations,
        floors_applied=applied_notes,
        blocking_reasons=blocking,
    )


def _level_for(score: float) -> RiskLevel:
    for threshold, level in _THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.LOW


def is_data_bearing(resource: Resource, action: ActionType) -> bool:
    """Whether the action could destroy data that is not trivially recreated."""
    from ..models.enums import ResourceType

    if action is ActionType.DELETE_EBS:
        return True
    if action is ActionType.RESIZE_RDS:
        return True
    if resource.resource_type in (ResourceType.RDS, ResourceType.S3, ResourceType.EBS):
        return action.is_destructive
    return False
