"""Impact analysis and simulation.

`simulate()` answers, for a specific proposed action on a specific resource:
what will this cost afterwards, what breaks while it happens, and can it be
undone. It runs before anything is executed and its output is what an approver
reads.

Three rules keep the numbers honest:

  * Savings are computed from the *same* price source as the current cost.
    Comparing an observed bill against a list price produces a number that is
    part saving and part accounting artifact.
  * Downtime is stated as a range's upper bound, not a best case. An approver
    planning a maintenance window needs the pessimistic figure.
  * Anything with no rollback path says so plainly rather than describing a
    manual recovery procedure as a rollback.
"""

from __future__ import annotations

from ..adapters import pricing
from ..models.domain import Resource, SimulationResult
from ..models.enums import ActionType, ResourceType, RiskLevel
from . import risk_engine

# Upper-bound downtime, in seconds, for the actions that interrupt service.
DOWNTIME_ESTIMATES: dict[ActionType, int] = {
    ActionType.STOP_EC2: 0,             # the stop IS the outcome, not an interruption
    ActionType.START_EC2: 120,
    ActionType.RESIZE_EC2: 300,         # stop, modify, start
    ActionType.RESIZE_RDS: 900,         # single-AZ: a full restart
    ActionType.MODIFY_LAMBDA_MEMORY: 0, # next invocation picks it up
    ActionType.DELETE_EBS: 0,
    ActionType.CREATE_EBS_SNAPSHOT: 0,
    ActionType.CHANGE_S3_STORAGE_CLASS: 0,
    ActionType.CREATE_S3_LIFECYCLE_POLICY: 0,
    ActionType.RELEASE_ELASTIC_IP: 0,
    ActionType.MODIFY_EBS_VOLUME_TYPE: 0,  # online conversion
}

RDS_MULTI_AZ_FAILOVER_SECONDS = 120

ROLLBACK_METHODS: dict[ActionType, str | None] = {
    ActionType.STOP_EC2: "start_instance",
    ActionType.START_EC2: "stop_instance",
    ActionType.RESIZE_EC2: "restore_previous_instance_type",
    ActionType.RESIZE_RDS: "restore_previous_instance_class",
    ActionType.MODIFY_LAMBDA_MEMORY: "restore_previous_memory_size",
    ActionType.CHANGE_S3_STORAGE_CLASS: "restore_previous_storage_class",
    ActionType.CREATE_S3_LIFECYCLE_POLICY: "remove_lifecycle_rule",
    ActionType.CREATE_EBS_SNAPSHOT: "delete_snapshot",
    ActionType.MODIFY_EBS_VOLUME_TYPE: "restore_previous_volume_type",
    # A deleted volume is restored from its snapshot as a *new* volume with a
    # new id, so this is recovery, not rollback. Named honestly.
    ActionType.DELETE_EBS: "restore_volume_from_snapshot",
    # AWS does not guarantee you can reallocate a released address. There is
    # no rollback for this, and pretending otherwise would be the lie that
    # gets someone's allow-listed IP released.
    ActionType.RELEASE_ELASTIC_IP: None,
}


def simulate(
    resource: Resource,
    action_type: ActionType,
    parameters: dict,
    *,
    current_monthly_cost: float,
    confidence: float = 100.0,
    cost_source: str = "price_book",
) -> SimulationResult:
    projected, assumptions, priced_from = _project_cost(
        resource, action_type, parameters, current_monthly_cost, cost_source
    )

    savings = round(current_monthly_cost - projected, 2)
    savings_percent = (
        round(savings / current_monthly_cost * 100, 1) if current_monthly_cost > 0 else 0.0
    )

    downtime = _downtime(resource, action_type)
    rollback_method = ROLLBACK_METHODS.get(action_type)
    rollback_possible = rollback_method is not None

    assessment = risk_engine.assess(
        risk_engine.RiskInputs(
            action_type=action_type,
            resource=resource,
            confidence=confidence,
            rollback_possible=rollback_possible,
            restart_required=action_type.requires_restart,
            downtime_seconds=downtime,
            has_recent_backup=_has_recent_backup(resource),
            data_bearing=risk_engine.is_data_bearing(resource, action_type),
        )
    )

    return SimulationResult(
        current_monthly_cost=round(current_monthly_cost, 2),
        projected_monthly_cost=round(projected, 2),
        monthly_savings=savings,
        annual_savings=round(savings * 12, 2),
        savings_percent=savings_percent,
        restart_required=action_type.requires_restart,
        downtime_estimate_seconds=downtime,
        rollback_possible=rollback_possible,
        rollback_method=rollback_method,
        risk=assessment.level,
        performance_impact=_performance_impact(resource, action_type, parameters),
        assumptions=assumptions,
        priced_from=priced_from,
    )


# --------------------------------------------------------------------------


def _project_cost(
    resource: Resource,
    action_type: ActionType,
    parameters: dict,
    current_monthly_cost: float,
    cost_source: str,
) -> tuple[float, list[str], str]:
    """Cost after the action, with the assumptions that produced it."""
    assumptions: list[str] = []
    config = resource.configuration

    if action_type in (ActionType.STOP_EC2, ActionType.RELEASE_ELASTIC_IP):
        if action_type is ActionType.STOP_EC2:
            assumptions.append(
                "Stopping removes the compute charge. Attached EBS volumes "
                "continue to bill in full and are not included in this saving."
            )
        return 0.0, assumptions, cost_source

    if action_type is ActionType.DELETE_EBS:
        size_gb = config.get("size_gb", 0)
        snapshot_cost = round(size_gb * pricing.EBS_SNAPSHOT_GB_MONTH * 0.5, 2)
        assumptions.append(
            f"A snapshot is retained after deletion. Snapshots are billed on "
            f"changed blocks, so this assumes roughly half of {size_gb:g} GB is "
            f"stored, about ${snapshot_cost:,.2f}/month."
        )
        return snapshot_cost, assumptions, cost_source

    if action_type is ActionType.RESIZE_EC2:
        target = parameters.get("target_instance_type")
        current_type = config.get("instance_type")
        return _resize_projection(
            current_type,
            target,
            current_monthly_cost,
            cost_source,
            assumptions,
            pricing.ec2_monthly,
            "instance type",
        )

    if action_type is ActionType.RESIZE_RDS:
        target = parameters.get("target_instance_class")
        current_class = config.get("instance_class")
        multi_az = config.get("multi_az", False)
        storage_cost = config.get("allocated_storage_gb", 0) * 0.115
        current_price = pricing.rds_monthly(current_class, multi_az)
        target_price = pricing.rds_monthly(target, multi_az) if target else None
        if current_price is None or target_price is None:
            assumptions.append(
                f"No list price available for {current_class} or {target}; "
                f"savings cannot be projected."
            )
            return current_monthly_cost, assumptions, "unpriced"
        ratio = target_price.monthly / current_price.monthly
        compute_now = max(0.0, current_monthly_cost - storage_cost)
        assumptions.append(
            f"Storage is unchanged at ${storage_cost:,.2f}/month; only the "
            f"instance-class portion of the bill changes."
        )
        if multi_az:
            assumptions.append(
                "Multi-AZ is enabled, so both instances are resized and the "
                "saving applies to both."
            )
        return round(compute_now * ratio + storage_cost, 2), assumptions, cost_source

    if action_type is ActionType.MODIFY_LAMBDA_MEMORY:
        target_memory = parameters.get("target_memory_mb")
        current_memory = config.get("memory_mb")
        projected_duration = parameters.get("projected_duration_ms")
        monthly_invocations = parameters.get("monthly_invocations")
        if not all((target_memory, current_memory, projected_duration, monthly_invocations)):
            return current_monthly_cost, ["Insufficient data to project cost."], "unpriced"
        projected = pricing.lambda_monthly(
            target_memory, projected_duration, monthly_invocations
        ).monthly
        assumptions.append(
            f"Assumes duration rises to {projected_duration:,.0f} ms at "
            f"{target_memory} MB. Lambda bills memory x duration, so this "
            f"increase is already subtracted from the saving."
        )
        return projected, assumptions, cost_source

    if action_type in (
        ActionType.CHANGE_S3_STORAGE_CLASS,
        ActionType.CREATE_S3_LIFECYCLE_POLICY,
    ):
        projected = parameters.get("projected_monthly_cost")
        if projected is None:
            return current_monthly_cost, ["No projection available."], "unpriced"
        assumptions.append(
            "Includes Intelligent-Tiering monitoring charges where applicable. "
            "Excludes future retrieval charges, which depend on access patterns "
            "that have not yet happened."
        )
        transition = parameters.get("transition_cost")
        if transition:
            assumptions.append(
                f"A one-off transition cost of ${transition:,.2f} applies in the "
                f"first month."
            )
        return float(projected), assumptions, cost_source

    if action_type is ActionType.MODIFY_EBS_VOLUME_TYPE:
        size_gb = config.get("size_gb", 0)
        target_type = parameters.get("target_volume_type", "gp3")
        projected = pricing.ebs_monthly(target_type, size_gb, 3000).monthly
        assumptions.append(
            f"gp3 includes 3,000 IOPS and 125 MB/s at no extra charge. Observed "
            f"demand fits inside that, so no paid IOPS are added. Conversion "
            f"happens online with no detach and no downtime."
        )
        return projected, assumptions, cost_source

    if action_type is ActionType.CREATE_EBS_SNAPSHOT:
        size_gb = config.get("size_gb", 0)
        snapshot_cost = round(size_gb * pricing.EBS_SNAPSHOT_GB_MONTH * 0.5, 2)
        assumptions.append(
            "A snapshot adds cost rather than removing it. It is taken to make "
            "a later deletion safe."
        )
        return round(current_monthly_cost + snapshot_cost, 2), assumptions, cost_source

    return current_monthly_cost, ["No cost model for this action."], "unpriced"


def _resize_projection(
    current_type, target, current_monthly_cost, cost_source, assumptions, price_fn, label
):
    if not target:
        return current_monthly_cost, ["No target configuration specified."], "unpriced"
    current_price = price_fn(current_type)
    target_price = price_fn(target)
    if current_price is None or target_price is None:
        assumptions.append(
            f"No list price available for {current_type} or {target}, so the "
            f"saving cannot be projected."
        )
        return current_monthly_cost, assumptions, "unpriced"

    # Scale the observed bill by the list-price ratio rather than substituting
    # the list price outright. That keeps discounts, Savings Plans and RI
    # coverage reflected in the projection.
    ratio = target_price.monthly / current_price.monthly
    projected = round(current_monthly_cost * ratio, 2)
    if cost_source == "cost_explorer":
        assumptions.append(
            f"Projected by scaling the observed bill by the list-price ratio "
            f"between {current_type} and {target} ({ratio:.2f}), so existing "
            f"discounts and commitments carry through."
        )
    else:
        assumptions.append(
            f"Both figures are on-demand list prices for the {label}; any "
            f"Savings Plan or Reserved Instance coverage will change the real "
            f"saving."
        )
    return projected, assumptions, cost_source


def _downtime(resource: Resource, action_type: ActionType) -> int:
    base = DOWNTIME_ESTIMATES.get(action_type, 0)
    if action_type is ActionType.RESIZE_RDS and resource.configuration.get("multi_az"):
        # Multi-AZ resizes as a failover, which is far quicker than a restart.
        return RDS_MULTI_AZ_FAILOVER_SECONDS
    return base


def _performance_impact(
    resource: Resource, action_type: ActionType, parameters: dict
) -> str:
    if action_type is ActionType.RESIZE_EC2:
        target = parameters.get("target_instance_type", "")
        return (
            f"Moving to {target} reduces vCPU and memory. Observed utilization "
            f"leaves headroom at the new size, but any workload that scales with "
            f"available cores will run proportionally slower."
        )
    if action_type is ActionType.RESIZE_RDS:
        multi_az = resource.configuration.get("multi_az")
        return (
            f"Reduced CPU, memory and network throughput. "
            + (
                "Multi-AZ means the change happens as a failover of about two "
                "minutes of write unavailability."
                if multi_az
                else "Single-AZ means a full restart, so the database is "
                "unavailable for the duration."
            )
        )
    if action_type is ActionType.MODIFY_LAMBDA_MEMORY:
        return (
            "Less memory means proportionally less CPU, so invocations will take "
            "longer. Cold starts are also slower. The projected saving already "
            "accounts for the increased duration."
        )
    if action_type is ActionType.STOP_EC2:
        return "The instance stops serving entirely until it is started again."
    if action_type is ActionType.DELETE_EBS:
        return "No performance impact. The volume is attached to nothing."
    if action_type is ActionType.MODIFY_EBS_VOLUME_TYPE:
        return (
            "None. gp3 matches gp2 durability and delivers at least the same "
            "throughput for this volume's observed load. The conversion is "
            "online and the volume stays attached and readable throughout."
        )
    if action_type is ActionType.CHANGE_S3_STORAGE_CLASS:
        return (
            "Retrieval latency is unchanged for Intelligent-Tiering and Glacier "
            "Instant Retrieval. Retrieval requests carry a per-GB charge in the "
            "colder tiers."
        )
    if action_type is ActionType.RELEASE_ELASTIC_IP:
        return "No performance impact. The address serves no traffic."
    return "No measurable performance impact expected."


def _has_recent_backup(resource: Resource) -> bool:
    config = resource.configuration
    if resource.resource_type is ResourceType.EBS:
        age = config.get("latest_snapshot_age_days")
        return config.get("latest_snapshot_id") is not None and (age is None or age <= 30)
    if resource.resource_type is ResourceType.RDS:
        return (config.get("backup_retention_days") or 0) > 0
    return False


def compare(before: SimulationResult, after_cost: float) -> dict:
    """Projected against realized, used by the verification stage."""
    delta = round(after_cost - before.projected_monthly_cost, 2)
    within_tolerance = abs(delta) <= max(1.0, before.projected_monthly_cost * 0.1)
    return {
        "projected_monthly_cost": before.projected_monthly_cost,
        "observed_monthly_cost": round(after_cost, 2),
        "difference": delta,
        "within_tolerance": within_tolerance,
        "detail": (
            f"Projected ${before.projected_monthly_cost:,.2f}/month, observed "
            f"${after_cost:,.2f}/month "
            + ("(within tolerance)" if within_tolerance else "(outside 10% tolerance)")
        ),
    }
