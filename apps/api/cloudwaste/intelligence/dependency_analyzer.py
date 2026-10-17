"""Resource dependency analysis.

Answers "what else is connected to this, and what might break?" before a
change. Pure: it combines relationships already present in the scanned
inventory with `DependencyFacts` a provider fetched, and reasons over both.

Two rules shape every output:

  * **Absence of evidence is not evidence of absence.** Each resource type has
    categories of dependency worth knowing about. A category the provider did
    not inspect -- or was denied permission to -- is listed under
    `unknown_dependencies`, and `dependency_status` is PARTIAL or UNKNOWN,
    never COMPLETE.
  * **Advisory only.** The result carries `affects_risk: false`. It is shown
    to approvers and to the agent, but it does not feed the risk engine or the
    policy engine. Wiring it into risk floors is a separate, deliberately
    tested change; populating it must not silently shift approval outcomes.
"""

from __future__ import annotations

from ..adapters.base import DependencyFacts
from ..models.domain import Resource
from ..models.enums import ActionType, ResourceType

#: Dependency categories worth knowing about, per resource type.
EXPECTED_CATEGORIES: dict[ResourceType, tuple[str, ...]] = {
    ResourceType.EC2: (
        "ebs_volumes", "network_interfaces", "security_groups", "iam_instance_profile",
        "auto_scaling_group", "load_balancer_targets",
    ),
    ResourceType.EBS: ("attachment", "snapshots"),
    ResourceType.RDS: (
        "security_groups", "subnet_group", "read_replicas", "parameter_group",
        "application_clients",
    ),
    ResourceType.LAMBDA: ("event_sources", "vpc_config", "push_invokers"),
    ResourceType.NAT_GATEWAY: ("route_tables",),
    ResourceType.ELASTIC_IP: ("association", "external_allow_lists"),
    ResourceType.S3: ("bucket_policy", "replication", "event_notifications", "access_points"),
}

#: Relationship directions. `used_by` means something depends on this
#: resource, which is what makes changing it dangerous.
DEPENDENTS = ("used_by",)


def _inventory_relationships(resource: Resource, related: dict[str, Resource]) -> list[dict]:
    """Relationships visible in the scanned configuration, no API call needed."""
    config = resource.configuration
    out: list[dict] = []

    def add(type_, id_, relationship, direction, category, detail=""):
        out.append({
            "type": type_, "id": id_, "relationship": relationship, "direction": direction,
            "category": category, "detail": detail, "source": "inventory",
        })

    if resource.resource_type is ResourceType.EC2:
        for volume in config.get("attached_volumes") or []:
            add("EBS", volume, "attached volume", "uses", "ebs_volumes")
        if config.get("vpc_id"):
            add("VPC", config["vpc_id"], "runs in", "uses", "network")
        if config.get("subnet_id"):
            add("SUBNET", config["subnet_id"], "runs in", "uses", "network")
    elif resource.resource_type is ResourceType.EBS:
        if config.get("attached_to"):
            instance = related.get(config["attached_to"])
            add(
                "EC2", config["attached_to"], "attached to", "used_by", "attachment",
                f"instance is {instance.state}" if instance and instance.state else "",
            )
        if config.get("latest_snapshot_id"):
            age = config.get("latest_snapshot_age_days")
            add(
                "EBS_SNAPSHOT", config["latest_snapshot_id"], "latest snapshot", "backup",
                "snapshots", f"{age} days old" if age is not None else "age unknown",
            )
    elif resource.resource_type is ResourceType.NAT_GATEWAY:
        for table in config.get("route_tables_referencing") or []:
            add("ROUTE_TABLE", table, "routes through this gateway", "used_by", "route_tables")
        if config.get("vpc_id"):
            add("VPC", config["vpc_id"], "serves", "uses", "network")
    elif resource.resource_type is ResourceType.ELASTIC_IP:
        if config.get("instance_id"):
            add("EC2", config["instance_id"], "associated", "used_by", "association")
    return out


def analyze(
    resource: Resource,
    facts: DependencyFacts | None,
    related: dict[str, Resource] | None = None,
    action_type: ActionType | None = None,
) -> dict:
    related = related or {}
    facts = facts or DependencyFacts()

    relationships: list[dict] = []
    seen: set[tuple] = set()
    for rel in facts.relationships + _inventory_relationships(resource, related):
        key = (rel["type"], rel["id"], rel["direction"])
        if key in seen:
            continue
        seen.add(key)
        relationships.append(rel)

    expected = EXPECTED_CATEGORIES.get(resource.resource_type, ())
    checked = set(facts.checked)
    unknown: list[dict] = []
    reported_unknown = {u["category"] for u in facts.unknown}
    unknown.extend(facts.unknown)
    for category in expected:
        if category not in checked and category not in reported_unknown:
            unknown.append({"category": category, "reason": "Not inspected"})

    if not checked and not facts.relationships:
        status = "UNKNOWN"
    elif unknown:
        status = "PARTIAL"
    else:
        status = "COMPLETE"

    dependents = [r for r in relationships if r["direction"] in DEPENDENTS]
    warnings = _warnings(resource, action_type, dependents, unknown, relationships)

    return {
        "resource_id": resource.resource_id,
        "resource_type": resource.resource_type.value,
        "account_id": resource.account_id,
        "region": resource.region,
        "dependency_status": status,
        "dependency_count": len(relationships),
        "dependent_count": len(dependents),
        "dependencies": relationships,
        "unknown_dependencies": unknown,
        "categories_checked": sorted(checked),
        "warnings": warnings,
        "action_type": action_type.value if action_type else None,
        "advisory": True,
        "affects_risk": False,
        "note": (
            "Advisory. Categories listed as unknown were not inspected or could not "
            "be read; that is not evidence that nothing depends on this resource."
        ),
    }


def _warnings(
    resource: Resource,
    action: ActionType | None,
    dependents: list[dict],
    unknown: list[dict],
    relationships: list[dict],
) -> list[dict]:
    warnings: list[dict] = []
    destructive = bool(action and action.is_destructive)
    disruptive = bool(action and (action.is_destructive or action.requires_restart))

    for dep in dependents:
        warnings.append({
            "severity": "high" if destructive else ("medium" if disruptive else "info"),
            "message": (
                f"{dep['type']} {dep['id']} depends on this resource ({dep['relationship']})"
                + (f"; {dep['detail']}" if dep.get("detail") else "")
            ),
        })

    if unknown and disruptive:
        categories = ", ".join(u["category"] for u in unknown)
        warnings.append({
            "severity": "high" if destructive else "medium",
            "message": (
                f"Could not establish {categories}. Unknown is not the same as none: "
                f"confirm with the owner before this change."
            ),
        })

    if action is ActionType.DELETE_EBS and not any(
        r["type"] == "EBS_SNAPSHOT" for r in relationships
    ):
        warnings.append({
            "severity": "high",
            "message": "No snapshot of this volume was found. Deletion would be unrecoverable.",
        })
    if action is ActionType.RELEASE_ELASTIC_IP:
        warnings.append({
            "severity": "high",
            "message": "A released address cannot be reliably reclaimed. Anything outside "
            "AWS that allow-lists it will stop matching.",
        })
    if action in (ActionType.STOP_EC2, ActionType.RESIZE_EC2) and any(
        r["type"] == "PUBLIC_IP" for r in relationships
    ):
        warnings.append({
            "severity": "medium",
            "message": "The instance has an auto-assigned public IP, which changes when it "
            "stops. Clients that address it directly will lose it.",
        })
    if action in (ActionType.STOP_EC2, ActionType.RESIZE_EC2) and any(
        r["type"] == "AUTO_SCALING_GROUP" for r in relationships
    ):
        warnings.append({
            "severity": "high",
            "message": "The instance belongs to an Auto Scaling group, which may replace a "
            "stopped instance or undo a resize. Change the group, not the instance.",
        })
    return warnings
