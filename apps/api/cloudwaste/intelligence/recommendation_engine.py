"""Turning findings into proposed actions.

A finding says "this is wasteful". A recommendation says "do exactly this".
The gap between them is where safety lives, and this module's job is to be
conservative inside it:

  * Some findings get no recommendation at all. A NAT gateway with low traffic
    and a live route table gets investigation steps, not a delete. A cost
    anomaly gets nothing, because "spend went up" has no safe generic fix.
  * Destructive actions are decomposed. Deleting an unbacked volume becomes a
    snapshot first, then a delete that depends on it, never a bare delete.
  * The recommended target always comes from AWS when AWS has an opinion,
    because Compute Optimizer profiles the real workload and our price-book
    ladder only knows what things cost.
"""

from __future__ import annotations

import logging

from ..adapters import pricing
from ..models.domain import Finding, Recommendation, Resource
from ..models.enums import ActionType, ResourceType, WasteType
from . import impact_analyzer
from .backups import has_recent_backup

logger = logging.getLogger(__name__)


class RecommendationEngine:
    def build(
        self, finding: Finding, resource: Resource, context: dict | None = None
    ) -> list[Recommendation]:
        """Zero, one or several recommendations for a finding.

        Several means an ordered chain: index 0 must complete before index 1
        starts. The action layer enforces that ordering.
        """
        # The detector's own computed values take precedence: it did the
        # modelling with the metrics in hand.
        context = {**(context or {}), **finding.action_context}
        builder = {
            WasteType.IDLE_RESOURCE: self._for_idle,
            WasteType.UNDERUTILIZED_RESOURCE: self._for_rightsizing,
            WasteType.OVERPROVISIONED_RESOURCE: self._for_rightsizing,
            WasteType.UNATTACHED_STORAGE: self._for_unattached_storage,
            WasteType.SCHEDULED_RUNTIME_WASTE: self._for_stopped_instance_storage,
            WasteType.STORAGE_LIFECYCLE_WASTE: self._for_s3_lifecycle,
            WasteType.CONFIGURATION_INEFFICIENCY: self._for_configuration,
            WasteType.UNUSED_NETWORK_RESOURCE: self._for_network,
            # Deliberately absent: COST_ANOMALY and DUPLICATE_RESOURCE have no
            # safe generic action.
        }.get(finding.waste_type)

        if builder is None:
            return []
        try:
            return builder(finding, resource, context)
        except Exception:  # noqa: BLE001
            logger.exception("recommendation build failed for %s", finding.finding_id)
            return []

    # ------------------------------------------------------------------

    def _for_idle(self, finding, resource, context) -> list[Recommendation]:
        if resource.resource_type is ResourceType.EC2:
            # Stop rather than terminate. Stopping is reversible and recovers
            # the whole compute charge; terminating is not and recovers only a
            # little more. The asymmetry decides it.
            return [
                self._make(
                    finding,
                    resource,
                    ActionType.STOP_EC2,
                    current_configuration=f"{resource.configuration.get('instance_type')} (running)",
                    recommended_configuration=f"{resource.configuration.get('instance_type')} (stopped)",
                    parameters={},
                    rationale=(
                        "Stopping recovers the full compute charge and is fully "
                        "reversible. Termination would recover only the small "
                        "remainder and cannot be undone, so it is not proposed "
                        "automatically. Attached volumes continue to bill and are "
                        "reported separately."
                    ),
                )
            ]

        if resource.resource_type is ResourceType.RDS:
            # An idle database is the case where the tool should say less, not
            # more. Deleting it needs a human who knows what the data is.
            return []

        if resource.resource_type is ResourceType.LAMBDA:
            return []  # an uninvoked function costs nothing; deletion is hygiene

        return []

    def _for_rightsizing(self, finding, resource, context) -> list[Recommendation]:
        optimizer = context.get("optimizer")

        if resource.resource_type is ResourceType.EC2:
            target = self._target_from(optimizer) or pricing.step_down(
                resource.configuration.get("instance_type", ""), 1
            )
            if not target:
                return []
            return [
                self._make(
                    finding,
                    resource,
                    ActionType.RESIZE_EC2,
                    current_configuration=resource.configuration.get("instance_type", ""),
                    recommended_configuration=target,
                    parameters={"target_instance_type": target},
                    rationale=self._rightsizing_rationale(finding, optimizer, target),
                )
            ]

        if resource.resource_type is ResourceType.RDS:
            target = self._target_from(optimizer) or pricing.step_down(
                resource.configuration.get("instance_class", ""), 1
            )
            if not target:
                return []
            return [
                self._make(
                    finding,
                    resource,
                    ActionType.RESIZE_RDS,
                    current_configuration=resource.configuration.get("instance_class", ""),
                    recommended_configuration=target,
                    parameters={"target_instance_class": target},
                    rationale=self._rightsizing_rationale(finding, optimizer, target)
                    + (
                        " Multi-AZ is enabled, so the change applies as a failover."
                        if resource.configuration.get("multi_az")
                        else " Single-AZ, so the database restarts and is briefly "
                        "unavailable."
                    ),
                )
            ]

        if resource.resource_type is ResourceType.LAMBDA:
            target_memory = context.get("target_memory_mb")
            if target_memory is None and optimizer:
                try:
                    target_memory = int(optimizer.recommended_configuration.split()[0])
                except (ValueError, IndexError, AttributeError):
                    target_memory = None
            if not target_memory:
                return []
            return [
                self._make(
                    finding,
                    resource,
                    ActionType.MODIFY_LAMBDA_MEMORY,
                    current_configuration=f"{resource.configuration.get('memory_mb')} MB",
                    recommended_configuration=f"{target_memory} MB",
                    parameters={
                        "target_memory_mb": target_memory,
                        "projected_duration_ms": context.get("projected_duration_ms"),
                        "monthly_invocations": context.get("monthly_invocations"),
                    },
                    rationale=(
                        "Lambda allocates CPU in proportion to memory, so the "
                        "projected saving already accounts for invocations taking "
                        "longer at the smaller size. The change takes effect on the "
                        "next invocation with no downtime."
                    ),
                )
            ]

        return []

    def _for_unattached_storage(self, finding, resource, context) -> list[Recommendation]:
        config = resource.configuration
        snapshot_is_current = has_recent_backup(resource)

        delete = self._make(
            finding,
            resource,
            ActionType.DELETE_EBS,
            current_configuration=(
                f"{config.get('size_gb')} GB {config.get('volume_type')} (available)"
            ),
            recommended_configuration="deleted, snapshot retained",
            parameters={"require_snapshot": True},
            rationale=(
                "The volume is attached to nothing and bills in full. Deleting it "
                "recovers the entire charge. The snapshot is retained so the data "
                "can be restored, though as a new volume with a new id rather than "
                "as a true rollback."
            ),
        )

        if snapshot_is_current:
            return [delete]

        # No usable snapshot: insert one first and make the delete depend on it.
        snapshot = self._make(
            finding,
            resource,
            ActionType.CREATE_EBS_SNAPSHOT,
            current_configuration="no current snapshot",
            recommended_configuration="snapshot created",
            parameters={"description": f"CloudWaste pre-deletion snapshot of {resource.resource_id}"},
            rationale=(
                "No current snapshot exists, so deletion would be irreversible. "
                "This snapshot makes the deletion recoverable and must complete "
                "before it runs. It adds a small monthly storage charge."
            ),
        )
        delete.action_parameters["depends_on"] = snapshot.recommendation_id
        delete.rationale = (
            "Runs only after the snapshot above completes successfully. "
            + delete.rationale
        )
        return [snapshot, delete]

    def _for_stopped_instance_storage(
        self, finding, resource, context
    ) -> list[Recommendation]:
        # The instance is stopped, not gone, so its volume may still be wanted.
        # Snapshot-and-delete is a decision about the instance's future, which
        # is the owner's to make. Report only.
        return []

    def _for_s3_lifecycle(self, finding, resource, context) -> list[Recommendation]:
        projected = context.get("projected_monthly_cost")
        target_class = context.get("target_storage_class", "INTELLIGENT_TIERING")
        if projected is None:
            projected = max(0.0, finding.monthly_cost - finding.potential_monthly_savings)

        return [
            self._make(
                finding,
                resource,
                ActionType.CREATE_S3_LIFECYCLE_POLICY,
                current_configuration="STANDARD, no lifecycle rule",
                recommended_configuration=f"lifecycle rule to {target_class}",
                parameters={
                    "target_storage_class": target_class,
                    "transition_days": 90,
                    "projected_monthly_cost": projected,
                    "transition_cost": context.get("transition_cost"),
                },
                rationale=(
                    "A lifecycle rule is preferred over a one-off bulk copy: it "
                    "applies continuously to new objects, needs no data movement "
                    "job, and is removed by deleting the rule. Existing objects "
                    "transition on their next evaluation."
                ),
            )
        ]

    def _for_configuration(self, finding, resource, context) -> list[Recommendation]:
        if (
            resource.resource_type is ResourceType.EBS
            and resource.configuration.get("volume_type") == "gp2"
        ):
            size_gb = resource.configuration.get("size_gb", 0)
            return [
                self._make(
                    finding,
                    resource,
                    ActionType.MODIFY_EBS_VOLUME_TYPE,
                    current_configuration=f"gp2, {size_gb:g} GB",
                    recommended_configuration=f"gp3, {size_gb:g} GB, 3000 IOPS",
                    parameters={
                        "target_volume_type": "gp3",
                        "target_iops": 3000,
                        "target_throughput": 125,
                    },
                    rationale=(
                        "gp3 costs less per GB than gp2 and includes 3,000 IOPS and "
                        "125 MB/s at no extra charge, which covers this volume's "
                        "observed demand. The conversion happens online: the volume "
                        "stays attached and readable, there is no downtime, and it "
                        "can be converted back the same way. This is the lowest-risk "
                        "saving available in AWS."
                    ),
                )
            ]
        return []

    def _for_network(self, finding, resource, context) -> list[Recommendation]:
        if resource.resource_type is ResourceType.ELASTIC_IP:
            return [
                self._make(
                    finding,
                    resource,
                    ActionType.RELEASE_ELASTIC_IP,
                    current_configuration=(
                        f"{resource.configuration.get('public_ip')} (unassociated)"
                    ),
                    recommended_configuration="released",
                    parameters={
                        "public_ip": resource.configuration.get("public_ip")
                    },
                    rationale=(
                        "The address is attached to nothing and is charged hourly. "
                        "Releasing is immediate. It cannot be undone: AWS does not "
                        "guarantee the same address can be allocated again, so "
                        "confirm nothing external depends on it."
                    ),
                )
            ]

        if resource.resource_type is ResourceType.NAT_GATEWAY:
            # No recommendation by design -- see the detector's docstring. Low
            # throughput does not establish that the gateway is unused.
            return []

        return []

    # ------------------------------------------------------------------

    def _make(
        self,
        finding: Finding,
        resource: Resource,
        action_type: ActionType,
        *,
        current_configuration: str,
        recommended_configuration: str,
        parameters: dict,
        rationale: str,
    ) -> Recommendation:
        # Priced from the finding's own cost and its own source, so the
        # projection and the current cost come from the same place. The
        # simulate endpoint re-runs exactly this call.
        simulation = impact_analyzer.simulate(
            resource,
            action_type,
            parameters,
            current_monthly_cost=finding.monthly_cost,
            confidence=finding.confidence,
            cost_source=finding.cost_source,
        )
        return Recommendation(
            finding_id=finding.finding_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            account_id=resource.account_id,
            region=resource.region,
            action_type=action_type,
            current_configuration=current_configuration,
            recommended_configuration=recommended_configuration,
            action_parameters=parameters,
            monthly_savings=simulation.monthly_savings,
            annual_savings=simulation.annual_savings,
            confidence=finding.confidence,
            risk=simulation.risk,
            restart_required=simulation.restart_required,
            rollback_possible=simulation.rollback_possible,
            rationale=rationale,
            simulation=simulation,
        )

    @staticmethod
    def _target_from(optimizer) -> str | None:
        if optimizer is None:
            return None
        target = (optimizer.recommended_configuration or "").strip()
        return target or None

    @staticmethod
    def _rightsizing_rationale(finding, optimizer, target) -> str:
        if optimizer:
            return (
                f"AWS reports this resource as '{optimizer.finding}' after "
                f"{optimizer.lookback_days or 14} days of profiling and recommends "
                f"{target}. CloudWaste's own utilization analysis agrees, and the "
                f"finding carries {finding.confidence:.0f}% confidence."
            )
        return (
            f"AWS has published no recommendation for this resource, so {target} "
            f"is one size down in the same family. Observed utilization leaves "
            f"headroom at that size, but with no AWS corroboration this warrants "
            f"a closer look before execution."
        )
