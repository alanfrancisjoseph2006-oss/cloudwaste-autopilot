"""EBS waste detection.

Unattached volumes are the single most common finding in a real account, and
also the one most likely to cause harm if handled carelessly: `state=available`
tells you nothing about whether the data matters. This detector therefore
reports the volume but records the two facts that decide what happens next --
how long it has been detached, and whether a snapshot exists. The risk engine
blocks any deletion of a data-bearing volume with no backup, and the
recommendation engine proposes snapshot-then-delete rather than a bare delete.

It also detects gp2 volumes that should be gp3, which is a pure price change
with no downtime and no performance loss -- the safest saving in AWS.
"""

from __future__ import annotations

from ...adapters import pricing
from ...models.domain import Evidence, Finding
from ...models.enums import ResourceType, WasteType
from .. import waste_score
from .base import (
    DetectionContext,
    activity_evidence,
    build_finding,
    cost_evidence,
    metric_evidence,
    optimizer_evidence,
    standard_confidence_inputs,
    tag_evidence,
)

# Below this, a volume is doing nothing meaningful even while attached.
IDLE_OPS_PER_DAY = 100.0


class EbsDetector:
    name = "ebs_storage"
    resource_type = ResourceType.EBS

    def detect(self, context: DetectionContext) -> list[Finding]:
        resource = context.resource
        if resource.state == "available":
            finding = self._detect_unattached(context)
            return [finding] if finding else []

        # Attached volumes: either the instance they hang off is switched off
        # and still costing storage, or the volume type itself is suboptimal.
        finding = self._detect_attached_to_stopped_instance(
            context
        ) or self._detect_gp2_upgrade(context)
        return [finding] if finding else []

    # ------------------------------------------------------------------

    def _detect_unattached(self, context: DetectionContext) -> Finding | None:
        resource = context.resource
        config = resource.configuration
        detached_days = config.get("detached_days")
        if detached_days is None:
            detached_days = context.days_since_last_write or resource.age_days

        if detached_days < context.settings.min_observation_days:
            return None

        snapshot_id = config.get("latest_snapshot_id")
        snapshot_age = config.get("latest_snapshot_age_days")
        size_gb = config.get("size_gb", 0)

        evidence = [
            Evidence(
                source="resource_config",
                metric="volume_state",
                value="available",
                detail=(
                    f"Volume is in state 'available', meaning it is attached to no "
                    f"instance, and has been for about {detached_days:.0f} days"
                ),
            ),
            Evidence(
                source="resource_config",
                metric="size_gb",
                value=size_gb,
                unit="GB",
                detail=(
                    f"{size_gb:g} GB {config.get('volume_type', 'unknown')} volume, "
                    f"{'encrypted' if config.get('encrypted') else 'not encrypted'}"
                ),
            ),
            cost_evidence(context),
            tag_evidence(resource),
        ]

        if snapshot_id:
            evidence.append(
                Evidence(
                    source="resource_config",
                    metric="latest_snapshot",
                    value=snapshot_id,
                    detail=(
                        f"A snapshot ({snapshot_id}) taken {snapshot_age} days ago "
                        f"exists, so the data is recoverable after deletion"
                    ),
                )
            )
        else:
            evidence.append(
                Evidence(
                    source="resource_config",
                    metric="latest_snapshot",
                    value=None,
                    detail=(
                        "No snapshot exists for this volume. Deleting it would be "
                        "irreversible, so a snapshot must be taken first"
                    ),
                )
            )

        activity = activity_evidence(context)
        if activity:
            evidence.append(activity)

        return build_finding(
            context,
            waste_type=WasteType.UNATTACHED_STORAGE,
            title=f"Unattached volume {resource.resource_id} ({size_gb:g} GB)",
            summary=(
                f"This {size_gb:g} GB volume has been unattached for about "
                f"{detached_days:.0f} days and is billed in full while attached to "
                f"nothing. "
                + (
                    f"A snapshot from {snapshot_age} days ago exists, so the data "
                    f"can be recovered if it is ever needed."
                    if snapshot_id
                    else "No snapshot exists, so it must be snapshotted before deletion."
                )
            ),
            evidence=evidence,
            potential_monthly_savings=context.monthly_cost,
            detector=self.name,
            score_inputs=waste_score.ScoreInputs(
                utilization_ratio=0.0,
                monthly_cost=context.monthly_cost,
                idle_days=detached_days,
                age_days=resource.age_days,
                aws_recommendation_savings_percent=(
                    context.optimizer.estimated_savings_percent if context.optimizer else None
                ),
            ),
            confidence_inputs=standard_confidence_inputs(
                context,
                corroborating_signals=3,
                memory_metric_missing=False,
                metrics_not_applicable=True,
            ),
        )

    def _detect_attached_to_stopped_instance(
        self, context: DetectionContext
    ) -> Finding | None:
        """A stopped instance bills nothing for compute but its volumes are
        charged in full, which is invisible on a per-instance cost view and is
        why long-stopped instances quietly accumulate cost."""
        resource = context.resource
        attached_to = resource.configuration.get("attached_to")
        if not attached_to:
            return None
        instance = context.related_resources.get(attached_to)
        if instance is None or instance.state != "stopped":
            return None

        stopped_days = context.days_since_last_write or instance.age_days
        if stopped_days < context.settings.min_observation_days:
            return None

        size_gb = resource.configuration.get("size_gb", 0)
        return build_finding(
            context,
            waste_type=WasteType.SCHEDULED_RUNTIME_WASTE,
            title=(
                f"Volume {resource.resource_id} bills in full while its instance "
                f"is stopped"
            ),
            summary=(
                f"This {size_gb:g} GB volume is attached to {attached_to} "
                f"({instance.name or 'unnamed'}), which has been stopped for about "
                f"{stopped_days:.0f} days. The instance costs nothing while stopped, "
                f"but the volume is charged in full at "
                f"${context.monthly_cost:,.2f}/month. Either the instance is coming "
                f"back, in which case nothing needs doing, or it is not, in which "
                f"case snapshotting and deleting both recovers the whole amount."
            ),
            evidence=[
                Evidence(
                    source="resource_config",
                    metric="attached_instance_state",
                    value="stopped",
                    detail=(
                        f"Attached to {attached_to}, which is in state 'stopped' "
                        f"and has been for about {stopped_days:.0f} days"
                    ),
                ),
                Evidence(
                    source="resource_config",
                    metric="size_gb",
                    value=size_gb,
                    unit="GB",
                    detail=(
                        f"{size_gb:g} GB "
                        f"{resource.configuration.get('volume_type', 'unknown')} volume"
                    ),
                ),
                cost_evidence(context),
                tag_evidence(resource),
            ],
            potential_monthly_savings=context.monthly_cost,
            detector=self.name,
            score_inputs=waste_score.ScoreInputs(
                utilization_ratio=0.0,
                monthly_cost=context.monthly_cost,
                idle_days=stopped_days,
                age_days=resource.age_days,
            ),
            confidence_inputs=standard_confidence_inputs(
                context, corroborating_signals=2, memory_metric_missing=False
            ),
        )

    def _detect_gp2_upgrade(self, context: DetectionContext) -> Finding | None:
        resource = context.resource
        config = resource.configuration
        if config.get("volume_type") != "gp2":
            return None

        size_gb = config.get("size_gb", 0)
        current = pricing.ebs_monthly("gp2", size_gb)
        target = pricing.ebs_monthly("gp3", size_gb, 3000)
        savings = round(current.monthly - target.monthly, 2)
        if savings < context.settings.min_monthly_savings_to_report:
            return None

        # gp3's included 3000 IOPS must actually cover observed demand.
        read_ops = context.series("read_ops")
        write_ops = context.series("write_ops")
        observed_iops = 0.0
        if read_ops or write_ops:
            period = (read_ops or write_ops).period_seconds
            peak_ops = max(
                (read_ops.maximum if read_ops else 0.0),
                (write_ops.maximum if write_ops else 0.0),
            )
            observed_iops = peak_ops / period
        if observed_iops > 2800:
            return None  # would need paid IOPS on gp3; not a clean win

        evidence = [
            Evidence(
                source="resource_config",
                metric="volume_type",
                value="gp2",
                detail=(
                    f"{size_gb:g} GB gp2 volume. gp3 delivers the same durability "
                    f"at a lower per-GB price with 3,000 IOPS included"
                ),
            ),
            cost_evidence(context),
            tag_evidence(resource),
        ]
        if read_ops:
            evidence.append(metric_evidence(read_ops, "VolumeReadOps", statistic="total"))
        if write_ops:
            evidence.append(metric_evidence(write_ops, "VolumeWriteOps", statistic="total"))
        evidence.append(
            Evidence(
                source="cloudwatch",
                metric="peak_iops",
                value=round(observed_iops, 1),
                unit="IOPS",
                detail=(
                    f"Peak observed demand of about {observed_iops:,.0f} IOPS fits "
                    f"inside the 3,000 IOPS gp3 includes at no extra charge"
                ),
            )
        )
        if context.optimizer:
            evidence.append(optimizer_evidence(context.optimizer))

        return build_finding(
            context,
            waste_type=WasteType.CONFIGURATION_INEFFICIENCY,
            title=f"Volume {resource.resource_id} should be gp3 rather than gp2",
            summary=(
                f"This {size_gb:g} GB volume uses gp2. Converting it to gp3 saves "
                f"about ${savings:,.2f}/month at identical size and durability, with "
                f"no downtime and no reduction in performance for its observed load."
            ),
            evidence=evidence,
            potential_monthly_savings=savings,
            detector=self.name,
            score_inputs=waste_score.ScoreInputs(
                monthly_cost=context.monthly_cost,
                age_days=resource.age_days,
                aws_recommendation_savings_percent=round(
                    savings / current.monthly * 100, 1
                ),
            ),
            confidence_inputs=standard_confidence_inputs(
                context, corroborating_signals=2, memory_metric_missing=False
            ),
        )
