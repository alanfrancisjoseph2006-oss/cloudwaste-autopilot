"""RDS waste detection.

Databases get the most conservative treatment in the system. A resize means a
failover or a restart, the blast radius is every application holding a
connection, and the rollback is another restart. So this detector requires more
agreement than the others before it will speak: CPU *and* connections *and*
IOPS must all be low, over the full window.

The one case it treats as clear-cut is a database nobody is connected to. Zero
connections over two weeks is not a rightsizing signal, it is an abandonment
signal, and it is reported as idle.
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

IDLE_CONNECTION_THRESHOLD = 1.0
LOW_CPU_THRESHOLD = 25.0
LOW_IOPS_THRESHOLD = 100.0


class RdsDetector:
    name = "rds_utilization"
    resource_type = ResourceType.RDS

    def detect(self, context: DetectionContext) -> list[Finding]:
        resource = context.resource
        if resource.state not in (None, "available"):
            return []
        if resource.age_days < context.settings.min_observation_days:
            return []

        cpu = context.series("cpu")
        connections = context.series("connections")
        connections_max = context.series("connections_max")
        if cpu is None or connections is None:
            return []

        finding = self._detect_idle(
            context, cpu, connections, connections_max
        ) or self._detect_oversized(context, cpu, connections, connections_max)
        return [finding] if finding else []

    # ------------------------------------------------------------------

    def _detect_idle(self, context, cpu, connections, connections_max) -> Finding | None:
        peak_connections = connections_max.maximum if connections_max else connections.maximum
        if peak_connections >= IDLE_CONNECTION_THRESHOLD * 3:
            return None
        if connections.average >= IDLE_CONNECTION_THRESHOLD:
            return None

        resource = context.resource
        config = resource.configuration

        evidence = [
            metric_evidence(connections, "DatabaseConnections", unit="Count"),
            cost_evidence(context),
            tag_evidence(resource),
            Evidence(
                source="cloudwatch",
                metric="DatabaseConnections peak",
                value=round(peak_connections, 2),
                unit="Count",
                window_days=context.window_days,
                detail=(
                    f"Peak connection count over {context.observation_days():.0f} days "
                    f"was {peak_connections:.0f}. A database serving an application "
                    f"does not look like this"
                ),
            ),
            metric_evidence(cpu, "CPUUtilization", unit="Percent"),
            Evidence(
                source="resource_config",
                metric="engine",
                value=f"{config.get('engine')} {config.get('engine_version')}",
                detail=(
                    f"{config.get('instance_class')} running "
                    f"{config.get('engine')} {config.get('engine_version')}, "
                    f"{config.get('allocated_storage_gb')} GB allocated, "
                    f"backup retention {config.get('backup_retention_days')} day(s)"
                ),
            ),
        ]
        activity = activity_evidence(context)
        if activity:
            evidence.append(activity)
        if context.optimizer:
            evidence.append(optimizer_evidence(context.optimizer))

        return build_finding(
            context,
            waste_type=WasteType.IDLE_RESOURCE,
            title=f"Database {resource.resource_id} has no active connections",
            summary=(
                f"Over {context.observation_days():.0f} days this database averaged "
                f"{connections.average:.2f} connections with a peak of "
                f"{peak_connections:.0f}, and CPU averaged {cpu.average:.1f}%. "
                f"Nothing appears to be using it. Before any deletion it should be "
                f"snapshotted and its owner asked to confirm."
            ),
            evidence=evidence,
            potential_monthly_savings=context.monthly_cost,
            detector=self.name,
            score_inputs=waste_score.ScoreInputs(
                utilization_ratio=cpu.average / 100.0,
                monthly_cost=context.monthly_cost,
                idle_days=min(resource.age_days, context.observation_days()),
                age_days=resource.age_days,
                aws_recommendation_savings_percent=(
                    context.optimizer.estimated_savings_percent if context.optimizer else None
                ),
            ),
            confidence_inputs=standard_confidence_inputs(
                context, corroborating_signals=3, memory_metric_missing=False
            ),
        )

    def _detect_oversized(self, context, cpu, connections, connections_max) -> Finding | None:
        resource = context.resource
        config = resource.configuration
        instance_class = config.get("instance_class", "")

        read_iops = context.series("read_iops")
        write_iops = context.series("write_iops")
        total_iops = (read_iops.average if read_iops else 0.0) + (
            write_iops.average if write_iops else 0.0
        )

        # All three must agree. Any one alone is not enough to restart a database.
        cpu_low = cpu.percentile(95) < LOW_CPU_THRESHOLD
        iops_low = total_iops < LOW_IOPS_THRESHOLD * 10
        connections_low = (connections_max.maximum if connections_max else 0.0) < 200

        if not (cpu_low and iops_low and connections_low):
            return None

        target, savings, basis = self._downsize_target(context, instance_class, config)
        if target is None or savings < context.settings.min_monthly_savings_to_report:
            return None

        evidence = [
            metric_evidence(cpu, "CPUUtilization", unit="Percent"),
            metric_evidence(cpu, "CPUUtilization p95", statistic="p95", unit="Percent"),
            metric_evidence(connections, "DatabaseConnections", unit="Count"),
            Evidence(
                source="cloudwatch",
                metric="TotalIOPS",
                value=round(total_iops, 1),
                unit="IOPS",
                window_days=context.window_days,
                detail=f"Combined read and write IOPS averaged {total_iops:,.0f}",
            ),
            cost_evidence(context),
            tag_evidence(resource),
        ]
        if context.optimizer:
            evidence.append(optimizer_evidence(context.optimizer))
        if config.get("multi_az"):
            evidence.append(
                Evidence(
                    source="resource_config",
                    metric="multi_az",
                    value=True,
                    detail=(
                        "Multi-AZ is enabled, so a resize performs a failover. "
                        "Expect roughly 60-120 seconds of write unavailability"
                    ),
                )
            )

        return build_finding(
            context,
            waste_type=WasteType.OVERPROVISIONED_RESOURCE,
            title=f"Database {resource.resource_id} is oversized ({instance_class})",
            summary=(
                f"CPU p95 is {cpu.percentile(95):.1f}%, connections peak at "
                f"{(connections_max.maximum if connections_max else 0):.0f}, and "
                f"combined IOPS average {total_iops:,.0f} over "
                f"{context.observation_days():.0f} days. {basis} Moving to {target} "
                f"would save about ${savings:,.2f}/month."
                + (
                    " This is a production database, so the change requires approval "
                    "and a maintenance window."
                    if resource.is_production
                    else ""
                )
            ),
            evidence=evidence,
            potential_monthly_savings=savings,
            detector=self.name,
            score_inputs=waste_score.ScoreInputs(
                utilization_ratio=cpu.percentile(95) / 100.0,
                monthly_cost=context.monthly_cost,
                age_days=resource.age_days,
                aws_recommendation_savings_percent=(
                    context.optimizer.estimated_savings_percent if context.optimizer else None
                ),
            ),
            confidence_inputs=standard_confidence_inputs(
                context, corroborating_signals=3, memory_metric_missing=False
            ),
        )

    @staticmethod
    def _downsize_target(
        context: DetectionContext, instance_class: str, config: dict
    ) -> tuple[str | None, float, str]:
        optimizer = context.optimizer
        if optimizer and optimizer.recommended_configuration:
            return (
                optimizer.recommended_configuration,
                optimizer.estimated_monthly_savings,
                f"AWS reports this database as '{optimizer.finding}'.",
            )
        target = pricing.step_down(instance_class, 1)
        if target is None:
            return None, 0.0, ""
        multi_az = config.get("multi_az", False)
        current = pricing.rds_monthly(instance_class, multi_az)
        proposed = pricing.rds_monthly(target, multi_az)
        if current is None or proposed is None:
            return None, 0.0, ""
        return (
            target,
            round(current.monthly - proposed.monthly, 2),
            "AWS has no recommendation for this database, so the target is one "
            "size down in the same family.",
        )
