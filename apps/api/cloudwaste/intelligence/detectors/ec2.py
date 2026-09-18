"""EC2 waste detection.

Three distinct findings, in priority order, and at most one per instance:

  IDLE            nothing is using it at all
  UNDERUTILIZED   it is doing real work, but far less than it is sized for
  OVERPROVISIONED AWS has named a smaller instance that fits

They are mutually exclusive on purpose. An instance that is both idle and
oversized is idle -- reporting both would double-count the same dollars in the
savings total, which is the fastest way to lose a FinOps tool's credibility.

The decision uses p95 rather than average CPU. An instance averaging 8% but
peaking to 95% every night is a batch worker, not waste, and average alone
cannot tell the two apart.
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

# A stopped instance costs nothing for compute, so its waste lives on its
# volumes and is the EBS detector's business, not ours.
_SKIP_STATES = {"stopped", "stopping", "terminated", "shutting-down"}


class Ec2Detector:
    name = "ec2_utilization"
    resource_type = ResourceType.EC2

    def detect(self, context: DetectionContext) -> list[Finding]:
        resource = context.resource
        settings = context.settings

        if resource.state in _SKIP_STATES:
            return []

        cpu = context.series("cpu")
        if cpu is None:
            # No CPU metric at all for a running instance is itself worth
            # knowing, but it is a monitoring gap, not a waste finding.
            return []

        if resource.age_days < settings.min_observation_days:
            return []

        cpu_avg = cpu.average
        cpu_p95 = cpu.percentile(95)
        cpu_max = cpu.maximum

        network_mb_day = self._network_mb_per_day(context)
        memory = context.series("memory")
        instance_type = resource.configuration.get("instance_type", "unknown")

        # A workload whose peak is far above its mean is periodic. Averages
        # mislead there, so the confidence engine is told to discount.
        spiky = cpu_max > max(3.0 * cpu_avg, 40.0) and cpu_avg > 0

        finding = (
            self._detect_idle(context, cpu, cpu_avg, cpu_p95, network_mb_day, spiky)
            or self._detect_underutilized(
                context, cpu, cpu_avg, cpu_p95, network_mb_day, memory, instance_type, spiky
            )
            or self._detect_overprovisioned(context, cpu, cpu_avg, cpu_p95, instance_type, spiky)
        )
        return [finding] if finding else []

    # ------------------------------------------------------------------

    def _detect_idle(
        self, context, cpu, cpu_avg, cpu_p95, network_mb_day, spiky
    ) -> Finding | None:
        settings = context.settings
        resource = context.resource

        network_threshold_mb = settings.idle_network_bytes_per_day / 1_000_000.0
        if not (
            cpu_avg < settings.idle_cpu_threshold
            and cpu_p95 < settings.idle_cpu_threshold * 2
            and network_mb_day < network_threshold_mb
            and resource.age_days > settings.min_observation_days
        ):
            return None

        idle_days = min(resource.age_days, context.observation_days())
        if context.days_since_last_write is not None:
            idle_days = min(idle_days, context.days_since_last_write)

        evidence = [
            metric_evidence(cpu, "CPUUtilization", unit="Percent"),
            metric_evidence(cpu, "CPUUtilization p95", statistic="p95", unit="Percent"),
            cost_evidence(context),
            tag_evidence(resource),
        ]
        network_series = context.series("network_in")
        if network_series:
            evidence.append(
                Evidence(
                    source="cloudwatch",
                    metric="NetworkIn+NetworkOut",
                    value=round(network_mb_day, 2),
                    unit="MB/day",
                    window_days=context.window_days,
                    detail=(
                        f"Combined network traffic of {network_mb_day:,.1f} MB/day, "
                        f"below the {network_threshold_mb:,.0f} MB/day idle threshold"
                    ),
                )
            )
        activity = activity_evidence(context)
        if activity:
            evidence.append(activity)
        if context.optimizer:
            evidence.append(optimizer_evidence(context.optimizer))

        savings = context.monthly_cost  # stopping recovers the whole compute charge

        return build_finding(
            context,
            waste_type=WasteType.IDLE_RESOURCE,
            title=f"{resource.name or resource.resource_id} is idle",
            summary=(
                f"CPU has averaged {cpu_avg:.1f}% with a 95th percentile of "
                f"{cpu_p95:.1f}% and network traffic of {network_mb_day:,.1f} MB/day "
                f"over {context.observation_days():.0f} days. The instance has been "
                f"running for {resource.age_days:.0f} days and shows no sign of "
                f"serving a workload."
            ),
            evidence=evidence,
            potential_monthly_savings=savings,
            detector=self.name,
            score_inputs=waste_score.ScoreInputs(
                utilization_ratio=cpu_avg / 100.0,
                monthly_cost=context.monthly_cost,
                idle_days=idle_days,
                age_days=resource.age_days,
                aws_recommendation_savings_percent=(
                    context.optimizer.estimated_savings_percent if context.optimizer else None
                ),
            ),
            confidence_inputs=standard_confidence_inputs(
                context,
                corroborating_signals=3 if network_series else 2,
                metric_variance_high=spiky,
                seasonal_pattern_suspected=spiky,
            ),
        )

    def _detect_underutilized(
        self, context, cpu, cpu_avg, cpu_p95, network_mb_day, memory, instance_type, spiky
    ) -> Finding | None:
        settings = context.settings
        resource = context.resource

        if cpu_p95 >= settings.underutilized_cpu_threshold:
            return None
        if memory is not None and memory.percentile(95) > 75.0:
            # Memory-bound workload: CPU is the wrong signal and downsizing on
            # it would cause an outage.
            return None

        target, savings, basis = self._downsize_target(context, instance_type)
        if target is None or savings < settings.min_monthly_savings_to_report:
            return None

        evidence = [
            metric_evidence(cpu, "CPUUtilization", unit="Percent"),
            metric_evidence(cpu, "CPUUtilization p95", statistic="p95", unit="Percent"),
            metric_evidence(cpu, "CPUUtilization max", statistic="maximum", unit="Percent"),
            cost_evidence(context),
            tag_evidence(resource),
        ]
        if memory is not None:
            evidence.append(metric_evidence(memory, "MemoryUtilization", unit="Percent"))
        else:
            evidence.append(
                Evidence(
                    source="cloudwatch",
                    metric="MemoryUtilization",
                    value=None,
                    detail=(
                        "Memory utilization is not published for this instance "
                        "(no CloudWatch agent), so the rightsizing decision rests "
                        "on CPU and network alone"
                    ),
                )
            )
        if context.optimizer:
            evidence.append(optimizer_evidence(context.optimizer))
        activity = activity_evidence(context)
        if activity:
            evidence.append(activity)

        return build_finding(
            context,
            waste_type=WasteType.UNDERUTILIZED_RESOURCE,
            title=(
                f"{resource.name or resource.resource_id} is underutilized "
                f"({instance_type})"
            ),
            summary=(
                f"CPU has averaged {cpu_avg:.1f}% with a 95th percentile of "
                f"{cpu_p95:.1f}% over {context.observation_days():.0f} days, well "
                f"below the {settings.underutilized_cpu_threshold:.0f}% threshold. "
                f"{basis} Moving to {target} would save about "
                f"${savings:,.2f}/month."
            ),
            evidence=evidence,
            potential_monthly_savings=savings,
            detector=self.name,
            score_inputs=waste_score.ScoreInputs(
                utilization_ratio=cpu_p95 / 100.0,
                monthly_cost=context.monthly_cost,
                idle_days=context.days_since_last_write,
                age_days=resource.age_days,
                aws_recommendation_savings_percent=(
                    context.optimizer.estimated_savings_percent if context.optimizer else None
                ),
            ),
            confidence_inputs=standard_confidence_inputs(
                context,
                corroborating_signals=3 if context.optimizer else 2,
                metric_variance_high=spiky,
                seasonal_pattern_suspected=spiky,
            ),
        )

    def _detect_overprovisioned(
        self, context, cpu, cpu_avg, cpu_p95, instance_type, spiky
    ) -> Finding | None:
        """AWS says a smaller instance fits, but our own CPU thresholds did not
        fire. We report it, attributed to AWS, at lower weight."""
        optimizer = context.optimizer
        if optimizer is None or optimizer.estimated_monthly_savings <= 0:
            return None
        if optimizer.finding.upper() in ("OPTIMIZED", "NOT_OPTIMIZED_UNAVAILABLE"):
            return None

        resource = context.resource
        savings = optimizer.estimated_monthly_savings

        return build_finding(
            context,
            waste_type=WasteType.OVERPROVISIONED_RESOURCE,
            title=(
                f"AWS recommends resizing {resource.name or resource.resource_id} "
                f"to {optimizer.recommended_configuration}"
            ),
            summary=(
                f"AWS reports this instance as '{optimizer.finding}' and recommends "
                f"{optimizer.recommended_configuration} in place of "
                f"{optimizer.current_configuration}, worth about "
                f"${savings:,.2f}/month. CloudWaste's own thresholds did not flag "
                f"it (CPU p95 {cpu_p95:.1f}%), so this rests on AWS's analysis."
            ),
            evidence=[
                optimizer_evidence(optimizer),
                metric_evidence(cpu, "CPUUtilization p95", statistic="p95", unit="Percent"),
                cost_evidence(context),
                tag_evidence(resource),
            ],
            potential_monthly_savings=savings,
            detector=self.name,
            score_inputs=waste_score.ScoreInputs(
                utilization_ratio=cpu_p95 / 100.0,
                monthly_cost=context.monthly_cost,
                age_days=resource.age_days,
                aws_recommendation_savings_percent=optimizer.estimated_savings_percent,
            ),
            confidence_inputs=standard_confidence_inputs(
                context, corroborating_signals=2, metric_variance_high=spiky
            ),
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _network_mb_per_day(context: DetectionContext) -> float:
        total_bytes = 0.0
        for key in ("network_in", "network_out"):
            series = context.series(key)
            if series:
                total_bytes += series.total
        days = max(context.observation_days(), 1.0)
        return total_bytes / days / 1_000_000.0

    @staticmethod
    def _downsize_target(
        context: DetectionContext, instance_type: str
    ) -> tuple[str | None, float, str]:
        """Prefer AWS's named target; fall back to our own price-book ladder.

        Returns (target_type, monthly_savings, prose describing the basis).
        """
        optimizer = context.optimizer
        if optimizer and optimizer.recommended_configuration:
            return (
                optimizer.recommended_configuration,
                optimizer.estimated_monthly_savings,
                f"AWS reports this instance as '{optimizer.finding}'.",
            )

        # No AWS opinion. Step down one size, which halves vCPU and memory --
        # only safe because we already know p95 is under 20%.
        target = pricing.step_down(instance_type, 1)
        if target is None:
            return None, 0.0, ""
        current_price = pricing.ec2_monthly(instance_type)
        target_price = pricing.ec2_monthly(target)
        if current_price is None or target_price is None:
            return None, 0.0, ""
        savings = round(current_price.monthly - target_price.monthly, 2)
        return (
            target,
            savings,
            "AWS has no recommendation for this instance, so the target is one "
            "size down in the same family.",
        )
