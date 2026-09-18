"""Lambda waste detection.

Lambda is the one service where downsizing can *increase* cost. Memory and CPU
are allocated together, so halving memory can more than double duration, and
billing is memory x duration. A naive "memory is over-provisioned, cut it"
rule loses money.

So this detector only proposes a memory reduction when it can show the new
configuration is cheaper *after* accounting for the duration increase, using a
deliberately pessimistic model of that increase. Where AWS has published a
recommendation it is preferred, because Compute Optimizer profiles the actual
cost-duration curve rather than modelling it.

It also flags functions whose configured memory dwarfs observed peak usage,
and functions that are effectively unused.
"""

from __future__ import annotations

from ...adapters import pricing
from ...models.domain import Evidence, Finding
from ...models.enums import ResourceType, WasteType
from .. import waste_score
from .base import (
    DetectionContext,
    build_finding,
    cost_evidence,
    metric_evidence,
    optimizer_evidence,
    standard_confidence_inputs,
    tag_evidence,
)

# Below 1769 MB a function has less than one full vCPU, so duration scales
# roughly inversely with memory. Above it, extra memory buys little speed.
FULL_VCPU_MB = 1769
HEADROOM_FACTOR = 1.6  # keep 60% headroom over observed peak memory


class LambdaDetector:
    name = "lambda_sizing"
    resource_type = ResourceType.LAMBDA

    def detect(self, context: DetectionContext) -> list[Finding]:
        resource = context.resource
        invocations = context.series("invocations")
        duration = context.series("duration")

        if invocations is None:
            return []

        monthly_invocations = invocations.total / max(context.observation_days(), 1.0) * 30.0

        finding = self._detect_unused(
            context, invocations, monthly_invocations
        ) or self._detect_oversized_memory(
            context, invocations, duration, monthly_invocations
        )
        return [finding] if finding else []

    # ------------------------------------------------------------------

    def _detect_unused(self, context, invocations, monthly_invocations) -> Finding | None:
        if monthly_invocations >= 1.0:
            return None
        resource = context.resource
        if resource.age_days < 30:
            return None  # a new function with no traffic yet is not waste

        return build_finding(
            context,
            waste_type=WasteType.IDLE_RESOURCE,
            title=f"Function {resource.resource_id} is never invoked",
            summary=(
                f"This function was invoked {invocations.total:.0f} times over "
                f"{context.observation_days():.0f} days. It costs almost nothing to "
                f"run, but it is unmaintained surface area: it still holds an "
                f"execution role and its code is still deployed."
            ),
            evidence=[
                metric_evidence(invocations, "Invocations", statistic="total", unit="Count"),
                cost_evidence(context),
                tag_evidence(resource),
                Evidence(
                    source="resource_config",
                    metric="runtime",
                    value=resource.configuration.get("runtime"),
                    detail=(
                        f"{resource.configuration.get('memory_mb')} MB, "
                        f"{resource.configuration.get('runtime')}, "
                        f"{resource.configuration.get('architecture')}"
                    ),
                ),
            ],
            potential_monthly_savings=context.monthly_cost,
            detector=self.name,
            score_inputs=waste_score.ScoreInputs(
                utilization_ratio=0.0,
                monthly_cost=context.monthly_cost,
                idle_days=context.observation_days(),
                age_days=resource.age_days,
            ),
            confidence_inputs=standard_confidence_inputs(
                context, corroborating_signals=2, memory_metric_missing=False
            ),
        )

    def _detect_oversized_memory(
        self, context, invocations, duration, monthly_invocations
    ) -> Finding | None:
        resource = context.resource
        config = resource.configuration
        current_memory = config.get("memory_mb")
        if not current_memory or duration is None:
            return None
        if monthly_invocations < 1000:
            return None  # too little traffic for the saving to be worth a change

        avg_duration = duration.average
        target_memory, projected_cost, basis = self._target_memory(
            context, current_memory, avg_duration, monthly_invocations
        )
        if target_memory is None:
            return None

        current_cost = pricing.lambda_monthly(
            current_memory, avg_duration, monthly_invocations
        ).monthly
        savings = round(current_cost - projected_cost, 2)
        if savings < context.settings.min_monthly_savings_to_report:
            return None

        peak_memory = config.get("max_memory_used_mb")
        evidence = [
            metric_evidence(invocations, "Invocations", statistic="total", unit="Count"),
            metric_evidence(duration, "Duration", unit="Milliseconds"),
            Evidence(
                source="resource_config",
                metric="memory_mb",
                value=current_memory,
                unit="MB",
                detail=(
                    f"Configured at {current_memory} MB"
                    + (f", peak observed usage {peak_memory} MB" if peak_memory else "")
                ),
            ),
            cost_evidence(context),
            tag_evidence(resource),
            Evidence(
                source="cloudwaste",
                metric="projected_cost",
                value=round(projected_cost, 2),
                unit="USD/month",
                detail=(
                    f"At {target_memory} MB the projected monthly cost is "
                    f"${projected_cost:,.2f} against ${current_cost:,.2f} today, "
                    f"after allowing for the duration increase that less memory causes"
                ),
            ),
        ]
        if context.optimizer:
            evidence.append(optimizer_evidence(context.optimizer))

        errors = context.series("errors")
        if errors and errors.total > 0:
            error_rate = errors.total / max(invocations.total, 1) * 100
            evidence.append(
                Evidence(
                    source="cloudwatch",
                    metric="ErrorRate",
                    value=round(error_rate, 3),
                    unit="Percent",
                    detail=(
                        f"Error rate of {error_rate:.2f}% over the window. A memory "
                        f"reduction must not make this worse"
                    ),
                )
            )

        return build_finding(
            context,
            waste_type=WasteType.OVERPROVISIONED_RESOURCE,
            title=(
                f"Function {resource.resource_id} is over-provisioned at "
                f"{current_memory} MB"
            ),
            summary=(
                f"Across {monthly_invocations:,.0f} invocations per month averaging "
                f"{avg_duration:.0f} ms, {basis} Reducing memory to {target_memory} MB "
                f"is projected to save about ${savings:,.2f}/month even after the "
                f"duration increase that comes with less CPU."
            ),
            evidence=evidence,
            potential_monthly_savings=savings,
            detector=self.name,
            score_inputs=waste_score.ScoreInputs(
                utilization_ratio=(peak_memory / current_memory) if peak_memory else None,
                monthly_cost=context.monthly_cost,
                age_days=resource.age_days,
                aws_recommendation_savings_percent=(
                    context.optimizer.estimated_savings_percent if context.optimizer else None
                ),
            ),
            confidence_inputs=standard_confidence_inputs(
                context,
                corroborating_signals=3 if context.optimizer else 2,
                memory_metric_missing=peak_memory is None,
            ),
            # The duration projection is the whole basis of this finding, so it
            # travels with it rather than being recomputed downstream.
            action_context={
                "target_memory_mb": target_memory,
                "projected_duration_ms": self._project_duration(
                    avg_duration, current_memory, target_memory
                ),
                "monthly_invocations": monthly_invocations,
                "current_duration_ms": avg_duration,
            },
        )

    # ------------------------------------------------------------------

    def _target_memory(
        self,
        context: DetectionContext,
        current_memory: int,
        avg_duration: float,
        monthly_invocations: float,
    ) -> tuple[int | None, float, str]:
        """Pick a memory setting that is cheaper after modelling slowdown."""
        optimizer = context.optimizer
        if optimizer and optimizer.recommended_configuration:
            try:
                target = int(optimizer.recommended_configuration.split()[0])
            except (ValueError, IndexError):
                target = None
            if target and target < current_memory:
                projected_duration = self._project_duration(
                    avg_duration, current_memory, target
                )
                cost = pricing.lambda_monthly(
                    target, projected_duration, monthly_invocations
                ).monthly
                return (
                    target,
                    cost,
                    f"AWS reports this function as '{optimizer.finding}' and "
                    f"recommends {target} MB.",
                )

        peak_memory = context.resource.configuration.get("max_memory_used_mb")
        if not peak_memory:
            return None, 0.0, ""

        needed = peak_memory * HEADROOM_FACTOR
        candidate = max(128, int(round(needed / 64.0)) * 64)
        if candidate >= current_memory:
            return None, 0.0, ""

        projected_duration = self._project_duration(avg_duration, current_memory, candidate)
        projected_cost = pricing.lambda_monthly(
            candidate, projected_duration, monthly_invocations
        ).monthly
        current_cost = pricing.lambda_monthly(
            current_memory, avg_duration, monthly_invocations
        ).monthly
        if projected_cost >= current_cost:
            # The slowdown eats the saving. Correct answer: say nothing.
            return None, 0.0, ""

        return (
            candidate,
            projected_cost,
            f"peak memory usage is {peak_memory} MB against {current_memory} MB "
            f"configured, leaving {HEADROOM_FACTOR:.0%} headroom at {candidate} MB.",
        )

    @staticmethod
    def _project_duration(
        current_duration: float, current_memory: int, target_memory: int
    ) -> float:
        """Pessimistic duration model for a memory reduction.

        Below one full vCPU (1769 MB) CPU scales linearly with memory, so
        duration scales inversely. Above it, extra memory buys almost no speed,
        so removing it costs almost nothing. Being pessimistic here means the
        tool under-promises savings, which is the right direction to be wrong.
        """
        if target_memory >= current_memory:
            return current_duration
        effective_current = min(current_memory, FULL_VCPU_MB)
        effective_target = min(target_memory, FULL_VCPU_MB)
        if effective_target >= effective_current:
            return current_duration
        slowdown = effective_current / effective_target
        # Damp the model: real functions are rarely purely CPU-bound.
        return current_duration * (1.0 + (slowdown - 1.0) * 0.75)
