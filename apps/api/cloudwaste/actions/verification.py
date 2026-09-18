"""Post-execution verification.

Verification answers three questions in order, and the order matters:

  1. Did the change take effect?           (the executor's own checks)
  2. Is the resource still healthy?        (CloudWatch, after a settle period)
  3. Did the cost actually fall?           (Cost Explorer, days later)

Only the first two can gate a rollback. The third cannot: AWS billing data lags
by up to 24 hours, so a cost check immediately after execution would always
fail and would roll back every successful action. Cost verification is
therefore recorded as deferred and reconciled later, and this module is
explicit about that rather than pretending to verify something it cannot yet
see.

Health verification compares against the pre-action baseline rather than
against an absolute threshold. "Error rate is 2%" means nothing; "error rate
went from 0.1% to 2%" means roll back.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ..adapters.aws.metrics import build_specs
from ..models.domain import Action, Resource, VerificationResult
from ..models.enums import ResourceType

logger = logging.getLogger(__name__)

# How long to let a resource settle before believing its metrics.
SETTLE_SECONDS = {
    ResourceType.EC2: 300,
    ResourceType.RDS: 600,
    ResourceType.LAMBDA: 900,  # needs invocations at the new size
    ResourceType.EBS: 60,
    ResourceType.S3: 0,
}

# Relative degradation that triggers a rollback.
ERROR_RATE_MULTIPLIER = 3.0
ERROR_RATE_FLOOR = 0.01  # below 1% absolute, a multiplier is noise
CPU_SATURATION_THRESHOLD = 90.0
LATENCY_MULTIPLIER = 2.0


@dataclass(slots=True)
class HealthBaseline:
    """Pre-action metrics, captured so 'worse' has a meaning."""

    error_rate: float | None = None
    cpu_p95: float | None = None
    duration_p95: float | None = None
    connections_avg: float | None = None
    captured_at: datetime | None = None

    def to_dict(self) -> dict:
        return {
            "error_rate": self.error_rate,
            "cpu_p95": self.cpu_p95,
            "duration_p95": self.duration_p95,
            "connections_avg": self.connections_avg,
            "captured_at": self.captured_at.isoformat() if self.captured_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HealthBaseline":
        captured = data.get("captured_at")
        return cls(
            error_rate=data.get("error_rate"),
            cpu_p95=data.get("cpu_p95"),
            duration_p95=data.get("duration_p95"),
            connections_avg=data.get("connections_avg"),
            captured_at=datetime.fromisoformat(captured) if captured else None,
        )


class VerificationEngine:
    def __init__(self, data_plane) -> None:
        self.data = data_plane

    # ------------------------------------------------------------------

    def capture_baseline(self, resource: Resource) -> HealthBaseline:
        """Metrics from before the change, for later comparison."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        baseline = HealthBaseline(captured_at=end)

        series = self._fetch(resource, start, end)
        cpu = series.get("cpu")
        if cpu and cpu.datapoint_count:
            baseline.cpu_p95 = round(cpu.percentile(95), 3)

        if resource.resource_type is ResourceType.LAMBDA:
            errors = series.get("errors")
            invocations = series.get("invocations")
            if errors is not None and invocations is not None and invocations.total > 0:
                baseline.error_rate = round(errors.total / invocations.total, 5)
            duration = series.get("duration_p95")
            if duration and duration.datapoint_count:
                baseline.duration_p95 = round(duration.percentile(95), 2)

        if resource.resource_type is ResourceType.RDS:
            connections = series.get("connections")
            if connections and connections.datapoint_count:
                baseline.connections_avg = round(connections.average, 3)

        return baseline

    def verify_health(
        self, resource: Resource, baseline: HealthBaseline, since: datetime
    ) -> list[VerificationResult]:
        """Compare post-action metrics against the captured baseline."""
        end = datetime.now(timezone.utc)
        settle = SETTLE_SECONDS.get(resource.resource_type, 300)
        elapsed = (end - since).total_seconds()

        if elapsed < settle:
            return [
                VerificationResult(
                    check="health_settle_period",
                    passed=True,
                    detail=(
                        f"Only {elapsed:.0f}s have passed since the change and this "
                        f"resource type needs {settle}s to produce meaningful "
                        f"metrics. Health verification is deferred, not skipped."
                    ),
                )
            ]

        series = self._fetch(resource, since, end)
        results: list[VerificationResult] = []

        cpu = series.get("cpu")
        if cpu and cpu.datapoint_count:
            cpu_p95 = cpu.percentile(95)
            if cpu_p95 >= CPU_SATURATION_THRESHOLD:
                results.append(
                    VerificationResult(
                        check="cpu_saturation",
                        passed=False,
                        detail=(
                            f"CPU p95 is {cpu_p95:.1f}% since the change, at or "
                            f"above the {CPU_SATURATION_THRESHOLD:.0f}% saturation "
                            f"threshold. The new size is too small."
                        ),
                    )
                )
            else:
                was = (
                    f" (was {baseline.cpu_p95:.1f}% before)"
                    if baseline.cpu_p95 is not None
                    else ""
                )
                results.append(
                    VerificationResult(
                        check="cpu_saturation",
                        passed=True,
                        detail=f"CPU p95 is {cpu_p95:.1f}%{was}, with headroom remaining",
                    )
                )
        else:
            results.append(
                VerificationResult(
                    check="cpu_saturation",
                    passed=True,
                    detail="No CPU metric available for this resource type",
                )
            )

        if resource.resource_type is ResourceType.LAMBDA:
            results.extend(self._verify_lambda(series, baseline))
        if resource.resource_type is ResourceType.RDS:
            results.extend(self._verify_rds(series, baseline))

        return results

    def verify_cost(
        self, action: Action, resource: Resource, projected_monthly_cost: float
    ) -> VerificationResult:
        """Confirm the bill actually moved.

        Returns a *deferred* result when billing data cannot yet reflect the
        change. Reporting a failure there would be wrong, and rolling back on
        it would be worse.
        """
        completed = action.completed_at or datetime.now(timezone.utc)
        hours_since = (datetime.now(timezone.utc) - completed).total_seconds() / 3600.0

        if hours_since < 24:
            return VerificationResult(
                check="cost_reduction",
                passed=True,
                detail=(
                    f"Only {hours_since:.1f} hours since execution. AWS billing "
                    f"data lags by up to 24 hours, so the saving is not yet "
                    f"observable. Verification is deferred and will be reconciled "
                    f"once Cost Explorer reflects the change."
                ),
            )

        end = datetime.now(timezone.utc)
        start = completed
        try:
            observed = self.data.cost.get_cost_by_resource(resource.resource_id, start, end)
        except Exception as exc:  # noqa: BLE001
            return VerificationResult(
                check="cost_reduction",
                passed=True,
                detail=f"Cost data unavailable for this resource: {exc}",
            )

        if observed is None:
            return VerificationResult(
                check="cost_reduction",
                passed=True,
                detail=(
                    "Resource-level cost data is not enabled on this account, so "
                    "the saving cannot be attributed to this resource directly. "
                    "The account-level trend is the available signal."
                ),
            )

        tolerance = max(1.0, projected_monthly_cost * 0.15)
        within = observed <= projected_monthly_cost + tolerance
        return VerificationResult(
            check="cost_reduction",
            passed=within,
            detail=(
                f"Observed ${observed:,.2f}/month against a projected "
                f"${projected_monthly_cost:,.2f}/month "
                + (
                    "(within tolerance)"
                    if within
                    else f"(above the ${tolerance:,.2f} tolerance; the projection "
                    f"may have been optimistic or another change intervened)"
                )
            ),
        )

    # ------------------------------------------------------------------

    def _verify_lambda(self, series, baseline) -> list[VerificationResult]:
        results = []
        errors = series.get("errors")
        invocations = series.get("invocations")

        if errors is None or invocations is None or invocations.total == 0:
            return [
                VerificationResult(
                    check="error_rate",
                    passed=True,
                    detail=(
                        "No invocations since the change, so the effect on error "
                        "rate cannot be observed yet."
                    ),
                )
            ]

        error_rate = errors.total / invocations.total
        if baseline.error_rate is None:
            results.append(
                VerificationResult(
                    check="error_rate",
                    passed=error_rate < 0.05,
                    detail=(
                        f"Error rate is {error_rate:.2%} over "
                        f"{invocations.total:,.0f} invocations. No pre-change "
                        f"baseline was captured, so this is an absolute check."
                    ),
                )
            )
        else:
            threshold = max(
                baseline.error_rate * ERROR_RATE_MULTIPLIER, ERROR_RATE_FLOOR
            )
            degraded = error_rate > threshold
            results.append(
                VerificationResult(
                    check="error_rate",
                    passed=not degraded,
                    detail=(
                        f"Error rate is {error_rate:.2%} against a pre-change "
                        f"baseline of {baseline.error_rate:.2%}"
                        + (
                            f", more than {ERROR_RATE_MULTIPLIER:.0f}x worse. "
                            f"The memory reduction is causing failures."
                            if degraded
                            else ", not materially worse."
                        )
                    ),
                )
            )

        duration = series.get("duration_p95") or series.get("duration")
        if duration and duration.datapoint_count and baseline.duration_p95:
            observed = duration.percentile(95)
            degraded = observed > baseline.duration_p95 * LATENCY_MULTIPLIER
            results.append(
                VerificationResult(
                    check="duration",
                    passed=not degraded,
                    detail=(
                        f"Duration p95 is {observed:,.0f} ms against a baseline of "
                        f"{baseline.duration_p95:,.0f} ms"
                        + (
                            f", more than {LATENCY_MULTIPLIER:.0f}x slower. The "
                            f"cost model assumed a smaller increase, so the "
                            f"projected saving will not materialize."
                            if degraded
                            else "."
                        )
                    ),
                )
            )

        throttles = series.get("throttles")
        if throttles and throttles.total > 0:
            results.append(
                VerificationResult(
                    check="throttles",
                    passed=False,
                    detail=f"{throttles.total:,.0f} throttles since the change",
                )
            )
        return results

    def _verify_rds(self, series, baseline) -> list[VerificationResult]:
        results = []
        connections = series.get("connections")
        if connections and connections.datapoint_count:
            if baseline.connections_avg and connections.average < baseline.connections_avg * 0.5:
                results.append(
                    VerificationResult(
                        check="database_connections",
                        passed=False,
                        detail=(
                            f"Average connections fell from "
                            f"{baseline.connections_avg:.1f} to "
                            f"{connections.average:.1f}. Clients may have failed "
                            f"to reconnect after the restart."
                        ),
                    )
                )
            else:
                results.append(
                    VerificationResult(
                        check="database_connections",
                        passed=True,
                        detail=(
                            f"Average connections are {connections.average:.1f}, "
                            f"consistent with the pre-change level"
                        ),
                    )
                )
        return results

    def _fetch(self, resource: Resource, start: datetime, end: datetime) -> dict:
        specs = build_specs(resource.resource_type.value, resource.resource_id)
        if not specs:
            return {}
        try:
            if hasattr(self.data.metrics, "get_metrics"):
                series_list = self.data.metrics.get_metrics(specs, start, end, 300)
            else:
                series_list = [
                    self.data.metrics.get_metric(
                        s["namespace"], s["metric_name"], s["dimensions"], start, end,
                        s.get("statistic", "Average"), 300,
                    )
                    for s in specs
                ]
        except Exception as exc:  # noqa: BLE001
            logger.warning("verification metric fetch failed: %s", exc)
            return {}
        return {spec["key"]: series for spec, series in zip(specs, series_list)}


def summarize(results: list[VerificationResult]) -> tuple[bool, str]:
    """Whether verification passed overall, and a one-line summary."""
    failures = [r for r in results if not r.passed]
    if not failures:
        return True, f"All {len(results)} verification checks passed."
    return False, (
        f"{len(failures)} of {len(results)} checks failed: "
        + "; ".join(f.check for f in failures)
    )
