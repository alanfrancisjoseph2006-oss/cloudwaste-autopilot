"""Cost Explorer and Cost Anomaly Detection.

Two facts shape this module:

  * Cost Explorer is billed per API request, so scans cache aggressively and
    prefer one grouped query over many narrow ones.
  * Resource-level granularity (RESOURCE_ID as a GroupBy) is off by default and
    only retains 14 days. `get_cost_by_resource` therefore returns None rather
    than 0.0 when it cannot answer, and the caller falls back to the price book.
    Reporting 0.0 there would silently zero out every savings number.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from ..base import CostAnomaly, CostPoint
from .clients import get_client, soft_call

logger = logging.getLogger(__name__)


def _day(value: datetime) -> str:
    return value.strftime("%Y-%m-%d")


class AwsCostProvider:
    """Implements `adapters.base.CostProvider` against a real account."""

    def __init__(
        self,
        account_id: str,
        region: str = "us-east-1",
        role_arn: str | None = None,
        external_id: str | None = None,
    ) -> None:
        self.account_id = account_id
        self.region = region
        self._role_arn = role_arn
        self._external_id = external_id
        self._cache: dict[tuple, Any] = {}

    def _ce(self):
        # Cost Explorer only answers in us-east-1; clients.get_client pins it.
        return get_client("ce", self._role_arn, self._external_id, "us-east-1")

    # ------------------------------------------------------------------

    def get_cost_and_usage(
        self,
        start: datetime,
        end: datetime,
        granularity: str = "DAILY",
        group_by: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[CostPoint]:
        cache_key = (_day(start), _day(end), granularity, tuple(group_by or ()), str(filters))
        if cache_key in self._cache:
            return self._cache[cache_key]

        kwargs: dict[str, Any] = {
            "TimePeriod": {"Start": _day(start), "End": _day(end)},
            "Granularity": granularity,
            "Metrics": ["UnblendedCost"],
        }
        if group_by:
            kwargs["GroupBy"] = [
                {
                    "Type": "DIMENSION" if key.isupper() else "TAG",
                    "Key": key,
                }
                for key in group_by
            ]
        if filters:
            kwargs["Filter"] = filters

        points: list[CostPoint] = []
        next_token: str | None = None
        client = self._ce()
        while True:
            if next_token:
                kwargs["NextPageToken"] = next_token
            response = soft_call(
                client.get_cost_and_usage,
                default={"ResultsByTime": []},
                context="ce:GetCostAndUsage",
                **kwargs,
            )
            for result in (response or {}).get("ResultsByTime", []):
                period_start = datetime.fromisoformat(result["TimePeriod"]["Start"])
                period_end = datetime.fromisoformat(result["TimePeriod"]["End"])
                groups = result.get("Groups", [])
                if groups:
                    for group in groups:
                        amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                        dimensions = dict(zip(group_by or [], group["Keys"]))
                        points.append(
                            CostPoint(period_start, period_end, amount, dimensions=dimensions)
                        )
                else:
                    amount = float(result["Total"]["UnblendedCost"]["Amount"])
                    points.append(CostPoint(period_start, period_end, amount))
            next_token = (response or {}).get("NextPageToken")
            if not next_token:
                break

        self._cache[cache_key] = points
        return points

    def get_cost_by_resource(
        self, resource_id: str, start: datetime, end: datetime
    ) -> float | None:
        """Observed unblended cost for one resource.

        Returns None -- not 0.0 -- when resource-level granularity is not
        enabled or the window predates its 14-day retention. The distinction
        matters: None means "ask the price book", 0.0 means "this was free".
        """
        kwargs = {
            "TimePeriod": {"Start": _day(start), "End": _day(end)},
            "Granularity": "DAILY",
            "Metrics": ["UnblendedCost"],
            "GroupBy": [{"Type": "DIMENSION", "Key": "RESOURCE_ID"}],
            "Filter": {
                "Dimensions": {"Key": "RESOURCE_ID", "Values": [resource_id]}
            },
        }
        try:
            response = self._ce().get_cost_and_usage_with_resources(**kwargs)
        except ClientError as exc:
            logger.info("resource-level cost unavailable for %s: %s", resource_id, exc)
            return None

        total = 0.0
        found = False
        for result in response.get("ResultsByTime", []):
            for group in result.get("Groups", []):
                total += float(group["Metrics"]["UnblendedCost"]["Amount"])
                found = True
        if not found:
            return None
        days = max((end - start).days, 1)
        return round(total / days * 30.0, 2)

    def get_forecast(self, days: int = 30) -> float:
        start = datetime.now(timezone.utc) + timedelta(days=1)
        end = start + timedelta(days=days)
        response = soft_call(
            self._ce().get_cost_forecast,
            TimePeriod={"Start": _day(start), "End": _day(end)},
            Metric="UNBLENDED_COST",
            Granularity="MONTHLY",
            default=None,
            context="ce:GetCostForecast",
        )
        if not response:
            return 0.0
        return round(float(response["Total"]["Amount"]), 2)

    def get_anomalies(self, start: datetime, end: datetime) -> list[CostAnomaly]:
        response = soft_call(
            self._ce().get_anomalies,
            DateInterval={"StartDate": _day(start), "EndDate": _day(end)},
            default={"Anomalies": []},
            context="ce:GetAnomalies",
        )
        anomalies: list[CostAnomaly] = []
        for item in (response or {}).get("Anomalies", []):
            impact = item.get("Impact", {})
            root_causes = item.get("RootCauses", [])
            service = next(
                (rc.get("Service") for rc in root_causes if rc.get("Service")),
                item.get("DimensionValue", "unknown"),
            )
            expected = float(impact.get("TotalExpectedSpend", 0.0))
            actual = float(impact.get("TotalActualSpend", 0.0))
            anomalies.append(
                CostAnomaly(
                    anomaly_id=item["AnomalyId"],
                    service=service,
                    start=datetime.fromisoformat(item["AnomalyStartDate"]),
                    end=(
                        datetime.fromisoformat(item["AnomalyEndDate"])
                        if item.get("AnomalyEndDate")
                        else None
                    ),
                    total_impact=float(impact.get("TotalImpact", 0.0)),
                    max_impact=float(impact.get("MaxImpact", 0.0)),
                    expected_spend=expected,
                    actual_spend=actual,
                    root_causes=root_causes,
                )
            )
        return anomalies

    # --- convenience queries used by the agent tools --------------------

    def cost_by_service(self, start: datetime, end: datetime) -> dict[str, float]:
        points = self.get_cost_and_usage(start, end, "MONTHLY", ["SERVICE"])
        totals: dict[str, float] = {}
        for point in points:
            service = point.dimensions.get("SERVICE", "unknown")
            totals[service] = round(totals.get(service, 0.0) + point.amount, 2)
        return dict(sorted(totals.items(), key=lambda kv: kv[1], reverse=True))

    def cost_by_region(self, start: datetime, end: datetime) -> dict[str, float]:
        points = self.get_cost_and_usage(start, end, "MONTHLY", ["REGION"])
        totals: dict[str, float] = {}
        for point in points:
            region = point.dimensions.get("REGION", "unknown")
            totals[region] = round(totals.get(region, 0.0) + point.amount, 2)
        return dict(sorted(totals.items(), key=lambda kv: kv[1], reverse=True))

    def compare_periods(
        self, current_start: datetime, current_end: datetime, window_days: int
    ) -> dict[str, Any]:
        """Same-length period-over-period comparison, grouped by service."""
        previous_end = current_start
        previous_start = current_start - timedelta(days=window_days)
        current = self.cost_by_service(current_start, current_end)
        previous = self.cost_by_service(previous_start, previous_end)

        deltas = []
        for service in set(current) | set(previous):
            now_amount = current.get(service, 0.0)
            then_amount = previous.get(service, 0.0)
            change = now_amount - then_amount
            deltas.append(
                {
                    "service": service,
                    "previous": round(then_amount, 2),
                    "current": round(now_amount, 2),
                    "increase": round(change, 2),
                    "percentage": (
                        round(change / then_amount * 100, 1) if then_amount > 0 else None
                    ),
                }
            )
        deltas.sort(key=lambda d: d["increase"], reverse=True)
        return {
            "current_period": {"start": _day(current_start), "end": _day(current_end)},
            "previous_period": {"start": _day(previous_start), "end": _day(previous_end)},
            "total_current": round(sum(current.values()), 2),
            "total_previous": round(sum(previous.values()), 2),
            "by_service": deltas,
        }
