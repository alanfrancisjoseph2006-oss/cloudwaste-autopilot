"""Compute Optimizer and Cost Optimization Hub, normalized into one signal.

The two services overlap. Cost Optimization Hub aggregates recommendations
(including Compute Optimizer's own) with consistent savings figures; Compute
Optimizer carries the richer utilization detail and performance risk. This
adapter reads both and de-duplicates by resource, preferring Cost Optimization
Hub for the savings number and Compute Optimizer for the supporting detail.

Both services must be explicitly enabled on an account. When they are not,
`soft_call` turns the OptInRequired error into an empty list and CloudWaste
falls back to its own detectors -- degraded, but still useful.
"""

from __future__ import annotations

import logging
from typing import Any

from ..base import OptimizerRecommendation
from ...models.enums import ResourceType
from .clients import get_client, paginate, soft_call

logger = logging.getLogger(__name__)

_CO_RESOURCE_TYPES = {
    ResourceType.EC2: "Ec2Instance",
    ResourceType.EBS: "EbsVolume",
    ResourceType.LAMBDA: "LambdaFunction",
    ResourceType.RDS: "RdsDBInstance",
}

_COH_TO_DOMAIN = {
    "Ec2Instance": ResourceType.EC2,
    "EbsVolume": ResourceType.EBS,
    "LambdaFunction": ResourceType.LAMBDA,
    "RdsDbInstance": ResourceType.RDS,
    "RdsDBInstance": ResourceType.RDS,
    "Ec2AutoScalingGroup": ResourceType.EC2,
    "EcsService": ResourceType.EC2,
}


class AwsRecommendationProvider:
    """Implements `adapters.base.RecommendationProvider` against a real account."""

    def __init__(
        self,
        account_id: str,
        region: str,
        role_arn: str | None = None,
        external_id: str | None = None,
    ) -> None:
        self.account_id = account_id
        self.region = region
        self._role_arn = role_arn
        self._external_id = external_id
        self._cache: list[OptimizerRecommendation] | None = None

    def _client(self, service: str):
        return get_client(service, self._role_arn, self._external_id, self.region)

    # ------------------------------------------------------------------

    def list_recommendations(
        self, resource_types: list[ResourceType] | None = None
    ) -> list[OptimizerRecommendation]:
        if self._cache is None:
            merged: dict[str, OptimizerRecommendation] = {}
            # Compute Optimizer first, then let the Hub's savings figure win.
            for rec in self._compute_optimizer():
                merged[rec.resource_id] = rec
            for rec in self._cost_optimization_hub():
                existing = merged.get(rec.resource_id)
                if existing:
                    rec.performance_risk = existing.performance_risk
                    rec.lookback_days = existing.lookback_days
                    rec.raw = {"compute_optimizer": existing.raw, "hub": rec.raw}
                    rec.source = "cost_optimization_hub+compute_optimizer"
                merged[rec.resource_id] = rec
            self._cache = list(merged.values())

        if resource_types:
            wanted = set(resource_types)
            return [r for r in self._cache if r.resource_type in wanted]
        return list(self._cache)

    def get_recommendation(self, resource_id: str) -> OptimizerRecommendation | None:
        return next(
            (r for r in self.list_recommendations() if r.resource_id == resource_id), None
        )

    def summary(self) -> dict[str, Any]:
        recs = self.list_recommendations()
        by_type: dict[str, dict[str, Any]] = {}
        for rec in recs:
            bucket = by_type.setdefault(
                rec.resource_type.value, {"count": 0, "estimated_monthly_savings": 0.0}
            )
            bucket["count"] += 1
            bucket["estimated_monthly_savings"] = round(
                bucket["estimated_monthly_savings"] + rec.estimated_monthly_savings, 2
            )
        return {
            "total_recommendations": len(recs),
            "estimated_monthly_savings": round(
                sum(r.estimated_monthly_savings for r in recs), 2
            ),
            "by_resource_type": by_type,
        }

    # ------------------------------------------------------------------
    # Compute Optimizer
    # ------------------------------------------------------------------

    def _compute_optimizer(self) -> list[OptimizerRecommendation]:
        client = self._client("compute-optimizer")
        out: list[OptimizerRecommendation] = []
        out.extend(self._co_ec2(client))
        out.extend(self._co_ebs(client))
        out.extend(self._co_lambda(client))
        out.extend(self._co_rds(client))
        return out

    def _co_ec2(self, client) -> list[OptimizerRecommendation]:
        items = soft_call(
            lambda: list(
                paginate(
                    client,
                    "get_ec2_instance_recommendations",
                    "instanceRecommendations",
                )
            ),
            default=[],
            context="compute-optimizer:GetEc2InstanceRecommendations",
        )
        out = []
        for item in items or []:
            options = item.get("recommendationOptions", [])
            if not options:
                continue
            best = options[0]
            savings = _extract_savings(best)
            out.append(
                OptimizerRecommendation(
                    source="compute_optimizer",
                    resource_id=item["instanceArn"].rsplit("/", 1)[-1],
                    resource_arn=item["instanceArn"],
                    resource_type=ResourceType.EC2,
                    finding=item.get("finding", "Unknown"),
                    current_configuration=item.get("currentInstanceType", ""),
                    recommended_configuration=best.get("instanceType", ""),
                    estimated_monthly_savings=savings,
                    estimated_savings_percent=_savings_percent(best),
                    performance_risk=best.get("performanceRisk"),
                    lookback_days=item.get("lookBackPeriodInDays"),
                    action_type="Rightsize",
                    raw={
                        "finding_reason_codes": item.get("findingReasonCodes", []),
                        "utilization_metrics": item.get("utilizationMetrics", []),
                        "current_performance_risk": item.get("currentPerformanceRisk"),
                    },
                )
            )
        return out

    def _co_ebs(self, client) -> list[OptimizerRecommendation]:
        items = soft_call(
            lambda: list(
                paginate(client, "get_ebs_volume_recommendations", "volumeRecommendations")
            ),
            default=[],
            context="compute-optimizer:GetEbsVolumeRecommendations",
        )
        out = []
        for item in items or []:
            options = item.get("volumeRecommendationOptions", [])
            if not options:
                continue
            best = options[0]
            current = item.get("currentConfiguration", {})
            configuration = best.get("configuration", {})
            out.append(
                OptimizerRecommendation(
                    source="compute_optimizer",
                    resource_id=item["volumeArn"].rsplit("/", 1)[-1],
                    resource_arn=item["volumeArn"],
                    resource_type=ResourceType.EBS,
                    finding=item.get("finding", "Unknown"),
                    current_configuration=(
                        f"{current.get('volumeType')} {current.get('volumeSize')}GB"
                    ),
                    recommended_configuration=(
                        f"{configuration.get('volumeType')} {configuration.get('volumeSize')}GB"
                    ),
                    estimated_monthly_savings=_extract_savings(best),
                    estimated_savings_percent=_savings_percent(best),
                    performance_risk=best.get("performanceRisk"),
                    lookback_days=item.get("lookBackPeriodInDays"),
                    action_type="Rightsize",
                    raw={"utilization_metrics": item.get("utilizationMetrics", [])},
                )
            )
        return out

    def _co_lambda(self, client) -> list[OptimizerRecommendation]:
        items = soft_call(
            lambda: list(
                paginate(
                    client,
                    "get_lambda_function_recommendations",
                    "lambdaFunctionRecommendations",
                )
            ),
            default=[],
            context="compute-optimizer:GetLambdaFunctionRecommendations",
        )
        out = []
        for item in items or []:
            options = item.get("memorySizeRecommendationOptions", [])
            if not options:
                continue
            best = options[0]
            out.append(
                OptimizerRecommendation(
                    source="compute_optimizer",
                    resource_id=item["functionArn"].rsplit(":", 1)[-1],
                    resource_arn=item["functionArn"],
                    resource_type=ResourceType.LAMBDA,
                    finding=item.get("finding", "Unknown"),
                    current_configuration=f"{item.get('currentMemorySize')} MB",
                    recommended_configuration=f"{best.get('memorySize')} MB",
                    estimated_monthly_savings=_extract_savings(best),
                    estimated_savings_percent=_savings_percent(best),
                    lookback_days=item.get("lookbackPeriodInDays"),
                    action_type="Rightsize",
                    raw={
                        "finding_reason_codes": item.get("findingReasonCodes", []),
                        "utilization_metrics": item.get("utilizationMetrics", []),
                        "number_of_invocations": item.get("numberOfInvocations"),
                    },
                )
            )
        return out

    def _co_rds(self, client) -> list[OptimizerRecommendation]:
        items = soft_call(
            lambda: list(
                paginate(
                    client, "get_rds_database_recommendations", "rdsDBRecommendations"
                )
            ),
            default=[],
            context="compute-optimizer:GetRdsDatabaseRecommendations",
        )
        out = []
        for item in items or []:
            options = item.get("instanceRecommendationOptions", [])
            if not options:
                continue
            best = options[0]
            arn = item.get("resourceArn", "")
            out.append(
                OptimizerRecommendation(
                    source="compute_optimizer",
                    resource_id=arn.rsplit(":", 1)[-1],
                    resource_arn=arn,
                    resource_type=ResourceType.RDS,
                    finding=item.get("instanceFinding", "Unknown"),
                    current_configuration=item.get("currentDBInstanceClass", ""),
                    recommended_configuration=best.get("dbInstanceClass", ""),
                    estimated_monthly_savings=_extract_savings(best),
                    estimated_savings_percent=_savings_percent(best),
                    performance_risk=best.get("performanceRisk"),
                    lookback_days=item.get("lookbackPeriodInDays"),
                    action_type="Rightsize",
                    raw={
                        "finding_reason_codes": item.get("instanceFindingReasonCodes", []),
                        "utilization_metrics": item.get("utilizationMetrics", []),
                    },
                )
            )
        return out

    # ------------------------------------------------------------------
    # Cost Optimization Hub
    # ------------------------------------------------------------------

    def _cost_optimization_hub(self) -> list[OptimizerRecommendation]:
        client = self._client("cost-optimization-hub")
        items = soft_call(
            lambda: list(paginate(client, "list_recommendations", "items")),
            default=[],
            context="cost-optimization-hub:ListRecommendations",
        )
        out: list[OptimizerRecommendation] = []
        for item in items or []:
            resource_type = _COH_TO_DOMAIN.get(item.get("currentResourceType", ""))
            if resource_type is None:
                continue
            arn = item.get("resourceArn", "")
            out.append(
                OptimizerRecommendation(
                    source="cost_optimization_hub",
                    resource_id=item.get("resourceId") or arn.rsplit("/", 1)[-1],
                    resource_arn=arn,
                    resource_type=resource_type,
                    finding=item.get("actionType", "Unknown"),
                    current_configuration=item.get("currentResourceSummary", ""),
                    recommended_configuration=item.get("recommendedResourceSummary", ""),
                    estimated_monthly_savings=round(
                        float(item.get("estimatedMonthlySavings", 0.0)), 2
                    ),
                    estimated_savings_percent=round(
                        float(item.get("estimatedSavingsPercentage", 0.0)), 1
                    ),
                    action_type=item.get("actionType"),
                    raw={
                        "recommendation_id": item.get("recommendationId"),
                        "implementation_effort": item.get("implementationEffort"),
                        "restart_needed": item.get("restartNeeded"),
                        "rollback_possible": item.get("rollbackPossible"),
                        "estimated_monthly_cost": item.get("estimatedMonthlyCost"),
                        "source": item.get("source"),
                    },
                )
            )
        return out


def _extract_savings(option: dict) -> float:
    saving = option.get("savingsOpportunity", {}) or {}
    value = saving.get("estimatedMonthlySavings", {}) or {}
    return round(float(value.get("value", 0.0)), 2)


def _savings_percent(option: dict) -> float:
    saving = option.get("savingsOpportunity", {}) or {}
    return round(float(saving.get("savingsOpportunityPercentage", 0.0)), 1)
