"""Agent tools.

The tool surface is split into two tiers, and the split is the security model:

  READ tools   -- query cost, metrics, inventory, AWS recommendations,
                  CloudTrail, findings. Freely callable.
  PROPOSE tool -- creates an Action in PENDING state and returns what policy
                  decided. It cannot approve, and it cannot execute.

There is no tool that mutates an AWS resource. The model can investigate and it
can draft a proposal, but the path from proposal to execution runs through the
policy engine and a human approval, both outside the model's reach. That is
what makes it safe to let a language model drive this at all: a prompt
injection in a resource tag or a CloudTrail user agent can at worst cause a
badly-reasoned proposal, which still has to survive policy and a person.

Each tool returns plain JSON-serializable data with units and provenance
attached, because a model that is told "8.7" will guess at what it means and a
model told "8.7 percent CPU, averaged over 14 days, 336 datapoints" will not.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from ..models.domain import Account
from ..models.enums import ResourceType

logger = logging.getLogger(__name__)


class ToolError(Exception):
    """Returned to the model as an error result rather than raised."""


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


class ToolRegistry:
    """Named tools with JSON schemas, in the shape the Bedrock Converse API wants."""

    def __init__(self) -> None:
        self._tools: dict[str, dict] = {}
        self._handlers: dict[str, Callable] = {}

    def register(
        self, name: str, description: str, parameters: dict, handler: Callable
    ) -> None:
        self._tools[name] = {
            "toolSpec": {
                "name": name,
                "description": description,
                "inputSchema": {"json": parameters},
            }
        }
        self._handlers[name] = handler

    def specs(self) -> list[dict]:
        return list(self._tools.values())

    def names(self) -> list[str]:
        return sorted(self._tools)

    def call(self, name: str, arguments: dict) -> Any:
        handler = self._handlers.get(name)
        if handler is None:
            raise ToolError(f"Unknown tool '{name}'. Available: {', '.join(self.names())}")
        return handler(**(arguments or {}))


def _schema(properties: dict, required: list[str] | None = None) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
    }


_STRING = {"type": "string"}
_INT = {"type": "integer"}


# --------------------------------------------------------------------------
# Tool construction
# --------------------------------------------------------------------------


def build_registry(service, account: Account) -> ToolRegistry:
    """All tools, bound to one account."""
    registry = ToolRegistry()
    plane = service.data_plane(account)
    repos = service.repos

    def _window(days: int = 30) -> tuple[datetime, datetime]:
        end = datetime.now(timezone.utc)
        return end - timedelta(days=days), end

    # ================================================================
    # Cost
    # ================================================================

    def get_cost_summary(days: int = 30) -> dict:
        start, end = _window(days)
        by_service = plane.cost.cost_by_service(start, end)
        total = round(sum(by_service.values()), 2)
        return {
            "period_days": days,
            "currency": "USD",
            "total_cost": total,
            "cost_by_service": by_service,
            "forecast_next_30_days": plane.cost.get_forecast(30),
            "note": "Amounts are unblended cost from Cost Explorer.",
        }

    def get_cost_by_service(days: int = 30, top_n: int = 10) -> dict:
        start, end = _window(days)
        by_service = plane.cost.cost_by_service(start, end)
        top = dict(list(by_service.items())[:top_n])
        return {"period_days": days, "currency": "USD", "cost_by_service": top}

    def get_cost_by_region(days: int = 30) -> dict:
        start, end = _window(days)
        return {
            "period_days": days,
            "currency": "USD",
            "cost_by_region": plane.cost.cost_by_region(start, end),
        }

    def get_daily_cost_trend(days: int = 30) -> dict:
        start, end = _window(days)
        points = plane.cost.get_cost_and_usage(start, end, "DAILY")
        series = [
            {"date": p.start.strftime("%Y-%m-%d"), "cost": round(p.amount, 2)}
            for p in points
        ]
        return {"period_days": days, "currency": "USD", "daily_cost": series}

    def get_cost_by_resource(resource_id: str, days: int = 30) -> dict:
        start, end = _window(days)
        observed = plane.cost.get_cost_by_resource(resource_id, start, end)
        if observed is None:
            resource = repos.resources.get(resource_id)
            return {
                "resource_id": resource_id,
                "observed_monthly_cost": None,
                "estimated_monthly_cost": resource.monthly_cost if resource else None,
                "note": (
                    "Resource-level cost data is not available for this account "
                    "or window. The estimate comes from on-demand list pricing "
                    "and does not reflect Savings Plans or Reserved Instances."
                ),
            }
        return {
            "resource_id": resource_id,
            "observed_monthly_cost": observed,
            "currency": "USD",
            "note": "Observed unblended cost from Cost Explorer, normalized to 30 days.",
        }

    def compare_cost_periods(window_days: int = 7) -> dict:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=window_days)
        return plane.cost.compare_periods(start, end, window_days)

    registry.register(
        "get_cost_summary",
        "Total AWS spend for the account broken down by service, plus a forecast. "
        "Use this first when asked a broad question about spending.",
        _schema({"days": {**_INT, "description": "Lookback window, default 30"}}),
        get_cost_summary,
    )
    registry.register(
        "get_cost_by_service",
        "Spend per AWS service, highest first.",
        _schema({"days": _INT, "top_n": _INT}),
        get_cost_by_service,
    )
    registry.register(
        "get_cost_by_region",
        "Spend per AWS region.",
        _schema({"days": _INT}),
        get_cost_by_region,
    )
    registry.register(
        "get_daily_cost_trend",
        "Daily spend as a time series. Use to see when a change in spending began.",
        _schema({"days": _INT}),
        get_daily_cost_trend,
    )
    registry.register(
        "get_cost_by_resource",
        "Cost attributable to one specific resource. Returns null observed cost "
        "when resource-level billing is not enabled, which is common.",
        _schema({"resource_id": _STRING, "days": _INT}, ["resource_id"]),
        get_cost_by_resource,
    )
    registry.register(
        "compare_cost_periods",
        "Compare the last N days against the N days before, per service. Use to "
        "quantify and attribute a spending increase.",
        _schema({"window_days": _INT}),
        compare_cost_periods,
    )

    # ================================================================
    # Anomalies
    # ================================================================

    def get_cost_anomalies(days: int = 30) -> dict:
        start, end = _window(days)
        anomalies = plane.cost.get_anomalies(start, end)
        return {
            "count": len(anomalies),
            "anomalies": [
                {
                    "anomaly_id": a.anomaly_id,
                    "service": a.service,
                    "start": a.start.strftime("%Y-%m-%d"),
                    "end": a.end.strftime("%Y-%m-%d") if a.end else None,
                    "expected_spend": a.expected_spend,
                    "actual_spend": a.actual_spend,
                    "excess": round(a.actual_spend - a.expected_spend, 2),
                    "increase_percent": a.increase_percent,
                    "root_causes": a.root_causes,
                }
                for a in anomalies
            ],
            "note": (
                "Raised by AWS Cost Anomaly Detection. An anomaly is a deviation "
                "from forecast, not necessarily waste: deployments and traffic "
                "growth look the same to it."
            ),
        }

    registry.register(
        "get_cost_anomalies",
        "Spending anomalies AWS has detected, with expected vs actual spend and "
        "AWS's own attribution.",
        _schema({"days": _INT}),
        get_cost_anomalies,
    )

    # ================================================================
    # AWS recommendations
    # ================================================================

    def get_aws_recommendations(resource_type: str | None = None) -> dict:
        types = None
        if resource_type:
            try:
                types = [ResourceType(resource_type.upper())]
            except ValueError as exc:
                raise ToolError(
                    f"Unknown resource_type '{resource_type}'. Valid: "
                    f"{', '.join(t.value for t in ResourceType)}"
                ) from exc
        recs = plane.recommendations.list_recommendations(types)
        return {
            "count": len(recs),
            "total_estimated_monthly_savings": round(
                sum(r.estimated_monthly_savings for r in recs), 2
            ),
            "recommendations": [
                {
                    "resource_id": r.resource_id,
                    "resource_type": r.resource_type.value,
                    "source": r.source,
                    "finding": r.finding,
                    "current": r.current_configuration,
                    "recommended": r.recommended_configuration,
                    "estimated_monthly_savings": r.estimated_monthly_savings,
                    "estimated_savings_percent": r.estimated_savings_percent,
                    "performance_risk": r.performance_risk,
                    "lookback_days": r.lookback_days,
                }
                for r in recs
            ],
            "note": (
                "These come from AWS Compute Optimizer and Cost Optimization Hub, "
                "not from CloudWaste. Attribute them to AWS when explaining."
            ),
        }

    registry.register(
        "get_aws_recommendations",
        "Optimization recommendations published by AWS Compute Optimizer and Cost "
        "Optimization Hub. Independent corroboration for a CloudWaste finding.",
        _schema({"resource_type": {**_STRING, "description": "EC2, EBS, RDS, LAMBDA"}}),
        get_aws_recommendations,
    )

    # ================================================================
    # Inventory and telemetry
    # ================================================================

    def list_resources(resource_type: str | None = None, limit: int = 50) -> dict:
        resources = repos.resources.list(account_id=account.account_id, limit=500)
        if resource_type:
            resources = [
                r for r in resources if r.resource_type.value == resource_type.upper()
            ]
        resources.sort(key=lambda r: r.monthly_cost, reverse=True)
        return {
            "count": len(resources),
            "resources": [
                {
                    "resource_id": r.resource_id,
                    "resource_type": r.resource_type.value,
                    "name": r.name,
                    "state": r.state,
                    "environment": r.environment.value,
                    "owner": r.owner,
                    "criticality": r.criticality.value,
                    "monthly_cost": r.monthly_cost,
                    "age_days": round(r.age_days, 1),
                }
                for r in resources[:limit]
            ],
        }

    def get_resource_details(resource_id: str) -> dict:
        resource = repos.resources.get(resource_id)
        if resource is None:
            raise ToolError(
                f"Resource '{resource_id}' is not in the inventory. Run a scan "
                f"first, or check the id."
            )
        return {
            "resource_id": resource.resource_id,
            "arn": resource.resource_arn,
            "resource_type": resource.resource_type.value,
            "name": resource.name,
            "state": resource.state,
            "region": resource.region,
            "environment": resource.environment.value,
            "owner": resource.owner,
            "criticality": resource.criticality.value,
            "auto_remediation_allowed": resource.auto_remediation_allowed,
            "tags": resource.tags,
            "configuration": resource.configuration,
            "monthly_cost": resource.monthly_cost,
            "age_days": round(resource.age_days, 1),
            "created_at": resource.created_at.isoformat() if resource.created_at else None,
        }

    def get_resource_metrics(resource_id: str, days: int = 14) -> dict:
        from ..adapters.aws.metrics import build_specs

        resource = repos.resources.get(resource_id)
        if resource is None:
            raise ToolError(f"Resource '{resource_id}' is not in the inventory")

        start, end = _window(days)
        specs = build_specs(resource.resource_type.value, resource_id)
        if not specs:
            return {
                "resource_id": resource_id,
                "metrics": {},
                "note": f"No metric catalog for {resource.resource_type.value}",
            }
        if hasattr(plane.metrics, "get_metrics"):
            series_list = plane.metrics.get_metrics(specs, start, end, 3600)
        else:
            series_list = [
                plane.metrics.get_metric(
                    s["namespace"], s["metric_name"], s["dimensions"], start, end,
                    s.get("statistic", "Average"), 3600,
                )
                for s in specs
            ]

        metrics = {}
        for spec, series in zip(specs, series_list):
            if series.datapoint_count == 0:
                metrics[spec["key"]] = {
                    "available": False,
                    "reason": (
                        "CloudWatch publishes no datapoints for this metric on "
                        "this resource. For memory and disk on EC2 this means the "
                        "CloudWatch agent is not installed. Treat as unmeasured, "
                        "not as zero."
                    ),
                }
                continue
            metrics[spec["key"]] = {
                "available": True,
                "metric": series.metric_name,
                "unit": series.unit,
                "average": round(series.average, 3),
                "p95": round(series.percentile(95), 3),
                "maximum": round(series.maximum, 3),
                "total": round(series.total, 3),
                "datapoints": series.datapoint_count,
                "window_days": round(series.span_days, 1),
            }
        return {"resource_id": resource_id, "window_days": days, "metrics": metrics}

    def get_resource_activity(resource_id: str, limit: int = 10) -> dict:
        resource = repos.resources.get(resource_id)
        if resource is None:
            raise ToolError(f"Resource '{resource_id}' is not in the inventory")
        events = plane.activity.lookup_events(resource_id=resource_id, limit=limit)
        last_write = plane.activity.days_since_last_write(
            resource_id, resource.resource_type.value
        )
        return {
            "resource_id": resource_id,
            "days_since_last_write": last_write,
            "events": [
                {
                    "event_name": e.event_name,
                    "event_time": e.event_time.isoformat(),
                    "user": e.username,
                    "source_ip": e.source_ip,
                    "read_only": e.read_only,
                }
                for e in events
            ],
            "note": (
                "CloudTrail management events cover the last 90 days only. No "
                "events for an older resource means untouched for at least that "
                "long, not that nothing ever happened."
            ),
        }

    registry.register(
        "list_resources",
        "Inventory of discovered resources, most expensive first.",
        _schema({"resource_type": _STRING, "limit": _INT}),
        list_resources,
    )
    registry.register(
        "get_resource_details",
        "Full configuration, tags, environment, owner and cost for one resource.",
        _schema({"resource_id": _STRING}, ["resource_id"]),
        get_resource_details,
    )
    registry.register(
        "get_resource_metrics",
        "CloudWatch utilization for one resource: average, p95, maximum and "
        "datapoint count per metric. Explicitly reports metrics that are not "
        "published rather than returning zero.",
        _schema({"resource_id": _STRING, "days": _INT}, ["resource_id"]),
        get_resource_metrics,
    )
    registry.register(
        "get_resource_activity",
        "CloudTrail history for one resource: who created it, who last changed "
        "it, and how long ago. Use this to answer 'who launched this?'.",
        _schema({"resource_id": _STRING, "limit": _INT}, ["resource_id"]),
        get_resource_activity,
    )

    # ================================================================
    # Findings and recommendations
    # ================================================================

    def list_findings(
        status: str = "OPEN", resource_type: str | None = None, limit: int = 25
    ) -> dict:
        findings = repos.findings.list(account_id=account.account_id, limit=500)
        if status and status.upper() != "ALL":
            findings = [f for f in findings if f.status.value == status.upper()]
        if resource_type:
            findings = [
                f for f in findings if f.resource_type.value == resource_type.upper()
            ]
        findings.sort(key=lambda f: f.potential_monthly_savings, reverse=True)
        return {
            "count": len(findings),
            "total_potential_monthly_savings": round(
                sum(f.potential_monthly_savings for f in findings), 2
            ),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "resource_id": f.resource_id,
                    "resource_type": f.resource_type.value,
                    "waste_type": f.waste_type.value,
                    "title": f.title,
                    "waste_score": f.waste_score,
                    "confidence": f.confidence,
                    "monthly_cost": f.monthly_cost,
                    "potential_monthly_savings": f.potential_monthly_savings,
                    "risk": f.risk.value,
                    "status": f.status.value,
                }
                for f in findings[:limit]
            ],
        }

    def get_finding_details(finding_id: str) -> dict:
        finding = repos.findings.get(finding_id)
        if finding is None:
            raise ToolError(f"Finding '{finding_id}' not found")
        recommendations = [
            r
            for r in repos.recommendations.list(account_id=account.account_id, limit=500)
            if r.finding_id == finding_id
        ]
        return {
            "finding": {
                **finding.model_dump(mode="json"),
                "score_contributions": finding.score_breakdown.as_contributions(),
            },
            "evidence": [e.model_dump(mode="json") for e in finding.evidence],
            "confidence_reasons": finding.confidence_reasons,
            "recommendations": [
                {
                    "recommendation_id": r.recommendation_id,
                    "action_type": r.action_type.value,
                    "current": r.current_configuration,
                    "recommended": r.recommended_configuration,
                    "monthly_savings": r.monthly_savings,
                    "risk": r.risk.value,
                    "restart_required": r.restart_required,
                    "rollback_possible": r.rollback_possible,
                    "rationale": r.rationale,
                    "simulation": (
                        r.simulation.model_dump(mode="json") if r.simulation else None
                    ),
                }
                for r in recommendations
            ],
        }

    registry.register(
        "list_findings",
        "Waste findings CloudWaste has produced, highest saving first.",
        _schema({"status": _STRING, "resource_type": _STRING, "limit": _INT}),
        list_findings,
    )
    registry.register(
        "get_finding_details",
        "Everything behind one finding: every piece of evidence with its source, "
        "the score breakdown, the confidence reasoning, and the proposed actions "
        "with their simulations. Use this before explaining a finding.",
        _schema({"finding_id": _STRING}, ["finding_id"]),
        get_finding_details,
    )

    # ================================================================
    # Simulation and proposal -- the only write, and it writes a proposal
    # ================================================================

    def simulate_recommendation(recommendation_id: str) -> dict:
        recommendation = repos.recommendations.get(recommendation_id)
        if recommendation is None:
            raise ToolError(f"Recommendation '{recommendation_id}' not found")
        resource = repos.resources.get(recommendation.resource_id)
        if resource is None:
            raise ToolError(f"Resource '{recommendation.resource_id}' not found")

        from ..intelligence import impact_analyzer

        simulation = impact_analyzer.simulate(
            resource,
            recommendation.action_type,
            recommendation.action_parameters,
            current_monthly_cost=resource.monthly_cost,
            confidence=recommendation.confidence,
        )
        return {
            "recommendation_id": recommendation_id,
            "resource_id": resource.resource_id,
            "action_type": recommendation.action_type.value,
            **simulation.model_dump(mode="json"),
        }

    def propose_action(recommendation_id: str, reason: str) -> dict:
        """Create a PENDING action. This never executes anything."""
        recommendation = repos.recommendations.get(recommendation_id)
        if recommendation is None:
            raise ToolError(f"Recommendation '{recommendation_id}' not found")
        resource = repos.resources.get(recommendation.resource_id)
        if resource is None:
            raise ToolError(f"Resource '{recommendation.resource_id}' not found")

        action, context = service.create_action(
            recommendation, resource, requested_by="agent", agent_id="cloudwaste-agent"
        )
        return {
            "action_id": action.action_id,
            "resource_id": action.resource_id,
            "action_type": action.action_type.value,
            "risk": action.risk.value,
            "policy_decision": action.policy_decision.value,
            "policy_rule": action.policy_rule,
            "approval_status": action.approval_status.value,
            "approval_required": action.approval_required,
            "agent_reason": reason,
            "risk_assessment": context["risk"],
            "policy_reasons": context["policy"]["reasons"],
            "note": (
                "This action is a proposal only. It has NOT been executed. It "
                "cannot be executed until a human approves it in the CloudWaste "
                "UI or API. You have no tool that can approve or execute it."
            ),
        }

    registry.register(
        "simulate_recommendation",
        "Project the cost, downtime, performance impact and rollback path for a "
        "recommendation, without changing anything.",
        _schema({"recommendation_id": _STRING}, ["recommendation_id"]),
        simulate_recommendation,
    )
    registry.register(
        "propose_action",
        "Create a proposed action for a recommendation and return what the policy "
        "engine decided about it. This does NOT execute anything and cannot: the "
        "action is created in a pending state and requires human approval. Use it "
        "when the user asks you to prepare or queue a change.",
        _schema(
            {
                "recommendation_id": _STRING,
                "reason": {
                    **_STRING,
                    "description": "Why you are proposing this, in one sentence",
                },
            },
            ["recommendation_id", "reason"],
        ),
        propose_action,
    )

    return registry
