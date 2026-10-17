"""Structured, deterministic explanation of a finding.

This is the explanation of record. It is assembled only from facts already
stored on the finding, its resource and its recommendations -- evidence items
with their sources, the score breakdown, confidence reasons, simulation and
risk and policy outcomes -- so every sentence can be traced to a field. The
AI agent may narrate this structure; it may not add to it.

Missing evidence is reported as missing. If there is no CloudTrail record, the
section says so; it does not say "no activity".
"""

from __future__ import annotations

from typing import Any

from ..models.domain import Evidence, Finding, Recommendation, Resource
from ..models.enums import ActionType, Environment, ResourceType, WasteType

#: Evidence source -> display group, in the order groups are shown.
EVIDENCE_GROUPS: list[tuple[str, str, tuple[str, ...]]] = [
    ("cloudwatch", "CloudWatch", ("cloudwatch",)),
    ("cloudtrail", "CloudTrail", ("cloudtrail",)),
    ("cost_explorer", "Cost Explorer", ("cost_explorer",)),
    ("compute_optimizer", "Compute Optimizer", ("compute_optimizer",)),
    ("cost_optimization_hub", "Cost Optimization Hub", ("cost_optimization_hub",)),
    (
        "aws_recommendation",
        "AWS recommendation (Cost Optimization Hub + Compute Optimizer)",
        ("cost_optimization_hub+compute_optimizer",),
    ),
    ("cost_anomaly", "Cost Anomaly Detection", ("cost_anomaly",)),
    ("tags", "Tags", ("tags",)),
    ("inventory", "AWS inventory", ("resource_config",)),
    ("pricing", "List pricing (estimate)", ("price_book",)),
    ("cloudwaste", "CloudWaste analysis", ("cloudwaste",)),
]

_AWS_RECOMMENDATION_SOURCES = (
    "compute_optimizer",
    "cost_optimization_hub",
    "cost_optimization_hub+compute_optimizer",
)

#: Resource types whose waste is measured by telemetry. For the others (a
#: detached volume, an unassociated address) the evidence is configuration and
#: an absent metric is not a gap.
_TELEMETRY_TYPES = {ResourceType.EC2, ResourceType.RDS, ResourceType.LAMBDA, ResourceType.NAT_GATEWAY}

_ROLLBACK_EXPLANATIONS = {
    "start_instance": "Start the instance again. Its instance id is unchanged.",
    "stop_instance": "Stop the instance again.",
    "restore_previous_instance_type": "Stop, set the previous instance type, start. Another brief outage.",
    "restore_previous_instance_class": "Modify the database back to its previous class. Another restart or failover.",
    "restore_previous_memory_size": "Set the previous memory size. Takes effect on the next invocation.",
    "restore_previous_storage_class": "Transition objects back. Retrieval and request charges apply.",
    "remove_lifecycle_rule": "Delete the lifecycle rule. Objects already transitioned stay where they are.",
    "delete_snapshot": "Delete the snapshot that was created.",
    "restore_previous_volume_type": "Convert the volume back. AWS allows one modification per volume every six hours.",
    "restore_volume_from_snapshot": (
        "Recovery, not undo: a NEW volume is created from the retained snapshot, with a "
        "new volume id, and must be re-attached by hand."
    ),
}


def _group_evidence(evidence: list[Evidence]) -> list[dict]:
    groups: list[dict] = []
    placed: set[int] = set()
    for key, label, sources in EVIDENCE_GROUPS:
        items = [
            (i, e) for i, e in enumerate(evidence) if e.source in sources and i not in placed
        ]
        placed.update(i for i, _ in items)
        if not items:
            continue
        groups.append({
            "key": key,
            "label": label,
            "items": [
                {
                    "metric": e.metric,
                    "value": e.value,
                    "unit": e.unit,
                    "window_days": e.window_days,
                    "detail": e.detail,
                    "measured": e.value is not None,
                }
                for _, e in items
            ],
        })
    leftovers = [e for i, e in enumerate(evidence) if i not in placed]
    if leftovers:
        groups.append({
            "key": "other",
            "label": "Other",
            "items": [
                {"metric": e.metric, "value": e.value, "unit": e.unit,
                 "window_days": e.window_days, "detail": f"[{e.source}] {e.detail}",
                 "measured": e.value is not None}
                for e in leftovers
            ],
        })
    return groups


def _missing_evidence(finding: Finding, resource: Resource | None) -> list[dict]:
    sources = {e.source for e in finding.evidence}
    missing: list[dict] = []
    anomaly = finding.waste_type is WasteType.COST_ANOMALY

    if finding.cost_source != "cost_explorer" and not anomaly:
        missing.append({
            "source": "Cost Explorer",
            "detail": "No observed resource-level billing. Cost is estimated from on-demand "
            "list prices and ignores Savings Plans and Reserved Instances.",
        })
    if not anomaly and not sources.intersection(_AWS_RECOMMENDATION_SOURCES):
        missing.append({
            "source": "Compute Optimizer / Cost Optimization Hub",
            "detail": "AWS has published no recommendation for this resource, so the "
            "finding is not independently corroborated.",
        })
    if "cloudtrail" not in sources and not anomaly:
        missing.append({
            "source": "CloudTrail",
            "detail": "No configuration change was found in the 90-day CloudTrail window. "
            "Who last changed this resource, and when, is unknown.",
        })
    if (
        finding.resource_type in _TELEMETRY_TYPES
        and "cloudwatch" not in sources
        and not anomaly
    ):
        missing.append({
            "source": "CloudWatch",
            "detail": "No utilization metrics support this finding.",
        })
    # Gaps the detector itself recorded, e.g. memory not published because the
    # CloudWatch agent is not installed. Only recorded gaps are reported: a
    # metric a detector simply did not cite is not claimed to be missing.
    for e in finding.evidence:
        if e.source == "cloudwatch" and e.value is None:
            missing.append({"source": "CloudWatch", "detail": e.detail})
    if resource is not None and not resource.tags:
        missing.append({
            "source": "Tags",
            "detail": "The resource has no tags: environment, owner and criticality are "
            "unknown, and it is treated as production.",
        })
    return missing


def _could_be_wrong(finding: Finding, resource: Resource | None) -> list[str]:
    reasons: list[str] = []
    sources = {e.source for e in finding.evidence}

    if finding.confidence < 70:
        reasons.append(
            f"Confidence is {finding.confidence:.0f}%, below the 70% level at which the "
            f"evidence is strong enough to act on without review."
        )
    windows = [e.window_days for e in finding.evidence if e.source == "cloudwatch" and e.window_days]
    if windows:
        reasons.append(
            f"Utilization was observed over {max(windows)} days; a monthly or quarterly "
            f"job would not appear in that window."
        )
    averages = {e.metric: e.value for e in finding.evidence if e.source == "cloudwatch"}
    avg = averages.get("CPUUtilization")
    p95 = averages.get("CPUUtilization p95")
    if isinstance(avg, (int, float)) and isinstance(p95, (int, float)) and avg > 0 and p95 > 3 * avg:
        reasons.append(
            f"CPU p95 ({p95:.1f}%) is far above the average ({avg:.1f}%): the workload "
            f"is bursty and a smaller size may not absorb the peaks."
        )
    if finding.cost_source != "cost_explorer":
        reasons.append(
            "Savings are priced from list prices; Savings Plan or Reserved Instance "
            "coverage would make the real saving smaller."
        )
    if not sources.intersection(_AWS_RECOMMENDATION_SOURCES) and finding.waste_type in (
        WasteType.UNDERUTILIZED_RESOURCE, WasteType.OVERPROVISIONED_RESOURCE
    ):
        reasons.append(
            "AWS has not profiled this workload itself; the target size comes from "
            "CloudWaste's price ladder rather than from Compute Optimizer."
        )
    last_write = next(
        (e.value for e in finding.evidence if e.metric == "days_since_last_write"), None
    )
    if isinstance(last_write, (int, float)) and last_write < 7:
        reasons.append(
            f"Someone changed this resource {last_write:.0f} day(s) ago; it may be "
            f"in active use or mid-migration."
        )
    if resource is not None and resource.environment is Environment.UNKNOWN:
        reasons.append(
            "The environment is unknown. It could be production, which is why it is "
            "treated as production."
        )
    if finding.waste_type is WasteType.UNATTACHED_STORAGE:
        reasons.append(
            "A detached volume may hold data someone still needs, such as a migration "
            "source or a forensic copy."
        )
    if finding.waste_type is WasteType.COST_ANOMALY:
        reasons.append(
            "An anomaly is a deviation from forecast. A deployment or genuine traffic "
            "growth looks identical to waste."
        )
    return reasons


def _rollback(rec: Recommendation) -> dict:
    method = rec.simulation.rollback_method if rec.simulation else None
    if not rec.rollback_possible or method is None:
        return {
            "available": False,
            "method": None,
            "description": "No rollback. This change cannot be undone, and CloudWaste "
            "does not describe a manual recovery as a rollback.",
        }
    return {
        "available": True,
        "method": method,
        "recovery_not_undo": rec.action_type is ActionType.DELETE_EBS,
        "description": _ROLLBACK_EXPLANATIONS.get(method, method),
    }


def build(
    finding: Finding,
    resource: Resource | None,
    recommendations: list[Recommendation],
    assessments: dict[str, Any] | None = None,
    policies: dict[str, Any] | None = None,
    dependencies: dict[str, Any] | None = None,
) -> dict:
    """Assemble the explanation.

    `assessments` and `policies` map recommendation_id to the risk assessment
    and policy evaluation for that recommendation, computed read-only by the
    service. `dependencies` is the advisory analysis for the resource, if any.
    """
    assessments = assessments or {}
    policies = policies or {}
    contributions = finding.score_breakdown.as_contributions()
    top = sorted(
        ((k, v) for k, v in contributions.items() if v > 0), key=lambda kv: kv[1], reverse=True
    )[:3]

    actions = []
    for rec in recommendations:
        sim = rec.simulation
        assessment = assessments.get(rec.recommendation_id)
        evaluation = policies.get(rec.recommendation_id)
        blocking = list(assessment.blocking_reasons) if assessment else []
        floors = list(assessment.floors_applied) if assessment else []
        actions.append({
            "recommendation_id": rec.recommendation_id,
            "action_type": rec.action_type.value,
            "current": rec.current_configuration,
            "recommended": rec.recommended_configuration,
            "rationale": rec.rationale,
            "expected_savings": {
                "monthly": rec.monthly_savings,
                "annual": rec.annual_savings,
                "basis": "ESTIMATED",
                "priced_from": sim.priced_from if sim else None,
                "assumptions": list(sim.assumptions) if sim else [],
            },
            "risk": {
                "level": (assessment.level if assessment else rec.risk).value,
                "score": assessment.score if assessment else None,
                "factors": list(assessment.factors) if assessment else [],
                "mitigations": list(assessment.mitigations) if assessment else [],
                "floors_applied": floors,
                "blocking_reasons": blocking,
            },
            "downtime": {
                "restart_required": rec.restart_required,
                "estimate_seconds": sim.downtime_estimate_seconds if sim else None,
                "description": (
                    "None expected."
                    if sim and sim.downtime_estimate_seconds == 0
                    else f"Up to {sim.downtime_estimate_seconds} seconds (upper bound)."
                    if sim
                    else "Unknown: no simulation."
                ),
                "performance_impact": sim.performance_impact if sim else None,
            },
            "rollback": _rollback(rec),
            "approval": {
                "decision": evaluation.decision.value if evaluation else None,
                "matched_rule": evaluation.matched_rule if evaluation else None,
                "reasons": list(evaluation.reasons) if evaluation else [],
                "summary": _approval_summary(evaluation),
            },
            "safety": {
                "why_safe": list(assessment.mitigations) if assessment else [],
                "why_unsafe": blocking + floors + (
                    [f for f in assessment.factors if not f.startswith("Base risk")]
                    if assessment else []
                ),
            },
        })

    primary = actions[0] if actions else None
    return {
        "finding_id": finding.finding_id,
        "generated_by": "deterministic",
        "llm_used": False,
        "resource": {
            "resource_id": finding.resource_id,
            "resource_type": finding.resource_type.value,
            "account_id": finding.account_id,
            "region": finding.region,
            "name": resource.name if resource else None,
            "environment": resource.environment.value if resource else "unknown",
            "owner": resource.owner if resource else None,
            "criticality": resource.criticality.value if resource else "unknown",
            "state": resource.state if resource else None,
            "auto_remediation_allowed": resource.auto_remediation_allowed if resource else None,
        },
        "scores": {
            "waste_score": finding.waste_score,
            "confidence": finding.confidence,
            "risk": finding.risk.value,
            "status": finding.status.value,
            "note": "Waste, confidence and risk are separate measures and are never combined.",
        },
        "cost": {
            "monthly_cost": finding.monthly_cost,
            "cost_source": finding.cost_source,
            "basis": "OBSERVED" if finding.cost_source == "cost_explorer" else "ESTIMATED",
        },
        "why_flagged": {
            "title": finding.title,
            "summary": finding.summary,
            "waste_type": finding.waste_type.value,
            "detector": finding.detector,
            "top_score_contributors": [{"component": k, "points": v} for k, v in top],
        },
        "evidence": _group_evidence(finding.evidence),
        "confidence_reasoning": list(finding.confidence_reasons),
        "missing_evidence": _missing_evidence(finding, resource),
        "could_be_wrong": _could_be_wrong(finding, resource),
        "recommended_actions": actions,
        "no_action_reason": None
        if actions
        else (
            "CloudWaste proposes no automatic action for this finding. Some findings, "
            "such as a low-traffic NAT gateway, an idle database or a cost anomaly, have "
            "no safe generic fix and need a person who knows the workload."
        ),
        "expected_savings": primary["expected_savings"] if primary else {
            "monthly": finding.potential_monthly_savings,
            "annual": finding.annual_savings,
            "basis": "ESTIMATED",
            "priced_from": finding.cost_source,
            "assumptions": [],
        },
        "risk": primary["risk"] if primary else None,
        "downtime": primary["downtime"] if primary else None,
        "rollback": primary["rollback"] if primary else None,
        "approval": primary["approval"] if primary else None,
        "dependencies": dependencies,
    }


def _approval_summary(evaluation) -> str | None:
    if evaluation is None:
        return None
    decision = evaluation.decision.value
    if decision == "DENY":
        return "Refused by policy. It cannot be executed, by anyone, until the reason changes."
    if decision == "AUTO_EXECUTE":
        return (
            "Policy would allow unattended execution. It still passes live preflight, "
            "checkpoint and verification, and runs in dry run while dry run is on."
        )
    return (
        "A human must approve it. The approval expires and is bound to this exact "
        "target, risk and saving."
    )
