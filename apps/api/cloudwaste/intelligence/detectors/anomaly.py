"""Cost anomaly detection.

Unlike the other detectors this one is account-scoped, not resource-scoped: AWS
Cost Anomaly Detection reports that a service's spend deviated from its
forecast, and the interesting work is attributing that to something a human can
act on.

The finding produced here is a question, not an instruction. A spend increase
can be a deployment, a traffic spike, a data migration or a mistake, and only
the first three are supposed to happen. So the detector assembles the
attribution -- which service, which usage type, which resources changed in that
window -- and hands it to the investigation layer rather than proposing a fix.

Anomaly findings carry no automatic remediation path for that reason. There is
no safe generic action for "spend went up".
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ...adapters.base import ActivityEvent, CostAnomaly
from ...config import Settings
from ...models.domain import Evidence, Finding, Resource
from ...models.enums import FindingStatus, ResourceType, RiskLevel, WasteType
from .. import confidence_engine, waste_score


class CostAnomalyDetector:
    """Account-level, so it does not implement the resource `Detector` protocol."""

    name = "cost_anomaly"

    def detect(
        self,
        anomalies: list[CostAnomaly],
        resources: list[Resource],
        settings: Settings,
        account_id: str,
        region: str,
        activity: list[ActivityEvent] | None = None,
        scan_id: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for anomaly in anomalies:
            if anomaly.total_impact < settings.min_monthly_savings_to_report:
                continue
            findings.append(
                self._build(anomaly, resources, settings, account_id, region, activity, scan_id)
            )
        return findings

    def _build(
        self, anomaly, resources, settings, account_id, region, activity, scan_id
    ) -> Finding:
        excess = anomaly.actual_spend - anomaly.expected_spend
        impact_ratio = excess / anomaly.expected_spend if anomaly.expected_spend else 0.0
        duration_days = (
            ((anomaly.end or datetime.now(timezone.utc)) - anomaly.start).total_seconds()
            / 86400.0
        )
        monthly_run_rate = (
            excess / duration_days * 30.0 if duration_days >= 1 else excess * 30.0
        )

        evidence: list[Evidence] = [
            Evidence(
                source="cost_anomaly",
                metric="spend_deviation",
                value=round(excess, 2),
                unit="USD",
                detail=(
                    f"{anomaly.service} spent ${anomaly.actual_spend:,.2f} against an "
                    f"expected ${anomaly.expected_spend:,.2f}, an excess of "
                    f"${excess:,.2f} ({anomaly.increase_percent:+.1f}%)"
                ),
            ),
            Evidence(
                source="cost_anomaly",
                metric="anomaly_window",
                value=anomaly.start.strftime("%Y-%m-%d"),
                detail=(
                    f"Detected from {anomaly.start:%Y-%m-%d}"
                    + (f" to {anomaly.end:%Y-%m-%d}" if anomaly.end else " and ongoing")
                    + f", about {duration_days:.0f} days"
                ),
            ),
            Evidence(
                source="cost_anomaly",
                metric="projected_monthly_impact",
                value=round(monthly_run_rate, 2),
                unit="USD/month",
                detail=(
                    f"If the new rate persists it adds about "
                    f"${monthly_run_rate:,.2f}/month"
                ),
            ),
        ]

        for cause in anomaly.root_causes[:3]:
            parts = [f"{k}={v}" for k, v in cause.items() if v]
            evidence.append(
                Evidence(
                    source="cost_anomaly",
                    metric="root_cause",
                    value=cause.get("UsageType") or cause.get("Service"),
                    detail="AWS attributes the deviation to " + ", ".join(parts),
                )
            )

        suspects = self._correlate_resources(anomaly, resources)
        if suspects:
            evidence.append(
                Evidence(
                    source="resource_config",
                    metric="correlated_resources",
                    value=len(suspects),
                    detail=(
                        "Resources created or changed inside the anomaly window that "
                        "match its usage type: "
                        + ", ".join(
                            f"{r.resource_id} ({r.configuration.get('instance_type') or r.resource_type.value}, "
                            f"${r.monthly_cost:,.0f}/month)"
                            for r in suspects[:5]
                        )
                    ),
                )
            )

        for event in (activity or [])[:3]:
            evidence.append(
                Evidence(
                    source="cloudtrail",
                    metric="change_in_window",
                    value=event.event_name,
                    detail=(
                        f"{event.event_name} by "
                        f"{(event.username or 'unknown').rsplit('/', 1)[-1]} at "
                        f"{event.event_time:%Y-%m-%d %H:%M} UTC"
                    ),
                )
            )

        evidence.append(
            Evidence(
                source="cloudwaste",
                metric="no_automatic_action",
                value="investigation_only",
                detail=(
                    "A spend increase is not itself waste. This finding carries no "
                    "remediation action: it needs a human to say whether the new "
                    "spend was intended"
                ),
            )
        )

        breakdown = waste_score.compute(
            waste_score.ScoreInputs(
                monthly_cost=monthly_run_rate,
                anomaly_impact_ratio=impact_ratio,
            )
        )
        confidence = confidence_engine.compute(
            confidence_engine.ConfidenceInputs(
                observation_days=duration_days,
                expected_observation_days=duration_days or 1.0,
                datapoint_count=int(max(duration_days, 1)),
                expected_datapoint_count=int(max(duration_days, 1)),
                aws_recommendation_present=True,  # AWS raised this itself
                corroborating_signals=2 if suspects else 1,
                cost_is_estimated=False,
            )
        )

        return Finding(
            account_id=account_id,
            region=region,
            resource_id=suspects[0].resource_id if suspects else anomaly.service,
            resource_type=suspects[0].resource_type if suspects else ResourceType.EC2,
            waste_type=WasteType.COST_ANOMALY,
            waste_score=breakdown.total,
            score_breakdown=breakdown,
            confidence=confidence.score,
            confidence_reasons=confidence.reasons,
            monthly_cost=round(anomaly.actual_spend, 2),
            # Deliberately zero. The excess spend is real money, but it is not
            # *recoverable* money until someone decides the spend was
            # unintended -- and this finding has no remediation action. Putting
            # the run-rate here would inflate the account's headline savings
            # figure with dollars CloudWaste cannot actually save, and would
            # double-count against the rightsizing finding on the same resource.
            # The projected impact is carried in the evidence instead.
            potential_monthly_savings=0.0,
            risk=RiskLevel.MEDIUM,
            status=FindingStatus.OPEN,
            title=(
                f"{anomaly.service} spend rose {anomaly.increase_percent:+.0f}% "
                f"from {anomaly.start:%d %b}"
            ),
            summary=(
                f"AWS Cost Anomaly Detection flagged {anomaly.service} spending "
                f"${anomaly.actual_spend:,.2f} against an expected "
                f"${anomaly.expected_spend:,.2f} over about {duration_days:.0f} days, "
                f"an excess of ${excess:,.2f}. "
                + (
                    f"{len(suspects)} resource(s) created or changed in that window "
                    f"match the usage type AWS names. "
                    if suspects
                    else "No resource in the current inventory obviously accounts for it. "
                )
                + "Confirm whether this increase was intended before acting."
            ),
            evidence=evidence,
            detector=self.name,
            scan_id=scan_id,
        )

    @staticmethod
    def _correlate_resources(
        anomaly: CostAnomaly, resources: list[Resource]
    ) -> list[Resource]:
        """Find resources that plausibly explain the anomaly.

        Matches on usage type where AWS provides one -- 'BoxUsage:r5.4xlarge'
        names an instance type directly -- and on creation inside the window.
        """
        usage_types = {
            rc.get("UsageType", "") for rc in anomaly.root_causes if rc.get("UsageType")
        }
        named_types = {ut.split(":", 1)[-1] for ut in usage_types if ":" in ut}
        window_start = anomaly.start - timedelta(days=1)
        window_end = (anomaly.end or datetime.now(timezone.utc)) + timedelta(days=1)

        matches: list[Resource] = []
        for resource in resources:
            instance_type = resource.configuration.get(
                "instance_type"
            ) or resource.configuration.get("instance_class")
            type_match = bool(named_types) and instance_type in named_types
            created_in_window = (
                resource.created_at is not None
                and window_start <= resource.created_at <= window_end
            )
            if type_match or created_in_window:
                matches.append(resource)

        matches.sort(key=lambda r: r.monthly_cost, reverse=True)
        return matches
