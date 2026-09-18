"""NAT gateway and Elastic IP detection.

The NAT gateway detector is deliberately the most cautious in the system, and
it is worth saying why. A NAT gateway processing almost no data looks like
obvious waste, and deleting it is a one-line API call. But a NAT gateway exists
so that private subnets can reach the internet, and the traffic it carries is
often bursty and rare: OS patching, certificate renewal, a nightly package
pull. Low throughput frequently means "correctly sized for occasional egress",
not "unused". Delete it and nothing breaks until the next patch window.

So this detector never proposes deletion. It reports the finding, states the
architecture it found, and names the specific checks a human must make. That is
the honest output for a signal this ambiguous, and it is the difference between
a tool operators trust and one they switch off.

Elastic IPs are the opposite case: an unassociated address has no function at
all, AWS charges for it by the hour, and releasing it is cheap and obvious.
"""

from __future__ import annotations

from ...models.domain import Evidence, Finding
from ...models.enums import ResourceType, WasteType
from .. import waste_score
from .base import (
    DetectionContext,
    activity_evidence,
    build_finding,
    cost_evidence,
    metric_evidence,
    standard_confidence_inputs,
    tag_evidence,
)

LOW_THROUGHPUT_GB_MONTH = 10.0


class NatGatewayDetector:
    name = "nat_gateway_usage"
    resource_type = ResourceType.NAT_GATEWAY

    def detect(self, context: DetectionContext) -> list[Finding]:
        resource = context.resource
        if resource.state not in (None, "available"):
            return []
        if resource.age_days < context.settings.min_observation_days:
            return []

        bytes_out = context.series("bytes_out_to_destination")
        bytes_in = context.series("bytes_in_from_source")
        if bytes_out is None and bytes_in is None:
            return []

        observed_days = max(context.observation_days(), 1.0)
        total_bytes = (bytes_out.total if bytes_out else 0.0) + (
            bytes_in.total if bytes_in else 0.0
        )
        gb_per_month = total_bytes / observed_days * 30.0 / 1e9
        if gb_per_month > LOW_THROUGHPUT_GB_MONTH:
            return []

        connections = context.series("active_connections")
        peak_connections = connections.maximum if connections else None
        config = resource.configuration
        route_tables = config.get("route_tables_referencing", [])
        private_subnets = config.get("private_subnets_served")

        evidence: list[Evidence] = [
            Evidence(
                source="cloudwatch",
                metric="data_processed",
                value=round(gb_per_month, 3),
                unit="GB/month",
                window_days=context.window_days,
                detail=(
                    f"About {gb_per_month:,.2f} GB/month passes through this gateway. "
                    f"The hourly charge dominates: it costs "
                    f"${context.monthly_cost:,.2f}/month regardless of traffic"
                ),
            ),
            cost_evidence(context),
            tag_evidence(resource),
        ]
        if connections:
            evidence.append(
                metric_evidence(
                    connections, "ActiveConnectionCount", statistic="maximum", unit="Count"
                )
            )
        if route_tables:
            evidence.append(
                Evidence(
                    source="resource_config",
                    metric="route_tables_referencing",
                    value=len(route_tables),
                    detail=(
                        f"{len(route_tables)} route table(s) still send 0.0.0.0/0 to "
                        f"this gateway: {', '.join(route_tables)}. Anything in those "
                        f"subnets loses outbound internet access if it is removed"
                    ),
                )
            )
        if private_subnets:
            evidence.append(
                Evidence(
                    source="resource_config",
                    metric="private_subnets_served",
                    value=private_subnets,
                    detail=(
                        f"{private_subnets} private subnet(s) depend on this gateway "
                        f"for outbound connectivity"
                    ),
                )
            )
        activity = activity_evidence(context)
        if activity:
            evidence.append(activity)

        evidence.append(
            Evidence(
                source="cloudwaste",
                metric="investigation_required",
                value="manual",
                detail=(
                    "Low throughput is not sufficient evidence to remove a NAT "
                    "gateway. Confirm first: (1) no workload in the attached private "
                    "subnets performs infrequent egress such as OS patching or "
                    "certificate renewal; (2) no scheduled or seasonal job depends on "
                    "it outside the observation window; (3) if egress is still needed "
                    "at this volume, VPC endpoints for S3 and DynamoDB may remove the "
                    "need entirely at lower cost"
                ),
            )
        )

        return [
            build_finding(
                context,
                waste_type=WasteType.UNUSED_NETWORK_RESOURCE,
                title=(
                    f"NAT gateway {resource.resource_id} processes almost no traffic"
                ),
                summary=(
                    f"This gateway processed about {gb_per_month:,.2f} GB/month over "
                    f"{observed_days:.0f} days while costing "
                    f"${context.monthly_cost:,.2f}/month, nearly all of it the fixed "
                    f"hourly charge. CloudWaste does not recommend deleting it on this "
                    f"evidence alone: {len(route_tables) or 'unknown'} route table(s) "
                    f"still reference it, and NAT traffic is often rare rather than "
                    f"absent. Review the listed checks, or consider replacing it with "
                    f"VPC endpoints if the egress is only to AWS services."
                ),
                evidence=evidence,
                potential_monthly_savings=context.monthly_cost,
                detector=self.name,
                score_inputs=waste_score.ScoreInputs(
                    utilization_ratio=min(1.0, gb_per_month / LOW_THROUGHPUT_GB_MONTH),
                    monthly_cost=context.monthly_cost,
                    age_days=resource.age_days,
                ),
                confidence_inputs=standard_confidence_inputs(
                    context,
                    corroborating_signals=2,
                    memory_metric_missing=False,
                    # Rare-but-essential egress is exactly a pattern a 14-day
                    # window can miss, and saying so lowers confidence honestly.
                    seasonal_pattern_suspected=True,
                ),
            )
        ]


class ElasticIpDetector:
    name = "elastic_ip_usage"
    resource_type = ResourceType.ELASTIC_IP

    def detect(self, context: DetectionContext) -> list[Finding]:
        resource = context.resource
        config = resource.configuration
        if config.get("association_id"):
            return []
        if context.monthly_cost <= 0:
            return []

        return [
            build_finding(
                context,
                waste_type=WasteType.UNUSED_NETWORK_RESOURCE,
                title=f"Unassociated Elastic IP {config.get('public_ip', resource.resource_id)}",
                summary=(
                    f"This address is allocated but attached to nothing, and AWS "
                    f"charges for unassociated public IPv4 addresses by the hour. It "
                    f"has been idle for about {resource.age_days:.0f} days at "
                    f"${context.monthly_cost:,.2f}/month. Releasing it is immediate "
                    f"and cheap, but the address itself cannot be reclaimed "
                    f"afterwards, so confirm nothing external allow-lists it."
                ),
                evidence=[
                    Evidence(
                        source="resource_config",
                        metric="association",
                        value=None,
                        detail=(
                            "No association ID and no attached network interface: "
                            "the address is reserved but unused"
                        ),
                    ),
                    cost_evidence(context),
                    tag_evidence(resource),
                    Evidence(
                        source="cloudwaste",
                        metric="irreversibility",
                        value="address_not_reclaimable",
                        detail=(
                            "Once released, the same address cannot be allocated "
                            "again. Check for DNS records, firewall allow-lists or "
                            "partner integrations pinned to it first"
                        ),
                    ),
                ],
                potential_monthly_savings=context.monthly_cost,
                detector=self.name,
                score_inputs=waste_score.ScoreInputs(
                    utilization_ratio=0.0,
                    monthly_cost=context.monthly_cost,
                    idle_days=resource.age_days,
                    age_days=resource.age_days,
                ),
                confidence_inputs=standard_confidence_inputs(
                    context,
                    corroborating_signals=2,
                    memory_metric_missing=False,
                    metrics_not_applicable=True,
                ),
            )
        ]
