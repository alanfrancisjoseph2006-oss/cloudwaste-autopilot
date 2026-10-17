"""S3 lifecycle waste detection.

The saving here is real but the arithmetic is easy to get wrong in the
customer's disfavour, so this detector models the costs that a naive
"move everything to Intelligent-Tiering" recommendation ignores:

  * Intelligent-Tiering charges a monitoring fee per object per month. For a
    bucket of many small objects that fee can exceed the storage saving. The
    detector computes the break-even and stays quiet when it fails.
  * Transitioning objects costs a per-object request fee, paid once. A saving
    that takes eleven months to pay back is not a saving worth a change.
  * Retrieval from the colder classes costs money, so a bucket serving heavy
    read traffic is left alone regardless of object age.

Object-age data comes from S3 Storage Lens or an inventory report. Without it
the detector reports what it can and lowers confidence rather than guessing.
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
    standard_confidence_inputs,
    tag_evidence,
)

TRANSITION_COST_PER_1K_OBJECTS = 0.01
MAX_ACCEPTABLE_PAYBACK_MONTHS = 6.0
# Above this read rate the bucket is hot and retrieval fees would bite.
HOT_BUCKET_GETS_PER_GB_MONTH = 100.0


class S3Detector:
    name = "s3_lifecycle"
    resource_type = ResourceType.S3

    def detect(self, context: DetectionContext) -> list[Finding]:
        resource = context.resource
        config = resource.configuration
        size_gb = config.get("size_gb")
        object_count = config.get("object_count")
        # Unpublished storage metrics mean the size is unknown, not zero. With
        # no size there is no saving to compute, so the bucket is not flagged.
        if size_gb is None or object_count is None:
            return []

        if size_gb < 1.0 or object_count <= 0:
            return []

        gets_per_month = config.get("get_requests_month", 0)
        gets_per_gb = gets_per_month / size_gb if size_gb else 0.0
        if gets_per_gb > HOT_BUCKET_GETS_PER_GB_MONTH:
            return []  # actively served; colder storage would cost more than it saves

        pct_cold = config.get("pct_objects_older_than_90d")
        if config.get("has_lifecycle_policy") and pct_cold is None:
            return []

        current_cost = pricing.s3_monthly("STANDARD", size_gb).monthly
        avg_object_mb = size_gb * 1024 / object_count

        target_class, projected_storage_cost, basis = self._choose_target(
            size_gb, pct_cold, config
        )
        if target_class is None:
            return []

        monitoring_cost = 0.0
        if target_class == "INTELLIGENT_TIERING":
            monitoring_cost = (
                object_count
                / 1000.0
                * pricing.S3_INTELLIGENT_TIERING_MONITORING_PER_1K_OBJECTS
            )

        net_monthly_saving = round(
            current_cost - projected_storage_cost - monitoring_cost, 2
        )
        if net_monthly_saving < context.settings.min_monthly_savings_to_report:
            return []

        transition_cost = object_count / 1000.0 * TRANSITION_COST_PER_1K_OBJECTS
        payback_months = (
            transition_cost / net_monthly_saving if net_monthly_saving > 0 else 999.0
        )
        if payback_months > MAX_ACCEPTABLE_PAYBACK_MONTHS:
            return []

        evidence = [
            Evidence(
                source="resource_config",
                metric="bucket_size",
                value=round(size_gb, 1),
                unit="GB",
                detail=(
                    f"{size_gb:,.0f} GB across {object_count:,} objects "
                    f"(average object {avg_object_mb:,.2f} MB), all in STANDARD"
                ),
            ),
            Evidence(
                source="resource_config",
                metric="lifecycle_policy",
                value=config.get("has_lifecycle_policy", False),
                detail=(
                    "No lifecycle policy is configured, so objects stay in STANDARD "
                    "for their entire life"
                    if not config.get("has_lifecycle_policy")
                    else "A lifecycle policy exists but leaves cold objects in STANDARD"
                ),
            ),
            cost_evidence(context),
            tag_evidence(resource),
            Evidence(
                source="cloudwaste",
                metric="net_monthly_saving",
                value=net_monthly_saving,
                unit="USD/month",
                detail=(
                    f"${current_cost:,.2f} today against ${projected_storage_cost:,.2f} "
                    f"storage"
                    + (
                        f" plus ${monitoring_cost:,.2f} monitoring"
                        if monitoring_cost
                        else ""
                    )
                    + f" on {target_class}, a net ${net_monthly_saving:,.2f}/month"
                ),
            ),
            Evidence(
                source="cloudwaste",
                metric="payback_period",
                value=round(payback_months, 2),
                unit="months",
                detail=(
                    f"One-off transition cost of ${transition_cost:,.2f} for "
                    f"{object_count:,} objects, recovered in "
                    f"{payback_months:.1f} months"
                ),
            ),
        ]
        if pct_cold is not None:
            evidence.append(
                Evidence(
                    source="resource_config",
                    metric="pct_objects_older_than_90d",
                    value=pct_cold,
                    unit="Percent",
                    detail=(
                        f"{pct_cold:.0f}% of objects are older than 90 days "
                        f"(average age {config.get('avg_object_age_days')} days)"
                    ),
                )
            )
        evidence.append(
            Evidence(
                source="cloudwatch",
                metric="GetRequests",
                value=gets_per_month,
                unit="Count/month",
                detail=(
                    f"{gets_per_month:,} GET requests per month, "
                    f"{gets_per_gb:,.1f} per GB stored, low enough that retrieval "
                    f"charges stay immaterial"
                ),
            )
        )

        return [
            build_finding(
                context,
                waste_type=WasteType.STORAGE_LIFECYCLE_WASTE,
                title=f"Bucket {resource.resource_id} has no cold-storage lifecycle",
                summary=(
                    f"{size_gb:,.0f} GB sits in STANDARD storage"
                    + (
                        f" with {pct_cold:.0f}% of objects older than 90 days"
                        if pct_cold is not None
                        else ""
                    )
                    + f". {basis} The net saving after monitoring and transition "
                    f"charges is about ${net_monthly_saving:,.2f}/month, paying back "
                    f"the one-off ${transition_cost:,.2f} transition cost in "
                    f"{payback_months:.1f} months."
                ),
                evidence=evidence,
                potential_monthly_savings=net_monthly_saving,
                detector=self.name,
                score_inputs=waste_score.ScoreInputs(
                    monthly_cost=context.monthly_cost,
                    age_days=resource.age_days,
                    aws_recommendation_savings_percent=round(
                        net_monthly_saving / current_cost * 100, 1
                    )
                    if current_cost
                    else None,
                ),
                confidence_inputs=standard_confidence_inputs(
                    context,
                    corroborating_signals=2 if pct_cold is not None else 1,
                    memory_metric_missing=False,
                ),
                action_context={
                    "target_storage_class": target_class,
                    "projected_monthly_cost": round(
                        projected_storage_cost + monitoring_cost, 2
                    ),
                    "transition_cost": round(transition_cost, 2),
                    "transition_days": 90,
                },
            )
        ]

    @staticmethod
    def _choose_target(
        size_gb: float, pct_cold: float | None, config: dict
    ) -> tuple[str | None, float, str]:
        """Intelligent-Tiering when access is unpredictable, an explicit
        archival transition when most objects are provably cold."""
        if pct_cold is not None and pct_cold >= 70.0:
            cold_gb = size_gb * pct_cold / 100.0
            warm_gb = size_gb - cold_gb
            projected = (
                pricing.s3_monthly("GLACIER_IR", cold_gb).monthly
                + pricing.s3_monthly("STANDARD", warm_gb).monthly
            )
            return (
                "GLACIER_IR",
                round(projected, 2),
                (
                    f"A lifecycle rule transitioning objects to Glacier Instant "
                    f"Retrieval after 90 days fits the access pattern, keeping "
                    f"millisecond retrieval."
                ),
            )
        if pct_cold is None or pct_cold >= 30.0:
            projected = pricing.s3_monthly("STANDARD_IA", size_gb * 0.6).monthly
            projected += pricing.s3_monthly("STANDARD", size_gb * 0.4).monthly
            return (
                "INTELLIGENT_TIERING",
                round(projected, 2),
                (
                    "Access is uneven enough that Intelligent-Tiering, which moves "
                    "objects between tiers automatically, is the safer choice than a "
                    "fixed rule."
                ),
            )
        return None, 0.0, ""
