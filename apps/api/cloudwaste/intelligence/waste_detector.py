"""Scan orchestration.

Gathers each resource's context once, runs the detectors over it, and returns
findings. The ordering matters for cost and for correctness:

  1. Inventory first, because everything else keys off resource ids.
  2. AWS recommendations in one bulk call, not one call per resource.
  3. Metrics in batches, because GetMetricData bills per request.
  4. CloudTrail last and only for resources that already look wasteful --
     LookupEvents is heavily throttled, and asking about a healthy production
     database wastes the budget that the interesting findings need.

That last point is the difference between a scan that finishes and one that
spends twenty minutes being throttled.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from ..adapters.aws.metrics import build_specs
from ..config import Settings, get_settings
from ..models.domain import Finding, Resource, Scan
from ..models.enums import ResourceType, WasteType
from .detectors.anomaly import CostAnomalyDetector
from .detectors.base import DetectionContext
from .detectors.ebs import EbsDetector
from .detectors.ec2 import Ec2Detector
from .detectors.lambda_ import LambdaDetector
from .detectors.network import ElasticIpDetector, NatGatewayDetector
from .detectors.rds import RdsDetector
from .detectors.s3 import S3Detector

logger = logging.getLogger(__name__)

DETECTORS = [
    Ec2Detector(),
    EbsDetector(),
    RdsDetector(),
    LambdaDetector(),
    S3Detector(),
    NatGatewayDetector(),
    ElasticIpDetector(),
]


class ScanResult:
    def __init__(self, scan: Scan, findings: list[Finding], resources: list[Resource]) -> None:
        self.scan = scan
        self.findings = findings
        self.resources = resources

    @property
    def total_monthly_cost(self) -> float:
        return round(sum(r.monthly_cost for r in self.resources), 2)

    @property
    def total_potential_savings(self) -> float:
        return round(sum(f.potential_monthly_savings for f in self.findings), 2)


class WasteDetector:
    def __init__(self, data_plane, settings: Settings | None = None) -> None:
        self.data = data_plane
        self.settings = settings or get_settings()
        self._detectors_by_type: dict[ResourceType, list] = {}
        for detector in DETECTORS:
            self._detectors_by_type.setdefault(detector.resource_type, []).append(detector)

    # ------------------------------------------------------------------

    def scan(self, scan_id: str | None = None) -> ScanResult:
        settings = self.settings
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=settings.metric_window_days)

        scan = Scan(
            account_id=self.data.account_id,
            regions=[self.data.region],
            scan_id=scan_id or Scan(account_id=self.data.account_id).scan_id,
        )

        # 1. Inventory
        resources = self.data.inventory.list_resources()
        by_id = {r.resource_id: r for r in resources}
        scan.resources_scanned = len(resources)
        for error in getattr(self.data.inventory, "discovery_errors", []):
            scan.errors.append(error)

        # 2. AWS recommendations, in bulk
        recommendations = {}
        try:
            recommendations = {
                rec.resource_id: rec
                for rec in self.data.recommendations.list_recommendations()
            }
        except Exception as exc:  # noqa: BLE001 - a scan must survive this
            logger.warning("recommendation lookup failed: %s", exc)
            scan.errors.append(f"AWS recommendations unavailable: {exc}")

        # 3. Metrics, batched per resource type
        metrics_by_resource = self._collect_metrics(resources, start, end)

        # 4. Observed cost, where the account exposes it
        observed_costs = self._collect_costs(resources, start, end)

        findings: list[Finding] = []
        for resource in resources:
            detectors = self._detectors_by_type.get(resource.resource_type, [])
            if not detectors:
                continue

            context = DetectionContext(
                resource=resource,
                settings=settings,
                metrics=metrics_by_resource.get(resource.resource_id, {}),
                optimizer=recommendations.get(resource.resource_id),
                observed_monthly_cost=observed_costs.get(resource.resource_id),
                scan_id=scan.scan_id,
                window_days=settings.metric_window_days,
                related_resources=by_id,
            )

            produced: list[Finding] = []
            for detector in detectors:
                try:
                    produced.extend(detector.detect(context))
                except Exception as exc:  # noqa: BLE001
                    logger.exception("detector %s failed on %s", detector.name, resource.resource_id)
                    scan.errors.append(
                        f"{detector.name} failed on {resource.resource_id}: {exc}"
                    )

            # 5. CloudTrail only for resources that produced a finding, then
            #    re-run so the finding carries the activity evidence.
            if produced:
                context.activity = self._activity_for(resource)
                context.days_since_last_write = self._last_write_for(resource)
                produced = []
                for detector in detectors:
                    try:
                        produced.extend(detector.detect(context))
                    except Exception as exc:  # noqa: BLE001
                        scan.errors.append(
                            f"{detector.name} failed on {resource.resource_id}: {exc}"
                        )
                findings.extend(produced)

        # 6. Account-level anomalies
        try:
            anomalies = self.data.cost.get_anomalies(start, end)
            findings.extend(
                CostAnomalyDetector().detect(
                    anomalies,
                    resources,
                    settings,
                    self.data.account_id,
                    self.data.region,
                    scan_id=scan.scan_id,
                )
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("anomaly detection failed: %s", exc)
            scan.errors.append(f"Cost anomaly detection unavailable: {exc}")

        # Drop findings too small to be worth anyone's attention. Anomalies are
        # exempt: they carry zero savings by design and are still worth showing.
        findings = [
            f
            for f in findings
            if f.waste_type is WasteType.COST_ANOMALY
            or f.potential_monthly_savings >= settings.min_monthly_savings_to_report
        ]
        findings.sort(
            key=lambda f: (f.potential_monthly_savings, f.waste_score), reverse=True
        )

        scan.findings_created = len(findings)
        scan.total_monthly_cost = round(sum(r.monthly_cost for r in resources), 2)
        scan.total_potential_savings = round(
            sum(f.potential_monthly_savings for f in findings), 2
        )
        scan.completed_at = datetime.now(timezone.utc)
        scan.status = "COMPLETED"

        return ScanResult(scan, findings, resources)

    # ------------------------------------------------------------------

    def _collect_metrics(
        self, resources: list[Resource], start: datetime, end: datetime
    ) -> dict[str, dict]:
        """One batched metrics call per resource type."""
        out: dict[str, dict] = {}
        by_type: dict[ResourceType, list[Resource]] = {}
        for resource in resources:
            by_type.setdefault(resource.resource_type, []).append(resource)

        for resource_type, group in by_type.items():
            if resource_type not in self._detectors_by_type:
                continue
            specs: list[dict] = []
            owners: list[tuple[str, str]] = []
            for resource in group:
                for spec in build_specs(resource_type.value, resource.resource_id):
                    specs.append(spec)
                    owners.append((resource.resource_id, spec["key"]))
            if not specs:
                continue

            try:
                if hasattr(self.data.metrics, "get_metrics"):
                    series_list = self.data.metrics.get_metrics(specs, start, end, 3600)
                else:
                    series_list = [
                        self.data.metrics.get_metric(
                            s["namespace"], s["metric_name"], s["dimensions"],
                            start, end, s.get("statistic", "Average"), 3600,
                        )
                        for s in specs
                    ]
            except Exception as exc:  # noqa: BLE001
                logger.warning("metric collection failed for %s: %s", resource_type, exc)
                continue

            for (resource_id, key), series in zip(owners, series_list):
                out.setdefault(resource_id, {})[key] = series
        return out

    def _collect_costs(
        self, resources: list[Resource], start: datetime, end: datetime
    ) -> dict[str, float]:
        """Observed per-resource cost, where the account supports it.

        A None answer is kept out of the map entirely so that detectors fall
        back to list pricing and mark the cost as estimated.
        """
        out: dict[str, float] = {}
        for resource in resources:
            try:
                observed = self.data.cost.get_cost_by_resource(
                    resource.resource_id, start, end
                )
            except Exception:  # noqa: BLE001
                observed = None
            if observed is not None:
                out[resource.resource_id] = observed
        return out

    def _activity_for(self, resource: Resource) -> list:
        try:
            return self.data.activity.lookup_events(resource_id=resource.resource_id, limit=10)
        except Exception as exc:  # noqa: BLE001
            logger.debug("cloudtrail lookup failed for %s: %s", resource.resource_id, exc)
            return []

    def _last_write_for(self, resource: Resource) -> float | None:
        try:
            return self.data.activity.days_since_last_write(
                resource.resource_id, resource.resource_type.value
            )
        except Exception:  # noqa: BLE001
            return None
