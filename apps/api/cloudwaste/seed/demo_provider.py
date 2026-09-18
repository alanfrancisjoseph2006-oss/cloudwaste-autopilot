"""A deterministic synthetic AWS account.

This exists for three reasons, in order of importance:

 1. The safety machinery (policy, approval, checkpoint, rollback, verification)
    is the hard part of this system and it must be testable without pointing a
    remediation engine at somebody's production account.
 2. A demo must be reproducible. Same seed, same numbers, every run.
 3. Reviewers can clone the repo and see the whole pipeline in one command.

Every value here is synthetic. Nothing in this module ever calls AWS. The
resources are shaped to exercise each detector *and* each risk tier, including
cases that must NOT produce a finding -- a busy production database, a
correctly-sized instance -- because a waste detector that flags everything is
worse than none.
"""

from __future__ import annotations

import hashlib
import math
import random
from datetime import datetime, timedelta, timezone
from typing import Any

from ..adapters import pricing, tags as tagging
from ..adapters.base import (
    ActivityEvent,
    CostAnomaly,
    CostPoint,
    MetricPoint,
    MetricSeries,
    OptimizerRecommendation,
)
from ..models.domain import Resource
from ..models.enums import ResourceType

DEMO_ACCOUNT_ID = "123456789012"
DEMO_REGION = "us-east-1"
SEED = 20260918


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _rng(*parts: Any) -> random.Random:
    """Deterministic per-key RNG, so one resource's numbers never shift when
    another is added."""
    key = "|".join(str(p) for p in parts)
    digest = hashlib.sha256(f"{SEED}|{key}".encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


# ---------------------------------------------------------------------------
# The account. Each spec carries a `profile` the metric generator reads.
# ---------------------------------------------------------------------------

_SPECS: list[dict[str, Any]] = [
    # --- the headline finding: underutilized production-adjacent dev box ----
    {
        "resource_id": "i-0a1b2c3d4e5f60001",
        "type": ResourceType.EC2,
        "name": "analytics-etl-runner",
        "tags": {"Name": "analytics-etl-runner", "Environment": "development",
                 "Owner": "data-platform", "Project": "etl"},
        "age_days": 23,
        "state": "running",
        "config": {"instance_type": "m5.2xlarge", "vpc_id": "vpc-demo01",
                   "subnet_id": "subnet-demo01", "architecture": "x86_64",
                   "attached_volumes": ["vol-0a1b2c3d4e5f60001"]},
        "profile": {"cpu_avg": 8.7, "cpu_p95": 14.2, "net_mb_day": 340,
                    "memory_avg": 22.0, "has_cwagent": True},
        "optimizer": {"finding": "OVER_PROVISIONED", "recommended": "m5.large",
                      "performance_risk": 1.0, "savings_percent": 75.0},
    },
    # --- genuinely idle: nothing running at all ----------------------------
    {
        "resource_id": "i-0a1b2c3d4e5f60002",
        "type": ResourceType.EC2,
        "name": "legacy-jenkins-agent",
        "tags": {"Name": "legacy-jenkins-agent", "Environment": "dev", "Owner": "platform"},
        "age_days": 96,
        "state": "running",
        "config": {"instance_type": "t3.xlarge", "vpc_id": "vpc-demo01",
                   "subnet_id": "subnet-demo01", "architecture": "x86_64",
                   "attached_volumes": ["vol-0a1b2c3d4e5f60002"]},
        "profile": {"cpu_avg": 0.9, "cpu_p95": 2.1, "net_mb_day": 1.2,
                    "memory_avg": 8.0, "has_cwagent": True},
        "optimizer": {"finding": "OVER_PROVISIONED", "recommended": "t3.micro",
                      "performance_risk": 1.0, "savings_percent": 93.0},
    },
    # --- production, busy, correctly sized: must NOT be flagged ------------
    {
        "resource_id": "i-0a1b2c3d4e5f60003",
        "type": ResourceType.EC2,
        "name": "payments-api-prod-01",
        "tags": {"Name": "payments-api-prod-01", "Environment": "production",
                 "Owner": "payments", "Criticality": "high", "AutoRemediation": "false"},
        "age_days": 412,
        "state": "running",
        "config": {"instance_type": "c5.2xlarge", "vpc_id": "vpc-demo02",
                   "subnet_id": "subnet-demo02", "architecture": "x86_64",
                   "attached_volumes": ["vol-0a1b2c3d4e5f60003"]},
        "profile": {"cpu_avg": 61.4, "cpu_p95": 84.0, "net_mb_day": 41000,
                    "memory_avg": 68.0, "has_cwagent": True},
    },
    # --- production but oversized: HIGH risk finding -----------------------
    {
        "resource_id": "i-0a1b2c3d4e5f60004",
        "type": ResourceType.EC2,
        "name": "reporting-prod-worker",
        "tags": {"Name": "reporting-prod-worker", "Environment": "production",
                 "Owner": "analytics", "Criticality": "medium"},
        "age_days": 187,
        "state": "running",
        "config": {"instance_type": "r5.4xlarge", "vpc_id": "vpc-demo02",
                   "subnet_id": "subnet-demo02", "architecture": "x86_64",
                   "attached_volumes": ["vol-0a1b2c3d4e5f60004"]},
        "profile": {"cpu_avg": 11.2, "cpu_p95": 19.8, "net_mb_day": 2200,
                    "memory_avg": 31.0, "has_cwagent": True},
        "optimizer": {"finding": "OVER_PROVISIONED", "recommended": "r5.xlarge",
                      "performance_risk": 2.0, "savings_percent": 50.0},
    },
    # --- untagged: environment UNKNOWN, must be treated as production ------
    {
        "resource_id": "i-0a1b2c3d4e5f60005",
        "type": ResourceType.EC2,
        "name": None,
        "tags": {},
        "age_days": 64,
        "state": "running",
        "config": {"instance_type": "m5.xlarge", "vpc_id": "vpc-demo01",
                   "subnet_id": "subnet-demo03", "architecture": "x86_64",
                   "attached_volumes": []},
        "profile": {"cpu_avg": 3.1, "cpu_p95": 6.4, "net_mb_day": 18,
                    "memory_avg": 0.0, "has_cwagent": False},
    },
    # --- stopped instance still paying for its volume ---------------------
    {
        "resource_id": "i-0a1b2c3d4e5f60006",
        "type": ResourceType.EC2,
        "name": "ml-training-spot",
        "tags": {"Name": "ml-training-spot", "Environment": "test", "Owner": "ml"},
        "age_days": 51,
        "state": "stopped",
        "config": {"instance_type": "m5.4xlarge", "vpc_id": "vpc-demo01",
                   "subnet_id": "subnet-demo01", "architecture": "x86_64",
                   "attached_volumes": ["vol-0a1b2c3d4e5f60005"]},
        "profile": {"cpu_avg": 0.0, "cpu_p95": 0.0, "net_mb_day": 0.0,
                    "memory_avg": 0.0, "has_cwagent": False},
    },
    # --- EBS -------------------------------------------------------------
    {
        "resource_id": "vol-0a1b2c3d4e5f60001",
        "type": ResourceType.EBS, "name": "analytics-etl-root",
        "tags": {"Environment": "development", "Owner": "data-platform"},
        "age_days": 23, "state": "in-use",
        "config": {"volume_type": "gp3", "size_gb": 200, "iops": 3000,
                   "attached_to": "i-0a1b2c3d4e5f60001", "encrypted": True},
        "profile": {"read_ops_day": 44000, "write_ops_day": 91000},
    },
    {
        "resource_id": "vol-0a1b2c3d4e5f60002",
        "type": ResourceType.EBS, "name": "jenkins-agent-root",
        "tags": {"Environment": "dev", "Owner": "platform"},
        "age_days": 96, "state": "in-use",
        "config": {"volume_type": "gp2", "size_gb": 100, "iops": 300,
                   "attached_to": "i-0a1b2c3d4e5f60002", "encrypted": False},
        "profile": {"read_ops_day": 120, "write_ops_day": 340},
    },
    {
        "resource_id": "vol-0a1b2c3d4e5f60003",
        "type": ResourceType.EBS, "name": "payments-prod-data",
        "tags": {"Environment": "production", "Owner": "payments", "Criticality": "high"},
        "age_days": 412, "state": "in-use",
        "config": {"volume_type": "io2", "size_gb": 500, "iops": 8000,
                   "attached_to": "i-0a1b2c3d4e5f60003", "encrypted": True},
        "profile": {"read_ops_day": 2_100_000, "write_ops_day": 3_400_000},
    },
    {
        "resource_id": "vol-0a1b2c3d4e5f60004",
        "type": ResourceType.EBS, "name": "reporting-prod-data",
        "tags": {"Environment": "production", "Owner": "analytics"},
        "age_days": 187, "state": "in-use",
        "config": {"volume_type": "gp3", "size_gb": 1000, "iops": 6000,
                   "attached_to": "i-0a1b2c3d4e5f60004", "encrypted": True},
        "profile": {"read_ops_day": 8000, "write_ops_day": 14000},
    },
    {
        "resource_id": "vol-0a1b2c3d4e5f60005",
        "type": ResourceType.EBS, "name": "ml-training-scratch",
        "tags": {"Environment": "test", "Owner": "ml"},
        "age_days": 51, "state": "in-use",
        "config": {"volume_type": "gp3", "size_gb": 2000, "iops": 3000,
                   "attached_to": "i-0a1b2c3d4e5f60006", "encrypted": True},
        "profile": {"read_ops_day": 0, "write_ops_day": 0},
    },
    # unattached, old, has a recent snapshot -> safe to delete
    {
        "resource_id": "vol-0a1b2c3d4e5f60006",
        "type": ResourceType.EBS, "name": "orphaned-migration-disk",
        "tags": {"Environment": "development", "Owner": "platform"},
        "age_days": 143, "state": "available",
        "config": {"volume_type": "gp2", "size_gb": 500, "iops": 1500,
                   "attached_to": None, "encrypted": True,
                   "latest_snapshot_id": "snap-0demo0001",
                   "latest_snapshot_age_days": 3, "detached_days": 131},
        "profile": {"read_ops_day": 0, "write_ops_day": 0},
    },
    # unattached, NO snapshot -> must be snapshot-first, higher risk
    {
        "resource_id": "vol-0a1b2c3d4e5f60007",
        "type": ResourceType.EBS, "name": "unknown-detached-volume",
        "tags": {},
        "age_days": 78, "state": "available",
        "config": {"volume_type": "gp3", "size_gb": 300, "iops": 3000,
                   "attached_to": None, "encrypted": False,
                   "latest_snapshot_id": None, "detached_days": 44},
        "profile": {"read_ops_day": 0, "write_ops_day": 0},
    },
    # --- RDS -------------------------------------------------------------
    {
        "resource_id": "payments-prod-db",
        "type": ResourceType.RDS, "name": "payments-prod-db",
        "tags": {"Environment": "production", "Owner": "payments", "Criticality": "high",
                 "AutoRemediation": "false"},
        "age_days": 620, "state": "available",
        "config": {"instance_class": "db.r6g.2xlarge", "engine": "postgres",
                   "engine_version": "15.5", "multi_az": True,
                   "allocated_storage_gb": 500, "storage_type": "gp3",
                   "deletion_protection": True, "backup_retention_days": 14},
        "profile": {"cpu_avg": 14.8, "cpu_p95": 28.5, "connections_avg": 42,
                    "connections_max": 88, "read_iops": 340, "write_iops": 210},
        "optimizer": {"finding": "Overprovisioned", "recommended": "db.r6g.large",
                      "performance_risk": 2.0, "savings_percent": 50.0},
    },
    {
        "resource_id": "analytics-dev-db",
        "type": ResourceType.RDS, "name": "analytics-dev-db",
        "tags": {"Environment": "development", "Owner": "data-platform"},
        "age_days": 210, "state": "available",
        "config": {"instance_class": "db.m5.xlarge", "engine": "mysql",
                   "engine_version": "8.0.35", "multi_az": False,
                   "allocated_storage_gb": 100, "storage_type": "gp2",
                   "deletion_protection": False, "backup_retention_days": 1},
        "profile": {"cpu_avg": 2.1, "cpu_p95": 5.0, "connections_avg": 0.2,
                    "connections_max": 2, "read_iops": 3, "write_iops": 1},
        "optimizer": {"finding": "Overprovisioned", "recommended": "db.t4g.medium",
                      "performance_risk": 1.0, "savings_percent": 82.0},
    },
    # --- Lambda ----------------------------------------------------------
    {
        "resource_id": "image-thumbnailer",
        "type": ResourceType.LAMBDA, "name": "image-thumbnailer",
        "tags": {"Environment": "production", "Owner": "media"},
        "age_days": 300,
        "config": {"memory_mb": 3008, "timeout_seconds": 60, "runtime": "python3.11",
                   "architecture": "x86_64", "reserved_concurrency": None},
        "profile": {"invocations_month": 4_200_000, "duration_avg_ms": 240,
                    "duration_max_ms": 900, "errors_month": 120,
                    "max_memory_used_mb": 690},
        "optimizer": {"finding": "NotOptimized", "recommended": "1024 MB",
                      "savings_percent": 62.0},
    },
    {
        "resource_id": "nightly-report-builder",
        "type": ResourceType.LAMBDA, "name": "nightly-report-builder",
        "tags": {"Environment": "production", "Owner": "analytics"},
        "age_days": 180,
        "config": {"memory_mb": 512, "timeout_seconds": 300, "runtime": "nodejs20.x",
                   "architecture": "arm64", "reserved_concurrency": None},
        "profile": {"invocations_month": 30, "duration_avg_ms": 42000,
                    "duration_max_ms": 61000, "errors_month": 0,
                    "max_memory_used_mb": 480},
    },
    # --- NAT gateway: low traffic, but do not blindly recommend deletion ---
    {
        "resource_id": "nat-0demo00000000001",
        "type": ResourceType.NAT_GATEWAY, "name": "dev-vpc-nat",
        "tags": {"Environment": "development", "Owner": "platform"},
        "age_days": 240, "state": "available",
        "config": {"vpc_id": "vpc-demo01", "subnet_id": "subnet-demo-public",
                   "connectivity_type": "public",
                   "route_tables_referencing": ["rtb-demo-private-a"],
                   "private_subnets_served": 2},
        "profile": {"gb_processed_month": 1.4, "active_connections_max": 3},
    },
    # --- Elastic IPs ------------------------------------------------------
    {
        "resource_id": "eipalloc-0demo000000001",
        "type": ResourceType.ELASTIC_IP, "name": "released-lb-ip",
        "tags": {"Environment": "development"},
        "age_days": 190, "state": "unassociated",
        "config": {"public_ip": "203.0.113.24", "association_id": None,
                   "instance_id": None},
        "profile": {},
    },
    {
        "resource_id": "eipalloc-0demo000000002",
        "type": ResourceType.ELASTIC_IP, "name": "payments-nat-ip",
        "tags": {"Environment": "production", "Owner": "payments"},
        "age_days": 412, "state": "associated",
        "config": {"public_ip": "203.0.113.25", "association_id": "eipassoc-demo1",
                   "instance_id": "i-0a1b2c3d4e5f60003"},
        "profile": {},
    },
    # --- S3 ---------------------------------------------------------------
    {
        "resource_id": "acme-analytics-raw-events",
        "type": ResourceType.S3, "name": "acme-analytics-raw-events",
        "tags": {"Environment": "production", "Owner": "data-platform"},
        "age_days": 900,
        "config": {"size_gb": 14200, "object_count": 2_400_000,
                   "storage_class": "STANDARD", "has_lifecycle_policy": False,
                   "avg_object_age_days": 410, "pct_objects_older_than_90d": 82.0,
                   "get_requests_month": 18000},
        "profile": {},
    },
    {
        "resource_id": "acme-app-assets",
        "type": ResourceType.S3, "name": "acme-app-assets",
        "tags": {"Environment": "production", "Owner": "web"},
        "age_days": 640,
        "config": {"size_gb": 42, "object_count": 900_000,
                   "storage_class": "STANDARD", "has_lifecycle_policy": True,
                   "avg_object_age_days": 60, "pct_objects_older_than_90d": 18.0,
                   "get_requests_month": 41_000_000},
        "profile": {},
    },
]


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------


class DemoInventoryProvider:
    def __init__(self, account_id: str = DEMO_ACCOUNT_ID, region: str = DEMO_REGION) -> None:
        self.account_id = account_id
        self.region = region
        self.discovery_errors: list[str] = []
        self._resources = [self._materialize(spec) for spec in _SPECS]

    def _materialize(self, spec: dict[str, Any]) -> Resource:
        config = dict(spec["config"])
        resource_type = spec["type"]
        monthly_cost, price_source = _price_for(resource_type, config, spec)
        config["price_source"] = price_source
        context = tagging.classify(spec["tags"], spec.get("name") or spec["resource_id"])
        return Resource(
            resource_id=spec["resource_id"],
            resource_arn=_arn(resource_type, spec["resource_id"], self.account_id, self.region),
            resource_type=resource_type,
            account_id=self.account_id,
            region=self.region,
            name=spec.get("name"),
            tags=dict(spec["tags"]),
            state=spec.get("state"),
            created_at=_now() - timedelta(days=spec["age_days"]),
            configuration=config,
            monthly_cost=monthly_cost,
            **context,
        )

    def list_resources(self, resource_types: list[ResourceType] | None = None) -> list[Resource]:
        if resource_types:
            wanted = set(resource_types)
            return [r.model_copy(deep=True) for r in self._resources if r.resource_type in wanted]
        return [r.model_copy(deep=True) for r in self._resources]

    def get_resource(self, resource_id: str) -> Resource | None:
        found = next((r for r in self._resources if r.resource_id == resource_id), None)
        return found.model_copy(deep=True) if found else None

    def spec_for(self, resource_id: str) -> dict[str, Any] | None:
        return next((s for s in _SPECS if s["resource_id"] == resource_id), None)


class DemoMetricsProvider:
    """Generates plausible CloudWatch series from each resource's profile.

    The series carry realistic shape -- diurnal variation and noise -- because
    a detector that only ever sees a flat line is not actually tested.
    """

    def __init__(self, account_id: str = DEMO_ACCOUNT_ID, region: str = DEMO_REGION) -> None:
        self.account_id = account_id
        self.region = region

    def get_metric(
        self,
        namespace: str,
        metric_name: str,
        dimensions: dict[str, str],
        start: datetime,
        end: datetime,
        statistic: str = "Average",
        period_seconds: int = 3600,
        unit: str | None = None,
    ) -> MetricSeries:
        resource_id = next(iter(dimensions.values()), "") if dimensions else ""
        spec = next((s for s in _SPECS if s["resource_id"] == resource_id), None)
        series = MetricSeries(
            namespace=namespace,
            metric_name=metric_name,
            dimensions=dimensions,
            unit=unit or _unit_for(metric_name),
            statistic=statistic,
            period_seconds=period_seconds,
        )
        if spec is None:
            return series

        base, shape = _baseline(spec, namespace, metric_name, statistic, period_seconds)
        if base is None:
            # Metric genuinely not published (no CloudWatch agent, no such
            # metric for this resource). Empty is the honest answer.
            return series

        rng = _rng(resource_id, namespace, metric_name, statistic)
        cursor = start
        while cursor < end:
            hours = (cursor - start).total_seconds() / 3600.0
            # Both shapes are mean-normalized to 1.0 so that a profile's stated
            # average survives the shaping -- a profile saying 8.7% CPU must
            # actually average 8.7%, or every threshold test is meaningless.
            if shape == "diurnal":
                factor = 1.0 + 0.38 * math.sin((hours % 24) / 24 * 2 * math.pi - 1.4)
            elif shape == "burst":
                # One spike per day, quiet otherwise: (20 + 23*0.174)/24 ~= 1.0
                factor = 20.0 if int(hours) % 24 == 3 else 0.174
            else:
                factor = 1.0
            noise = rng.uniform(0.86, 1.14)
            value = max(0.0, base * factor * noise)
            if metric_name == "CPUUtilization":
                value = min(value, 100.0)
            series.points.append(MetricPoint(timestamp=cursor, value=round(value, 4)))
            cursor += timedelta(seconds=period_seconds)
        return series

    def get_metrics(
        self, specs: list[dict], start: datetime, end: datetime, period_seconds: int = 3600
    ) -> list[MetricSeries]:
        return [
            self.get_metric(
                s["namespace"], s["metric_name"], s["dimensions"], start, end,
                s.get("statistic", "Average"), period_seconds, s.get("unit"),
            )
            for s in specs
        ]


class DemoCostProvider:
    """Daily spend built from the inventory, plus one injected anomaly."""

    def __init__(self, account_id: str = DEMO_ACCOUNT_ID, region: str = DEMO_REGION) -> None:
        self.account_id = account_id
        self.region = region
        self._inventory = DemoInventoryProvider(account_id, region)

    def _service_totals(self) -> dict[str, float]:
        totals: dict[str, float] = {}
        service_of = {
            ResourceType.EC2: "Amazon Elastic Compute Cloud - Compute",
            ResourceType.EBS: "EC2 - Other",
            ResourceType.NAT_GATEWAY: "EC2 - Other",
            ResourceType.ELASTIC_IP: "EC2 - Other",
            ResourceType.RDS: "Amazon Relational Database Service",
            ResourceType.LAMBDA: "AWS Lambda",
            ResourceType.S3: "Amazon Simple Storage Service",
        }
        for resource in self._inventory.list_resources():
            service = service_of.get(resource.resource_type, "Other")
            totals[service] = round(totals.get(service, 0.0) + resource.monthly_cost, 2)
        totals["AmazonCloudWatch"] = 88.40
        totals["AWS Key Management Service"] = 12.00
        return totals

    def get_cost_and_usage(
        self,
        start: datetime,
        end: datetime,
        granularity: str = "DAILY",
        group_by: list[str] | None = None,
        filters: dict[str, Any] | None = None,
    ) -> list[CostPoint]:
        totals = self._service_totals()
        points: list[CostPoint] = []
        anomaly_start = _now() - timedelta(days=6)
        anomaly_end = _now() - timedelta(days=2)

        if granularity == "MONTHLY":
            for service, monthly in totals.items():
                if group_by and "SERVICE" in group_by:
                    points.append(
                        CostPoint(start, end, monthly, dimensions={"SERVICE": service})
                    )
            if not group_by:
                points.append(CostPoint(start, end, round(sum(totals.values()), 2)))
            if group_by and "REGION" in group_by:
                grand = sum(totals.values())
                points = [
                    CostPoint(start, end, round(grand * 0.82, 2),
                              dimensions={"REGION": "us-east-1"}),
                    CostPoint(start, end, round(grand * 0.14, 2),
                              dimensions={"REGION": "eu-west-1"}),
                    CostPoint(start, end, round(grand * 0.04, 2),
                              dimensions={"REGION": "ap-south-1"}),
                ]
            return points

        cursor = start
        while cursor < end:
            next_day = cursor + timedelta(days=1)
            rng = _rng("daily", cursor.date().isoformat())
            for service, monthly in totals.items():
                daily = monthly / 30.0 * rng.uniform(0.94, 1.06)
                # Injected EC2 anomaly so the anomaly path has something real.
                if (
                    service == "Amazon Elastic Compute Cloud - Compute"
                    and anomaly_start <= cursor <= anomaly_end
                ):
                    daily *= 1.58
                if group_by and "SERVICE" in group_by:
                    points.append(
                        CostPoint(cursor, next_day, round(daily, 4),
                                  dimensions={"SERVICE": service})
                    )
            if not group_by:
                total = sum(totals.values()) / 30.0 * rng.uniform(0.94, 1.06)
                if anomaly_start <= cursor <= anomaly_end:
                    total += totals["Amazon Elastic Compute Cloud - Compute"] / 30.0 * 0.58
                points.append(CostPoint(cursor, next_day, round(total, 4)))
            cursor = next_day
        return points

    def get_cost_by_resource(
        self, resource_id: str, start: datetime, end: datetime
    ) -> float | None:
        resource = self._inventory.get_resource(resource_id)
        if resource is None:
            return None
        # The demo account has resource-level granularity enabled, so observed
        # cost is available and sits a few percent off the list price.
        rng = _rng("resource_cost", resource_id)
        return round(resource.monthly_cost * rng.uniform(0.97, 1.04), 2)

    def get_forecast(self, days: int = 30) -> float:
        return round(sum(self._service_totals().values()) * (days / 30.0) * 1.041, 2)

    def get_anomalies(self, start: datetime, end: datetime) -> list[CostAnomaly]:
        ec2_monthly = self._service_totals()["Amazon Elastic Compute Cloud - Compute"]
        expected = round(ec2_monthly / 30.0 * 5, 2)
        actual = round(expected * 1.58, 2)
        anomaly_start = _now() - timedelta(days=6)
        if anomaly_start < start:
            return []
        return [
            CostAnomaly(
                anomaly_id="anomaly-demo-0001",
                service="AmazonEC2",
                start=anomaly_start,
                end=_now() - timedelta(days=2),
                total_impact=round(actual - expected, 2),
                max_impact=round((actual - expected) / 5 * 1.4, 2),
                expected_spend=expected,
                actual_spend=actual,
                root_causes=[
                    {
                        "Service": "AmazonEC2",
                        "Region": "us-east-1",
                        "UsageType": "BoxUsage:r5.4xlarge",
                        "LinkedAccount": DEMO_ACCOUNT_ID,
                    }
                ],
            )
        ]

    def cost_by_service(self, start: datetime, end: datetime) -> dict[str, float]:
        totals = self._service_totals()
        return dict(sorted(totals.items(), key=lambda kv: kv[1], reverse=True))

    def cost_by_region(self, start: datetime, end: datetime) -> dict[str, float]:
        grand = sum(self._service_totals().values())
        return {
            "us-east-1": round(grand * 0.82, 2),
            "eu-west-1": round(grand * 0.14, 2),
            "ap-south-1": round(grand * 0.04, 2),
        }

    def compare_periods(
        self, current_start: datetime, current_end: datetime, window_days: int
    ) -> dict[str, Any]:
        current = self.cost_by_service(current_start, current_end)
        deltas = []
        for service, amount in current.items():
            rng = _rng("compare", service)
            previous = amount / rng.uniform(1.02, 1.12)
            if service == "Amazon Elastic Compute Cloud - Compute":
                previous = amount / 1.583
            change = amount - previous
            deltas.append(
                {
                    "service": service,
                    "previous": round(previous, 2),
                    "current": round(amount, 2),
                    "increase": round(change, 2),
                    "percentage": round(change / previous * 100, 1) if previous else None,
                }
            )
        deltas.sort(key=lambda d: d["increase"], reverse=True)
        return {
            "current_period": {
                "start": current_start.strftime("%Y-%m-%d"),
                "end": current_end.strftime("%Y-%m-%d"),
            },
            "previous_period": {
                "start": (current_start - timedelta(days=window_days)).strftime("%Y-%m-%d"),
                "end": current_start.strftime("%Y-%m-%d"),
            },
            "total_current": round(sum(d["current"] for d in deltas), 2),
            "total_previous": round(sum(d["previous"] for d in deltas), 2),
            "by_service": deltas,
        }


class DemoRecommendationProvider:
    """Stands in for Compute Optimizer / Cost Optimization Hub.

    Only resources whose spec carries an `optimizer` block get one, mirroring
    reality: AWS has no opinion about most resources, so CloudWaste's own
    detectors have to carry those cases alone.
    """

    def __init__(self, account_id: str = DEMO_ACCOUNT_ID, region: str = DEMO_REGION) -> None:
        self.account_id = account_id
        self.region = region
        self._inventory = DemoInventoryProvider(account_id, region)

    def list_recommendations(
        self, resource_types: list[ResourceType] | None = None
    ) -> list[OptimizerRecommendation]:
        out: list[OptimizerRecommendation] = []
        for spec in _SPECS:
            opt = spec.get("optimizer")
            if not opt:
                continue
            if resource_types and spec["type"] not in set(resource_types):
                continue
            resource = self._inventory.get_resource(spec["resource_id"])
            if resource is None:
                continue
            current, recommended = _config_labels(spec)
            # Derive the saving from the actual price gap between the current
            # and recommended configuration rather than from a hand-written
            # percentage. A percentage that disagrees with its own target is
            # exactly the inconsistency that makes a demo fall apart on stage,
            # and real Compute Optimizer responses are internally consistent.
            savings, savings_percent = _savings_between(spec, resource, opt)
            out.append(
                OptimizerRecommendation(
                    source="cost_optimization_hub+compute_optimizer",
                    resource_id=spec["resource_id"],
                    resource_arn=resource.resource_arn,
                    resource_type=spec["type"],
                    finding=opt["finding"],
                    current_configuration=current,
                    recommended_configuration=recommended,
                    estimated_monthly_savings=savings,
                    estimated_savings_percent=savings_percent,
                    performance_risk=opt.get("performance_risk"),
                    lookback_days=14,
                    action_type="Rightsize",
                    raw={"demo": True, "finding_reason_codes": ["CPUOverprovisioned"]},
                )
            )
        return out

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


class DemoActivityProvider:
    """Synthetic CloudTrail history.

    Resources carry an implied story: the ETL box was launched by an engineer
    who has since left, the orphaned volume was detached during a migration and
    never cleaned up. That story is what makes a finding actionable.
    """

    _ACTORS = {
        "i-0a1b2c3d4e5f60001": "arn:aws:iam::123456789012:user/priya.raman",
        "i-0a1b2c3d4e5f60002": "arn:aws:iam::123456789012:user/former.employee",
        "i-0a1b2c3d4e5f60004": "arn:aws:sts::123456789012:assumed-role/terraform-ci/build-8821",
        "i-0a1b2c3d4e5f60005": "arn:aws:iam::123456789012:user/contractor.temp",
        "vol-0a1b2c3d4e5f60006": "arn:aws:iam::123456789012:user/former.employee",
        "vol-0a1b2c3d4e5f60007": "arn:aws:iam::123456789012:root",
        "analytics-dev-db": "arn:aws:iam::123456789012:user/priya.raman",
        "nat-0demo00000000001": "arn:aws:sts::123456789012:assumed-role/terraform-ci/build-3310",
    }
    # Days since the last write event. None means no write inside retention.
    _LAST_WRITE = {
        "i-0a1b2c3d4e5f60001": 23.0,
        "i-0a1b2c3d4e5f60002": None,
        "i-0a1b2c3d4e5f60003": 4.0,
        "i-0a1b2c3d4e5f60004": 61.0,
        "i-0a1b2c3d4e5f60005": 64.0,
        "vol-0a1b2c3d4e5f60006": 131.0,
        "vol-0a1b2c3d4e5f60007": 44.0,
        "analytics-dev-db": 88.0,
    }

    def __init__(self, account_id: str = DEMO_ACCOUNT_ID, region: str = DEMO_REGION) -> None:
        self.account_id = account_id
        self.region = region

    def lookup_events(
        self,
        resource_id: str | None = None,
        event_names: list[str] | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 50,
    ) -> list[ActivityEvent]:
        if not resource_id:
            return []
        spec = next((s for s in _SPECS if s["resource_id"] == resource_id), None)
        if spec is None:
            return []

        actor = self._ACTORS.get(resource_id, "arn:aws:iam::123456789012:user/platform.bot")
        events: list[ActivityEvent] = []
        age_days = spec["age_days"]
        if age_days <= 90:
            events.append(
                ActivityEvent(
                    event_id=f"evt-create-{resource_id[-6:]}",
                    event_name=_creation_event_name(spec["type"]),
                    event_time=_now() - timedelta(days=age_days),
                    username=actor,
                    source_ip="198.51.100.14",
                    resource_id=resource_id,
                    read_only=False,
                    raw={"user_identity": {"arn": actor}, "user_agent": "aws-cli/2.15.0"},
                )
            )
        last_write = self._LAST_WRITE.get(resource_id)
        if last_write is not None and last_write <= 90:
            events.append(
                ActivityEvent(
                    event_id=f"evt-modify-{resource_id[-6:]}",
                    event_name=_modify_event_name(spec["type"]),
                    event_time=_now() - timedelta(days=last_write),
                    username=actor,
                    source_ip="198.51.100.14",
                    resource_id=resource_id,
                    read_only=False,
                    raw={"user_identity": {"arn": actor}},
                )
            )
        events.sort(key=lambda e: e.event_time, reverse=True)
        if event_names:
            wanted = set(event_names)
            events = [e for e in events if e.event_name in wanted]
        return events[:limit]

    def get_creation_event(self, resource_id: str, resource_type: str) -> ActivityEvent | None:
        events = self.lookup_events(resource_id=resource_id)
        creations = [e for e in events if e.event_name.startswith(("Run", "Create", "Allocate"))]
        return creations[-1] if creations else None

    def get_last_modification(self, resource_id: str, resource_type: str) -> ActivityEvent | None:
        events = self.lookup_events(resource_id=resource_id)
        return events[0] if events else None

    def days_since_last_write(self, resource_id: str, resource_type: str) -> float | None:
        return self._LAST_WRITE.get(resource_id)


class DemoDataPlane:
    """Bundles the five demo providers, matching `adapters.base.DataPlane`."""

    def __init__(self, account_id: str = DEMO_ACCOUNT_ID, region: str = DEMO_REGION) -> None:
        self.account_id = account_id
        self.region = region
        self.inventory = DemoInventoryProvider(account_id, region)
        self.metrics = DemoMetricsProvider(account_id, region)
        self.cost = DemoCostProvider(account_id, region)
        self.recommendations = DemoRecommendationProvider(account_id, region)
        self.activity = DemoActivityProvider(account_id, region)
        self.mode = "demo"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _price_for(
    resource_type: ResourceType, config: dict, spec: dict
) -> tuple[float, str]:
    if resource_type is ResourceType.EC2:
        if spec.get("state") == "stopped":
            return 0.0, "price_book"  # stopped instances bill only their volumes
        price = pricing.ec2_monthly(config["instance_type"])
        return (price.monthly, price.source) if price else (0.0, "unpriced")
    if resource_type is ResourceType.EBS:
        price = pricing.ebs_monthly(config["volume_type"], config["size_gb"], config.get("iops"))
        return price.monthly, price.source
    if resource_type is ResourceType.RDS:
        price = pricing.rds_monthly(config["instance_class"], config.get("multi_az", False))
        storage = config.get("allocated_storage_gb", 0) * 0.115
        return (round((price.monthly if price else 0.0) + storage, 2), "price_book")
    if resource_type is ResourceType.LAMBDA:
        profile = spec["profile"]
        price = pricing.lambda_monthly(
            config["memory_mb"], profile["duration_avg_ms"], profile["invocations_month"]
        )
        return price.monthly, price.source
    if resource_type is ResourceType.NAT_GATEWAY:
        price = pricing.nat_gateway_monthly(spec["profile"].get("gb_processed_month", 0.0))
        return price.monthly, price.source
    if resource_type is ResourceType.ELASTIC_IP:
        # Associated addresses attached to a running instance are not charged.
        if spec.get("state") == "associated":
            return 0.0, "price_book"
        return pricing.idle_eip_monthly().monthly, "price_book"
    if resource_type is ResourceType.S3:
        price = pricing.s3_monthly(config["storage_class"], config["size_gb"])
        return price.monthly, price.source
    return 0.0, "unpriced"


def _arn(resource_type: ResourceType, resource_id: str, account: str, region: str) -> str:
    if resource_type is ResourceType.EC2:
        return f"arn:aws:ec2:{region}:{account}:instance/{resource_id}"
    if resource_type is ResourceType.EBS:
        return f"arn:aws:ec2:{region}:{account}:volume/{resource_id}"
    if resource_type is ResourceType.RDS:
        return f"arn:aws:rds:{region}:{account}:db:{resource_id}"
    if resource_type is ResourceType.LAMBDA:
        return f"arn:aws:lambda:{region}:{account}:function:{resource_id}"
    if resource_type is ResourceType.NAT_GATEWAY:
        return f"arn:aws:ec2:{region}:{account}:natgateway/{resource_id}"
    if resource_type is ResourceType.ELASTIC_IP:
        return f"arn:aws:ec2:{region}:{account}:elastic-ip/{resource_id}"
    return f"arn:aws:s3:::{resource_id}"


def _baseline(
    spec: dict, namespace: str, metric_name: str, statistic: str, period_seconds: int
) -> tuple[float | None, str]:
    """Return (per-period baseline value, shape) or (None, _) if unpublished."""
    profile = spec["profile"]
    periods_per_day = 86400.0 / period_seconds

    if metric_name == "CPUUtilization":
        if spec["type"] is ResourceType.EC2 and spec.get("state") == "stopped":
            return None, "flat"
        key = "cpu_p95" if statistic == "Maximum" else "cpu_avg"
        value = profile.get(key, profile.get("cpu_avg"))
        return (value, "diurnal") if value is not None else (None, "flat")

    if metric_name in ("NetworkIn", "NetworkOut"):
        mb_day = profile.get("net_mb_day")
        if mb_day is None:
            return None, "flat"
        split = 0.6 if metric_name == "NetworkIn" else 0.4
        return (mb_day * 1_000_000 * split / periods_per_day, "diurnal")

    if metric_name == "mem_used_percent":
        if not profile.get("has_cwagent"):
            return None, "flat"  # no agent installed: metric does not exist
        return profile.get("memory_avg"), "diurnal"

    if metric_name == "disk_used_percent":
        if not profile.get("has_cwagent"):
            return None, "flat"
        return 42.0, "flat"

    if metric_name in ("VolumeReadOps", "VolumeWriteOps"):
        key = "read_ops_day" if metric_name == "VolumeReadOps" else "write_ops_day"
        ops = profile.get(key)
        return (ops / periods_per_day, "diurnal") if ops is not None else (None, "flat")

    if metric_name == "VolumeIdleTime":
        total = profile.get("read_ops_day", 0) + profile.get("write_ops_day", 0)
        busy = min(1.0, total / 500_000.0)
        return period_seconds * (1.0 - busy), "flat"

    if metric_name == "DatabaseConnections":
        key = "connections_max" if statistic == "Maximum" else "connections_avg"
        return profile.get(key), "diurnal"

    if metric_name == "FreeableMemory":
        return 6.4e9, "flat"

    if metric_name in ("ReadIOPS", "WriteIOPS"):
        key = "read_iops" if metric_name == "ReadIOPS" else "write_iops"
        return profile.get(key), "diurnal"

    if metric_name == "FreeStorageSpace":
        allocated = spec["config"].get("allocated_storage_gb", 100)
        return allocated * 1e9 * 0.62, "flat"

    if metric_name == "Invocations":
        per_month = profile.get("invocations_month")
        if per_month is None:
            return None, "flat"
        shape = "burst" if per_month < 1000 else "diurnal"
        return per_month / 30.0 / periods_per_day, shape

    if metric_name == "Duration":
        key = "duration_max_ms" if statistic == "Maximum" else "duration_avg_ms"
        return profile.get(key), "flat"

    if metric_name == "Errors":
        per_month = profile.get("errors_month")
        return (per_month / 30.0 / periods_per_day, "diurnal") if per_month else (0.0, "flat")

    if metric_name in ("Throttles",):
        return 0.0, "flat"

    if metric_name == "ConcurrentExecutions":
        return 3.0, "diurnal"

    if metric_name in ("BytesOutToDestination", "BytesInFromSource"):
        gb_month = profile.get("gb_processed_month")
        if gb_month is None:
            return None, "flat"
        split = 0.7 if metric_name == "BytesOutToDestination" else 0.3
        return (gb_month * 1e9 * split / 30.0 / periods_per_day, "diurnal")

    if metric_name == "ActiveConnectionCount":
        return profile.get("active_connections_max"), "diurnal"

    if metric_name == "BucketSizeBytes":
        return spec["config"].get("size_gb", 0) * 1024**3, "flat"

    if metric_name == "NumberOfObjects":
        return float(spec["config"].get("object_count", 0)), "flat"

    if metric_name in ("AllRequests", "GetRequests"):
        per_month = spec["config"].get("get_requests_month", 0)
        return per_month / 30.0 / periods_per_day, "diurnal"

    return None, "flat"


def _unit_for(metric_name: str) -> str:
    if metric_name == "CPUUtilization" or metric_name.endswith("_percent"):
        return "Percent"
    if "Bytes" in metric_name or metric_name in ("NetworkIn", "NetworkOut", "FreeableMemory"):
        return "Bytes"
    if metric_name == "Duration":
        return "Milliseconds"
    return "Count"


def _savings_between(spec: dict, resource, opt: dict) -> tuple[float, float]:
    """Monthly saving from moving this resource to its recommended config.

    Falls back to the spec's stated percentage only where the resource has no
    priced ladder to compare against.
    """
    resource_type = spec["type"]
    config = spec["config"]
    target = opt["recommended"]

    if resource_type is ResourceType.EC2:
        current_price = pricing.ec2_monthly(config["instance_type"])
        target_price = pricing.ec2_monthly(target)
        if current_price and target_price:
            saving = current_price.monthly - target_price.monthly
            return round(saving, 2), round(saving / current_price.monthly * 100, 1)

    elif resource_type is ResourceType.RDS:
        multi_az = config.get("multi_az", False)
        current_price = pricing.rds_monthly(config["instance_class"], multi_az)
        target_price = pricing.rds_monthly(target, multi_az)
        if current_price and target_price:
            # Storage is unchanged by an instance-class change, so the saving
            # applies to the compute portion only.
            saving = current_price.monthly - target_price.monthly
            return round(saving, 2), round(saving / resource.monthly_cost * 100, 1)

    elif resource_type is ResourceType.LAMBDA:
        profile = spec["profile"]
        try:
            target_mb = int(str(target).split()[0])
        except (ValueError, IndexError):
            target_mb = None
        if target_mb:
            current_price = pricing.lambda_monthly(
                config["memory_mb"], profile["duration_avg_ms"], profile["invocations_month"]
            )
            # Less memory means less CPU, so duration rises. Model it the same
            # pessimistic way the detector does.
            ratio = min(config["memory_mb"], 1769) / max(min(target_mb, 1769), 1)
            projected_duration = profile["duration_avg_ms"] * (1.0 + (ratio - 1.0) * 0.75)
            target_price = pricing.lambda_monthly(
                target_mb, projected_duration, profile["invocations_month"]
            )
            saving = current_price.monthly - target_price.monthly
            return round(saving, 2), round(saving / current_price.monthly * 100, 1)

    saving = round(resource.monthly_cost * opt["savings_percent"] / 100.0, 2)
    return saving, float(opt["savings_percent"])


def _config_labels(spec: dict) -> tuple[str, str]:
    opt = spec["optimizer"]
    resource_type = spec["type"]
    if resource_type is ResourceType.EC2:
        return spec["config"]["instance_type"], opt["recommended"]
    if resource_type is ResourceType.RDS:
        return spec["config"]["instance_class"], opt["recommended"]
    if resource_type is ResourceType.LAMBDA:
        return f"{spec['config']['memory_mb']} MB", opt["recommended"]
    return str(spec["config"]), opt["recommended"]


def _creation_event_name(resource_type: ResourceType) -> str:
    return {
        ResourceType.EC2: "RunInstances",
        ResourceType.EBS: "CreateVolume",
        ResourceType.RDS: "CreateDBInstance",
        ResourceType.LAMBDA: "CreateFunction20150331",
        ResourceType.NAT_GATEWAY: "CreateNatGateway",
        ResourceType.ELASTIC_IP: "AllocateAddress",
        ResourceType.S3: "CreateBucket",
    }.get(resource_type, "Create")


def _modify_event_name(resource_type: ResourceType) -> str:
    return {
        ResourceType.EC2: "ModifyInstanceAttribute",
        ResourceType.EBS: "DetachVolume",
        ResourceType.RDS: "ModifyDBInstance",
        ResourceType.LAMBDA: "UpdateFunctionConfiguration20150331v2",
    }.get(resource_type, "Modify")
