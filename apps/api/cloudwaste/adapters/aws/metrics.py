"""CloudWatch metrics.

Uses GetMetricData rather than GetMetricStatistics: a scan asks for many series
at once and GetMetricData batches up to 500 queries per call, which keeps a
full-account scan inside a sane number of API calls.

One caveat the detectors depend on: an EC2 instance with no CloudWatch agent
reports CPU and network but *not* memory or disk. An absent series is therefore
"not measured", never "zero", and `MetricSeries.datapoint_count == 0` is how the
confidence engine learns to discount a finding.
"""

from __future__ import annotations

import logging
from datetime import datetime

from ..base import MetricPoint, MetricSeries
from .clients import get_client, soft_call

logger = logging.getLogger(__name__)


class AwsMetricsProvider:
    """Implements `adapters.base.MetricsProvider` against a real account."""

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

    def _client(self):
        return get_client("cloudwatch", self._role_arn, self._external_id, self.region)

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
        series = self.get_metrics(
            [
                {
                    "namespace": namespace,
                    "metric_name": metric_name,
                    "dimensions": dimensions,
                    "statistic": statistic,
                    "unit": unit,
                }
            ],
            start,
            end,
            period_seconds,
        )
        return series[0]

    def get_metrics(
        self,
        specs: list[dict],
        start: datetime,
        end: datetime,
        period_seconds: int = 3600,
    ) -> list[MetricSeries]:
        """Fetch many series in as few GetMetricData calls as possible.

        Returns one MetricSeries per spec, in the order given. A series that
        CloudWatch has no data for comes back empty rather than missing, so
        callers can always index by position.
        """
        client = self._client()
        results: list[MetricSeries] = []

        for chunk_start in range(0, len(specs), 500):
            chunk = specs[chunk_start : chunk_start + 500]
            queries = []
            for index, spec in enumerate(chunk):
                query = {
                    "Id": f"m{index}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": spec["namespace"],
                            "MetricName": spec["metric_name"],
                            "Dimensions": [
                                {"Name": k, "Value": v}
                                for k, v in spec["dimensions"].items()
                            ],
                        },
                        "Period": period_seconds,
                        "Stat": spec.get("statistic", "Average"),
                    },
                    "ReturnData": True,
                }
                if spec.get("unit"):
                    query["MetricStat"]["Unit"] = spec["unit"]
                queries.append(query)

            payload: dict[str, list] = {}
            next_token: str | None = None
            while True:
                kwargs = {
                    "MetricDataQueries": queries,
                    "StartTime": start,
                    "EndTime": end,
                    "ScanBy": "TimestampAscending",
                    "MaxDatapoints": 100_800,
                }
                if next_token:
                    kwargs["NextToken"] = next_token
                response = soft_call(
                    client.get_metric_data,
                    default={"MetricDataResults": []},
                    context="cloudwatch:GetMetricData",
                    **kwargs,
                )
                for result in (response or {}).get("MetricDataResults", []):
                    entry = payload.setdefault(result["Id"], [[], []])
                    entry[0].extend(result.get("Timestamps", []))
                    entry[1].extend(result.get("Values", []))
                next_token = (response or {}).get("NextToken")
                if not next_token:
                    break

            for index, spec in enumerate(chunk):
                timestamps, values = payload.get(f"m{index}", ([], []))
                results.append(
                    MetricSeries(
                        namespace=spec["namespace"],
                        metric_name=spec["metric_name"],
                        dimensions=spec["dimensions"],
                        unit=spec.get("unit") or "None",
                        statistic=spec.get("statistic", "Average"),
                        period_seconds=period_seconds,
                        points=[
                            MetricPoint(timestamp=t, value=float(v))
                            for t, v in zip(timestamps, values)
                        ],
                    )
                )
        return results


# Metric identity per resource type. Keeping this as data rather than branching
# code means a new service needs a table entry, not a new detector code path.
METRIC_CATALOG: dict[str, dict[str, tuple[str, str, str]]] = {
    "EC2": {
        "cpu": ("AWS/EC2", "CPUUtilization", "Average"),
        "cpu_max": ("AWS/EC2", "CPUUtilization", "Maximum"),
        "network_in": ("AWS/EC2", "NetworkIn", "Sum"),
        "network_out": ("AWS/EC2", "NetworkOut", "Sum"),
        # CWAgent metrics exist only where the agent is installed.
        "memory": ("CWAgent", "mem_used_percent", "Average"),
        "disk": ("CWAgent", "disk_used_percent", "Average"),
    },
    "EBS": {
        "read_ops": ("AWS/EBS", "VolumeReadOps", "Sum"),
        "write_ops": ("AWS/EBS", "VolumeWriteOps", "Sum"),
        "idle_time": ("AWS/EBS", "VolumeIdleTime", "Average"),
    },
    "RDS": {
        "cpu": ("AWS/RDS", "CPUUtilization", "Average"),
        "connections": ("AWS/RDS", "DatabaseConnections", "Average"),
        "connections_max": ("AWS/RDS", "DatabaseConnections", "Maximum"),
        "freeable_memory": ("AWS/RDS", "FreeableMemory", "Average"),
        "read_iops": ("AWS/RDS", "ReadIOPS", "Average"),
        "write_iops": ("AWS/RDS", "WriteIOPS", "Average"),
        "free_storage": ("AWS/RDS", "FreeStorageSpace", "Average"),
    },
    "LAMBDA": {
        "invocations": ("AWS/Lambda", "Invocations", "Sum"),
        "duration": ("AWS/Lambda", "Duration", "Average"),
        "duration_p95": ("AWS/Lambda", "Duration", "Maximum"),
        "errors": ("AWS/Lambda", "Errors", "Sum"),
        "throttles": ("AWS/Lambda", "Throttles", "Sum"),
        "concurrent": ("AWS/Lambda", "ConcurrentExecutions", "Maximum"),
    },
    "NAT_GATEWAY": {
        "bytes_out_to_destination": ("AWS/NATGateway", "BytesOutToDestination", "Sum"),
        "bytes_in_from_source": ("AWS/NATGateway", "BytesInFromSource", "Sum"),
        "active_connections": ("AWS/NATGateway", "ActiveConnectionCount", "Maximum"),
    },
    "S3": {
        "bucket_size": ("AWS/S3", "BucketSizeBytes", "Average"),
        "object_count": ("AWS/S3", "NumberOfObjects", "Average"),
        "all_requests": ("AWS/S3", "AllRequests", "Sum"),
        "get_requests": ("AWS/S3", "GetRequests", "Sum"),
    },
}

DIMENSION_KEY: dict[str, str] = {
    "EC2": "InstanceId",
    "EBS": "VolumeId",
    "RDS": "DBInstanceIdentifier",
    "LAMBDA": "FunctionName",
    "NAT_GATEWAY": "NatGatewayId",
    "S3": "BucketName",
}


def build_specs(resource_type: str, resource_id: str, metrics: list[str] | None = None) -> list[dict]:
    """Build GetMetricData specs for one resource from the catalog."""
    catalog = METRIC_CATALOG.get(resource_type, {})
    selected = metrics or list(catalog)
    dimension_key = DIMENSION_KEY.get(resource_type)
    specs = []
    for key in selected:
        if key not in catalog:
            continue
        namespace, metric_name, statistic = catalog[key]
        dimensions = {dimension_key: resource_id} if dimension_key else {}
        if resource_type == "S3":
            dimensions = {
                "BucketName": resource_id,
                "StorageType": "StandardStorage"
                if metric_name == "BucketSizeBytes"
                else "AllStorageTypes",
            }
            if metric_name in ("AllRequests", "GetRequests"):
                dimensions = {"BucketName": resource_id, "FilterId": "EntireBucket"}
        specs.append(
            {
                "key": key,
                "namespace": namespace,
                "metric_name": metric_name,
                "dimensions": dimensions,
                "statistic": statistic,
            }
        )
    return specs
