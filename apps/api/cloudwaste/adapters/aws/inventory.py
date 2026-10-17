"""Live resource discovery via boto3.

Each `_discover_*` method returns fully normalized `Resource` objects with the
service-specific facts the detectors need parked in `configuration`. Discovery
is fail-soft per service: if a caller lacks `rds:DescribeDBInstances` we still
return the EC2 and EBS inventory and record the gap.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from ...models.domain import Resource
from ...models.enums import ResourceType
from .. import pricing, tags as tagging
from ..base import DependencyFacts
from .clients import get_client, is_access_denied, paginate, soft_call

logger = logging.getLogger(__name__)


class AwsInventoryProvider:
    """Implements `adapters.base.InventoryProvider` against a real account."""

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
        self.discovery_errors: list[str] = []

    def _client(self, service: str):
        return get_client(service, self._role_arn, self._external_id, self.region)

    def _arn(self, service: str, resource: str) -> str:
        return f"arn:aws:{service}:{self.region}:{self.account_id}:{resource}"

    def _build(
        self,
        resource_id: str,
        resource_type: ResourceType,
        raw_tags: dict[str, str],
        *,
        name: str | None = None,
        arn: str | None = None,
        state: str | None = None,
        created_at: datetime | None = None,
        configuration: dict[str, Any] | None = None,
        monthly_cost: float = 0.0,
    ) -> Resource:
        context = tagging.classify(raw_tags, name or resource_id)
        return Resource(
            resource_id=resource_id,
            resource_arn=arn,
            resource_type=resource_type,
            account_id=self.account_id,
            region=self.region,
            name=name,
            tags=raw_tags,
            state=state,
            created_at=created_at,
            configuration=configuration or {},
            monthly_cost=monthly_cost,
            **context,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def list_resources(
        self, resource_types: list[ResourceType] | None = None
    ) -> list[Resource]:
        wanted = set(resource_types) if resource_types else set(ResourceType)
        discoverers = {
            ResourceType.EC2: self._discover_ec2,
            ResourceType.EBS: self._discover_ebs,
            ResourceType.S3: self._discover_s3,
            ResourceType.RDS: self._discover_rds,
            ResourceType.LAMBDA: self._discover_lambda,
            ResourceType.NAT_GATEWAY: self._discover_nat_gateways,
            ResourceType.ELASTIC_IP: self._discover_elastic_ips,
        }
        resources: list[Resource] = []
        for resource_type, discover in discoverers.items():
            if resource_type not in wanted:
                continue
            try:
                resources.extend(discover())
            except ClientError as exc:
                message = f"{resource_type.value} discovery failed: {exc}"
                logger.warning(message)
                self.discovery_errors.append(message)
        return resources

    def get_resource(self, resource_id: str) -> Resource | None:
        inferred = _infer_type(resource_id)
        candidates = self.list_resources([inferred] if inferred else None)
        return next((r for r in candidates if r.resource_id == resource_id), None)

    # ------------------------------------------------------------------
    # Dependencies (on demand, read-only)
    # ------------------------------------------------------------------

    def describe_dependencies(self, resource: Resource) -> DependencyFacts:
        """Relationships for one resource. Every call here is a Describe/List.

        A category whose API call is denied or fails is reported as unknown
        with the reason, so the analyzer never mistakes "could not look" for
        "nothing there".
        """
        facts = DependencyFacts()
        handler = {
            ResourceType.EC2: self._deps_ec2,
            ResourceType.EBS: self._deps_ebs,
            ResourceType.RDS: self._deps_rds,
            ResourceType.LAMBDA: self._deps_lambda,
            ResourceType.NAT_GATEWAY: self._deps_nat,
            ResourceType.ELASTIC_IP: self._deps_eip,
        }.get(resource.resource_type)
        if handler is None:
            facts.unknown.append(
                {
                    "category": "all",
                    "reason": f"No dependency lookup for {resource.resource_type.value}",
                }
            )
            return facts
        handler(resource, facts)
        return facts

    @staticmethod
    def _dep_failed(facts: DependencyFacts, category: str, exc: Exception, api: str) -> None:
        if isinstance(exc, ClientError) and is_access_denied(exc):
            reason = f"permission denied for {api}"
        else:
            reason = f"{api} failed: {type(exc).__name__}"
        facts.unknown.append({"category": category, "reason": reason})

    @staticmethod
    def _rel(facts, type_, id_, relationship, direction, category, detail=""):
        facts.relationships.append(
            {
                "type": type_,
                "id": id_,
                "relationship": relationship,
                "direction": direction,
                "category": category,
                "detail": detail,
                "source": "aws",
            }
        )

    def _deps_ec2(self, resource: Resource, facts: DependencyFacts) -> None:
        ec2 = self._client("ec2")
        try:
            reservations = ec2.describe_instances(InstanceIds=[resource.resource_id])[
                "Reservations"
            ]
        except ClientError as exc:
            for category in (
                "ebs_volumes", "network_interfaces", "security_groups",
                "iam_instance_profile", "auto_scaling_group",
            ):
                self._dep_failed(facts, category, exc, "ec2:DescribeInstances")
            return
        instance = next((i for r in reservations for i in r.get("Instances", [])), {})
        for mapping in instance.get("BlockDeviceMappings", []):
            if "Ebs" in mapping:
                ebs = mapping["Ebs"]
                self._rel(
                    facts, "EBS", ebs["VolumeId"], f"attached at {mapping.get('DeviceName')}",
                    "uses", "ebs_volumes",
                    "deleted on termination" if ebs.get("DeleteOnTermination")
                    else "retained on termination",
                )
        facts.checked.append("ebs_volumes")
        for eni in instance.get("NetworkInterfaces", []):
            self._rel(
                facts, "ENI", eni.get("NetworkInterfaceId"), "network interface", "uses",
                "network_interfaces", f"private IP {eni.get('PrivateIpAddress')}",
            )
            public_ip = (eni.get("Association") or {}).get("PublicIp")
            if public_ip:
                self._rel(
                    facts, "PUBLIC_IP", public_ip, "public address", "uses",
                    "network_interfaces", "changes on stop/start unless it is an Elastic IP",
                )
        facts.checked.append("network_interfaces")
        for group in instance.get("SecurityGroups", []):
            self._rel(
                facts, "SECURITY_GROUP", group.get("GroupId"),
                group.get("GroupName") or "security group", "uses", "security_groups",
            )
        facts.checked.append("security_groups")
        profile = instance.get("IamInstanceProfile")
        if profile:
            self._rel(
                facts, "IAM_INSTANCE_PROFILE", profile.get("Arn"), "instance role", "uses",
                "iam_instance_profile",
            )
        facts.checked.append("iam_instance_profile")
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        if tags.get("aws:autoscaling:groupName"):
            self._rel(
                facts, "AUTO_SCALING_GROUP", tags["aws:autoscaling:groupName"], "member of",
                "used_by", "auto_scaling_group",
                "the group may replace or resize this instance itself",
            )
        facts.checked.append("auto_scaling_group")
        facts.unknown.append(
            {
                "category": "load_balancer_targets",
                "reason": "Target group membership is not inspected; an instance behind "
                "a load balancer serves traffic that CPU alone does not show",
            }
        )

    def _deps_ebs(self, resource: Resource, facts: DependencyFacts) -> None:
        ec2 = self._client("ec2")
        try:
            volume = ec2.describe_volumes(VolumeIds=[resource.resource_id])["Volumes"][0]
            for attachment in volume.get("Attachments", []):
                self._rel(
                    facts, "EC2", attachment.get("InstanceId"),
                    f"attached at {attachment.get('Device')}", "used_by", "attachment",
                    f"state {attachment.get('State')}",
                )
            facts.checked.append("attachment")
        except (ClientError, IndexError) as exc:
            self._dep_failed(facts, "attachment", exc, "ec2:DescribeVolumes")
        try:
            snapshots = ec2.describe_snapshots(
                OwnerIds=["self"],
                Filters=[{"Name": "volume-id", "Values": [resource.resource_id]}],
            )["Snapshots"]
            for snap in sorted(snapshots, key=lambda s: s["StartTime"], reverse=True)[:5]:
                self._rel(
                    facts, "EBS_SNAPSHOT", snap["SnapshotId"], "snapshot of this volume",
                    "backup", "snapshots",
                    f"{snap.get('State')}, {snap.get('VolumeSize')} GB, "
                    f"{snap['StartTime']:%Y-%m-%d}",
                )
            facts.checked.append("snapshots")
        except ClientError as exc:
            self._dep_failed(facts, "snapshots", exc, "ec2:DescribeSnapshots")

    def _deps_rds(self, resource: Resource, facts: DependencyFacts) -> None:
        rds = self._client("rds")
        try:
            db = rds.describe_db_instances(DBInstanceIdentifier=resource.resource_id)[
                "DBInstances"
            ][0]
        except (ClientError, IndexError) as exc:
            for category in ("security_groups", "subnet_group", "read_replicas", "parameter_group"):
                self._dep_failed(facts, category, exc, "rds:DescribeDBInstances")
            return
        for group in db.get("VpcSecurityGroups", []):
            self._rel(
                facts, "SECURITY_GROUP", group.get("VpcSecurityGroupId"),
                "VPC security group", "uses", "security_groups", group.get("Status", ""),
            )
        facts.checked.append("security_groups")
        subnet_group = db.get("DBSubnetGroup") or {}
        if subnet_group:
            self._rel(
                facts, "DB_SUBNET_GROUP", subnet_group.get("DBSubnetGroupName"),
                "subnet group", "uses", "subnet_group",
                f"{len(subnet_group.get('Subnets', []))} subnets in {subnet_group.get('VpcId')}",
            )
        facts.checked.append("subnet_group")
        for replica in db.get("ReadReplicaDBInstanceIdentifiers", []):
            self._rel(
                facts, "RDS", replica, "read replica", "used_by", "read_replicas",
                "replicates from this instance",
            )
        if db.get("ReadReplicaSourceDBInstanceIdentifier"):
            self._rel(
                facts, "RDS", db["ReadReplicaSourceDBInstanceIdentifier"], "replica source",
                "uses", "read_replicas", "this instance is a replica",
            )
        facts.checked.append("read_replicas")
        for group in db.get("DBParameterGroups", []):
            self._rel(
                facts, "DB_PARAMETER_GROUP", group.get("DBParameterGroupName"),
                "parameter group", "uses", "parameter_group",
                group.get("ParameterApplyStatus", ""),
            )
        facts.checked.append("parameter_group")
        facts.unknown.append(
            {
                "category": "application_clients",
                "reason": "Which applications connect to this database is not visible to "
                "AWS APIs; connection counts are the only signal",
            }
        )

    def _deps_lambda(self, resource: Resource, facts: DependencyFacts) -> None:
        lam = self._client("lambda")
        try:
            mappings = lam.list_event_source_mappings(FunctionName=resource.resource_id)
            for mapping in mappings.get("EventSourceMappings", []):
                self._rel(
                    facts, "EVENT_SOURCE", mapping.get("EventSourceArn"),
                    "event source mapping", "used_by", "event_sources",
                    mapping.get("State", ""),
                )
            facts.checked.append("event_sources")
        except ClientError as exc:
            self._dep_failed(facts, "event_sources", exc, "lambda:ListEventSourceMappings")
        try:
            config = lam.get_function_configuration(FunctionName=resource.resource_id)
            for group in (config.get("VpcConfig") or {}).get("SecurityGroupIds", []):
                self._rel(facts, "SECURITY_GROUP", group, "VPC access", "uses", "vpc_config")
            facts.checked.append("vpc_config")
        except ClientError as exc:
            self._dep_failed(facts, "vpc_config", exc, "lambda:GetFunctionConfiguration")
        facts.unknown.append(
            {
                "category": "push_invokers",
                "reason": "Services that invoke the function directly (API Gateway, S3 "
                "notifications, EventBridge) are recorded on those services, not on "
                "the function",
            }
        )

    def _deps_nat(self, resource: Resource, facts: DependencyFacts) -> None:
        ec2 = self._client("ec2")
        try:
            tables = ec2.describe_route_tables(
                Filters=[{"Name": "route.nat-gateway-id", "Values": [resource.resource_id]}]
            )["RouteTables"]
            for table in tables:
                self._rel(
                    facts, "ROUTE_TABLE", table.get("RouteTableId"),
                    "routes outbound traffic through this gateway", "used_by", "route_tables",
                    f"{len(table.get('Associations', []))} subnet association(s)",
                )
            facts.checked.append("route_tables")
        except ClientError as exc:
            self._dep_failed(facts, "route_tables", exc, "ec2:DescribeRouteTables")

    def _deps_eip(self, resource: Resource, facts: DependencyFacts) -> None:
        ec2 = self._client("ec2")
        try:
            address = ec2.describe_addresses(AllocationIds=[resource.resource_id])["Addresses"][0]
            if address.get("AssociationId"):
                self._rel(
                    facts, "EC2" if address.get("InstanceId") else "ENI",
                    address.get("InstanceId") or address.get("NetworkInterfaceId"),
                    "associated", "used_by", "association", address.get("PublicIp", ""),
                )
            facts.checked.append("association")
        except (ClientError, IndexError) as exc:
            self._dep_failed(facts, "association", exc, "ec2:DescribeAddresses")
        facts.unknown.append(
            {
                "category": "external_allow_lists",
                "reason": "Firewalls, DNS records and partner allow-lists outside AWS may "
                "reference this address; AWS cannot see them",
            }
        )

    # ------------------------------------------------------------------
    # Per-service discovery
    # ------------------------------------------------------------------

    def _discover_ec2(self) -> list[Resource]:
        ec2 = self._client("ec2")
        out: list[Resource] = []
        for reservation in paginate(ec2, "describe_instances", "Reservations"):
            for inst in reservation.get("Instances", []):
                if inst.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                    continue
                raw_tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                instance_type = inst["InstanceType"]
                price = pricing.ec2_monthly(instance_type)
                out.append(
                    self._build(
                        inst["InstanceId"],
                        ResourceType.EC2,
                        raw_tags,
                        name=raw_tags.get("Name"),
                        arn=self._arn("ec2", f"instance/{inst['InstanceId']}"),
                        state=inst.get("State", {}).get("Name"),
                        created_at=inst.get("LaunchTime"),
                        monthly_cost=price.monthly if price else 0.0,
                        configuration={
                            "instance_type": instance_type,
                            "platform": inst.get("PlatformDetails"),
                            "vpc_id": inst.get("VpcId"),
                            "subnet_id": inst.get("SubnetId"),
                            "availability_zone": inst.get("Placement", {}).get(
                                "AvailabilityZone"
                            ),
                            "architecture": inst.get("Architecture"),
                            "ebs_optimized": inst.get("EbsOptimized"),
                            "attached_volumes": [
                                m["Ebs"]["VolumeId"]
                                for m in inst.get("BlockDeviceMappings", [])
                                if "Ebs" in m
                            ],
                            "price_source": price.source if price else "unpriced",
                        },
                    )
                )
        return out

    def _discover_ebs(self) -> list[Resource]:
        ec2 = self._client("ec2")
        out: list[Resource] = []
        for vol in paginate(ec2, "describe_volumes", "Volumes"):
            raw_tags = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
            price = pricing.ebs_monthly(vol["VolumeType"], vol["Size"], vol.get("Iops"))
            attachments = vol.get("Attachments", [])
            out.append(
                self._build(
                    vol["VolumeId"],
                    ResourceType.EBS,
                    raw_tags,
                    name=raw_tags.get("Name"),
                    arn=self._arn("ec2", f"volume/{vol['VolumeId']}"),
                    state=vol["State"],
                    created_at=vol.get("CreateTime"),
                    monthly_cost=price.monthly,
                    configuration={
                        "volume_type": vol["VolumeType"],
                        "size_gb": vol["Size"],
                        "iops": vol.get("Iops"),
                        "throughput": vol.get("Throughput"),
                        "encrypted": vol.get("Encrypted"),
                        "attached_to": attachments[0]["InstanceId"] if attachments else None,
                        "snapshot_id": vol.get("SnapshotId"),
                        "price_source": price.source,
                    },
                )
            )
        return out

    def _discover_s3(self) -> list[Resource]:
        s3 = self._client("s3")
        cloudwatch = self._client("cloudwatch")
        out: list[Resource] = []
        buckets = soft_call(s3.list_buckets, default={"Buckets": []}, context="s3:ListBuckets")
        for bucket in (buckets or {}).get("Buckets", []):
            name = bucket["Name"]
            location = soft_call(
                s3.get_bucket_location, Bucket=name, default=None, context="s3:GetBucketLocation"
            )
            bucket_region = (location or {}).get("LocationConstraint") or "us-east-1"
            if bucket_region != self.region:
                continue  # each region's scan owns its own buckets

            raw_tags = {}
            tag_result = soft_call(
                s3.get_bucket_tagging, Bucket=name, default=None, context="s3:GetBucketTagging"
            )
            if tag_result:
                raw_tags = {t["Key"]: t["Value"] for t in tag_result.get("TagSet", [])}

            lifecycle = soft_call(
                s3.get_bucket_lifecycle_configuration,
                Bucket=name,
                default=None,
                context="s3:GetLifecycleConfiguration",
            )
            size_gb = _bucket_size_gb(cloudwatch, name)
            object_count = _bucket_object_count(cloudwatch, name)
            # CloudWatch publishes storage metrics once a day and not at all for
            # a new or empty-of-metrics bucket. Unknown size is not zero size.
            price = pricing.s3_monthly("STANDARD", size_gb) if size_gb is not None else None
            out.append(
                self._build(
                    name,
                    ResourceType.S3,
                    raw_tags,
                    name=name,
                    arn=f"arn:aws:s3:::{name}",
                    created_at=bucket.get("CreationDate"),
                    monthly_cost=price.monthly if price else 0.0,
                    configuration={
                        "size_gb": size_gb,
                        "object_count": object_count,
                        "storage_class": "STANDARD",
                        "has_lifecycle_policy": bool(lifecycle),
                        "lifecycle_rules": (lifecycle or {}).get("Rules", []),
                        "price_source": price.source if price else "unavailable",
                    },
                )
            )
        return out

    def _discover_rds(self) -> list[Resource]:
        rds = self._client("rds")
        out: list[Resource] = []
        for db in paginate(rds, "describe_db_instances", "DBInstances"):
            arn = db["DBInstanceArn"]
            raw_tags = {t["Key"]: t["Value"] for t in db.get("TagList", [])}
            price = pricing.rds_monthly(db["DBInstanceClass"], db.get("MultiAZ", False))
            storage_cost = db.get("AllocatedStorage", 0) * 0.115
            out.append(
                self._build(
                    db["DBInstanceIdentifier"],
                    ResourceType.RDS,
                    raw_tags,
                    name=db["DBInstanceIdentifier"],
                    arn=arn,
                    state=db.get("DBInstanceStatus"),
                    created_at=db.get("InstanceCreateTime"),
                    monthly_cost=round((price.monthly if price else 0.0) + storage_cost, 2),
                    configuration={
                        "instance_class": db["DBInstanceClass"],
                        "engine": db.get("Engine"),
                        "engine_version": db.get("EngineVersion"),
                        "multi_az": db.get("MultiAZ", False),
                        "allocated_storage_gb": db.get("AllocatedStorage"),
                        "storage_type": db.get("StorageType"),
                        "iops": db.get("Iops"),
                        "deletion_protection": db.get("DeletionProtection", False),
                        "backup_retention_days": db.get("BackupRetentionPeriod"),
                        "price_source": price.source if price else "unpriced",
                    },
                )
            )
        return out

    def _discover_lambda(self) -> list[Resource]:
        lam = self._client("lambda")
        out: list[Resource] = []
        for fn in paginate(lam, "list_functions", "Functions"):
            arn = fn["FunctionArn"]
            tag_result = soft_call(
                lam.list_tags, Resource=arn, default=None, context="lambda:ListTags"
            )
            raw_tags = (tag_result or {}).get("Tags", {})
            concurrency = soft_call(
                lam.get_function_concurrency,
                FunctionName=fn["FunctionName"],
                default=None,
                context="lambda:GetFunctionConcurrency",
            )
            last_modified = fn.get("LastModified")
            out.append(
                self._build(
                    fn["FunctionName"],
                    ResourceType.LAMBDA,
                    raw_tags,
                    name=fn["FunctionName"],
                    arn=arn,
                    created_at=_parse_lambda_timestamp(last_modified),
                    configuration={
                        "memory_mb": fn.get("MemorySize"),
                        "timeout_seconds": fn.get("Timeout"),
                        "runtime": fn.get("Runtime"),
                        "architecture": (fn.get("Architectures") or ["x86_64"])[0],
                        "package_type": fn.get("PackageType"),
                        "reserved_concurrency": (concurrency or {}).get(
                            "ReservedConcurrentExecutions"
                        ),
                    },
                )
            )
        return out

    def _discover_nat_gateways(self) -> list[Resource]:
        ec2 = self._client("ec2")
        out: list[Resource] = []
        for nat in paginate(ec2, "describe_nat_gateways", "NatGateways"):
            if nat.get("State") not in ("available", "pending"):
                continue
            raw_tags = {t["Key"]: t["Value"] for t in nat.get("Tags", [])}
            price = pricing.nat_gateway_monthly()
            out.append(
                self._build(
                    nat["NatGatewayId"],
                    ResourceType.NAT_GATEWAY,
                    raw_tags,
                    name=raw_tags.get("Name"),
                    arn=self._arn("ec2", f"natgateway/{nat['NatGatewayId']}"),
                    state=nat.get("State"),
                    created_at=nat.get("CreateTime"),
                    monthly_cost=price.monthly,
                    configuration={
                        "vpc_id": nat.get("VpcId"),
                        "subnet_id": nat.get("SubnetId"),
                        "connectivity_type": nat.get("ConnectivityType", "public"),
                        "price_source": price.source,
                    },
                )
            )
        return out

    def _discover_elastic_ips(self) -> list[Resource]:
        ec2 = self._client("ec2")
        addresses = soft_call(
            ec2.describe_addresses, default={"Addresses": []}, context="ec2:DescribeAddresses"
        )
        out: list[Resource] = []
        for addr in (addresses or {}).get("Addresses", []):
            attached = bool(addr.get("AssociationId"))
            raw_tags = {t["Key"]: t["Value"] for t in addr.get("Tags", [])}
            price = pricing.idle_eip_monthly()
            allocation_id = addr.get("AllocationId", addr.get("PublicIp"))
            out.append(
                self._build(
                    allocation_id,
                    ResourceType.ELASTIC_IP,
                    raw_tags,
                    name=raw_tags.get("Name") or addr.get("PublicIp"),
                    state="associated" if attached else "unassociated",
                    monthly_cost=price.monthly,
                    configuration={
                        "public_ip": addr.get("PublicIp"),
                        "association_id": addr.get("AssociationId"),
                        "instance_id": addr.get("InstanceId"),
                        "network_interface_id": addr.get("NetworkInterfaceId"),
                        "price_source": price.source,
                    },
                )
            )
        return out


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _bucket_size_gb(cloudwatch, bucket: str) -> float | None:
    """S3 has no cheap size API, so read the daily CloudWatch storage metric."""
    from datetime import timedelta

    end = datetime.now(timezone.utc)
    stats = soft_call(
        cloudwatch.get_metric_statistics,
        Namespace="AWS/S3",
        MetricName="BucketSizeBytes",
        Dimensions=[
            {"Name": "BucketName", "Value": bucket},
            {"Name": "StorageType", "Value": "StandardStorage"},
        ],
        StartTime=end - timedelta(days=3),
        EndTime=end,
        Period=86400,
        Statistics=["Average"],
        default=None,
        context="cloudwatch:BucketSizeBytes",
    )
    points = (stats or {}).get("Datapoints", [])
    if not points:
        return None
    latest = max(points, key=lambda p: p["Timestamp"])
    return round(latest["Average"] / (1024**3), 3)


def _bucket_object_count(cloudwatch, bucket: str) -> int | None:
    from datetime import timedelta

    end = datetime.now(timezone.utc)
    stats = soft_call(
        cloudwatch.get_metric_statistics,
        Namespace="AWS/S3",
        MetricName="NumberOfObjects",
        Dimensions=[
            {"Name": "BucketName", "Value": bucket},
            {"Name": "StorageType", "Value": "AllStorageTypes"},
        ],
        StartTime=end - timedelta(days=3),
        EndTime=end,
        Period=86400,
        Statistics=["Average"],
        default=None,
        context="cloudwatch:NumberOfObjects",
    )
    points = (stats or {}).get("Datapoints", [])
    if not points:
        return None
    return int(max(points, key=lambda p: p["Timestamp"])["Average"])


def _parse_lambda_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        return None


def _infer_type(resource_id: str) -> ResourceType | None:
    if resource_id.startswith("i-"):
        return ResourceType.EC2
    if resource_id.startswith("vol-"):
        return ResourceType.EBS
    if resource_id.startswith("nat-"):
        return ResourceType.NAT_GATEWAY
    if resource_id.startswith("eipalloc-"):
        return ResourceType.ELASTIC_IP
    return None
