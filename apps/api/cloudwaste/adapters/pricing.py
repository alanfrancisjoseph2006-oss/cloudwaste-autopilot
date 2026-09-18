"""Pricing.

Savings numbers are the product's headline claim, so provenance matters more
than precision. Every price this module returns carries a `source` telling you
where it came from:

  * "cost_explorer"  -- the resource's own observed unblended cost. Most truthful.
  * "pricing_api"    -- live AWS Price List query (live accounts only).
  * "price_book"     -- the static table below.

The static table is on-demand, Linux, us-east-1, USD/hour, and is a fallback
only. It is deliberately small: the detectors prefer observed cost and only
fall back here when Cost Explorer has no resource-level record (which is the
normal case unless resource-level granularity is enabled on the account).
"""

from __future__ import annotations

from dataclasses import dataclass

HOURS_PER_MONTH = 730.0


@dataclass(slots=True)
class Price:
    monthly: float
    source: str
    detail: str = ""

    @property
    def hourly(self) -> float:
        return self.monthly / HOURS_PER_MONTH


# On-demand USD/hour, Linux, us-east-1. Fallback only -- see module docstring.
EC2_HOURLY: dict[str, float] = {
    "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416,
    "t3.large": 0.0832, "t3.xlarge": 0.1664, "t3.2xlarge": 0.3328,
    "t3a.medium": 0.0376, "t3a.large": 0.0752,
    "m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384,
    "m5.4xlarge": 0.768, "m5.8xlarge": 1.536,
    "m6i.large": 0.096, "m6i.xlarge": 0.192, "m6i.2xlarge": 0.384,
    "m6g.large": 0.077, "m6g.xlarge": 0.154, "m6g.2xlarge": 0.308,
    "c5.large": 0.085, "c5.xlarge": 0.17, "c5.2xlarge": 0.34, "c5.4xlarge": 0.68,
    "c6i.large": 0.085, "c6i.xlarge": 0.17, "c6i.2xlarge": 0.34,
    "r5.large": 0.126, "r5.xlarge": 0.252, "r5.2xlarge": 0.504, "r5.4xlarge": 1.008,
    "r6i.large": 0.126, "r6i.xlarge": 0.252, "r6i.2xlarge": 0.504,
}

RDS_HOURLY: dict[str, float] = {
    "db.t3.micro": 0.017, "db.t3.small": 0.034, "db.t3.medium": 0.068,
    "db.t3.large": 0.136, "db.t4g.medium": 0.065, "db.t4g.large": 0.129,
    "db.m5.large": 0.178, "db.m5.xlarge": 0.356, "db.m5.2xlarge": 0.712,
    "db.m6g.large": 0.159, "db.m6g.xlarge": 0.318,
    "db.r5.large": 0.24, "db.r5.xlarge": 0.48, "db.r5.2xlarge": 0.96,
    "db.r6g.large": 0.206, "db.r6g.xlarge": 0.412, "db.r6g.2xlarge": 0.824,
    "db.r6g.4xlarge": 1.648,
}

# USD per GB-month.
EBS_GB_MONTH: dict[str, float] = {
    "gp2": 0.10, "gp3": 0.08, "io1": 0.125, "io2": 0.125,
    "st1": 0.045, "sc1": 0.015, "standard": 0.05,
}
EBS_SNAPSHOT_GB_MONTH = 0.05

S3_GB_MONTH: dict[str, float] = {
    "STANDARD": 0.023,
    "INTELLIGENT_TIERING": 0.023,       # frequent tier; auto-tiers downward
    "STANDARD_IA": 0.0125,
    "ONEZONE_IA": 0.01,
    "GLACIER_IR": 0.004,
    "GLACIER": 0.0036,
    "DEEP_ARCHIVE": 0.00099,
}
# Intelligent-Tiering monitoring, per 1000 objects per month. Small objects can
# make this cost more than it saves, which the S3 detector checks for.
S3_INTELLIGENT_TIERING_MONITORING_PER_1K_OBJECTS = 0.0025

LAMBDA_GB_SECOND = 0.0000166667
LAMBDA_PER_REQUEST = 0.0000002

NAT_GATEWAY_HOURLY = 0.045
NAT_GATEWAY_GB_PROCESSED = 0.045
IDLE_ELASTIC_IP_HOURLY = 0.005


def ec2_monthly(instance_type: str) -> Price | None:
    hourly = EC2_HOURLY.get(instance_type)
    if hourly is None:
        return None
    return Price(round(hourly * HOURS_PER_MONTH, 2), "price_book", f"on-demand {instance_type}")


def rds_monthly(instance_class: str, multi_az: bool = False) -> Price | None:
    hourly = RDS_HOURLY.get(instance_class)
    if hourly is None:
        return None
    multiplier = 2.0 if multi_az else 1.0
    detail = f"on-demand {instance_class}" + (" multi-AZ" if multi_az else "")
    return Price(round(hourly * HOURS_PER_MONTH * multiplier, 2), "price_book", detail)


def ebs_monthly(volume_type: str, size_gb: float, provisioned_iops: int | None = None) -> Price:
    rate = EBS_GB_MONTH.get(volume_type, EBS_GB_MONTH["gp2"])
    cost = rate * size_gb
    detail = f"{size_gb:g} GB {volume_type}"
    if volume_type == "gp3":
        # gp3 includes 3000 IOPS and 125 MB/s at no extra charge.
        billable_iops = max(0, (provisioned_iops or 3000) - 3000)
        if billable_iops:
            cost += billable_iops * 0.005
            detail += f" + {billable_iops} billable IOPS"
    elif volume_type in ("io1", "io2") and provisioned_iops:
        cost += provisioned_iops * 0.065
        detail += f" + {provisioned_iops} provisioned IOPS"
    return Price(round(cost, 2), "price_book", detail)


def s3_monthly(storage_class: str, size_gb: float) -> Price:
    rate = S3_GB_MONTH.get(storage_class.upper(), S3_GB_MONTH["STANDARD"])
    return Price(round(rate * size_gb, 2), "price_book", f"{size_gb:g} GB {storage_class}")


def lambda_monthly(memory_mb: int, avg_duration_ms: float, monthly_invocations: float) -> Price:
    gb_seconds = (memory_mb / 1024.0) * (avg_duration_ms / 1000.0) * monthly_invocations
    cost = gb_seconds * LAMBDA_GB_SECOND + monthly_invocations * LAMBDA_PER_REQUEST
    return Price(
        round(cost, 2),
        "price_book",
        f"{memory_mb} MB x {avg_duration_ms:.0f} ms x {monthly_invocations:,.0f} invocations",
    )


def nat_gateway_monthly(gb_processed: float = 0.0) -> Price:
    cost = NAT_GATEWAY_HOURLY * HOURS_PER_MONTH + gb_processed * NAT_GATEWAY_GB_PROCESSED
    return Price(round(cost, 2), "price_book", f"hourly + {gb_processed:g} GB processed")


def idle_eip_monthly() -> Price:
    return Price(
        round(IDLE_ELASTIC_IP_HOURLY * HOURS_PER_MONTH, 2), "price_book", "idle public IPv4"
    )


# Family ladder used to propose a downsize target when AWS has not already
# named one. Ordered smallest to largest within each family.
_FAMILY_LADDER: dict[str, list[str]] = {}
for _table in (EC2_HOURLY, RDS_HOURLY):
    for _name in _table:
        _family = _name.rsplit(".", 1)[0]
        _FAMILY_LADDER.setdefault(_family, []).append(_name)
for _family, _members in _FAMILY_LADDER.items():
    _table = RDS_HOURLY if _family.startswith("db.") else EC2_HOURLY
    _members.sort(key=lambda n: _table[n])


def step_down(instance_type: str, steps: int = 1) -> str | None:
    """Return the instance `steps` sizes smaller in the same family, if priced."""
    family = instance_type.rsplit(".", 1)[0]
    ladder = _FAMILY_LADDER.get(family)
    if not ladder or instance_type not in ladder:
        return None
    idx = ladder.index(instance_type) - steps
    return ladder[idx] if idx >= 0 else None
