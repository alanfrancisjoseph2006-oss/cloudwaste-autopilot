"""Backup detection -- the one definition every layer uses.

Whether a resource "has a backup" decides whether a destructive action is
blocked outright or merely risky, so it must mean the same thing to the risk
engine, the simulator and the recommendation engine. Two definitions that
disagree is how a volume gets a LOW-risk simulation and a CRITICAL action.

Pure: reads only facts already on the resource. Live confirmation that the
snapshot still exists and covers the volume's current size is the executor's
preflight job, not this module's.
"""

from __future__ import annotations

from ..models.domain import Resource
from ..models.enums import ResourceType

#: A snapshot older than this no longer counts as a backup of the volume as it
#: is today.
MAX_SNAPSHOT_AGE_DAYS = 30


def has_recent_backup(resource: Resource) -> bool:
    config = resource.configuration
    if resource.resource_type is ResourceType.EBS:
        if config.get("latest_snapshot_id") is None:
            return False
        age = config.get("latest_snapshot_age_days")
        # An unknown age is accepted here because preflight re-checks the live
        # snapshot's completion and size before any deletion runs.
        return age is None or age <= MAX_SNAPSHOT_AGE_DAYS
    if resource.resource_type is ResourceType.RDS:
        return (config.get("backup_retention_days") or 0) > 0
    return False
