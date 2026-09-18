"""CloudTrail lookups.

This is the adapter that lets a finding say *who* and *when*, not just *what*.
"Nobody has touched this instance in 23 days and the person who launched it
left the team" is the sentence that gets a cleanup approved.

Two hard limits shape the code: LookupEvents only covers the last 90 days of
management events, and it is rate-limited to roughly two requests per second,
so callers ask narrowly and cache.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from ..base import ActivityEvent
from .clients import get_client, soft_call

logger = logging.getLogger(__name__)

CLOUDTRAIL_RETENTION_DAYS = 90

CREATION_EVENTS = {
    "EC2": ["RunInstances"],
    "EBS": ["CreateVolume"],
    "RDS": ["CreateDBInstance", "RestoreDBInstanceFromDBSnapshot"],
    "LAMBDA": ["CreateFunction20150331"],
    "S3": ["CreateBucket"],
    "NAT_GATEWAY": ["CreateNatGateway"],
    "ELASTIC_IP": ["AllocateAddress"],
}

MODIFICATION_EVENTS = {
    "EC2": ["ModifyInstanceAttribute", "StartInstances", "StopInstances", "RebootInstances"],
    "EBS": ["ModifyVolume", "AttachVolume", "DetachVolume"],
    "RDS": ["ModifyDBInstance", "RebootDBInstance"],
    "LAMBDA": ["UpdateFunctionConfiguration20150331v2", "UpdateFunctionCode20150331v2"],
    "S3": ["PutBucketLifecycleConfiguration", "PutBucketPolicy"],
}


class AwsActivityProvider:
    """Implements `adapters.base.ActivityProvider` against a real account."""

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
        self._cache: dict[tuple, list[ActivityEvent]] = {}

    def _client(self):
        return get_client("cloudtrail", self._role_arn, self._external_id, self.region)

    def lookup_events(
        self,
        resource_id: str | None = None,
        event_names: list[str] | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 50,
    ) -> list[ActivityEvent]:
        end = end or datetime.now(timezone.utc)
        start = start or end - timedelta(days=CLOUDTRAIL_RETENTION_DAYS)
        # Asking beyond retention returns nothing and wastes a throttled call.
        earliest = end - timedelta(days=CLOUDTRAIL_RETENTION_DAYS)
        if start < earliest:
            start = earliest

        cache_key = (resource_id, tuple(event_names or ()), start.date(), end.date(), limit)
        if cache_key in self._cache:
            return self._cache[cache_key]

        # LookupEvents accepts exactly one attribute, so a resource plus several
        # event names means one call per event name, filtered locally.
        lookups: list[list[dict]] = []
        if resource_id and event_names:
            lookups = [
                [{"AttributeKey": "EventName", "AttributeValue": name}] for name in event_names
            ]
        elif resource_id:
            lookups = [[{"AttributeKey": "ResourceName", "AttributeValue": resource_id}]]
        elif event_names:
            lookups = [
                [{"AttributeKey": "EventName", "AttributeValue": name}] for name in event_names
            ]
        else:
            lookups = [[]]

        client = self._client()
        collected: list[ActivityEvent] = []
        for attributes in lookups:
            kwargs = {"StartTime": start, "EndTime": end, "MaxResults": min(limit, 50)}
            if attributes:
                kwargs["LookupAttributes"] = attributes
            response = soft_call(
                client.lookup_events,
                default={"Events": []},
                context="cloudtrail:LookupEvents",
                **kwargs,
            )
            for event in (response or {}).get("Events", []):
                parsed = _parse_event(event)
                if resource_id and not _mentions(event, resource_id):
                    continue
                collected.append(parsed)

        collected.sort(key=lambda e: e.event_time, reverse=True)
        collected = collected[:limit]
        self._cache[cache_key] = collected
        return collected

    # --- higher-level questions the agent actually asks ------------------

    def get_creation_event(self, resource_id: str, resource_type: str) -> ActivityEvent | None:
        events = self.lookup_events(
            resource_id=resource_id,
            event_names=CREATION_EVENTS.get(resource_type, []),
            limit=10,
        )
        return events[-1] if events else None

    def get_last_modification(self, resource_id: str, resource_type: str) -> ActivityEvent | None:
        events = self.lookup_events(
            resource_id=resource_id,
            event_names=MODIFICATION_EVENTS.get(resource_type, []),
            limit=10,
        )
        return events[0] if events else None

    def days_since_last_write(self, resource_id: str, resource_type: str) -> float | None:
        """Days since anyone last changed this resource.

        None means CloudTrail has no record, which for a resource older than
        the 90-day window means "untouched for at least 90 days" -- a strong
        idleness signal, but one the caller must interpret, not assume.
        """
        events = self.lookup_events(
            resource_id=resource_id,
            event_names=MODIFICATION_EVENTS.get(resource_type, []),
            limit=5,
        )
        writes = [e for e in events if not e.read_only]
        if not writes:
            return None
        newest = max(e.event_time for e in writes)
        return round((datetime.now(timezone.utc) - newest).total_seconds() / 86400.0, 1)


def _parse_event(event: dict) -> ActivityEvent:
    import json

    raw: dict = {}
    if event.get("CloudTrailEvent"):
        try:
            raw = json.loads(event["CloudTrailEvent"])
        except (ValueError, TypeError):
            raw = {}
    resources = event.get("Resources", [])
    return ActivityEvent(
        event_id=event.get("EventId", ""),
        event_name=event.get("EventName", ""),
        event_time=event["EventTime"],
        username=event.get("Username") or raw.get("userIdentity", {}).get("arn"),
        source_ip=raw.get("sourceIPAddress"),
        resource_id=resources[0].get("ResourceName") if resources else None,
        read_only=bool(raw.get("readOnly", False)),
        raw={
            "user_identity": raw.get("userIdentity", {}),
            "user_agent": raw.get("userAgent"),
            "error_code": raw.get("errorCode"),
        },
    )


def _mentions(event: dict, resource_id: str) -> bool:
    if any(r.get("ResourceName") == resource_id for r in event.get("Resources", [])):
        return True
    return resource_id in (event.get("CloudTrailEvent") or "")
