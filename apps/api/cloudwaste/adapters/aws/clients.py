"""boto3 session and client construction.

Customer accounts are reached by assuming a cross-account role with an
ExternalId. Sessions are cached per (role, region) and refreshed before the
credentials expire.

Regional notes that matter and are easy to get wrong:
  * Cost Explorer (`ce`) is global and only answers in us-east-1.
  * Cost Optimization Hub (`cost-optimization-hub`) is likewise us-east-1.
  * Compute Optimizer and CloudWatch are regional.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Services whose endpoints only exist in us-east-1 regardless of the account's
# working region.
GLOBAL_SERVICES = {"ce", "cost-optimization-hub", "organizations", "iam"}
GLOBAL_REGION = "us-east-1"

BOTO_CONFIG = Config(
    retries={"max_attempts": 6, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=60,
    user_agent_extra="cloudwaste-autopilot/1.0",
)


class AwsSessionFactory:
    """Builds boto3 sessions, assuming a role when one is configured."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: dict[tuple[str | None, str | None], tuple[boto3.Session, datetime]] = {}

    def session(
        self,
        role_arn: str | None = None,
        external_id: str | None = None,
        region: str = GLOBAL_REGION,
        session_name: str = "cloudwaste-autopilot",
    ) -> boto3.Session:
        if not role_arn:
            return boto3.Session(region_name=region)

        key = (role_arn, external_id)
        now = datetime.now(timezone.utc)
        with self._lock:
            cached = self._cache.get(key)
            if cached and cached[1] > now + timedelta(minutes=5):
                return cached[0]

            sts = boto3.client("sts", config=BOTO_CONFIG)
            params: dict[str, Any] = {
                "RoleArn": role_arn,
                "RoleSessionName": session_name,
                "DurationSeconds": 3600,
            }
            if external_id:
                params["ExternalId"] = external_id

            response = sts.assume_role(**params)
            creds = response["Credentials"]
            session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
            self._cache[key] = (session, creds["Expiration"])
            return session

    def client(
        self,
        service: str,
        role_arn: str | None = None,
        external_id: str | None = None,
        region: str = GLOBAL_REGION,
    ):
        effective_region = GLOBAL_REGION if service in GLOBAL_SERVICES else region
        session = self.session(role_arn, external_id, effective_region)
        return session.client(service, region_name=effective_region, config=BOTO_CONFIG)


_factory = AwsSessionFactory()


def get_client(
    service: str,
    role_arn: str | None = None,
    external_id: str | None = None,
    region: str = GLOBAL_REGION,
):
    return _factory.client(service, role_arn, external_id, region)


def paginate(client, operation: str, result_key: str, **kwargs):
    """Yield every item from a paginated operation, or fall back to a single
    call for operations botocore has no paginator for."""
    if client.can_paginate(operation):
        for page in client.get_paginator(operation).paginate(**kwargs):
            yield from page.get(result_key, [])
        return
    response = getattr(client, operation)(**kwargs)
    yield from response.get(result_key, [])


def is_access_denied(error: ClientError) -> bool:
    code = error.response.get("Error", {}).get("Code", "")
    return code in (
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "OptInRequired",
        "SubscriptionRequiredException",
    )


def soft_call(fn, *args, default=None, context: str = "", **kwargs):
    """Run an AWS call, downgrading the two failures that are expected in the
    field -- a permission we were not granted, and a service the account has
    not opted into -- to a logged miss rather than a failed scan.

    A partial scan that reports what it could not see is more useful than no
    scan, so the caller receives `default` and the reason is logged.
    """
    try:
        return fn(*args, **kwargs)
    except ClientError as exc:
        if is_access_denied(exc):
            logger.warning("aws call denied or not enabled (%s): %s", context, exc)
            return default
        raise
