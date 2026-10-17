"""Notification transports.

Publishing is the only I/O in the notifications package, and it lives here
behind one small interface so the rules that decide *what* to send can be
tested without SNS.

SNS topics live in the account that runs CloudWaste (the CloudFormation stack
creates them), so the SNS client uses the host's credentials, not a customer
role. Nothing is published when no topic is configured.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class NotificationEvent(str, Enum):
    HIGH_RISK_FINDING = "high_risk_finding"
    APPROVAL_REQUESTED = "approval_requested"
    COST_ANOMALY = "cost_anomaly"
    BUDGET_THRESHOLD = "budget_threshold"
    ROLLBACK_FAILURE = "rollback_failure"
    REMEDIATION_FAILURE = "remediation_failure"
    HIGH_CONFIDENCE_OPPORTUNITY = "high_confidence_opportunity"


@dataclass(slots=True)
class Notification:
    event: NotificationEvent
    severity: str  # info | warning | critical
    subject: str
    message: str
    account_id: str
    # Escalations page a human and go to their own topic.
    escalation: bool = False
    data: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def payload(self) -> dict:
        return {
            "source": "cloudwaste-autopilot",
            "event": self.event.value,
            "severity": self.severity,
            "account_id": self.account_id,
            "subject": self.subject,
            "message": self.message,
            "data": self.data,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(slots=True)
class PublishResult:
    delivered: bool
    channel: str
    detail: str = ""
    message_id: str | None = None


class Publisher(Protocol):
    channel: str

    @property
    def enabled(self) -> bool: ...

    def publish(self, notification: Notification) -> PublishResult: ...


class DisabledPublisher:
    """Used when no topic is configured. Publishes nothing, says so."""

    channel = "disabled"

    @property
    def enabled(self) -> bool:
        return False

    def publish(self, notification: Notification) -> PublishResult:
        return PublishResult(False, self.channel, "Notifications are not configured.")


class RecordingPublisher:
    """Keeps notifications in memory. For tests and local inspection."""

    channel = "memory"

    def __init__(self) -> None:
        self.sent: list[Notification] = []

    @property
    def enabled(self) -> bool:
        return True

    def publish(self, notification: Notification) -> PublishResult:
        self.sent.append(notification)
        return PublishResult(True, self.channel, "recorded")


class SnsPublisher:
    """Publishes to the CloudFormation stack's SNS topics."""

    channel = "sns"

    def __init__(
        self,
        topic_arn: str | None,
        escalation_topic_arn: str | None = None,
        region: str | None = None,
        client=None,
    ) -> None:
        self.topic_arn = topic_arn
        self.escalation_topic_arn = escalation_topic_arn or topic_arn
        self._region = region or (topic_arn or escalation_topic_arn or "::::").split(":")[3]
        self._client = client

    @property
    def enabled(self) -> bool:
        return bool(self.topic_arn or self.escalation_topic_arn)

    def _sns(self):
        if self._client is None:
            import boto3

            self._client = boto3.client("sns", region_name=self._region)
        return self._client

    def publish(self, notification: Notification) -> PublishResult:
        topic = self.escalation_topic_arn if notification.escalation else self.topic_arn
        if not topic:
            return PublishResult(
                False, self.channel, "No topic configured for this kind of notification."
            )
        try:
            response = self._sns().publish(
                TopicArn=topic,
                # SNS subjects are limited to 100 characters, ASCII, no newlines.
                Subject=notification.subject.replace("\n", " ")[:100],
                Message=json.dumps(notification.payload(), default=str),
                MessageAttributes={
                    "event": {"DataType": "String", "StringValue": notification.event.value},
                    "severity": {"DataType": "String", "StringValue": notification.severity},
                    "account_id": {"DataType": "String", "StringValue": notification.account_id},
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "SNS publish of %s to %s failed: %s", notification.event.value, topic, exc
            )
            return PublishResult(False, self.channel, f"{type(exc).__name__}: {exc}")
        return PublishResult(True, self.channel, topic, response.get("MessageId"))
