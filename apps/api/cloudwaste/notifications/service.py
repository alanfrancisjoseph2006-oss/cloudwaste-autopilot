"""Notification dispatch.

Decides with `rules`, sends with a `Publisher`, and records every delivery
attempt in the existing audit log -- there is no separate notification store.

A failed notification never fails the operation that triggered it, but it is
never silent either: it is logged at ERROR and written to the audit trail with
outcome FAILED. A rollback-failure page that did not arrive has to be visible
somewhere a human will look.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..models.domain import Account, Action, AuditLog, Finding, Recommendation
from . import rules
from .publisher import DisabledPublisher, Notification, NotificationEvent, SnsPublisher

logger = logging.getLogger(__name__)


def build_publisher(settings):
    if settings.sns_topic_arn or settings.sns_escalation_topic_arn:
        return SnsPublisher(settings.sns_topic_arn, settings.sns_escalation_topic_arn)
    return DisabledPublisher()


class NotificationService:
    def __init__(self, publisher, settings, repos) -> None:
        self.publisher = publisher
        self.settings = settings
        self.repos = repos

    @property
    def enabled(self) -> bool:
        return self.publisher.enabled

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "channel": self.publisher.channel,
            "events": list(self.settings.notify_events),
            "topic_configured": bool(self.settings.sns_topic_arn),
            "escalation_topic_configured": bool(
                self.settings.sns_escalation_topic_arn or self.settings.sns_topic_arn
            ),
        }

    # ------------------------------------------------------------------

    def send(self, notification: Notification) -> bool:
        if not self.enabled:
            return False
        if notification.event.value not in self.settings.notify_events:
            return False
        result = self.publisher.publish(notification)
        if not result.delivered:
            logger.error(
                "notification %s for %s was not delivered: %s",
                notification.event.value,
                notification.account_id,
                result.detail,
            )
        self.repos.audit.put(
            AuditLog(
                account_id=notification.account_id,
                action_id=notification.data.get("action_id"),
                resource_id=notification.data.get("resource_id"),
                actor="system",
                event="notification.sent" if result.delivered else "notification.failed",
                outcome="SUCCESS" if result.delivered else "FAILED",
                detail={
                    "event_type": notification.event.value,
                    "severity": notification.severity,
                    "subject": notification.subject,
                    "channel": result.channel,
                    "message_id": result.message_id,
                    "delivery_detail": result.detail,
                    "escalation": notification.escalation,
                },
            )
        )
        return result.delivered

    # --- hooks called by the service layer ----------------------------------

    def after_scan(
        self,
        account: Account,
        *,
        findings: list[Finding],
        new_findings: list[Finding],
        recommendations: list[Recommendation],
        anomalies_finding_count: int = 0,
        monthly_spend: float | None = None,
    ) -> None:
        if not self.enabled:
            return
        for notification in rules.scan_notifications(
            account.account_id,
            new_findings=new_findings,
            recommendations=recommendations,
            monthly_spend=monthly_spend,
            settings=self.settings,
        ):
            if (
                notification.event is NotificationEvent.BUDGET_THRESHOLD
                and self._budget_alert_sent_this_month(account.account_id)
            ):
                continue
            self.send(notification)

    def approval_requested(self, action: Action, recommendation: Recommendation | None) -> None:
        if self.enabled:
            self.send(rules.approval_notification(action, recommendation))

    def after_execution(self, action: Action) -> None:
        if not self.enabled:
            return
        notification = rules.execution_notification(action)
        if notification is not None:
            self.send(notification)

    # ------------------------------------------------------------------

    def _budget_alert_sent_this_month(self, account_id: str) -> bool:
        month = datetime.now(timezone.utc).strftime("%Y-%m")
        return any(
            entry.event == "notification.sent"
            and entry.detail.get("event_type") == NotificationEvent.BUDGET_THRESHOLD.value
            and entry.timestamp.strftime("%Y-%m") == month
            for entry in self.repos.audit.list(account_id=account_id, limit=1000)
        )
