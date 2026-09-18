"""Repository interfaces.

Deliberately narrow: get, put, list, delete. The query patterns CloudWaste
actually needs are "everything for this account" and "this one by id", which is
what DynamoDB is good at and what keeps the in-memory implementation an honest
stand-in rather than a fake that supports queries the real store cannot.
"""

from __future__ import annotations

from typing import Generic, Protocol, TypeVar

from ..models.domain import (
    Account,
    Action,
    AuditLog,
    Finding,
    Recommendation,
    Resource,
    Scan,
)

T = TypeVar("T")


class Repository(Protocol, Generic[T]):
    def get(self, key: str) -> T | None: ...
    def put(self, item: T) -> T: ...
    def list(self, account_id: str | None = None, limit: int = 1000) -> list[T]: ...
    def delete(self, key: str) -> bool: ...


class Repositories(Protocol):
    accounts: Repository[Account]
    resources: Repository[Resource]
    findings: Repository[Finding]
    recommendations: Repository[Recommendation]
    actions: Repository[Action]
    audit: Repository[AuditLog]
    scans: Repository[Scan]


#: Primary key attribute for each model, shared by both implementations.
KEY_FIELDS: dict[str, str] = {
    "Account": "account_id",
    "Resource": "resource_id",
    "Finding": "finding_id",
    "Recommendation": "recommendation_id",
    "Action": "action_id",
    "AuditLog": "audit_id",
    "Scan": "scan_id",
}
