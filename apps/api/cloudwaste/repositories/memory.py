"""In-process storage.

The default backend, so the API runs with no AWS and no database. Items are
stored as deep copies: handing out a shared reference would let a caller mutate
stored state without a `put`, which the DynamoDB backend would never allow, and
a stand-in that is more permissive than the real thing hides bugs until
deployment.

Not durable, and not safe across processes. `storage_backend=dynamodb` is the
answer for anything that needs to survive a restart.
"""

from __future__ import annotations

import threading
from typing import Generic, TypeVar

from ..models.domain import (
    Account,
    Action,
    AuditLog,
    Finding,
    Recommendation,
    Resource,
    Scan,
)
from .base import KEY_FIELDS

T = TypeVar("T")


class MemoryRepository(Generic[T]):
    def __init__(self, model: type[T]) -> None:
        self._model = model
        self._key = KEY_FIELDS[model.__name__]
        self._items: dict[str, T] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> T | None:
        with self._lock:
            item = self._items.get(key)
            return item.model_copy(deep=True) if item is not None else None

    def put(self, item: T) -> T:
        with self._lock:
            self._items[getattr(item, self._key)] = item.model_copy(deep=True)
        return item

    def list(self, account_id: str | None = None, limit: int = 1000) -> list[T]:
        with self._lock:
            items = list(self._items.values())
        if account_id is not None:
            items = [
                i for i in items if getattr(i, "account_id", None) in (account_id, None)
            ]
        items = self._sort(items)
        return [i.model_copy(deep=True) for i in items[:limit]]

    def delete(self, key: str) -> bool:
        with self._lock:
            return self._items.pop(key, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def _sort(self, items: list[T]) -> list[T]:
        """Newest first where the model has a timestamp to sort by."""
        for attribute in ("timestamp", "created_at", "started_at", "first_seen_at"):
            if items and hasattr(items[0], attribute):
                return sorted(
                    items,
                    key=lambda i: getattr(i, attribute) or _EPOCH,
                    reverse=True,
                )
        return items


from datetime import datetime, timezone  # noqa: E402

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class MemoryRepositories:
    def __init__(self) -> None:
        self.accounts = MemoryRepository(Account)
        self.resources = MemoryRepository(Resource)
        self.findings = MemoryRepository(Finding)
        self.recommendations = MemoryRepository(Recommendation)
        self.actions = MemoryRepository(Action)
        self.audit = MemoryRepository(AuditLog)
        self.scans = MemoryRepository(Scan)

    def clear(self) -> None:
        for repo in (
            self.accounts, self.resources, self.findings,
            self.recommendations, self.actions, self.audit, self.scans,
        ):
            repo.clear()
