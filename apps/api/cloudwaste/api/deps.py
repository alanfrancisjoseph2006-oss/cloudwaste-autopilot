"""Shared FastAPI dependencies."""

from __future__ import annotations

from typing import Any

from fastapi import Depends, Header, HTTPException, Query, status

from ..config import Settings, get_settings
from ..models.domain import Account
from ..services import CloudWasteService, get_service


def service() -> CloudWasteService:
    return get_service()


def settings() -> Settings:
    return get_settings()


def current_user(
    x_user: str | None = Header(
        default=None,
        alias="X-User",
        description="Identity of the caller, used for approvals and the audit trail.",
    ),
) -> str:
    """Caller identity.

    A real deployment puts Cognito or an OIDC proxy in front of this and reads a
    verified claim. This header stands in for that, and the fact that it is
    unverified is why it is named plainly rather than dressed up as auth: every
    approval records who claimed to make it, and that record is only as good as
    whatever sits in front of the API.
    """
    return x_user or "anonymous"


def get_account(account_id: str, svc: CloudWasteService = Depends(service)) -> Account:
    account = svc.repos.accounts.get(account_id)
    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Account {account_id} is not registered",
        )
    return account


def resolve_account(
    account_id: str | None = Query(
        None,
        description=(
            "Account to operate on. Required when more than one account is "
            "registered; optional for single-account deployments."
        ),
    ),
    svc: CloudWasteService = Depends(service),
) -> Account:
    """The account a request is about.

    Explicit when given. When omitted, only an unambiguous deployment (exactly
    one account) gets a default: guessing between several accounts is how one
    account's data ends up on another's dashboard.
    """
    if account_id:
        return get_account(account_id, svc)
    accounts = svc.repos.accounts.list()
    if not accounts:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No accounts are registered. POST /api/v1/accounts first.",
        )
    if len(accounts) > 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"{len(accounts)} accounts are registered; pass ?account_id= to "
                f"choose one. Valid: {', '.join(sorted(a.account_id for a in accounts))}"
            ),
        )
    return accounts[0]


def optional_account(
    account_id: str | None = Query(
        None, description="If given, the entity must belong to this account."
    ),
    svc: CloudWasteService = Depends(service),
) -> Account | None:
    return get_account(account_id, svc) if account_id else None


def ensure_owned(entity: Any, account: Account | None, label: str, entity_id: str) -> None:
    """404 when an entity is requested through the wrong account.

    404 rather than 403 so that one account's ids cannot be used to probe
    whether an entity exists in another.
    """
    if entity is None or (account is not None and entity.account_id != account.account_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{label} {entity_id} not found")


# Kept for compatibility with anything importing it; resolves the same way.
default_account = resolve_account
