"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException, status

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


def default_account(svc: CloudWasteService = Depends(service)) -> Account:
    """The single account, for endpoints that do not take one explicitly."""
    accounts = svc.repos.accounts.list()
    if not accounts:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No accounts are registered. POST /api/v1/accounts first.",
        )
    return accounts[0]
