"""Shared fixtures.

Every test runs against the deterministic demo account, so assertions can name
exact resources and exact numbers without a network or a mock framework.
"""

from __future__ import annotations

import pytest

from cloudwaste.config import Settings
from cloudwaste.models.domain import Account
from cloudwaste.policy.policy_loader import load_rules
from cloudwaste.repositories.memory import MemoryRepositories
from cloudwaste.seed.demo_provider import DEMO_ACCOUNT_ID, DEMO_REGION, DemoDataPlane
from cloudwaste.services import CloudWasteService


@pytest.fixture
def settings() -> Settings:
    return Settings(
        storage_backend="memory",
        dry_run_default=True,
        autopilot_enabled=False,
        bedrock_enabled=False,
    )


@pytest.fixture
def account() -> Account:
    return Account(
        account_id=DEMO_ACCOUNT_ID,
        name="Demo account",
        regions=[DEMO_REGION],
        mode="demo",
    )


@pytest.fixture
def data_plane() -> DemoDataPlane:
    return DemoDataPlane()


@pytest.fixture
def repos(account) -> MemoryRepositories:
    repositories = MemoryRepositories()
    repositories.accounts.put(account)
    return repositories


@pytest.fixture
def service(repos, settings) -> CloudWasteService:
    return CloudWasteService(repos, settings)


@pytest.fixture
def scanned(service, account):
    """A service with one completed scan, and the scan's output."""
    return service, account, service.scan_account(account)


@pytest.fixture
def policy_rules():
    return load_rules()
