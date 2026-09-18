"""Application service layer.

Wires the engines together and owns the one object graph the API and the agent
both talk to. Everything above this line is a pure engine with no I/O; this is
where a data plane, a repository and a policy set get bound to a running
account.

The composition is:

    Account -> DataPlane (live boto3 | demo)
            -> WasteDetector      -> findings
            -> RecommendationEngine -> recommendations
            -> RiskEngine + PolicyEngine -> a decision
            -> ApprovalEngine     -> an Action in the right initial state
            -> RemediationOrchestrator -> execution, verification, rollback
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from .actions.approval import ApprovalEngine, plan_fingerprint
from .actions.orchestrator import RemediationOrchestrator
from .actions.registry import is_executable
from .config import Settings, get_settings
from .intelligence import risk_engine
from .intelligence.recommendation_engine import RecommendationEngine
from .intelligence.waste_detector import WasteDetector
from .models.domain import Account, Action, AuditLog, Finding, Recommendation, Resource
from .models.enums import ExecutionStatus, PolicyDecision
from .policy.policy_engine import PolicyEngine
from .policy.policy_loader import load_and_validate
from .repositories.base import Repositories
from .seed.demo_provider import DEMO_ACCOUNT_ID, DEMO_REGION, DemoDataPlane

logger = logging.getLogger(__name__)


class LiveDataPlane:
    """The five boto3-backed providers, bundled to match `adapters.base.DataPlane`."""

    def __init__(self, account: Account, region: str) -> None:
        from .adapters.aws.activity import AwsActivityProvider
        from .adapters.aws.cost import AwsCostProvider
        from .adapters.aws.inventory import AwsInventoryProvider
        from .adapters.aws.metrics import AwsMetricsProvider
        from .adapters.aws.recommendations import AwsRecommendationProvider

        args = (account.account_id, region, account.role_arn, account.external_id)
        self.account_id = account.account_id
        self.region = region
        self.mode = "live"
        self.inventory = AwsInventoryProvider(*args)
        self.metrics = AwsMetricsProvider(*args)
        self.cost = AwsCostProvider(*args)
        self.recommendations = AwsRecommendationProvider(*args)
        self.activity = AwsActivityProvider(*args)

    def client_factory(self, service: str, region: str):
        from .adapters.aws.clients import get_client

        return get_client(service, None, None, region)


class CloudWasteService:
    """The application. One instance per process."""

    def __init__(self, repositories: Repositories, settings: Settings | None = None) -> None:
        self.repos = repositories
        self.settings = settings or get_settings()
        rules, problems = load_and_validate(settings=self.settings, strict=True)
        self.policy_rules = rules
        self.policy_problems = problems
        self.policy = PolicyEngine(rules, self.settings)
        self.recommender = RecommendationEngine()
        self.approvals = ApprovalEngine(self.settings)

    # ------------------------------------------------------------------
    # Data plane
    # ------------------------------------------------------------------

    def data_plane(self, account: Account, region: str | None = None):
        region = region or (account.regions[0] if account.regions else self.settings.aws_region)
        if account.mode == "demo":
            return DemoDataPlane(account.account_id, region)
        return LiveDataPlane(account, region)

    def client_factory_for(self, account: Account):
        """Executors get a client factory only for live accounts.

        A demo account returns None, which makes any attempt to call AWS raise
        rather than silently succeed. Demo actions run in dry-run mode, where
        no AWS call is reached at all.
        """
        if account.mode == "demo":
            return None
        plane = self.data_plane(account)
        return plane.client_factory

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_account(self, account: Account, region: str | None = None) -> dict:
        plane = self.data_plane(account, region)
        detector = WasteDetector(plane, self.settings)
        result = detector.scan()

        self.repos.scans.put(result.scan)
        for resource in result.resources:
            self.repos.resources.put(resource)

        # Carry forward human decisions: a finding an operator suppressed must
        # not reappear as OPEN on the next scan, or the tool becomes noise.
        previous = {
            (f.resource_id, f.waste_type): f
            for f in self.repos.findings.list(account_id=account.account_id)
        }
        for finding in result.findings:
            prior = previous.get((finding.resource_id, finding.waste_type))
            if prior is not None:
                finding.finding_id = prior.finding_id
                finding.first_seen_at = prior.first_seen_at
                if prior.status.value in ("SUPPRESSED", "ACKNOWLEDGED"):
                    finding.status = prior.status
            self.repos.findings.put(finding)

        # Findings whose resource no longer appears, or which no longer fire,
        # are marked stale rather than deleted, so history survives.
        current_keys = {(f.resource_id, f.waste_type) for f in result.findings}
        for key, prior in previous.items():
            if key not in current_keys and prior.status.value == "OPEN":
                prior.status = prior.status.__class__("STALE")
                prior.last_seen_at = datetime.now(timezone.utc)
                self.repos.findings.put(prior)

        recommendations = self.build_recommendations(account, result.findings, plane)

        self.repos.audit.put(
            AuditLog(
                account_id=account.account_id,
                actor="system",
                event="scan.completed",
                detail={
                    "scan_id": result.scan.scan_id,
                    "resources_scanned": result.scan.resources_scanned,
                    "findings": len(result.findings),
                    "recommendations": len(recommendations),
                    "potential_monthly_savings": result.total_potential_savings,
                    "errors": result.scan.errors,
                },
            )
        )

        return {
            "scan": result.scan,
            "findings": result.findings,
            "recommendations": recommendations,
            "resources": result.resources,
        }

    def build_recommendations(
        self, account: Account, findings: list[Finding], plane=None
    ) -> list[Recommendation]:
        plane = plane or self.data_plane(account)
        try:
            optimizer = {
                rec.resource_id: rec for rec in plane.recommendations.list_recommendations()
            }
        except Exception:  # noqa: BLE001
            optimizer = {}

        out: list[Recommendation] = []
        for finding in findings:
            resource = self.repos.resources.get(finding.resource_id)
            if resource is None:
                continue
            for rec in self.recommender.build(
                finding, resource, {"optimizer": optimizer.get(finding.resource_id)}
            ):
                if not is_executable(rec.action_type):
                    continue
                # The finding's risk is the risk of the action proposed for it,
                # which is only known now.
                finding.risk = rec.risk
                self.repos.findings.put(finding)
                self.repos.recommendations.put(rec)
                out.append(rec)
        return out

    # ------------------------------------------------------------------
    # Action lifecycle
    # ------------------------------------------------------------------

    def create_action(
        self,
        recommendation: Recommendation,
        resource: Resource,
        requested_by: str = "system",
        agent_id: str | None = None,
        dry_run: bool | None = None,
    ) -> tuple[Action, dict]:
        assessment = risk_engine.assess(
            risk_engine.RiskInputs(
                action_type=recommendation.action_type,
                resource=resource,
                confidence=recommendation.confidence,
                rollback_possible=recommendation.rollback_possible,
                restart_required=recommendation.restart_required,
                downtime_seconds=(
                    recommendation.simulation.downtime_estimate_seconds
                    if recommendation.simulation
                    else 0
                ),
                has_recent_backup=_has_backup(resource),
                data_bearing=risk_engine.is_data_bearing(resource, recommendation.action_type),
            )
        )
        evaluation = self.policy.evaluate(recommendation, resource, assessment)

        action = Action(
            recommendation_id=recommendation.recommendation_id,
            finding_id=recommendation.finding_id,
            resource_id=recommendation.resource_id,
            resource_type=recommendation.resource_type,
            account_id=recommendation.account_id,
            region=recommendation.region,
            action_type=recommendation.action_type,
            parameters={
                **recommendation.action_parameters,
                "_plan_fingerprint": plan_fingerprint(recommendation),
            },
            risk=assessment.level,
            policy_decision=evaluation.decision,
            policy_rule=evaluation.matched_rule,
            dry_run=self.settings.dry_run_default if dry_run is None else dry_run,
            requested_by=requested_by,
            agent_id=agent_id,
            reason=recommendation.rationale,
        )
        self.approvals.initialize(action, evaluation)
        self.repos.actions.put(action)

        self.repos.audit.put(
            AuditLog(
                action_id=action.action_id,
                resource_id=action.resource_id,
                account_id=action.account_id,
                actor=requested_by,
                agent_id=agent_id,
                event="action.created",
                risk=assessment.level,
                detail={
                    "action_type": action.action_type.value,
                    "policy_decision": evaluation.decision.value,
                    "policy_rule": evaluation.matched_rule,
                    "policy_reasons": evaluation.reasons,
                    "risk_factors": assessment.factors,
                    "risk_mitigations": assessment.mitigations,
                    "risk_floors": assessment.floors_applied,
                    "blocking_reasons": assessment.blocking_reasons,
                },
            )
        )

        return action, {
            "risk": {
                "level": assessment.level.value,
                "score": assessment.score,
                "factors": assessment.factors,
                "mitigations": assessment.mitigations,
                "floors_applied": assessment.floors_applied,
                "blocking_reasons": assessment.blocking_reasons,
            },
            "policy": evaluation.model_dump(mode="json"),
        }

    def execute_action(
        self, action: Action, account: Account, settle_seconds: int | None = None
    ):
        resource = self.repos.resources.get(action.resource_id)
        if resource is None:
            raise LookupError(f"Resource {action.resource_id} is not in the inventory")
        recommendation = self.repos.recommendations.get(action.recommendation_id)

        orchestrator = RemediationOrchestrator(
            self.data_plane(account),
            client_factory=self.client_factory_for(account),
            settings=self.settings,
            approval_engine=self.approvals,
        )
        result = orchestrator.run(
            action, resource, recommendation, settle_seconds=settle_seconds
        )

        self.repos.actions.put(result.action)
        for entry in result.audit:
            self.repos.audit.put(entry)

        if result.succeeded and result.action.finding_id:
            finding = self.repos.findings.get(result.action.finding_id)
            if finding is not None and not result.action.dry_run:
                finding.status = finding.status.__class__("REMEDIATED")
                self.repos.findings.put(finding)

        return result

    def rollback_action(self, action: Action, account: Account):
        resource = self.repos.resources.get(action.resource_id)
        if resource is None:
            raise LookupError(f"Resource {action.resource_id} is not in the inventory")
        orchestrator = RemediationOrchestrator(
            self.data_plane(account),
            client_factory=self.client_factory_for(account),
            settings=self.settings,
            approval_engine=self.approvals,
        )
        result = orchestrator.rollback_completed_action(action, resource)
        self.repos.actions.put(result.action)
        for entry in result.audit:
            self.repos.audit.put(entry)
        return result

    # ------------------------------------------------------------------
    # Dashboard aggregation
    # ------------------------------------------------------------------

    def dashboard(self, account: Account) -> dict:
        from .intelligence.waste_score import account_waste_score

        findings = [
            f
            for f in self.repos.findings.list(account_id=account.account_id)
            if f.status.value == "OPEN"
        ]
        resources = self.repos.resources.list(account_id=account.account_id)
        actions = self.repos.actions.list(account_id=account.account_id)

        total_cost = round(sum(r.monthly_cost for r in resources), 2)
        savings = round(sum(f.potential_monthly_savings for f in findings), 2)
        flagged_cost = round(
            sum(
                r.monthly_cost
                for r in resources
                if any(f.resource_id == r.resource_id for f in findings)
            ),
            2,
        )

        plane = self.data_plane(account)
        end = datetime.now(timezone.utc)
        try:
            forecast = plane.cost.get_forecast(30)
            by_service = plane.cost.cost_by_service(end - timedelta(days=30), end)
        except Exception:  # noqa: BLE001
            forecast, by_service = 0.0, {}

        by_type: dict[str, dict] = {}
        for finding in findings:
            bucket = by_type.setdefault(
                finding.waste_type.value, {"count": 0, "monthly_savings": 0.0}
            )
            bucket["count"] += 1
            bucket["monthly_savings"] = round(
                bucket["monthly_savings"] + finding.potential_monthly_savings, 2
            )

        by_risk: dict[str, int] = {}
        for finding in findings:
            by_risk[finding.risk.value] = by_risk.get(finding.risk.value, 0) + 1

        realized = round(
            sum(
                a.realized_monthly_savings or 0.0
                for a in actions
                if a.execution_status is ExecutionStatus.COMPLETED and not a.dry_run
            ),
            2,
        )

        return {
            "account_id": account.account_id,
            "monthly_spend": total_cost,
            "forecast_next_30_days": forecast,
            "potential_monthly_savings": savings,
            "potential_annual_savings": round(savings * 12, 2),
            "realized_monthly_savings": realized,
            "waste_score": account_waste_score(flagged_cost, total_cost),
            "active_findings": len(findings),
            "resources_tracked": len(resources),
            "pending_approvals": sum(
                1 for a in actions if a.approval_status.value == "PENDING"
            ),
            "findings_by_type": by_type,
            "findings_by_risk": by_risk,
            "cost_by_service": by_service,
            "autopilot_enabled": self.settings.autopilot_enabled,
            "dry_run": self.settings.dry_run_default,
        }


def _has_backup(resource: Resource) -> bool:
    config = resource.configuration
    if config.get("latest_snapshot_id"):
        return True
    return bool(config.get("backup_retention_days"))


# --------------------------------------------------------------------------


@lru_cache
def get_service() -> CloudWasteService:
    from .repositories.memory import MemoryRepositories

    settings = get_settings()
    repos = MemoryRepositories()

    if not repos.accounts.list():
        repos.accounts.put(
            Account(
                account_id=DEMO_ACCOUNT_ID,
                name="Demo account (synthetic)",
                regions=[DEMO_REGION],
                mode="demo",
            )
        )
    return CloudWasteService(repos, settings)
