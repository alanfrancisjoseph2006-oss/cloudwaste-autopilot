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

Every operation on an action resolves the account that *owns the action*, from
`action.account_id`. It never falls back to "the first registered account":
with more than one account registered, that fallback would run one account's
action through another account's data plane.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any

from .actions.approval import ApprovalEngine, plan_fingerprint
from .actions.orchestrator import RemediationOrchestrator
from .actions.registry import is_executable
from .config import Settings, get_settings
from .intelligence import impact_analyzer, risk_engine
from .intelligence.backups import has_recent_backup
from .intelligence.recommendation_engine import RecommendationEngine
from .intelligence.waste_detector import WasteDetector
from .models.domain import (
    Account,
    Action,
    AuditLog,
    Finding,
    PolicyEvaluation,
    Recommendation,
    Resource,
    SimulationResult,
    resource_key,
)
from .models.enums import ExecutionStatus, SavingsStatus
from .policy.policy_engine import PolicyEngine
from .policy.policy_loader import load_and_validate
from .repositories.base import Repositories
from .seed.demo_provider import DEMO_ACCOUNT_ID, DEMO_REGION, DemoDataPlane

logger = logging.getLogger(__name__)


class AccountMismatchError(LookupError):
    """An operation named one account and an entity belongs to another."""


class CustomerRoleRequired(RuntimeError):
    """A live account has no role to assume and host credentials are not allowed."""


class LiveDataPlane:
    """The five boto3-backed providers, bundled to match `adapters.base.DataPlane`.

    Every provider -- and every executor, through `client_factory` -- reaches
    the customer account through the account's own cross-account role. The
    role is the permission boundary that denies writes to production at the
    IAM layer, so nothing here is allowed to quietly use the host's
    credentials instead.
    """

    def __init__(self, account: Account, region: str, settings: Settings | None = None) -> None:
        from .adapters.aws.activity import AwsActivityProvider
        from .adapters.aws.cost import AwsCostProvider
        from .adapters.aws.inventory import AwsInventoryProvider
        from .adapters.aws.metrics import AwsMetricsProvider
        from .adapters.aws.recommendations import AwsRecommendationProvider

        settings = settings or get_settings()
        if not account.role_arn and not settings.allow_host_credentials:
            raise CustomerRoleRequired(
                f"Account {account.account_id} is registered as live but has no "
                f"role_arn. CloudWaste reaches customer accounts only by assuming "
                f"their CloudWasteAutopilotRole; set "
                f"CLOUDWASTE_ALLOW_HOST_CREDENTIALS=true only for a single-account "
                f"deployment scanning the account it runs in."
            )

        self._role_arn = account.role_arn
        self._external_id = account.external_id
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
        """Clients for executors, built from the customer role's credentials."""
        from .adapters.aws.clients import get_client

        return get_client(service, self._role_arn, self._external_id, region)


class CloudWasteService:
    """The application. One instance per process."""

    def __init__(
        self,
        repositories: Repositories,
        settings: Settings | None = None,
        notifier=None,
        step_functions_client=None,
    ) -> None:
        from .notifications.service import NotificationService, build_publisher

        self.repos = repositories
        self.settings = settings or get_settings()
        rules, problems = load_and_validate(settings=self.settings, strict=True)
        self.policy_rules = rules
        self.policy_problems = problems
        self.policy = PolicyEngine(rules, self.settings)
        self.recommender = RecommendationEngine()
        self.approvals = ApprovalEngine(self.settings)
        self.notifications = NotificationService(
            notifier if notifier is not None else build_publisher(self.settings),
            self.settings,
            self.repos,
        )
        self._step_functions_client = step_functions_client

    # ------------------------------------------------------------------
    # Accounts and ownership
    # ------------------------------------------------------------------

    def get_account(self, account_id: str) -> Account:
        account = self.repos.accounts.get(account_id)
        if account is None:
            raise AccountMismatchError(f"Account {account_id} is not registered")
        return account

    def owning_account(self, entity: Any, supplied: Account | None = None) -> Account:
        """The account an action, finding or recommendation belongs to.

        If the caller also named an account, it must be the same one. A
        mismatch is refused rather than resolved in either direction.
        """
        owner_id = entity.account_id
        if supplied is not None and supplied.account_id != owner_id:
            raise AccountMismatchError(
                f"{type(entity).__name__} belongs to account {owner_id}, not "
                f"{supplied.account_id}. Refusing to act across accounts."
            )
        return self.get_account(owner_id)

    def resource_for(self, entity: Any) -> Resource | None:
        """The stored resource an entity refers to, in the entity's own account."""
        return self.repos.resources.get(
            resource_key(entity.account_id, entity.region, entity.resource_id)
        )

    def find_resource(
        self, account_id: str, resource_id: str, region: str | None = None
    ) -> Resource | None:
        """Look up a resource by AWS id within one account."""
        if region:
            return self.repos.resources.get(resource_key(account_id, region, resource_id))
        matches = [
            r
            for r in self.repos.resources.list(account_id=account_id, limit=5000)
            if r.resource_id == resource_id
        ]
        return matches[0] if len(matches) == 1 else None

    # ------------------------------------------------------------------
    # Data plane
    # ------------------------------------------------------------------

    def data_plane(self, account: Account, region: str | None = None):
        region = region or (account.regions[0] if account.regions else self.settings.aws_region)
        if account.mode == "demo":
            return DemoDataPlane(account.account_id, region)
        return LiveDataPlane(account, region, self.settings)

    def client_factory_for(self, account: Account, region: str | None = None):
        """Executors get a client factory only for live accounts.

        A demo account returns None, which makes any attempt to call AWS raise
        rather than silently succeed. Demo actions run in dry-run mode, where
        no AWS call is reached at all.
        """
        if account.mode == "demo":
            return None
        return self.data_plane(account, region).client_factory

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
            (f.resource_id, f.region, f.waste_type): f
            for f in self.repos.findings.list(account_id=account.account_id, limit=5000)
            if f.account_id == account.account_id
        }
        new_findings: list[Finding] = []
        for finding in result.findings:
            prior = previous.get((finding.resource_id, finding.region, finding.waste_type))
            if prior is not None:
                finding.finding_id = prior.finding_id
                finding.first_seen_at = prior.first_seen_at
                if prior.status.value in ("SUPPRESSED", "ACKNOWLEDGED"):
                    finding.status = prior.status
            else:
                new_findings.append(finding)
            self.repos.findings.put(finding)

        # Findings whose resource no longer appears, or which no longer fire,
        # are marked stale rather than deleted, so history survives. Only
        # findings from the region just scanned can be judged stale by it.
        current_keys = {(f.resource_id, f.region, f.waste_type) for f in result.findings}
        for key, prior in previous.items():
            if prior.region != plane.region:
                continue
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
                    "region": plane.region,
                    "resources_scanned": result.scan.resources_scanned,
                    "findings": len(result.findings),
                    "recommendations": len(recommendations),
                    "potential_monthly_savings": result.total_potential_savings,
                    "errors": result.scan.errors,
                },
            )
        )

        # Savings reconciliation piggybacks on the scan schedule: pending
        # actions are checked against billing once per scan, one Cost Explorer
        # call each, rather than on every page load.
        reconciled = self.reconcile_savings(account)

        self.notifications.after_scan(
            account,
            findings=result.findings,
            new_findings=new_findings,
            recommendations=recommendations,
            anomalies_finding_count=sum(
                1 for f in result.findings if f.waste_type.value == "cost_anomaly"
            ),
            monthly_spend=result.total_monthly_cost,
        )

        return {
            "scan": result.scan,
            "findings": result.findings,
            "recommendations": recommendations,
            "resources": result.resources,
            "reconciled_actions": reconciled,
        }

    def build_recommendations(
        self, account: Account, findings: list[Finding], plane=None
    ) -> list[Recommendation]:
        plane = plane or self.data_plane(account)
        try:
            optimizer = {
                rec.resource_id: rec for rec in plane.recommendations.list_recommendations()
            }
        except Exception as exc:  # noqa: BLE001
            logger.warning("AWS recommendations unavailable while building: %s", exc)
            optimizer = {}

        out: list[Recommendation] = []
        for finding in findings:
            resource = self.resource_for(finding)
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
    # Risk, policy and simulation -- read-only
    # ------------------------------------------------------------------

    def assess_risk(
        self, recommendation: Recommendation, resource: Resource
    ) -> risk_engine.RiskAssessment:
        """The risk of this action on this resource.

        The same inputs the simulator uses, so a recommendation's simulated
        risk and the risk its action is created with cannot drift apart.
        """
        return risk_engine.assess(
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
                has_recent_backup=has_recent_backup(resource),
                data_bearing=risk_engine.is_data_bearing(resource, recommendation.action_type),
            )
        )

    def preview_policy(
        self, recommendation: Recommendation, resource: Resource
    ) -> tuple[risk_engine.RiskAssessment, PolicyEvaluation]:
        """What policy would decide, without creating anything."""
        assessment = self.assess_risk(recommendation, resource)
        return assessment, self.policy.evaluate(recommendation, resource, assessment)

    def simulate(self, recommendation: Recommendation) -> SimulationResult:
        """Re-run a recommendation's simulation. Reads stored state only."""
        resource = self.resource_for(recommendation)
        if resource is None:
            raise LookupError(f"Resource {recommendation.resource_id} not found")
        finding = self.repos.findings.get(recommendation.finding_id)
        return impact_analyzer.resimulate(recommendation, resource, finding)

    # ------------------------------------------------------------------
    # Dependencies, explanation, what-if -- all read-only
    # ------------------------------------------------------------------

    def dependencies(self, resource: Resource, action_type=None) -> dict:
        """Advisory dependency analysis. Reads only; never feeds risk or policy."""
        from .intelligence import dependency_analyzer

        account = self.get_account(resource.account_id)
        related = {
            r.resource_id: r
            for r in self.repos.resources.list(account_id=resource.account_id, limit=5000)
            if r.account_id == resource.account_id and r.region == resource.region
        }
        facts = None
        error = None
        try:
            plane = self.data_plane(account, resource.region)
            describe = getattr(plane.inventory, "describe_dependencies", None)
            if describe is not None:
                facts = describe(resource)
        except Exception as exc:  # noqa: BLE001 - reported below, never read as "none"
            logger.warning("dependency lookup failed for %s: %s", resource.resource_id, exc)
            error = f"{type(exc).__name__}: {exc}"
        result = dependency_analyzer.analyze(resource, facts, related, action_type)
        if error:
            result["unknown_dependencies"].insert(
                0, {"category": "all", "reason": f"Dependency lookup failed ({error})"}
            )
            if result["dependency_status"] == "COMPLETE":
                result["dependency_status"] = "PARTIAL"
        return result

    def explain_finding(self, finding: Finding) -> dict:
        """The deterministic explanation of record for a finding."""
        from .intelligence import explanation

        resource = self.resource_for(finding)
        recommendations = [
            r
            for r in self.repos.recommendations.list(account_id=finding.account_id, limit=5000)
            if r.finding_id == finding.finding_id and r.account_id == finding.account_id
        ]
        assessments: dict[str, Any] = {}
        policies: dict[str, Any] = {}
        if resource is not None:
            for rec in recommendations:
                assessments[rec.recommendation_id], policies[rec.recommendation_id] = (
                    self.preview_policy(rec, resource)
                )
        dependencies = None
        risky = [
            r for r in recommendations
            if r.action_type.is_destructive or r.action_type.requires_restart
        ]
        if resource is not None and risky:
            dependencies = self.dependencies(resource, risky[-1].action_type)
        return explanation.build(
            finding, resource, recommendations, assessments, policies, dependencies
        )

    def what_if(self, recommendation: Recommendation) -> dict:
        """Current state against proposed state. Reads stored state only."""
        resource = self.resource_for(recommendation)
        if resource is None:
            raise LookupError(f"Resource {recommendation.resource_id} not found")
        finding = self.repos.findings.get(recommendation.finding_id)
        simulation = impact_analyzer.resimulate(recommendation, resource, finding)
        assessment, evaluation = self.preview_policy(recommendation, resource)
        dependencies = (
            self.dependencies(resource, recommendation.action_type)
            if recommendation.action_type.is_destructive
            or recommendation.action_type.requires_restart
            else None
        )
        utilization = (
            [
                e.model_dump(mode="json")
                for e in finding.evidence
                if e.source == "cloudwatch"
            ]
            if finding
            else []
        )
        stored = recommendation.simulation
        return {
            "recommendation_id": recommendation.recommendation_id,
            "account_id": recommendation.account_id,
            "resource_id": resource.resource_id,
            "action_type": recommendation.action_type.value,
            "mutates_aws": False,
            "current": {
                "configuration": recommendation.current_configuration,
                "monthly_cost": simulation.current_monthly_cost,
                "cost_source": simulation.priced_from,
                "cost_basis": "OBSERVED"
                if simulation.priced_from == "cost_explorer"
                else "ESTIMATED",
                "utilization": utilization,
                "environment": resource.environment.value,
                "state": resource.state,
            },
            "proposed": {
                "configuration": recommendation.recommended_configuration,
                "monthly_cost": simulation.projected_monthly_cost,
                "cost_basis": "ESTIMATED",
            },
            "savings": {
                "monthly": simulation.monthly_savings,
                "annual": simulation.annual_savings,
                "percent": simulation.savings_percent,
                "basis": "ESTIMATED",
                "matches_recommendation": stored is None
                or round(stored.monthly_savings, 2) == round(simulation.monthly_savings, 2),
            },
            "risk": {
                "level": assessment.level.value,
                "score": assessment.score,
                "factors": assessment.factors,
                "mitigations": assessment.mitigations,
                "floors_applied": assessment.floors_applied,
                "blocking_reasons": assessment.blocking_reasons,
            },
            "downtime_seconds": simulation.downtime_estimate_seconds,
            "restart_required": simulation.restart_required,
            "rollback": {
                "possible": simulation.rollback_possible,
                "method": simulation.rollback_method,
            },
            "performance_impact": simulation.performance_impact,
            "assumptions": simulation.assumptions,
            "policy": {
                "decision": evaluation.decision.value,
                "matched_rule": evaluation.matched_rule,
                "reasons": evaluation.reasons,
            },
            "dependencies": dependencies,
            "simulation": simulation,
        }

    # ------------------------------------------------------------------
    # Optimization history -- a view over existing records
    # ------------------------------------------------------------------

    def action_history(self, account: Account) -> list[dict]:
        actions = [
            a
            for a in self.repos.actions.list(account_id=account.account_id, limit=5000)
            if a.account_id == account.account_id
        ]
        audit_by_action: dict[str, list[AuditLog]] = {}
        for entry in self.repos.audit.list(account_id=account.account_id, limit=5000):
            if entry.account_id == account.account_id and entry.action_id:
                audit_by_action.setdefault(entry.action_id, []).append(entry)

        rows = []
        for action in sorted(actions, key=lambda a: a.created_at, reverse=True):
            entries = sorted(audit_by_action.get(action.action_id, []), key=lambda e: e.timestamp)
            rollback_status = "NOT_NEEDED"
            if action.execution_status is ExecutionStatus.ROLLED_BACK:
                rollback_status = "ROLLED_BACK"
            elif action.execution_status is ExecutionStatus.ROLLBACK_FAILED:
                rollback_status = "ROLLBACK_FAILED"
            elif action.can_rollback:
                rollback_status = "AVAILABLE"
            failed_checks = [v.check for v in action.verifications if not v.passed]
            verification_status = (
                "NOT_RUN"
                if not action.verifications
                else "FAILED"
                if failed_checks
                else "PASSED"
            )
            rows.append(
                {
                    "action_id": action.action_id,
                    "account_id": action.account_id,
                    "region": action.region,
                    "action_type": action.action_type.value,
                    "resource_id": action.resource_id,
                    "resource_type": action.resource_type.value,
                    "finding_id": action.finding_id,
                    "created_at": action.created_at.isoformat(),
                    "started_at": action.started_at.isoformat() if action.started_at else None,
                    "completed_at": action.completed_at.isoformat()
                    if action.completed_at
                    else None,
                    "requested_by": action.requested_by,
                    "agent_id": action.agent_id,
                    "approver": action.approved_by,
                    "approval_status": action.approval_status.value,
                    "policy_decision": action.policy_decision.value,
                    "policy_rule": action.policy_rule,
                    "risk": action.risk.value,
                    "dry_run": action.dry_run,
                    "execution_status": action.execution_status.value,
                    "verification_status": verification_status,
                    "failed_checks": failed_checks,
                    "rollback_status": rollback_status,
                    "rollback_method": action.checkpoint.rollback_method
                    if action.checkpoint
                    else None,
                    "estimated_monthly_savings": action.estimated_monthly_savings,
                    "verified_monthly_savings": action.verified_monthly_savings,
                    "savings_variance": action.savings_variance,
                    "savings_status": action.savings_status.value,
                    "savings_detail": action.savings_detail,
                    "error": action.error,
                    "timeline": [
                        {
                            "at": e.timestamp.isoformat(),
                            "event": e.event,
                            "actor": e.actor,
                            "outcome": e.outcome,
                        }
                        for e in entries
                    ],
                }
            )
        return rows

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
        if (resource.account_id, resource.resource_id) != (
            recommendation.account_id,
            recommendation.resource_id,
        ):
            raise AccountMismatchError(
                f"Recommendation {recommendation.recommendation_id} targets "
                f"{recommendation.account_id}/{recommendation.resource_id}, not "
                f"{resource.account_id}/{resource.resource_id}"
            )
        assessment, evaluation = self.preview_policy(recommendation, resource)

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
            estimated_monthly_savings=recommendation.monthly_savings,
            savings_status=SavingsStatus.ESTIMATED,
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
                    "estimated_monthly_savings": recommendation.monthly_savings,
                },
            )
        )
        if action.approval_status.value == "PENDING":
            self.notifications.approval_requested(action, recommendation)

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

    def _orchestrator(self, account: Account, region: str) -> RemediationOrchestrator:
        return RemediationOrchestrator(
            self.data_plane(account, region),
            client_factory=self.client_factory_for(account, region),
            settings=self.settings,
            approval_engine=self.approvals,
        )

    def execute_action(
        self, action: Action, account: Account | None = None, settle_seconds: int | None = None
    ):
        """Run an action through the remediation state machine.

        The data plane, the AWS clients, preflight and verification all come
        from the account that owns the action. `account` is accepted only as a
        cross-check: if it names a different account the call is refused.
        """
        owner = self.owning_account(action, account)
        resource = self.resource_for(action)
        if resource is None:
            raise LookupError(f"Resource {action.resource_id} is not in the inventory")
        recommendation = self.repos.recommendations.get(action.recommendation_id)

        if self.settings.use_step_functions:
            from .actions.step_functions import start_remediation

            return start_remediation(self, action, owner, self._step_functions_client)

        result = self._orchestrator(owner, action.region).run(
            action, resource, recommendation, settle_seconds=settle_seconds
        )
        self._persist_result(result)

        if result.succeeded and result.action.finding_id:
            finding = self.repos.findings.get(result.action.finding_id)
            if finding is not None and not result.action.dry_run:
                finding.status = finding.status.__class__("REMEDIATED")
                self.repos.findings.put(finding)

        self.notifications.after_execution(result.action)
        return result

    def rollback_action(
        self, action: Action, account: Account | None = None, operator: str | None = None
    ):
        owner = self.owning_account(action, account)
        resource = self.resource_for(action)
        if resource is None:
            raise LookupError(f"Resource {action.resource_id} is not in the inventory")
        result = self._orchestrator(owner, action.region).rollback_completed_action(
            action, resource
        )
        if operator:
            # The operator who asked for the rollback is recorded on the audit
            # entry; the action's own requester is history and stays as it was.
            for entry in result.audit:
                entry.actor = operator
                entry.detail["rollback_requested_by"] = operator
        self._persist_result(result)
        self.notifications.after_execution(result.action)
        return result

    def _persist_result(self, result) -> None:
        self.repos.actions.put(result.action)
        for entry in result.audit:
            self.repos.audit.put(entry)

    # ------------------------------------------------------------------
    # Savings reconciliation
    # ------------------------------------------------------------------

    def reconcile_savings(self, account: Account, now: datetime | None = None) -> list[Action]:
        """Check executed actions' savings against observed billing.

        Only actions that actually changed something and are still waiting on
        billing are examined, one resource-level Cost Explorer query each.
        """
        from .intelligence import savings_reconciliation as recon

        now = now or datetime.now(timezone.utc)
        changed: list[Action] = []
        pending = [
            a
            for a in self.repos.actions.list(account_id=account.account_id, limit=5000)
            if a.account_id == account.account_id
            and a.savings_status in recon.RECONCILABLE_STATES
            and a.execution_status is ExecutionStatus.COMPLETED
            and not a.dry_run
        ]
        if not pending:
            return changed

        policy = recon.ReconciliationPolicy.from_settings(self.settings)
        plane = None
        for action in pending:
            observed_after: float | None = None
            observed_before: float | None = None
            error: str | None = None
            window = recon.observation_window(action, now, policy)
            if window is not None:
                try:
                    plane = plane or self.data_plane(account, action.region)
                    observed_after = plane.cost.get_cost_by_resource(
                        action.resource_id, window[0], window[1]
                    )
                    before = recon.baseline_window(action)
                    if before is not None:
                        observed_before = plane.cost.get_cost_by_resource(
                            action.resource_id, before[0], before[1]
                        )
                except Exception as exc:  # noqa: BLE001
                    error = f"{type(exc).__name__}: {exc}"
                    logger.warning(
                        "savings reconciliation for %s failed: %s", action.action_id, error
                    )
            outcome = recon.reconcile(
                action,
                observed_after,
                now,
                observed_before=observed_before,
                error=error,
                policy=policy,
            )
            previous = action.savings_status
            recon.apply(action, outcome, now)
            self.repos.actions.put(action)
            if outcome.status is not previous:
                changed.append(action)
                self.repos.audit.put(
                    AuditLog(
                        action_id=action.action_id,
                        resource_id=action.resource_id,
                        account_id=action.account_id,
                        actor="system",
                        event="savings.reconciled",
                        outcome=outcome.status.value,
                        risk=action.risk,
                        detail=outcome.as_dict(),
                    )
                )
        return changed

    # ------------------------------------------------------------------
    # Forecasting
    # ------------------------------------------------------------------

    def cost_forecast(
        self, account: Account, history_days: int = 90, horizons: tuple[int, ...] = (7, 30, 90)
    ) -> dict:
        """Forecast from observed daily billing, beside AWS's own forecast."""
        from .intelligence import forecasting

        plane = self.data_plane(account)
        # Complete UTC days only: today's billing is partial and would drag
        # the last point down.
        end = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        start = end - timedelta(days=history_days)
        history_error = None
        try:
            points = plane.cost.get_cost_and_usage(start, end, "DAILY")
        except Exception as exc:  # noqa: BLE001
            logger.warning("daily cost unavailable for %s: %s", account.account_id, exc)
            points, history_error = [], f"{type(exc).__name__}"

        by_day: dict = {}
        for point in points:
            day = point.start.date()
            if point.start >= end:
                continue
            by_day[day] = by_day.get(day, 0.0) + point.amount
        history = [forecasting.DailyCost(day, amount) for day, amount in by_day.items()]
        result = forecasting.forecast(history, horizons=horizons)
        if history_error:
            result["status"] = "ERROR"
            result["notes"].insert(0, f"Billing history could not be read ({history_error}).")

        try:
            aws_forecast = plane.cost.get_forecast(30)
        except Exception as exc:  # noqa: BLE001
            logger.warning("AWS forecast unavailable for %s: %s", account.account_id, exc)
            aws_forecast = None

        open_findings = [
            f
            for f in self.repos.findings.list(account_id=account.account_id, limit=5000)
            if f.account_id == account.account_id and f.status.value == "OPEN"
        ]
        potential = round(sum(f.potential_monthly_savings for f in open_findings), 2)
        thirty = next((h for h in result["horizons"] if h["days"] == 30), None)
        pending = round(
            sum(
                a.estimated_monthly_savings or 0.0
                for a in self.repos.actions.list(account_id=account.account_id, limit=5000)
                if a.account_id == account.account_id
                and a.savings_status.value
                in ("EXECUTED_PENDING_BILLING", "VERIFICATION_PENDING")
            ),
            2,
        )
        scans = sorted(
            (
                s
                for s in self.repos.scans.list(account_id=account.account_id, limit=200)
                if s.account_id == account.account_id and s.status == "COMPLETED"
            ),
            key=lambda s: s.started_at,
        )
        result.update(
            {
                "account_id": account.account_id,
                "currency": "USD",
                "aws_forecast_30_days": aws_forecast,
                "aws_forecast_status": "AVAILABLE" if aws_forecast is not None else "UNAVAILABLE",
                "potential_monthly_savings": potential,
                "potential_savings_basis": "ESTIMATED",
                "forecast_30_days_if_all_open_recommendations_applied": (
                    round(max(0.0, thirty["forecast"] - potential), 2)
                    if thirty and thirty["forecast"] is not None
                    else None
                ),
                "pending_verification_monthly_savings": pending,
                "potential_savings_trend": [
                    {
                        "date": s.started_at.strftime("%Y-%m-%d %H:%M"),
                        "potential_monthly_savings": s.total_potential_savings,
                    }
                    for s in scans[-30:]
                ],
            }
        )
        return result

    # ------------------------------------------------------------------
    # Accounts overview
    # ------------------------------------------------------------------

    def accounts_summary(self) -> list[dict]:
        """One row per account, each computed only from that account's data."""
        rows = []
        for account in self.repos.accounts.list():
            resources = [
                r
                for r in self.repos.resources.list(account_id=account.account_id, limit=5000)
                if r.account_id == account.account_id
            ]
            findings = [
                f
                for f in self.repos.findings.list(account_id=account.account_id, limit=5000)
                if f.account_id == account.account_id and f.status.value == "OPEN"
            ]
            actions = [
                a
                for a in self.repos.actions.list(account_id=account.account_id, limit=5000)
                if a.account_id == account.account_id
            ]
            scans = [
                s
                for s in self.repos.scans.list(account_id=account.account_id, limit=50)
                if s.account_id == account.account_id
            ]
            last_scan = max(scans, key=lambda s: s.started_at) if scans else None
            priced = [r for r in resources if r.cost_known]
            rows.append(
                {
                    "account_id": account.account_id,
                    "name": account.name,
                    "mode": account.mode,
                    "environment": account.environment,
                    "owner": account.owner,
                    "regions": account.regions,
                    "enabled": account.enabled,
                    "role_configured": bool(account.role_arn),
                    "resource_count": len(resources),
                    "unpriced_resources": len(resources) - len(priced),
                    "monthly_spend": round(sum(r.monthly_cost for r in priced), 2)
                    if resources
                    else None,
                    "monthly_spend_basis": "ESTIMATED",
                    "potential_monthly_savings": round(
                        sum(f.potential_monthly_savings for f in findings), 2
                    )
                    if resources
                    else None,
                    "open_findings": len(findings),
                    "high_risk_findings": sum(1 for f in findings if f.risk.rank >= 2),
                    "pending_approvals": sum(
                        1 for a in actions if a.approval_status.value == "PENDING"
                    ),
                    "verified_monthly_savings": round(
                        sum(
                            a.verified_monthly_savings or 0.0
                            for a in actions
                            if a.savings_status.value in ("VERIFIED", "PARTIALLY_VERIFIED")
                        ),
                        2,
                    ),
                    "last_scan_at": last_scan.started_at.isoformat() if last_scan else None,
                    "scanned": last_scan is not None,
                }
            )
        return rows

    # ------------------------------------------------------------------
    # Dashboard aggregation
    # ------------------------------------------------------------------

    def dashboard(self, account: Account) -> dict:
        from .intelligence.dashboard import build_dashboard

        findings = [
            f
            for f in self.repos.findings.list(account_id=account.account_id, limit=5000)
            if f.account_id == account.account_id
        ]
        resources = [
            r
            for r in self.repos.resources.list(account_id=account.account_id, limit=5000)
            if r.account_id == account.account_id
        ]
        actions = [
            a
            for a in self.repos.actions.list(account_id=account.account_id, limit=5000)
            if a.account_id == account.account_id
        ]
        scans = [
            s
            for s in self.repos.scans.list(account_id=account.account_id, limit=200)
            if s.account_id == account.account_id
        ]

        plane = self.data_plane(account)
        end = datetime.now(timezone.utc)
        cost_signals: dict[str, Any] = {}
        try:
            cost_signals["aws_forecast_30d"] = plane.cost.get_forecast(30)
            cost_signals["forecast_error"] = None
        except Exception as exc:  # noqa: BLE001
            logger.warning("forecast unavailable for %s: %s", account.account_id, exc)
            cost_signals["aws_forecast_30d"] = None
            cost_signals["forecast_error"] = f"{type(exc).__name__}"
        try:
            cost_signals["cost_by_service"] = plane.cost.cost_by_service(
                end - timedelta(days=30), end
            )
            cost_signals["cost_error"] = None
        except Exception as exc:  # noqa: BLE001
            logger.warning("cost by service unavailable for %s: %s", account.account_id, exc)
            cost_signals["cost_by_service"] = None
            cost_signals["cost_error"] = f"{type(exc).__name__}"

        return build_dashboard(
            account,
            findings=findings,
            resources=resources,
            actions=actions,
            scans=scans,
            settings=self.settings,
            **cost_signals,
        )


# --------------------------------------------------------------------------


def build_repositories(settings: Settings):
    """The configured storage backend. No silent fallback between backends."""
    if settings.storage_backend == "dynamodb":
        from .repositories.dynamodb import DynamoRepositories

        repos = DynamoRepositories(settings)
        repos.verify_tables()
        return repos
    from .repositories.memory import MemoryRepositories

    return MemoryRepositories()


@lru_cache
def get_service() -> CloudWasteService:
    settings = get_settings()
    repos = build_repositories(settings)

    if settings.seed_demo_account and not repos.accounts.list():
        repos.accounts.put(
            Account(
                account_id=DEMO_ACCOUNT_ID,
                name="Demo account (synthetic)",
                regions=[DEMO_REGION],
                mode="demo",
                environment="demo",
            )
        )
    return CloudWasteService(repos, settings)
