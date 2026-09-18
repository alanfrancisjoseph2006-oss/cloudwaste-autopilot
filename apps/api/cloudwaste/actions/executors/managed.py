"""RDS, Lambda and Elastic IP executors.

RDS is the highest-consequence executor here, and the one where AWS's own
behaviour is most likely to surprise: a resize on a Multi-AZ instance performs
a failover rather than a restart, `ApplyImmediately=False` silently defers the
change to the next maintenance window, and the instance passes through
`modifying` and `rebooting` before returning to `available`. Each of those is
handled explicitly, because each one otherwise produces a "successful" action
that did not actually happen.

Elastic IP release has no rollback and the executor says so rather than
pretending. AWS does not guarantee a released address can be re-allocated.
"""

from __future__ import annotations

import logging
import time

from botocore.exceptions import ClientError

from ...models.domain import Checkpoint, VerificationResult
from ...models.enums import ActionType
from .base import (
    ExecutionContext,
    ExecutionFailure,
    ExecutionOutcome,
    Executor,
    PreflightFailure,
)

logger = logging.getLogger(__name__)

RDS_POLL_SECONDS = 15
RDS_POLL_ATTEMPTS = 80  # up to 20 minutes


class ResizeRdsExecutor(Executor):
    action_type = ActionType.RESIZE_RDS
    rollback_description = "restore_previous_instance_class"

    def describe(self, context: ExecutionContext) -> str:
        target = context.action.parameters.get("target_instance_class")
        return (
            f"resize database {context.resource.resource_id} from "
            f"{context.resource.configuration.get('instance_class')} to {target}"
        )

    def _describe_db(self, context: ExecutionContext) -> dict:
        rds = context.client("rds")
        try:
            response = rds.describe_db_instances(
                DBInstanceIdentifier=context.resource.resource_id
            )
        except ClientError as exc:
            raise PreflightFailure(
                f"Cannot read database {context.resource.resource_id}: {exc}"
            ) from exc
        instances = response.get("DBInstances", [])
        if not instances:
            raise PreflightFailure(f"Database {context.resource.resource_id} not found")
        return instances[0]

    def capture(self, context: ExecutionContext) -> Checkpoint:
        config = context.resource.configuration
        return Checkpoint(
            resource_state={
                "instance_class": config.get("instance_class"),
                "multi_az": config.get("multi_az"),
                "allocated_storage_gb": config.get("allocated_storage_gb"),
                "engine": config.get("engine"),
                "engine_version": config.get("engine_version"),
            },
            rollback_method=self.rollback_description,
            rollback_data={
                "db_identifier": context.resource.resource_id,
                "original_instance_class": config.get("instance_class"),
            },
            rollback_timeout_seconds=1800,
        )

    def preflight(self, context: ExecutionContext) -> None:
        target = context.action.parameters.get("target_instance_class")
        if not target:
            raise PreflightFailure("No target_instance_class given")

        db = self._describe_db(context)
        status = db["DBInstanceStatus"]
        if status != "available":
            raise PreflightFailure(
                f"Database is '{status}', not 'available'. A resize can only be "
                f"applied to an available instance."
            )
        current = db["DBInstanceClass"]
        if current == target:
            raise PreflightFailure(f"Database is already {target}")
        if current != context.resource.configuration.get("instance_class"):
            raise PreflightFailure(
                f"Instance class changed since this action was planned "
                f"(expected {context.resource.configuration.get('instance_class')}, "
                f"found {current}). Re-scan before acting."
            )
        if db.get("PendingModifiedValues"):
            raise PreflightFailure(
                f"Database already has pending modifications "
                f"({db['PendingModifiedValues']}), which would be applied "
                f"alongside this change. Refusing."
            )

        # A resize is not safe without a recovery path.
        if (db.get("BackupRetentionPeriod") or 0) == 0:
            raise PreflightFailure(
                "Automated backups are disabled on this database (retention 0), "
                "so there is no restore point if the resize goes wrong. Refusing."
            )

        rds = context.client("rds")
        try:
            options = rds.describe_orderable_db_instance_options(
                Engine=db["Engine"],
                EngineVersion=db["EngineVersion"],
                DBInstanceClass=target,
            ).get("OrderableDBInstanceOptions", [])
            if not options:
                raise PreflightFailure(
                    f"{target} does not support {db['Engine']} "
                    f"{db['EngineVersion']} in this region."
                )
            if db.get("MultiAZ") and not any(o.get("MultiAZCapable") for o in options):
                raise PreflightFailure(
                    f"{target} does not support Multi-AZ, which this database uses."
                )
        except ClientError as exc:
            raise PreflightFailure(f"Cannot validate target class: {exc}") from exc

    def _apply(self, context: ExecutionContext) -> ExecutionOutcome:
        rds = context.client("rds")
        identifier = context.resource.resource_id
        target = context.action.parameters["target_instance_class"]
        multi_az = context.resource.configuration.get("multi_az", False)

        try:
            rds.modify_db_instance(
                DBInstanceIdentifier=identifier,
                DBInstanceClass=target,
                # Without this the change is deferred to the next maintenance
                # window and the action would report success having changed
                # nothing today.
                ApplyImmediately=True,
            )
        except ClientError as exc:
            raise ExecutionFailure(f"modify_db_instance failed: {exc}") from exc

        status = self._wait_for_available(context)
        return ExecutionOutcome(
            succeeded=True,
            detail=(
                f"Database {identifier} resized to {target} and returned to "
                f"'{status}'"
                + (
                    " via a Multi-AZ failover"
                    if multi_az
                    else " after a restart"
                )
            ),
            artifacts={"new_instance_class": target},
        )

    def _wait_for_available(self, context: ExecutionContext) -> str:
        """Wait through modifying/rebooting back to available.

        A naive wait returns immediately because the instance is still
        'available' for a moment after the API call is accepted, so this waits
        for it to leave 'available' first.
        """
        rds = context.client("rds")
        identifier = context.resource.resource_id
        saw_transition = False

        for _ in range(RDS_POLL_ATTEMPTS):
            db = rds.describe_db_instances(DBInstanceIdentifier=identifier)["DBInstances"][0]
            status = db["DBInstanceStatus"]
            if status in ("modifying", "rebooting", "storage-optimization", "upgrading"):
                saw_transition = True
            elif status == "available" and saw_transition:
                return status
            elif status in ("failed", "incompatible-parameters", "inaccessible-encryption-credentials"):
                raise ExecutionFailure(f"Database entered state '{status}'")
            time.sleep(RDS_POLL_SECONDS)

        raise ExecutionFailure(
            f"Database {identifier} did not return to 'available' within "
            f"{RDS_POLL_SECONDS * RDS_POLL_ATTEMPTS} seconds"
        )

    def verify(self, context: ExecutionContext) -> list[VerificationResult]:
        if context.dry_run:
            return [self.passed("instance_class", "DRY RUN: class not changed")]

        db = self._describe_db(context)
        target = context.action.parameters["target_instance_class"]
        results = []

        results.append(
            self.passed("instance_class", f"Database is now {db['DBInstanceClass']}")
            if db["DBInstanceClass"] == target
            else self.failed(
                "instance_class",
                f"Database is {db['DBInstanceClass']}, expected {target}",
            )
        )
        results.append(
            self.passed("db_status", f"Database status is '{db['DBInstanceStatus']}'")
            if db["DBInstanceStatus"] == "available"
            else self.failed("db_status", f"Database status is '{db['DBInstanceStatus']}'")
        )
        if db.get("PendingModifiedValues"):
            results.append(
                self.failed(
                    "pending_changes",
                    f"Database still has pending modifications: "
                    f"{db['PendingModifiedValues']}",
                )
            )
        return results

    def rollback(self, context: ExecutionContext, checkpoint: Checkpoint) -> ExecutionOutcome:
        if context.dry_run:
            return ExecutionOutcome(
                True, "DRY RUN: would restore the previous instance class", dry_run=True
            )
        rds = context.client("rds")
        original = checkpoint.rollback_data["original_instance_class"]
        rds.modify_db_instance(
            DBInstanceIdentifier=checkpoint.rollback_data["db_identifier"],
            DBInstanceClass=original,
            ApplyImmediately=True,
        )
        status = self._wait_for_available(context)
        return ExecutionOutcome(
            True,
            f"Database restored to {original} and is '{status}'. Note this is a "
            f"second restart or failover on top of the first.",
        )


class ModifyLambdaMemoryExecutor(Executor):
    action_type = ActionType.MODIFY_LAMBDA_MEMORY
    rollback_description = "restore_previous_memory_size"

    def describe(self, context: ExecutionContext) -> str:
        target = context.action.parameters.get("target_memory_mb")
        return (
            f"set {context.resource.resource_id} memory from "
            f"{context.resource.configuration.get('memory_mb')} MB to {target} MB"
        )

    def _get_config(self, context: ExecutionContext) -> dict:
        lam = context.client("lambda")
        try:
            return lam.get_function_configuration(
                FunctionName=context.resource.resource_id
            )
        except ClientError as exc:
            raise PreflightFailure(
                f"Cannot read function {context.resource.resource_id}: {exc}"
            ) from exc

    def capture(self, context: ExecutionContext) -> Checkpoint:
        config = context.resource.configuration
        return Checkpoint(
            resource_state={
                "memory_mb": config.get("memory_mb"),
                "timeout_seconds": config.get("timeout_seconds"),
                "runtime": config.get("runtime"),
            },
            rollback_method=self.rollback_description,
            rollback_data={
                "function_name": context.resource.resource_id,
                "original_memory_mb": config.get("memory_mb"),
            },
        )

    def preflight(self, context: ExecutionContext) -> None:
        target = context.action.parameters.get("target_memory_mb")
        if not target:
            raise PreflightFailure("No target_memory_mb given")
        if not (128 <= int(target) <= 10240):
            raise PreflightFailure(f"Memory {target} MB is outside the 128-10240 MB range")

        config = self._get_config(context)
        if config["MemorySize"] == int(target):
            raise PreflightFailure(f"Function is already configured at {target} MB")
        if config["MemorySize"] != context.resource.configuration.get("memory_mb"):
            raise PreflightFailure(
                f"Memory changed since this action was planned (expected "
                f"{context.resource.configuration.get('memory_mb')}, found "
                f"{config['MemorySize']}). Re-scan before acting."
            )
        if config.get("State") not in (None, "Active"):
            raise PreflightFailure(f"Function is in state '{config.get('State')}'")

        # A function already near its timeout will start failing when it slows
        # down, which is the way this action causes an incident.
        peak_duration = context.action.parameters.get("projected_duration_ms")
        timeout_ms = config.get("Timeout", 3) * 1000
        if peak_duration and peak_duration > timeout_ms * 0.7:
            raise PreflightFailure(
                f"Projected duration at {target} MB is {peak_duration:,.0f} ms "
                f"against a {timeout_ms:,.0f} ms timeout. Reducing memory would "
                f"leave too little headroom and risk timeouts. Refusing."
            )

    def _apply(self, context: ExecutionContext) -> ExecutionOutcome:
        lam = context.client("lambda")
        target = int(context.action.parameters["target_memory_mb"])
        try:
            lam.update_function_configuration(
                FunctionName=context.resource.resource_id, MemorySize=target
            )
            waiter = lam.get_waiter("function_updated_v2")
            waiter.wait(FunctionName=context.resource.resource_id)
        except ClientError as exc:
            raise ExecutionFailure(f"update_function_configuration failed: {exc}") from exc

        return ExecutionOutcome(
            succeeded=True,
            detail=(
                f"Function {context.resource.resource_id} is now configured at "
                f"{target} MB. The change applies to invocations from now on; "
                f"in-flight invocations finish at the old size."
            ),
            artifacts={"new_memory_mb": str(target)},
        )

    def verify(self, context: ExecutionContext) -> list[VerificationResult]:
        if context.dry_run:
            return [self.passed("memory_size", "DRY RUN: memory not changed")]
        config = self._get_config(context)
        target = int(context.action.parameters["target_memory_mb"])
        results = [
            self.passed("memory_size", f"Function is configured at {config['MemorySize']} MB")
            if config["MemorySize"] == target
            else self.failed(
                "memory_size", f"Function is {config['MemorySize']} MB, expected {target}"
            ),
            self.passed("function_state", f"Function state is '{config.get('State')}'")
            if config.get("State") in (None, "Active")
            else self.failed("function_state", f"Function state is '{config.get('State')}'"),
        ]
        results.append(
            self.passed(
                "error_rate_watch",
                "Error rate and duration are re-checked by the verification stage "
                "after the settle period, since the effect only appears once "
                "invocations run at the new size.",
            )
        )
        return results

    def rollback(self, context: ExecutionContext, checkpoint: Checkpoint) -> ExecutionOutcome:
        if context.dry_run:
            return ExecutionOutcome(True, "DRY RUN: would restore memory", dry_run=True)
        lam = context.client("lambda")
        original = int(checkpoint.rollback_data["original_memory_mb"])
        lam.update_function_configuration(
            FunctionName=checkpoint.rollback_data["function_name"], MemorySize=original
        )
        lam.get_waiter("function_updated_v2").wait(
            FunctionName=checkpoint.rollback_data["function_name"]
        )
        return ExecutionOutcome(True, f"Function memory restored to {original} MB")


class ReleaseElasticIpExecutor(Executor):
    action_type = ActionType.RELEASE_ELASTIC_IP
    rollback_description = "none"

    def describe(self, context: ExecutionContext) -> str:
        return (
            f"permanently release Elastic IP "
            f"{context.resource.configuration.get('public_ip')} "
            f"({context.resource.resource_id})"
        )

    def capture(self, context: ExecutionContext) -> Checkpoint:
        config = context.resource.configuration
        return Checkpoint(
            resource_state={
                "public_ip": config.get("public_ip"),
                "allocation_id": context.resource.resource_id,
                "tags": dict(context.resource.tags),
            },
            rollback_method="none",
            rollback_data={
                "note": (
                    "Releasing a public IPv4 address is irreversible. AWS does "
                    "not guarantee the same address can be allocated again, so "
                    "there is no rollback. The address and its tags are recorded "
                    "here only for the audit trail."
                )
            },
        )

    def preflight(self, context: ExecutionContext) -> None:
        ec2 = context.client("ec2")
        try:
            addresses = ec2.describe_addresses(
                AllocationIds=[context.resource.resource_id]
            ).get("Addresses", [])
        except ClientError as exc:
            raise PreflightFailure(f"Cannot read address: {exc}") from exc
        if not addresses:
            raise PreflightFailure("Address no longer exists")
        address = addresses[0]
        if address.get("AssociationId"):
            raise PreflightFailure(
                f"Address is now associated with "
                f"{address.get('InstanceId') or address.get('NetworkInterfaceId')}. "
                f"It is in use. Refusing to release."
            )

    def _apply(self, context: ExecutionContext) -> ExecutionOutcome:
        ec2 = context.client("ec2")
        try:
            ec2.release_address(AllocationId=context.resource.resource_id)
        except ClientError as exc:
            raise ExecutionFailure(f"release_address failed: {exc}") from exc
        return ExecutionOutcome(
            succeeded=True,
            detail=(
                f"Elastic IP {context.resource.configuration.get('public_ip')} "
                f"released. This cannot be undone."
            ),
        )

    def verify(self, context: ExecutionContext) -> list[VerificationResult]:
        if context.dry_run:
            return [self.passed("address_released", "DRY RUN: address not released")]
        ec2 = context.client("ec2")
        try:
            addresses = ec2.describe_addresses(
                AllocationIds=[context.resource.resource_id]
            ).get("Addresses", [])
        except ClientError as exc:
            if "InvalidAllocationID.NotFound" in str(exc):
                return [self.passed("address_released", "Address no longer exists")]
            return [self.failed("address_released", f"Could not confirm release: {exc}")]
        return (
            [self.failed("address_released", "Address still exists")]
            if addresses
            else [self.passed("address_released", "Address no longer exists")]
        )

    def rollback(self, context: ExecutionContext, checkpoint: Checkpoint) -> ExecutionOutcome:
        return ExecutionOutcome(
            succeeded=False,
            detail=(
                "Releasing an Elastic IP cannot be rolled back. AWS does not "
                "guarantee the same address can be allocated again. A new address "
                "can be allocated, but it will be a different IP and any external "
                "allow-list, DNS record or partner integration pinned to "
                f"{checkpoint.resource_state.get('public_ip')} must be updated."
            ),
        )
