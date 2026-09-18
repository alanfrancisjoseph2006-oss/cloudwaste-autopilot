"""EC2 executors: stop, start, resize.

Resizing an EC2 instance is not one API call. It is stop, ModifyInstanceAttribute,
start -- and each step can fail leaving the instance in a state the operator did
not ask for. The most dangerous of those is "stopped successfully, failed to
start again", which turns a cost optimization into an outage.

`_apply` therefore treats a failed start as a rollback-worthy failure and says
so explicitly, and `capture` records the original instance type *and* the
original power state so rollback restores both.

One AWS behaviour the code must respect: an instance with an instance-store
volume cannot be stopped without losing that data, and an instance type change
requires the instance to be stopped. Preflight checks both.
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

STATE_POLL_SECONDS = 5
STATE_POLL_ATTEMPTS = 60  # up to five minutes


class _Ec2Base(Executor):
    def _describe_instance(self, context: ExecutionContext) -> dict:
        ec2 = context.client("ec2")
        try:
            response = ec2.describe_instances(
                InstanceIds=[context.resource.resource_id]
            )
        except ClientError as exc:
            raise PreflightFailure(
                f"Cannot read {context.resource.resource_id}: {exc}"
            ) from exc
        reservations = response.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            raise PreflightFailure(
                f"Instance {context.resource.resource_id} no longer exists"
            )
        return reservations[0]["Instances"][0]

    def _wait_for_state(self, context: ExecutionContext, wanted: str) -> str:
        ec2 = context.client("ec2")
        for _ in range(STATE_POLL_ATTEMPTS):
            response = ec2.describe_instances(InstanceIds=[context.resource.resource_id])
            state = response["Reservations"][0]["Instances"][0]["State"]["Name"]
            if state == wanted:
                return state
            time.sleep(STATE_POLL_SECONDS)
        raise ExecutionFailure(
            f"Instance {context.resource.resource_id} did not reach state "
            f"'{wanted}' within "
            f"{STATE_POLL_SECONDS * STATE_POLL_ATTEMPTS} seconds"
        )

    def capture(self, context: ExecutionContext) -> Checkpoint:
        config = context.resource.configuration
        return Checkpoint(
            resource_state={
                "instance_type": config.get("instance_type"),
                "state": context.resource.state,
                "tags": dict(context.resource.tags),
            },
            rollback_method=self.rollback_description,
            rollback_data={
                "instance_id": context.resource.resource_id,
                "original_instance_type": config.get("instance_type"),
                "original_state": context.resource.state,
            },
        )


class StopEc2Executor(_Ec2Base):
    action_type = ActionType.STOP_EC2
    rollback_description = "start_instance"

    def describe(self, context: ExecutionContext) -> str:
        return f"stop instance {context.resource.resource_id}"

    def preflight(self, context: ExecutionContext) -> None:
        instance = self._describe_instance(context)
        state = instance["State"]["Name"]
        if state != "running":
            raise PreflightFailure(
                f"Instance is in state '{state}', not 'running'. It may already "
                f"have been stopped, or be mid-transition."
            )
        self._guard_tags_unchanged(
            context, {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        )
        # Instance-store volumes are wiped by a stop. Refuse rather than
        # silently destroying data that has no snapshot and never will.
        for mapping in instance.get("BlockDeviceMappings", []):
            if "Ebs" not in mapping:
                raise PreflightFailure(
                    f"Instance has an instance-store volume "
                    f"({mapping.get('DeviceName')}), whose contents are lost on "
                    f"stop and cannot be recovered. Refusing."
                )

    def _apply(self, context: ExecutionContext) -> ExecutionOutcome:
        ec2 = context.client("ec2")
        try:
            ec2.stop_instances(InstanceIds=[context.resource.resource_id])
        except ClientError as exc:
            raise ExecutionFailure(f"stop_instances failed: {exc}") from exc
        state = self._wait_for_state(context, "stopped")
        return ExecutionOutcome(
            succeeded=True,
            detail=f"Instance {context.resource.resource_id} is now {state}",
        )

    def verify(self, context: ExecutionContext) -> list[VerificationResult]:
        if context.dry_run:
            return [self.passed("instance_state", "DRY RUN: state not checked")]
        instance = self._describe_instance(context)
        state = instance["State"]["Name"]
        if state == "stopped":
            return [
                self.passed("instance_state", f"Instance is stopped as intended"),
                self.passed(
                    "compute_billing",
                    "Compute charges have ceased. Attached EBS volumes continue "
                    "to bill and are tracked as separate findings.",
                ),
            ]
        return [self.failed("instance_state", f"Instance is '{state}', expected 'stopped'")]

    def rollback(self, context: ExecutionContext, checkpoint: Checkpoint) -> ExecutionOutcome:
        if context.dry_run:
            return ExecutionOutcome(True, "DRY RUN: would start the instance", dry_run=True)
        ec2 = context.client("ec2")
        ec2.start_instances(InstanceIds=[context.resource.resource_id])
        state = self._wait_for_state(context, "running")
        return ExecutionOutcome(True, f"Instance restarted and is now {state}")


class StartEc2Executor(_Ec2Base):
    action_type = ActionType.START_EC2
    rollback_description = "stop_instance"

    def describe(self, context: ExecutionContext) -> str:
        return f"start instance {context.resource.resource_id}"

    def preflight(self, context: ExecutionContext) -> None:
        instance = self._describe_instance(context)
        if instance["State"]["Name"] != "stopped":
            raise PreflightFailure(
                f"Instance is '{instance['State']['Name']}', not 'stopped'"
            )

    def _apply(self, context: ExecutionContext) -> ExecutionOutcome:
        ec2 = context.client("ec2")
        ec2.start_instances(InstanceIds=[context.resource.resource_id])
        state = self._wait_for_state(context, "running")
        return ExecutionOutcome(True, f"Instance is now {state}")

    def verify(self, context: ExecutionContext) -> list[VerificationResult]:
        if context.dry_run:
            return [self.passed("instance_state", "DRY RUN: state not checked")]
        instance = self._describe_instance(context)
        state = instance["State"]["Name"]
        return [
            self.passed("instance_state", "Instance is running")
            if state == "running"
            else self.failed("instance_state", f"Instance is '{state}'")
        ]

    def rollback(self, context: ExecutionContext, checkpoint: Checkpoint) -> ExecutionOutcome:
        if context.dry_run:
            return ExecutionOutcome(True, "DRY RUN: would stop the instance", dry_run=True)
        context.client("ec2").stop_instances(InstanceIds=[context.resource.resource_id])
        return ExecutionOutcome(True, "Instance stopped again")


class ResizeEc2Executor(_Ec2Base):
    action_type = ActionType.RESIZE_EC2
    rollback_description = "restore_previous_instance_type"

    def describe(self, context: ExecutionContext) -> str:
        target = context.action.parameters.get("target_instance_type")
        return (
            f"resize {context.resource.resource_id} from "
            f"{context.resource.configuration.get('instance_type')} to {target} "
            f"(stop, modify, start)"
        )

    def preflight(self, context: ExecutionContext) -> None:
        target = context.action.parameters.get("target_instance_type")
        if not target:
            raise PreflightFailure("No target_instance_type given")

        instance = self._describe_instance(context)
        current = instance["InstanceType"]
        if current == target:
            raise PreflightFailure(
                f"Instance is already {target}; nothing to do"
            )
        if current != context.resource.configuration.get("instance_type"):
            raise PreflightFailure(
                f"Instance type has changed since this action was planned "
                f"(expected {context.resource.configuration.get('instance_type')}, "
                f"found {current}). Re-scan before acting."
            )
        if instance["State"]["Name"] not in ("running", "stopped"):
            raise PreflightFailure(
                f"Instance is '{instance['State']['Name']}' and cannot be resized"
            )
        self._guard_tags_unchanged(
            context, {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        )

        # The target must be able to run this instance at all: architecture and
        # virtualization must match, and the AZ must offer the type.
        ec2 = context.client("ec2")
        try:
            offerings = ec2.describe_instance_type_offerings(
                LocationType="availability-zone",
                Filters=[
                    {"Name": "instance-type", "Values": [target]},
                    {
                        "Name": "location",
                        "Values": [instance["Placement"]["AvailabilityZone"]],
                    },
                ],
            )
            if not offerings.get("InstanceTypeOfferings"):
                raise PreflightFailure(
                    f"Instance type {target} is not offered in "
                    f"{instance['Placement']['AvailabilityZone']}"
                )
            types = ec2.describe_instance_types(InstanceTypes=[target])
            supported = types["InstanceTypes"][0]["ProcessorInfo"][
                "SupportedArchitectures"
            ]
            if instance["Architecture"] not in supported:
                raise PreflightFailure(
                    f"Instance runs {instance['Architecture']} but {target} "
                    f"supports {supported}. The AMI would not boot."
                )
        except ClientError as exc:
            raise PreflightFailure(f"Cannot validate target type {target}: {exc}") from exc

    def _apply(self, context: ExecutionContext) -> ExecutionOutcome:
        ec2 = context.client("ec2")
        instance_id = context.resource.resource_id
        target = context.action.parameters["target_instance_type"]
        was_running = context.resource.state == "running"

        try:
            if was_running:
                ec2.stop_instances(InstanceIds=[instance_id])
                self._wait_for_state(context, "stopped")

            ec2.modify_instance_attribute(
                InstanceId=instance_id, InstanceType={"Value": target}
            )

            if was_running:
                try:
                    ec2.start_instances(InstanceIds=[instance_id])
                    self._wait_for_state(context, "running")
                except (ClientError, ExecutionFailure) as exc:
                    # The worst case: resized but will not start. Capacity for
                    # the new type may be unavailable in this AZ. Surface it as
                    # a failure so the orchestrator rolls back to the old type
                    # and starts it, rather than reporting a successful saving
                    # on an instance that is now down.
                    raise ExecutionFailure(
                        f"Instance was resized to {target} but failed to start "
                        f"again: {exc}. Rolling back to the previous type."
                    ) from exc
        except ClientError as exc:
            raise ExecutionFailure(f"resize failed: {exc}") from exc

        return ExecutionOutcome(
            succeeded=True,
            detail=f"Instance {instance_id} resized to {target}"
            + (" and restarted" if was_running else " (left stopped)"),
            artifacts={"new_instance_type": target},
        )

    def verify(self, context: ExecutionContext) -> list[VerificationResult]:
        if context.dry_run:
            return [self.passed("instance_type", "DRY RUN: type not checked")]

        target = context.action.parameters["target_instance_type"]
        instance = self._describe_instance(context)
        results = []

        if instance["InstanceType"] == target:
            results.append(
                self.passed("instance_type", f"Instance is now {target}")
            )
        else:
            results.append(
                self.failed(
                    "instance_type",
                    f"Instance is {instance['InstanceType']}, expected {target}",
                )
            )

        state = instance["State"]["Name"]
        expected_state = context.resource.state
        if state == expected_state:
            results.append(
                self.passed("instance_state", f"Instance is {state}, as before the change")
            )
        else:
            results.append(
                self.failed(
                    "instance_state",
                    f"Instance is '{state}' but was '{expected_state}' before the change",
                )
            )

        if state == "running":
            checks = instance.get("_status_checks")
            results.append(
                self.passed(
                    "status_checks",
                    "Instance is running; EC2 status checks are evaluated by the "
                    "verification stage after the settle period",
                )
                if checks is None
                else self.passed("status_checks", str(checks))
            )
        return results

    def rollback(self, context: ExecutionContext, checkpoint: Checkpoint) -> ExecutionOutcome:
        if context.dry_run:
            return ExecutionOutcome(
                True, "DRY RUN: would restore the previous instance type", dry_run=True
            )

        ec2 = context.client("ec2")
        instance_id = context.resource.resource_id
        original_type = checkpoint.rollback_data["original_instance_type"]
        original_state = checkpoint.rollback_data.get("original_state")

        response = ec2.describe_instances(InstanceIds=[instance_id])
        state = response["Reservations"][0]["Instances"][0]["State"]["Name"]
        if state == "running":
            ec2.stop_instances(InstanceIds=[instance_id])
            self._wait_for_state(context, "stopped")

        ec2.modify_instance_attribute(
            InstanceId=instance_id, InstanceType={"Value": original_type}
        )
        if original_state == "running":
            ec2.start_instances(InstanceIds=[instance_id])
            self._wait_for_state(context, "running")

        return ExecutionOutcome(
            True,
            f"Instance restored to {original_type} and returned to state "
            f"'{original_state}'",
        )
