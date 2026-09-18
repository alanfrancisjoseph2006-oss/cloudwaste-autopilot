"""EBS and S3 executors.

`DeleteEbsExecutor` is the most dangerous code in this repository, so it is
also the most defensive. It refuses to run unless it can prove, against live
AWS at the moment of execution, that:

  * the volume is still unattached,
  * a completed snapshot exists,
  * that snapshot is of *this* volume and covers its current size.

The third check exists because a snapshot taken before the volume was resized
does not restore the whole volume, and "we had a snapshot" is not the same as
"we can get the data back".

Deletion is irreversible, so `rollback` does not claim otherwise: it restores
from the snapshot into a *new* volume with a new id, tells the caller the id,
and states plainly that attachments and references must be recreated by hand.
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


class _EbsBase(Executor):
    def _describe_volume(self, context: ExecutionContext) -> dict:
        ec2 = context.client("ec2")
        try:
            response = ec2.describe_volumes(VolumeIds=[context.resource.resource_id])
        except ClientError as exc:
            raise PreflightFailure(
                f"Cannot read volume {context.resource.resource_id}: {exc}"
            ) from exc
        volumes = response.get("Volumes", [])
        if not volumes:
            raise PreflightFailure(f"Volume {context.resource.resource_id} no longer exists")
        return volumes[0]

    def capture(self, context: ExecutionContext) -> Checkpoint:
        config = context.resource.configuration
        return Checkpoint(
            resource_state={
                "volume_type": config.get("volume_type"),
                "size_gb": config.get("size_gb"),
                "iops": config.get("iops"),
                "throughput": config.get("throughput"),
                "state": context.resource.state,
                "attached_to": config.get("attached_to"),
                "tags": dict(context.resource.tags),
            },
            rollback_method=self.rollback_description,
            rollback_data={
                "volume_id": context.resource.resource_id,
                "original_volume_type": config.get("volume_type"),
                "original_iops": config.get("iops"),
                "original_throughput": config.get("throughput"),
                "availability_zone": config.get("availability_zone"),
            },
        )


class CreateEbsSnapshotExecutor(_EbsBase):
    action_type = ActionType.CREATE_EBS_SNAPSHOT
    rollback_description = "delete_snapshot"

    def describe(self, context: ExecutionContext) -> str:
        return f"create a snapshot of volume {context.resource.resource_id}"

    def preflight(self, context: ExecutionContext) -> None:
        volume = self._describe_volume(context)
        if volume["State"] not in ("available", "in-use"):
            raise PreflightFailure(f"Volume is '{volume['State']}' and cannot be snapshotted")

    def _apply(self, context: ExecutionContext) -> ExecutionOutcome:
        ec2 = context.client("ec2")
        volume_id = context.resource.resource_id
        description = context.action.parameters.get(
            "description", f"CloudWaste pre-deletion snapshot of {volume_id}"
        )
        try:
            snapshot = ec2.create_snapshot(
                VolumeId=volume_id,
                Description=description,
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "CreatedBy", "Value": "cloudwaste-autopilot"},
                            {"Key": "SourceVolume", "Value": volume_id},
                            {"Key": "ActionId", "Value": context.action.action_id},
                        ],
                    }
                ],
            )
        except ClientError as exc:
            raise ExecutionFailure(f"create_snapshot failed: {exc}") from exc

        snapshot_id = snapshot["SnapshotId"]
        # Wait for completion: an incomplete snapshot is not a backup, and the
        # deletion that follows depends on this one being usable.
        waiter = ec2.get_waiter("snapshot_completed")
        try:
            waiter.wait(
                SnapshotIds=[snapshot_id],
                WaiterConfig={"Delay": 15, "MaxAttempts": 120},  # up to 30 min
            )
        except Exception as exc:  # noqa: BLE001 - waiter raises WaiterError
            raise ExecutionFailure(
                f"Snapshot {snapshot_id} did not complete: {exc}. The volume has "
                f"NOT been deleted."
            ) from exc

        return ExecutionOutcome(
            succeeded=True,
            detail=f"Snapshot {snapshot_id} completed for volume {volume_id}",
            artifacts={"snapshot_id": snapshot_id},
        )

    def verify(self, context: ExecutionContext) -> list[VerificationResult]:
        if context.dry_run:
            return [self.passed("snapshot", "DRY RUN: no snapshot created")]
        snapshot_id = (context.action.checkpoint.artifacts or {}).get("snapshot_id")
        if not snapshot_id:
            return [self.failed("snapshot", "No snapshot id was recorded")]
        ec2 = context.client("ec2")
        snapshots = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"]
        state = snapshots[0]["State"]
        return [
            self.passed("snapshot", f"Snapshot {snapshot_id} is {state}")
            if state == "completed"
            else self.failed("snapshot", f"Snapshot {snapshot_id} is '{state}'")
        ]

    def rollback(self, context: ExecutionContext, checkpoint: Checkpoint) -> ExecutionOutcome:
        if context.dry_run:
            return ExecutionOutcome(True, "DRY RUN: would delete the snapshot", dry_run=True)
        snapshot_id = (checkpoint.artifacts or {}).get("snapshot_id")
        if not snapshot_id:
            return ExecutionOutcome(True, "No snapshot was created; nothing to undo")
        context.client("ec2").delete_snapshot(SnapshotId=snapshot_id)
        return ExecutionOutcome(True, f"Snapshot {snapshot_id} deleted")


class DeleteEbsExecutor(_EbsBase):
    action_type = ActionType.DELETE_EBS
    rollback_description = "restore_volume_from_snapshot"

    def describe(self, context: ExecutionContext) -> str:
        return (
            f"permanently delete volume {context.resource.resource_id} "
            f"({context.resource.configuration.get('size_gb')} GB)"
        )

    def preflight(self, context: ExecutionContext) -> None:
        volume = self._describe_volume(context)

        if volume["State"] != "available":
            raise PreflightFailure(
                f"Volume is '{volume['State']}', not 'available'. It may have "
                f"been attached since this action was planned."
            )
        if volume.get("Attachments"):
            raise PreflightFailure(
                f"Volume is attached to "
                f"{volume['Attachments'][0].get('InstanceId')}. Refusing to delete."
            )

        self._guard_tags_unchanged(
            context, {t["Key"]: t["Value"] for t in volume.get("Tags", [])}
        )

        # Prove a usable snapshot exists, right now, for THIS volume.
        ec2 = context.client("ec2")
        snapshots = ec2.describe_snapshots(
            OwnerIds=["self"],
            Filters=[{"Name": "volume-id", "Values": [context.resource.resource_id]}],
        ).get("Snapshots", [])
        completed = [s for s in snapshots if s["State"] == "completed"]
        if not completed:
            raise PreflightFailure(
                "No completed snapshot exists for this volume. Deleting it would "
                "be irreversible. Refusing."
            )

        newest = max(completed, key=lambda s: s["StartTime"])
        if newest.get("VolumeSize", 0) < volume["Size"]:
            raise PreflightFailure(
                f"The most recent snapshot covers {newest.get('VolumeSize')} GB "
                f"but the volume is now {volume['Size']} GB. Restoring it would "
                f"not recover the whole volume. Refusing."
            )
        context.notes.append(
            f"Verified snapshot {newest['SnapshotId']} "
            f"({newest.get('VolumeSize')} GB, completed "
            f"{newest['StartTime']:%Y-%m-%d}) before deletion"
        )

    def capture(self, context: ExecutionContext) -> Checkpoint:
        checkpoint = super().capture(context)
        if context.dry_run:
            checkpoint.rollback_data["snapshot_id"] = "snap-dryrun"
            return checkpoint
        ec2 = context.client("ec2")
        snapshots = ec2.describe_snapshots(
            OwnerIds=["self"],
            Filters=[{"Name": "volume-id", "Values": [context.resource.resource_id]}],
        ).get("Snapshots", [])
        completed = [s for s in snapshots if s["State"] == "completed"]
        if completed:
            newest = max(completed, key=lambda s: s["StartTime"])
            checkpoint.rollback_data["snapshot_id"] = newest["SnapshotId"]
            checkpoint.artifacts["snapshot_id"] = newest["SnapshotId"]
        volume = self._describe_volume(context)
        checkpoint.resource_state["availability_zone"] = volume["AvailabilityZone"]
        checkpoint.rollback_data["availability_zone"] = volume["AvailabilityZone"]
        return checkpoint

    def _apply(self, context: ExecutionContext) -> ExecutionOutcome:
        ec2 = context.client("ec2")
        volume_id = context.resource.resource_id
        try:
            ec2.delete_volume(VolumeId=volume_id)
        except ClientError as exc:
            raise ExecutionFailure(f"delete_volume failed: {exc}") from exc
        return ExecutionOutcome(
            succeeded=True,
            detail=(
                f"Volume {volume_id} deleted. Snapshot "
                f"{(context.action.checkpoint.rollback_data or {}).get('snapshot_id')} "
                f"is retained."
            ),
        )

    def verify(self, context: ExecutionContext) -> list[VerificationResult]:
        if context.dry_run:
            return [self.passed("volume_deleted", "DRY RUN: volume not deleted")]
        ec2 = context.client("ec2")
        try:
            ec2.describe_volumes(VolumeIds=[context.resource.resource_id])
        except ClientError as exc:
            if "InvalidVolume.NotFound" in str(exc):
                return [
                    self.passed(
                        "volume_deleted",
                        f"Volume {context.resource.resource_id} no longer exists",
                    )
                ]
            return [self.failed("volume_deleted", f"Could not confirm deletion: {exc}")]
        return [
            self.failed(
                "volume_deleted", f"Volume {context.resource.resource_id} still exists"
            )
        ]

    def rollback(self, context: ExecutionContext, checkpoint: Checkpoint) -> ExecutionOutcome:
        """Restore from snapshot into a NEW volume. This is recovery, not undo."""
        if context.dry_run:
            return ExecutionOutcome(
                True, "DRY RUN: would restore the volume from its snapshot", dry_run=True
            )

        snapshot_id = checkpoint.rollback_data.get("snapshot_id")
        if not snapshot_id:
            return ExecutionOutcome(
                False,
                "No snapshot was recorded, so the volume cannot be restored. "
                "This data is unrecoverable.",
            )

        ec2 = context.client("ec2")
        state = checkpoint.resource_state
        new_volume = ec2.create_volume(
            SnapshotId=snapshot_id,
            AvailabilityZone=checkpoint.rollback_data["availability_zone"],
            VolumeType=state.get("volume_type", "gp3"),
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": [
                        {"Key": "RestoredBy", "Value": "cloudwaste-autopilot"},
                        {"Key": "OriginalVolumeId", "Value": checkpoint.rollback_data["volume_id"]},
                    ],
                }
            ],
        )
        new_id = new_volume["VolumeId"]
        return ExecutionOutcome(
            succeeded=True,
            detail=(
                f"Restored snapshot {snapshot_id} into a new volume {new_id}. "
                f"This is a new resource with a new id: any instance attachment, "
                f"mount configuration or infrastructure-as-code reference to "
                f"{checkpoint.rollback_data['volume_id']} must be updated by hand."
            ),
            artifacts={"restored_volume_id": new_id},
        )


class ModifyEbsVolumeTypeExecutor(_EbsBase):
    action_type = ActionType.MODIFY_EBS_VOLUME_TYPE
    rollback_description = "restore_previous_volume_type"

    def describe(self, context: ExecutionContext) -> str:
        target = context.action.parameters.get("target_volume_type")
        return (
            f"convert volume {context.resource.resource_id} from "
            f"{context.resource.configuration.get('volume_type')} to {target}"
        )

    def preflight(self, context: ExecutionContext) -> None:
        volume = self._describe_volume(context)
        target = context.action.parameters.get("target_volume_type")
        if not target:
            raise PreflightFailure("No target_volume_type given")
        if volume["VolumeType"] == target:
            raise PreflightFailure(f"Volume is already {target}")
        if volume["State"] not in ("available", "in-use"):
            raise PreflightFailure(f"Volume is '{volume['State']}' and cannot be modified")

        # AWS allows one modification per volume per six hours.
        ec2 = context.client("ec2")
        try:
            modifications = ec2.describe_volumes_modifications(
                VolumeIds=[context.resource.resource_id]
            ).get("VolumesModifications", [])
            in_flight = [
                m for m in modifications if m["ModificationState"] in ("modifying", "optimizing")
            ]
            if in_flight:
                raise PreflightFailure(
                    f"Volume already has a modification in progress "
                    f"({in_flight[0]['ModificationState']}). AWS permits one "
                    f"modification per volume every six hours."
                )
        except ClientError as exc:
            if "InvalidVolumeModification.NotFound" not in str(exc):
                raise PreflightFailure(f"Cannot check modification state: {exc}") from exc

    def _apply(self, context: ExecutionContext) -> ExecutionOutcome:
        ec2 = context.client("ec2")
        params = context.action.parameters
        kwargs = {
            "VolumeId": context.resource.resource_id,
            "VolumeType": params["target_volume_type"],
        }
        if params.get("target_iops"):
            kwargs["Iops"] = params["target_iops"]
        if params.get("target_throughput"):
            kwargs["Throughput"] = params["target_throughput"]
        try:
            ec2.modify_volume(**kwargs)
        except ClientError as exc:
            raise ExecutionFailure(f"modify_volume failed: {exc}") from exc
        return ExecutionOutcome(
            succeeded=True,
            detail=(
                f"Volume {context.resource.resource_id} is converting to "
                f"{params['target_volume_type']}. The volume stays attached and "
                f"usable throughout; AWS optimizes in the background."
            ),
        )

    def verify(self, context: ExecutionContext) -> list[VerificationResult]:
        if context.dry_run:
            return [self.passed("volume_type", "DRY RUN: type not changed")]
        volume = self._describe_volume(context)
        target = context.action.parameters["target_volume_type"]
        results = [
            self.passed("volume_type", f"Volume is now {volume['VolumeType']}")
            if volume["VolumeType"] == target
            else self.failed(
                "volume_type", f"Volume is {volume['VolumeType']}, expected {target}"
            )
        ]
        if volume["State"] in ("available", "in-use"):
            results.append(
                self.passed("volume_state", f"Volume is '{volume['State']}' and usable")
            )
        else:
            results.append(self.failed("volume_state", f"Volume is '{volume['State']}'"))
        return results

    def rollback(self, context: ExecutionContext, checkpoint: Checkpoint) -> ExecutionOutcome:
        if context.dry_run:
            return ExecutionOutcome(
                True, "DRY RUN: would restore the previous volume type", dry_run=True
            )
        ec2 = context.client("ec2")
        data = checkpoint.rollback_data
        kwargs = {
            "VolumeId": data["volume_id"],
            "VolumeType": data["original_volume_type"],
        }
        if data.get("original_iops") and data["original_volume_type"] in ("io1", "io2", "gp3"):
            kwargs["Iops"] = data["original_iops"]
        ec2.modify_volume(**kwargs)
        return ExecutionOutcome(
            True,
            f"Volume reverting to {data['original_volume_type']}. Note that AWS "
            f"permits one modification per volume every six hours, so this may "
            f"be rejected if the original change was recent.",
        )


class CreateS3LifecyclePolicyExecutor(Executor):
    action_type = ActionType.CREATE_S3_LIFECYCLE_POLICY
    rollback_description = "remove_lifecycle_rule"

    RULE_ID = "cloudwaste-autopilot-transition"

    def describe(self, context: ExecutionContext) -> str:
        params = context.action.parameters
        return (
            f"add a lifecycle rule to {context.resource.resource_id} "
            f"transitioning objects to {params.get('target_storage_class')} "
            f"after {params.get('transition_days', 90)} days"
        )

    def capture(self, context: ExecutionContext) -> Checkpoint:
        existing: list = []
        if not context.dry_run:
            s3 = context.client("s3")
            try:
                existing = s3.get_bucket_lifecycle_configuration(
                    Bucket=context.resource.resource_id
                ).get("Rules", [])
            except ClientError as exc:
                if "NoSuchLifecycleConfiguration" not in str(exc):
                    raise
        else:
            existing = context.resource.configuration.get("lifecycle_rules", [])

        return Checkpoint(
            resource_state={"lifecycle_rules": existing},
            rollback_method=self.rollback_description,
            rollback_data={
                "bucket": context.resource.resource_id,
                "original_rules": existing,
                "added_rule_id": self.RULE_ID,
            },
        )

    def preflight(self, context: ExecutionContext) -> None:
        params = context.action.parameters
        if not params.get("target_storage_class"):
            raise PreflightFailure("No target_storage_class given")
        s3 = context.client("s3")
        try:
            rules = s3.get_bucket_lifecycle_configuration(
                Bucket=context.resource.resource_id
            ).get("Rules", [])
        except ClientError as exc:
            if "NoSuchLifecycleConfiguration" in str(exc):
                return
            raise PreflightFailure(f"Cannot read bucket lifecycle: {exc}") from exc

        if any(rule.get("ID") == self.RULE_ID for rule in rules):
            raise PreflightFailure(
                f"Bucket already carries a '{self.RULE_ID}' rule; nothing to do"
            )

    def _apply(self, context: ExecutionContext) -> ExecutionOutcome:
        s3 = context.client("s3")
        params = context.action.parameters
        bucket = context.resource.resource_id
        existing = (context.action.checkpoint.resource_state or {}).get("lifecycle_rules", [])

        new_rule = {
            "ID": self.RULE_ID,
            "Status": "Enabled",
            "Filter": {},
            "Transitions": [
                {
                    "Days": int(params.get("transition_days", 90)),
                    "StorageClass": params["target_storage_class"],
                }
            ],
            # Incomplete uploads bill as storage and are invisible in the
            # console. Cleaning them up is free money and costs nothing to add.
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
        }

        try:
            s3.put_bucket_lifecycle_configuration(
                Bucket=bucket,
                LifecycleConfiguration={"Rules": [*existing, new_rule]},
            )
        except ClientError as exc:
            raise ExecutionFailure(f"put_bucket_lifecycle_configuration failed: {exc}") from exc

        return ExecutionOutcome(
            succeeded=True,
            detail=(
                f"Lifecycle rule '{self.RULE_ID}' added to {bucket}. Objects "
                f"transition to {params['target_storage_class']} after "
                f"{params.get('transition_days', 90)} days. Existing objects "
                f"move on their next daily evaluation, so the saving appears "
                f"over the following days rather than immediately."
            ),
            artifacts={"rule_id": self.RULE_ID},
        )

    def verify(self, context: ExecutionContext) -> list[VerificationResult]:
        if context.dry_run:
            return [self.passed("lifecycle_rule", "DRY RUN: no rule added")]
        s3 = context.client("s3")
        rules = s3.get_bucket_lifecycle_configuration(
            Bucket=context.resource.resource_id
        ).get("Rules", [])
        rule = next((r for r in rules if r.get("ID") == self.RULE_ID), None)
        if rule is None:
            return [self.failed("lifecycle_rule", "Rule was not found on the bucket")]
        return [
            self.passed(
                "lifecycle_rule",
                f"Rule '{self.RULE_ID}' is {rule.get('Status')} on the bucket",
            ),
            self.passed(
                "cost_effect_timing",
                "Storage-class transitions are applied by S3 asynchronously, so "
                "the billing change appears over the next few days rather than "
                "at once. Cost verification is deferred accordingly.",
            ),
        ]

    def rollback(self, context: ExecutionContext, checkpoint: Checkpoint) -> ExecutionOutcome:
        if context.dry_run:
            return ExecutionOutcome(
                True, "DRY RUN: would remove the lifecycle rule", dry_run=True
            )
        s3 = context.client("s3")
        bucket = checkpoint.rollback_data["bucket"]
        original = checkpoint.rollback_data.get("original_rules") or []
        if original:
            s3.put_bucket_lifecycle_configuration(
                Bucket=bucket, LifecycleConfiguration={"Rules": original}
            )
        else:
            s3.delete_bucket_lifecycle(Bucket=bucket)
        return ExecutionOutcome(
            succeeded=True,
            detail=(
                f"Lifecycle configuration on {bucket} restored. Objects that have "
                f"already transitioned to a colder class stay there: removing the "
                f"rule stops future transitions but does not move data back."
            ),
        )
