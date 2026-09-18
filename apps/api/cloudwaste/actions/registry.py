"""Action type to executor mapping.

An action with no registered executor is refused. That is deliberate: the enum
carries types the system understands conceptually (SCHEDULE_RESOURCE,
CHANGE_S3_STORAGE_CLASS) but has no safe implementation for yet, and the
absence of an executor is the honest way to represent "recognized but not
implemented" rather than a stub that half-works.
"""

from __future__ import annotations

from ..models.enums import ActionType
from .executors.base import Executor
from .executors.compute import ResizeEc2Executor, StartEc2Executor, StopEc2Executor
from .executors.managed import (
    ModifyLambdaMemoryExecutor,
    ReleaseElasticIpExecutor,
    ResizeRdsExecutor,
)
from .executors.storage import (
    CreateEbsSnapshotExecutor,
    CreateS3LifecyclePolicyExecutor,
    DeleteEbsExecutor,
    ModifyEbsVolumeTypeExecutor,
)

_EXECUTORS: dict[ActionType, Executor] = {
    executor.action_type: executor
    for executor in (
        StopEc2Executor(),
        StartEc2Executor(),
        ResizeEc2Executor(),
        CreateEbsSnapshotExecutor(),
        DeleteEbsExecutor(),
        ModifyEbsVolumeTypeExecutor(),
        CreateS3LifecyclePolicyExecutor(),
        ResizeRdsExecutor(),
        ModifyLambdaMemoryExecutor(),
        ReleaseElasticIpExecutor(),
    )
}

#: Action types the enum defines but no executor implements. Listed explicitly
#: so the gap is visible rather than discovered at runtime.
UNIMPLEMENTED: dict[ActionType, str] = {
    ActionType.CHANGE_S3_STORAGE_CLASS: (
        "Bulk re-copying existing objects is a data-movement job, not an API "
        "call. Use CREATE_S3_LIFECYCLE_POLICY, which achieves the same result "
        "without moving data synchronously."
    ),
    ActionType.SCHEDULE_RESOURCE: (
        "Scheduled start/stop needs an EventBridge rule per resource and an "
        "owner-confirmed schedule. Not implemented in v1.0."
    ),
    ActionType.ROLLBACK_ACTION: (
        "Rollback is not dispatched as an action. It is a phase of the "
        "orchestrator, invoked with the original action's checkpoint."
    ),
}


class NoExecutorError(LookupError):
    pass


def get_executor(action_type: ActionType) -> Executor:
    executor = _EXECUTORS.get(action_type)
    if executor is not None:
        return executor
    reason = UNIMPLEMENTED.get(action_type)
    if reason:
        raise NoExecutorError(f"{action_type.value} is not executable: {reason}")
    raise NoExecutorError(f"No executor is registered for {action_type.value}")


def is_executable(action_type: ActionType) -> bool:
    return action_type in _EXECUTORS


def executable_actions() -> list[ActionType]:
    return sorted(_EXECUTORS, key=lambda a: a.value)
