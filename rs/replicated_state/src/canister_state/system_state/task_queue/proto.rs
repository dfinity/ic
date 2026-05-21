use super::*;
use crate::CallContextManager;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::canister_state_bits::v1 as pb;

impl From<&TaskQueue> for pb::TaskQueue {
    fn from(item: &TaskQueue) -> Self {
        Self {
            paused_or_aborted_task: item.paused_or_aborted_task.as_ref().map(|task| task.into()),
            on_low_wasm_memory_hook_status: pb::OnLowWasmMemoryHookStatus::from(
                &item.on_low_wasm_memory_hook_status,
            )
            .into(),
            queue: item.queue.iter().map(|task| task.into()).collect(),
        }
    }
}

// TODO(DSM-95): Drop the `ccm` parameter in the next replica release.
// It is only needed for backward compatible decoding of the legacy
// `ExecutionTask::Response` variant, which has no callback.
impl TryFrom<(pb::TaskQueue, &mut CallContextManager)> for TaskQueue {
    type Error = ProxyDecodeError;

    fn try_from(
        (item, ccm): (pb::TaskQueue, &mut CallContextManager),
    ) -> Result<Self, Self::Error> {
        fn decode_task(
            task: pb::ExecutionTask,
            ccm: &mut CallContextManager,
        ) -> Result<ExecutionTask, ProxyDecodeError> {
            (task, ccm).try_into()
        }
        Ok(Self {
            paused_or_aborted_task: item
                .paused_or_aborted_task
                .map(|task| decode_task(task, ccm))
                .transpose()?,
            on_low_wasm_memory_hook_status: pb::OnLowWasmMemoryHookStatus::try_from(
                item.on_low_wasm_memory_hook_status,
            )
            .map_err(|e| ProxyDecodeError::Other(
                format!("Error while trying to decode pb::TaskQueue::on_low_wasm_memory_hook_status, {e:?}")))?
            .try_into()?,
            queue: item
                .queue
                .into_iter()
                .map(|task| decode_task(task, ccm))
                .collect::<Result<VecDeque<_>, _>>()?,
        })
    }
}
