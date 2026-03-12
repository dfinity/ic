use super::*;
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

impl TryFrom<pb::TaskQueue> for TaskQueue {
    type Error = ProxyDecodeError;

    fn try_from(item: pb::TaskQueue) -> Result<Self, Self::Error> {
        Ok(Self {
            paused_or_aborted_task: item
                .paused_or_aborted_task
                .map(|task| task.try_into())
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
                .map(|task| task.try_into())
                .collect::<Result<VecDeque<_>, _>>()?,
        })
    }
}
