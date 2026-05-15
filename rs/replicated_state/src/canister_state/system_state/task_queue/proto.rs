use super::*;
use ic_protobuf::proxy::ProxyDecodeError;
use ic_protobuf::state::canister_state_bits::v1 as pb;
use ic_protobuf::state::queues::v1::CompoundCycles as PbCompoundCycles;

impl From<&TaskQueue> for pb::TaskQueue {
    fn from(item: &TaskQueue) -> Self {
        let on_low_wasm_memory_hook_reservation = match item.on_low_wasm_memory_hook_task.as_ref() {
            Some(ExecutionTask::OnLowWasmMemory(reservation)) => {
                Some(PbCompoundCycles::from(*reservation))
            }
            Some(other) => {
                panic!("BUG: unexpected task stored in `on_low_wasm_memory_hook_task`: {other:?}")
            }
            None => None,
        };
        Self {
            paused_or_aborted_task: item.paused_or_aborted_task.as_ref().map(|task| task.into()),
            on_low_wasm_memory_hook_status: pb::OnLowWasmMemoryHookStatus::from(
                &item.on_low_wasm_memory_hook_status,
            )
            .into(),
            on_low_wasm_memory_hook_reservation,
            queue: item.queue.iter().map(|task| task.into()).collect(),
        }
    }
}

impl TryFrom<pb::TaskQueue> for TaskQueue {
    type Error = ProxyDecodeError;

    fn try_from(item: pb::TaskQueue) -> Result<Self, Self::Error> {
        let on_low_wasm_memory_hook_status: OnLowWasmMemoryHookStatus =
            pb::OnLowWasmMemoryHookStatus::try_from(item.on_low_wasm_memory_hook_status)
                .map_err(|e| {
                    ProxyDecodeError::Other(format!(
                        "Error while trying to decode pb::TaskQueue::on_low_wasm_memory_hook_status, {e:?}"
                    ))
                })?
                .try_into()?;
        let on_low_wasm_memory_hook_reservation: Option<CompoundCycles<Instructions>> = item
            .on_low_wasm_memory_hook_reservation
            .map(CompoundCycles::try_from)
            .transpose()?;
        // The invariant `Ready ⇔ reservation.is_some()` is enforced by the
        // encode path; reject any persisted state that violates it here so a
        // bug is surfaced at the checkpoint boundary rather than silently.
        let on_low_wasm_memory_hook_task = match (
            on_low_wasm_memory_hook_status,
            on_low_wasm_memory_hook_reservation,
        ) {
            (OnLowWasmMemoryHookStatus::Ready, Some(reservation)) => {
                Some(ExecutionTask::OnLowWasmMemory(reservation))
            }
            // FIXME: This could happen when loading a checkpoint from an earlier replica version.
            (OnLowWasmMemoryHookStatus::Ready, None) => {
                return Err(ProxyDecodeError::Other(
                    "pb::TaskQueue::on_low_wasm_memory_hook_status was `Ready` but \
                     `on_low_wasm_memory_hook_reservation` is missing."
                        .into(),
                ));
            }
            (status, Some(_)) => {
                return Err(ProxyDecodeError::Other(format!(
                    "pb::TaskQueue::on_low_wasm_memory_hook_reservation is set but \
                     `on_low_wasm_memory_hook_status` is {status:?} (expected `Ready`)."
                )));
            }
            (_, None) => None,
        };
        Ok(Self {
            paused_or_aborted_task: item
                .paused_or_aborted_task
                .map(|task| task.try_into())
                .transpose()?,
            on_low_wasm_memory_hook_status,
            on_low_wasm_memory_hook_task,
            queue: item
                .queue
                .into_iter()
                .map(|task| task.try_into())
                .collect::<Result<VecDeque<_>, _>>()?,
        })
    }
}
