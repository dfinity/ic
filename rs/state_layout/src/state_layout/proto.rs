use super::*;
use ic_protobuf::{
    proxy::{ProxyDecodeError, try_from_option_field},
    state::{
        canister_snapshot_bits::v1 as pb_canister_snapshot_bits,
        canister_state_bits::v1 as pb_canister_state_bits,
    },
};

impl From<CanisterStateBits> for pb_canister_state_bits::CanisterStateBits {
    fn from(item: CanisterStateBits) -> Self {
        Self {
            controllers: item
                .controllers
                .into_iter()
                .map(|controller| controller.into())
                .collect(),
            last_full_execution_round: item.last_full_execution_round.get(),
            compute_allocation: item.compute_allocation.as_percent(),
            accumulated_priority: item.accumulated_priority.get(),
            priority_credit: item.priority_credit.get(),
            long_execution_mode: pb_canister_state_bits::LongExecutionMode::from(
                item.long_execution_mode,
            )
            .into(),
            execution_state_bits: item.execution_state_bits.as_ref().map(|v| v.into()),
            memory_allocation: item.memory_allocation.pre_allocated_bytes().get(),
            wasm_memory_threshold: Some(item.wasm_memory_threshold.get()),
            freeze_threshold: item.freeze_threshold.get(),
            cycles_balance: Some(item.cycles_balance.into()),
            cycles_debit: Some(item.cycles_debit.into()),
            reserved_balance: Some(item.reserved_balance.into()),
            reserved_balance_limit: item.reserved_balance_limit.map(|v| v.into()),
            canister_status: Some((&item.status).into()),
            scheduled_as_first: item.scheduled_as_first,
            skipped_round_due_to_no_messages: item.skipped_round_due_to_no_messages,
            executed: item.executed,
            interrupted_during_execution: item.interrupted_during_execution,
            certified_data: item.certified_data.clone(),
            consumed_cycles: Some((&item.consumed_cycles).into()),
            stable_memory_size64: item.stable_memory_size.get() as u64,
            heap_delta_debit: item.heap_delta_debit.get(),
            install_code_debit: item.install_code_debit.get(),
            time_of_last_allocation_charge_nanos: Some(item.time_of_last_allocation_charge_nanos),
            global_timer_nanos: item.global_timer_nanos,
            canister_version: item.canister_version,
            consumed_cycles_by_use_cases: item
                .consumed_cycles_by_use_cases
                .into_iter()
                .map(
                    |(use_case, cycles)| pb_canister_state_bits::ConsumedCyclesByUseCase {
                        use_case: pb_canister_state_bits::CyclesUseCase::from(use_case).into(),
                        cycles: Some((&cycles).into()),
                    },
                )
                .collect(),
            canister_history: Some((&item.canister_history).into()),
            wasm_chunk_store_metadata: Some((&item.wasm_chunk_store_metadata).into()),
            total_query_stats: Some((&item.total_query_stats).into()),
            log_visibility_v2: pb_canister_state_bits::LogVisibilityV2::from(&item.log_visibility)
                .into(),
            canister_log_records: item
                .canister_log
                .records()
                .iter()
                .map(|record| record.into())
                .collect(),
            next_canister_log_record_idx: item.canister_log.next_idx(),
            wasm_memory_limit: item.wasm_memory_limit.map(|v| v.get()),
            next_snapshot_id: item.next_snapshot_id,
            snapshots_memory_usage: item.snapshots_memory_usage.get(),
            tasks: Some((&item.task_queue).into()),
            environment_variables: item.environment_variables.into_iter().collect(),
        }
    }
}

impl TryFrom<pb_canister_state_bits::CanisterStateBits> for CanisterStateBits {
    type Error = ProxyDecodeError;

    fn try_from(value: pb_canister_state_bits::CanisterStateBits) -> Result<Self, Self::Error> {
        let execution_state_bits = value
            .execution_state_bits
            .map(|b| b.try_into())
            .transpose()?;

        let consumed_cycles =
            try_from_option_field(value.consumed_cycles, "CanisterStateBits::consumed_cycles")
                .unwrap_or_default();

        let mut controllers = BTreeSet::new();
        for controller in value.controllers.into_iter() {
            controllers.insert(PrincipalId::try_from(controller)?);
        }

        let cycles_balance =
            try_from_option_field(value.cycles_balance, "CanisterStateBits::cycles_balance")?;

        let cycles_debit = value
            .cycles_debit
            .map(|c| c.into())
            .unwrap_or_else(Cycles::zero);

        let reserved_balance = value
            .reserved_balance
            .map(|c| c.into())
            .unwrap_or_else(Cycles::zero);

        let mut consumed_cycles_by_use_cases = BTreeMap::new();
        for x in value.consumed_cycles_by_use_cases.into_iter() {
            consumed_cycles_by_use_cases.insert(
                CyclesUseCase::try_from(
                    pb_canister_state_bits::CyclesUseCase::try_from(x.use_case).map_err(|_| {
                        ProxyDecodeError::ValueOutOfRange {
                            typ: "CyclesUseCase",
                            err: format!("Unexpected value of cycles use case: {}", x.use_case),
                        }
                    })?,
                )?,
                NominalCycles::try_from(x.cycles.unwrap_or_default()).unwrap_or_default(),
            );
        }

        let tasks: pb_canister_state_bits::TaskQueue =
            try_from_option_field(value.tasks, "CanisterStateBits::tasks").unwrap_or_default();

        let task_queue = TaskQueue::try_from(tasks)?;

        Ok(Self {
            controllers,
            last_full_execution_round: value.last_full_execution_round.into(),
            compute_allocation: ComputeAllocation::try_from(value.compute_allocation).map_err(
                |e| ProxyDecodeError::ValueOutOfRange {
                    typ: "ComputeAllocation",
                    err: format!("{e:?}"),
                },
            )?,
            accumulated_priority: value.accumulated_priority.into(),
            priority_credit: value.priority_credit.into(),
            long_execution_mode: pb_canister_state_bits::LongExecutionMode::try_from(
                value.long_execution_mode,
            )
            .unwrap_or_default()
            .into(),
            execution_state_bits,
            memory_allocation: MemoryAllocation::from(NumBytes::from(value.memory_allocation)),
            wasm_memory_threshold: NumBytes::new(value.wasm_memory_threshold.unwrap_or(0)),
            freeze_threshold: NumSeconds::from(value.freeze_threshold),
            cycles_balance,
            cycles_debit,
            reserved_balance,
            reserved_balance_limit: value.reserved_balance_limit.map(|v| v.into()),
            status: try_from_option_field(
                value.canister_status,
                "CanisterStateBits::canister_status",
            )?,
            scheduled_as_first: value.scheduled_as_first,
            skipped_round_due_to_no_messages: value.skipped_round_due_to_no_messages,
            executed: value.executed,
            interrupted_during_execution: value.interrupted_during_execution,
            certified_data: value.certified_data,
            consumed_cycles,
            stable_memory_size: NumWasmPages::from(value.stable_memory_size64 as usize),
            heap_delta_debit: NumBytes::from(value.heap_delta_debit),
            install_code_debit: NumInstructions::from(value.install_code_debit),
            time_of_last_allocation_charge_nanos: try_from_option_field(
                value.time_of_last_allocation_charge_nanos,
                "CanisterStateBits::time_of_last_allocation_charge_nanos",
            )?,
            global_timer_nanos: value.global_timer_nanos,
            canister_version: value.canister_version,
            consumed_cycles_by_use_cases,
            // TODO(MR-412): replace `unwrap_or_default` by returning an error on missing canister_history field
            canister_history: try_from_option_field(
                value.canister_history,
                "CanisterStateBits::canister_history",
            )
            .unwrap_or_default(),
            wasm_chunk_store_metadata: try_from_option_field(
                value.wasm_chunk_store_metadata,
                "CanisterStateBits::wasm_chunk_store_metadata",
            )
            .unwrap_or_default(),
            total_query_stats: try_from_option_field(
                value.total_query_stats,
                "CanisterStateBits::total_query_stats",
            )
            .unwrap_or_default(),
            log_visibility: try_from_option_field(
                value.log_visibility_v2,
                "CanisterStateBits::log_visibility_v2",
            )
            .unwrap_or_default(),
            // TODO(DSM-11): old implementation of canister log does not resize, remove after migration is done.
            canister_log: CanisterLog::new_aggregate(
                value.next_canister_log_record_idx,
                value
                    .canister_log_records
                    .into_iter()
                    .map(|record| record.into())
                    .collect(),
            ),
            wasm_memory_limit: value.wasm_memory_limit.map(NumBytes::from),
            next_snapshot_id: value.next_snapshot_id,
            snapshots_memory_usage: NumBytes::from(value.snapshots_memory_usage),
            task_queue,
            environment_variables: value.environment_variables.into_iter().collect(),
        })
    }
}

impl From<&ExecutionStateBits> for pb_canister_state_bits::ExecutionStateBits {
    fn from(item: &ExecutionStateBits) -> Self {
        Self {
            exported_globals: item
                .exported_globals
                .iter()
                .map(|global| global.into())
                .collect(),
            heap_size: item
                .heap_size
                .get()
                .try_into()
                .expect("Canister heap size didn't fit into 32 bits"),
            exports: (&item.exports).into(),
            last_executed_round: item.last_executed_round.get(),
            metadata: Some((&item.metadata).into()),
            binary_hash: item.binary_hash.to_vec(),
            next_scheduled_method: Some(
                pb_canister_state_bits::NextScheduledMethod::from(item.next_scheduled_method)
                    .into(),
            ),
            is_wasm64: item.is_wasm64,
        }
    }
}

impl TryFrom<pb_canister_state_bits::ExecutionStateBits> for ExecutionStateBits {
    type Error = ProxyDecodeError;

    fn try_from(value: pb_canister_state_bits::ExecutionStateBits) -> Result<Self, Self::Error> {
        let mut globals = Vec::with_capacity(value.exported_globals.len());
        for g in value.exported_globals.into_iter() {
            globals.push(g.try_into()?);
        }
        let binary_hash: [u8; 32] =
            value
                .binary_hash
                .try_into()
                .map_err(|e| ProxyDecodeError::ValueOutOfRange {
                    typ: "BinaryHash",
                    err: format!("Expected a 32-byte long module hash, got {e:?}"),
                })?;

        Ok(Self {
            exported_globals: globals,
            heap_size: (value.heap_size as usize).into(),
            exports: value.exports.try_into()?,
            last_executed_round: value.last_executed_round.into(),
            metadata: try_from_option_field(value.metadata, "ExecutionStateBits::metadata")
                .unwrap_or_default(),
            binary_hash: WasmHash::from(binary_hash),
            next_scheduled_method: match value.next_scheduled_method {
                Some(method_id) => pb_canister_state_bits::NextScheduledMethod::try_from(method_id)
                    .unwrap_or_default()
                    .into(),
                None => NextScheduledMethod::default(),
            },
            is_wasm64: value.is_wasm64,
        })
    }
}

impl From<CanisterSnapshotBits> for pb_canister_snapshot_bits::CanisterSnapshotBits {
    fn from(item: CanisterSnapshotBits) -> Self {
        Self {
            snapshot_id: item.snapshot_id.get_local_snapshot_id(),
            canister_id: Some((item.canister_id).into()),
            taken_at_timestamp: item.taken_at_timestamp.as_nanos_since_unix_epoch(),
            canister_version: item.canister_version,
            binary_hash: item.binary_hash.to_vec(),
            certified_data: item.certified_data.clone(),
            wasm_chunk_store_metadata: Some((&item.wasm_chunk_store_metadata).into()),
            stable_memory_size: item.stable_memory_size.get() as u64,
            wasm_memory_size: item.wasm_memory_size.get() as u64,
            total_size: item.total_size.get(),
            exported_globals: item
                .exported_globals
                .iter()
                .map(|global| global.into())
                .collect(),
            global_timer: item
                .global_timer
                .map(pb_canister_snapshot_bits::CanisterTimer::from),
            on_low_wasm_memory_hook_status: item
                .on_low_wasm_memory_hook_status
                .map(|x| pb_canister_state_bits::OnLowWasmMemoryHookStatus::from(&x).into()),
            source: pb_canister_state_bits::SnapshotSource::from(item.source).into(),
        }
    }
}

impl TryFrom<pb_canister_snapshot_bits::CanisterSnapshotBits> for CanisterSnapshotBits {
    type Error = ProxyDecodeError;
    fn try_from(
        item: pb_canister_snapshot_bits::CanisterSnapshotBits,
    ) -> Result<Self, Self::Error> {
        let canister_id: CanisterId =
            try_from_option_field(item.canister_id, "CanisterSnapshotBits::canister_id")?;

        let binary_hash: [u8; 32] =
            item.binary_hash
                .try_into()
                .map_err(|e| ProxyDecodeError::ValueOutOfRange {
                    typ: "BinaryHash",
                    err: format!("Expected a 32-byte long module hash, got {e:?}"),
                })?;

        let mut exported_globals = Vec::with_capacity(item.exported_globals.len());
        for global in item.exported_globals.into_iter() {
            exported_globals.push(global.try_into()?);
        }
        let global_timer = item.global_timer.map(CanisterTimer::from);

        let on_low_wasm_memory_hook_status = item
            .on_low_wasm_memory_hook_status
            .map(pb_canister_state_bits::OnLowWasmMemoryHookStatus::try_from)
            .and_then(Result::ok)
            .map(OnLowWasmMemoryHookStatus::try_from)
            .and_then(Result::ok);

        let source =
            pb_canister_state_bits::SnapshotSource::try_from(item.source).unwrap_or_default();
        let source = SnapshotSource::try_from(source).unwrap_or_default();
        Ok(Self {
            snapshot_id: SnapshotId::from((canister_id, item.snapshot_id)),
            canister_id,
            taken_at_timestamp: Time::from_nanos_since_unix_epoch(item.taken_at_timestamp),
            canister_version: item.canister_version,
            binary_hash: WasmHash::from(binary_hash),
            certified_data: item.certified_data,
            wasm_chunk_store_metadata: try_from_option_field(
                item.wasm_chunk_store_metadata,
                "CanisterSnapshotBits::wasm_chunk_store_metadata",
            )
            .unwrap_or_default(),
            stable_memory_size: NumWasmPages::from(item.stable_memory_size as usize),
            wasm_memory_size: NumWasmPages::from(item.wasm_memory_size as usize),
            total_size: NumBytes::from(item.total_size),
            exported_globals,
            global_timer,
            on_low_wasm_memory_hook_status,
            source,
        })
    }
}
