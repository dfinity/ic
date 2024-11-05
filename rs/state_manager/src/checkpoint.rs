use crossbeam_channel::{unbounded, Sender};
use ic_base_types::{subnet_id_try_from_protobuf, CanisterId, SnapshotId};
use ic_config::flag_status::FlagStatus;
use ic_logger::error;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_snapshots::{
    CanisterSnapshot, CanisterSnapshots, ExecutionStateSnapshot, PageMemory,
};
use ic_replicated_state::canister_state::system_state::wasm_chunk_store::WasmChunkStore;
use ic_replicated_state::page_map::{storage::verify, PageAllocatorFileDescriptor};
use ic_replicated_state::{
    canister_state::execution_state::WasmBinary, page_map::PageMap, CanisterMetrics, CanisterState,
    ExecutionState, ReplicatedState, SchedulerState, SystemState,
};
use ic_replicated_state::{CheckpointLoadingMetrics, Memory};
use ic_state_layout::{
    CanisterLayout, CanisterSnapshotBits, CanisterStateBits, CheckpointLayout, ReadOnly,
    SnapshotLayout,
};
use ic_types::batch::RawQueryStats;
use ic_types::{CanisterTimer, Height, Time};
use ic_utils::thread::maybe_parallel_map;
use std::collections::BTreeMap;
use std::convert::{identity, TryFrom};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{
    CheckpointError, CheckpointMetrics, HasDowngrade, PageMapType, TipRequest,
    CRITICAL_ERROR_CHECKPOINT_SOFT_INVARIANT_BROKEN, NUMBER_OF_CHECKPOINT_THREADS,
};

#[cfg(test)]
mod tests;

impl CheckpointLoadingMetrics for CheckpointMetrics {
    fn observe_broken_soft_invariant(&self, msg: String) {
        self.load_checkpoint_soft_invariant_broken.inc();
        error!(
            self.log,
            "{}: Checkpoint invariant broken: {}",
            CRITICAL_ERROR_CHECKPOINT_SOFT_INVARIANT_BROKEN,
            msg
        );
        debug_assert!(false);
    }
}

/// Creates a checkpoint of the node state using specified directory
/// layout. Returns a new state that is equivalent to the given one
/// and a result of the operation.
///
/// This function uses the provided thread-pool to parallelize expensive
/// operations.
///
/// If the result is `Ok`, the returned state is "rebased" to use
/// files from the newly created checkpoint. If the result is `Err`,
/// the returned state is exactly the one that was passed as argument.
pub(crate) fn make_checkpoint(
    state: &ReplicatedState,
    height: Height,
    tip_channel: &Sender<TipRequest>,
    metrics: &CheckpointMetrics,
    thread_pool: &mut scoped_threadpool::Pool,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    lsmt_storage: FlagStatus,
) -> Result<(CheckpointLayout<ReadOnly>, ReplicatedState, HasDowngrade), CheckpointError> {
    {
        let _timer = metrics
            .make_checkpoint_step_duration
            .with_label_values(&["serialize_to_tip_cloning"])
            .start_timer();
        tip_channel
            .send(TipRequest::SerializeToTip {
                height,
                replicated_state: Box::new(state.clone()),
            })
            .unwrap();
    }

    tip_channel
        .send(TipRequest::FilterTipCanisters {
            height,
            ids: state.canister_states.keys().copied().collect(),
        })
        .unwrap();

    let (cp, has_downgrade) = {
        let _timer = metrics
            .make_checkpoint_step_duration
            .with_label_values(&["tip_to_checkpoint"])
            .start_timer();
        #[allow(clippy::disallowed_methods)]
        let (send, recv) = unbounded();
        tip_channel
            .send(TipRequest::TipToCheckpoint {
                height,
                sender: send,
            })
            .unwrap();
        let (cp, has_downgrade) = recv.recv().unwrap()?;
        // With lsmt storage, ResetTipAndMerge happens later (after manifest).
        if lsmt_storage == FlagStatus::Disabled {
            tip_channel
                .send(TipRequest::ResetTipAndMerge {
                    checkpoint_layout: cp.clone(),
                    pagemaptypes: PageMapType::list_all_including_snapshots(state),
                    is_initializing_tip: false,
                })
                .unwrap();
        }
        (cp, has_downgrade)
    };

    if lsmt_storage == FlagStatus::Disabled {
        // Wait for reset_tip_to so that we don't reflink in parallel with other operations.
        let _timer = metrics
            .make_checkpoint_step_duration
            .with_label_values(&["wait_for_reflinking"])
            .start_timer();
        #[allow(clippy::disallowed_methods)]
        let (send, recv) = unbounded();
        tip_channel.send(TipRequest::Wait { sender: send }).unwrap();
        recv.recv().unwrap();
    }

    let state = {
        let _timer = metrics
            .make_checkpoint_step_duration
            .with_label_values(&["load"])
            .start_timer();
        load_checkpoint(
            &cp,
            state.metadata.own_subnet_type,
            metrics,
            Some(thread_pool),
            Arc::clone(&fd_factory),
        )?
    };

    Ok((cp, state, has_downgrade))
}

pub(crate) fn validate_checkpoint_and_remove_unverified_marker(
    checkpoint_layout: &CheckpointLayout<ReadOnly>,
    mut thread_pool: Option<&mut scoped_threadpool::Pool>,
) -> Result<(), CheckpointError> {
    maybe_parallel_map(
        &mut thread_pool,
        checkpoint_layout.all_existing_pagemaps()?.into_iter(),
        |pm| verify(pm),
    )
    .into_iter()
    .try_for_each(identity)?;
    checkpoint_layout
        .remove_unverified_checkpoint_marker()
        .map_err(CheckpointError::from)?;
    Ok(())
}

/// Loads checkpoint and validates correctness of the overlays in parallel, if success removes the
/// unverified checkpoint marker.
/// This combination is useful when marking a checkpoint as verified immediately after a
/// successful loading.
pub fn load_checkpoint_and_validate_parallel(
    checkpoint_layout: &CheckpointLayout<ReadOnly>,
    own_subnet_type: SubnetType,
    metrics: &CheckpointMetrics,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<ReplicatedState, CheckpointError> {
    let mut thread_pool = scoped_threadpool::Pool::new(NUMBER_OF_CHECKPOINT_THREADS);
    let state = load_checkpoint(
        checkpoint_layout,
        own_subnet_type,
        metrics,
        Some(&mut thread_pool),
        Arc::clone(&fd_factory),
    )?;
    validate_checkpoint_and_remove_unverified_marker(checkpoint_layout, Some(&mut thread_pool))?;
    Ok(state)
}

struct CheckpointLoader {
    checkpoint_layout: CheckpointLayout<ReadOnly>,
    own_subnet_type: SubnetType,
    metrics: CheckpointMetrics,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
}

impl CheckpointLoader {
    fn map_to_checkpoint_error(
        &self,
        field: String,
        err: ic_protobuf::proxy::ProxyDecodeError,
    ) -> CheckpointError {
        CheckpointError::ProtoError {
            path: self.checkpoint_layout.raw_path().into(),
            field,
            proto_err: err.to_string(),
        }
    }

    fn load_system_metadata(&self) -> Result<ic_replicated_state::SystemMetadata, CheckpointError> {
        let _timer = self
            .metrics
            .load_checkpoint_step_duration
            .with_label_values(&["system_metadata"])
            .start_timer();

        let ingress_history_proto = self.checkpoint_layout.ingress_history().deserialize()?;
        let ingress_history =
            ic_replicated_state::IngressHistoryState::try_from(ingress_history_proto)
                .map_err(|err| self.map_to_checkpoint_error("IngressHistoryState".into(), err))?;
        let metadata_proto = self.checkpoint_layout.system_metadata().deserialize()?;
        let mut metadata = ic_replicated_state::SystemMetadata::try_from((
            metadata_proto,
            &self.metrics as &dyn CheckpointLoadingMetrics,
        ))
        .map_err(|err| self.map_to_checkpoint_error("SystemMetadata".into(), err))?;
        metadata.ingress_history = ingress_history;
        metadata.own_subnet_type = self.own_subnet_type;

        if let Some(split_from) = self
            .checkpoint_layout
            .split_marker()
            .deserialize()?
            .subnet_id
        {
            metadata.split_from = Some(
                subnet_id_try_from_protobuf(split_from)
                    .map_err(|err| self.map_to_checkpoint_error("split_from".into(), err))?,
            );
        }

        Ok(metadata)
    }

    fn load_subnet_queues(&self) -> Result<ic_replicated_state::CanisterQueues, CheckpointError> {
        let _timer = self
            .metrics
            .load_checkpoint_step_duration
            .with_label_values(&["subnet_queues"])
            .start_timer();

        ic_replicated_state::CanisterQueues::try_from((
            self.checkpoint_layout.subnet_queues().deserialize()?,
            &self.metrics as &dyn CheckpointLoadingMetrics,
        ))
        .map_err(|err| self.map_to_checkpoint_error("CanisterQueues".into(), err))
    }

    fn load_query_stats(&self) -> Result<RawQueryStats, CheckpointError> {
        let stats = self.checkpoint_layout.stats().deserialize()?;
        if let Some(query_stats) = stats.query_stats {
            Ok(RawQueryStats::try_from(query_stats)
                .map_err(|err| self.map_to_checkpoint_error("QueryStats".into(), err))?)
        } else {
            Ok(RawQueryStats::default())
        }
    }

    fn load_canister_states(
        &self,
        thread_pool: &mut Option<&mut scoped_threadpool::Pool>,
    ) -> Result<BTreeMap<CanisterId, CanisterState>, CheckpointError> {
        let _timer = self
            .metrics
            .load_checkpoint_step_duration
            .with_label_values(&["canister_states"])
            .start_timer();

        let mut canister_states = BTreeMap::new();
        let canister_ids = self.checkpoint_layout.canister_ids()?;
        let results = maybe_parallel_map(thread_pool, canister_ids.iter(), |canister_id| {
            load_canister_state_from_checkpoint(
                &self.checkpoint_layout,
                canister_id,
                Arc::clone(&self.fd_factory),
                &self.metrics,
            )
        });

        for canister_state in results.into_iter() {
            let (canister_state, durations) = canister_state?;
            canister_states.insert(canister_state.system_state.canister_id(), canister_state);

            durations.apply(&self.metrics);
        }

        Ok(canister_states)
    }

    fn load_canister_snapshots(
        &self,
        thread_pool: &mut Option<&mut scoped_threadpool::Pool>,
    ) -> Result<CanisterSnapshots, CheckpointError> {
        let _timer = self
            .metrics
            .load_checkpoint_step_duration
            .with_label_values(&["canister_snapshots"])
            .start_timer();

        let mut canister_snapshots = BTreeMap::new();
        let snapshot_ids = self.checkpoint_layout.snapshot_ids()?;
        let results = maybe_parallel_map(thread_pool, snapshot_ids.iter(), |snapshot_id| {
            (
                **snapshot_id,
                load_snapshot_from_checkpoint(
                    &self.checkpoint_layout,
                    snapshot_id,
                    Arc::clone(&self.fd_factory),
                ),
            )
        });

        for (snapshot_id, canister_snapshot) in results.into_iter() {
            let (canister_snapshot, durations) = canister_snapshot?;
            canister_snapshots.insert(snapshot_id, Arc::new(canister_snapshot));

            durations.apply(&self.metrics);
        }

        Ok(CanisterSnapshots::new(canister_snapshots))
    }
}

/// Loads the node state heighted with `height` using the specified
/// directory layout.
pub fn load_checkpoint(
    checkpoint_layout: &CheckpointLayout<ReadOnly>,
    own_subnet_type: SubnetType,
    metrics: &CheckpointMetrics,
    mut thread_pool: Option<&mut scoped_threadpool::Pool>,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<ReplicatedState, CheckpointError> {
    let checkpoint_loader = CheckpointLoader {
        checkpoint_layout: checkpoint_layout.clone(),
        own_subnet_type,
        metrics: metrics.clone(),
        fd_factory,
    };
    Ok(ReplicatedState::new_from_checkpoint(
        checkpoint_loader.load_canister_states(&mut thread_pool)?,
        checkpoint_loader.load_system_metadata()?,
        checkpoint_loader.load_subnet_queues()?,
        checkpoint_loader.load_query_stats()?,
        checkpoint_loader.load_canister_snapshots(&mut thread_pool)?,
    ))
}

#[derive(Default)]
pub struct LoadCanisterMetrics {
    durations: BTreeMap<&'static str, Duration>,
}

impl LoadCanisterMetrics {
    pub fn apply(&self, metrics: &CheckpointMetrics) {
        for (key, duration) in &self.durations {
            metrics
                .load_canister_step_duration
                .with_label_values(&[key])
                .observe(duration.as_secs_f64());
        }
    }
}

pub fn load_canister_state(
    canister_layout: &CanisterLayout<ReadOnly>,
    canister_id: &CanisterId,
    height: Height,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    metrics: &dyn CheckpointLoadingMetrics,
) -> Result<(CanisterState, LoadCanisterMetrics), CheckpointError> {
    let mut durations = BTreeMap::<&str, Duration>::default();

    let into_checkpoint_error =
        |field: String, err: ic_protobuf::proxy::ProxyDecodeError| CheckpointError::ProtoError {
            path: canister_layout.raw_path(),
            field,
            proto_err: err.to_string(),
        };

    let starting_time = Instant::now();
    let canister_state_bits: CanisterStateBits =
        CanisterStateBits::try_from(canister_layout.canister().deserialize()?).map_err(|err| {
            into_checkpoint_error(
                format!("canister_states[{}]::canister_state_bits", canister_id),
                err,
            )
        })?;
    durations.insert("canister_state_bits", starting_time.elapsed());

    let execution_state = match canister_state_bits.execution_state_bits {
        Some(execution_state_bits) => {
            let starting_time = Instant::now();
            let wasm_memory_layout = canister_layout.vmemory_0();
            let wasm_memory = Memory::new(
                PageMap::open(
                    Box::new(wasm_memory_layout),
                    height,
                    Arc::clone(&fd_factory),
                )?,
                execution_state_bits.heap_size,
            );
            durations.insert("wasm_memory", starting_time.elapsed());

            let starting_time = Instant::now();
            let stable_memory_layout = canister_layout.stable_memory();
            let stable_memory = Memory::new(
                PageMap::open(
                    Box::new(stable_memory_layout),
                    height,
                    Arc::clone(&fd_factory),
                )?,
                canister_state_bits.stable_memory_size,
            );
            durations.insert("stable_memory", starting_time.elapsed());

            let starting_time = Instant::now();
            let wasm_binary = WasmBinary::new(
                canister_layout
                    .wasm()
                    .deserialize(execution_state_bits.binary_hash)?,
            );
            durations.insert("wasm_binary", starting_time.elapsed());

            let canister_root =
                CheckpointLayout::<ReadOnly>::new_untracked("NOT_USED".into(), height)?
                    .canister(canister_id)?
                    .raw_path();
            Some(ExecutionState {
                canister_root,
                wasm_binary,
                exports: execution_state_bits.exports,
                wasm_memory,
                stable_memory,
                exported_globals: execution_state_bits.exported_globals,
                metadata: execution_state_bits.metadata,
                last_executed_round: execution_state_bits.last_executed_round,
                next_scheduled_method: execution_state_bits.next_scheduled_method,
                is_wasm64: execution_state_bits.is_wasm64,
            })
        }
        None => None,
    };

    let starting_time = Instant::now();
    let queues = ic_replicated_state::CanisterQueues::try_from((
        canister_layout.queues().deserialize()?,
        metrics,
    ))
    .map_err(|err| {
        into_checkpoint_error(
            format!("canister_states[{}]::system_state::queues", canister_id),
            err,
        )
    })?;
    durations.insert("canister_queues", starting_time.elapsed());

    let canister_metrics = CanisterMetrics::new(
        canister_state_bits.scheduled_as_first,
        canister_state_bits.skipped_round_due_to_no_messages,
        canister_state_bits.executed,
        canister_state_bits.interrupted_during_execution,
        canister_state_bits.consumed_cycles,
        canister_state_bits.consumed_cycles_by_use_cases,
    );

    let starting_time = Instant::now();
    let wasm_chunk_store_layout = canister_layout.wasm_chunk_store();
    let wasm_chunk_store_data = PageMap::open(
        Box::new(wasm_chunk_store_layout),
        height,
        Arc::clone(&fd_factory),
    )?;
    durations.insert("wasm_chunk_store", starting_time.elapsed());

    let system_state = SystemState::new_from_checkpoint(
        canister_state_bits.controllers,
        *canister_id,
        queues,
        canister_state_bits.memory_allocation,
        canister_state_bits.wasm_memory_threshold,
        canister_state_bits.freeze_threshold,
        canister_state_bits.status,
        canister_state_bits.certified_data,
        canister_metrics,
        canister_state_bits.cycles_balance,
        canister_state_bits.cycles_debit,
        canister_state_bits.reserved_balance,
        canister_state_bits.reserved_balance_limit,
        canister_state_bits.task_queue.into_iter().collect(),
        CanisterTimer::from_nanos_since_unix_epoch(canister_state_bits.global_timer_nanos),
        canister_state_bits.canister_version,
        canister_state_bits.canister_history,
        wasm_chunk_store_data,
        canister_state_bits.wasm_chunk_store_metadata,
        canister_state_bits.log_visibility,
        canister_state_bits.canister_log,
        canister_state_bits.wasm_memory_limit,
        canister_state_bits.next_snapshot_id,
        canister_state_bits.snapshots_memory_usage,
        metrics,
        canister_state_bits.on_low_wasm_memory_hook_status,
    );

    let canister_state = CanisterState {
        system_state,
        execution_state,
        scheduler_state: SchedulerState {
            last_full_execution_round: canister_state_bits.last_full_execution_round,
            compute_allocation: canister_state_bits.compute_allocation,
            accumulated_priority: canister_state_bits.accumulated_priority,
            priority_credit: canister_state_bits.priority_credit,
            long_execution_mode: canister_state_bits.long_execution_mode,
            heap_delta_debit: canister_state_bits.heap_delta_debit,
            install_code_debit: canister_state_bits.install_code_debit,
            time_of_last_allocation_charge: Time::from_nanos_since_unix_epoch(
                canister_state_bits.time_of_last_allocation_charge_nanos,
            ),
            total_query_stats: canister_state_bits.total_query_stats,
        },
    };

    let metrics = LoadCanisterMetrics { durations };

    Ok((canister_state, metrics))
}

fn load_canister_state_from_checkpoint(
    checkpoint_layout: &CheckpointLayout<ReadOnly>,
    canister_id: &CanisterId,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    metrics: &CheckpointMetrics,
) -> Result<(CanisterState, LoadCanisterMetrics), CheckpointError> {
    let canister_layout = checkpoint_layout.canister(canister_id)?;
    load_canister_state(
        &canister_layout,
        canister_id,
        checkpoint_layout.height(),
        Arc::clone(&fd_factory),
        metrics,
    )
}

pub fn load_snapshot(
    snapshot_layout: &SnapshotLayout<ReadOnly>,
    snapshot_id: &SnapshotId,
    height: Height,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<(CanisterSnapshot, LoadCanisterMetrics), CheckpointError> {
    let mut durations = BTreeMap::<&str, Duration>::default();

    let into_checkpoint_error =
        |field: String, err: ic_protobuf::proxy::ProxyDecodeError| CheckpointError::ProtoError {
            path: snapshot_layout.raw_path(),
            field,
            proto_err: err.to_string(),
        };

    let starting_time = Instant::now();
    let canister_snapshot_bits: CanisterSnapshotBits = CanisterSnapshotBits::try_from(
        snapshot_layout.snapshot().deserialize()?,
    )
    .map_err(|err| {
        into_checkpoint_error(
            format!("canister_snapshot[{}]::canister_snapshot_bits", snapshot_id),
            err,
        )
    })?;
    durations.insert("canister_snapshot_bits", starting_time.elapsed());

    let execution_snapshot: ExecutionStateSnapshot = {
        let starting_time = Instant::now();
        let wasm_memory_layout = snapshot_layout.vmemory_0();
        let wasm_memory = PageMemory {
            page_map: PageMap::open(
                Box::new(wasm_memory_layout),
                height,
                Arc::clone(&fd_factory),
            )?,
            size: canister_snapshot_bits.wasm_memory_size,
        };
        durations.insert("snapshot_wasm_memory", starting_time.elapsed());

        let starting_time = Instant::now();
        let stable_memory_layout = snapshot_layout.stable_memory();
        let stable_memory = PageMemory {
            page_map: PageMap::open(
                Box::new(stable_memory_layout),
                height,
                Arc::clone(&fd_factory),
            )?,
            size: canister_snapshot_bits.stable_memory_size,
        };
        durations.insert("snapshot_stable_memory", starting_time.elapsed());

        let starting_time = Instant::now();
        let wasm_binary = snapshot_layout
            .wasm()
            .deserialize(canister_snapshot_bits.binary_hash)?;
        durations.insert("snapshot_canister_module", starting_time.elapsed());

        let exported_globals = canister_snapshot_bits.exported_globals.clone();

        ExecutionStateSnapshot {
            wasm_binary,
            exported_globals,
            stable_memory,
            wasm_memory,
        }
    };

    let starting_time = Instant::now();
    let wasm_chunk_store_layout = snapshot_layout.wasm_chunk_store();
    let wasm_chunk_store_data = PageMap::open(
        Box::new(wasm_chunk_store_layout),
        height,
        Arc::clone(&fd_factory),
    )?;
    let wasm_chunk_store = WasmChunkStore::from_checkpoint(
        wasm_chunk_store_data,
        canister_snapshot_bits.wasm_chunk_store_metadata,
    );
    durations.insert("snapshot_wasm_chunk_store", starting_time.elapsed());

    let canister_snapshot = CanisterSnapshot::new(
        canister_snapshot_bits.canister_id,
        canister_snapshot_bits.taken_at_timestamp,
        canister_snapshot_bits.canister_version,
        canister_snapshot_bits.certified_data.clone(),
        wasm_chunk_store,
        execution_snapshot,
        canister_snapshot_bits.total_size,
    );

    let metrics = LoadCanisterMetrics { durations };

    Ok((canister_snapshot, metrics))
}

fn load_snapshot_from_checkpoint(
    checkpoint_layout: &CheckpointLayout<ReadOnly>,
    snapshot_id: &SnapshotId,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<(CanisterSnapshot, LoadCanisterMetrics), CheckpointError> {
    let snapshot_layout = checkpoint_layout.snapshot(snapshot_id)?;
    load_snapshot(
        &snapshot_layout,
        snapshot_id,
        checkpoint_layout.height(),
        Arc::clone(&fd_factory),
    )
}
