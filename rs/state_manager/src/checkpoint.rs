use crate::{
    pagemaptypes_with_num_pages, CheckpointError, CheckpointMetrics, HasDowngrade, TipRequest,
    CRITICAL_ERROR_CHECKPOINT_SOFT_INVARIANT_BROKEN, NUMBER_OF_CHECKPOINT_THREADS,
};
use crossbeam_channel::{unbounded, Sender};
use ic_base_types::{subnet_id_try_from_protobuf, CanisterId, SnapshotId};
use ic_config::flag_status::FlagStatus;
use ic_logger::error;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_snapshots::{
    CanisterSnapshot, CanisterSnapshots, ExecutionStateSnapshot, PageMemory,
};
use ic_replicated_state::canister_state::system_state::wasm_chunk_store::WasmChunkStore;
use ic_replicated_state::page_map::PageAllocatorFileDescriptor;
use ic_replicated_state::{
    canister_state::execution_state::WasmBinary, page_map::PageMap, CanisterMetrics, CanisterState,
    ExecutionState, ReplicatedState, SchedulerState, SystemState,
};
use ic_replicated_state::{CheckpointLoadingMetrics, Memory};
use ic_state_layout::{
    CanisterLayout, CanisterSnapshotBits, CanisterStateBits, CheckpointLayout, ReadOnly,
    ReadPolicy, SnapshotLayout,
};
use ic_types::batch::RawQueryStats;
use ic_types::{CanisterTimer, Height, Time};
use ic_utils::thread::parallel_map;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
                    pagemaptypes_with_num_pages: pagemaptypes_with_num_pages(state),
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

    cp.remove_unverified_checkpoint_marker()?;

    Ok((cp, state, has_downgrade))
}

/// Calls [load_checkpoint] with a newly created thread pool.
/// See [load_checkpoint] for further details.
pub fn load_checkpoint_parallel(
    checkpoint_layout: &CheckpointLayout<ReadOnly>,
    own_subnet_type: SubnetType,
    metrics: &CheckpointMetrics,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<ReplicatedState, CheckpointError> {
    let mut thread_pool = scoped_threadpool::Pool::new(NUMBER_OF_CHECKPOINT_THREADS);

    load_checkpoint(
        checkpoint_layout,
        own_subnet_type,
        metrics,
        Some(&mut thread_pool),
        Arc::clone(&fd_factory),
    )
}

/// Calls [load_checkpoint_parallel] and removes the unverified checkpoint marker.
/// This combination is useful when marking a checkpoint as verified immediately after a successful loading.
pub fn load_checkpoint_parallel_and_mark_verified(
    checkpoint_layout: &CheckpointLayout<ReadOnly>,
    own_subnet_type: SubnetType,
    metrics: &CheckpointMetrics,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<ReplicatedState, CheckpointError> {
    let state = load_checkpoint_parallel(checkpoint_layout, own_subnet_type, metrics, fd_factory)?;
    checkpoint_layout
        .remove_unverified_checkpoint_marker()
        .map_err(CheckpointError::from)?;
    Ok(state)
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
    let into_checkpoint_error =
        |field: String, err: ic_protobuf::proxy::ProxyDecodeError| CheckpointError::ProtoError {
            path: checkpoint_layout.raw_path().into(),
            field,
            proto_err: err.to_string(),
        };

    let metadata = {
        let _timer = metrics
            .load_checkpoint_step_duration
            .with_label_values(&["system_metadata"])
            .start_timer();

        let ingress_history_proto = checkpoint_layout.ingress_history().deserialize()?;
        let ingress_history =
            ic_replicated_state::IngressHistoryState::try_from(ingress_history_proto)
                .map_err(|err| into_checkpoint_error("IngressHistoryState".into(), err))?;
        let metadata_proto = checkpoint_layout.system_metadata().deserialize()?;
        let mut metadata = ic_replicated_state::SystemMetadata::try_from((
            metadata_proto,
            metrics as &dyn CheckpointLoadingMetrics,
        ))
        .map_err(|err| into_checkpoint_error("SystemMetadata".into(), err))?;
        metadata.ingress_history = ingress_history;
        metadata.own_subnet_type = own_subnet_type;

        if let Some(split_from) = checkpoint_layout.split_marker().deserialize()?.subnet_id {
            metadata.split_from = Some(
                subnet_id_try_from_protobuf(split_from)
                    .map_err(|err| into_checkpoint_error("split_from".into(), err))?,
            );
        }

        metadata
    };

    let subnet_queues = {
        let _timer = metrics
            .load_checkpoint_step_duration
            .with_label_values(&["subnet_queues"])
            .start_timer();

        ic_replicated_state::CanisterQueues::try_from((
            checkpoint_layout.subnet_queues().deserialize()?,
            metrics as &dyn CheckpointLoadingMetrics,
        ))
        .map_err(|err| into_checkpoint_error("CanisterQueues".into(), err))?
    };

    let stats = checkpoint_layout.stats().deserialize()?;
    let query_stats = if let Some(query_stats) = stats.query_stats {
        RawQueryStats::try_from(query_stats)
            .map_err(|err| into_checkpoint_error("QueryStats".into(), err))?
    } else {
        RawQueryStats::default()
    };

    let canister_states = {
        let _timer = metrics
            .load_checkpoint_step_duration
            .with_label_values(&["canister_states"])
            .start_timer();

        let mut canister_states = BTreeMap::new();
        let canister_ids = checkpoint_layout.canister_ids()?;
        match thread_pool {
            Some(ref mut thread_pool) => {
                let results = parallel_map(thread_pool, canister_ids.iter(), |canister_id| {
                    load_canister_state_from_checkpoint(
                        checkpoint_layout,
                        canister_id,
                        Arc::clone(&fd_factory),
                        metrics,
                    )
                });

                for canister_state in results.into_iter() {
                    let (canister_state, durations) = canister_state?;
                    canister_states
                        .insert(canister_state.system_state.canister_id(), canister_state);

                    durations.apply(metrics);
                }
            }
            None => {
                for canister_id in canister_ids.iter() {
                    let (canister_state, durations) = load_canister_state_from_checkpoint(
                        checkpoint_layout,
                        canister_id,
                        Arc::clone(&fd_factory),
                        metrics,
                    )?;
                    canister_states
                        .insert(canister_state.system_state.canister_id(), canister_state);

                    durations.apply(metrics);
                }
            }
        }

        canister_states
    };

    let canister_snapshots = {
        let _timer = metrics
            .load_checkpoint_step_duration
            .with_label_values(&["canister_snapshots"])
            .start_timer();

        let mut canister_snapshots = BTreeMap::new();
        let snapshot_ids = checkpoint_layout.snapshot_ids()?;
        match thread_pool {
            Some(thread_pool) => {
                let results = parallel_map(thread_pool, snapshot_ids.iter(), |snapshot_id| {
                    (
                        **snapshot_id,
                        load_snapshot_from_checkpoint(
                            checkpoint_layout,
                            snapshot_id,
                            Arc::clone(&fd_factory),
                        ),
                    )
                });

                for (snapshot_id, canister_snapshot) in results.into_iter() {
                    let (canister_snapshot, durations) = canister_snapshot?;
                    canister_snapshots.insert(snapshot_id, Arc::new(canister_snapshot));

                    durations.apply(metrics);
                }
            }
            None => {
                for snapshot_id in snapshot_ids.iter() {
                    let (canister_snapshot, durations) = load_snapshot_from_checkpoint(
                        checkpoint_layout,
                        snapshot_id,
                        Arc::clone(&fd_factory),
                    )?;
                    canister_snapshots.insert(*snapshot_id, Arc::new(canister_snapshot));

                    durations.apply(metrics);
                }
            }
        }

        CanisterSnapshots::new(canister_snapshots)
    };

    let state = ReplicatedState::new_from_checkpoint(
        canister_states,
        metadata,
        subnet_queues,
        query_stats,
        canister_snapshots,
    );

    Ok(state)
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
                PageMap::open(&wasm_memory_layout, height, Arc::clone(&fd_factory))?,
                execution_state_bits.heap_size,
            );
            durations.insert("wasm_memory", starting_time.elapsed());

            let starting_time = Instant::now();
            let stable_memory_layout = canister_layout.stable_memory();
            let stable_memory = Memory::new(
                PageMap::open(&stable_memory_layout, height, Arc::clone(&fd_factory))?,
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
                wasm_memory,
                stable_memory,
                exported_globals: execution_state_bits.exported_globals,
                exports: execution_state_bits.exports,
                metadata: execution_state_bits.metadata,
                last_executed_round: execution_state_bits.last_executed_round,
                next_scheduled_method: execution_state_bits.next_scheduled_method,
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
    let wasm_chunk_store_data =
        PageMap::open(&wasm_chunk_store_layout, height, Arc::clone(&fd_factory))?;
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

pub fn load_snapshot<P: ReadPolicy>(
    snapshot_layout: &SnapshotLayout<P>,
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
            page_map: PageMap::open(&wasm_memory_layout, height, Arc::clone(&fd_factory))?,
            size: canister_snapshot_bits.wasm_memory_size,
        };
        durations.insert("snapshot_wasm_memory", starting_time.elapsed());

        let starting_time = Instant::now();
        let stable_memory_layout = snapshot_layout.stable_memory();
        let stable_memory = PageMemory {
            page_map: PageMap::open(&stable_memory_layout, height, Arc::clone(&fd_factory))?,
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
    let wasm_chunk_store_data =
        PageMap::open(&wasm_chunk_store_layout, height, Arc::clone(&fd_factory))?;
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

fn load_snapshot_from_checkpoint<P: ReadPolicy>(
    checkpoint_layout: &CheckpointLayout<P>,
    snapshot_id: &SnapshotId,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<(CanisterSnapshot, LoadCanisterMetrics), CheckpointError> {
    let snapshot_layout = checkpoint_layout.snapshot(snapshot_id)?;
    load_snapshot::<P>(
        &snapshot_layout,
        snapshot_id,
        checkpoint_layout.height(),
        Arc::clone(&fd_factory),
    )
}
