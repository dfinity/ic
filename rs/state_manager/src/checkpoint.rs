use crossbeam_channel::{Sender, unbounded};
use ic_base_types::{CanisterId, SnapshotId, subnet_id_try_from_protobuf};
use ic_logger::error;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_snapshots::{
    CanisterSnapshot, CanisterSnapshots, ExecutionStateSnapshot, PageMemory,
};
use ic_replicated_state::canister_state::system_state::wasm_chunk_store::WasmChunkStore;
use ic_replicated_state::page_map::{PageAllocatorFileDescriptor, storage::validate};
use ic_replicated_state::{
    CanisterMetrics, CanisterState, ExecutionState, ReplicatedState, SchedulerState, SystemState,
    canister_state::execution_state::{SandboxMemory, WasmBinary, WasmExecutionMode},
    page_map::PageMap,
};
use ic_replicated_state::{CheckpointLoadingMetrics, Memory};
use ic_state_layout::{
    AccessPolicy, CanisterLayout, CanisterSnapshotBits, CanisterStateBits, CheckpointLayout,
    PageMapLayout, ReadOnly, SnapshotLayout, error::LayoutError, try_mmap_wasm_file,
};
use ic_types::batch::RawQueryStats;
use ic_types::{CanisterTimer, Height, Time};
use ic_utils::thread::maybe_parallel_map;
use ic_validate_eq::ValidateEq;
use std::collections::BTreeMap;
use std::convert::{TryFrom, identity};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{
    CRITICAL_ERROR_CHECKPOINT_SOFT_INVARIANT_BROKEN,
    CRITICAL_ERROR_REPLICATED_STATE_ALTERED_AFTER_CHECKPOINT, CheckpointError, CheckpointMetrics,
    NUMBER_OF_CHECKPOINT_THREADS, PageMapToFlush, TipRequest,
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
/// layout. Returns a layout of the new state that is equivalent to the
/// given one and a result of the operation.
pub(crate) fn make_unvalidated_checkpoint(
    mut state: ReplicatedState,
    height: Height,
    tip_channel: &Sender<TipRequest>,
    metrics: &CheckpointMetrics,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<(Arc<ReplicatedState>, CheckpointLayout<ReadOnly>), Box<dyn std::error::Error + Send>> {
    {
        let _timer = metrics
            .make_checkpoint_step_duration
            .with_label_values(&["flush_page_map_deltas_preprocessing"])
            .start_timer();
        flush_canister_snapshots_and_page_maps(&mut state, height, tip_channel);
    }
    {
        let _timer = metrics
            .make_checkpoint_step_duration
            .with_label_values(&["strip_page_map_deltas"])
            .start_timer();
        strip_page_map_deltas(&mut state, Arc::clone(&fd_factory));
    }

    tip_channel
        .send(TipRequest::FilterTipCanisters {
            height,
            canister_ids: state.canister_states.keys().copied().collect(),
            snapshot_ids: state
                .canister_snapshots
                .iter()
                .map(|(k, _v)| k)
                .copied()
                .collect(),
        })
        .unwrap();

    {
        let _timer = metrics
            .make_checkpoint_step_duration
            .with_label_values(&["wait_for_tip_to_checkpoint"])
            .start_timer();
        #[allow(clippy::disallowed_methods)]
        let (send, recv) = unbounded();
        tip_channel
            .send(TipRequest::TipToCheckpointAndSwitch {
                height,
                state,
                fd_factory,
                sender: send,
            })
            .unwrap();
        recv.recv().unwrap()
    }
}

pub(crate) fn validate_and_finalize_checkpoint_and_remove_unverified_marker(
    checkpoint_layout: &CheckpointLayout<ReadOnly>,
    reference_state: Option<&ReplicatedState>,
    own_subnet_type: SubnetType,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
    metrics: &CheckpointMetrics,
    mut thread_pool: Option<&mut scoped_threadpool::Pool>,
) -> Result<(), CheckpointError> {
    maybe_parallel_map(
        &mut thread_pool,
        checkpoint_layout.all_existing_pagemaps()?.into_iter(),
        |pm| validate(pm),
    )
    .into_iter()
    .try_for_each(identity)?;

    maybe_parallel_map(
        &mut thread_pool,
        checkpoint_layout.all_existing_wasm_files()?.into_iter(),
        |wasm_file| try_mmap_wasm_file(wasm_file),
    )
    .into_iter()
    .try_for_each(identity)?;

    if let Some(reference_state) = reference_state {
        validate_eq_checkpoint(
            checkpoint_layout,
            reference_state,
            own_subnet_type,
            &mut thread_pool,
            fd_factory,
            metrics,
        );
    }
    checkpoint_layout
        .finalize_and_remove_unverified_marker(thread_pool)
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

    validate_and_finalize_checkpoint_and_remove_unverified_marker(
        checkpoint_layout,
        None,
        own_subnet_type,
        fd_factory,
        metrics,
        Some(&mut thread_pool),
    )?;
    Ok(state)
}

/// An enum describing all possible PageMaps in ReplicatedState
/// When adding additional PageMaps, add an appropriate entry here
/// to enable all relevant state manager features, e.g. incremental
/// manifest computations
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub(crate) enum PageMapType {
    WasmMemory(CanisterId),
    StableMemory(CanisterId),
    WasmChunkStore(CanisterId),
    SnapshotWasmMemory(SnapshotId),
    SnapshotStableMemory(SnapshotId),
    SnapshotWasmChunkStore(SnapshotId),
}

impl PageMapType {
    /// List all PageMaps contained in `state`, ignoring PageMaps that are in snapshots.
    fn list_all_without_snapshots(state: &ReplicatedState) -> Vec<PageMapType> {
        let mut result = vec![];
        for (id, canister) in &state.canister_states {
            result.push(Self::WasmChunkStore(id.to_owned()));
            if canister.execution_state.is_some() {
                result.push(Self::WasmMemory(id.to_owned()));
                result.push(Self::StableMemory(id.to_owned()));
            }
        }

        result
    }

    /// List all PageMaps contained in `state`, including those in snapshots.
    pub(crate) fn list_all_including_snapshots(state: &ReplicatedState) -> Vec<PageMapType> {
        let mut result = Self::list_all_without_snapshots(state);
        for (id, _snapshot) in state.canister_snapshots.iter() {
            result.push(Self::SnapshotWasmMemory(id.to_owned()));
            result.push(Self::SnapshotStableMemory(id.to_owned()));
            result.push(Self::SnapshotWasmChunkStore(id.to_owned()));
        }

        result
    }

    /// The layout of the files on disk for this PageMap.
    pub(crate) fn layout<Access>(
        &self,
        layout: &CheckpointLayout<Access>,
    ) -> Result<PageMapLayout<Access>, LayoutError>
    where
        Access: AccessPolicy,
    {
        match &self {
            PageMapType::WasmMemory(id) => Ok(layout.canister(id)?.vmemory_0()),
            PageMapType::StableMemory(id) => Ok(layout.canister(id)?.stable_memory()),
            PageMapType::WasmChunkStore(id) => Ok(layout.canister(id)?.wasm_chunk_store()),
            PageMapType::SnapshotWasmMemory(id) => Ok(layout.snapshot(id)?.vmemory_0()),
            PageMapType::SnapshotStableMemory(id) => Ok(layout.snapshot(id)?.stable_memory()),
            PageMapType::SnapshotWasmChunkStore(id) => Ok(layout.snapshot(id)?.wasm_chunk_store()),
        }
    }

    /// Maps a PageMapType to the the `&PageMap` in `state`
    pub(crate) fn get<'a>(&self, state: &'a ReplicatedState) -> Option<&'a PageMap> {
        match &self {
            PageMapType::WasmMemory(id) => state.canister_state(id).and_then(|can| {
                can.execution_state
                    .as_ref()
                    .map(|ex| &ex.wasm_memory.page_map)
            }),
            PageMapType::StableMemory(id) => state.canister_state(id).and_then(|can| {
                can.execution_state
                    .as_ref()
                    .map(|ex| &ex.stable_memory.page_map)
            }),
            PageMapType::WasmChunkStore(id) => state
                .canister_state(id)
                .map(|can| can.system_state.wasm_chunk_store.page_map()),
            PageMapType::SnapshotWasmMemory(id) => state
                .canister_snapshots
                .get(*id)
                .map(|snap| &snap.execution_snapshot().wasm_memory.page_map),
            PageMapType::SnapshotStableMemory(id) => state
                .canister_snapshots
                .get(*id)
                .map(|snap| &snap.execution_snapshot().stable_memory.page_map),
            PageMapType::SnapshotWasmChunkStore(id) => state
                .canister_snapshots
                .get(*id)
                .map(|snap| snap.chunk_store().page_map()),
        }
    }
}

/// Strips away the deltas from all page maps of the replicated state.
/// We execute this procedure before making a checkpoint because we
/// don't want those deltas to be persisted to TIP as we apply deltas
/// incrementally.
fn strip_page_map_deltas(
    state: &mut ReplicatedState,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) {
    for (_id, canister) in state.canister_states.iter_mut() {
        canister
            .system_state
            .wasm_chunk_store
            .page_map_mut()
            .strip_all_deltas(Arc::clone(&fd_factory));
        if let Some(execution_state) = canister.execution_state.as_mut() {
            execution_state
                .wasm_memory
                .page_map
                .strip_all_deltas(Arc::clone(&fd_factory));
            execution_state
                .stable_memory
                .page_map
                .strip_all_deltas(Arc::clone(&fd_factory));
        }
    }

    for (_id, canister_snapshot) in state.canister_snapshots.iter_mut() {
        let new_snapshot = Arc::make_mut(canister_snapshot);
        new_snapshot
            .chunk_store_mut()
            .page_map_mut()
            .strip_all_deltas(Arc::clone(&fd_factory));
        new_snapshot
            .execution_snapshot_mut()
            .wasm_memory
            .page_map
            .strip_all_deltas(Arc::clone(&fd_factory));
        new_snapshot
            .execution_snapshot_mut()
            .stable_memory
            .page_map
            .strip_all_deltas(Arc::clone(&fd_factory));
    }

    // Reset the sandbox state to force full synchronization on the next execution
    // since the page deltas are out of sync now.
    for canister in state.canisters_iter_mut() {
        if let Some(execution_state) = &mut canister.execution_state {
            execution_state.wasm_memory.sandbox_memory = SandboxMemory::new();
            execution_state.stable_memory.sandbox_memory = SandboxMemory::new();
        }
    }
}

/// Flushes to disk all the canister heap deltas accumulated in memory
/// during execution from the last flush.
pub(crate) fn flush_canister_snapshots_and_page_maps(
    tip_state: &mut ReplicatedState,
    height: Height,
    tip_channel: &Sender<TipRequest>,
) {
    let mut pagemaps = Vec::new();

    let mut add_to_pagemaps_and_strip = |entry, page_map: &mut PageMap| {
        // In cases where a PageMap's data has to be wiped, execution will replace the PageMap with a newly
        // created one. In these cases, we also need to wipe the data from the file on disk.
        // If the PageMap represents a new file, then the base_height will be None, as we set base_height only
        // when loading a PageMap from a checkpoint. Furthermore, we only want to wipe data from the file on
        // disk before applying any unflushed deltas of that PageMap. We detect this case by looking at
        // has_stripped_unflushed_deltas, which will be false at the beginning, but true as soon as we strip unflushed
        // deltas for the first time in the lifetime of the PageMap. As a result, if there is no base_height and
        // we have not persisted unflushed deltas before, then there are no relevant pages beyond the ones in the
        // unlushed delta, and we truncate the file on disk to size 0.
        let truncate = page_map.base_height.is_none() && !page_map.has_stripped_unflushed_deltas();
        let page_map_clone = if !page_map.unflushed_delta_is_empty() {
            Some(page_map.clone())
        } else {
            None
        };
        if truncate || page_map_clone.is_some() {
            pagemaps.push(PageMapToFlush {
                page_map_type: entry,
                truncate,
                page_map: page_map_clone,
            });
        }
        // We strip empty unflushed deltas to keep has_stripped_unflushed_deltas() correct
        page_map.strip_unflushed_delta();
    };

    for (id, canister) in tip_state.canister_states.iter_mut() {
        add_to_pagemaps_and_strip(
            PageMapType::WasmChunkStore(id.to_owned()),
            canister.system_state.wasm_chunk_store.page_map_mut(),
        );
        if let Some(execution_state) = canister.execution_state.as_mut() {
            add_to_pagemaps_and_strip(
                PageMapType::WasmMemory(id.to_owned()),
                &mut execution_state.wasm_memory.page_map,
            );
            add_to_pagemaps_and_strip(
                PageMapType::StableMemory(id.to_owned()),
                &mut execution_state.stable_memory.page_map,
            );
        }
    }

    for (snapshot_id, canister_snapshot) in tip_state.canister_snapshots.iter_mut() {
        let new_snapshot = Arc::make_mut(canister_snapshot);

        add_to_pagemaps_and_strip(
            PageMapType::SnapshotWasmChunkStore(*snapshot_id),
            new_snapshot.chunk_store_mut().page_map_mut(),
        );
        add_to_pagemaps_and_strip(
            PageMapType::SnapshotWasmMemory(*snapshot_id),
            &mut new_snapshot.execution_snapshot_mut().wasm_memory.page_map,
        );
        add_to_pagemaps_and_strip(
            PageMapType::SnapshotStableMemory(*snapshot_id),
            &mut new_snapshot.execution_snapshot_mut().stable_memory.page_map,
        );
    }

    // Take all snapshot operations that happened since the last flush and clear the list stored in `tip_state`.
    // This way each operation is executed exactly once, independent of how many times `flush_page_maps` is called.
    let unflushed_checkpoint_ops = tip_state.metadata.unflushed_checkpoint_ops.take();

    tip_channel
        .send(TipRequest::FlushPageMapDelta {
            height,
            pagemaps,
            unflushed_checkpoint_ops,
        })
        .unwrap();
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

    fn load_refunds(&self) -> Result<ic_replicated_state::RefundPool, CheckpointError> {
        let _timer = self
            .metrics
            .load_checkpoint_step_duration
            .with_label_values(&["refunds"])
            .start_timer();

        ic_replicated_state::RefundPool::try_from((
            self.checkpoint_layout.refunds().deserialize()?,
            &self.metrics as &dyn CheckpointLoadingMetrics,
        ))
        .map_err(|err| self.map_to_checkpoint_error("RefundPool".into(), err))
    }

    fn load_epoch_query_stats(&self) -> Result<RawQueryStats, CheckpointError> {
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

    fn validate_eq_canister_states(
        &self,
        thread_pool: &mut Option<&mut scoped_threadpool::Pool>,
        ref_canister_states: &BTreeMap<CanisterId, CanisterState>,
    ) -> Result<(), String> {
        let on_disk_canister_ids = self
            .checkpoint_layout
            .canister_ids()
            .map_err(|err| format!("Canister Validation: failed to load canister ids: {err}"))?;
        let ref_canister_ids: Vec<_> = ref_canister_states.keys().copied().collect();
        debug_assert!(on_disk_canister_ids.is_sorted());
        debug_assert!(ref_canister_ids.is_sorted());
        if on_disk_canister_ids != ref_canister_ids {
            return Err("Canister ids mismatch".to_string());
        }
        maybe_parallel_map(thread_pool, ref_canister_ids.iter(), |canister_id| {
            load_canister_state_from_checkpoint(
                &self.checkpoint_layout,
                canister_id,
                Arc::clone(&self.fd_factory),
                &self.metrics,
            )
            .map_err(|err| {
                format!(
                    "Failed to load canister state for validation for key #{canister_id}: {err}"
                )
            })?
            .0
            .validate_eq(
                ref_canister_states
                    .get(canister_id)
                    .expect("Failed to get canister from canister_states"),
            )
        })
        .into_iter()
        .try_for_each(identity)
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

    fn validate_eq_canister_snapshots(
        &self,
        thread_pool: &mut Option<&mut scoped_threadpool::Pool>,
        ref_canister_snapshots: &CanisterSnapshots,
    ) -> Result<(), String> {
        let mut on_disk_snapshot_ids = self.checkpoint_layout.snapshot_ids().map_err(|err| {
            format!("Snapshot validation: failed to load list of snapshot ids: {err}")
        })?;
        let mut ref_snapshot_ids: Vec<_> = ref_canister_snapshots.iter().map(|x| *x.0).collect();
        on_disk_snapshot_ids.sort();
        ref_snapshot_ids.sort();
        if on_disk_snapshot_ids != ref_snapshot_ids {
            return Err("Snapshot ids mismatch".to_string());
        }
        maybe_parallel_map(thread_pool, ref_snapshot_ids.iter(), |snapshot_id| {
            load_snapshot_from_checkpoint(
                &self.checkpoint_layout,
                snapshot_id,
                Arc::clone(&self.fd_factory),
            )
            .map_err(|err| {
                format!("Failed to load canister snapshot {snapshot_id} for validation: {err}")
            })?
            .0
            .validate_eq(
                ref_canister_snapshots
                    .get(**snapshot_id)
                    .expect("Failed to lookup snapshot in ref state"),
            )
        })
        .into_iter()
        .try_for_each(identity)
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
        checkpoint_loader.load_refunds()?,
        checkpoint_loader.load_epoch_query_stats()?,
        checkpoint_loader.load_canister_snapshots(&mut thread_pool)?,
    ))
}

pub fn validate_eq_checkpoint(
    checkpoint_layout: &CheckpointLayout<ReadOnly>,
    reference_state: &ReplicatedState,
    own_subnet_type: SubnetType,
    thread_pool: &mut Option<&mut scoped_threadpool::Pool>,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>, //
    metrics: &CheckpointMetrics, // Make optional in the loader & don't provide?
) {
    validate_eq_checkpoint_internal(
        checkpoint_layout,
        reference_state,
        own_subnet_type,
        thread_pool,
        fd_factory,
        metrics,
    )
    .unwrap_or_else(|err: String| {
        error!(
            &metrics.log,
            "{}: Replicated state altered: {}",
            CRITICAL_ERROR_REPLICATED_STATE_ALTERED_AFTER_CHECKPOINT,
            err
        );
        metrics.replicated_state_altered_after_checkpoint.inc();
    });
}

fn validate_eq_checkpoint_internal(
    checkpoint_layout: &CheckpointLayout<ReadOnly>,
    reference_state: &ReplicatedState,
    own_subnet_type: SubnetType,
    thread_pool: &mut Option<&mut scoped_threadpool::Pool>,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>, //
    metrics: &CheckpointMetrics, // Make optional in the loader & don't provide?
) -> Result<(), String> {
    let (
        canister_states,
        metadata,
        subnet_queues,
        refunds,
        consensus_queue,
        epoch_query_stats,
        canister_snapshots,
    ) = reference_state.component_refs();

    let checkpoint_loader = CheckpointLoader {
        checkpoint_layout: checkpoint_layout.clone(),
        own_subnet_type,
        metrics: metrics.clone(),
        fd_factory,
    };

    checkpoint_loader.validate_eq_canister_states(thread_pool, canister_states)?;
    checkpoint_loader
        .load_system_metadata()
        .map_err(|err| format!("Failed to load system metadata: {err}"))?
        .validate_eq(metadata)?;
    if !metadata.unflushed_checkpoint_ops.is_empty() {
        return Err("Metadata has unflushed changes after checkpoint".to_string());
    }
    checkpoint_loader
        .load_subnet_queues()
        .unwrap()
        .validate_eq(subnet_queues)?;
    checkpoint_loader
        .load_refunds()
        .unwrap()
        .validate_eq(refunds)?;
    if checkpoint_loader.load_epoch_query_stats().unwrap() != *epoch_query_stats {
        return Err("query_stats has diverged.".to_string());
    }
    if !consensus_queue.is_empty() {
        return Err("consensus_queue is not empty".to_string());
    }
    checkpoint_loader.validate_eq_canister_snapshots(thread_pool, canister_snapshots)
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
                format!("canister_states[{canister_id}]::canister_state_bits"),
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
                    .lazy_load_with_module_hash(execution_state_bits.binary_hash, None)?,
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
                wasm_execution_mode: WasmExecutionMode::from_is_wasm64(
                    execution_state_bits.is_wasm64,
                ),
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
            format!("canister_states[{canister_id}]::system_state::queues"),
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
        canister_state_bits.task_queue,
        CanisterTimer::from_nanos_since_unix_epoch(canister_state_bits.global_timer_nanos),
        canister_state_bits.canister_version,
        canister_state_bits.canister_history,
        wasm_chunk_store_data,
        canister_state_bits.wasm_chunk_store_metadata,
        canister_state_bits.log_visibility,
        canister_state_bits.log_memory_limit,
        canister_state_bits.canister_log,
        canister_state_bits.wasm_memory_limit,
        canister_state_bits.next_snapshot_id,
        canister_state_bits.snapshots_memory_usage,
        canister_state_bits.environment_variables,
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
            format!("canister_snapshot[{snapshot_id}]::canister_snapshot_bits"),
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
            .lazy_load_with_module_hash(canister_snapshot_bits.binary_hash, None)?;
        durations.insert("snapshot_canister_module", starting_time.elapsed());

        let exported_globals = canister_snapshot_bits.exported_globals.clone();
        let global_timer = canister_snapshot_bits.global_timer;
        let on_low_wasm_memory_hook_status = canister_snapshot_bits.on_low_wasm_memory_hook_status;
        ExecutionStateSnapshot {
            wasm_binary,
            exported_globals,
            stable_memory,
            wasm_memory,
            global_timer,
            on_low_wasm_memory_hook_status,
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
        canister_snapshot_bits.source,
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
