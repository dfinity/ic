use super::PageAllocatorFileDescriptorImpl;
use crate::{
    CheckpointError, CheckpointMetrics, PageMapType, PersistenceError, TipRequest,
    NUMBER_OF_CHECKPOINT_THREADS,
};
use crossbeam_channel::{unbounded, Sender};
use ic_base_types::CanisterId;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::page_map::PageAllocatorFileDescriptor;
use ic_replicated_state::Memory;
use ic_replicated_state::{
    bitcoin_state::{BitcoinState, UtxoSet},
    canister_state::execution_state::WasmBinary,
    page_map::PageMap,
    CanisterMetrics, CanisterState, ExecutionState, ReplicatedState, SchedulerState, SystemState,
};
use ic_state_layout::{
    BitcoinStateBits, CanisterLayout, CanisterStateBits, CheckpointLayout, ReadOnly, ReadPolicy,
};
use ic_types::{CanisterTimer, Height, LongExecutionMode, Time};
use ic_utils::thread::parallel_map;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{
    convert::{From, TryFrom},
    path::Path,
};

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
pub fn make_checkpoint(
    state: &ReplicatedState,
    height: Height,
    tip_channel: &Sender<TipRequest>,
    metrics: &CheckpointMetrics,
    thread_pool: &mut scoped_threadpool::Pool,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<(CheckpointLayout<ReadOnly>, ReplicatedState), CheckpointError> {
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

    let cp = {
        let _timer = metrics
            .make_checkpoint_step_duration
            .with_label_values(&["tip_to_checkpoint"])
            .start_timer();
        let (send, recv) = unbounded();
        tip_channel
            .send(TipRequest::TipToCheckpoint {
                height,
                sender: send,
            })
            .unwrap();
        recv.recv().unwrap()?
    };

    // Wait for reset_tip_to so that we don't reflink in parallel with other operations.
    let (send, recv) = unbounded();
    tip_channel.send(TipRequest::Wait { sender: send }).unwrap();
    recv.recv().unwrap();

    tip_channel
        .send(TipRequest::DefragTip {
            height,
            page_map_types: PageMapType::list_all(state),
        })
        .unwrap();

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

    Ok((cp, state))
}
/// Calls [load_checkpoint] with a newly created thread pool.
/// See [load_checkpoint] for further details.
pub fn load_checkpoint_parallel<P: ReadPolicy + Send + Sync>(
    checkpoint_layout: &CheckpointLayout<P>,
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

/// loads the node state heighted with `height` using the specified
/// directory layout.
pub fn load_checkpoint<P: ReadPolicy + Send + Sync>(
    checkpoint_layout: &CheckpointLayout<P>,
    own_subnet_type: SubnetType,
    metrics: &CheckpointMetrics,
    thread_pool: Option<&mut scoped_threadpool::Pool>,
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

        let mut metadata = ic_replicated_state::SystemMetadata::try_from(
            checkpoint_layout.system_metadata().deserialize()?,
        )
        .map_err(|err| into_checkpoint_error("SystemMetadata".into(), err))?;
        metadata.own_subnet_type = own_subnet_type;
        metadata
    };

    let subnet_queues = {
        let _timer = metrics
            .load_checkpoint_step_duration
            .with_label_values(&["subnet_queues"])
            .start_timer();

        ic_replicated_state::CanisterQueues::try_from(
            checkpoint_layout.subnet_queues().deserialize()?,
        )
        .map_err(|err| into_checkpoint_error("CanisterQueues".into(), err))?
    };

    let canister_states = {
        let _timer = metrics
            .load_checkpoint_step_duration
            .with_label_values(&["canister_states"])
            .start_timer();

        let mut canister_states = BTreeMap::new();
        let canister_ids = checkpoint_layout.canister_ids()?;
        match thread_pool {
            Some(thread_pool) => {
                let results = parallel_map(thread_pool, canister_ids.iter(), |canister_id| {
                    load_canister_state_from_checkpoint(
                        checkpoint_layout,
                        canister_id,
                        Arc::clone(&fd_factory),
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
                    )?;
                    canister_states
                        .insert(canister_state.system_state.canister_id(), canister_state);

                    durations.apply(metrics);
                }
            }
        }

        canister_states
    };

    let bitcoin = {
        let _timer = metrics
            .load_checkpoint_step_duration
            .with_label_values(&["bitcoin"])
            .start_timer();

        load_bitcoin_state(checkpoint_layout)?
    };

    let state =
        ReplicatedState::new_from_checkpoint(canister_states, metadata, subnet_queues, bitcoin);

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

pub fn load_canister_state<P: ReadPolicy>(
    canister_layout: &CanisterLayout<P>,
    canister_id: &CanisterId,
    height: Height,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
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

    let session_nonce = None;

    let execution_state = match canister_state_bits.execution_state_bits {
        Some(execution_state_bits) => {
            let starting_time = Instant::now();
            let wasm_memory = Memory::new(
                PageMap::open(
                    &canister_layout.vmemory_0(),
                    height,
                    Arc::clone(&fd_factory),
                )?,
                execution_state_bits.heap_size,
            );
            durations.insert("wasm_memory", starting_time.elapsed());

            let starting_time = Instant::now();
            let stable_memory = Memory::new(
                PageMap::open(
                    &canister_layout.stable_memory_blob(),
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
                session_nonce,
                wasm_binary,
                wasm_memory,
                stable_memory,
                exported_globals: execution_state_bits.exported_globals,
                exports: execution_state_bits.exports,
                metadata: execution_state_bits.metadata,
                last_executed_round: execution_state_bits.last_executed_round,
            })
        }
        None => None,
    };

    let starting_time = Instant::now();
    let queues =
        ic_replicated_state::CanisterQueues::try_from(canister_layout.queues().deserialize()?)
            .map_err(|err| {
                into_checkpoint_error(
                    format!("canister_states[{}]::system_state::queues", canister_id),
                    err,
                )
            })?;
    durations.insert("canister_queues", starting_time.elapsed());

    let canister_metrics = CanisterMetrics {
        scheduled_as_first: canister_state_bits.scheduled_as_first,
        skipped_round_due_to_no_messages: canister_state_bits.skipped_round_due_to_no_messages,
        executed: canister_state_bits.executed,
        interruped_during_execution: canister_state_bits.interruped_during_execution,
        consumed_cycles_since_replica_started: canister_state_bits
            .consumed_cycles_since_replica_started,
    };
    let system_state = SystemState::new_from_checkpoint(
        canister_state_bits.controllers,
        *canister_id,
        queues,
        canister_state_bits.memory_allocation,
        canister_state_bits.freeze_threshold,
        canister_state_bits.status,
        canister_state_bits.certified_data,
        canister_metrics,
        canister_state_bits.cycles_balance,
        canister_state_bits.cycles_debit,
        canister_state_bits.task_queue.into_iter().collect(),
        CanisterTimer::from_nanos_since_unix_epoch(canister_state_bits.global_timer_nanos),
        canister_state_bits.canister_version,
    );

    let canister_state = CanisterState {
        system_state,
        execution_state,
        scheduler_state: SchedulerState {
            last_full_execution_round: canister_state_bits.last_full_execution_round,
            compute_allocation: canister_state_bits.compute_allocation,
            accumulated_priority: canister_state_bits.accumulated_priority,
            // Longs executions get aborted at the checkpoint,
            // so both the credit and the execution mode below are set to their defaults.
            priority_credit: Default::default(),
            long_execution_mode: LongExecutionMode::default(),
            heap_delta_debit: canister_state_bits.heap_delta_debit,
            install_code_debit: canister_state_bits.install_code_debit,
            time_of_last_allocation_charge: Time::from_nanos_since_unix_epoch(
                canister_state_bits.time_of_last_allocation_charge_nanos,
            ),
        },
    };

    let metrics = LoadCanisterMetrics { durations };

    Ok((canister_state, metrics))
}

fn load_canister_state_from_checkpoint<P: ReadPolicy>(
    checkpoint_layout: &CheckpointLayout<P>,
    canister_id: &CanisterId,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<(CanisterState, LoadCanisterMetrics), CheckpointError> {
    let canister_layout = checkpoint_layout.canister(canister_id)?;
    load_canister_state::<P>(
        &canister_layout,
        canister_id,
        checkpoint_layout.height(),
        Arc::clone(&fd_factory),
    )
}

fn load_bitcoin_state<P: ReadPolicy>(
    checkpoint_layout: &CheckpointLayout<P>,
) -> Result<BitcoinState, CheckpointError> {
    let layout = checkpoint_layout.bitcoin()?;
    let height = checkpoint_layout.height();

    let into_checkpoint_error =
        |field: String, err: ic_protobuf::proxy::ProxyDecodeError| CheckpointError::ProtoError {
            path: layout.raw_path(),
            field,
            proto_err: err.to_string(),
        };

    let bitcoin_state_proto = layout.bitcoin_state().deserialize_opt()?;

    let bitcoin_state_bits: BitcoinStateBits =
        BitcoinStateBits::try_from(bitcoin_state_proto.unwrap_or_default())
            .map_err(|err| into_checkpoint_error(String::from("BitcoinStateBits"), err))?;

    // Create a page allocator file descriptor factory for the bitcoin canister.
    // TODO: this code will be removed together with the bitcoin canister.
    let fd_factory: Arc<dyn PageAllocatorFileDescriptor> =
        Arc::new(PageAllocatorFileDescriptorImpl::new(layout.raw_path()));

    let utxos_small =
        load_or_create_pagemap(&layout.utxos_small(), height, Arc::clone(&fd_factory))?;
    let utxos_medium =
        load_or_create_pagemap(&layout.utxos_medium(), height, Arc::clone(&fd_factory))?;
    let address_outpoints =
        load_or_create_pagemap(&layout.address_outpoints(), height, Arc::clone(&fd_factory))?;

    Ok(BitcoinState {
        adapter_queues: bitcoin_state_bits.adapter_queues,
        unstable_blocks: bitcoin_state_bits.unstable_blocks,
        stable_height: bitcoin_state_bits.stable_height,
        utxo_set: UtxoSet {
            network: bitcoin_state_bits.network,
            utxos_small,
            utxos_medium,
            utxos_large: bitcoin_state_bits.utxos_large,
            address_outpoints,
        },
        fee_percentiles_cache: None,
    })
}

fn load_or_create_pagemap(
    path: &Path,
    height: Height,
    fd_factory: Arc<dyn PageAllocatorFileDescriptor>,
) -> Result<PageMap, PersistenceError> {
    if path.exists() {
        PageMap::open(path, height, fd_factory)
    } else {
        Ok(PageMap::new(fd_factory))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{spawn_tip_thread, StateManagerMetrics, NUMBER_OF_CHECKPOINT_THREADS};
    use ic_base_types::NumSeconds;
    use ic_ic00_types::CanisterStatusType;
    use ic_metrics::MetricsRegistry;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        canister_state::execution_state::WasmBinary,
        canister_state::execution_state::WasmMetadata,
        page_map::{self, TestPageAllocatorFileDescriptorImpl},
        testing::ReplicatedStateTesting,
        CallContextManager, CanisterStatus, ExecutionState, ExportedFunctions, NumWasmPages,
        PageIndex,
    };
    use ic_state_layout::StateLayout;
    use ic_sys::PAGE_SIZE;
    use ic_test_utilities::{
        state::{canister_ids, new_canister_state},
        types::{
            ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id},
            messages::IngressBuilder,
        },
    };
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_tmpdir::tmpdir;
    use ic_types::messages::StopCanisterContext;
    use ic_types::{CanisterId, Cycles, ExecutionRound, Height};
    use ic_wasm_types::CanisterModule;
    use std::collections::BTreeSet;

    const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

    fn state_manager_metrics() -> StateManagerMetrics {
        let metrics_registry = ic_metrics::MetricsRegistry::new();
        StateManagerMetrics::new(&metrics_registry)
    }

    fn thread_pool() -> scoped_threadpool::Pool {
        scoped_threadpool::Pool::new(NUMBER_OF_CHECKPOINT_THREADS)
    }

    fn empty_wasm() -> CanisterModule {
        CanisterModule::new(vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x04, 0x6e, 0x61, 0x6d,
            0x65, 0x02, 0x01, 0x00,
        ])
    }

    fn one_page_of(byte: u8) -> Memory {
        let contents = [byte; PAGE_SIZE];
        let delta = &[(PageIndex::from(0), &contents)];
        let mut page_map = PageMap::new_for_testing();
        page_map.update(delta);
        Memory::new(page_map, NumWasmPages::from(1))
    }

    fn mark_readonly(path: &std::path::Path) -> std::io::Result<()> {
        let mut permissions = path.metadata()?.permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(path, permissions)
    }

    fn make_checkpoint_and_get_state(
        state: &ReplicatedState,
        height: Height,
        tip_channel: &Sender<TipRequest>,
    ) -> ReplicatedState {
        make_checkpoint(
            state,
            height,
            tip_channel,
            &state_manager_metrics().checkpoint_metrics,
            &mut thread_pool(),
            Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
        )
        .unwrap_or_else(|err| panic!("Expected make_checkpoint to succeed, got {:?}", err))
        .1
    }

    #[test]
    fn can_make_a_checkpoint() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let layout =
                StateLayout::try_new(log.clone(), root.clone(), &MetricsRegistry::new()).unwrap();
            let tip_handler = layout.capture_tip_handler();
            let (_tip_thread, tip_channel) =
                spawn_tip_thread(log, tip_handler, layout.clone(), state_manager_metrics());

            const HEIGHT: Height = Height::new(42);
            let canister_id = canister_test_id(10);

            let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
            state.put_canister_state(new_canister_state(
                canister_id,
                user_test_id(24).get(),
                INITIAL_CYCLES,
                NumSeconds::from(100_000),
            ));

            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel);

            // Ensure that checkpoint data is now available via layout API.
            assert_eq!(layout.checkpoint_heights().unwrap(), vec![HEIGHT]);
            let checkpoint = layout.checkpoint(HEIGHT).unwrap();
            assert_eq!(checkpoint.canister_ids().unwrap(), vec![canister_id]);
            assert!(checkpoint
                .canister(&canister_id)
                .unwrap()
                .queues()
                .deserialize()
                .is_ok());

            // Ensure the expected paths actually exist.
            let checkpoint_path = root.join("checkpoints").join("000000000000002a");
            let canister_path = checkpoint_path
                .join("canister_states")
                .join("000000000000000a0101");

            let expected_paths = vec![
                checkpoint_path.join("system_metadata.pbuf"),
                canister_path.join("queues.pbuf"),
                canister_path.join("canister.pbuf"),
            ];

            for path in expected_paths {
                assert!(path.exists(), "Expected path {} to exist", path.display());
                assert!(
                    path.metadata().unwrap().permissions().readonly(),
                    "Expected path {} to be readonly",
                    path.display()
                );
            }
        });
    }

    #[test]
    fn scratchpad_dir_is_deleted_if_checkpointing_failed() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let checkpoints_dir = root.join("checkpoints");
            let layout =
                StateLayout::try_new(log.clone(), root.clone(), &MetricsRegistry::new()).unwrap();
            let tip_handler = layout.capture_tip_handler();
            let state_manager_metrics = state_manager_metrics();
            let (_tip_thread, tip_channel) =
                spawn_tip_thread(log, tip_handler, layout, state_manager_metrics.clone());

            const HEIGHT: Height = Height::new(42);
            let canister_id = canister_test_id(10);
            let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
            state.put_canister_state(new_canister_state(
                canister_id,
                user_test_id(24).get(),
                INITIAL_CYCLES,
                NumSeconds::from(100_000),
            ));

            mark_readonly(&checkpoints_dir).unwrap();

            // Scratchpad directory is "tmp/scatchpad_{hex(height)}"
            let expected_scratchpad_dir = root.join("tmp").join("scratchpad_000000000000002a");

            let replicated_state = make_checkpoint(
                &state,
                HEIGHT,
                &tip_channel,
                &state_manager_metrics.checkpoint_metrics,
                &mut thread_pool(),
                Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
            );

            match replicated_state {
                Err(_) => assert!(
                    !expected_scratchpad_dir.exists(),
                    "Expected incomplete scratchpad to be deleted"
                ),
                Ok(_) => panic!("Expected checkpointing to fail"),
            }
        });
    }

    #[test]
    fn can_recover_from_a_checkpoint() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::try_new(log.clone(), root, &MetricsRegistry::new()).unwrap();
            let tip_handler = layout.capture_tip_handler();
            let state_manager_metrics = state_manager_metrics();
            let (_tip_thread, tip_channel) = spawn_tip_thread(
                log,
                tip_handler,
                layout.clone(),
                state_manager_metrics.clone(),
            );

            const HEIGHT: Height = Height::new(42);
            let canister_id: CanisterId = canister_test_id(10);

            let wasm = empty_wasm();
            let wasm_memory = one_page_of(1);

            let mut canister_state = new_canister_state(
                canister_id,
                user_test_id(24).get(),
                INITIAL_CYCLES,
                NumSeconds::from(100_000),
            );
            let page_map = PageMap::from(&[1, 2, 3, 4][..]);
            let stable_memory = Memory::new(page_map, NumWasmPages::new(1));
            let execution_state = ExecutionState {
                canister_root: "NOT_USED".into(),
                session_nonce: None,
                wasm_binary: WasmBinary::new(wasm.clone()),
                wasm_memory: wasm_memory.clone(),
                stable_memory,
                exported_globals: vec![],
                exports: ExportedFunctions::new(BTreeSet::new()),
                metadata: WasmMetadata::default(),
                last_executed_round: ExecutionRound::from(0),
            };
            canister_state.execution_state = Some(execution_state);

            let own_subnet_type = SubnetType::Application;
            let mut state = ReplicatedState::new(subnet_test_id(1), own_subnet_type);
            state.put_canister_state(canister_state);
            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel);

            let recovered_state = load_checkpoint(
                &layout.checkpoint(HEIGHT).unwrap(),
                own_subnet_type,
                &state_manager_metrics.checkpoint_metrics,
                Some(&mut thread_pool()),
                Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
            )
            .unwrap();

            assert_eq!(canister_ids(&recovered_state), vec![canister_id]);

            let canister = recovered_state.canister_state(&canister_id).unwrap();
            assert_eq!(
                canister
                    .execution_state
                    .as_ref()
                    .unwrap()
                    .wasm_binary
                    .binary
                    .as_slice(),
                wasm.as_slice()
            );
            assert_eq!(
                canister.execution_state.as_ref().unwrap().wasm_memory,
                wasm_memory
            );
            assert_eq!(
                canister
                    .execution_state
                    .as_ref()
                    .unwrap()
                    .stable_memory
                    .size,
                NumWasmPages::new(1)
            );

            // Verify that the deserialized stable memory is correctly retrieved.
            let mut data = vec![0, 0, 0, 0];
            let buf = page_map::Buffer::new(
                canister
                    .execution_state
                    .as_ref()
                    .unwrap()
                    .stable_memory
                    .page_map
                    .clone(),
            );
            buf.read(&mut data[..], 0);
            assert_eq!(data, vec![1, 2, 3, 4]);
        });
    }

    #[test]
    fn can_recover_an_empty_state() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::try_new(log.clone(), root, &MetricsRegistry::new()).unwrap();
            let tip_handler = layout.capture_tip_handler();
            let state_manager_metrics = state_manager_metrics();
            let (_tip_thread, tip_channel) = spawn_tip_thread(
                log,
                tip_handler,
                layout.clone(),
                state_manager_metrics.clone(),
            );

            const HEIGHT: Height = Height::new(42);
            let own_subnet_type = SubnetType::Application;

            let _state = make_checkpoint_and_get_state(
                &ReplicatedState::new(subnet_test_id(1), own_subnet_type),
                HEIGHT,
                &tip_channel,
            );

            let recovered_state = load_checkpoint(
                &layout.checkpoint(HEIGHT).unwrap(),
                own_subnet_type,
                &state_manager_metrics.checkpoint_metrics,
                Some(&mut thread_pool()),
                Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
            )
            .unwrap();
            assert!(recovered_state.canisters_iter().next().is_none());
        });
    }

    #[test]
    fn returns_not_found_for_missing_checkpoints() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::try_new(log, root, &MetricsRegistry::new()).unwrap();

            const MISSING_HEIGHT: Height = Height::new(42);
            match layout
                .checkpoint(MISSING_HEIGHT)
                .map_err(CheckpointError::from)
                .and_then(|c| {
                    load_checkpoint(
                        &c,
                        SubnetType::Application,
                        &state_manager_metrics().checkpoint_metrics,
                        Some(&mut thread_pool()),
                        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
                    )
                }) {
                Err(CheckpointError::NotFound(_)) => (),
                Err(err) => panic!("Expected to get NotFound error, got {:?}", err),
                Ok(_) => panic!("Expected to get an error, got state!"),
            }
        });
    }

    #[test]
    fn reports_an_error_on_misconfiguration() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint_reports_an_error_on_misconfiguration");
            let root = tmp.path().to_path_buf();

            mark_readonly(&root).unwrap();

            let layout = StateLayout::try_new(log, root, &MetricsRegistry::new());

            assert!(layout.is_err());
            let err_msg = layout.err().unwrap().to_string();
            assert!(
                err_msg.contains("Permission denied"),
                "Expected a permission error, got {}",
                err_msg
            );
        });
    }

    #[test]
    fn can_recover_a_stopping_canister() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::try_new(log.clone(), root, &MetricsRegistry::new()).unwrap();
            let tip_handler = layout.capture_tip_handler();
            let state_manager_metrics = state_manager_metrics();
            let (_tip_thread, tip_channel) = spawn_tip_thread(
                log,
                tip_handler,
                layout.clone(),
                state_manager_metrics.clone(),
            );

            const HEIGHT: Height = Height::new(42);
            let canister_id: CanisterId = canister_test_id(10);
            let controller = user_test_id(24).get();

            let mut canister_state = CanisterState {
                system_state: SystemState::new_stopping(
                    canister_id,
                    controller,
                    INITIAL_CYCLES,
                    NumSeconds::from(100_000),
                ),
                execution_state: None,
                scheduler_state: Default::default(),
            };

            let stop_context = StopCanisterContext::Ingress {
                sender: user_test_id(0),
                message_id: message_test_id(0),
            };
            canister_state
                .system_state
                .add_stop_context(stop_context.clone());

            let own_subnet_type = SubnetType::Application;
            let mut state = ReplicatedState::new(subnet_test_id(1), own_subnet_type);
            state.put_canister_state(canister_state);
            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel);

            let recovered_state = load_checkpoint(
                &layout.checkpoint(HEIGHT).unwrap(),
                own_subnet_type,
                &state_manager_metrics.checkpoint_metrics,
                Some(&mut thread_pool()),
                Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
            )
            .unwrap();

            assert_eq!(canister_ids(&recovered_state), vec![canister_id]);

            let canister = recovered_state.canister_state(&canister_id).unwrap();
            assert_eq!(
                canister.system_state.status,
                CanisterStatus::Stopping {
                    stop_contexts: vec![stop_context],
                    call_context_manager: CallContextManager::default(),
                }
            );
        });
    }

    #[test]
    fn can_recover_a_stopped_canister() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::try_new(log.clone(), root, &MetricsRegistry::new()).unwrap();
            let tip_handler = layout.capture_tip_handler();
            let state_manager_metrics = state_manager_metrics();
            let (_tip_thread, tip_channel) = spawn_tip_thread(
                log,
                tip_handler,
                layout.clone(),
                state_manager_metrics.clone(),
            );

            const HEIGHT: Height = Height::new(42);
            let canister_id: CanisterId = canister_test_id(10);
            let controller = user_test_id(24).get();

            let canister_state = CanisterState {
                system_state: SystemState::new_stopped(
                    canister_id,
                    controller,
                    INITIAL_CYCLES,
                    NumSeconds::from(100_000),
                ),
                execution_state: None,
                scheduler_state: Default::default(),
            };

            let own_subnet_type = SubnetType::Application;
            let mut state = ReplicatedState::new(subnet_test_id(1), own_subnet_type);
            state.put_canister_state(canister_state);
            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel);

            let loaded_state = load_checkpoint(
                &layout.checkpoint(HEIGHT).unwrap(),
                own_subnet_type,
                &state_manager_metrics.checkpoint_metrics,
                Some(&mut thread_pool()),
                Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
            )
            .unwrap();

            assert_eq!(canister_ids(&loaded_state), vec![canister_id]);

            let canister = loaded_state.canister_state(&canister_id).unwrap();
            assert_eq!(canister.status(), CanisterStatusType::Stopped);
        });
    }

    #[test]
    fn can_recover_a_running_canister() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::try_new(log.clone(), root, &MetricsRegistry::new()).unwrap();
            let tip_handler = layout.capture_tip_handler();
            let state_manager_metrics = state_manager_metrics();
            let (_tip_thread, tip_channel) = spawn_tip_thread(
                log,
                tip_handler,
                layout.clone(),
                state_manager_metrics.clone(),
            );

            const HEIGHT: Height = Height::new(42);
            let canister_id: CanisterId = canister_test_id(10);
            let controller = user_test_id(24).get();

            let canister_state = CanisterState {
                system_state: SystemState::new_running(
                    canister_id,
                    controller,
                    INITIAL_CYCLES,
                    NumSeconds::from(100_000),
                ),
                execution_state: None,
                scheduler_state: Default::default(),
            };

            let own_subnet_type = SubnetType::Application;
            let mut state = ReplicatedState::new(subnet_test_id(1), own_subnet_type);
            state.put_canister_state(canister_state);
            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel);

            let recovered_state = load_checkpoint(
                &layout.checkpoint(HEIGHT).unwrap(),
                own_subnet_type,
                &state_manager_metrics.checkpoint_metrics,
                Some(&mut thread_pool()),
                Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
            )
            .unwrap();

            assert_eq!(canister_ids(&recovered_state), vec![canister_id]);

            let canister = recovered_state.canister_state(&canister_id).unwrap();
            assert_eq!(canister.status(), CanisterStatusType::Running)
        });
    }

    #[test]
    fn can_recover_subnet_queues() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::try_new(log.clone(), root, &MetricsRegistry::new()).unwrap();
            let tip_handler = layout.capture_tip_handler();
            let state_manager_metrics = state_manager_metrics();
            let (_tip_thread, tip_channel) = spawn_tip_thread(
                log,
                tip_handler,
                layout.clone(),
                state_manager_metrics.clone(),
            );

            const HEIGHT: Height = Height::new(42);

            let own_subnet_type = SubnetType::Application;
            let subnet_id = subnet_test_id(1);
            let subnet_id_as_canister_id = CanisterId::from(subnet_id);
            let mut state = ReplicatedState::new(subnet_id, own_subnet_type);

            // Add an ingress message to the subnet queues to later verify
            // it gets recovered.
            state.subnet_queues_mut().push_ingress(
                IngressBuilder::new()
                    .receiver(subnet_id_as_canister_id)
                    .build(),
            );

            let original_state = state.clone();
            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel);

            let recovered_state = load_checkpoint(
                &layout.checkpoint(HEIGHT).unwrap(),
                own_subnet_type,
                &state_manager_metrics.checkpoint_metrics,
                Some(&mut thread_pool()),
                Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
            )
            .unwrap();

            assert_eq!(
                original_state.subnet_queues(),
                recovered_state.subnet_queues()
            );
        });
    }

    #[test]
    fn can_recover_bitcoin_state() {
        use ic_btc_types::Network as BitcoinNetwork;
        use ic_btc_types_internal::{BitcoinAdapterRequestWrapper, GetSuccessorsRequest};
        use ic_registry_subnet_features::{BitcoinFeature, BitcoinFeatureStatus};

        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::try_new(log.clone(), root, &MetricsRegistry::new()).unwrap();
            let tip_handler = layout.capture_tip_handler();
            let state_manager_metrics = state_manager_metrics();
            let (_tip_thread, tip_channel) = spawn_tip_thread(
                log,
                tip_handler,
                layout.clone(),
                state_manager_metrics.clone(),
            );

            const HEIGHT: Height = Height::new(42);

            let own_subnet_type = SubnetType::Application;
            let subnet_id = subnet_test_id(1);
            let mut state = ReplicatedState::new(subnet_id, own_subnet_type);

            // Enable the bitcoin feature to be able to mutate its state.
            state.metadata.own_subnet_features.bitcoin = Some(BitcoinFeature {
                network: BitcoinNetwork::Testnet,
                status: BitcoinFeatureStatus::Enabled,
            });

            // Make some change in the Bitcoin state to later verify that it gets recovered.
            state
                .push_request_bitcoin(BitcoinAdapterRequestWrapper::GetSuccessorsRequest(
                    GetSuccessorsRequest {
                        processed_block_hashes: vec![],
                        anchor: vec![],
                    },
                ))
                .unwrap();

            let original_state = state.clone();
            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel);

            let recovered_state = load_checkpoint(
                &layout.checkpoint(HEIGHT).unwrap(),
                own_subnet_type,
                &state_manager_metrics.checkpoint_metrics,
                Some(&mut thread_pool()),
                Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
            )
            .unwrap();

            assert_eq!(recovered_state.bitcoin(), original_state.bitcoin(),);
        });
    }

    #[test]
    fn can_recover_bitcoin_page_maps() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::try_new(log.clone(), root, &MetricsRegistry::new()).unwrap();
            let tip_handler = layout.capture_tip_handler();
            let state_manager_metrics = state_manager_metrics();
            let (_tip_thread, tip_channel) = spawn_tip_thread(
                log,
                tip_handler,
                layout.clone(),
                state_manager_metrics.clone(),
            );

            const HEIGHT: Height = Height::new(42);

            let own_subnet_type = SubnetType::Application;
            let subnet_id = subnet_test_id(1);
            let mut state = ReplicatedState::new(subnet_id, own_subnet_type);

            // Make some change in the Bitcoin page maps to later verify they get recovered.
            state.bitcoin_mut().utxo_set.utxos_small = PageMap::from(&[1, 2, 3, 4][..]);
            state.bitcoin_mut().utxo_set.utxos_medium = PageMap::from(&[5, 6, 7, 8][..]);
            state.bitcoin_mut().utxo_set.address_outpoints = PageMap::from(&[9, 10, 11, 12][..]);

            let original_state = state.clone();
            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel);

            let recovered_state = load_checkpoint(
                &layout.checkpoint(HEIGHT).unwrap(),
                own_subnet_type,
                &state_manager_metrics.checkpoint_metrics,
                Some(&mut thread_pool()),
                Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
            )
            .unwrap();

            assert_eq!(recovered_state.bitcoin(), original_state.bitcoin());
        });
    }
}
