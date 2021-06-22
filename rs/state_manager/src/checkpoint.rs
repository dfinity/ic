use crate::CheckpointError;
use ic_cow_state::{CowMemoryManager, CowMemoryManagerImpl, MappedState};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    page_map::PageMap, CanisterMetrics, CanisterState, ExecutionState, NumWasmPages,
    ReplicatedState,
};
use ic_replicated_state::{SchedulerState, SystemState};
use ic_state_layout::{
    CanisterStateBits, CheckpointLayout, ExecutionStateBits, ReadPolicy, ReadWritePolicy,
    StateLayout,
};
use ic_types::Height;
use ic_utils::ic_features::*;
use std::collections::BTreeMap;
use std::convert::{From, TryFrom};
use std::sync::Arc;

/// Creates a checkpoint of the node state using specified directory
/// layout. Returns a new state that is equivalent the to given one
/// and a result of the operation.
///
/// If the result is `Ok`, the returned state is "rebased" to use
/// files from the newly created checkpoint. If the result is `Err`,
/// the returned state is exactly the one that was passed as argument.
pub fn make_checkpoint(
    state: &ReplicatedState,
    height: Height,
    layout: &StateLayout,
) -> Result<ReplicatedState, CheckpointError> {
    let tip = layout.tip().map_err(CheckpointError::from)?;

    tip.system_metadata()
        .serialize(state.system_metadata().into())?;

    tip.subnet_queues()
        .serialize((&state.subnet_queues).into())?;

    for canister_state in state.canisters_iter() {
        let canister_layout = tip.canister(&canister_state.canister_id())?;
        canister_layout
            .queues()
            .serialize((&canister_state.system_state.queues).into())?;

        canister_state
            .system_state
            .stable_memory
            .persist_and_sync_delta(&canister_layout.stable_memory_blob())?;

        let execution_state_bits = match &canister_state.execution_state {
            Some(execution_state) => {
                canister_layout
                    .wasm()
                    .serialize(&execution_state.wasm_binary)?;
                execution_state
                    .page_map
                    .persist_and_sync_delta(&canister_layout.vmemory_0())?;

                execution_state.cow_mem_mgr.checkpoint();

                Some(ExecutionStateBits {
                    exported_globals: execution_state.exported_globals.clone(),
                    heap_size: execution_state.heap_size,
                    exports: execution_state.exports.clone(),
                    last_executed_round: execution_state.last_executed_round,
                })
            }
            None => None,
        };
        canister_layout.canister().serialize(
            CanisterStateBits {
                controllers: canister_state.system_state.controllers.clone(),
                last_full_execution_round: canister_state.scheduler_state.last_full_execution_round,
                call_context_manager: canister_state.system_state.call_context_manager().cloned(),
                compute_allocation: canister_state.scheduler_state.compute_allocation,
                accumulated_priority: canister_state.scheduler_state.accumulated_priority,
                query_allocation: canister_state.scheduler_state.query_allocation,
                memory_allocation: canister_state.system_state.memory_allocation,
                freeze_threshold: canister_state.system_state.freeze_threshold,
                cycles_balance: canister_state.system_state.cycles_balance,
                icp_balance: 0,
                execution_state_bits,
                status: canister_state.system_state.status.clone(),
                scheduled_as_first: canister_state
                    .system_state
                    .canister_metrics
                    .scheduled_as_first,
                skipped_round_due_to_no_messages: canister_state
                    .system_state
                    .canister_metrics
                    .skipped_round_due_to_no_messages,
                executed: canister_state.system_state.canister_metrics.executed,
                interruped_during_execution: canister_state
                    .system_state
                    .canister_metrics
                    .interruped_during_execution,
                certified_data: canister_state.system_state.certified_data.clone(),
                consumed_cycles_since_replica_started: canister_state
                    .system_state
                    .canister_metrics
                    .consumed_cycles_since_replica_started,
                stable_memory_size: canister_state.system_state.stable_memory_size,
            }
            .into(),
        )?;
    }

    let cp = layout.tip_to_checkpoint(tip, height)?;
    let state = load_checkpoint(&cp, state.metadata.own_subnet_type)?;

    Ok(state)
}

/// loads the node state heighted with `height` using the specified
/// directory layout.
pub fn load_checkpoint<P: ReadPolicy>(
    checkpoint_layout: &CheckpointLayout<P>,
    own_subnet_type: SubnetType,
) -> Result<ReplicatedState, CheckpointError> {
    let into_checkpoint_error =
        |field: String, err: ic_protobuf::proxy::ProxyDecodeError| CheckpointError::ProtoError {
            path: checkpoint_layout.raw_path().into(),
            field,
            proto_err: err.to_string(),
        };

    let mut metadata = ic_replicated_state::SystemMetadata::try_from(
        checkpoint_layout.system_metadata().deserialize()?,
    )
    .map_err(|err| into_checkpoint_error("SystemMetadata".into(), err))?;
    metadata.own_subnet_type = own_subnet_type;

    let subnet_queues = ic_replicated_state::CanisterQueues::try_from(
        checkpoint_layout.subnet_queues().deserialize()?,
    )
    .map_err(|err| into_checkpoint_error("CanisterQueues".into(), err))?;

    let mut canister_states = BTreeMap::new();
    for canister_id in checkpoint_layout.canister_ids()?.iter() {
        let canister_layout = checkpoint_layout.canister(canister_id)?;
        let canister_state_bits: CanisterStateBits = CanisterStateBits::try_from(
            canister_layout.canister().deserialize()?,
        )
        .map_err(|err| {
            into_checkpoint_error(
                format!("canister_states[{}]::canister_state_bits", canister_id),
                err,
            )
        })?;
        let session_nonce = None;

        let execution_state = match canister_state_bits.execution_state_bits {
            Some(execution_state_bits) => {
                let page_map = PageMap::open(&canister_layout.vmemory_0())?;
                let wasm_binary = canister_layout.wasm().deserialize()?;
                let canister_root = canister_layout.raw_path();
                Some(ExecutionState {
                    canister_root: canister_root.clone(),
                    session_nonce,
                    wasm_binary,
                    page_map,
                    exported_globals: execution_state_bits.exported_globals,
                    heap_size: execution_state_bits.heap_size,
                    exports: execution_state_bits.exports,
                    last_executed_round: execution_state_bits.last_executed_round,
                    embedder_cache: None,
                    cow_mem_mgr: Arc::new(CowMemoryManagerImpl::open_readonly(
                        canister_layout.raw_path(),
                    )),
                    mapped_state: None,
                })
            }
            None => None,
        };

        let stable_memory_bin_file = canister_layout.stable_memory_blob();
        let (stable_memory, stable_memory_size) = if stable_memory_bin_file.exists() {
            (
                PageMap::open(&stable_memory_bin_file)?,
                canister_state_bits.stable_memory_size,
            )
        } else {
            let stable_mem = ic_replicated_state::StableMemory::try_from(
                canister_layout.stable_memory_proto().deserialize()?,
            )
            .map_err(|err| {
                into_checkpoint_error(
                    format!(
                        "canister_states[{}]::system_state::stable_memory",
                        canister_id
                    ),
                    err,
                )
            })?;
            (
                PageMap::from(stable_mem.as_bytes()),
                NumWasmPages::from(stable_mem.page_count()),
            )
        };

        let queues =
            ic_replicated_state::CanisterQueues::try_from(canister_layout.queues().deserialize()?)
                .map_err(|err| {
                    into_checkpoint_error(
                        format!("canister_states[{}]::system_state::queues", canister_id),
                        err,
                    )
                })?;
        let canister_metrics = CanisterMetrics {
            scheduled_as_first: canister_state_bits.scheduled_as_first,
            skipped_round_due_to_no_messages: canister_state_bits.skipped_round_due_to_no_messages,
            executed: canister_state_bits.executed,
            interruped_during_execution: canister_state_bits.interruped_during_execution,
            consumed_cycles_since_replica_started: canister_state_bits
                .consumed_cycles_since_replica_started,
        };
        let system_state = SystemState {
            canister_id: *canister_id,
            controllers: canister_state_bits.controllers,
            queues,
            stable_memory,
            stable_memory_size,
            memory_allocation: canister_state_bits.memory_allocation,
            freeze_threshold: canister_state_bits.freeze_threshold,
            status: canister_state_bits.status,
            certified_data: canister_state_bits.certified_data,
            canister_metrics,
            cycles_balance: canister_state_bits.cycles_balance,
        };

        canister_states.insert(
            system_state.canister_id(),
            CanisterState {
                system_state,
                execution_state,
                scheduler_state: SchedulerState {
                    last_full_execution_round: canister_state_bits.last_full_execution_round,
                    compute_allocation: canister_state_bits.compute_allocation,
                    accumulated_priority: canister_state_bits.accumulated_priority,
                    query_allocation: canister_state_bits.query_allocation,
                },
            },
        );
    }

    let state = ReplicatedState {
        canister_states,
        metadata,
        subnet_queues,
        // Consensus queue needs to be empty at the end of every round.
        consensus_queue: Vec::new(),
        root: checkpoint_layout.raw_path().into(),
    };

    Ok(state)
}

pub fn handle_disk_format_changes<P: ReadWritePolicy>(
    layout: &CheckpointLayout<P>,
    state: &ReplicatedState,
) -> Result<bool, CheckpointError> {
    let mut needs_reload = false;
    for (canister, canister_state) in state.canister_states.iter() {
        if canister_state.execution_state.is_some() {
            let canister_layout = layout.canister(canister)?;
            let execution_state = canister_state.execution_state.as_ref().unwrap();

            let cansister_base = canister_layout.raw_path();
            let is_cow = CowMemoryManagerImpl::is_cow(&cansister_base);
            let should_upgrade =
                !is_cow && cow_state_feature::is_enabled(cow_state_feature::cow_state);
            let should_downgrade =
                is_cow && !cow_state_feature::is_enabled(cow_state_feature::cow_state);

            if should_upgrade {
                let cow_mem_mgr = CowMemoryManagerImpl::open_readwrite(canister_layout.raw_path());

                let mut pages_to_write = Vec::new();
                let mapped_state = cow_mem_mgr.get_map();
                for (idx, data) in execution_state.page_map.host_pages_iter() {
                    pages_to_write.push(idx.get());
                    mapped_state.update_heap_page(idx.get(), data);
                }
                mapped_state.soft_commit(&pages_to_write.as_mut_slice());
                cow_mem_mgr.create_snapshot(execution_state.last_executed_round.get());
            } else if should_downgrade {
                let cow_mem_mgr = CowMemoryManagerImpl::open_readonly(canister_layout.raw_path());
                let mapped_state = cow_mem_mgr.get_map();
                let heap_base = mapped_state.get_heap_base();
                let heap_len = mapped_state.get_heap_len();
                mapped_state.make_heap_accessible();

                let contents = unsafe { std::slice::from_raw_parts(heap_base, heap_len) };

                let memory_path = &canister_layout.vmemory_0();

                std::fs::write(memory_path, contents).map_err(|err| CheckpointError::IoError {
                    path: memory_path.clone(),
                    message: "Failed to overwrite file".to_string(),
                    io_err: err.to_string(),
                })?;

                CowMemoryManagerImpl::purge(&cansister_base);

                // We should reload the state from disk after this format change
                needs_reload = true;
            }
        }
    }
    Ok(needs_reload)
}

// This function prepares the passed in state as a mutable tip. Primarily it
// reopens the cow state in writable mode.
pub fn reopen_state_as_tip<P: ReadWritePolicy>(
    layout: &CheckpointLayout<P>,
    state: &mut ReplicatedState,
) -> Result<(), CheckpointError> {
    for (canister, canister_state) in state.canister_states.iter_mut() {
        if canister_state.execution_state.is_some() {
            let canister_layout = layout.canister(canister)?;
            let mut execution_state = canister_state.execution_state.take().unwrap();
            execution_state.cow_mem_mgr = Arc::new(CowMemoryManagerImpl::open_readwrite(
                canister_layout.raw_path(),
            ));
            canister_state.execution_state = Some(execution_state);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_base_types::NumSeconds;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        page_map, CallContextManager, CanisterStatus, ExecutionState, ExportedFunctions,
        NumWasmPages, PageDelta, PageIndex,
    };
    use ic_sys::PAGE_SIZE;
    use ic_test_utilities::{
        state::{canister_ids, new_canister_state},
        types::{
            ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id},
            messages::IngressBuilder,
        },
        with_test_replica_logger,
    };
    use ic_types::messages::StopCanisterContext;
    use ic_types::{CanisterId, CanisterStatusType, Cycles, ExecutionRound, Height};
    use ic_wasm_types::BinaryEncodedWasm;
    use std::collections::BTreeSet;
    use tempfile::Builder;

    const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

    fn empty_wasm() -> BinaryEncodedWasm {
        BinaryEncodedWasm::new(vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x04, 0x6e, 0x61, 0x6d,
            0x65, 0x02, 0x01, 0x00,
        ])
    }

    fn one_page_of(byte: u8) -> PageMap {
        let contents = vec![byte; *PAGE_SIZE];
        let delta = PageDelta::from(&[(PageIndex::from(0), &contents[..])][..]);
        let mut page_map = PageMap::new();
        page_map.update(delta);
        page_map
    }

    fn mark_readonly(path: &std::path::Path) -> std::io::Result<()> {
        let mut permissions = path.metadata()?.permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(path, permissions)
    }

    fn make_checkpoint_and_get_state(
        state: &ReplicatedState,
        height: Height,
        layout: &StateLayout,
    ) -> ReplicatedState {
        make_checkpoint(state, height, &layout)
            .unwrap_or_else(|err| panic!("Expected make_checkpoint to succeed, got {:?}", err))
    }

    #[test]
    fn can_make_a_checkpoint() {
        with_test_replica_logger(|log| {
            let tmp = Builder::new().prefix("test").tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::new(log, root.clone());

            const HEIGHT: Height = Height::new(42);
            let canister_id = canister_test_id(10);

            let mut state = ReplicatedState::new_rooted_at(
                subnet_test_id(1),
                SubnetType::Application,
                "NOT_USED".into(),
            );
            state.put_canister_state(new_canister_state(
                canister_id,
                user_test_id(24).get(),
                INITIAL_CYCLES,
                NumSeconds::from(100_000),
            ));

            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &layout);

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
            let tmp = Builder::new().prefix("test").tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let checkpoints_dir = root.join("checkpoints");
            let layout = StateLayout::new(log, root.clone());

            const HEIGHT: Height = Height::new(42);
            let canister_id = canister_test_id(10);
            let mut state = ReplicatedState::new_rooted_at(
                subnet_test_id(1),
                SubnetType::Application,
                "NOT_USED".into(),
            );
            state.put_canister_state(new_canister_state(
                canister_id,
                user_test_id(24).get(),
                INITIAL_CYCLES,
                NumSeconds::from(100_000),
            ));

            std::fs::create_dir(&checkpoints_dir).unwrap();
            mark_readonly(&checkpoints_dir).unwrap();

            // Scratchpad directory is "tmp/scatchpad_{hex(height)}"
            let expected_scratchpad_dir = root.join("tmp").join("scratchpad_000000000000002a");

            match make_checkpoint(&state, HEIGHT, &layout) {
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
            let tmp = Builder::new().prefix("test").tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::new(log, root.clone());

            const HEIGHT: Height = Height::new(42);
            let canister_id: CanisterId = canister_test_id(10);

            let tip = layout.tip().unwrap();
            let can_layout = tip.canister(&canister_id);

            let wasm = empty_wasm();
            let page_map = one_page_of(1);

            let mut canister_state = new_canister_state(
                canister_id,
                user_test_id(24).get(),
                INITIAL_CYCLES,
                NumSeconds::from(100_000),
            );
            let execution_state = ExecutionState {
                canister_root: root.clone(),
                session_nonce: None,
                wasm_binary: wasm.clone(),
                page_map: page_map.clone(),
                exported_globals: vec![],
                heap_size: NumWasmPages::from(0),
                exports: ExportedFunctions::new(BTreeSet::new()),
                embedder_cache: None,
                last_executed_round: ExecutionRound::from(0),
                cow_mem_mgr: Arc::new(CowMemoryManagerImpl::open_readwrite(
                    can_layout.unwrap().raw_path(),
                )),
                mapped_state: None,
            };
            canister_state.execution_state = Some(execution_state);
            canister_state.system_state.stable_memory_size = NumWasmPages::new(1);

            let mut buf = page_map::Buffer::new(canister_state.system_state.stable_memory);
            buf.write(&[1, 2, 3, 4][..], 0);
            canister_state.system_state.stable_memory = buf.into_page_map();

            let own_subnet_type = SubnetType::Application;
            let mut state =
                ReplicatedState::new_rooted_at(subnet_test_id(1), own_subnet_type, root);
            state.put_canister_state(canister_state);
            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &layout);

            let recovered_state =
                load_checkpoint(&layout.checkpoint(HEIGHT).unwrap(), own_subnet_type).unwrap();

            assert_eq!(canister_ids(&recovered_state), vec![canister_id]);

            let canister = recovered_state.canister_state(&canister_id).unwrap();
            assert_eq!(
                canister
                    .execution_state
                    .as_ref()
                    .unwrap()
                    .wasm_binary
                    .as_slice(),
                wasm.as_slice()
            );
            assert_eq!(
                canister.execution_state.as_ref().unwrap().page_map,
                page_map
            );
            assert_eq!(
                canister.system_state.stable_memory_size,
                NumWasmPages::new(1)
            );

            // Verify that the deserialized stable memory is correctly retrieved.
            let mut data = vec![0, 0, 0, 0];
            let buf = page_map::Buffer::new(canister.system_state.stable_memory.clone());
            buf.read(&mut data[..], 0);
            assert_eq!(data, vec![1, 2, 3, 4]);
        });
    }

    #[test]
    fn can_recover_an_empty_state() {
        with_test_replica_logger(|log| {
            let tmp = Builder::new().prefix("test").tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::new(log, root);

            const HEIGHT: Height = Height::new(42);
            let own_subnet_type = SubnetType::Application;

            let _state = make_checkpoint_and_get_state(
                &ReplicatedState::new_rooted_at(
                    subnet_test_id(1),
                    own_subnet_type,
                    "NOT_USED".into(),
                ),
                HEIGHT,
                &layout,
            );

            let recovered_state =
                load_checkpoint(&layout.checkpoint(HEIGHT).unwrap(), own_subnet_type).unwrap();
            assert!(recovered_state.canisters_iter().next().is_none());
        });
    }

    #[test]
    fn returns_not_found_for_missing_checkpoints() {
        with_test_replica_logger(|log| {
            let tmp = Builder::new().prefix("test").tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::new(log, root);

            const MISSING_HEIGHT: Height = Height::new(42);
            match layout
                .checkpoint(MISSING_HEIGHT)
                .map_err(CheckpointError::from)
                .and_then(|c| load_checkpoint(&c, SubnetType::Application))
            {
                Err(CheckpointError::NotFound(_)) => (),
                Err(err) => panic!("Expected to get NotFound error, got {:?}", err),
                Ok(_) => panic!("Expected to get an error, got state!"),
            }
        });
    }

    #[test]
    fn reports_an_error_on_misconfiguration() {
        with_test_replica_logger(|log| {
            let tmp = Builder::new().prefix("test").tempdir().unwrap();
            let root = tmp.path().to_path_buf();

            mark_readonly(&root).unwrap();

            let layout = StateLayout::new(log, root);

            let own_subnet_type = SubnetType::Application;
            const HEIGHT: Height = Height::new(42);
            let canister_id = canister_test_id(10);

            let mut state = ReplicatedState::new_rooted_at(
                subnet_test_id(1),
                own_subnet_type,
                "NOT_USED".into(),
            );
            state.put_canister_state(new_canister_state(
                canister_id,
                user_test_id(24).get(),
                INITIAL_CYCLES,
                NumSeconds::from(100_000),
            ));

            let result = make_checkpoint(&state, HEIGHT, &layout);

            assert!(
                result.is_err()
                    && result
                        .as_ref()
                        .unwrap_err()
                        .to_string()
                        .contains("Permission denied"),
                "Expected a permission error, got {:?}",
                result
            );
        });
    }

    #[test]
    fn can_recover_a_stopping_canister() {
        with_test_replica_logger(|log| {
            let tmp = Builder::new().prefix("test").tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::new(log, root);

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
            let mut state = ReplicatedState::new_rooted_at(
                subnet_test_id(1),
                own_subnet_type,
                "NOT_USED".into(),
            );
            state.put_canister_state(canister_state);
            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &layout);

            let recovered_state =
                load_checkpoint(&layout.checkpoint(HEIGHT).unwrap(), own_subnet_type).unwrap();

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
            let tmp = Builder::new().prefix("test").tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::new(log, root);

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
            let mut state = ReplicatedState::new_rooted_at(
                subnet_test_id(1),
                own_subnet_type,
                "NOT_USED".into(),
            );
            state.put_canister_state(canister_state);
            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &layout);

            let loaded_state =
                load_checkpoint(&layout.checkpoint(HEIGHT).unwrap(), own_subnet_type).unwrap();

            assert_eq!(canister_ids(&loaded_state), vec![canister_id]);

            let canister = loaded_state.canister_state(&canister_id).unwrap();
            assert_eq!(canister.status(), CanisterStatusType::Stopped);
        });
    }

    #[test]
    fn can_recover_a_running_canister() {
        with_test_replica_logger(|log| {
            let tmp = Builder::new().prefix("test").tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::new(log, root);

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
            let mut state = ReplicatedState::new_rooted_at(
                subnet_test_id(1),
                own_subnet_type,
                "NOT_USED".into(),
            );
            state.put_canister_state(canister_state);
            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &layout);

            let recovered_state =
                load_checkpoint(&layout.checkpoint(HEIGHT).unwrap(), own_subnet_type).unwrap();

            assert_eq!(canister_ids(&recovered_state), vec![canister_id]);

            let canister = recovered_state.canister_state(&canister_id).unwrap();
            assert_eq!(canister.status(), CanisterStatusType::Running)
        });
    }

    #[test]
    fn can_recover_subnet_queues() {
        with_test_replica_logger(|log| {
            let tmp = Builder::new().prefix("test").tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::new(log, root);

            const HEIGHT: Height = Height::new(42);

            let own_subnet_type = SubnetType::Application;
            let subnet_id = subnet_test_id(1);
            let subnet_id_as_canister_id = CanisterId::from(subnet_id);
            let mut state =
                ReplicatedState::new_rooted_at(subnet_id, own_subnet_type, "NOT_USED".into());

            // Add an ingress message to the subnet queues to later verify
            // it gets recovered.
            state.subnet_queues.push_ingress(
                IngressBuilder::new()
                    .receiver(subnet_id_as_canister_id)
                    .build(),
            );

            let original_state = state.clone();
            let _state = make_checkpoint_and_get_state(&state, HEIGHT, &layout);

            let recovered_state =
                load_checkpoint(&layout.checkpoint(HEIGHT).unwrap(), own_subnet_type).unwrap();

            assert_eq!(original_state.subnet_queues, recovered_state.subnet_queues,);
        });
    }
}
