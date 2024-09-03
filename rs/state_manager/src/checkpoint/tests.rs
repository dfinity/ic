use super::*;
use crate::{spawn_tip_thread, StateManagerMetrics, NUMBER_OF_CHECKPOINT_THREADS};
use ic_base_types::NumSeconds;
use ic_config::state_manager::lsmt_config_default;
use ic_logger::ReplicaLogger;
use ic_management_canister_types::CanisterStatusType;
use ic_metrics::MetricsRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::execution_state::{NextScheduledMethod, WasmBinary, WasmMetadata},
    page_map::{Buffer, TestPageAllocatorFileDescriptorImpl},
    testing::ReplicatedStateTesting,
    CallContextManager, CanisterStatus, ExecutionState, ExportedFunctions, NumWasmPages, PageIndex,
};
use ic_state_layout::{
    StateLayout, CANISTER_FILE, CANISTER_STATES_DIR, CHECKPOINTS_DIR, SYSTEM_METADATA_FILE,
};
use ic_sys::PAGE_SIZE;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_state::{canister_ids, new_canister_state};
use ic_test_utilities_tmpdir::tmpdir;
use ic_test_utilities_types::{
    ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id},
    messages::IngressBuilder,
};
use ic_types::{
    malicious_flags::MaliciousFlags,
    messages::{StopCanisterCallId, StopCanisterContext},
    CanisterId, Cycles, ExecutionRound, Height,
};
use ic_wasm_types::CanisterModule;
use std::{collections::BTreeSet, fs::OpenOptions};

const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

fn state_manager_metrics(log: &ReplicaLogger) -> StateManagerMetrics {
    let metrics_registry = ic_metrics::MetricsRegistry::new();
    StateManagerMetrics::new(&metrics_registry, log.clone())
}

fn thread_pool() -> scoped_threadpool::Pool {
    scoped_threadpool::Pool::new(NUMBER_OF_CHECKPOINT_THREADS)
}

fn empty_wasm() -> CanisterModule {
    CanisterModule::new(vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x04, 0x6e, 0x61, 0x6d, 0x65,
        0x02, 0x01, 0x00,
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

fn make_checkpoint_and_get_state_impl(
    state: &ReplicatedState,
    height: Height,
    tip_channel: &Sender<TipRequest>,
    log: &ReplicaLogger,
) -> ReplicatedState {
    make_checkpoint(
        state,
        height,
        tip_channel,
        &state_manager_metrics(log).checkpoint_metrics,
        &mut thread_pool(),
        Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
        ic_config::state_manager::lsmt_config_default().lsmt_status,
    )
    .unwrap_or_else(|err| panic!("Expected make_checkpoint to succeed, got {:?}", err))
    .1
}

fn make_checkpoint_and_get_state(
    state: &ReplicatedState,
    height: Height,
    tip_channel: &Sender<TipRequest>,
    log: &ReplicaLogger,
) -> ReplicatedState {
    make_checkpoint_and_get_state_impl(state, height, tip_channel, log)
}

#[test]
fn can_make_a_checkpoint() {
    with_test_replica_logger(|log| {
        let tmp = tmpdir("checkpoint");
        let root = tmp.path().to_path_buf();
        let layout =
            StateLayout::try_new(log.clone(), root.clone(), &MetricsRegistry::new()).unwrap();
        let tip_handler = layout.capture_tip_handler();
        let (_tip_thread, tip_channel) = spawn_tip_thread(
            log.clone(),
            tip_handler,
            layout.clone(),
            lsmt_config_default(),
            state_manager_metrics(&log),
            MaliciousFlags::default(),
        );

        const HEIGHT: Height = Height::new(42);
        let canister_id = canister_test_id(10);

        let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);
        state.put_canister_state(new_canister_state(
            canister_id,
            user_test_id(24).get(),
            INITIAL_CYCLES,
            NumSeconds::from(100_000),
        ));

        let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel, &log);

        // Ensure that checkpoint data is now available via layout API.
        assert_eq!(layout.checkpoint_heights().unwrap(), vec![HEIGHT]);
        let checkpoint = layout.checkpoint_verified(HEIGHT).unwrap();
        assert_eq!(checkpoint.canister_ids().unwrap(), vec![canister_id]);
        assert!(checkpoint
            .canister(&canister_id)
            .unwrap()
            .queues()
            .deserialize()
            .is_ok());

        // Ensure the expected paths actually exist.
        let checkpoint_path = root.join(CHECKPOINTS_DIR).join("000000000000002a");
        let canister_path = checkpoint_path
            .join(CANISTER_STATES_DIR)
            .join("000000000000000a0101");

        let expected_paths = vec![
            checkpoint_path.join(SYSTEM_METADATA_FILE),
            canister_path.join(CANISTER_FILE),
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
        let checkpoints_dir = root.join(CHECKPOINTS_DIR);
        let layout =
            StateLayout::try_new(log.clone(), root.clone(), &MetricsRegistry::new()).unwrap();
        let tip_handler = layout.capture_tip_handler();
        let state_manager_metrics = state_manager_metrics(&log);
        let (_tip_thread, tip_channel) = spawn_tip_thread(
            log,
            tip_handler,
            layout,
            lsmt_config_default(),
            state_manager_metrics.clone(),
            MaliciousFlags::default(),
        );

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
            ic_config::state_manager::lsmt_config_default().lsmt_status,
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
        let state_manager_metrics = state_manager_metrics(&log);
        let (_tip_thread, tip_channel) = spawn_tip_thread(
            log.clone(),
            tip_handler,
            layout.clone(),
            lsmt_config_default(),
            state_manager_metrics.clone(),
            MaliciousFlags::default(),
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
            wasm_binary: WasmBinary::new(wasm.clone()),
            wasm_memory: wasm_memory.clone(),
            stable_memory,
            exported_globals: vec![],
            exports: ExportedFunctions::new(BTreeSet::new()),
            metadata: WasmMetadata::default(),
            last_executed_round: ExecutionRound::from(0),
            next_scheduled_method: NextScheduledMethod::default(),
        };

        canister_state.execution_state = Some(execution_state);

        let own_subnet_type = SubnetType::Application;
        let mut state = ReplicatedState::new(subnet_test_id(1), own_subnet_type);
        state.put_canister_state(canister_state);
        let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel, &log);

        let recovered_state = load_checkpoint(
            &layout.checkpoint_verified(HEIGHT).unwrap(),
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
        let buf = Buffer::new(
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
        let state_manager_metrics = state_manager_metrics(&log);
        let (_tip_thread, tip_channel) = spawn_tip_thread(
            log.clone(),
            tip_handler,
            layout.clone(),
            lsmt_config_default(),
            state_manager_metrics.clone(),
            MaliciousFlags::default(),
        );

        const HEIGHT: Height = Height::new(42);
        let own_subnet_type = SubnetType::Application;

        let _state = make_checkpoint_and_get_state(
            &ReplicatedState::new(subnet_test_id(1), own_subnet_type),
            HEIGHT,
            &tip_channel,
            &log,
        );

        let recovered_state = load_checkpoint(
            &layout.checkpoint_verified(HEIGHT).unwrap(),
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
        let layout = StateLayout::try_new(log.clone(), root, &MetricsRegistry::new()).unwrap();

        const MISSING_HEIGHT: Height = Height::new(42);
        match layout
            .checkpoint_verified(MISSING_HEIGHT)
            .map_err(CheckpointError::from)
            .and_then(|c| {
                load_checkpoint(
                    &c,
                    SubnetType::Application,
                    &state_manager_metrics(&log).checkpoint_metrics,
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
        let state_manager_metrics = state_manager_metrics(&log);
        let (_tip_thread, tip_channel) = spawn_tip_thread(
            log.clone(),
            tip_handler,
            layout.clone(),
            lsmt_config_default(),
            state_manager_metrics.clone(),
            MaliciousFlags::default(),
        );

        const HEIGHT: Height = Height::new(42);
        let canister_id: CanisterId = canister_test_id(10);
        let controller = user_test_id(24).get();

        let mut canister_state = CanisterState {
            system_state: SystemState::new_stopping_for_testing(
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
            call_id: Some(StopCanisterCallId::new(0)),
        };
        canister_state
            .system_state
            .add_stop_context(stop_context.clone());

        let own_subnet_type = SubnetType::Application;
        let mut state = ReplicatedState::new(subnet_test_id(1), own_subnet_type);
        state.put_canister_state(canister_state);
        let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel, &log);

        let recovered_state = load_checkpoint(
            &layout.checkpoint_verified(HEIGHT).unwrap(),
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
        let state_manager_metrics = state_manager_metrics(&log);
        let (_tip_thread, tip_channel) = spawn_tip_thread(
            log.clone(),
            tip_handler,
            layout.clone(),
            lsmt_config_default(),
            state_manager_metrics.clone(),
            MaliciousFlags::default(),
        );

        const HEIGHT: Height = Height::new(42);
        let canister_id: CanisterId = canister_test_id(10);
        let controller = user_test_id(24).get();

        let canister_state = CanisterState {
            system_state: SystemState::new_stopped_for_testing(
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
        let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel, &log);

        let loaded_state = load_checkpoint(
            &layout.checkpoint_verified(HEIGHT).unwrap(),
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
        let state_manager_metrics = state_manager_metrics(&log);
        let (_tip_thread, tip_channel) = spawn_tip_thread(
            log.clone(),
            tip_handler,
            layout.clone(),
            lsmt_config_default(),
            state_manager_metrics.clone(),
            MaliciousFlags::default(),
        );

        const HEIGHT: Height = Height::new(42);
        let canister_id: CanisterId = canister_test_id(10);
        let controller = user_test_id(24).get();

        let canister_state = CanisterState {
            system_state: SystemState::new_running_for_testing(
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
        let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel, &log);

        let recovered_state = load_checkpoint(
            &layout.checkpoint_verified(HEIGHT).unwrap(),
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
        let state_manager_metrics = state_manager_metrics(&log);
        let (_tip_thread, tip_channel) = spawn_tip_thread(
            log.clone(),
            tip_handler,
            layout.clone(),
            lsmt_config_default(),
            state_manager_metrics.clone(),
            MaliciousFlags::default(),
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
        let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel, &log);

        let recovered_state = load_checkpoint(
            &layout.checkpoint_verified(HEIGHT).unwrap(),
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
fn empty_protobufs_are_loaded_correctly() {
    with_test_replica_logger(|log| {
        let tmp = tmpdir("checkpoint");
        let root = tmp.path().to_path_buf();
        let layout = StateLayout::try_new(log.clone(), root, &MetricsRegistry::new()).unwrap();
        let tip_handler = layout.capture_tip_handler();
        let state_manager_metrics = state_manager_metrics(&log);
        let (_tip_thread, tip_channel) = spawn_tip_thread(
            log.clone(),
            tip_handler,
            layout.clone(),
            lsmt_config_default(),
            state_manager_metrics.clone(),
            MaliciousFlags::default(),
        );

        const HEIGHT: Height = Height::new(42);
        let canister_id = canister_test_id(1);

        let own_subnet_type = SubnetType::Application;
        let subnet_id = subnet_test_id(1);
        let mut state = ReplicatedState::new(subnet_id, own_subnet_type);
        let canister_state = new_canister_state(
            canister_id,
            user_test_id(24).get(),
            INITIAL_CYCLES,
            NumSeconds::from(100_000),
        );
        state.put_canister_state(canister_state);

        let _state = make_checkpoint_and_get_state(&state, HEIGHT, &tip_channel, &log);

        let recovered_state = load_checkpoint(
            &layout.checkpoint_verified(HEIGHT).unwrap(),
            own_subnet_type,
            &state_manager_metrics.checkpoint_metrics,
            Some(&mut thread_pool()),
            Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
        )
        .unwrap();

        let checkpoint_layout = layout.checkpoint_verified(HEIGHT).unwrap();
        let canister_layout = checkpoint_layout.canister(&canister_id).unwrap();

        let empty_protobufs = vec![
            checkpoint_layout.subnet_queues().raw_path().to_owned(),
            checkpoint_layout.ingress_history().raw_path().to_owned(),
            canister_layout.queues().raw_path().to_owned(),
        ];

        for path in empty_protobufs {
            assert!(!path.exists());
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            assert!(path.exists());
        }

        let recovered_state_altered = load_checkpoint(
            &layout.checkpoint_verified(HEIGHT).unwrap(),
            own_subnet_type,
            &state_manager_metrics.checkpoint_metrics,
            Some(&mut thread_pool()),
            Arc::new(TestPageAllocatorFileDescriptorImpl::new()),
        )
        .unwrap();

        assert_eq!(recovered_state, recovered_state_altered);
    });
}
