use candid::{Decode, Encode};
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable, CANISTER_IDS_PER_SUBNET};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    finalize_registry, PrincipalId, StateMachine, StateMachineBuilder, StateMachineConfig,
};
use ic_types::{ingress::WasmResult, CanisterId, Cycles};
use once_cell::sync::Lazy;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use libafl::{
    corpus::inmemory_ondisk::InMemoryOnDiskCorpus,
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::map::AflMapFeedback,
    feedbacks::CrashFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::map::hitcount_map::HitcountsMapObserver,
    observers::map::StdMapObserver,
    prelude::*,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};

use libafl::monitors::SimpleMonitor;
// use libafl::monitors::tui::{ui::TuiUI, TuiMonitor};
use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list};
use slog::Level;

fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut result = 0u64;
    for &byte in bytes.iter().take(8).rev() {
        result = (result << 8) | byte as u64;
    }
    result
}

struct State {
    test: Arc<StateMachine>,
    ledger_canister_id: CanisterId,
    main_canister_id: CanisterId,
}

// TODO: This should be obtained from env
const EXECUTION_DIR: &str = "/ic/rs/canister_fuzzing/trap_after_await";
const SYNCHRONOUS_EXECUTION: bool = false;
static mut TEST: Lazy<RefCell<State>> = Lazy::new(|| RefCell::new(create_execution_test()));
static mut COVERAGE_MAP: &mut [u8] = &mut [0; 65536];

fn read_main_canister_bytes() -> Vec<u8> {
    let wasm_path = std::path::PathBuf::from(std::env::var("FUZZ_CANISTER_WASM_PATH").unwrap());
    let mut f = File::open(wasm_path).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    buffer
}

fn read_ledger_canister_bytes() -> Vec<u8> {
    let wasm_path = std::path::PathBuf::from(std::env::var("LEDGER_WASM_PATH").unwrap());
    let mut f = File::open(wasm_path).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    buffer
}

fn create_execution_test() -> State {
    let subnets = Arc::new(RwLock::new(BTreeMap::new()));
    let config = StateMachineConfig::new(
        SubnetConfig::new(SubnetType::Application),
        HypervisorConfig::default(),
    );
    let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());

    let test = StateMachineBuilder::new()
        .no_dts()
        .with_log_level(Some(Level::Critical))
        .with_config(Some(config))
        .with_subnet_seed([1; 32])
        .with_registry_data_provider(registry_data_provider.clone())
        .build_with_subnets(subnets);

    // subnet x registry setup
    let subnet_id = test.get_subnet_id();
    let range = CanisterIdRange {
        start: CanisterId::from_u64(0),
        end: CanisterId::from_u64(CANISTER_IDS_PER_SUBNET - 1),
    };
    let mut routing_table = RoutingTable::new();
    routing_table.insert(range, subnet_id).unwrap();
    let subnet_list = vec![subnet_id];

    finalize_registry(
        subnet_id,
        routing_table,
        subnet_list,
        registry_data_provider,
    );

    test.reload_registry();

    // Install ledger canister
    let ledger_canister_id = test
        .install_canister_with_cycles(
            read_ledger_canister_bytes(),
            vec![],
            None,
            Cycles::new(u128::MAX / 2),
        )
        .unwrap();

    // Install main canister
    let main_canister_id = test
        .install_canister_with_cycles(
            read_main_canister_bytes(),
            Encode!(&ledger_canister_id).unwrap(),
            None,
            Cycles::new(u128::MAX / 2),
        )
        .unwrap();

    State {
        test,
        ledger_canister_id,
        main_canister_id,
    }
}

pub fn main() {
    let mut harness = |input: &BytesInput| {
        let ledger_canister_id = unsafe { TEST.borrow().ledger_canister_id };
        let main_canister_id = unsafe { TEST.borrow().main_canister_id };
        let test = unsafe { &TEST.borrow_mut().test };

        // Prepare the main canister
        // Adds a local balance of 10_000_000 to anonymous principal
        test.execute_ingress(main_canister_id, "update_balance", Encode!().unwrap())
            .unwrap();

        // Prepare the ledger canister
        // Adds a ledger balance of 10_000_000 to main_canister_id
        test.execute_ingress(
            ledger_canister_id,
            "setup_balance",
            Encode!(&main_canister_id, &10_000_000_u64).unwrap(),
        )
        .unwrap();

        // Assert both balances match
        let b1 = match test
            .query(main_canister_id, "get_total_balance", Encode!().unwrap())
            .unwrap()
        {
            WasmResult::Reply(result) => Decode!(&result, u64).unwrap(),
            _ => panic!("Unable to get result"),
        };

        let b2 = match test.query(
            ledger_canister_id,
            "get_balance",
            Encode!(&main_canister_id, &10_000_000_u64).unwrap(),
        ) {
            Ok(WasmResult::Reply(result)) => Decode!(&result, u64).unwrap(),
            _ => panic!("Unable to get result"),
        };

        // should never fail
        assert_eq!(b1, b2);

        // Initialize payload from bytes
        // let trap = Encode!(&(bytes_to_u64(input.bytes()) % 500_000)).unwrap();
        let trap = (*input).bytes().to_vec();
        // let trap = 3278_u64;

        if SYNCHRONOUS_EXECUTION {
            // Synchronous message execution - ABABAB
            // Each execute_ingress_as is executed in place
            // as a single round
            for _ in 0..3 {
                // Execution result doesn't matter here
                let _result = test.execute_ingress_as(
                    PrincipalId::new_anonymous(),
                    main_canister_id,
                    "refund_balance",
                    trap.clone(),
                );
            }
        } else {
            // Asynchronous setup AABBAB
            // We use submit_ingress and execute_round to trigger
            // asynchronous message execution.
            for i in 0..3 {
                let _messaage_id = test
                    .submit_ingress_as(
                        PrincipalId::new_anonymous(),
                        main_canister_id,
                        "refund_balance",
                        trap.clone(),
                    )
                    .unwrap();
                if i == 1 {
                    test.execute_round();
                }
            }
            test.execute_round();
        }

        // Assert both balances match
        let b1 = match test
            .query(main_canister_id, "get_total_balance", Encode!().unwrap())
            .unwrap()
        {
            WasmResult::Reply(result) => Decode!(&result, u64).unwrap(),
            _ => panic!("Unable to get result"),
        };

        let b2 = match test.query(
            ledger_canister_id,
            "get_balance",
            Encode!(&main_canister_id, &10_000_000_u64).unwrap(),
        ) {
            Ok(WasmResult::Reply(result)) => Decode!(&result, u64).unwrap(),
            _ => panic!("Unable to get result"),
        };

        // can fail
        if b1 != b2 {
            println!("Results fail b1 : {}, b2 : {}", b1, b2);
            return ExitKind::Crash;
        }

        // Report coverage
        let result = test.query(main_canister_id, "export_coverage", vec![]);
        if let Ok(WasmResult::Reply(result)) = result {
            unsafe { COVERAGE_MAP.copy_from_slice(&result) };
        }

        test.advance_time(Duration::from_secs(1));

        ExitKind::Ok
    };

    let hitcount_map_observer =
        HitcountsMapObserver::new(unsafe { StdMapObserver::new("coverage_map", COVERAGE_MAP) });
    let afl_map_feedback = AflMapFeedback::new(&hitcount_map_observer);
    let mut feedback = afl_map_feedback;
    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryOnDiskCorpus::no_meta(PathBuf::from(format!("{}/input", EXECUTION_DIR))).unwrap(),
        InMemoryOnDiskCorpus::no_meta(PathBuf::from(format!("{}/crashes", EXECUTION_DIR))).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .unwrap();

    let mon = SimpleMonitor::new(|s| println!("{s}"));

    // let ui = TuiUI::with_version(
    //     String::from("Decode Candid by Instruction / Input Ratio"),
    //     String::from("0.0.1"),
    //     false,
    // );
    // let mon = TuiMonitor::new(ui);

    let mut mgr = SimpleEventManager::new(mon);
    let scheduler = QueueScheduler::new();
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut executor = InProcessExecutor::new(
        &mut harness,
        tuple_list!(hitcount_map_observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    // bazel run @candid//:didc random -- -t '(nat64)' | bazel run @candid//:didc encode | xxd -r -p
    let paths = fs::read_dir(PathBuf::from(format!("{}/corpus", EXECUTION_DIR))).unwrap();
    for path in paths {
        let mut f = File::open(path.unwrap().path()).unwrap();
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer).unwrap();
        fuzzer
            .evaluate_input(&mut state, &mut executor, &mut mgr, BytesInput::new(buffer))
            .unwrap();
    }

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
