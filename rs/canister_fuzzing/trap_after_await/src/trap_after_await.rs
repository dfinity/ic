use candid::{Decode, Encode};
use ic_state_machine_tests::{PrincipalId, StateMachine, StateMachineBuilder};
use ic_types::{ingress::WasmResult, CanisterId, Cycles};
use once_cell::sync::Lazy;
use std::cell::RefCell;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
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
    test: StateMachine,
    ledger_canister_id: CanisterId,
    main_canister_id: CanisterId,
}

// TODO: This should be obtained from env
const EXECUTION_DIR: &str = "/ic/rs/canister_fuzzing/trap_after_await";
static mut TEST: Lazy<RefCell<State>> = Lazy::new(|| RefCell::new(create_execution_test()));
static mut COVERAGE_MAP: &'static mut [u8] = &mut [0; 65536];

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
    let test = StateMachineBuilder::new()
        .no_dts()
        .with_log_level(Some(Level::Critical))
        .build();

    // Install ledger canister
    let ledger_canister_id = test
        .install_canister_with_cycles(
            read_ledger_canister_bytes(),
            vec![],
            None,
            Cycles::new(5_000_000_000_000),
        )
        .unwrap();

    // Install main canister
    let main_canister_id = test
        .install_canister_with_cycles(
            read_main_canister_bytes(),
            Encode!(&ledger_canister_id).unwrap(),
            None,
            Cycles::new(5_000_000_000_000),
        )
        .unwrap();

    State {
        test: test,
        ledger_canister_id: ledger_canister_id,
        main_canister_id: main_canister_id,
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
        let trap = bytes_to_u64(input.bytes()) % 50_000;

        // async setup
        let _m1 = test
            .submit_ingress_as(
                PrincipalId::new_anonymous(),
                main_canister_id,
                "refund_balance",
                Encode!(&trap).unwrap(),
            )
            .unwrap();
        let _m2 = test
            .submit_ingress_as(
                PrincipalId::new_anonymous(),
                main_canister_id,
                "refund_balance",
                Encode!(&trap).unwrap(),
            )
            .unwrap();
        test.execute_round();

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
            println!("b1 : {}, b2 : {}", b1, b2);
            return ExitKind::Crash;
        }

        // Report coverage
        let result = test.query(main_canister_id, "export_coverage", vec![]);
        match result {
            Ok(WasmResult::Reply(result)) => {
                unsafe { COVERAGE_MAP.copy_from_slice(&result) };
            }
            _ => (),
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
