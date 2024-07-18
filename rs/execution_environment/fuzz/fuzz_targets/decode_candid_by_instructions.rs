use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder};
use ic_types::{ingress::WasmResult, CanisterId, Cycles};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Cow;
use std::cell::RefCell;
use std::fmt::Debug;
use std::fs;
use std::fs::File;
use std::io::Read;

use libafl::{
    corpus::InMemoryCorpus,
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::CrashFeedback,
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    mutators::scheduled::{havoc_mutations, StdScheduledMutator},
    observers::value::RefCellValueObserver,
    prelude::*,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};

use libafl::monitors::SimpleMonitor;
// use libafl::monitors::tui::{ui::TuiUI, TuiMonitor};

use libafl_bolts::{current_nanos, rands::StdRand, tuples::tuple_list, HasLen, Named};

// TODO: This should be obtained from env
const CORPUS_DIR: &str = "rs/execution_environment/fuzz/corpus";

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
struct DecodingMap {
    previous_ratio: u64,
    increased: bool,
}

// There are deprecated fields in this method
#[derive(Serialize, Clone, Debug)]
pub struct DecodingMapFeedback {}

impl<S> Feedback<S> for DecodingMapFeedback
where
    S: State,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State = S>,
        OT: ObserversTuple<S>,
    {
        let observer = observers
            .match_name::<RefCellValueObserver<DecodingMap>>("DecodingMapObserver")
            .unwrap();
        Ok(observer.get_ref().increased)
    }
}

impl Named for DecodingMapFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("DecodingMapFeedback");
        &NAME
    }
}

impl DecodingMapFeedback {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DecodingMapFeedback {
    fn default() -> Self {
        Self::new()
    }
}

static mut MAP: RefCell<DecodingMap> = RefCell::new(DecodingMap {
    previous_ratio: 0u64,
    increased: false,
});

static mut TEST: Lazy<RefCell<(ExecutionTest, CanisterId)>> =
    Lazy::new(|| RefCell::new(create_execution_test()));

// TODO: The right way to do this would be iclude_bytes! but would require a build.rs
// since the env var is not set at compile time.
fn read_canister_bytes() -> Vec<u8> {
    let wasm_path = std::path::PathBuf::from(std::env::var("FUZZ_CANISTER_WASM_PATH").unwrap());
    let mut f = File::open(wasm_path).unwrap();
    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).unwrap();
    buffer
}

fn create_execution_test() -> (ExecutionTest, CanisterId) {
    let mut test = ExecutionTestBuilder::new()
        .with_deterministic_time_slicing_disabled()
        .with_canister_sandboxing_disabled()
        .build();

    let canister_id = test
        .canister_from_cycles_and_binary(Cycles::new(5_000_000_000_000), read_canister_bytes())
        .unwrap();
    (test, canister_id)
}

pub fn main() {
    let mut harness = |input: &BytesInput| {
        let canister_id = unsafe { TEST.borrow().1 };
        let test = unsafe { &mut TEST.borrow_mut().0 };
        let result = test.non_replicated_query(canister_id, "decode", (*input).clone().into());
        let cycles = match result {
            Ok(WasmResult::Reply(result)) => {
                let mut cycles = [0u8; 8];
                cycles.clone_from_slice(&result[0..8]);
                u64::from_le_bytes(cycles)
            }
            _ => 0,
        };

        let ratio = cycles / input.len() as u64;
        let previous_ratio = unsafe { MAP.borrow().previous_ratio };
        let mut decoding_map = unsafe { MAP.borrow_mut() };
        if ratio > previous_ratio {
            decoding_map.increased = true;
            decoding_map.previous_ratio = ratio;
        } else {
            decoding_map.increased = false;
        }

        // The success condition for the fuzzer is cycles consumed to input length ratio
        // is too high. Once we reach this condition, the fuzzer creates a crash.
        if ratio > 10_000_000 {
            return ExitKind::Crash;
        }
        ExitKind::Ok
    };

    let observer = unsafe {
        RefCellValueObserver::new(
            "DecodingMapObserver",
            libafl_bolts::ownedref::OwnedRef::Ref(&MAP),
        )
    };
    let mut feedback = DecodingMapFeedback::new();

    // [TODO]
    // An observer to observe coverage in WASM
    // A MaxMapFeedback to adapt the coverage map information
    // A feedback_or to combine DecodingMapFeedback and MaxMapFeedback

    let mut objective = CrashFeedback::new();

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        InMemoryCorpus::new(), // corpus
        InMemoryCorpus::new(), // crash corpus
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
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("Failed to create the Executor");

    let paths = fs::read_dir(CORPUS_DIR).unwrap();
    for path in paths {
        let mut f = File::open(path.unwrap().path()).unwrap();
        let mut buffer = Vec::new();
        f.read_to_end(&mut buffer).unwrap();
        fuzzer
            .evaluate_input(&mut state, &mut executor, &mut mgr, BytesInput::new(buffer))
            .unwrap();
    }

    // [TOOD]
    // We could have an actual Candid random generator
    // let mut generator = RandBytesGenerator::new(32);
    // state
    //     .generate_initial_inputs_forced(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
    //     .expect("Failed to generate the initial corpus");

    let mutator = StdScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
