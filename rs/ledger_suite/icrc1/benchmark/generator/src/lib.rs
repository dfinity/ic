mod scenario;
mod state;

use candid::{CandidType, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_cdk::api::management_canister::main::WasmModule;
use rand::RngCore;
use rand_chacha::rand_core::SeedableRng;
use state::GeneratorState;
use std::cell::RefCell;

// Pseudo-random is good enough for benchmarking.
const SEED: u64 = 5000;

const NANO: u64 = 1_000_000_000;

thread_local! {
    static STATE: RefCell<GeneratorState> = const { RefCell::new(GeneratorState::new()) };
}

#[derive(Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct RunScenarioResult {
    scenario: Scenario,
    success: bool,
    duration_sec: Nat,
    blocks: Nat,
}

#[derive(Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub enum Scenario {
    Accounts,
    Transactions,
    IndexPerf,
}

#[derive(Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct InitArgs {
    ledger_id: CanisterId,
    index_id: CanisterId,
}

pub fn init(args: InitArgs) {
    ic_cdk::println!("Initializing benchmark generator canister...");
    STATE.with(|cell| {
        let mut state = cell.borrow_mut();
        state.rng = Some(rand_chacha::ChaCha8Rng::seed_from_u64(SEED));
        state.ledger_principal = Some(args.ledger_id.get());
        state.index_principal = Some(args.index_id.get());
        state.index_wasm = None;
        state.worker_wasm = None;
    });
}

pub async fn upload_index_wasm(blob: &[u8]) -> bool {
    ic_cdk::println!("Uploading index wasm...");
    let wasm = blob.to_vec();
    ic_cdk::println!("Uploaded index wasm size: {}", wasm.len());
    STATE.with(|cell| cell.borrow_mut().index_wasm = Some(wasm));
    true
}

pub async fn upload_worker_wasm(blob: &[u8]) -> bool {
    ic_cdk::println!("Uploading worker wasm...");
    let wasm = blob.to_vec();
    ic_cdk::println!("Uploaded worker wasm size: {}", wasm.len());
    STATE.with(|cell| cell.borrow_mut().worker_wasm = Some(wasm));
    true
}

pub async fn run_scenario(scenario: Scenario) -> RunScenarioResult {
    let result = match scenario {
        Scenario::Accounts => scenario::accounts::run_benchmark().await,
        Scenario::Transactions => scenario::transactions::run_benchmark().await,
        Scenario::IndexPerf => scenario::indexperf::run_benchmark().await,
    };
    ic_cdk::println!("Benchmark result: {:?}", result);
    result
}

/// Return the principal of the ledger canister.
pub(crate) fn get_ledger_principal() -> PrincipalId {
    PrincipalId::from(STATE.with(|c| {
        c.borrow()
            .ledger_principal
            .expect("Error while getting ledger principal")
            .0
    }))
}

/// Return the principal of the index canister.
pub(crate) fn get_index_principal() -> PrincipalId {
    PrincipalId::from(STATE.with(|c| {
        c.borrow()
            .index_principal
            .expect("Error while getting index principal")
            .0
    }))
}

pub(crate) fn get_index_wasm() -> WasmModule {
    STATE.with(|c| {
        c.borrow()
            .index_wasm
            .clone()
            .expect("Error while getting index WASM")
    })
}

pub(crate) fn get_worker_wasm() -> WasmModule {
    STATE.with(|c| {
        c.borrow()
            .worker_wasm
            .clone()
            .expect("Error while getting worker WASM")
    })
}

/// Return the next random u64.
pub(crate) fn next_u64() -> u64 {
    STATE.with(|c| {
        c.borrow_mut()
            .rng
            .as_mut()
            .expect("Error while getting ChaChaRng")
            .next_u64()
    })
}

pub fn encode_metrics(
    metrics: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>,
) -> std::io::Result<()> {
    metrics.encode_gauge(
        "icrc1_benchmark_generator_stable_memory_bytes",
        ic_cdk::api::stable::stable64_size() as f64,
        "Size of the stable memory allocated by this canister.",
    )?;
    Ok(())
}
