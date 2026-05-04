#![allow(deprecated)]
use candid::CandidType;
use futures::future::join_all;
use ic_cdk::api::call::CallResult;
use ic_cdk::api::management_canister::main::{
    CanisterId, CanisterIdRecord, CanisterInstallMode, CanisterSettings, CanisterStatusType,
    CreateCanisterArgument, InstallCodeArgument, canister_status, create_canister, install_code,
};
use ic_cdk::update;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeSet;

/// The amount of cycles that each created canister gets.
/// It is used to pay for the canister creation and wasm module installation.
const INITIAL_CYCLES_BALANCE: u128 = 10_u64.pow(12) as u128; // 1T Cycles;

/// This number should not exceed the length of the canister output queue,
/// which is currently 500.
const CANISTERS_PER_BATCH: usize = 250;

/// Number of attempts to check the status of a canister after it is created and
/// wasm module is optionally installed.
const CHECK_STATUS_ATTEMPTS: usize = 20;

thread_local! {
    static CANISTER_IDS: RefCell<BTreeSet<CanisterId>> = const { RefCell::new(BTreeSet::new()) };
}

async fn spinup_canister(wasm_module: Vec<u8>) -> CallResult<()> {
    // Create canister.
    let canister_id = create_canister(
        CreateCanisterArgument {
            settings: Some(CanisterSettings {
                controllers: Some(vec![ic_cdk::api::id()]),
                ..CanisterSettings::default()
            }),
        },
        INITIAL_CYCLES_BALANCE,
    )
    .await?
    .0
    .canister_id;

    // Store canister id.
    CANISTER_IDS.with(|canister_ids| canister_ids.borrow_mut().insert(canister_id));

    // Install code if provided.
    let is_wasm_module_empty = wasm_module.is_empty();
    if !is_wasm_module_empty {
        install_code(InstallCodeArgument {
            mode: CanisterInstallMode::Install,
            canister_id,
            wasm_module,
            arg: vec![],
        })
        .await?;
    }

    // Check the canister is properly running.
    for _ in 0..CHECK_STATUS_ATTEMPTS {
        let (response,) = canister_status(CanisterIdRecord { canister_id }).await?;
        // Stop checking status if the canister is running and if the wasm module
        // was provided, then also check that the module hash is not empty.
        if response.status == CanisterStatusType::Running
            && (is_wasm_module_empty || response.module_hash.is_some())
        {
            break;
        }
    }

    CallResult::Ok(())
}

#[update]
async fn spinup_canisters(args: SpinupCanistersArgs) {
    let mut remaining_canisters = args.canisters_number as usize;
    while remaining_canisters > 0 {
        let batch_size = CANISTERS_PER_BATCH.min(remaining_canisters);
        let futures: Vec<_> = (0..batch_size)
            .map(|_| spinup_canister(args.wasm_module.clone()))
            .collect();
        let _ = join_all(futures).await;
        remaining_canisters -= batch_size;
    }
}

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct SpinupCanistersArgs {
    pub canisters_number: u64,
    pub wasm_module: Vec<u8>,
}

// Needed since we build this file both as a canister and as a lib for `SpinupCanistersArgs`
#[allow(dead_code)]
fn main() {}
