use candid::Decode;
use dfn_core::{api, CanisterId};
use dfn_macro::update;
use futures::future::join_all;
use ic_management_canister_types::{CanisterIdRecord, CanisterInstallMode, Payload};
use std::cell::RefCell;
use std::collections::BTreeSet;

thread_local! {
    static CANISTER_IDS: RefCell<BTreeSet<CanisterId>> = RefCell::new(Default::default());
}

/// The amount of cycles that each created canister gets.
const INITIAL_CYCLES_BALANCE: u64 = 1_000_000_000_000;

/// This number should not exceed the length of the canister output queue, which
/// is currently 500.
const CANISTERS_PER_BATCH: usize = 490;

fn add_canister_id(canister_id: CanisterId) {
    CANISTER_IDS.with(|canister_ids| {
        canister_ids.borrow_mut().insert(canister_id);
    });
}

fn read_canister_ids() -> Vec<CanisterId> {
    CANISTER_IDS.with(|canister_ids| canister_ids.borrow().iter().cloned().collect())
}

/// Sends the given number of `create_canister` messages to the IC management
/// canister in parallel and waits for the responses.
async fn create_canisters_in_batch(
    number_of_canisters: usize,
) -> Result<Vec<CanisterId>, (Option<i32>, String)> {
    let mut futures = vec![];
    for _ in 0..number_of_canisters {
        let result = api::call_bytes(
            CanisterId::ic_00(),
            "create_canister",
            &ic_management_canister_types::CreateCanisterArgs {
                settings: Some(
                    ic_management_canister_types::CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![api::id().get()])
                        .build(),
                ),
                sender_canister_version: Some(api::canister_version()),
            }
            .encode(),
            api::Funds::new(INITIAL_CYCLES_BALANCE),
        );
        futures.push(result);
    }

    let results = join_all(futures).await;

    results
        .into_iter()
        .map(|result| {
            result.map(|reply| Decode!(&reply, CanisterIdRecord).unwrap().get_canister_id())
        })
        .collect()
}

/// Creates the given number of canisters.
#[update]
async fn create_canisters(number_of_canisters: usize) {
    let mut remaining_canisters = number_of_canisters;
    while remaining_canisters > 0 {
        let batch = CANISTERS_PER_BATCH.min(remaining_canisters);
        match create_canisters_in_batch(batch).await {
            Ok(canisters) => canisters
                .iter()
                .for_each(|canister_id| add_canister_id(*canister_id)),
            Err((_, err)) => api::print(format!("Failed to create a canister: {}", err)),
        }
        remaining_canisters -= batch;
    }
}

/// Installs provided wasm module with arguments on all the created canisters.
/// This is useful for testing many management canister calls within one round,
/// while regular universal_canister does only one management canister call per round.
#[update]
async fn install_code(wasm_module: Vec<u8>, arg: Vec<u8>) {
    let canister_ids = read_canister_ids();
    let mut remaining_canisters = canister_ids.len();
    while remaining_canisters > 0 {
        let batch = CANISTERS_PER_BATCH.min(remaining_canisters);
        let mut futures = vec![];
        for canister_id in &canister_ids {
            let result = api::call_bytes(
                CanisterId::ic_00(),
                "install_code",
                &ic_management_canister_types::InstallCodeArgs::new(
                    CanisterInstallMode::Install,
                    *canister_id,
                    wasm_module.clone(),
                    arg.clone(),
                    None,
                    None,
                )
                .encode(),
                api::Funds::new(INITIAL_CYCLES_BALANCE),
            );
            futures.push(result);
        }
        let _canisters = join_all(futures).await;
        remaining_canisters -= batch;
    }
}

#[export_name = "canister_init"]
fn main() {}
