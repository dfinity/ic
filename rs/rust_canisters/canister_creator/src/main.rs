use candid::Decode;
use dfn_core::{api, CanisterId};
use dfn_macro::update;
use ic_ic00_types::CanisterIdRecord;

/// The amount of cycles that each created canister gets.
const INITIAL_CYCLES_BALANCE: u64 = 1_000_000_000_000;

/// This number should not exceed the length of the canister output queue, which
/// is currently 500.
const CANISTERS_PER_BATCH: usize = 490;

/// Sends the given number of `create_canister` messages to the IC management
/// canister in parallel and waits for the responses.
async fn create_canisters_in_batch(
    number_of_canisters: usize,
) -> Result<Vec<CanisterId>, (Option<i32>, String)> {
    let mut futures = vec![];
    for _ in 0..number_of_canisters {
        let result = dfn_core::api::call_bytes(
            CanisterId::ic_00(),
            "create_canister",
            &ic_ic00_types::CreateCanisterArgs {
                settings: Some(ic_ic00_types::CanisterSettingsArgs {
                    controller: Some(dfn_core::api::id().get()),
                    ..ic_ic00_types::CanisterSettingsArgs::default()
                }),
            }
            .encode(),
            dfn_core::api::Funds::new(INITIAL_CYCLES_BALANCE),
        );
        futures.push(result);
    }

    let canisters = futures::future::join_all(futures).await;
    canisters
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
        if let Err((_, err)) = create_canisters_in_batch(batch).await {
            api::print(format!("Failed to create a canister: {}", err));
        }
        remaining_canisters -= batch;
    }
}

#[export_name = "canister_init"]
fn main() {}
