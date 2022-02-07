use crate::api::handle::Ic;
use canister_test::{Canister, Project};
use chrono::Utc;
use std::time::Duration;

/// How long to run the test after canisters have been installed
const TEST_DURATION_SECONDS: usize = 120;
/// Number of canisters to be installed
const NUM_CANISTERS: usize = 2;

/// `SIZE_LEVEL` is level of the size of canister state.
/// Each `statesync-test` canister's state size will be `SIZE_LEVEL` *
/// `VECTOR_LENGTH` bytes. `SIZE_LEVEL = 0` exercises the original testcase.
/// `SIZE_LEVEL > 0` is used for the state sync test of large size.
const SIZE_LEVEL: usize = 0;

const RANDOM_SEED: usize = 0;
/// Testcase 5.2 implementation: installs copies of the
/// `statesync-test-canister` onto the second node of each `subnet` of `ic`;
/// calls `change()` on it and sleeps for `sleeptime / 8`; 8 times.
pub async fn test_impl(
    ic: &dyn Ic,
    sleeptime: Option<u64>,
    num_canisters: Option<u64>,
    size_level: Option<u64>,
    random_seed: Option<u64>,
) {
    // Load the statesync-test-canister.
    let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
        "rust_canisters/statesync_test",
        "statesync-test-canister",
        &[],
    );

    println!("UTC before installing canisters is: {}", Utc::now());
    let num_canisters = num_canisters.unwrap_or(NUM_CANISTERS as u64) as usize;
    let node1 = ic.subnet(ic.subnet_ids()[0]).node_by_idx(1);
    let r = node1.api();
    let mut canisters: Vec<Canister> = Vec::new();
    for i in 0..num_canisters {
        canisters.push(
            wasm.clone()
                .install(&r)
                .with_memory_allocation(1056 * 1024 * 1024)
                .bytes(Vec::new())
                .await
                .unwrap_or_else(|err| {
                    panic!("Failed to install canister {}: {}", i, err);
                }),
        );
    }
    println!(
        "UTC after installing {} canisters is: {}",
        num_canisters,
        Utc::now()
    );

    let size_level = size_level.unwrap_or(SIZE_LEVEL as u64) as usize;
    let random_seed = random_seed.unwrap_or(RANDOM_SEED as u64) as usize;
    if size_level == 0 {
        // Call `change()` on all canisters 8 times, sleep inbetween
        let total_changes: u8 = 8;
        for x in 1..=total_changes {
            println!("Start updating canisters, it is now {}", Utc::now());
            for canister in &canisters {
                let seed = x + canister.canister_id_vec8()[0];
                let res: Result<u8, String> = canister
                    .update_("change_state", dfn_json::json, seed as u32)
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "Calling change_state() on canister {} failed: {}",
                            canister.canister_id_vec8()[0],
                            e
                        )
                    });
                assert_eq!(
                    res,
                    Ok(x),
                    "Changed state {} times, result should have been Ok({}), was {:?}",
                    x,
                    x,
                    res
                );
            }
            println!("Updated canisters {} times, it is now {}", x, Utc::now());
            let time = sleeptime.unwrap_or(TEST_DURATION_SECONDS as u64) / (total_changes as u64);
            let delay = Duration::from_secs(time);
            std::thread::sleep(delay); // x: i32
        }
    } else {
        for x in 1..=size_level {
            println!("Start expanding canisters, it is now {}", Utc::now());
            for (i, canister) in canisters.iter().enumerate() {
                let seed = i + (x - 1) * num_canisters + random_seed;
                let res: Result<u8, String> = canister
                    .update_("expand_state", dfn_json::json, (x as u32, seed as u32))
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "Calling expand_state() on canister {} failed: {}",
                            canister.canister_id_vec8()[0],
                            e
                        )
                    });
                assert_eq!(
                    res,
                    Ok(x as u8),
                    "Expanded state {} times, result should have been Ok({}), was {:?}",
                    x,
                    x,
                    res
                );
            }
            println!("Expanded canisters {} times, it is now {}", x, Utc::now());
            let time = sleeptime.unwrap_or(TEST_DURATION_SECONDS as u64) / size_level as u64;
            let delay = Duration::from_secs(time);
            std::thread::sleep(delay); // x: i32
        }
    }
}
