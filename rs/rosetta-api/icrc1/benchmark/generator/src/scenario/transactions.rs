use crate::scenario::{
    create_workers, install_code_on_canisters, transfer_cycles_to_canisters,
    transfer_tokens_to_canisters, verify_canister_upgrade, ICP_E8S,
};
use crate::{
    get_index_principal, get_index_wasm, get_worker_wasm, RunScenarioResult, Scenario, NANO,
};
use candid::{Nat, Principal};
use ic_base_types::PrincipalId;
use ic_icrc1_benchmark_worker::{BatchArgs, BatchResult};

const USERS: u32 = 10;

/// The number of worker canisters used to generate traffic.
const NB_WORKERS: u32 = 10;

/// The number of transactions to generate by workers in each batch.
const WORKER_BATCH_TRANSACTIONS: u32 = 5000;

pub(crate) async fn run_benchmark() -> RunScenarioResult {
    // Required for testing canister upgrade.
    let index_wasm = get_index_wasm();
    let index_principal_id = get_index_principal().0;

    // Create worker canisters.
    ic_cdk::println!("Creating {} worker canisters...", NB_WORKERS);
    let workers = create_workers(NB_WORKERS).await;
    // Transfer some cycles to workers.
    transfer_cycles_to_canisters(100_000_000_000_000u128, workers.clone()).await;
    // Install worker canister code.
    let worker_wasm = get_worker_wasm();
    install_code_on_canisters(worker_wasm, workers.clone()).await;

    // Transfer tokens to workers accounts.
    transfer_tokens_to_canisters(10_000_000 * ICP_E8S.get_e8s(), workers.clone()).await;

    // Create users.
    let mut users: Vec<Principal> = vec![];
    for i in 0..USERS {
        users.push(PrincipalId::new_user_test_id(i.into()).0);
    }

    // Ask workers to start generating traffic and regularly verify that index can be upgraded.
    let start = ic_cdk::api::time();
    loop {
        let start_batch = ic_cdk::api::time();
        let mut futures: Vec<_> = vec![];
        for canister_id in &workers {
            let args = BatchArgs {
                transactions: Nat::from(WORKER_BATCH_TRANSACTIONS),
                scenario: ic_icrc1_benchmark_worker::Scenario::Transactions,
                users: Some(users.clone()),
            };
            let future = ic_cdk::call(*canister_id, "run_batch", (args,));
            futures.push(future);
        }
        let res: Vec<(BatchResult,)> = futures::future::try_join_all(futures)
            .await
            .expect("Error during worker transfer batch");
        let last_block = &res.last().unwrap().0.last_block;

        let end_batch = ic_cdk::api::time();
        ic_cdk::println!(
            "[time {} sec] All {} workers completed their batches (size {}).",
            (end_batch - start) / NANO,
            NB_WORKERS,
            WORKER_BATCH_TRANSACTIONS
        );
        let batch_duration_sec = (end_batch - start_batch) / NANO;
        let tx_per_sec = (NB_WORKERS * WORKER_BATCH_TRANSACTIONS) as u64 / batch_duration_sec;
        ic_cdk::println!(
            "Executed {} transactions in {} seconds ({} tx/sec)",
            NB_WORKERS * WORKER_BATCH_TRANSACTIONS,
            batch_duration_sec,
            tx_per_sec
        );

        // Verify index canister upgrade success.
        ic_cdk::println!("[block {}] Testing index canister upgrade", last_block);
        if verify_canister_upgrade(index_principal_id, index_wasm.clone())
            .await
            .is_err()
        {
            ic_cdk::eprintln!("Error while upgrading canister after block {}", last_block);
            let duration_sec = Nat::from((ic_cdk::api::time() - start) / NANO);
            return RunScenarioResult {
                scenario: Scenario::Transactions,
                success: false,
                duration_sec,
                blocks: last_block.clone(),
            };
        }
    }
}
