use crate::scenario::{
    create_workers, install_code_on_canisters, transfer_cycles_to_canisters,
    transfer_tokens_to_canisters, ICP_E8S,
};
use crate::{get_index_principal, get_worker_wasm, RunScenarioResult, Scenario, NANO};
use candid::{Nat, Principal};
use ic_base_types::PrincipalId;
use ic_icrc1_benchmark_worker::{BatchArgs, BatchResult};
use ic_icrc1_index::{
    GetAccountTransactionsArgs, GetTransactions, GetTransactionsErr, GetTransactionsResult,
};
use icrc_ledger_types::icrc1::account::Account;

const USERS: u32 = 3;

/// The number of worker canisters used to generate traffic.
const NB_WORKERS: u32 = 10;

/// The number of transactions to generate by workers in each batch.
const WORKER_BATCH_TRANSACTIONS: u32 = 10_000;

/// The number of batches to generate.
const NB_BATCHES: u32 = 1;

pub(crate) async fn run_benchmark() -> RunScenarioResult {
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

    // Ask workers to generate traffic for a given number of batches.
    let start = ic_cdk::api::time();
    for _batch in 0..NB_BATCHES {
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
        let _res: Vec<(BatchResult,)> = futures::future::try_join_all(futures)
            .await
            .expect("Error during worker transfer batch");
        // let _last_block = &res.last().unwrap().0.last_block;

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
    }

    // Measure speed of querying the index canister.
    // TODO
    let user = users[0];
    let account = Account {
        owner: user,
        subaccount: None,
    };
    let args = GetAccountTransactionsArgs {
        account,
        start: None,
        max_results: Nat::from(1000_u32),
    };
    let start = ic_cdk::api::time();
    let (res,): (GetTransactionsResult,) =
        ic_cdk::call(index_principal_id, "get_account_transactions", (args,))
            .await
            .expect("Error while calling index canister");
    let end = ic_cdk::api::time();
    let duration_sec = Nat::from((end - start) / NANO);
    let duration_ms = Nat::from((end - start) / 1_000_000);

    match res {
        Ok(GetTransactions {
            transactions,
            oldest_tx_id,
        }) => {
            ic_cdk::println!(
                "Retrieved {} transactions in {} ms",
                transactions.len(),
                duration_ms
            );
            RunScenarioResult {
                scenario: Scenario::IndexPerf,
                success: true,
                duration_sec,
                blocks: oldest_tx_id.unwrap_or_else(|| Nat::from(0_u8)),
            }
        }
        Err(GetTransactionsErr { message }) => {
            ic_cdk::println!("Index canister error: {}", message);
            RunScenarioResult {
                scenario: Scenario::IndexPerf,
                success: false,
                duration_sec,
                blocks: Default::default(),
            }
        }
    }
}
