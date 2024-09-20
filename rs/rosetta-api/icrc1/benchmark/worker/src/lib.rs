use candid::{CandidType, Nat, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use icrc_ledger_client_cdk::{CdkRuntime, ICRC1Client};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg};
use num_traits::ToPrimitive;
use rand::RngCore;
use rand_chacha::{rand_core::SeedableRng, ChaCha8Rng};
use std::cell::RefCell;
use std::cmp::min;

// Crashes above 500 (max ingress queue size).
const BATCH_SIZE: u64 = 500;

const TRANSFER_AMOUNT: u64 = 1_000;

const NANO: u64 = 1_000_000_000;

thread_local! {
    static RNG: RefCell<Option<ChaCha8Rng>> = const { RefCell::new(None) };
    static LEDGER_PRINCIPAL: RefCell<Option<PrincipalId>> = const { RefCell::new(None) };
}

#[derive(Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct InitArgs {
    pub ledger_id: CanisterId,
    pub rand_seed: Nat,
}

#[derive(Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub enum Scenario {
    Accounts,
    Transactions,
}

#[derive(Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct BatchArgs {
    pub transactions: Nat,
    pub scenario: Scenario,
    pub users: Option<Vec<Principal>>,
}

#[derive(Eq, PartialEq, Debug, CandidType, candid::Deserialize)]
pub struct BatchResult {
    success: bool,
    duration_sec: Nat,
    blocks: Nat,
    pub last_block: Nat,
}

pub fn init(args: InitArgs) {
    ic_cdk::println!("Initializing benchmark worker canister...");
    RNG.with(|cell| {
        *cell.borrow_mut() = Some(rand_chacha::ChaCha8Rng::seed_from_u64(
            args.rand_seed
                .0
                .to_u64()
                .expect("Error while converting nat to u64"),
        ))
    });
    LEDGER_PRINCIPAL.with(|cell| *cell.borrow_mut() = Some(args.ledger_id.get()));
}

pub async fn run_batch(batch_args: BatchArgs) -> BatchResult {
    match batch_args.scenario {
        Scenario::Accounts => run_accounts_batch(batch_args).await,
        Scenario::Transactions => run_transactions_batch(batch_args).await,
    }
}

async fn run_accounts_batch(batch_args: BatchArgs) -> BatchResult {
    let client = get_ledger_client();
    let mut nb_blocks: u64 = 0;
    let mut last_block: u64 = 0;
    let mut remaining = batch_args
        .transactions
        .0
        .to_u64()
        .expect("Error while reading args");
    let start = ic_cdk::api::time();
    while remaining > 0 {
        let mut futures: Vec<_> = vec![];
        // Split the transactions in fixed-sized batches.
        let batch_size = min(BATCH_SIZE, remaining);
        for _ in 0..batch_size {
            let to = PrincipalId::new_user_test_id(next_u64());
            let args = TransferArg {
                from_subaccount: None,
                to: Account {
                    owner: to.0,
                    subaccount: None,
                },
                fee: None,
                created_at_time: None,
                memo: Some(Memo::from(next_u64())),
                amount: Nat::from(TRANSFER_AMOUNT),
            };
            futures.push(client.transfer(args));
        }

        // Wait for batch completion.
        let batch_result = futures::future::try_join_all(futures).await;
        if batch_result.is_err() {
            ic_cdk::eprintln!("Error during batch execution: {:?}", batch_result.err());
            let duration_sec = Nat::from((ic_cdk::api::time() - start) / NANO);
            return BatchResult {
                success: false,
                duration_sec,
                blocks: Nat::from(nb_blocks),
                last_block: Nat::from(last_block),
            };
        }
        let res = batch_result.expect("Error while getting batch result");
        nb_blocks += res.len() as u64;
        last_block = res
            .last()
            .expect("No block in result")
            .as_ref()
            .expect("Error while getting last block")
            .0
            .to_u64()
            .expect("nat does not fit into u64");
        ic_cdk::println!(
            "Executed {:?} transfers, last block: {:?}",
            res.len(),
            last_block
        );

        remaining -= batch_size;
        ic_cdk::println!(
            "Ran a batch of {} transactions, {} remaining.",
            batch_size,
            remaining
        );
    }

    let duration_sec = Nat::from((ic_cdk::api::time() - start) / NANO);
    BatchResult {
        success: true,
        duration_sec,
        blocks: Nat::from(nb_blocks),
        last_block: Nat::from(last_block),
    }
}

async fn run_transactions_batch(batch_args: BatchArgs) -> BatchResult {
    let client = get_ledger_client();
    let mut nb_blocks: u64 = 0;
    let mut last_block: u64 = 0;
    let mut remaining = batch_args
        .transactions
        .0
        .to_u64()
        .expect("Error while reading args");

    let users = batch_args
        .users
        .expect("Users required for transactions batch.");
    let nb_users = users.len();
    let mut index = 0;

    let start = ic_cdk::api::time();
    while remaining > 0 {
        let mut futures: Vec<_> = vec![];
        // Split the transactions in fixed-sized batches.
        let batch_size = min(BATCH_SIZE, remaining);
        for _ in 0..batch_size {
            index = (index + 1) % nb_users;
            let to = users[index];
            let args = TransferArg {
                from_subaccount: None,
                to: Account {
                    owner: to,
                    subaccount: None,
                },
                fee: None,
                created_at_time: None,
                memo: Some(Memo::from(next_u64())),
                amount: Nat::from(TRANSFER_AMOUNT),
            };
            futures.push(client.transfer(args));
        }

        // Wait for batch completion.
        let batch_result = futures::future::try_join_all(futures).await;
        if batch_result.is_err() {
            ic_cdk::eprintln!("Error during batch execution: {:?}", batch_result.err());
            let duration_sec = Nat::from((ic_cdk::api::time() - start) / NANO);
            return BatchResult {
                success: false,
                duration_sec,
                blocks: Nat::from(nb_blocks),
                last_block: Nat::from(last_block),
            };
        }
        let res = batch_result.expect("Error while getting batch result");
        nb_blocks += res.len() as u64;
        last_block = res[res.len() - 1]
            .as_ref()
            .expect("Error while getting last block")
            .0
            .to_u64()
            .expect("nat does not fit into u64");
        ic_cdk::println!(
            "Executed {:?} transfers, last block: {:?}",
            res.len(),
            last_block
        );

        remaining -= batch_size;
        ic_cdk::println!(
            "Ran a batch of {} transactions, {} remaining.",
            batch_size,
            remaining
        );
    }

    let duration_sec = Nat::from((ic_cdk::api::time() - start) / NANO);
    BatchResult {
        success: true,
        duration_sec,
        blocks: Nat::from(nb_blocks),
        last_block: Nat::from(last_block),
    }
}

fn get_ledger_client() -> ICRC1Client<CdkRuntime> {
    let ledger_canister_id = Principal::from(get_ledger_principal());
    ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id,
    }
}

/// Return the principal of the ledger canister.
fn get_ledger_principal() -> PrincipalId {
    PrincipalId::from(
        LEDGER_PRINCIPAL.with(|c| c.borrow().expect("Error while getting ledger principal").0),
    )
}

/// Return the next random u64.
fn next_u64() -> u64 {
    RNG.with(|c| {
        c.borrow_mut()
            .as_mut()
            .expect("Error while getting ChaChaRng")
            .next_u64()
    })
}
