/* tag::catalog[]

Title:: ckBTC minter endpoints.

Goal:: Ensure the ckBTC minter endpoints are working and returning expected values.

Runbook::
0. Instantiate an IC with one System and one Application subnet.
1. Install NNS canisters on the System subnet.
2. Build and install ledger canister and ckBTC minter canister on application subnet.
3. Activate ECDSA signature on subnet.
4. Perform calls and verify results for following endpoints:
    - get_btc_address
    - get_withdrawal_account
    - update_balance
        - with canister upgrades to verify proper state preservation.
        - with ledger failure simulation to verify proper utxo handling.
    - retrieve_btc

end::catalog[] */

use crate::{
    ckbtc::lib::ADDRESS_LENGTH,
    driver::{test_env::TestEnv, universal_vm::UniversalVms},
    util::UniversalCanister,
};
use bitcoincore_rpc::{
    bitcoin::{Address, Amount, Txid},
    bitcoincore_rpc_json, Auth, Client, RpcApi,
};
use candid::{Decode, Encode, Nat};
use canister_test::Canister;
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::state::RetrieveBtcStatus;
use ic_ckbtc_minter::updates::update_balance::{
    UpdateBalanceArgs, UpdateBalanceError, UpdateBalanceResult,
};
use ic_icrc1::endpoints::{BlockIndex, GetTransactionsRequest, GetTransactionsResponse};
use ic_icrc1::{Account, Subaccount};
use ic_icrc1_agent::{CallMode, Icrc1Agent, Icrc1AgentError};
use ic_universal_canister::{management, wasm};
use slog::{debug, info, Logger};
use std::time::{Duration, Instant};

pub const UNIVERSAL_VM_NAME: &str = "btc-node";

pub const TIMEOUT_30S: Duration = Duration::from_secs(300);
pub const RETREIEVE_BTC_STATUS_TIMEOUT: Duration = Duration::from_secs(600);

/// The default value of minimum confirmations on the Bitcoin server.
pub const BTC_MIN_CONFIRMATIONS: u64 = 6;

/// The initial amount of Satoshi per blocks (before halving).
pub const BTC_BLOCK_SIZE: u64 = 50_0000_0000;

pub async fn stop_canister(canister: &Canister<'_>) {
    let stop_result = canister.stop().await;
    assert!(
        stop_result.is_ok(),
        "Error while stopping the ledger canister"
    );
}

pub async fn start_canister(canister: &Canister<'_>) {
    let result = canister.stop_then_restart().await;
    assert!(result.is_ok(), "Error while starting the ledger canister");
}

/// Mint some blocks to the given address.
pub fn generate_blocks(btc_client: &Client, logger: &Logger, nb_blocks: u64, address: &Address) {
    let generated_blocks = btc_client.generate_to_address(nb_blocks, address).unwrap();
    info!(&logger, "Generated {} btc blocks.", generated_blocks.len());
    assert_eq!(
        generated_blocks.len() as u64,
        nb_blocks,
        "Expected {} blocks.",
        nb_blocks
    );
}

/// Wait for the expected balance to be available at the given btc address.
/// Timeout after TIMEOUT_30S if the expected balance is not reached.
pub async fn wait_for_bitcoin_balance<'a>(
    canister: &UniversalCanister<'a>,
    logger: &Logger,
    expected_balance_in_satoshis: u64,
    btc_address: &Address,
) {
    let mut balance = 0;
    let start = Instant::now();
    while balance != expected_balance_in_satoshis {
        if start.elapsed() >= TIMEOUT_30S {
            panic!("update_balance timeout");
        };
        balance = get_bitcoin_balance(canister, btc_address).await;
        debug!(
            &logger,
            "current balance: {}, expecting {}", balance, expected_balance_in_satoshis
        );
    }
}

/// Wait until we have a tx in btc mempool
/// Timeout after TIMEOUT_30S if the minter doesn't successfully find a new tx in the timeframe.
pub async fn wait_for_mempool_change(btc_rpc: &Client, logger: &Logger) -> Vec<Txid> {
    let start = Instant::now();
    loop {
        if start.elapsed() >= TIMEOUT_30S {
            panic!("No new utxos in mempool timeout");
        };
        match btc_rpc.get_raw_mempool() {
            Ok(r) => {
                for txid in r.iter() {
                    info!(&logger, "Tx in mempool : {:?}", txid);
                }
                if !r.is_empty() {
                    return r;
                }
            }
            Err(e) => {
                info!(&logger, "Error {}", e.to_string());
            }
        };
    }
}

/// Wait for minter to send a tx.
/// Timeout after RETREIEVE_BTC_STATUS_TIMEOUT if the minter doesn't send a new tx.
pub async fn wait_for_signed_tx(
    ckbtc_minter_agent: &CkBtcMinterAgent,
    logger: &Logger,
    block_index: u64,
) -> [u8; 32] {
    let start = Instant::now();
    loop {
        if start.elapsed() >= RETREIEVE_BTC_STATUS_TIMEOUT {
            panic!("No new signed tx emitted by minter");
        };
        match ckbtc_minter_agent
            .retrieve_btc_status(block_index)
            .await
            .expect("failed to call retrieve_btc_status")
        {
            RetrieveBtcStatus::Pending => {
                info!(&logger, "[retrieve_btc_status] : Tx building (1/3)")
            }
            RetrieveBtcStatus::Signing => {
                info!(&logger, "[retrieve_btc_status] : Tx signing (2/3)")
            }
            RetrieveBtcStatus::Sending { txid } => {
                info!(&logger, "[retrieve_btc_status] : Tx sent to mempool (3/3)");
                return txid;
            }
            status => info!(
                &logger,
                "[retrieve_btc_status] unexpected status, got : {:?}", status
            ),
        }
    }
}

/// Wait for the minter to find new utxos
/// Timeout after TIMEOUT_30S if the minter doesn't find new utxos in the time limit.
pub async fn wait_for_update_balance(
    ckbtc_minter_agent: &CkBtcMinterAgent,
    logger: &Logger,
    subaccount: Option<Subaccount>,
) {
    debug!(logger, "Calling update balance");
    let start = Instant::now();
    let mut update_result = ckbtc_minter_agent
        .update_balance(UpdateBalanceArgs { subaccount })
        .await
        .expect("Error while calling update_balance");
    while update_result.is_err() {
        if start.elapsed() >= TIMEOUT_30S {
            panic!("update_balance timeout");
        };
        update_result = ckbtc_minter_agent
            .update_balance(UpdateBalanceArgs { subaccount })
            .await
            .expect("Error while calling update_balance");
    }
}

pub async fn update_balance(
    ckbtc_minter_agent: &CkBtcMinterAgent,
    logger: &Logger,
    subaccount: Option<Subaccount>,
) -> Result<UpdateBalanceResult, UpdateBalanceError> {
    debug!(logger, "Calling update balance");
    ckbtc_minter_agent
        .update_balance(UpdateBalanceArgs { subaccount })
        .await
        .expect("Error while calling update_balance")
}

pub async fn update_balance_without_subaccount(
    ckbtc_minter_agent: &CkBtcMinterAgent,
) -> Result<UpdateBalanceResult, UpdateBalanceError> {
    let result = ckbtc_minter_agent
        .update_balance(UpdateBalanceArgs { subaccount: None })
        .await
        .expect("Error while calling update_balance");
    result
}

/// Get the Bitcoin address for the given subaccount.
pub async fn get_btc_address(
    agent: &CkBtcMinterAgent,
    logger: &Logger,
    subaccount: Subaccount,
) -> Address {
    let address = agent
        .get_btc_address(Some(subaccount))
        .await
        .expect("Error while calling get_btc_address");
    debug!(logger, "Btc address for subaccount is: {}", address);
    // Checking only proper format of address since ECDSA signature is non-deterministic.
    assert_eq!(ADDRESS_LENGTH, address.len());
    address.parse().unwrap()
}

pub async fn send_to_btc_address(btc_rpc: &Client, logger: &Logger, dst: &Address, amount: u64) {
    match btc_rpc.send_to_address(
        dst,
        Amount::from_sat(amount),
        None,
        None,
        Some(true),
        Some(true),
        None,
        Some(bitcoincore_rpc_json::EstimateMode::Unset),
    ) {
        Ok(txid) => {
            debug!(&logger, "txid: {:?}", txid);
        }
        Err(e) => {
            panic!("bug: could not send btc to btc client : {}", e);
        }
    }
}

/// Create a client for bitcoind.
pub fn get_btc_client(env: &TestEnv) -> Client {
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    Client::new(
        &format!(
            "http://[{}]:8332",
            deployed_universal_vm.get_vm().unwrap().ipv6
        ),
        Auth::UserPass(
            "btc-dev-preview".to_string(),
            "Wjh4u6SAjT4UMJKxPmoZ0AN2r9qbE-ksXQ5I2_-Hm4w=".to_string(),
        ),
    )
    .unwrap()
}

pub async fn get_bitcoin_balance<'a>(
    canister: &UniversalCanister<'a>,
    btc_address: &Address,
) -> u64 {
    canister
        .update(wasm().call(management::bitcoin_get_balance(
            btc_address.to_string(),
            None,
        )))
        .await
        .map(|res| Decode!(res.as_slice(), u64))
        .unwrap()
        .unwrap()
}

pub async fn upgrade_canister(canister: &mut Canister<'_>) {
    let upgrade_result = canister.upgrade_to_self_binary(Vec::new()).await;
    assert!(upgrade_result.is_ok(), "Error while upgrading canister");
}

/// Verify the account balance on the ledger.
pub async fn assert_account_balance(agent: &Icrc1Agent, account: &Account, expected_balance: u64) {
    assert_eq!(
        Nat::from(expected_balance),
        agent
            .balance_of(account.clone(), CallMode::Query)
            .await
            .expect("Error while calling balance_of")
    );
}

/// Verify that a mint transaction exists on the ledger at given block.
pub async fn assert_mint_transaction(
    agent: &Icrc1Agent,
    logger: &Logger,
    block_index: u64,
    to: &Account,
    amount: u64,
) {
    debug!(
        &logger,
        "Looking for a mint transaction at block {}", block_index
    );
    let res = get_ledger_transactions(
        agent,
        GetTransactionsRequest {
            start: BlockIndex::from(block_index),
            length: Nat::from(1u32),
        },
    )
    .await
    .expect("Error while getting ledger transaction");
    assert_eq!(1, res.transactions.len(), "Expecting one transaction");
    let transaction = res.transactions.get(0).unwrap();
    assert_eq!("mint", transaction.kind);
    let mint = transaction
        .mint
        .as_ref()
        .expect("Expecting mint transaction");
    assert_eq!(to, &mint.to, "Expecting mint to account {}", to);
    assert_eq!(
        Nat::from(amount),
        mint.amount,
        "Expecting {} satoshis",
        amount
    );
}

/// Verify that a burn transaction exists on the ledger at given block.
pub async fn assert_burn_transaction(
    agent: &Icrc1Agent,
    logger: &Logger,
    block_index: u64,
    from: &Account,
    amount: u64,
) {
    debug!(
        &logger,
        "Looking for a burn transaction at block {}", block_index
    );
    let res = get_ledger_transactions(
        agent,
        GetTransactionsRequest {
            start: BlockIndex::from(block_index),
            length: Nat::from(1u32),
        },
    )
    .await
    .expect("Error while getting ledger transaction");
    assert_eq!(1, res.transactions.len(), "Expecting one transaction");
    let transaction = res.transactions.get(0).unwrap();
    assert_eq!("burn", transaction.kind);
    let burn = transaction
        .burn
        .as_ref()
        .expect("Expecting burn transaction");
    assert_eq!(from, &burn.from, "Expecting burn from account {}", from);
    assert_eq!(
        Nat::from(amount),
        burn.amount,
        "Expecting {} satoshis",
        amount
    );
}

pub async fn assert_no_transaction(agent: &Icrc1Agent, logger: &Logger) {
    debug!(&logger, "Verifying that no transaction exist.");
    let res = get_ledger_transactions(
        agent,
        GetTransactionsRequest {
            start: BlockIndex::from(0),
            length: Nat::from(1_000u32),
        },
    )
    .await
    .expect("Error while getting ledger transaction");
    assert_eq!(
        Nat::from(0),
        res.log_length,
        "Ledger expected to not have transactions, got {:?}",
        res
    )
}

/// Assert that calling update_balance will throw an error.
pub async fn assert_no_new_utxo(agent: &CkBtcMinterAgent, subaccount: &Subaccount) {
    assert_update_balance_error(agent, subaccount, UpdateBalanceError::NoNewUtxos).await;
}

pub async fn assert_temporarily_unavailable(agent: &CkBtcMinterAgent, subaccount: &Subaccount) {
    let result = agent
        .update_balance(UpdateBalanceArgs {
            subaccount: Some(*subaccount),
        })
        .await
        .expect("Error while calling update_balance");
    matches!(result, Err(UpdateBalanceError::TemporarilyUnavailable(..)));
}

pub async fn assert_update_balance_error(
    agent: &CkBtcMinterAgent,
    subaccount: &Subaccount,
    expected_error: UpdateBalanceError,
) {
    let result = agent
        .update_balance(UpdateBalanceArgs {
            subaccount: Some(*subaccount),
        })
        .await
        .expect("Error while calling update_balance");
    assert_eq!(result, Err(expected_error));
}

/// Ensure wallet existence by creating one if required.
pub fn ensure_wallet(btc_rpc: &Client, logger: &Logger) {
    let wallets = btc_rpc
        .list_wallets()
        .expect("Error while retrieving wallets.");
    if wallets.is_empty() {
        // Create wallet if not existing yet.
        let res = btc_rpc
            .create_wallet("mywallet", None, None, None, None)
            .expect("Error while creating wallet.");
        info!(&logger, "Created wallet: {}", res.name);
    } else {
        info!(&logger, "Existing wallets:");
        for w in wallets {
            info!(&logger, "- wallet: {}", w);
        }
    }
}

/// Get transactions log from the ledger canister.
/// Required since this method is not provided by the icrc1 ledger agent.
pub async fn get_ledger_transactions(
    ic_icrc1_agent: &Icrc1Agent,
    args: GetTransactionsRequest,
) -> Result<GetTransactionsResponse, Icrc1AgentError> {
    let encoded_args = candid::Encode!(&args)?;
    let res = ic_icrc1_agent
        .agent
        .query(&ic_icrc1_agent.ledger_canister_id, "get_transactions")
        .with_arg(encoded_args)
        .call()
        .await?;
    Ok(Decode!(&res, GetTransactionsResponse)?)
}
