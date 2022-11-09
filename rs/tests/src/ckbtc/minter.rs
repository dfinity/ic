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
    ckbtc::lib::{
        activate_ecdsa_signature, create_canister, install_ledger, install_minter, print_subnets,
        subnet_app, subnet_sys, ADDRESS_LENGTH, RETRIEVE_BTC_MIN_AMOUNT, RETRIEVE_BTC_MIN_FEE,
        TEST_KEY_LOCAL, TRANSFER_FEE,
    },
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
        universal_vm::UniversalVms,
    },
    util::{assert_create_agent, block_on, delay, runtime_from_url, UniversalCanister},
};
use bitcoincore_rpc::{bitcoin::Address, Auth, Client, RpcApi};
use candid::{Decode, Encode, Nat, Principal};
use canister_test::Canister;
use ic_base_types::PrincipalId;
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::updates::{
    get_btc_address::GetBtcAddressArgs,
    get_withdrawal_account::{compute_subaccount, GetWithdrawalAccountResult},
    retrieve_btc::{RetrieveBtcArgs, RetrieveBtcError},
    update_balance::{UpdateBalanceArgs, UpdateBalanceError, UpdateBalanceResult},
};
use ic_icrc1::endpoints::{
    BlockIndex, GetTransactionsRequest, GetTransactionsResponse, TransferArg, TransferError,
};
use ic_icrc1::{Account, Subaccount};
use ic_icrc1_agent::{CallMode, Icrc1Agent, Icrc1AgentError};
use ic_universal_canister::{management, wasm};
use slog::{debug, info, Logger};
use std::time::{Duration, Instant};

const UNIVERSAL_VM_NAME: &str = "btc-node";

const UPDATE_BALANCE_TIMEOUT: Duration = Duration::from_secs(300);

/// The default value of minimum confirmations on the Bitcoin server.
const BTC_MIN_CONFIRMATIONS: u64 = 6;

/// The initial amount of Satoshi per blocks (before halving).
const BTC_BLOCK_SIZE: u64 = 50_0000_0000;

pub fn test_get_btc_address(env: TestEnv) {
    let logger = env.logger();
    let subnet_app = subnet_app(&env);
    let subnet_sys = subnet_sys(&env);
    let node = subnet_app.nodes().next().expect("No node in app subnet.");
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_subnet_id = subnet_app.subnet_id;
    print_subnets(&env);

    block_on(async {
        let runtime = runtime_from_url(node.get_public_url());
        let mut ledger_canister = create_canister(&runtime).await;
        let mut minter_canister = create_canister(&runtime).await;
        let minting_user = minter_canister.canister_id().get();
        let ledger_id = install_ledger(&env, &mut ledger_canister, minting_user, &logger).await;
        let minter_id = install_minter(&env, &mut minter_canister, ledger_id, &logger).await;
        let minter = Principal::try_from_slice(minter_id.as_ref()).unwrap();
        let agent = assert_create_agent(node.get_public_url().as_str()).await;
        activate_ecdsa_signature(sys_node, app_subnet_id, TEST_KEY_LOCAL, &logger).await;

        // Call endpoint.
        info!(logger, "Calling get_btc_address endpoint...");
        let arg = GetBtcAddressArgs { subaccount: None };
        let arg = &Encode!(&arg).expect("Error while encoding arg.");
        let res = agent
            .update(&minter, "get_btc_address")
            .with_arg(arg)
            .call_and_wait(delay())
            .await
            .expect("Error while calling endpoint.");
        let address = Decode!(res.as_slice(), String).expect("Error while decoding response.");

        // Checking only proper format of address since ECDSA signature is non-deterministic.
        assert_eq!(ADDRESS_LENGTH, address.len());
        assert!(
            address.starts_with("bcrt"),
            "Expected Regtest address format."
        );
    });
}

pub fn test_get_withdrawal_account(env: TestEnv) {
    let logger = env.logger();
    let subnet_app = subnet_app(&env);
    let subnet_sys = subnet_sys(&env);
    let node = subnet_app.nodes().next().expect("No node in app subnet.");
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_subnet_id = subnet_app.subnet_id;
    print_subnets(&env);

    block_on(async {
        let runtime = runtime_from_url(node.get_public_url());
        let mut ledger_canister = create_canister(&runtime).await;
        let mut minter_canister = create_canister(&runtime).await;
        let minting_user = minter_canister.canister_id().get();
        let ledger_id = install_ledger(&env, &mut ledger_canister, minting_user, &logger).await;
        let minter_id = install_minter(&env, &mut minter_canister, ledger_id, &logger).await;
        let minter = Principal::try_from_slice(minter_id.as_ref()).unwrap();
        let agent = assert_create_agent(node.get_public_url().as_str()).await;
        activate_ecdsa_signature(sys_node, app_subnet_id, TEST_KEY_LOCAL, &logger).await;

        // Call endpoint.
        let arg = GetBtcAddressArgs { subaccount: None };
        let arg = &Encode!(&arg).expect("Error while encoding argument.");
        let res = agent
            .update(&minter, "get_withdrawal_account")
            .with_arg(arg)
            .call_and_wait(delay())
            .await
            .expect("Error while calling endpoint.");
        let res = Decode!(res.as_slice(), GetWithdrawalAccountResult)
            .expect("Error while decoding response.");

        // Check results.
        let caller = agent
            .get_principal()
            .expect("Error while getting principal.");
        let subaccount = compute_subaccount(PrincipalId::from(caller), 0);
        assert_eq!(
            Account {
                owner: minter_id.get(),
                subaccount: Some(subaccount),
            },
            res.account
        );
    });
}

/// Test update_balance method of the minter canister.
/// Verify proper state preservation after canister update.
/// Verify proper utxo management in case of a ledger failure during the mint operation.
pub fn test_update_balance(env: TestEnv) {
    let logger = env.logger();
    let subnet_app = subnet_app(&env);
    let subnet_sys = subnet_sys(&env);
    let node = subnet_app.nodes().next().expect("No node in app subnet.");
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_subnet_id = subnet_app.subnet_id;

    // Get access to btc replica.
    let btc_rpc = get_btc_client(&env);

    // Create wallet if required.
    ensure_wallet(&btc_rpc, &logger);

    let default_btc_address = btc_rpc.get_new_address(None, None).unwrap();
    // Creating the 10 first block to reach the min confirmations of the minter canister.
    debug!(
        &logger,
        "Generating 10 blocks to default address: {}", &default_btc_address
    );
    btc_rpc
        .generate_to_address(10, &default_btc_address)
        .unwrap();

    block_on(async {
        let runtime = runtime_from_url(node.get_public_url());
        let mut ledger_canister = create_canister(&runtime).await;
        let mut minter_canister = create_canister(&runtime).await;
        let minting_user = minter_canister.canister_id().get();
        let ledger_id = install_ledger(&env, &mut ledger_canister, minting_user, &logger).await;
        let minter_id = install_minter(&env, &mut minter_canister, ledger_id, &logger).await;
        let minter = Principal::from(minter_id.get());
        let ledger = Principal::from(ledger_id.get());
        let agent = assert_create_agent(node.get_public_url().as_str()).await;
        let universal_canister = UniversalCanister::new(&agent, node.effective_canister_id()).await;
        activate_ecdsa_signature(sys_node, app_subnet_id, TEST_KEY_LOCAL, &logger).await;

        let ledger_agent = Icrc1Agent {
            agent: agent.clone(),
            ledger_canister_id: ledger,
        };
        let minter_agent = CkBtcMinterAgent {
            agent: agent.clone(),
            minter_canister_id: minter,
        };

        let caller = agent
            .get_principal()
            .expect("Error while getting principal.");
        let subaccount0 = compute_subaccount(PrincipalId::from(caller), 0);
        let subaccount1 = compute_subaccount(PrincipalId::from(caller), 567);
        let subaccount2 = compute_subaccount(PrincipalId::from(caller), 890);
        let account1 = Account {
            owner: PrincipalId::from(caller),
            subaccount: Some(subaccount1),
        };
        let account2 = Account {
            owner: PrincipalId::from(caller),
            subaccount: Some(subaccount2),
        };

        // Get the BTC address of the caller's sub-accounts.
        let btc_address0 = get_btc_address(&minter_agent, &logger, subaccount0).await;
        let btc_address1 = get_btc_address(&minter_agent, &logger, subaccount1).await;
        let btc_address2 = get_btc_address(&minter_agent, &logger, subaccount2).await;

        // -- beginning of test logic --

        // We shouldn't have any new utxo for now.
        assert_no_new_utxo(&minter_agent, &subaccount0).await;
        assert_no_new_utxo(&minter_agent, &subaccount1).await;
        assert_no_new_utxo(&minter_agent, &subaccount2).await;

        // Mint block to the first sub-account (with single utxo).
        generate_blocks(&btc_rpc, &logger, 3, &btc_address1);
        generate_blocks(&btc_rpc, &logger, BTC_MIN_CONFIRMATIONS, &btc_address0);
        wait_for_bitcoin_balance(
            &universal_canister,
            &logger,
            BTC_MIN_CONFIRMATIONS * BTC_BLOCK_SIZE,
            &btc_address0,
        )
        .await;

        // Without calling update_balance, ledger balance shouldn't change even with new utxo.
        // Verify that no transaction appears on the ledger.
        assert_no_transaction(&ledger_agent, &logger).await;

        // Verify that calling update_balance on one account doesn't impact the others.
        debug!(&logger, "Calling update balance on first subaccount.");
        let update_result = update_balance(&minter_agent, &logger, &subaccount1).await;
        // The other subaccount should not be impacted.
        assert_no_new_utxo(&minter_agent, &subaccount2).await;
        assert_mint_transaction(
            &ledger_agent,
            &logger,
            update_result.block_index,
            &account1,
            3 * BTC_BLOCK_SIZE,
        )
        .await;
        // Calling update_balance again will always trigger a NoNewUtxo error.
        upgrade_canister(&mut minter_canister).await;
        assert_no_new_utxo(&minter_agent, &subaccount1).await;

        // Now triggering a failure on the ledger canister.
        info!(&logger, "Simulating failure on the ledger canister");
        stop_canister(&ledger_canister).await;

        // Mint blocks to the second sub-account (with multiple utxos).
        generate_blocks(&btc_rpc, &logger, 5, &btc_address2);
        generate_blocks(&btc_rpc, &logger, 1, &btc_address2);
        generate_blocks(&btc_rpc, &logger, 1, &btc_address2);
        generate_blocks(&btc_rpc, &logger, BTC_MIN_CONFIRMATIONS, &btc_address0);
        wait_for_bitcoin_balance(
            &universal_canister,
            &logger,
            2 * BTC_MIN_CONFIRMATIONS * BTC_BLOCK_SIZE,
            &btc_address0,
        )
        .await;

        debug!(
            &logger,
            "Calling update balance on second subaccount with missing ledger."
        );
        assert_temporarily_unavailable(&minter_agent, &subaccount2).await;

        // The ledger canister is back online.
        start_canister(&ledger_canister).await;

        debug!(
            &logger,
            "Calling update balance on second subaccount with ledger started again."
        );
        let update_result = update_balance(&minter_agent, &logger, &subaccount2).await;
        // The other subaccount should not be impacted.
        assert_no_new_utxo(&minter_agent, &subaccount1).await;
        assert_mint_transaction(
            &ledger_agent,
            &logger,
            update_result.block_index,
            &account2,
            7 * BTC_BLOCK_SIZE,
        )
        .await;
        // Calling update_balance again will always trigger a NoNewUtxo error.
        upgrade_canister(&mut minter_canister).await;
        assert_no_new_utxo(&minter_agent, &subaccount2).await;
    });
}

/// Test retrieve_btc method of the minter canister.
pub fn test_retrieve_btc(env: TestEnv) {
    let logger = env.logger();
    let subnet_app = subnet_app(&env);
    let subnet_sys = subnet_sys(&env);
    let node = subnet_app.nodes().next().expect("No node in app subnet.");
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_subnet_id = subnet_app.subnet_id;
    let btc_rpc = get_btc_client(&env);
    ensure_wallet(&btc_rpc, &logger);

    let default_btc_address = btc_rpc.get_new_address(None, None).unwrap();
    // Creating the 10 first block to reach the min confirmations of the minter canister.
    debug!(
        &logger,
        "Generating 10 blocks to default address: {}", &default_btc_address
    );
    btc_rpc
        .generate_to_address(10, &default_btc_address)
        .unwrap();

    block_on(async {
        let runtime = runtime_from_url(node.get_public_url());
        let mut ledger_canister = create_canister(&runtime).await;
        let mut minter_canister = create_canister(&runtime).await;
        let minting_user = minter_canister.canister_id().get();
        let ledger_id = install_ledger(&env, &mut ledger_canister, minting_user, &logger).await;
        let minter_id = install_minter(&env, &mut minter_canister, ledger_id, &logger).await;
        let minter = Principal::from(minter_id.get());
        let ledger = Principal::from(ledger_id.get());
        let agent = assert_create_agent(node.get_public_url().as_str()).await;
        let universal_canister = UniversalCanister::new(&agent, node.effective_canister_id()).await;
        activate_ecdsa_signature(sys_node, app_subnet_id, TEST_KEY_LOCAL, &logger).await;

        let ledger_agent = Icrc1Agent {
            agent: agent.clone(),
            ledger_canister_id: ledger,
        };
        let minter_agent = CkBtcMinterAgent {
            agent: agent.clone(),
            minter_canister_id: minter,
        };

        let caller = agent
            .get_principal()
            .expect("Error while getting principal.");
        let subaccount0 = compute_subaccount(PrincipalId::from(caller), 0);
        let subaccount1 = compute_subaccount(PrincipalId::from(caller), 567);
        let subaccount2 = compute_subaccount(PrincipalId::from(caller), 890);
        let account1 = Account {
            owner: PrincipalId::from(caller),
            subaccount: Some(subaccount1),
        };

        // Get the BTC address of the caller's sub-accounts.
        let btc_address0 = get_btc_address(&minter_agent, &logger, subaccount0).await;
        let btc_address1 = get_btc_address(&minter_agent, &logger, subaccount1).await;
        let btc_address2 = get_btc_address(&minter_agent, &logger, subaccount2).await;

        // -- beginning of test logic --
        // Scenario: We are minting btc to account 1, minting ckbtc out of it,
        // transferring ckbtc to the withdraw account, calling retrieve_btc.

        // Start by creating ckBTC to the first subaccount.
        generate_blocks(&btc_rpc, &logger, 3, &btc_address1);
        generate_blocks(&btc_rpc, &logger, BTC_MIN_CONFIRMATIONS, &btc_address0);
        wait_for_bitcoin_balance(
            &universal_canister,
            &logger,
            BTC_MIN_CONFIRMATIONS * BTC_BLOCK_SIZE,
            &btc_address0,
        )
        .await;
        let update_result = update_balance(&minter_agent, &logger, &subaccount1).await;
        assert_mint_transaction(
            &ledger_agent,
            &logger,
            update_result.block_index,
            &account1,
            3 * BTC_BLOCK_SIZE,
        )
        .await;

        // Now test retrieve_btc logic.
        // Get the subaccount used for btc retrieval.
        let withdrawal_account = minter_agent
            .get_withdrawal_account()
            .await
            .expect("Error while calling get_withdrawal_account")
            .account;
        info!(&logger, "Transferring to the minter the ckBTC to be burned");
        let transfer_amount = 42_000_000;
        let transfer_result = ledger_agent
            .transfer(TransferArg {
                from_subaccount: Some(subaccount1),
                to: withdrawal_account.clone(),
                fee: None,
                created_at_time: None,
                memo: None,
                amount: Nat::from(transfer_amount),
            })
            .await
            .expect("Error while calling transfer")
            .expect("Error during transfer");
        debug!(
            &logger,
            "Transfer to the minter account occurred at block {}", transfer_result
        );
        info!(
            &logger,
            "Verify account1 balance on the ledger (adjusted for fee)"
        );
        assert_account_balance(
            &ledger_agent,
            &account1,
            3 * BTC_BLOCK_SIZE - transfer_amount - TRANSFER_FEE,
        )
        .await;
        info!(&logger, "Verify withdrawal_account balance on the ledger");
        assert_account_balance(&ledger_agent, &withdrawal_account, transfer_amount).await;

        info!(&logger, "Call retrieve_btc");
        let retrieve_result = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: 35_000_000,
                fee: None,
                address: btc_address2.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc")
            .expect("Error in retrieve_btc");
        assert_eq!(2, retrieve_result.block_index);

        info!(&logger, "Call retrieve_btc with insufficient funds");
        let retrieve_result = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: 35_000_000,
                fee: None,
                address: btc_address2.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc");
        assert_eq!(
            Err(RetrieveBtcError::LedgerError(
                TransferError::InsufficientFunds {
                    balance: Nat::from(7_000_000u64)
                }
            )),
            retrieve_result
        );

        info!(&logger, "Call retrieve_btc with insufficient fee");
        let retrieve_result = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: 1_000_000,
                fee: Some(80),
                address: btc_address2.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc");
        assert_eq!(
            Err(RetrieveBtcError::FeeTooLow(RETRIEVE_BTC_MIN_FEE)),
            retrieve_result
        );

        info!(&logger, "Call retrieve_btc with insufficient amount");
        let retrieve_result = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: 33,
                fee: None,
                address: btc_address2.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc");
        assert_eq!(
            Err(RetrieveBtcError::AmountTooLow(RETRIEVE_BTC_MIN_AMOUNT)),
            retrieve_result
        );

        // Verify that a burn transaction occurred.
        assert_burn_transaction(&ledger_agent, &logger, 2, &withdrawal_account, 35_000_000).await;

        // Testing maximum amount of concurrent requests
        // NB: remove this test once heartbeat is done.
        debug!(&logger, "Testing transfers up to max concurrency");
        for i in 1..100 {
            let retrieve_result = minter_agent
                .retrieve_btc(RetrieveBtcArgs {
                    amount: 70_000,
                    fee: None,
                    address: btc_address2.to_string(),
                })
                .await
                .expect("Error while calling retrieve_btc")
                .expect("Error in retrieve_btc");
            assert_eq!(i + 2, retrieve_result.block_index);
        }
        // One additional transfer should trigger an error.
        debug!(&logger, "Testing one more transfer");
        let retrieve_result = minter_agent
            .retrieve_btc(RetrieveBtcArgs {
                amount: 70_000,
                fee: None,
                address: btc_address2.to_string(),
            })
            .await
            .expect("Error while calling retrieve_btc");
        assert_eq!(
            Err(RetrieveBtcError::TooManyConcurrentRequests),
            retrieve_result
        );
    });
}

async fn stop_canister(canister: &Canister<'_>) {
    let stop_result = canister.stop().await;
    assert!(
        stop_result.is_ok(),
        "Error while stopping the ledger canister"
    );
}

async fn start_canister(canister: &Canister<'_>) {
    let result = canister.stop_then_restart().await;
    assert!(result.is_ok(), "Error while starting the ledger canister");
}

/// Mint some blocks to the given address.
fn generate_blocks(btc_client: &Client, logger: &Logger, nb_blocks: u64, address: &Address) {
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
/// Timeout after UPDATE_BALANCE_TIMEOUT if the expected balance is not reached.
async fn wait_for_bitcoin_balance<'a>(
    canister: &UniversalCanister<'a>,
    logger: &Logger,
    expected_balance_in_satoshis: u64,
    btc_address: &Address,
) {
    let mut balance = 0;
    let start = Instant::now();
    while balance != expected_balance_in_satoshis {
        if start.elapsed() >= UPDATE_BALANCE_TIMEOUT {
            panic!("update_balance timeout");
        };
        balance = get_bitcoin_balance(canister, btc_address).await;
        debug!(
            &logger,
            "current balance: {}, expecting {}", balance, expected_balance_in_satoshis
        );
    }
}

async fn update_balance(
    ckbtc_minter_agent: &CkBtcMinterAgent,
    logger: &Logger,
    subaccount: &Subaccount,
) -> UpdateBalanceResult {
    let result = ckbtc_minter_agent
        .update_balance(UpdateBalanceArgs {
            subaccount: Some(*subaccount),
        })
        .await
        .expect("Error while calling update_balance")
        .expect("Error while updating balance");
    info!(
        &logger,
        "New Balance added: {} at block index {}", result.amount, result.block_index
    );
    result
}

/// Get the Bitcoin address for the given subaccount.
async fn get_btc_address(
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

/// Create a client for bitcoind.
fn get_btc_client(env: &TestEnv) -> Client {
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

async fn get_bitcoin_balance<'a>(canister: &UniversalCanister<'a>, btc_address: &Address) -> u64 {
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

async fn upgrade_canister(canister: &mut Canister<'_>) {
    let upgrade_result = canister.upgrade_to_self_binary(Vec::new()).await;
    assert!(upgrade_result.is_ok(), "Error while upgrading canister");
}

/// Verify the account balance on the ledger.
async fn assert_account_balance(agent: &Icrc1Agent, account: &Account, expected_balance: u64) {
    assert_eq!(
        Nat::from(expected_balance),
        agent
            .balance_of(account.clone(), CallMode::Query)
            .await
            .expect("Error while calling balance_of")
    );
}

/// Verify that a mint transaction exists on the ledger at given block.
async fn assert_mint_transaction(
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
async fn assert_burn_transaction(
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

async fn assert_no_transaction(agent: &Icrc1Agent, logger: &Logger) {
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
async fn assert_no_new_utxo(agent: &CkBtcMinterAgent, subaccount: &Subaccount) {
    assert_update_balance_error(agent, subaccount, UpdateBalanceError::NoNewUtxos).await;
}

async fn assert_temporarily_unavailable(agent: &CkBtcMinterAgent, subaccount: &Subaccount) {
    let result = agent
        .update_balance(UpdateBalanceArgs {
            subaccount: Some(*subaccount),
        })
        .await
        .expect("Error while calling update_balance");
    matches!(result, Err(UpdateBalanceError::TemporarilyUnavailable(..)));
}

async fn assert_update_balance_error(
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
fn ensure_wallet(btc_rpc: &Client, logger: &Logger) {
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
async fn get_ledger_transactions(
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
