use anyhow::Result;

use bitcoin::{Amount, dogecoin, dogecoin::Address};
use candid::Nat;
use candid::{Decode, Encode, Principal};
use ic_ckdoge_agent::CkDogeMinterAgent;
use ic_ckdoge_minter::{
    UpdateBalanceArgs, UtxoStatus,
    candid_api::{RetrieveDogeStatus, RetrieveDogeWithApprovalArgs, WithdrawalFee},
};
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    systest,
    util::{assert_create_agent, block_on, runtime_from_url},
};
use ic_tests_ckbtc::{
    DOGE_MIN_CONFIRMATIONS, OVERALL_TIMEOUT, TIMEOUT_PER_TEST, adapter::fund_with_btc,
    ckdoge_setup, create_canister, install_ckdoge_minter, install_dogecoin_canister,
    install_ledger, subnet_app, subnet_sys, utils::get_rpc_client,
};
use icrc_ledger_agent::{CallMode, Icrc1Agent};
use icrc_ledger_types::{icrc1::account::Account, icrc2::approve::ApproveArgs};
use slog::{Logger, info};
use std::str::FromStr;

/// Run through the steps of DOGE -> ckDOGE -> DOGE conversions, and ensure correct amounts
/// were transferred at each step.
pub fn test_ckdoge_minter_agent(env: TestEnv) {
    let logger = env.logger();
    let subnet_sys = subnet_sys(&env);
    let subnet_app = subnet_app(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_node = subnet_app.nodes().next().expect("No node in app subnet.");
    let doge_rpc = get_rpc_client::<dogecoin::Network>(&env);

    let default_address = doge_rpc.get_address().unwrap();
    fund_with_btc(&doge_rpc, default_address);

    info!(&logger, "Testing ckDOGE minter agent");
    block_on(async {
        let sys_runtime =
            runtime_from_url(sys_node.get_public_url(), sys_node.effective_canister_id());
        let runtime = runtime_from_url(app_node.get_public_url(), app_node.effective_canister_id());
        install_dogecoin_canister(&sys_runtime, &logger).await;
        let mut ledger_canister = create_canister(&runtime).await;
        let mut minter_canister = create_canister(&runtime).await;
        let minting_user = minter_canister.canister_id().get();
        let agent = assert_create_agent(app_node.get_public_url().as_str()).await;
        let ledger_id = install_ledger(&mut ledger_canister, minting_user, &logger).await;
        let minter_id = install_ckdoge_minter(&mut minter_canister, ledger_id, &logger, 0).await;

        // Build agents.
        let ledger_agent = Icrc1Agent {
            agent: agent.clone(),
            ledger_canister_id: ledger_id.into(),
        };
        let minter_agent = CkDogeMinterAgent {
            agent: agent.clone(),
            minter_canister_id: minter_id.into(),
        };

        // Test agent endpoints.
        info!(logger, "Testing get_doge_address endpoint...");
        let address = test_get_doge_address(&minter_agent).await;

        info!(logger, "Send DOGE to the address {address}...");
        let amount = Amount::from_btc(200.0).unwrap();
        let tx_fee = Amount::from_btc(0.001).unwrap();
        let _txid = doge_rpc
            .send_to(&address, amount, tx_fee)
            .unwrap_or_else(|err| panic!("bug: could not send DOGE to address: {err:?}"));

        info!(logger, "Generate more blocks to finalize...");
        doge_rpc
            .generate_to_address(DOGE_MIN_CONFIRMATIONS, default_address)
            .unwrap();

        info!(logger, "Get UTXOs from dogecoin canister...");
        let sys_agent = assert_create_agent(sys_node.get_public_url().as_str()).await;
        test_get_utxos(&sys_agent, &logger, &address).await;

        info!(logger, "Call update_balance...");
        let received = test_update_balance(&minter_agent, &ledger_agent).await;

        info!(logger, "Call retrieve_doge_with_approval...");
        let to_retrieve = received / 2;
        let original_balance = doge_rpc.get_balance(None).unwrap();
        let (fee, block_index) = test_retrieve_doge_with_approval(
            &minter_agent,
            &ledger_agent,
            default_address,
            to_retrieve,
        )
        .await;

        info!(logger, "Call retrieve_doge_status...");
        test_retrieve_doge_status(&minter_agent, &logger, block_index, || {
            doge_rpc
                .generate_to_address(DOGE_MIN_CONFIRMATIONS, default_address)
                .unwrap();
        })
        .await;
        let new_balance = doge_rpc.get_balance(None).unwrap();
        assert_eq!(
            new_balance,
            original_balance + Amount::from_sat(fee.minter_fee + fee.dogecoin_fee)
        );
    });
}

async fn test_get_utxos(sys_agent: &ic_agent::Agent, logger: &Logger, address: &Address) {
    use ic_btc_interface::{
        GetUtxosRequest, GetUtxosResponse, NetworkInRequest, UtxosFilterInRequest,
    };
    let dogecoin_canister =
        Principal::from_str(ic_config::execution_environment::DOGECOIN_MAINNET_CANISTER_ID)
            .unwrap();
    let retries = 30;
    for i in 1..=30 {
        let res = sys_agent
            .update(&dogecoin_canister, "dogecoin_get_utxos")
            .with_arg(
                Encode!(&GetUtxosRequest {
                    address: address.to_string(),
                    network: NetworkInRequest::Regtest,
                    filter: Some(UtxosFilterInRequest::MinConfirmations(
                        DOGE_MIN_CONFIRMATIONS as u32
                    )),
                })
                .expect("failed to encode GetUtxosRequest"),
            )
            .call_and_wait()
            .await;
        info!(logger, "[{i}/{retries}] get_utxos returns {res:?}");
        if let Ok(res) = res {
            let utxos = Decode!(res.as_slice(), GetUtxosResponse)
                .expect("Failed to decode GetUtxosResponse");
            if !utxos.utxos.is_empty() {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

async fn test_get_doge_address(agent: &CkDogeMinterAgent) -> Address {
    let address = agent
        .get_doge_address(None, None)
        .await
        .expect("Error while decoding response");
    Address::from_str(&address)
        .expect("Invalid Dogecoin address")
        .require_network(dogecoin::Network::Regtest)
        .expect("Not a Regtest address")
}

async fn test_update_balance(minter_agent: &CkDogeMinterAgent, ledger_agent: &Icrc1Agent) -> u64 {
    let caller = minter_agent.agent.get_principal().unwrap();
    let args = UpdateBalanceArgs {
        owner: None,
        subaccount: None,
    };
    let res = minter_agent
        .update_balance(args)
        .await
        .expect("Error while decoding response.");
    assert!(res.is_ok(), "update_balance failed: {res:?}");

    let utxos = res.unwrap();
    let received = utxos
        .into_iter()
        .flat_map(|utxo| {
            if let UtxoStatus::Minted { minted_amount, .. } = utxo {
                Some(minted_amount)
            } else {
                None
            }
        })
        .sum();
    let balance = ledger_agent
        .balance_of(
            Account {
                owner: caller,
                subaccount: None,
            },
            CallMode::Update,
        )
        .await
        .unwrap();
    assert_eq!(balance, Nat::from(received));
    received
}

async fn test_retrieve_doge_with_approval(
    minter_agent: &CkDogeMinterAgent,
    ledger_agent: &Icrc1Agent,
    address: &Address,
    amount: u64,
) -> (WithdrawalFee, u64) {
    use ic_tests_ckbtc::TRANSFER_FEE;

    let account = Account {
        owner: minter_agent.agent.get_principal().unwrap(),
        subaccount: None,
    };
    let balance = ledger_agent
        .balance_of(account, CallMode::Update)
        .await
        .unwrap();
    assert!(amount + TRANSFER_FEE <= balance);
    let args = ApproveArgs {
        spender: Account {
            owner: minter_agent.minter_canister_id,
            subaccount: None,
        },
        amount: Nat::from(amount),
        from_subaccount: None,
        expected_allowance: None,
        expires_at: None,
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let _res = ledger_agent
        .approve(args)
        .await
        .expect("Error while decoding response.");

    let res = minter_agent
        .estimate_withdrawal_fee(amount)
        .await
        .expect("Error while decoding response.");
    assert!(res.is_ok(), "estimate_withdrawal_fee failed: {res:?}");
    let fee = res.unwrap();

    let args = RetrieveDogeWithApprovalArgs {
        amount,
        address: address.to_string(),
        from_subaccount: None,
    };
    let res = minter_agent
        .retrieve_doge_with_approval(args)
        .await
        .expect("Error while decoding response.");
    assert!(res.is_ok(), "retrieve_doge_with_approval failed: {res:?}");

    let new_balance = ledger_agent
        .balance_of(account, CallMode::Update)
        .await
        .unwrap();
    let expected_balance = balance - Nat::from(amount + TRANSFER_FEE);
    assert_eq!(new_balance, expected_balance);

    let retrieve_response = res.unwrap();
    (fee, retrieve_response.block_index)
}

async fn test_retrieve_doge_status<F: Fn()>(
    minter_agent: &CkDogeMinterAgent,
    logger: &Logger,
    block_index: u64,
    generate_blocks: F,
) -> ic_btc_interface::Txid {
    let retries = 30;
    for i in 1..=retries {
        let status = minter_agent
            .retrieve_doge_status(block_index)
            .await
            .expect("failed to call retrieve_doge_status");
        info!(
            &logger,
            "[{i}/{retries}] retrieve_doge_status returns {:?}", status
        );
        match status {
            RetrieveDogeStatus::Confirmed { txid } => {
                return txid;
            }
            RetrieveDogeStatus::Submitted { .. } => generate_blocks(),
            RetrieveDogeStatus::AmountTooLow => break,
            _ => {}
        }
        // Wait a bit to avoid spamming the logs
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
    panic!("retrieve_doge_status failed");
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(TIMEOUT_PER_TEST)
        .with_overall_timeout(OVERALL_TIMEOUT)
        .with_setup(ckdoge_setup)
        .add_test(systest!(test_ckdoge_minter_agent))
        .execute_from_args()?;
    Ok(())
}
