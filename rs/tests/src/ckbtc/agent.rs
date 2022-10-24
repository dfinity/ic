/* tag::catalog[]

Title:: ckBTC agent.

Goal:: Ensure the ckBTC agent works properly with the ckBTC minter endpoints.

Runbook::
0. Instantiate an IC with one System and one Application subnet.
1. Install NNS canisters on the System subnet.
2. Build and install ledger canister and ckBTC minter canister on application subnet.
3. Activate ECDSA signature on subnet.
4. Create a ckBTC agent for the ckBTC minter.
4. Perform calls and verify results for following endpoints:
    - get_btc_address
    - get_withdrawal_account

end::catalog[] */

use crate::{
    ckbtc::lib::{
        activate_ecdsa_signature, install_ledger, install_minter, subnet_app, subnet_sys,
        ADDRESS_LENGTH, TEST_KEY_LOCAL,
    },
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    util::{assert_create_agent, block_on},
};
use candid::Principal;
use canister_test::PrincipalId;
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::updates::{
    get_withdrawal_account::{compute_subaccount, GetWithdrawalAccountResult},
    retrieve_btc::RetrieveBtcArgs,
    update_balance::UpdateBalanceArgs,
};
use ic_icrc1::Account;
use slog::info;

pub fn ckbtc_minter_agent_test(env: TestEnv) {
    let logger = env.logger();
    let subnet_app = subnet_app(&env);
    let subnet_sys = subnet_sys(&env);
    let node = subnet_app.nodes().next().expect("No node in app subnet.");
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_subnet_id = subnet_app.subnet_id;

    info!(&logger, "Testing ckBTC minter agent");
    block_on(async {
        let ledger_id = install_ledger(&node, &logger).await;
        let minter_id = install_minter(&node, ledger_id, &logger).await;
        let minter = Principal::try_from_slice(minter_id.as_ref()).unwrap();
        let agent = assert_create_agent(node.get_public_url().as_str()).await;
        activate_ecdsa_signature(sys_node, app_subnet_id, TEST_KEY_LOCAL, &logger).await;

        // Build agent.
        let agent = CkBtcMinterAgent {
            agent,
            minter_canister_id: minter,
        };

        // Test agent endpoints.
        info!(logger, "Testing get_btc_address endpoint...");
        test_get_btc_address(&agent).await;
        info!(logger, "Testing get_withdrawal_account endpoint...");
        test_get_withdrawal_account(&agent).await;
        info!(logger, "Testing retrieve_btc endpoint...");
        test_retrieve_btc(&agent).await;
        info!(logger, "Testing update_balance endpoint...");
        test_update_balance(&agent).await;
    });
}

async fn test_get_btc_address(agent: &CkBtcMinterAgent) {
    let res = agent
        .get_btc_address(None)
        .await
        .expect("Error while decoding response");
    // Checking only proper format of address since ECDSA signature is non-deterministic.
    assert_eq!(ADDRESS_LENGTH, res.len());
    assert!(res.starts_with("bcrt"), "Expected Regtest address format.");
}

async fn test_get_withdrawal_account(agent: &CkBtcMinterAgent) {
    let res = agent
        .get_withdrawal_account()
        .await
        .expect("Error while decoding response.");
    let owner = PrincipalId(agent.agent.get_principal().unwrap());
    let subaccount = compute_subaccount(owner, 0);
    assert_eq!(
        GetWithdrawalAccountResult {
            account: Account {
                owner: PrincipalId(agent.minter_canister_id),
                subaccount: Some(subaccount),
            }
        },
        res
    );
}

async fn test_retrieve_btc(agent: &CkBtcMinterAgent) {
    let args = RetrieveBtcArgs {
        amount: 42_000,
        fee: Some(1_000),
        address: "".to_string(),
    };
    let res = agent
        .retrieve_btc(args)
        .await
        .expect("Error while decoding response.");
    // For now retrieve_btc is not implemented, finish test once available.
    assert!(res.is_err());
}

async fn test_update_balance(agent: &CkBtcMinterAgent) {
    let owner = PrincipalId(agent.agent.get_principal().unwrap());
    let subaccount = compute_subaccount(owner, 0);
    let args = UpdateBalanceArgs { subaccount };
    let res = agent
        .update_balance(args)
        .await
        .expect("Error while decoding response.");
    assert!(res.is_err());
}
