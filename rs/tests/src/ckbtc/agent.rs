/* tag::catalog[]

Title:: ckBTC agent.

Goal:: Ensure the ckBTC agent works properly with the ckBTC minter endpoints.

Runbook::
0. Instantiate an IC with one System and one Application subnet.
1. Install NNS canisters on the System subnet.
2. Build and install ledger canister and ckBTC minter canister on application subnet.
3. Activate ECDSA signature on subnet.
4. Create a ckBTC agent for the ckBTC minter.
5. Perform calls and verify results for following endpoints:
    - get_btc_address
    - get_withdrawal_account

end::catalog[] */

use crate::ckbtc::lib::{
    activate_ecdsa_signature, create_canister, install_kyt, install_ledger, install_minter,
    set_kyt_api_key, subnet_sys, ADDRESS_LENGTH, TEST_KEY_LOCAL,
};
use candid::Principal;
use canister_test::PrincipalId;
use ic_ckbtc_agent::CkBtcMinterAgent;
use ic_ckbtc_minter::updates::{
    get_withdrawal_account::compute_subaccount, retrieve_btc::RetrieveBtcArgs,
    update_balance::UpdateBalanceArgs,
};
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    util::{assert_create_agent, block_on, runtime_from_url},
};
use icrc_ledger_types::icrc1::account::Account;
use slog::info;

pub fn test_ckbtc_minter_agent(env: TestEnv) {
    let logger = env.logger();
    let subnet_sys = subnet_sys(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");

    info!(&logger, "Testing ckBTC minter agent");
    block_on(async {
        let runtime = runtime_from_url(sys_node.get_public_url(), sys_node.effective_canister_id());
        let mut ledger_canister = create_canister(&runtime).await;
        let mut minter_canister = create_canister(&runtime).await;
        let mut kyt_canister = create_canister(&runtime).await;

        let minting_user = minter_canister.canister_id().get();

        let agent = assert_create_agent(sys_node.get_public_url().as_str()).await;
        let agent_principal = agent.get_principal().unwrap();

        let kyt_id = install_kyt(
            &mut kyt_canister,
            &logger,
            Principal::from(minting_user),
            vec![agent_principal],
        )
        .await;

        set_kyt_api_key(&agent, &kyt_id.get().0, "fake key".to_string()).await;

        let ledger_id = install_ledger(&mut ledger_canister, minting_user, &logger).await;
        let minter_id = install_minter(&mut minter_canister, ledger_id, &logger, 0, kyt_id).await;
        let minter = Principal::try_from_slice(minter_id.as_ref()).unwrap();
        activate_ecdsa_signature(sys_node, subnet_sys.subnet_id, TEST_KEY_LOCAL, &logger).await;

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
        .get_btc_address(None, None)
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
        Account {
            owner: agent.minter_canister_id,
            subaccount: Some(subaccount),
        },
        res
    );
}

async fn test_retrieve_btc(agent: &CkBtcMinterAgent) {
    let args = RetrieveBtcArgs {
        amount: 42_000,
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
    let owner = agent.agent.get_principal().unwrap();
    let subaccount = compute_subaccount(PrincipalId(owner), 0);
    let args = UpdateBalanceArgs {
        owner: None,
        subaccount: Some(subaccount),
    };
    let res = agent
        .update_balance(args)
        .await
        .expect("Error while decoding response.");
    assert!(res.is_err());
}
