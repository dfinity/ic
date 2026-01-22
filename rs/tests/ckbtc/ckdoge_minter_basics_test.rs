use anyhow::Result;

use candid::{Decode, Encode, Principal};
use ic_ckdoge_agent::CkDogeMinterAgent;
use ic_ckdoge_minter::{
    UpdateBalanceArgs,
    address::DogecoinAddress,
    candid_api::{GetDogeAddressArgs, RetrieveDogeWithApprovalArgs},
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
    ADDRESS_LENGTH, OVERALL_TIMEOUT, TIMEOUT_PER_TEST, ckdoge_setup, create_canister,
    install_bitcoin_canister, install_ckdoge_minter, install_ledger, subnet_app, subnet_sys,
};
use slog::info;

pub fn test_ckdoge_addresses(env: TestEnv) {
    let logger = env.logger();
    let subnet_sys = subnet_sys(&env);
    let subnet_app = subnet_app(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_node = subnet_app.nodes().next().expect("No node in app subnet.");

    block_on(async {
        let sys_runtime =
            runtime_from_url(sys_node.get_public_url(), sys_node.effective_canister_id());
        let runtime = runtime_from_url(app_node.get_public_url(), app_node.effective_canister_id());
        install_bitcoin_canister(&sys_runtime, &logger).await;
        let mut ledger_canister = create_canister(&runtime).await;
        let mut minter_canister = create_canister(&runtime).await;

        let minting_user = minter_canister.canister_id().get();
        let agent = assert_create_agent(app_node.get_public_url().as_str()).await;
        let ledger_id = install_ledger(&mut ledger_canister, minting_user, &logger).await;
        let minter_id = install_ckdoge_minter(&mut minter_canister, ledger_id, &logger, 0).await;
        let minter = Principal::try_from_slice(minter_id.as_ref()).unwrap();

        // Call endpoint get_doge_address
        info!(logger, "Calling get_doge_address endpoint...");
        let arg = GetDogeAddressArgs {
            owner: None,
            subaccount: None,
        };
        let arg = Encode!(&arg).expect("Error while encoding arg.");
        let res = agent
            .update(&minter, "get_doge_address")
            .with_arg(arg)
            .call_and_wait()
            .await
            .expect("Error while calling endpoint.");
        let address = Decode!(res.as_slice(), String).expect("Error while decoding response.");

        // Checking only proper format of address since ECDSA signature is non-deterministic.
        assert!(
            DogecoinAddress::parse(
                &address,
                &ic_ckdoge_minter::lifecycle::init::Network::Regtest
            )
            .is_ok()
        );
    });
}

/* tag::catalog[]

Title:: ckDOGE agent.

Goal:: Ensure the ckDOGE agent works properly with the ckDOGE minter endpoints.

Runbook::
0. Instantiate an IC with one System and one Application subnet.
1. Install NNS canisters on the System subnet.
2. Build and install ledger canister and ckDOGE minter canister on application subnet.
3. Activate ECDSA signature on subnet.
4. Create a ckDOGE agent for the ckDOGE minter.
5. Perform calls and verify results for following endpoints:
    - get_doge_address

end::catalog[] */

pub fn test_ckdoge_minter_agent(env: TestEnv) {
    let logger = env.logger();
    let subnet_app = subnet_app(&env);
    let app_node = subnet_app.nodes().next().expect("No node in app subnet.");

    info!(&logger, "Testing ckDOGE minter agent");
    block_on(async {
        let runtime = runtime_from_url(app_node.get_public_url(), app_node.effective_canister_id());
        let mut ledger_canister = create_canister(&runtime).await;
        let mut minter_canister = create_canister(&runtime).await;

        let minting_user = minter_canister.canister_id().get();
        let agent = assert_create_agent(app_node.get_public_url().as_str()).await;
        let ledger_id = install_ledger(&mut ledger_canister, minting_user, &logger).await;
        let minter_id = install_ckdoge_minter(&mut minter_canister, ledger_id, &logger, 0).await;
        let minter = Principal::try_from_slice(minter_id.as_ref()).unwrap();

        // Build agent.
        let agent = CkDogeMinterAgent {
            agent,
            minter_canister_id: minter,
        };

        // Test agent endpoints.
        info!(logger, "Testing get_doge_address endpoint...");
        test_get_doge_address(&agent).await;
        info!(logger, "Testing retrieve_doge_with_approval endpoint...");
        test_retrieve_doge_with_approval(&agent).await;
        info!(logger, "Testing update_balance endpoint...");
        test_update_balance(&agent).await;
    });
}

async fn test_get_doge_address(agent: &CkDogeMinterAgent) {
    let res = agent
        .get_doge_address(None, None)
        .await
        .expect("Error while decoding response");

    assert!(
        DogecoinAddress::parse(
            &address,
            &ic_ckdoge_minter::lifecycle::init::Network::Regtest
        )
        .is_ok()
    );
}

async fn test_retrieve_doge_with_approval(agent: &CkDogeMinterAgent) {
    let args = RetrieveDogeWithApprovalArgs {
        amount: 42_000,
        address: "".to_string(),
        from_subaccount: None,
    };
    let res = agent
        .retrieve_doge_with_approval(args)
        .await
        .expect("Error while decoding response.");
    assert!(res.is_err());
}

async fn test_update_balance(agent: &CkDogeMinterAgent) {
    let owner = agent.agent.get_principal().unwrap();
    let args = UpdateBalanceArgs {
        owner: Some(owner),
        subaccount: None,
    };
    let res = agent
        .update_balance(args)
        .await
        .expect("Error while decoding response.");
    assert!(res.is_err());
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(TIMEOUT_PER_TEST)
        .with_overall_timeout(OVERALL_TIMEOUT)
        .with_setup(ckdoge_setup)
        .add_test(systest!(test_ckdoge_addresses))
        .add_test(systest!(test_ckdoge_minter_agent))
        .execute_from_args()?;
    Ok(())
}
