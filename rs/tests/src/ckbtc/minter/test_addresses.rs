use crate::ckbtc::lib::install_bitcoin_canister;
use crate::ckbtc::lib::{
    activate_ecdsa_signature, create_canister, install_kyt, install_ledger, install_minter,
    set_kyt_api_key, subnet_sys, ADDRESS_LENGTH, TEST_KEY_LOCAL,
};
use candid::{Decode, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_ckbtc_minter::updates::{
    get_btc_address::GetBtcAddressArgs, get_withdrawal_account::compute_subaccount,
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

pub fn test_ckbtc_addresses(env: TestEnv) {
    let logger = env.logger();
    let subnet_sys = subnet_sys(&env);
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");

    block_on(async {
        let runtime = runtime_from_url(sys_node.get_public_url(), sys_node.effective_canister_id());
        install_bitcoin_canister(&runtime, &logger).await;
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

        // Call endpoint get_btc_address
        info!(logger, "Calling get_btc_address endpoint...");
        let arg = GetBtcAddressArgs {
            owner: None,
            subaccount: None,
        };
        let arg = Encode!(&arg).expect("Error while encoding arg.");
        let res = agent
            .update(&minter, "get_btc_address")
            .with_arg(arg)
            .call_and_wait()
            .await
            .expect("Error while calling endpoint.");
        let address = Decode!(res.as_slice(), String).expect("Error while decoding response.");

        // Checking only proper format of address since ECDSA signature is non-deterministic.
        assert_eq!(ADDRESS_LENGTH, address.len());
        assert!(
            address.starts_with("bcrt"),
            "Expected Regtest address format."
        );

        // Call endpoint get_withdrawal_account
        let arg = GetBtcAddressArgs {
            owner: None,
            subaccount: None,
        };
        let arg = Encode!(&arg).expect("Error while encoding argument.");
        let res = agent
            .update(&minter, "get_withdrawal_account")
            .with_arg(arg)
            .call_and_wait()
            .await
            .expect("Error while calling endpoint.");
        let res = Decode!(res.as_slice(), Account).expect("Error while decoding response.");

        // Check results.
        let caller = agent
            .get_principal()
            .expect("Error while getting principal.");
        let subaccount = compute_subaccount(PrincipalId::from(caller), 0);
        assert_eq!(
            Account {
                owner: minter_id.get().0,
                subaccount: Some(subaccount),
            },
            res
        );
    });
}
