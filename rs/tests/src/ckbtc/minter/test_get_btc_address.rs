use crate::ckbtc::lib::{
    activate_ecdsa_signature, create_canister, install_bitcoin_canister, install_kyt,
    install_ledger, install_minter, subnet_sys, ADDRESS_LENGTH, TEST_KEY_LOCAL,
};
use candid::{Decode, Encode, Principal};
use ic_ckbtc_minter::updates::get_btc_address::GetBtcAddressArgs;
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
    },
    util::{assert_create_agent, block_on, delay, runtime_from_url},
};
use slog::info;

pub fn test_get_btc_address(env: TestEnv) {
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
        let kyt_id = install_kyt(&mut kyt_canister, &logger, Principal::from(minting_user)).await;

        let ledger_id = install_ledger(&mut ledger_canister, minting_user, &logger).await;
        let minter_id = install_minter(&mut minter_canister, ledger_id, &logger, 0, kyt_id).await;
        let minter = Principal::try_from_slice(minter_id.as_ref()).unwrap();
        let agent = assert_create_agent(sys_node.get_public_url().as_str()).await;
        activate_ecdsa_signature(sys_node, subnet_sys.subnet_id, TEST_KEY_LOCAL, &logger).await;

        // Call endpoint.
        info!(logger, "Calling get_btc_address endpoint...");
        let arg = GetBtcAddressArgs {
            owner: None,
            subaccount: None,
        };
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
