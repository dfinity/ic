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
    - check_update_balance

end::catalog[] */

use crate::ckbtc::lib::{
    activate_ecdsa_signature, install_ledger, install_minter, print_subnets, subnet_app,
    subnet_sys, ADDRESS_LENGTH, TEST_KEY_LOCAL,
};
use crate::{
    driver::{
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, IcNodeContainer},
        universal_vm::UniversalVms,
    },
    util::{assert_create_agent, block_on, delay, UniversalCanister},
};
use bitcoincore_rpc::bitcoin::Address;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use candid::{Decode, Encode, Nat, Principal};
use ic_base_types::PrincipalId;
use ic_ckbtc_minter::updates::{
    get_btc_address::GetBtcAddressArgs,
    get_withdrawal_account::{compute_subaccount, GetWithdrawalAccountResult},
    update_balance::{UpdateBalanceArgs, UpdateBalanceError, UpdateBalanceResult},
};
use ic_icrc1::Account;
use ic_icrc1_agent::{CallMode, Icrc1Agent, TransferArg};
use ic_universal_canister::{management, wasm};
use slog::info;
use std::time::{Duration, Instant};

const UNIVERSAL_VM_NAME: &str = "btc-node";

const UPDATE_BALANCE_TIMEOUT: Duration = Duration::from_secs(300);

pub fn get_btc_address_test(env: TestEnv) {
    let logger = env.logger();
    let subnet_app = subnet_app(&env);
    let subnet_sys = subnet_sys(&env);
    let node = subnet_app.nodes().next().expect("No node in app subnet.");
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_subnet_id = subnet_app.subnet_id;
    print_subnets(&env);

    block_on(async {
        let ledger_id = install_ledger(&node, &logger).await;
        let minter_id = install_minter(&node, ledger_id, &logger).await;
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

pub fn get_withdrawal_account_test(env: TestEnv) {
    let logger = env.logger();
    let subnet_app = subnet_app(&env);
    let subnet_sys = subnet_sys(&env);
    let node = subnet_app.nodes().next().expect("No node in app subnet.");
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_subnet_id = subnet_app.subnet_id;
    print_subnets(&env);

    block_on(async {
        let ledger_id = install_ledger(&node, &logger).await;
        let minter_id = install_minter(&node, ledger_id, &logger).await;
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

pub fn update_balance(env: TestEnv) {
    let logger = env.logger();
    let subnet_app = subnet_app(&env);
    let subnet_sys = subnet_sys(&env);
    let node = subnet_app.nodes().next().expect("No node in app subnet.");
    let sys_node = subnet_sys.nodes().next().expect("No node in sys subnet.");
    let app_subnet_id = subnet_app.subnet_id;

    // Get access to btc replica
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let btc_rpc = Client::new(
        &format!(
            "http://[{}]:8332",
            deployed_universal_vm.get_vm().unwrap().ipv6
        ),
        Auth::UserPass(
            "btc-dev-preview".to_string(),
            "Wjh4u6SAjT4UMJKxPmoZ0AN2r9qbE-ksXQ5I2_-Hm4w=".to_string(),
        ),
    )
    .unwrap();
    // Let's create a wallet
    let _ = btc_rpc
        .create_wallet("mywallet", None, None, None, None)
        .unwrap();
    // Default btc address to mint block to
    let default_btc_address = btc_rpc.get_new_address(None, None).unwrap();
    // Creating the 10 first block to reach the min confirmations of the minter canister
    btc_rpc
        .generate_to_address(10, &default_btc_address)
        .unwrap();

    block_on(async {
        let agent = assert_create_agent(node.get_public_url().as_str()).await;
        activate_ecdsa_signature(sys_node.clone(), app_subnet_id, TEST_KEY_LOCAL, &logger).await;
        let caller = agent
            .get_principal()
            .expect("Error while getting principal.");
        let subaccount = compute_subaccount(PrincipalId::from(caller), 0);
        let ledger_id = install_ledger(&node, &logger).await;
        let minter_id = install_minter(&node, ledger_id, &logger).await;
        let minter = Principal::from(minter_id.get());
        let ledger = Principal::from(ledger_id.get());
        let icrc1_agent = Icrc1Agent {
            agent: agent.clone(),
            ledger_canister_id: ledger,
        };

        // Transferring some tokens to the minter canister.
        let to_minter_account = Account {
            owner: PrincipalId::from(minter),
            subaccount: None,
        };
        let transfer_to_minter = TransferArg {
            from_subaccount: None,
            to: to_minter_account,
            fee: None,
            created_at_time: None,
            memo: None,
            amount: Nat::from(4_000_000_000_000_u64),
        };

        let transfer_result = icrc1_agent
            .transfer(transfer_to_minter)
            .await
            .expect("Error while calling endpoint icrc1_transfer.")
            .unwrap();
        info!(
            &logger,
            "Block index of transfer to minter: {:#?}", transfer_result
        );
        assert_eq!(transfer_result, Nat::from(1_u64));

        // Let's see how much the minter canister has
        let minter_canister_account = Account {
            owner: PrincipalId::from(minter),
            subaccount: None,
        };
        let res_verif_balance = icrc1_agent
            .balance_of(minter_canister_account, CallMode::Query)
            .await
            .expect("Error while calling endpoint icrc1_balance_of.");
        info!(&logger, "Balance of minter : {}", res_verif_balance);
        assert_eq!(res_verif_balance, Nat::from(4_000_000_000_000_u64));
        // Let's see how much the caller has tokens
        let caller_account = Account {
            owner: PrincipalId::from(caller),
            subaccount: Some(subaccount),
        };

        let res_verif_balance_caller = icrc1_agent
            .balance_of(caller_account, CallMode::Query)
            .await
            .expect("Error while calling endpoint icrc1_balance_of.");
        info!(&logger, "Balance of caller: {}", res_verif_balance_caller);
        assert_eq!(res_verif_balance_caller, Nat::from(0_u64));
        // Let's get the BTC address of the first subaccount of the caller
        // The other_subaccount is the fifth subaccount of our caller Principal
        let other_subaccount = compute_subaccount(PrincipalId::from(caller), 5);
        let get_btc_address = GetBtcAddressArgs {
            subaccount: Some(other_subaccount),
        };
        let get_btc_address_encoded =
            &Encode!(&get_btc_address).expect("Error while encoding arg.");
        let res_address = agent
            .update(&minter, "get_btc_address")
            .with_arg(get_btc_address_encoded)
            .call_and_wait(delay())
            .await
            .expect("Error while calling endpoint.");
        let res_address =
            Decode!(res_address.as_slice(), String).expect("Error while decoding response.");

        // Try to update_balance with no new utxos
        let update_balance_args = UpdateBalanceArgs {
            subaccount: other_subaccount,
        };
        let update_balance_args_encoded =
            &Encode!((&update_balance_args)).expect("Error while encoding arg for update_balance.");
        let update_balance_result = agent
            .update(&minter, "update_balance")
            .with_arg(update_balance_args_encoded)
            .call_and_wait(delay())
            .await
            .expect("fail to update");
        let result = Decode!(
            update_balance_result.as_slice(),
            Result<UpdateBalanceResult, UpdateBalanceError>
        )
        .expect("Error while decoding response.");
        match result {
            Ok(_) => {
                panic!("New utxos found, expected no new utxos.");
            }
            Err(update_balance_error) => {
                info!(&logger, "Error {:#?}", update_balance_error);
            }
        }
        // Checking only proper format of address since ECDSA signature is non-deterministic.
        assert_eq!(ADDRESS_LENGTH, res_address.len());
        info!(&logger, "Address {}", res_address);
        let btc_address: Address = res_address.parse().unwrap();
        // Mint some blocks for the address we generated.
        let block = btc_rpc.generate_to_address(101, &btc_address).unwrap();
        info!(&logger, "Generated {} btc blocks.", block.len());
        assert_eq!(block.len(), 101_usize);
        // We have minted 101 blocks and each one gives 50 bitcoin to the target address,
        // so in total the balance of the address without setting `any min_confirmations`
        // should be 50 * 101 = 5050 bitcoin or 505000000000 satoshis.
        let expected_balance_in_satoshis = 5050_0000_0000_u64;
        // Call endpoint.
        let canister = UniversalCanister::new(&agent, node.effective_canister_id()).await;
        let mut res_mint = 0;
        // Let's wait until the balance has been updated on the bitcoin replica
        let start = Instant::now();
        while res_mint != expected_balance_in_satoshis {
            if start.elapsed() >= UPDATE_BALANCE_TIMEOUT {
                panic!("update_balance timeout");
            };
            res_mint = canister
                .update(wasm().call(management::bitcoin_get_balance(
                    btc_address.to_string(),
                    None,
                )))
                .await
                .map(|res| Decode!(res.as_slice(), u64))
                .unwrap()
                .unwrap();
        }

        // Check if we received the right amount of minted bitcoins
        assert_eq!(res_mint, expected_balance_in_satoshis);

        // Update the balance on ckBTC
        let account_to_query_balance_from = Account {
            owner: PrincipalId::from(caller),
            subaccount: Some(other_subaccount),
        };
        let update_balance_args = UpdateBalanceArgs {
            subaccount: other_subaccount,
        };
        let update_balance_args_encoded =
            &Encode!((&update_balance_args)).expect("Error while encoding arg for update_balance.");
        let get_btc_address_account0 = GetBtcAddressArgs {
            subaccount: Some(subaccount),
        };
        let get_btc_address_encoded_account0 =
            &Encode!(&get_btc_address_account0).expect("Error while encoding arg.");
        let res_address_account0 = agent
            .update(&minter, "get_btc_address")
            .with_arg(get_btc_address_encoded_account0)
            .call_and_wait(delay())
            .await
            .expect("Error while calling endpoint.");
        let res_address_account0 = Decode!(res_address_account0.as_slice(), String)
            .expect("Error while decoding response.");
        let btc_address_account0: Address = res_address_account0.parse().unwrap();

        for i in 2..8_u64 {
            // We mint one new block on each iteration
            btc_rpc
                .generate_to_address(1, &btc_address_account0)
                .unwrap();
            let update_balance_result = agent
                .update(&minter, "update_balance")
                .with_arg(update_balance_args_encoded)
                .call_and_wait(delay())
                .await
                .expect("Failed to update balance");
            let result = Decode!(
                update_balance_result.as_slice(),
                Result<UpdateBalanceResult, UpdateBalanceError>
            )
            .expect("Error while decoding response.")
            .expect("Error update Balance");
            info!(
                &logger,
                "New Balance added : {} at block index {}", result.amount, result.block_index
            );
            assert_eq!(result.block_index, i);
            if i == 2 {
                // If it's the first time we call update_balance we minted 102 new blocks - 6 blocks because of the min_confirmations to accept new blocks.
                assert_eq!(result.amount, 4800_0000_0000_u64);
            } else {
                // On each iteration we add one block, so we should see 50 new BTC confirmed to our address
                assert_eq!(result.amount, 50_0000_0000_u64);
            }
            // Getting the balance_of the first subaccount of the caller
            let decoded_balance_of_result = icrc1_agent
                .balance_of(account_to_query_balance_from.clone(), CallMode::Query)
                .await
                .expect("Error while calling endpoint icrc1_balance_of.");
            info!(
                &logger,
                "Balance of caller (subaccount 1): {}", decoded_balance_of_result
            );
            // We make sure that the right amount of tokens has been minted
            assert_eq!(
                decoded_balance_of_result,
                480000000000_u64 + (i - 2) * 5000000000_u64
            );
        }
    });
}
