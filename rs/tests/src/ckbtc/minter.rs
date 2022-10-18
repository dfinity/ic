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

end::catalog[] */

use crate::{
    btc_integration,
    canister_http::lib::install_nns_canisters,
    driver::{
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, SubnetSnapshot,
        },
        universal_vm::UniversalVms,
    },
    icrc1_agent_test::install_icrc1_ledger,
    nns::vote_and_execute_proposal,
    tecdsa::tecdsa_signature_test::{
        get_public_key_with_logger, get_signature_with_logger, make_key, verify_signature,
    },
    util::{assert_create_agent, block_on, delay, runtime_from_url, UniversalCanister},
};
use bitcoincore_rpc::bitcoin::Address;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use candid::Nat;
use candid::Principal;
use candid::{Decode, Encode};
use canister_test::{ic00::EcdsaKeyId, Canister};
use ic_agent::Agent;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_btc_types::Network;
use ic_canister_client::Sender;
use ic_ckbtc_minter::{
    lifecycle::init::InitArgs as CkbtcMinterInitArgs,
    updates::{
        get_btc_address::GetBtcAddressArgs,
        get_withdrawal_account::{compute_subaccount, GetWithdrawalAccountResult},
        update_balance::{UpdateBalanceArgs, UpdateBalanceError, UpdateBalanceResult},
    },
};
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_fondue::pot::log::Logger;
use ic_icrc1::Account;
use ic_icrc1_agent::TransferArg;
use ic_icrc1_agent::{CallMode, Icrc1Agent};
use ic_icrc1_ledger::InitArgs;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::{NnsFunction, ProposalStatus};
use ic_nns_test_utils::{
    governance::submit_external_update_proposal, ids::TEST_NEURON_1_ID,
    itest_helpers::install_rust_canister,
};
use ic_registry_subnet_features::{EcdsaConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
use ic_registry_subnet_type::SubnetType;
use ic_types_test_utils::ids::subnet_test_id;
use ic_universal_canister::{management, wasm};
use ledger_canister::ArchiveOptions;
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::{debug, info};
use std::convert::TryFrom;
use std::time::{Duration, Instant};

const ADDRESS_LENGTH: usize = 44;

const TEST_KEY_LOCAL: &str = "dfx_test_key";

const UNIVERSAL_VM_NAME: &str = "btc-node";

const UPDATE_BALANCE_TIMEOUT: Duration = Duration::from_secs(300);

pub fn config(env: TestEnv) {
    // Use the btc integration setup.
    btc_integration::btc::config(env.clone());
    check_nodes_health(&env);
    install_nns_canisters(&env);
}

fn check_nodes_health(env: &TestEnv) {
    info!(
        &env.logger(),
        "Checking readiness of all nodes after the IC setup ..."
    );
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    info!(&env.logger(), "All nodes are ready, IC setup succeeded.");
}

async fn install_ledger(node: &IcNodeSnapshot, logger: &Logger) -> CanisterId {
    info!(&logger, "Installing ledger ...");
    let runtime = runtime_from_url(node.get_public_url());
    let agent: Agent = assert_create_agent(node.get_public_url().as_str()).await;
    let minting_user = PrincipalId::new_user_test_id(100);
    let user1 = PrincipalId::try_from(agent.get_principal().unwrap().as_ref()).unwrap();
    let account1 = Account {
        owner: user1,
        subaccount: None,
    };
    let minting_account = Account {
        owner: minting_user,
        subaccount: None,
    };
    let mut ledger = runtime
        .create_canister_max_cycles_with_retries()
        .await
        .expect("Unable to create canister");
    let init_args = InitArgs {
        minting_account,
        initial_balances: vec![(account1.clone(), 5_000_000_000_000_u64)],
        transfer_fee: 1_000,
        token_name: "Wrapped Bitcoin".to_string(),
        token_symbol: "ckBTC".to_string(),
        metadata: vec![],
        archive_options: ArchiveOptions {
            trigger_threshold: 1000,
            num_blocks_to_archive: 1000,
            node_max_memory_size_bytes: None,
            max_message_size_bytes: None,
            controller_id: minting_user,
            cycles_for_archive_creation: None,
            max_transactions_per_response: None,
        },
    };
    install_icrc1_ledger(&mut ledger, &init_args).await;
    ledger.canister_id()
}

async fn install_minter(
    node: &IcNodeSnapshot,
    ledger_id: CanisterId,
    logger: &Logger,
) -> CanisterId {
    info!(&logger, "Installing minter ...");
    let runtime = runtime_from_url(node.get_public_url());
    let mut canister = runtime
        .create_canister_max_cycles_with_retries()
        .await
        .expect("Unable to create canister");
    let args = CkbtcMinterInitArgs {
        btc_network: Network::Regtest,
        /// The name of the [EcdsaKeyId]. Use "dfx_test_key" for local replica and "test_key_1" for
        /// a testing key for testnet and mainnet
        ecdsa_key_name: TEST_KEY_LOCAL.parse().unwrap(),
        // ecdsa_key_name: "test_key_1".parse().unwrap(),
        retrieve_btc_min_fee: 0,
        retrieve_btc_min_amount: 0,
        ledger_id,
    };

    install_rust_canister(
        &mut canister,
        "ic-ckbtc-minter",
        &[],
        Some(Encode!(&args).unwrap()),
    )
    .await;
    canister.canister_id()
}

// By default ECDSA signature is not activated, we need to activate it explicitly.
async fn activate_ecdsa_signature(
    sys_node: IcNodeSnapshot,
    app_subnet_id: SubnetId,
    key_name: &str,
    logger: &Logger,
) {
    debug!(
        logger,
        "Activating ECDSA signature with key {:?} on subnet {:?}", key_name, app_subnet_id
    );
    let nns = runtime_from_url(sys_node.get_public_url());
    let governance = Canister::new(&nns, GOVERNANCE_CANISTER_ID);
    enable_ecdsa_signing(&governance, app_subnet_id, make_key(key_name)).await;
    let sys_agent = assert_create_agent(sys_node.get_public_url().as_str()).await;

    // Wait for key creation and verify signature (as it's done in tecdsa tests).
    let uni_can = UniversalCanister::new(&sys_agent, sys_node.effective_canister_id()).await;
    let public_key = get_public_key_with_logger(make_key(TEST_KEY_LOCAL), &uni_can, logger)
        .await
        .unwrap();
    let message_hash = [0xabu8; 32];
    let signature = get_signature_with_logger(
        &message_hash,
        ECDSA_SIGNATURE_FEE,
        make_key(TEST_KEY_LOCAL),
        &uni_can,
        logger,
    )
    .await
    .unwrap();
    verify_signature(&message_hash, &public_key, &signature);
}

async fn enable_ecdsa_signing(governance: &Canister<'_>, subnet_id: SubnetId, key_id: EcdsaKeyId) {
    // The ECDSA key sharing process requires that a key first be added to a
    // subnet, and then enabling signing with that key must happen in a separate
    // proposal.
    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_config: Some(EcdsaConfig {
            quadruples_to_create_in_advance: 10,
            key_ids: vec![key_id.clone()],
            max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            signature_request_timeout_ns: None,
        }),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload).await;

    let proposal_payload = UpdateSubnetPayload {
        subnet_id,
        ecdsa_key_signing_enable: Some(vec![key_id]),
        ..empty_subnet_update()
    };
    execute_update_subnet_proposal(governance, proposal_payload).await;
}

async fn execute_update_subnet_proposal(
    governance: &Canister<'_>,
    proposal_payload: UpdateSubnetPayload,
) {
    let proposal_id: ProposalId = submit_external_update_proposal(
        governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::UpdateConfigOfSubnet,
        proposal_payload,
        "<proposal created by ckbtc minter test>".to_string(),
        "Test summary".to_string(),
    )
    .await;
    let proposal_result = vote_and_execute_proposal(governance, proposal_id).await;
    assert_eq!(proposal_result.status(), ProposalStatus::Executed);
}

fn empty_subnet_update() -> UpdateSubnetPayload {
    UpdateSubnetPayload {
        subnet_id: subnet_test_id(0),
        max_ingress_bytes_per_message: None,
        max_ingress_messages_per_block: None,
        max_block_payload_size: None,
        unit_delay_millis: None,
        initial_notary_delay_millis: None,
        dkg_interval_length: None,
        dkg_dealings_per_block: None,
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        advert_best_effort_percentage: None,
        set_gossip_config_to_default: false,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
        max_instructions_per_message: None,
        max_instructions_per_round: None,
        max_instructions_per_install_code: None,
        features: None,
        ecdsa_config: None,
        ecdsa_key_signing_enable: None,
        ecdsa_key_signing_disable: None,
        max_number_of_canisters: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
    }
}

fn subnet_sys(env: &TestEnv) -> SubnetSnapshot {
    env.topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::System)
        .unwrap()
}

fn subnet_app(env: &TestEnv) -> SubnetSnapshot {
    env.topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
}

// Print subnets to facilitate debugging.
fn print_subnets(env: &TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();
    debug!(
        logger,
        "-- List of {} subnets --",
        topology.subnets().count()
    );
    topology
        .subnets()
        .for_each(|s| debug!(logger, "Subnet {:?}", s.subnet_id));
}

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

pub fn check_update_balance(env: TestEnv) {
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

        // Transfering some tokens to the minter canister
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
            "Block index of transfer to minter : {:#?}", transfer_result
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
        info!(&logger, "Balance of caller : {}", res_verif_balance_caller);
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
                panic!("updpate_balance timeout");
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
                .expect("Faield to update balance");
            let result = Decode!(
                update_balance_result.as_slice(),
                Result<UpdateBalanceResult, UpdateBalanceError>
            )
            .expect("Error while decoding response.")
            .expect("Error update Balance");
            info!(
                &logger,
                "New Blance added : {} at block index {}", result.amount, result.block_index
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
