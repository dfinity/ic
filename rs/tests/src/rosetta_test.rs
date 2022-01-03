/* tag::catalog[]
Title:: Integration tests for ic-rosetta-api

Goal:: Among others, demonstrate that we pass rosetta-cli verification tests

Runbook::
. Setup a ledger canister with prefunded accounts
. Run ic-rosetta-api
. Check that the ledger canister can be accessed through ic-rosetta-api
. Verify that balances reported by rosetta-api match balances in the ledger
. Run more specific tests (account_derive, make a transaction)
. Run rosetta-cli check:construction test scenarios
. Run rosetta-cli check:data test scenarios

end::catalog[] */

use assert_json_diff::{assert_json_eq, assert_json_include};
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::pb::v1::neuron::DissolveState;
use ic_rosetta_api::models::{ConstructionPayloadsResponse, NeuronState, Object, PublicKey};
use ic_rosetta_api::time::Seconds;
use ledger_canister::{
    protobuf::TipOfChainRequest, AccountBalanceArgs, AccountIdentifier, ArchiveOptions,
    BlockHeight, Certification, LedgerCanisterInitPayload, Operation, Subaccount, TipOfChainRes,
    Tokens, TRANSACTION_FEE,
};

use canister_test::{Canister, RemoteTestRuntime, Runtime};
use dfn_protobuf::protobuf;
use ed25519_dalek::Signer;
use fondue::log::info;
use ic_canister_client::Sender;
use ic_fondue::{ic_manager::IcHandle, internet_computer::InternetComputer};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_governance::governance::compute_neuron_staking_subaccount;
use ic_nns_governance::pb::v1::{Governance, NetworkEconomics, Neuron};
use ic_nns_test_utils::itest_helpers::{set_up_governance_canister, set_up_ledger_canister};
use ic_registry_subnet_type::SubnetType;
use ic_rosetta_api::convert::{
    from_hex, from_model_account_identifier, neuron_account_from_public_key,
    neuron_subaccount_bytes_from_public_key, to_hex, to_model_account_identifier,
};
use ic_rosetta_api::request_types::{
    AddHotKey, Disburse, MergeMaturity, PublicKeyOrPrincipal, Request, RequestResult,
    SetDissolveTimestamp, Spawn, Stake, StartDissolve, Status, StopDissolve,
};
use ic_rosetta_test_utils::{
    acc_id, assert_canister_error, assert_ic_error, do_multiple_txn, do_txn, make_user,
    prepare_txn, rosetta_api_serv::RosettaApiHandle, send_icpts, sign_txn, to_public_key,
    EdKeypair, RequestInfo,
};
use ic_types::{messages::Blob, CanisterId, PrincipalId};
use serde_json::{json, Value};
use slog::Logger;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

pub fn config() -> InternetComputer {
    InternetComputer::new().add_fast_single_node_subnet(SubnetType::System)
    //.add_subnet(Subnet::new(SubnetType::System).add_nodes(2))
}

/// No changes to the IC environment
pub fn test_everything(handle: IcHandle, ctx: &fondue::pot::Context) {
    let minting_address = AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), None);

    let (acc_a, kp_a, _pk_a, _pid_a) = make_user(100);
    let kp_a = Arc::new(kp_a);
    let (acc_b, kp_b, _pk_b, _pid_b) = make_user(101);
    let kp_b = Arc::new(kp_b);

    let mut ledger_balances = HashMap::new();
    let acc1 = hex2addr("35548ec29e9d85305850e87a2d2642fe7214ff4bb36334070deafc3345c3b127");
    let acc2 = hex2addr("42a3eb61d549dc9fe6429ce2361ec60a569b8befe43eb15a3fc5c88516711bc5");
    let acc3 = hex2addr("eaf407f7fa3770edb621ce920f6c83cefb63df333044d1cdcd2a300ceb85cb1c");
    let acc4 = hex2addr("ba5b33d11f93033ba45b0a0136d4f7f6310ee482cfb1cfebdb4cea55f4aeda17");
    let acc5 = hex2addr("776ab0ef12a63f5b1bd605f202b1b5cefeaf5791c0241c773fc8e76a6c4a8b40");
    let acc6 = hex2addr("88bf52d6380bf2ed7b5fd4010afd145dc351cbf386def9b9be017bbeb640a919");
    let acc7 = hex2addr("92c9c807da64528240f65ec29b58c839bf2374e9c1c38b7661da65fd8710124e");

    ledger_balances.insert(acc1, Tokens::from_e8s(100_000_000_001));
    ledger_balances.insert(acc2, Tokens::from_e8s(100_000_000_002));
    ledger_balances.insert(acc3, Tokens::from_e8s(100_000_000_003));
    ledger_balances.insert(acc4, Tokens::from_e8s(100_000_000_004));
    ledger_balances.insert(acc5, Tokens::from_e8s(100_000_000_005));
    ledger_balances.insert(acc6, Tokens::from_e8s(100_000_000_006));
    ledger_balances.insert(acc7, Tokens::from_e8s(100_000_000_007));

    ledger_balances.insert(acc_a, Tokens::from_e8s(200_000_000_000));
    ledger_balances.insert(acc_b, Tokens::new(1000, 0).unwrap());

    let one_year_from_now = 60 * 60 * 24 * 365
        + std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    let mut neuron_tests = NeuronTestsSetup::new(2000, ctx.logger.clone());
    neuron_tests.add(
        &mut ledger_balances,
        "Test disburse",
        rand::random(),
        |neuron| neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0)),
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test raw JSON disburse",
        rand::random(),
        |neuron| neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0)),
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test disburse to custom recipient",
        rand::random(),
        |neuron| neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0)),
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test disburse before neuron is dissolved (fail)",
        rand::random(),
        |neuron| {
            neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(
                one_year_from_now,
            ))
        },
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test disburse an amount",
        rand::random(),
        |neuron| neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0)),
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test disburse an amount full stake",
        rand::random(),
        |neuron| neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0)),
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test disburse more than staked amount (fail)",
        rand::random(),
        |neuron| neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0)),
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test set dissolve timestamp to a prior timestamp (fail)",
        rand::random(),
        |neuron| {
            neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(
                one_year_from_now,
            ))
        },
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test set dissolve timestamp to 5000 seconds from now",
        rand::random(),
        |neuron| neuron.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(0)),
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test start dissolving neuron",
        rand::random(),
        |neuron| {
            neuron.dissolve_state = Some(DissolveState::DissolveDelaySeconds(one_year_from_now))
        },
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test re-start dissolving a dissolved neuron",
        rand::random(),
        |neuron| {
            neuron.dissolve_state = Some(DissolveState::DissolveDelaySeconds(one_year_from_now))
        },
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test add hot key",
        rand::random(),
        |_| {},
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test start dissolving neuron before delay has been set",
        rand::random(),
        |neuron| {
            neuron.dissolve_state = None;
        },
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test spawn neuron with enough maturity",
        rand::random(),
        |neuron| {
            neuron.dissolve_state = None;
            neuron.maturity_e8s_equivalent = 500_000_000;
        },
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test spawn neuron with not enough maturity",
        rand::random(),
        |neuron| {
            neuron.dissolve_state = None;
            neuron.maturity_e8s_equivalent = 4_000;
        },
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test merge all neuron maturity",
        rand::random(),
        |neuron| {
            neuron.dissolve_state = None;
            neuron.maturity_e8s_equivalent = 420_000_000;
        },
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test merge partial neuron maturity",
        rand::random(),
        |neuron| {
            neuron.dissolve_state = None;
            neuron.maturity_e8s_equivalent = 420_000_000;
        },
    );

    neuron_tests.add(
        &mut ledger_balances,
        "Test merge neuron maturity invalid",
        rand::random(),
        |neuron| {
            neuron.dissolve_state = None;
            neuron.maturity_e8s_equivalent = 420_000_000;
        },
    );

    let archive_options = Some(ArchiveOptions {
        trigger_threshold: 8,
        num_blocks_to_archive: 4,
        node_max_memory_size_bytes: Some(1024 + 512), // about 10 blocks
        max_message_size_bytes: Some(2 * 1024 * 1024),
        controller_id: CanisterId::from_u64(876),
    });

    let ledger_canister_payload = LedgerCanisterInitPayload::new(
        minting_address,
        ledger_balances,
        archive_options,
        None,
        None,
        std::iter::once(GOVERNANCE_CANISTER_ID).collect(),
    );

    let (neurons, mut neuron_tests) = neuron_tests.neurons();

    let governance_canister_init = Governance {
        economics: Some(NetworkEconomics::with_default_values()),
        wait_for_quiet_threshold_seconds: 60 * 60 * 24 * 2, // 2 days
        short_voting_period_seconds: 60 * 60 * 12,          // 12 hours
        neurons,
        ..Default::default()
    };

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        let endpoint = handle.public_api_endpoints.first().expect("no endpoints");
        endpoint.assert_ready(ctx).await;
        let node_url = endpoint.url.clone();
        //let ic_agent = assert_create_agent(node_url.as_str()).await;
        let agent = ic_canister_client::Agent::new(
            node_url.clone(),
            Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
        );
        let root_key = agent.root_key().await.unwrap().unwrap();
        let remote_runtime = Runtime::Remote(RemoteTestRuntime { agent });

        // Reserve the registry canister to ensure that the governance
        // and ledger canisters have the right canister ID.
        let dummy_canister = remote_runtime.create_canister_max_cycles_with_retries().await.unwrap();
        assert_eq!(dummy_canister.canister_id(), REGISTRY_CANISTER_ID);

        info!(&ctx.logger, "Installing governance canister");
        let governance_future = set_up_governance_canister(&remote_runtime, governance_canister_init);

        let governance = governance_future.await;
        info!(&ctx.logger, "Governance canister installed");
        assert_eq!(governance.canister_id(), GOVERNANCE_CANISTER_ID);

        info!(&ctx.logger, "Installing ledger canister");
        let ledger_future = set_up_ledger_canister(&remote_runtime, ledger_canister_payload);

        let ledger = ledger_future.await;
        info!(&ctx.logger, "Ledger canister installed");
        assert_eq!(ledger.canister_id(), LEDGER_CANISTER_ID);

        let balance = get_balance(&ledger, acc1).await;
        assert_eq!(balance, Tokens::from_e8s(100_000_000_001));

        let (_cert, tip_idx) = get_tip(&ledger).await;

        info!(&ctx.logger, "Starting rosetta-api");
        let mut rosetta_api_serv = RosettaApiHandle::start(
            node_url.clone(),
            8099,
            ledger.canister_id(),
            governance.canister_id(),
            workspace_path(),
            Some(&root_key),
        )
        .await;

        rosetta_api_serv.wait_for_tip_sync(tip_idx).await.unwrap();

        // smoke test first

        let net_status = rosetta_api_serv.network_status().await.unwrap().unwrap();
        assert_eq!(net_status.current_block_identifier.index as u64, tip_idx);

        let b = rosetta_api_serv.wait_for_block_at(6).await.unwrap();
        assert_eq!(b.block_identifier.index, 6);

        let br = rosetta_api_serv.block_at(6).await.unwrap().unwrap();
        assert_eq!(br.block.unwrap().block_identifier.index as u64, 6);

        let bal_resp = rosetta_api_serv.balance(acc1).await.unwrap().unwrap();
        assert_eq!(
            Tokens::from_e8s(bal_resp.balances[0].value.parse().unwrap()),
            Tokens::from_e8s(100_000_000_001)
        );

        // Some more advanced tests
        info!(&ctx.logger, "Test derive endpoint");
        test_derive(&rosetta_api_serv).await;
        info!(&ctx.logger, "Test make transaction");
        test_make_transaction(&rosetta_api_serv, &ledger, acc_a, Arc::clone(&kp_a)).await;
        info!(&ctx.logger, "Test wrong key");
        test_wrong_key(&rosetta_api_serv, acc_a, Arc::clone(&kp_a)).await;
        info!(&ctx.logger, "Test no funds");
        test_no_funds(&rosetta_api_serv, Arc::clone(&kp_a)).await;
        info!(&ctx.logger, "Test configurable ingress window");
        test_ingress_window(&rosetta_api_serv, Arc::clone(&kp_a)).await;
        info!(&ctx.logger, "Test multiple transfers");
        test_multiple_transfers(&rosetta_api_serv, &ledger, acc_b, Arc::clone(&kp_b)).await;
        info!(&ctx.logger, "Test multiple transfers (fail)");
        test_multiple_transfers_fail(&rosetta_api_serv, &ledger, acc_b, Arc::clone(&kp_b)).await;


        info!(&ctx.logger, "Neuron management tests");
        // Test against prepopulated neurons
        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, neuron, ..} = neuron_tests.get_neuron_for_test("Test disburse");
        test_disburse(&rosetta_api_serv, &ledger, account_id, key_pair.into(), neuron_subaccount_identifier, None, None, &neuron).await.unwrap();
        // Test against prepopulated neurons (raw)
        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, neuron, ..} = neuron_tests.get_neuron_for_test("Test raw JSON disburse");
        test_disburse_raw(&rosetta_api_serv, &ledger, account_id, key_pair.into(), neuron_subaccount_identifier, None, None, &neuron, &ctx.logger).await.unwrap();

        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, neuron, ..} = neuron_tests.get_neuron_for_test("Test disburse to custom recipient");
        let (recipient, _, _, _) = make_user(102);
        test_disburse(&rosetta_api_serv, &ledger, account_id, key_pair.into(), neuron_subaccount_identifier, None, Some(recipient), &neuron).await.unwrap();

        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, neuron, ..} = neuron_tests.get_neuron_for_test("Test disburse before neuron is dissolved (fail)");
        test_disburse(&rosetta_api_serv, &ledger, account_id, key_pair.into(), neuron_subaccount_identifier, None, None, &neuron).await.unwrap_err();

        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, neuron, ..} = neuron_tests.get_neuron_for_test("Test disburse an amount");
        test_disburse(&rosetta_api_serv, &ledger, account_id, key_pair.into(), neuron_subaccount_identifier, Some(Tokens::new(5, 0).unwrap()), None, &neuron).await.unwrap();

        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, neuron, ..} = neuron_tests.get_neuron_for_test("Test disburse an amount full stake");
        test_disburse(&rosetta_api_serv, &ledger, account_id, key_pair.into(), neuron_subaccount_identifier, Some(Tokens::new(10, 0).unwrap()), None, &neuron).await.unwrap();

        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, neuron, ..} = neuron_tests.get_neuron_for_test("Test disburse more than staked amount (fail)");
        test_disburse(&rosetta_api_serv, &ledger, account_id, key_pair.into(), neuron_subaccount_identifier, Some(Tokens::new(11, 0).unwrap()), None, &neuron).await.unwrap_err();

        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, ..} = neuron_tests.get_neuron_for_test("Test set dissolve timestamp to a prior timestamp (fail)");
        test_set_dissolve_timestamp_in_the_past_fail(&rosetta_api_serv, account_id, key_pair.into(), neuron_subaccount_identifier).await;

        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, ..} = neuron_tests.get_neuron_for_test("Test set dissolve timestamp to 5000 seconds from now");
        let timestamp = Seconds::from(std::time::SystemTime::now() + Duration::from_secs(5000));
        let key_pair = Arc::new(key_pair);
        test_set_dissolve_timestamp(&rosetta_api_serv, account_id, key_pair.clone(), timestamp, neuron_subaccount_identifier).await;
        info!(&ctx.logger, "Test set dissolve timestamp to 5 seconds from now again");
        test_set_dissolve_timestamp(&rosetta_api_serv, account_id, key_pair.clone(), timestamp, neuron_subaccount_identifier).await;
        // Note that this is an incorrect usage, but no error is returned.
        // we would like this to fail, but to make the above case work we have to swallow these errors.
        info!(&ctx.logger, "Test set dissolve timestamp to less than it's currently set to (we would like this to fail)");
        test_set_dissolve_timestamp(&rosetta_api_serv, account_id, key_pair.clone(), timestamp, neuron_subaccount_identifier).await;

        info!(&ctx.logger, "Test set dissolve timestamp to a prior timestamp (fail)");
        test_set_dissolve_timestamp_in_the_past_fail(&rosetta_api_serv, account_id, key_pair.clone(), neuron_subaccount_identifier).await;

        let NeuronInfo {account_id, key_pair, public_key, neuron_subaccount_identifier, neuron_account, ..} = neuron_tests.get_neuron_for_test("Test start dissolving neuron");
        let key_pair = Arc::new(key_pair);
        test_start_dissolve(&rosetta_api_serv, account_id, key_pair.clone(), neuron_subaccount_identifier).await.unwrap();
        let neuron_info = rosetta_api_serv.account_balance_neuron(neuron_account, None, Some((public_key, neuron_subaccount_identifier)), false).await.unwrap().unwrap().metadata.unwrap();
        assert_eq!(neuron_info.state, NeuronState::Dissolving);

        info!(&ctx.logger, "Test start dissolving neuron again");
        test_start_dissolve(&rosetta_api_serv, account_id, key_pair.clone(), neuron_subaccount_identifier).await.unwrap();
        info!(&ctx.logger, "Test stop dissolving neuron");
        test_stop_dissolve(&rosetta_api_serv, account_id, key_pair.clone(), neuron_subaccount_identifier).await.unwrap();
        info!(&ctx.logger, "Test stop dissolving neuron again");
        test_stop_dissolve(&rosetta_api_serv, account_id, key_pair.clone(), neuron_subaccount_identifier).await.unwrap();
        info!(&ctx.logger, "Test restart dissolving neuron");
        test_start_dissolve(&rosetta_api_serv, account_id, key_pair.clone(), neuron_subaccount_identifier).await.unwrap();

        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, ..} = neuron_tests.get_neuron_for_test("Test re-start dissolving a dissolved neuron");
        let key_pair = Arc::new(key_pair);
        test_start_dissolve(&rosetta_api_serv, account_id, key_pair.clone(), neuron_subaccount_identifier).await.unwrap();
        info!(&ctx.logger, "Test stop dissolving a dissolved neuron");
        test_stop_dissolve(&rosetta_api_serv, account_id, key_pair.clone(), neuron_subaccount_identifier).await.unwrap();


        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, ..} = neuron_tests.get_neuron_for_test("Test add hot key");
        let key_pair = Arc::new(key_pair);
        test_add_hot_key(&rosetta_api_serv, account_id, key_pair.clone(), neuron_subaccount_identifier).await.unwrap();
        test_start_dissolve(&rosetta_api_serv, account_id, key_pair, neuron_subaccount_identifier).await.unwrap();

        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, ..} = neuron_tests.get_neuron_for_test("Test start dissolving neuron before delay has been set");
        // Note that this is an incorrect usage, but no error is returned.
        // Start and Stop operations never fail, even when they have no affect.
        test_start_dissolve(&rosetta_api_serv, account_id, key_pair.into(), neuron_subaccount_identifier).await.unwrap();

        let neuron_info= neuron_tests.get_neuron_for_test("Test spawn neuron with enough maturity");
        test_spawn(&rosetta_api_serv, &ledger, neuron_info).await;

        let neuron_info= neuron_tests.get_neuron_for_test("Test spawn neuron with not enough maturity");
        test_spawn_invalid(&rosetta_api_serv, neuron_info).await;

        let neuron_info= neuron_tests.get_neuron_for_test("Test merge all neuron maturity");
        test_merge_maturity_all(&rosetta_api_serv, &ledger, neuron_info).await;
        let neuron_info= neuron_tests.get_neuron_for_test("Test merge partial neuron maturity");
        test_merge_maturity_partial(&rosetta_api_serv, &ledger, neuron_info).await;
        let neuron_info= neuron_tests.get_neuron_for_test("Test merge neuron maturity invalid");
        test_merge_maturity_invalid(&rosetta_api_serv, neuron_info).await;

        info!(&ctx.logger, "Test staking");
        let _ = test_staking(&rosetta_api_serv, acc_b, Arc::clone(&kp_b)).await;
        info!(&ctx.logger, "Test staking (raw JSON)");
        let _ = test_staking_raw(&rosetta_api_serv, acc_b, Arc::clone(&kp_b)).await;
        info!(&ctx.logger, "Test staking failure");
        test_staking_failure(&rosetta_api_serv, acc_b, Arc::clone(&kp_b)).await;

        info!(&ctx.logger, "Test staking flow");
        test_staking_flow(&rosetta_api_serv, &ledger, acc_b, Arc::clone(&kp_b), Seconds(one_year_from_now)).await;
        info!(&ctx.logger, "Test staking flow two txns");
        test_staking_flow_two_txns(&rosetta_api_serv, &ledger, acc_b, Arc::clone(&kp_b), Seconds(one_year_from_now)).await;

        // Rosetta-cli tests
        let cli_json = PathBuf::from(format!("{}/rosetta_cli.json", workspace_path()));
        let cli_ros = PathBuf::from(format!("{}/rosetta_workflows.ros", workspace_path()));
        let conf = rosetta_api_serv.generate_rosetta_cli_config(&cli_json, &cli_ros);
        info!(&ctx.logger, "Running rosetta-cli check:construction");
        rosetta_cli_construction_check(&conf);
        info!(&ctx.logger, "check:construction finished successfully");

        info!(&ctx.logger, "Running rosetta-cli check:data");
        rosetta_cli_data_check(&conf);
        info!(&ctx.logger, "check:data finished successfully");

        // Finish up. (calling stop is optional because it would be called on drop, but
        // this way it's more explicit what is happening)
        rosetta_api_serv.stop();


        let (_cert, tip_idx) = get_tip(&ledger).await;
        info!(&ctx.logger, "Starting rosetta-api again to see if it properly fetches blocks in batches from all the archives");
        let mut rosetta_api_serv = RosettaApiHandle::start(
            node_url.clone(),
            8101,
            ledger.canister_id(),
            governance.canister_id(),
            workspace_path(),
            Some(&root_key),
        ).await;

        rosetta_api_serv.wait_for_tip_sync(tip_idx).await.unwrap();

        let net_status = rosetta_api_serv.network_status().await.unwrap().unwrap();
        assert_eq!(net_status.current_block_identifier.index as u64, tip_idx, "Newly started rosetta-api did not fetch all the blocks from the ledger properly");
        rosetta_api_serv.stop();

        // this test starts rosetta-api with wrong canister id
        // theoretically it can run together with the previous rosetta_api
        // but we stopped the previous one to be on the safe side and
        // avoid potential problems unrelated to this test
        info!(
            &ctx.logger,
            "Test wrong canister id (expected rosetta-api sync errors in logs)"
        );
        test_wrong_canister_id(node_url, None).await;
        info!(&ctx.logger, "Test wrong canister id finished");
    });
}

fn hex2addr(a: &str) -> AccountIdentifier {
    AccountIdentifier::from_hex(a).unwrap()
}

async fn get_balance(ledger: &Canister<'_>, acc: AccountIdentifier) -> Tokens {
    let reply: Result<Tokens, String> = ledger
        .query_("account_balance_pb", protobuf, AccountBalanceArgs::new(acc))
        .await;
    reply.unwrap()
}

async fn get_tip(ledger: &Canister<'_>) -> (Certification, BlockHeight) {
    let reply: Result<TipOfChainRes, String> = ledger
        .query_("tip_of_chain_pb", protobuf, TipOfChainRequest {})
        .await;
    let res = reply.unwrap();
    (res.certification, res.tip_index)
}

// Check that derive endpoint of rosetta-api returns correct account address
async fn test_derive(ros: &RosettaApiHandle) {
    test_derive_ledger_address(ros).await;
    test_derive_neuron_address(ros).await;
}

async fn test_derive_ledger_address(ros: &RosettaApiHandle) {
    let (acc, _kp, pk, _pid) = make_user(5);
    let derived = ros.construction_derive(pk).await.unwrap().unwrap();
    assert_eq!(
        acc.to_hex(),
        derived.account_identifier.unwrap().address,
        "Account id derived via construction/derive is different than expected"
    );
}

async fn test_derive_neuron_address(ros: &RosettaApiHandle) {
    let (_acc, _kp, pk, pid) = make_user(6);
    let derived = ros.neuron_derive(pk).await.unwrap().unwrap();

    let account_id = derived.account_identifier.unwrap();

    let subaccount_bytes = {
        const DOMAIN: &[u8] = b"neuron-stake";

        let mut hasher = ic_crypto_sha::Sha256::new();
        hasher.write(&[DOMAIN.len() as u8]);
        hasher.write(DOMAIN);
        hasher.write(pid.as_slice());
        hasher.write(&[0u8; 8]);
        hasher.finish()
    };

    assert_eq!(
        account_id,
        to_model_account_identifier(&AccountIdentifier::new(
            GOVERNANCE_CANISTER_ID.get(),
            Some(Subaccount(subaccount_bytes)),
        ))
    );
}

// Make a transaction through rosetta-api and verify that it landed on the
// blockchain
async fn test_make_transaction(
    ros: &RosettaApiHandle,
    ledger: &Canister<'_>,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
) {
    let (dst_acc, _kp, _pk, _pid) = make_user(1050);
    let balance_before = Tokens::from_e8s(
        ros.balance(dst_acc).await.unwrap().unwrap().balances[0]
            .value
            .parse()
            .unwrap(),
    );

    let amount = Tokens::from_e8s(1000);

    let tip_idx = ros
        .network_status()
        .await
        .unwrap()
        .unwrap()
        .current_block_identifier
        .index as u64;
    let expected_idx = tip_idx + 1;

    let t = Operation::Transfer {
        from: acc,
        to: dst_acc,
        amount,
        fee: TRANSACTION_FEE,
    };
    let (tid, results, _fee) = do_txn(
        ros,
        key_pair,
        t.clone(),
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .unwrap();

    if let Some(h) = results.last_block_index() {
        assert_eq!(h, expected_idx);
    }
    let block = ros.wait_for_block_at(expected_idx).await.unwrap();
    assert_eq!(block.transactions.len(), 1);

    let t = block.transactions.first().unwrap();
    assert_eq!(t.transaction_identifier, tid);

    check_balance(ros, ledger, &dst_acc, (balance_before + amount).unwrap()).await;
}

async fn check_balance(
    ros: &RosettaApiHandle,
    ledger: &Canister<'_>,
    acc: &AccountIdentifier,
    expected_balance: Tokens,
) {
    let balance = Tokens::from_e8s(
        ros.balance(*acc).await.unwrap().unwrap().balances[0]
            .value
            .parse()
            .unwrap(),
    );
    assert_eq!(expected_balance, balance);
    let balance_from_ledger = get_balance(ledger, *acc).await;
    assert_eq!(balance_from_ledger, balance);
}

// Sign a transaction with wrong key and check if it gets rejected
async fn test_wrong_key(ros: &RosettaApiHandle, acc: AccountIdentifier, key_pair: Arc<EdKeypair>) {
    let (_acc, wrong_kp, _wrong_pk, _pid) = make_user(1052);
    let t = Operation::Transfer {
        from: acc,
        to: acc_id(1051),
        amount: Tokens::from_e8s(100),
        fee: TRANSACTION_FEE,
    };

    let (payloads, _fee) = prepare_txn(ros, t, key_pair, false, None, None)
        .await
        .unwrap();

    let signed = sign_txn(ros, &[Arc::new(wrong_kp)], payloads)
        .await
        .unwrap()
        .signed_transaction()
        .unwrap();
    let err = ros.construction_submit(signed).await.unwrap().unwrap_err();
    assert_ic_error(&err, 740, 403, "does not match the public key");
}

async fn test_no_funds(ros: &RosettaApiHandle, funding_key_pair: Arc<EdKeypair>) {
    let (acc1, keypair1, _, _) = make_user(9275456);
    let keypair1 = Arc::new(keypair1);
    let acc2 = acc_id(598620493);

    // charge up user1
    let (_, bh, _) = send_icpts(
        ros,
        funding_key_pair,
        acc1,
        (Tokens::from_e8s(10_000) + TRANSACTION_FEE).unwrap(),
    )
    .await
    .unwrap();
    ros.wait_for_tip_sync(bh.unwrap()).await.unwrap();

    // Transfer some funds from user1 to user2
    let (_, bh, _) = send_icpts(ros, Arc::clone(&keypair1), acc2, Tokens::from_e8s(1000))
        .await
        .unwrap();
    ros.wait_for_tip_sync(bh.unwrap()).await.unwrap();

    // Try to transfer more. This should fail with an error from the canister.
    let err = send_icpts(ros, keypair1, acc2, Tokens::from_e8s(10_000))
        .await
        .unwrap_err();
    assert_canister_error(&err, 750, "account doesn't have enough funds");

    // and now try to make a transfer from an empty account
    let (_, empty_acc_kp, _, _) = make_user(434561);
    let err = send_icpts(ros, Arc::new(empty_acc_kp), acc2, Tokens::from_e8s(100))
        .await
        .unwrap_err();
    assert_canister_error(&err, 750, "account doesn't have enough funds");
}

async fn test_ingress_window(ros: &RosettaApiHandle, funding_key_pair: Arc<EdKeypair>) {
    let (acc1, _keypair1, _, _) = make_user(42);

    let now = ic_types::time::current_time();
    let expiry = now + Duration::from_secs(24 * 60 * 60);

    // charge up user1
    let (_, bh, _) = ic_rosetta_test_utils::send_icpts_with_window(
        ros,
        Arc::clone(&funding_key_pair),
        acc1,
        Tokens::from_e8s(10_000),
        Some(expiry.as_nanos_since_unix_epoch()),
        Some(now.as_nanos_since_unix_epoch()),
    )
    .await
    .unwrap();
    ros.wait_for_tip_sync(bh.unwrap()).await.unwrap();

    // do the same transaction again; this should be rejected
    // note that we pass the same created_at value to get the same
    // transaction
    let err = ic_rosetta_test_utils::send_icpts_with_window(
        ros,
        funding_key_pair,
        acc1,
        Tokens::from_e8s(10_000),
        None,
        Some(now.as_nanos_since_unix_epoch()),
    )
    .await
    .unwrap_err();
    assert_canister_error(&err, 750, "transaction is a duplicate");
}

async fn test_wrong_canister_id(node_url: Url, root_key_blob: Option<&Blob>) {
    let (_acc1, kp, _pk, pid) = make_user(1);

    let some_can_id = CanisterId::new(pid).unwrap();
    let ros = RosettaApiHandle::start(
        node_url,
        8100,
        some_can_id,
        some_can_id,
        workspace_path(),
        root_key_blob,
    )
    .await;

    let acc2 = acc_id(2);

    let err = send_icpts(&ros, Arc::new(kp), acc2, Tokens::from_e8s(1000))
        .await
        .unwrap_err();
    assert_ic_error(&err, 740, 404, "Requested canister does not exist");
}

/// Test doing multiple transfers in a single submit call
async fn test_multiple_transfers(
    ros: &RosettaApiHandle,
    ledger: &Canister<'_>,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
) {
    let (dst_acc1, dst_acc1_kp, _pk, _pid) = make_user(1100);
    let (dst_acc2, dst_acc2_kp, _pk, _pid) = make_user(1101);
    let (dst_acc3, _kp, _pk, _pid) = make_user(1102);

    let amount1 = Tokens::new(3, 0).unwrap();
    let amount2 = Tokens::new(2, 0).unwrap();
    let amount3 = Tokens::new(1, 0).unwrap();

    let tip_idx = ros
        .network_status()
        .await
        .unwrap()
        .unwrap()
        .current_block_identifier
        .index as u64;
    let expected_idx = tip_idx + 3;

    let (tid, results, _fee) = do_multiple_txn(
        ros,
        &[
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: acc,
                    to: dst_acc1,
                    amount: amount1,
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::clone(&key_pair),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc1,
                    to: dst_acc2,
                    amount: amount2,
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::new(dst_acc1_kp),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc2,
                    to: dst_acc3,
                    amount: amount3,
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::new(dst_acc2_kp),
            },
        ],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .unwrap();

    if let Some(h) = results.last_block_index() {
        assert_eq!(h, expected_idx);
    }
    let block = ros.wait_for_block_at(expected_idx).await.unwrap();
    assert_eq!(block.transactions.len(), 1);

    let t = block.transactions.first().unwrap();
    assert_eq!(t.transaction_identifier, tid);

    check_balance(
        ros,
        ledger,
        &dst_acc1,
        ((amount1 - amount2).unwrap() - TRANSACTION_FEE).unwrap(),
    )
    .await;
    check_balance(
        ros,
        ledger,
        &dst_acc2,
        ((amount2 - amount3).unwrap() - TRANSACTION_FEE).unwrap(),
    )
    .await;
    check_balance(ros, ledger, &dst_acc3, amount3).await;
}

/// Test part of a multiple transfer failing. This is not atomic.
async fn test_multiple_transfers_fail(
    ros: &RosettaApiHandle,
    ledger: &Canister<'_>,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
) {
    let (dst_acc1, dst_acc1_kp, _pk, _pid) = make_user(1200);
    let (dst_acc2, dst_acc2_kp, _pk, _pid) = make_user(1201);
    let (dst_acc3, _kp, _pk, _pid) = make_user(1202);

    let amount1 = Tokens::new(3, 0).unwrap();
    let amount2 = Tokens::new(2, 0).unwrap();
    let amount3 = Tokens::new(100_000, 0).unwrap();

    let tip_idx = ros
        .network_status()
        .await
        .unwrap()
        .unwrap()
        .current_block_identifier
        .index as u64;
    let expected_idx = tip_idx + 1;

    let err = do_multiple_txn(
        ros,
        &[
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: acc,
                    to: dst_acc1,
                    amount: amount1,
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::clone(&key_pair),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: acc,
                    to: dst_acc3,
                    amount: amount3,
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::new(dst_acc2_kp),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc1,
                    to: dst_acc2,
                    amount: amount2,
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::new(dst_acc1_kp),
            },
        ],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .unwrap_err();
    assert_canister_error(&err, 750, "debit account doesn't have enough funds");

    let block = ros.wait_for_block_at(expected_idx).await.unwrap();
    assert_eq!(block.transactions.len(), 1);

    check_balance(ros, ledger, &dst_acc1, amount1).await;
    check_balance(ros, ledger, &dst_acc2, Tokens::ZERO).await;
    check_balance(ros, ledger, &dst_acc3, Tokens::ZERO).await;
}

async fn test_staking(
    ros: &RosettaApiHandle,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
) -> (AccountIdentifier, Arc<EdKeypair>) {
    let (dst_acc, dst_acc_kp, dst_acc_pk, _pid) = make_user(1300);
    let dst_acc_kp = Arc::new(dst_acc_kp);
    let neuron_index = 2;

    let staked_amount = Tokens::new(10, 0).unwrap();

    // Could use /construction/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_index).unwrap();
    let neuron_account = from_model_account_identifier(&neuron_account).unwrap();

    let (_tid, results, _fee) = do_multiple_txn(
        ros,
        &[
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: acc,
                    to: dst_acc,
                    amount: (staked_amount + TRANSACTION_FEE).unwrap(),
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::clone(&key_pair),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc,
                    to: neuron_account,
                    amount: staked_amount,
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::Stake(Stake {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
        ],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .unwrap();

    let neuron_id = results.operations.last().unwrap().neuron_id;
    assert!(
        neuron_id.is_some(),
        "NeuronId should have been returned here"
    );

    // Block height is the last block observed.
    // In this case the transfer to neuron_account.
    assert!(results.last_block_index().is_some());

    let neuron_info = ros
        .account_balance_neuron(neuron_account, neuron_id, None, false)
        .await
        .unwrap()
        .unwrap()
        .metadata
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolved);

    let neuron_info = ros
        .account_balance_neuron(
            neuron_account,
            None,
            Some((dst_acc_pk.clone(), neuron_index)),
            false,
        )
        .await
        .unwrap()
        .unwrap()
        .metadata
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolved);

    let neuron_info = ros
        .account_balance_neuron(neuron_account, None, Some((dst_acc_pk, neuron_index)), true)
        .await
        .unwrap()
        .unwrap()
        .metadata
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolved);

    // Return staked account.
    (dst_acc, dst_acc_kp)
}

async fn test_staking_raw(
    ros: &RosettaApiHandle,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
) -> (AccountIdentifier, Arc<EdKeypair>) {
    let (dst_acc, dst_acc_kp, dst_acc_pk, _pid) = make_user(1300);
    let dst_acc_kp = Arc::new(dst_acc_kp);
    let neuron_index = 2;

    // Could use /construction/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_index).unwrap();
    let neuron_account = from_model_account_identifier(&neuron_account).unwrap();

    // Key pairs as Json.
    let pk1 = serde_json::to_value(to_public_key(&key_pair)).unwrap();
    let pk2 = serde_json::to_value(to_public_key(&dst_acc_kp)).unwrap();

    // Call /construction/derive.
    let req_derive = json!({
        "network_identifier": &ros.network_id(),
        "public_key": pk1,
        "metadata": {
            "account_type": "ledger"
        }
    });
    let res_derive = raw_construction(ros, "derive", req_derive).await;
    let address = res_derive
        .get("account_identifier")
        .unwrap()
        .get("address")
        .unwrap();
    assert_eq!(&acc.to_hex(), address); // 52bef...

    // acc => 52bef...
    // dest_acc => 1e31da...
    // neuron_account => 79ec2...

    // Call /construction/preprocess
    let operations = json!([
        {
            "operation_identifier": {
                "index": 0
            },
            "type": "TRANSACTION",
            "account": {
                "address": &acc
            },
            "amount": {
                "value": "-1000010000",
                "currency": {
                    "symbol": "ICP",
                    "decimals": 8
                }
            },
        },
        {
            "operation_identifier": {
                "index": 1
            },
            "type": "TRANSACTION",
            "account": {
                "address": &dst_acc
            },
            "amount": {
                "value": "1000010000",
                "currency": {
                    "symbol": "ICP",
                    "decimals": 8
                }
            },
        },
        {
            "operation_identifier": {
                "index": 2
            },
            "type": "FEE",
            "account": {
                "address": &acc
            },
            "amount": {
                "value": "-10000",
                "currency": {
                    "symbol": "ICP",
                    "decimals": 8
                }
            },
        },
        {
            "operation_identifier": {
                "index": 3
            },
            "type": "TRANSACTION",
            "account": {
                "address": &dst_acc
            },
            "amount": {
                "value": "-1000000000",
                "currency": {
                    "symbol": "ICP",
                    "decimals": 8
                }
            },
        },
        {
            "operation_identifier": {
                "index": 4
            },
            "type": "TRANSACTION",
            "account": {
                "address": &neuron_account
            },
            "amount": {
                "value": "1000000000",
                "currency": {
                    "symbol": "ICP",
                    "decimals": 8
                }
            },
        },
        {
            "operation_identifier": {
                "index": 5
            },
            "type": "FEE",
            "account": {
                "address": &dst_acc
            },
            "amount": {
                "value": "-10000",
                "currency": {
                    "symbol": "ICP",
                    "decimals": 8
                }
            },
        },
        {
            "operation_identifier": {
                "index": 6
            },
            "type": "STAKE",
            "account": {
                "address": &dst_acc
            },
            "metadata": {
                "neuron_index": &neuron_index
            }
        }
    ]);
    let req_preprocess = json!({
        "network_identifier": &ros.network_id(),
        "operations": operations,
        "metadata": {},
    });
    let res_preprocess = raw_construction(ros, "preprocess", req_preprocess).await;
    let options = res_preprocess.get("options");
    assert_json_eq!(
        json!({
            "request_types": [
                "TRANSACTION",
                "TRANSACTION",
                {"STAKE": {"neuron_index": 2}}
            ]
        }),
        options.unwrap()
    );

    // Call /construction/metadata
    let req_metadata = json!({
        "network_identifier": &ros.network_id(),
        "options": options,
        "public_keys": [pk1]
    });
    let res_metadata = raw_construction(ros, "metadata", req_metadata).await;
    assert_json_eq!(
        json!([
            {
                "currency": {"symbol": "ICP", "decimals": 8},
                "value": "10000"
            }
        ]),
        res_metadata.get("suggested_fee").unwrap()
    );
    // NB: metadata response will have to be added to payloads request.

    // Call /construction/payloads
    let req_payloads = json!({
        "network_identifier": &ros.network_id(),
        "operations": operations,
        "metadata": res_metadata,
        "public_keys": [pk1,pk2]
    });
    let res_payloads = raw_construction(ros, "payloads", req_payloads).await;
    let unsigned_transaction: &Value = res_payloads.get("unsigned_transaction").unwrap();
    let payloads = res_payloads.get("payloads").unwrap();
    let payloads = payloads.as_array().unwrap();

    // Call /construction/parse (unsigned).
    let req_parse = json!({
        "network_identifier": &ros.network_id(),
        "signed": false,
        "transaction": &unsigned_transaction
    });
    let _res_parse = raw_construction(ros, "parse", req_parse).await;

    // Call /construction/combine.
    let signatures = json!([
        {
            "signing_payload": payloads[0],
            "public_key": pk1,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[0], &key_pair)
        },{
            "signing_payload": payloads[1],
            "public_key": pk1,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[1], &key_pair)
        },{
            "signing_payload": payloads[2],
            "public_key": pk2,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[2], &dst_acc_kp)
        },{
            "signing_payload": payloads[3],
            "public_key": pk2,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[3], &dst_acc_kp)
        },{
            "signing_payload": payloads[4],
            "public_key": pk2,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[4], &dst_acc_kp)
        },{
            "signing_payload": payloads[5],
            "public_key": pk2,
            "signature_type": "ed25519",
            "hex_bytes": sign(&payloads[5], &dst_acc_kp)
        },
    ]);

    let req_combine = json!({
        "network_identifier": &ros.network_id(),
        "unsigned_transaction": &unsigned_transaction,
        "signatures": signatures
    });
    let res_combine = raw_construction(ros, "combine", req_combine).await;

    // Call /construction/parse (signed).
    let signed_transaction: &Value = res_combine.get("signed_transaction").unwrap();
    let req_parse = json!({
        "network_identifier": &ros.network_id(),
        "signed": true,
        "transaction": &signed_transaction
    });
    let _res_parse = raw_construction(ros, "parse", req_parse).await;

    // Call /construction/hash.
    let req_hash = json!({
        "network_identifier": &ros.network_id(),
        "signed_transaction": &signed_transaction
    });
    let _res_hash = raw_construction(ros, "hash", req_hash).await;

    // Call /construction/submit.
    let req_submit = json!({
        "network_identifier": &ros.network_id(),
        "signed_transaction": &signed_transaction
    });
    let res_submit = raw_construction(ros, "submit", req_submit).await;

    // Check proper state after staking.
    let operations = res_submit
        .get("metadata")
        .unwrap()
        .get("operations")
        .unwrap()
        .as_array()
        .unwrap();
    for op in operations.iter() {
        assert_eq!(
            op.get("status").unwrap(),
            "COMPLETED",
            "Operation didn't complete."
        );
    }
    assert_json_include!(
        actual: &operations[0],
        expected: json!({
            "amount": {"e8s": 1000010000},
            "fee": {"e8s": 10000},
            "from": &acc,
            "to": &dst_acc,
            "status": "COMPLETED"
        })
    );

    let last_neuron_id = operations.last().unwrap().get("neuron_id");
    assert!(
        last_neuron_id.is_some(),
        "NeuronId should have been returned here"
    );
    let neuron_id = last_neuron_id.unwrap().as_u64();

    // Block height is the last block observed.
    // In this case the transfer to neuron_account.
    let last_block_idx = operations.iter().rev().find_map(|r| r.get("block_index"));
    assert!(last_block_idx.is_some());

    let neuron_info = ros
        .account_balance_neuron(neuron_account, neuron_id, None, false)
        .await
        .unwrap()
        .unwrap()
        .metadata
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolved);

    // Return staked account.
    (dst_acc, dst_acc_kp)
}

async fn raw_construction(ros: &RosettaApiHandle, operation: &str, req: Value) -> Object {
    let req = req.to_string();
    let res = &ros
        .raw_construction_endpoint(operation, req.as_bytes())
        .await
        .unwrap();
    assert!(res.1.is_success(), "Result should be a success");
    serde_json::from_slice(&res.0).unwrap()
}

fn sign(payload: &Value, keypair: &Arc<EdKeypair>) -> Value {
    let hex_bytes: &str = payload.get("hex_bytes").unwrap().as_str().unwrap();
    let bytes = from_hex(hex_bytes).unwrap();
    let signature_bytes = keypair.sign(&bytes).to_bytes();
    let hex_bytes = to_hex(&signature_bytes);
    json!(hex_bytes)
}

async fn test_staking_failure(
    ros: &RosettaApiHandle,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
) {
    let (dst_acc, dst_acc_kp, dst_acc_pk, _pid) = make_user(1301);
    let dst_acc_kp = Arc::new(dst_acc_kp);
    let neuron_index = 2;

    // This is just below the minimum (NetworkEconomics.neuron_minimum_stake_e8s).
    let staked_amount = (Tokens::new(1, 0).unwrap() - Tokens::from_e8s(1)).unwrap();

    // Could use /construction/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_index).unwrap();
    let neuron_account = from_model_account_identifier(&neuron_account).unwrap();

    let err = do_multiple_txn(
        ros,
        &[
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: acc,
                    to: dst_acc,
                    amount: (staked_amount + TRANSACTION_FEE).unwrap(),
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::clone(&key_pair),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc,
                    to: neuron_account,
                    amount: staked_amount,
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::Stake(Stake {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
        ],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .unwrap_err();

    assert_canister_error(
        &err,
        750,
        "Could not claim neuron: InsufficientFunds: Account does not have enough funds to stake a neuron",
    );
}

async fn test_start_dissolve(
    ros: &RosettaApiHandle,
    account: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
    neuron_index: u64,
) -> Result<(), ic_rosetta_api::models::Error> {
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::StartDissolve(StartDissolve {
                account,
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::StartDissolve(_),
                ..
            }
        ));
    })
}

async fn test_stop_dissolve(
    ros: &RosettaApiHandle,
    account: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
    neuron_index: u64,
) -> Result<(), ic_rosetta_api::models::Error> {
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::StopDissolve(StopDissolve {
                account,
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::StopDissolve(_),
                ..
            }
        ));
    })
}

async fn test_set_dissolve_timestamp_in_the_past_fail(
    ros: &RosettaApiHandle,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
    neuron_index: u64,
) {
    let err = set_dissolve_timestamp(
        ros,
        acc,
        key_pair,
        Seconds::from(std::time::SystemTime::now() - Duration::from_secs(100000)),
        neuron_index,
    )
    .await;

    assert_canister_error(
        &err.unwrap_err(),
        750,
        "The dissolve delay must be set to a future time.",
    );
}

async fn test_set_dissolve_timestamp(
    ros: &RosettaApiHandle,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
    delay_secs: Seconds,
    neuron_index: u64,
) {
    set_dissolve_timestamp(ros, acc, key_pair, delay_secs, neuron_index)
        .await
        .unwrap();
}

async fn set_dissolve_timestamp(
    ros: &RosettaApiHandle,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
    timestamp: Seconds,
    neuron_index: u64,
) -> Result<(), ic_rosetta_api::models::Error> {
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::SetDissolveTimestamp(SetDissolveTimestamp {
                account: acc,
                neuron_index,
                timestamp,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::SetDissolveTimestamp(_),
                ..
            }
        ));
    })
}

async fn test_add_hot_key(
    ros: &RosettaApiHandle,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
    neuron_index: u64,
) -> Result<(), ic_rosetta_api::models::Error> {
    let (_, _, pk, pid) = make_user(1400);

    let r = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::AddHotKey(AddHotKey {
                account: acc,
                neuron_index,
                key: PublicKeyOrPrincipal::PublicKey(pk),
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(
            (ic_types::time::current_time() + Duration::from_secs(24 * 60 * 60))
                .as_nanos_since_unix_epoch(),
        ),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::AddHotKey(_),
                ..
            }
        ));
    });

    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::AddHotKey(AddHotKey {
                account: acc,
                neuron_index,
                key: PublicKeyOrPrincipal::Principal(pid),
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        None,
        Some(
            (ic_types::time::current_time() + Duration::from_secs(24 * 60 * 60))
                .as_nanos_since_unix_epoch(),
        ),
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::AddHotKey(_),
                ..
            }
        ));
    })
    .unwrap_or_else(|e| panic!("{:?}", e));
    r
}

#[allow(clippy::too_many_arguments)]
async fn test_disburse(
    ros: &RosettaApiHandle,
    ledger: &Canister<'_>,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
    neuron_index: u64,
    amount: Option<Tokens>,
    recipient: Option<AccountIdentifier>,
    neuron: &Neuron,
) -> Result<(), ic_rosetta_api::models::Error> {
    let pre_disburse = get_balance(ledger, acc).await;
    let (_, tip_idx) = get_tip(ledger).await;

    let res = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::Disburse(Disburse {
                account: acc,
                amount,
                recipient,
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::Disburse(_),
                status: Status::Completed,
                ..
            }
        ));
        results
    })?;

    let amount = amount.unwrap_or_else(|| Tokens::from_e8s(neuron.cached_neuron_stake_e8s));

    let expected_idx = tip_idx + 1;

    if let Some(h) = res.last_block_index() {
        assert_eq!(h, expected_idx);
    }
    let _ = ros.wait_for_block_at(expected_idx).await.unwrap();

    check_balance(
        ros,
        ledger,
        &recipient.unwrap_or(acc),
        ((pre_disburse + amount).unwrap() - TRANSACTION_FEE).unwrap(),
    )
    .await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn test_disburse_raw(
    ros: &RosettaApiHandle,
    ledger: &Canister<'_>,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
    neuron_index: u64,
    amount: Option<Tokens>,
    recipient: Option<AccountIdentifier>,
    neuron: &Neuron,
    logger: &Logger,
) -> Result<(), ic_rosetta_api::models::Error> {
    let pre_disburse = get_balance(ledger, acc).await;
    let (_, tip_idx) = get_tip(ledger).await;
    let req = json!({
        "network_identifier": &ros.network_id(),
        "operations": [
            {
                "operation_identifier": {
                    "index": 0
                },
                "type": "DISBURSE",
                "account": {
                    "address": &acc
                },
                "metadata": {
                    "neuron_index": &neuron_index
                }
            }
        ]
    });
    let req = req.to_string();

    let metadata: Object = serde_json::from_slice(
        &ros.raw_construction_endpoint("metadata", req.as_bytes())
            .await
            .unwrap()
            .0,
    )
    .unwrap();

    info!(logger, "{}", &req);

    let mut req: Object = serde_json::from_str(&req).unwrap();
    req.insert("metadata".to_string(), metadata.into());
    req.insert(
        "public_keys".to_string(),
        serde_json::to_value(vec![to_public_key(&key_pair)]).unwrap(),
    );

    let payloads: ConstructionPayloadsResponse = serde_json::from_slice(
        &ros.raw_construction_endpoint("payloads", &serde_json::to_vec_pretty(&req).unwrap())
            .await
            .unwrap()
            .0,
    )
    .unwrap();

    let signed = sign_txn(ros, &[key_pair.clone()], payloads).await.unwrap();

    let hash_res = ros
        .construction_hash(signed.signed_transaction.clone())
        .await
        .unwrap()?;

    let submit_res = ros
        .construction_submit(signed.signed_transaction().unwrap())
        .await
        .unwrap()?;

    assert_eq!(
        hash_res.transaction_identifier,
        submit_res.transaction_identifier
    );

    let amount = amount.unwrap_or_else(|| Tokens::from_e8s(neuron.cached_neuron_stake_e8s));
    let expected_idx = tip_idx + 1;
    let _ = ros.wait_for_block_at(expected_idx).await.unwrap();

    check_balance(
        ros,
        ledger,
        &recipient.unwrap_or(acc),
        ((pre_disburse + amount).unwrap() - TRANSACTION_FEE).unwrap(),
    )
    .await;
    Ok(())
}

async fn test_staking_flow(
    ros: &RosettaApiHandle,
    ledger: &Canister<'_>,
    test_account: AccountIdentifier,
    test_key_pair: Arc<EdKeypair>,
    timestamp: Seconds,
) {
    let (_, tip_idx) = get_tip(ledger).await;
    let balance_before = get_balance(ledger, test_account).await;
    let (dst_acc, dst_acc_kp, dst_acc_pk, _pid) = make_user(1400);
    let dst_acc_kp = Arc::new(dst_acc_kp);

    let staked_amount = Tokens::new(1, 0).unwrap();

    let neuron_index = 1;
    // Could use /neuron/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_index).unwrap();
    let neuron_account = from_model_account_identifier(&neuron_account).unwrap();

    let (_tid, res, _fee) = do_multiple_txn(
        ros,
        &[
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: test_account,
                    to: dst_acc,
                    amount: (staked_amount + TRANSACTION_FEE).unwrap(),
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::clone(&test_key_pair),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc,
                    to: neuron_account,
                    amount: staked_amount,
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::Stake(Stake {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::SetDissolveTimestamp(SetDissolveTimestamp {
                    account: dst_acc,
                    neuron_index,
                    timestamp,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::StartDissolve(StartDissolve {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::StopDissolve(StopDissolve {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
        ],
        false,
        None,
        None,
    )
    .await
    .unwrap();

    let expected_idx = tip_idx + 2;

    if let Some(h) = res.last_block_index() {
        assert_eq!(h, expected_idx);
    }
    let _ = ros.wait_for_block_at(expected_idx).await.unwrap();

    check_balance(
        ros,
        ledger,
        &test_account,
        (((balance_before - staked_amount).unwrap() - TRANSACTION_FEE).unwrap() - TRANSACTION_FEE)
            .unwrap(),
    )
    .await;
}

async fn test_staking_flow_two_txns(
    ros: &RosettaApiHandle,
    ledger: &Canister<'_>,
    test_account: AccountIdentifier,
    test_key_pair: Arc<EdKeypair>,
    timestamp: Seconds,
) {
    let (_, tip_idx) = get_tip(ledger).await;
    let balance_before = get_balance(ledger, test_account).await;

    let (dst_acc, dst_acc_kp, dst_acc_pk, _pid) = make_user(1401);
    let dst_acc_kp = Arc::new(dst_acc_kp);

    let staked_amount = Tokens::new(1, 0).unwrap();
    let neuron_index = 1;

    // Could use /neuron/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_index).unwrap();
    let neuron_account = from_model_account_identifier(&neuron_account).unwrap();

    let (_tid, _bh, _fee) = do_multiple_txn(
        ros,
        &[
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: test_account,
                    to: dst_acc,
                    amount: (staked_amount + TRANSACTION_FEE).unwrap(),
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::clone(&test_key_pair),
            },
            RequestInfo {
                request: Request::Transfer(Operation::Transfer {
                    from: dst_acc,
                    to: neuron_account,
                    amount: staked_amount,
                    fee: TRANSACTION_FEE,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
        ],
        false,
        None,
        None,
    )
    .await
    .unwrap();

    let (_tid, res, _fee) = do_multiple_txn(
        ros,
        &[
            RequestInfo {
                request: Request::Stake(Stake {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::SetDissolveTimestamp(SetDissolveTimestamp {
                    account: dst_acc,
                    neuron_index,
                    timestamp,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::StartDissolve(StartDissolve {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::StopDissolve(StopDissolve {
                    account: dst_acc,
                    neuron_index,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
        ],
        false,
        None,
        None,
    )
    .await
    .unwrap();

    let expected_idx = tip_idx + 2;

    if let Some(h) = res.last_block_index() {
        assert_eq!(h, expected_idx);
    }
    let _ = ros.wait_for_block_at(expected_idx).await.unwrap();

    check_balance(
        ros,
        ledger,
        &test_account,
        (((balance_before - staked_amount).unwrap() - TRANSACTION_FEE).unwrap() - TRANSACTION_FEE)
            .unwrap(),
    )
    .await;
}

async fn test_spawn(ros: &RosettaApiHandle, ledger: &Canister<'_>, neuron_info: NeuronInfo) {
    let (_, tip_idx) = get_tip(ledger).await;

    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.into();

    let neuron_acc = neuron_info.neuron_account;
    let balance_main_before = get_balance(ledger, neuron_acc).await;
    assert_ne!(
        balance_main_before.get_e8s(),
        0,
        "Neuron balance shouldn't be 0."
    );

    // the nonce used to generate spawned neuron.
    let spawned_neuron_index: u64 = 4321;
    let res = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::Spawn(Spawn {
                account: acc,
                spawned_neuron_index,
                controller: Option::None, // use default (same) controller.
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::Spawn(_),
                status: Status::Completed,
                ..
            }
        ));
        results
    });

    // Check spawn results.
    // We expect one transaction to happen.
    let expected_idx = tip_idx + 1;
    if let Some(h) = res.unwrap().last_block_index() {
        assert_eq!(h, expected_idx);
    }
    // Wait for Rosetta sync.
    ros.wait_for_tip_sync(expected_idx).await.unwrap();
    let balance_main_after = get_balance(ledger, neuron_acc).await;
    assert_eq!(
        balance_main_before.get_e8s(),
        balance_main_after.get_e8s(),
        "Neuron balance shouldn't change during spawn."
    );

    // Verify that maturity got transferred to the spawned neuron.
    let subaccount =
        compute_neuron_staking_subaccount(neuron_info.principal_id, spawned_neuron_index);
    let spawned_neuron = AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(subaccount));
    let balance_sub = get_balance(ledger, spawned_neuron).await;
    assert_eq!(
        500_000_000,
        balance_sub.get_e8s(),
        "Expecting all maturity to be transferred to the spawned neuron."
    );

    // We should get the same results with Rosetta call (step not required though).
    check_balance(ros, ledger, &spawned_neuron, Tokens::from_e8s(500_000_000)).await;
}

async fn test_spawn_invalid(ros: &RosettaApiHandle, neuron_info: NeuronInfo) {
    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.into();

    // the nonce used to generate spawned neuron.
    let spawned_neuron_index: u64 = 5678;
    let res = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::Spawn(Spawn {
                account: acc,
                spawned_neuron_index,
                controller: Option::None, // use default (same) controller.
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::Spawn(_),
                status: Status::Completed,
                ..
            }
        ));
        results
    });

    assert!(
        res.is_err(),
        "Error expected while trying to spawn a neuron with no enough maturity"
    );

    let err = res.unwrap_err();
    assert_eq!(err.code, 770);
    assert_eq!(err.message, "Operation failed".to_string());
}

async fn test_merge_maturity_all(
    ros: &RosettaApiHandle,
    ledger: &Canister<'_>,
    neuron_info: NeuronInfo,
) {
    test_merge_maturity(ros, ledger, neuron_info, None).await;
}

async fn test_merge_maturity_partial(
    ros: &RosettaApiHandle,
    ledger: &Canister<'_>,
    neuron_info: NeuronInfo,
) {
    test_merge_maturity(ros, ledger, neuron_info, Some(14)).await;
}

async fn test_merge_maturity(
    ros: &RosettaApiHandle,
    ledger: &Canister<'_>,
    neuron_info: NeuronInfo,
    percent: Option<u32>,
) {
    let (_, tip_idx) = get_tip(ledger).await;

    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.into();

    let neuron_acc = neuron_info.neuron_account;
    let balance_before = get_balance(ledger, neuron_acc).await;
    assert_ne!(
        balance_before.get_e8s(),
        0,
        "Neuron balance shouldn't be 0."
    );

    let res = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::MergeMaturity(MergeMaturity {
                account: acc,
                percentage_to_merge: percent.unwrap_or(100),
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await
    .map(|(tx_id, results, _)| {
        assert!(!tx_id.is_transfer());
        assert!(matches!(
            results.operations.first().unwrap(),
            RequestResult {
                _type: Request::MergeMaturity(_),
                status: Status::Completed,
                ..
            }
        ));
        results
    })
    .expect("failed to merge neuron maturity");

    // Check merge maturity results.
    // We expect one transaction to happen.
    let expected_idx = tip_idx + 1;
    if let Some(h) = res.last_block_index() {
        assert_eq!(h, expected_idx);
    }
    // Wait for Rosetta sync.
    ros.wait_for_tip_sync(expected_idx).await.unwrap();
    let balance_after = get_balance(ledger, neuron_acc).await;
    let maturity = 420_000_000;
    let transferred_maturity = (maturity * percent.unwrap_or(100) as u64) / 100;

    assert_eq!(
        balance_before.get_e8s() + transferred_maturity,
        balance_after.get_e8s(),
        "Neuron balance should have increased after merge maturity operation."
    );

    // We should get the same results with Rosetta call (step not required though).
    check_balance(
        ros,
        ledger,
        &neuron_acc,
        Tokens::from_e8s(balance_before.get_e8s() + transferred_maturity),
    )
    .await;
}

async fn test_merge_maturity_invalid(ros: &RosettaApiHandle, neuron_info: NeuronInfo) {
    let acc = neuron_info.account_id;
    let neuron_index = neuron_info.neuron_subaccount_identifier;
    let key_pair: Arc<EdKeypair> = neuron_info.key_pair.into();

    let res = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::MergeMaturity(MergeMaturity {
                account: acc,
                percentage_to_merge: 104,
                neuron_index,
            }),
            sender_keypair: Arc::clone(&key_pair),
        }],
        false,
        Some(one_day_from_now_nanos()),
        None,
    )
    .await;

    assert!(
        res.is_err(),
        "Error expected while trying to merge neuron maturity with an invalid percentage"
    );
}

fn rosetta_cli_construction_check(conf_file: &str) {
    let output = std::process::Command::new("timeout")
        .args(&[
            "300s",
            "rosetta-cli",
            "check:construction",
            "--configuration-file",
            conf_file,
        ])
        //.stdout(std::process::Stdio::inherit())
        //.stderr(std::process::Stdio::inherit())
        .output()
        .expect("failed to execute rosetta-cli");

    assert!(
        output.status.success(),
        "rosetta-cli construction check did not finish successfully: {},/\
\n\n--------------------------\nstdout: {}, \
\n\n--------------------------\nstderr: {}",
        output.status,
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap()
    );
}

fn rosetta_cli_data_check(conf_file: &str) {
    let output = std::process::Command::new("timeout")
        .args(&[
            "300s",
            "rosetta-cli",
            "check:data",
            "--configuration-file",
            conf_file,
        ])
        //.stdout(std::process::Stdio::inherit())
        //.stderr(std::process::Stdio::inherit())
        .output()
        .expect("failed to execute rosetta-cli");

    assert!(
        output.status.success(),
        "rosetta-cli data check did not finish successfully: {},/\
\n\n--------------------------\nstdout: {}, \
\n\n--------------------------\nstderr: {}",
        output.status,
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap()
    );
}

fn workspace_path() -> String {
    match std::env::var("CI_PROJECT_DIR") {
        Ok(dir) => format!("{}/rs/tests/rosetta_workspace", dir),
        Err(_) => "rosetta_workspace".to_string(),
    }
}

fn one_day_from_now_nanos() -> u64 {
    (ic_types::time::current_time() + Duration::from_secs(24 * 60 * 60)).as_nanos_since_unix_epoch()
}

#[allow(dead_code)]
#[derive(Debug)]
struct NeuronInfo {
    account_id: AccountIdentifier,
    key_pair: EdKeypair,
    public_key: PublicKey,
    principal_id: PrincipalId,
    neuron_subaccount_identifier: u64,
    neuron: Neuron,
    neuron_account: ledger_canister::AccountIdentifier,
}

struct NeuronTestsSetup {
    info: HashMap<String, NeuronInfo>,
    seed: u64,
    logger: Logger,
}

struct NeuronTests {
    info: HashMap<String, NeuronInfo>,
    logger: Logger,
}

impl Drop for NeuronTests {
    fn drop(&mut self) {
        if !self.info.is_empty() {
            let keys: Vec<&String> = self.info.keys().collect();
            panic!("Some NeuronTests where never run: {:#?}\n You must consume every test with `NeuronTests::run_test`", keys);
        }
    }
}

impl NeuronTests {
    fn get_neuron_for_test(&mut self, test_name: &str) -> NeuronInfo {
        info!(self.logger, "{}", test_name);
        self.info.remove(test_name).unwrap_or_else(|| {
            panic!(
                "No test `{}` was setup!\n Use `NeuronTestsSetup::add` to setup neuron tests.",
                test_name
            )
        })
    }
}

impl NeuronTestsSetup {
    fn new(seed: u64, logger: Logger) -> NeuronTestsSetup {
        NeuronTestsSetup {
            info: HashMap::default(),
            seed: seed * 100_000,
            logger,
        }
    }

    /// This method is used to setup a mature neuron.
    /// The default `Neuron` can be modified in the setup closure.
    ///
    /// This would be much nicer if we took a test closure to run against the
    /// neuron, upon calling `NeuronTests.test()`.
    /// That is not ergonomic, until async_closures are on stable.
    fn add(
        &mut self,
        ledger_balances: &mut HashMap<AccountIdentifier, Tokens>,
        test_name: &str,
        neuron_subaccount_identifier: u64,
        setup: impl FnOnce(&mut Neuron),
    ) {
        let (account_id, key_pair, public_key, principal_id) = make_user(self.seed);

        let created_timestamp_seconds = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
            - Duration::from_secs(60 * 60 * 24 * 365))
        .as_secs();

        let mut neuron = Neuron {
            id: Some(NeuronId { id: self.seed }),
            account: neuron_subaccount_bytes_from_public_key(
                &public_key,
                neuron_subaccount_identifier,
            )
            .unwrap()
            .to_vec(),
            controller: Some(principal_id),
            created_timestamp_seconds,
            aging_since_timestamp_seconds: created_timestamp_seconds + 10,
            dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(0)),
            cached_neuron_stake_e8s: Tokens::new(10, 0).unwrap().get_e8s(),
            kyc_verified: true,
            ..Default::default()
        };
        setup(&mut neuron);

        let neuron_account = neuron_account_from_public_key(
            &GOVERNANCE_CANISTER_ID,
            &public_key,
            neuron_subaccount_identifier,
        )
        .unwrap();
        let neuron_account = from_model_account_identifier(&neuron_account).unwrap();
        ledger_balances.insert(
            neuron_account,
            Tokens::from_e8s(neuron.cached_neuron_stake_e8s),
        );

        assert!(
            self.info
                .insert(
                    test_name.into(),
                    NeuronInfo {
                        account_id,
                        key_pair,
                        public_key,
                        principal_id,
                        neuron_subaccount_identifier,
                        neuron,
                        neuron_account,
                    },
                )
                .is_none(),
            "You added the same test twice"
        );
        self.seed += 1;
    }

    /// Returns hashmap for prepopulating governance, and info about each
    /// neuron. The vec is reversed relative to `add` calls, so you should
    /// use `Vec.pop()`.
    fn neurons(self) -> (HashMap<u64, Neuron>, NeuronTests) {
        let NeuronTestsSetup { info, logger, .. } = self;
        let neurons = info
            .values()
            .map(|NeuronInfo { neuron, .. }| (neuron.id.clone().unwrap().id, neuron.clone()))
            .collect();
        (neurons, NeuronTests { info, logger })
    }
}
