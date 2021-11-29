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

use ic_nns_common::pb::v1::NeuronId;
use ic_nns_governance::pb::v1::neuron::DissolveState;
use ic_rosetta_api::models::PublicKey;
use ic_rosetta_api::request_types::Status;
use ic_rosetta_api::time::Seconds;
use ledger_canister::{
    protobuf::TipOfChainRequest, AccountBalanceArgs, AccountIdentifier, ArchiveOptions,
    BlockHeight, Certification, LedgerCanisterInitPayload, Operation, Subaccount, TipOfChainRes,
    Tokens, TRANSACTION_FEE,
};

use canister_test::{Canister, RemoteTestRuntime, Runtime};
use dfn_protobuf::protobuf;
use fondue::log::info;
use ic_canister_client::Sender;
use ic_fondue::{ic_manager::IcHandle, internet_computer::InternetComputer};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_governance::pb::v1::{Governance, NetworkEconomics, Neuron, NeuronState};
use ic_nns_test_utils::itest_helpers::{set_up_governance_canister, set_up_ledger_canister};
use ic_registry_subnet_type::SubnetType;
use ic_rosetta_api::convert::{
    from_model_account_identifier, neuron_account_from_public_key,
    neuron_subaccount_bytes_from_public_key, to_model_account_identifier,
};
use ic_rosetta_api::request_types::{
    AddHotKey, Disburse, PublicKeyOrPrincipal, Request, RequestResult, SetDissolveTimestamp, Stake,
    StartDissolve, StopDissolve,
};
use ic_rosetta_test_utils::{
    acc_id, assert_canister_error, assert_ic_error, do_multiple_txn, do_txn, make_user,
    prepare_txn, rosetta_api_serv::RosettaApiHandle, send_icpts, sign_txn, EdKeypair, RequestInfo,
};
use ic_types::{messages::Blob, CanisterId, PrincipalId};
use slog::Logger;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

pub fn config() -> InternetComputer {
    InternetComputer::new().add_fast_single_node_subnet(SubnetType::System)
    //.add_subnet(Subnet::new(SubnetType::System).add_nodes(2))
}

/// No changes to the IC environment
pub fn test_everything(handle: IcHandle, ctx: &fondue::pot::Context) {
    let minting_address = AccountIdentifier::new(
        PrincipalId::from_str("hn6vo-x2xxx-axxxx-minti-ngxxa-ddres-sxxxx-xxxxx-xxxxx-xxxxx-xq")
            .unwrap(),
        None,
    );

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


        // Test against prepopulated neurons
        let NeuronInfo {account_id, key_pair, neuron_subaccount_identifier, neuron, ..} = neuron_tests.get_neuron_for_test("Test disburse");
        test_disburse(&rosetta_api_serv, &ledger, account_id, key_pair.into(), neuron_subaccount_identifier, None, None, &neuron).await.unwrap();

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
        assert_eq!(neuron_info.state, i32::from(NeuronState::Dissolving));

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

        info!(&ctx.logger, "Test staking");
        let _ = test_staking(&rosetta_api_serv, acc_b, Arc::clone(&kp_b)).await;
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
    let neuron_identifier = 2;

    let staked_amount = Tokens::new(10, 0).unwrap();

    // Could use /construction/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_identifier)
            .unwrap();
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
                    neuron_identifier,
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
    assert_eq!(neuron_info.state, i32::from(NeuronState::Dissolved));

    let neuron_info = ros
        .account_balance_neuron(
            neuron_account,
            None,
            Some((dst_acc_pk.clone(), neuron_identifier)),
            false,
        )
        .await
        .unwrap()
        .unwrap()
        .metadata
        .unwrap();
    assert_eq!(neuron_info.state, i32::from(NeuronState::Dissolved));

    let neuron_info = ros
        .account_balance_neuron(
            neuron_account,
            None,
            Some((dst_acc_pk, neuron_identifier)),
            true,
        )
        .await
        .unwrap()
        .unwrap()
        .metadata
        .unwrap();
    assert_eq!(neuron_info.state, i32::from(NeuronState::Dissolved));

    // Return staked account.
    (dst_acc, dst_acc_kp)
}

async fn test_staking_failure(
    ros: &RosettaApiHandle,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
) {
    let (dst_acc, dst_acc_kp, dst_acc_pk, _pid) = make_user(1301);
    let dst_acc_kp = Arc::new(dst_acc_kp);
    let neuron_identifier = 2;

    // This is just below the minimum (NetworkEconomics.neuron_minimum_stake_e8s).
    let staked_amount = (Tokens::new(1, 0).unwrap() - Tokens::from_e8s(1)).unwrap();

    // Could use /construction/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_identifier)
            .unwrap();
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
                    neuron_identifier,
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
    neuron_identifier: u64,
) -> Result<(), ic_rosetta_api::models::Error> {
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::StartDissolve(StartDissolve {
                account,
                neuron_identifier,
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
    neuron_identifier: u64,
) -> Result<(), ic_rosetta_api::models::Error> {
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::StopDissolve(StopDissolve {
                account,
                neuron_identifier,
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
    neuron_identifier: u64,
) {
    let err = set_dissolve_timestamp(
        ros,
        acc,
        key_pair,
        Seconds::from(std::time::SystemTime::now() - Duration::from_secs(100000)),
        neuron_identifier,
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
    neuron_identifier: u64,
) {
    set_dissolve_timestamp(ros, acc, key_pair, delay_secs, neuron_identifier)
        .await
        .unwrap();
}

async fn set_dissolve_timestamp(
    ros: &RosettaApiHandle,
    acc: AccountIdentifier,
    key_pair: Arc<EdKeypair>,
    timestamp: Seconds,
    neuron_identifier: u64,
) -> Result<(), ic_rosetta_api::models::Error> {
    do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::SetDissolveTimestamp(SetDissolveTimestamp {
                account: acc,
                neuron_identifier,
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
    neuron_identifier: u64,
) -> Result<(), ic_rosetta_api::models::Error> {
    let (_, _, pk, pid) = make_user(1400);

    let r = do_multiple_txn(
        ros,
        &[RequestInfo {
            request: Request::AddHotKey(AddHotKey {
                account: acc,
                neuron_identifier,
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
                neuron_identifier,
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
    neuron_identifier: u64,
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
                neuron_identifier,
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

    let neuron_identifier = 1;
    // Could use /neuron/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_identifier)
            .unwrap();
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
                    neuron_identifier,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::SetDissolveTimestamp(SetDissolveTimestamp {
                    account: dst_acc,
                    neuron_identifier,
                    timestamp,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::StartDissolve(StartDissolve {
                    account: dst_acc,
                    neuron_identifier,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::StopDissolve(StopDissolve {
                    account: dst_acc,
                    neuron_identifier,
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
    let neuron_identifier = 1;

    // Could use /neuron/derive for this.
    let neuron_account =
        neuron_account_from_public_key(&GOVERNANCE_CANISTER_ID, &dst_acc_pk, neuron_identifier)
            .unwrap();
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
                    neuron_identifier,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::SetDissolveTimestamp(SetDissolveTimestamp {
                    account: dst_acc,
                    neuron_identifier,
                    timestamp,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::StartDissolve(StartDissolve {
                    account: dst_acc,
                    neuron_identifier,
                }),
                sender_keypair: Arc::clone(&dst_acc_kp),
            },
            RequestInfo {
                request: Request::StopDissolve(StopDissolve {
                    account: dst_acc,
                    neuron_identifier,
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
