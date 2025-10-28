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

use anyhow::Result;
use canister_test::{Canister, RemoteTestRuntime, Runtime};
use dfn_protobuf::protobuf;
use ic_canister_client::Sender;
use ic_ledger_canister_blocks_synchronizer_test_utils::sample_data::acc_id;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, REGISTRY_CANISTER_ID};
use ic_nns_governance_api::{Governance, NetworkEconomics};
use ic_nns_test_utils::itest_helpers::{set_up_governance_canister, set_up_ledger_canister};
use ic_registry_subnet_type::SubnetType;
use ic_rosetta_test_utils::make_user_ecdsa_secp256k1;
use ic_rosetta_test_utils::{
    assert_ic_error, make_user_ed25519, rosetta_api_serv::RosettaApiHandle, send_icpts,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::systest;
use ic_system_test_driver::{
    driver::{
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, get_dependency_path,
            get_dependency_path_from_env,
        },
    },
    util::block_on,
};
use ic_types::{CanisterId, messages::Blob};
use icp_ledger::{
    AccountBalanceArgs, AccountIdentifier, ArchiveOptions, BlockIndex, Certification,
    DEFAULT_TRANSFER_FEE, LedgerCanisterInitPayload, TipOfChainRes, Tokens,
    protobuf::TipOfChainRequest, tokens_from_proto,
};
use lazy_static::lazy_static;
use slog::info;
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::Arc,
};
use url::Url;

lazy_static! {
    static ref FEE: Tokens = Tokens::from_e8s(1_000);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;

    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        //.add_subnet(Subnet::new(SubnetType::System).add_nodes(2))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

/// No changes to the IC environment
pub fn test(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    // let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let minting_address = AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), None);

    let (acc_a, _kp_a, _pk_a, _pid_a) = make_user_ed25519(100);
    // let _kp_a = Arc::new(kp_a);
    let (acc_b, _kp_b, _pk_b, _pid_b) = make_user_ed25519(101);
    // let _kp_b = Arc::new(kp_b);
    let (acc_secp256k1, kp_secp256k1, _pk_secp256k1, _pid_secp256k1) =
        make_user_ecdsa_secp256k1(200);
    let _kp_secp256k1 = Arc::new(kp_secp256k1);
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
    ledger_balances.insert(acc_secp256k1, Tokens::from_e8s(200_000_000_000));

    // let neuron_tests = NeuronTestsSetup::new(2000, log.clone());

    let archive_options = ArchiveOptions {
        trigger_threshold: 8,
        num_blocks_to_archive: 4,
        node_max_memory_size_bytes: Some(1024 + 512), // about 10 blocks
        max_message_size_bytes: Some(2 * 1024 * 1024),
        controller_id: CanisterId::from_u64(876).into(),
        more_controller_ids: None,
        cycles_for_archive_creation: Some(0),
        max_transactions_per_response: None,
    };

    let ledger_canister_for_governance_payload = LedgerCanisterInitPayload::builder()
        .minting_account(minting_address)
        .initial_values(ledger_balances.clone())
        .archive_options(archive_options.clone())
        .send_whitelist(std::iter::once(GOVERNANCE_CANISTER_ID).collect())
        .transfer_fee(DEFAULT_TRANSFER_FEE)
        .build()
        .unwrap();

    let ledger_canister_payload = LedgerCanisterInitPayload::builder()
        .minting_account(minting_address)
        .initial_values(ledger_balances)
        .archive_options(archive_options)
        .send_whitelist(std::iter::once(GOVERNANCE_CANISTER_ID).collect())
        .transfer_fee(*FEE)
        .build()
        .unwrap();

    let neurons = BTreeMap::new();

    let governance_canister_init = Governance {
        economics: Some(NetworkEconomics::with_default_values()),
        wait_for_quiet_threshold_seconds: 60 * 60 * 24 * 2, // 2 days
        short_voting_period_seconds: 60 * 60 * 12,          // 12 hours
        neurons,
        ..Default::default()
    };

    block_on(async move {
        let nns_agent = ic_canister_client::Agent::new(
            nns_node.get_public_url(),
            Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
        );
        let root_key = nns_agent.root_key().await.unwrap().unwrap();
        let remote_runtime = Runtime::Remote(RemoteTestRuntime {
            agent: nns_agent,
            effective_canister_id: nns_node.effective_canister_id(),
        });

        // Reserve the registry canister to ensure that the governance
        // and ledger canisters have the right canister ID.
        let dummy_canister = remote_runtime
            .create_canister_max_cycles_with_retries()
            .await
            .unwrap();
        assert_eq!(dummy_canister.canister_id(), REGISTRY_CANISTER_ID);

        info!(log, "Installing governance canister");
        let governance_future =
            set_up_governance_canister(&remote_runtime, governance_canister_init);

        let governance = governance_future.await;
        info!(log, "Governance canister installed");
        assert_eq!(governance.canister_id(), GOVERNANCE_CANISTER_ID);

        info!(log, "Installing ledger canister for governance");
        let ledger_for_governance_future =
            set_up_ledger_canister(&remote_runtime, ledger_canister_for_governance_payload);

        info!(log, "Installing ledger canister");
        let ledger_future = set_up_ledger_canister(&remote_runtime, ledger_canister_payload);

        let ledger_for_governance = ledger_for_governance_future.await;
        info!(log, "Ledger canister installed");
        assert_eq!(ledger_for_governance.canister_id(), LEDGER_CANISTER_ID);

        let ledger = ledger_future.await;
        info!(log, "Ledger canister installed");

        let balance = get_balance(&ledger, acc1).await;
        assert_eq!(balance, Tokens::from_e8s(100_000_000_001));

        let balance = get_balance(&ledger, acc_secp256k1).await;
        assert_eq!(balance, Tokens::from_e8s(200_000_000_000));

        let (_cert, tip_idx) = get_tip(&ledger).await;

        info!(log, "Starting Rosetta");
        let rosetta_api_bin_path = rosetta_api_bin_path();
        let mut rosetta_api_serv = RosettaApiHandle::start(
            env.logger(),
            rosetta_api_bin_path.clone(),
            nns_node.get_public_url(),
            8099,
            ledger.canister_id(),
            governance.canister_id(),
            rosetta_workspace_path(),
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

        info!(log, "Test metadata suggested fee");
        let metadata = rosetta_api_serv
            .construction_metadata(None, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            metadata.suggested_fee.unwrap()[0].value,
            format!("{}", FEE.get_e8s())
        );

        // Rosetta-cli tests
        let cli_json = PathBuf::from(format!("{}/rosetta_cli.json", rosetta_workspace_path()));
        let cli_ros = PathBuf::from(format!(
            "{}/rosetta_workflows.ros",
            rosetta_workspace_path()
        ));
        let conf = rosetta_api_serv.generate_rosetta_cli_config(&cli_json, &cli_ros);
        info!(log, "Running rosetta-cli check:construction");
        rosetta_cli_construction_check(&conf);
        info!(log, "check:construction finished successfully");

        info!(log, "Running rosetta-cli check:data");
        rosetta_cli_data_check(&conf);
        info!(log, "check:data finished successfully");

        // Finish up. (calling stop is optional because it would be called on drop, but
        // this way it's more explicit what is happening)
        rosetta_api_serv.stop();

        let (_cert, tip_idx) = get_tip(&ledger).await;
        info!(
            log,
            "Starting Rosetta again to see if it properly fetches blocks in batches from all the archives"
        );
        let mut rosetta_api_serv = RosettaApiHandle::start(
            env.logger(),
            rosetta_api_bin_path.clone(),
            nns_node.get_public_url(),
            8101,
            ledger.canister_id(),
            governance.canister_id(),
            rosetta_workspace_path(),
            Some(&root_key),
        )
        .await;

        rosetta_api_serv.wait_for_tip_sync(tip_idx).await.unwrap();

        let net_status = rosetta_api_serv.network_status().await.unwrap().unwrap();
        assert_eq!(
            net_status.current_block_identifier.index as u64, tip_idx,
            "Newly started Rosetta did not fetch all the blocks from the ledger properly"
        );
        rosetta_api_serv.stop();

        // this test starts rosetta-api with wrong canister id
        // theoretically it can run together with the previous rosetta_api
        // but we stopped the previous one to be on the safe side and
        // avoid potential problems unrelated to this test
        info!(
            log,
            "Test wrong canister id (expected Rosetta sync errors in logs)"
        );
        test_wrong_canister_id(&env, nns_node.get_public_url(), None).await;
        info!(log, "Test wrong canister id finished");

        let (_cert, tip_idx) = get_tip(&ledger_for_governance).await;

        info!(log, "Starting Rosetta with default fee");
        let mut rosetta_api_serv = RosettaApiHandle::start(
            env.logger(),
            rosetta_api_bin_path,
            nns_node.get_public_url(),
            8100,
            ledger_for_governance.canister_id(),
            governance.canister_id(),
            rosetta_workspace_path(),
            Some(&root_key),
        )
        .await;

        rosetta_api_serv.wait_for_tip_sync(tip_idx).await.unwrap();
        // All tests have been moved to rosetta_split_test.
        rosetta_api_serv.stop();
    });
}

fn hex2addr(a: &str) -> AccountIdentifier {
    AccountIdentifier::from_hex(a).unwrap()
}

async fn get_balance(ledger: &Canister<'_>, acc: AccountIdentifier) -> Tokens {
    let reply: Result<Tokens, String> = ledger
        .query_("account_balance_pb", protobuf, AccountBalanceArgs::new(acc))
        .await
        .map(tokens_from_proto);
    reply.unwrap()
}

async fn get_tip(ledger: &Canister<'_>) -> (Certification, BlockIndex) {
    let reply: Result<TipOfChainRes, String> = ledger
        .query_("tip_of_chain_pb", protobuf, TipOfChainRequest {})
        .await;
    let res = reply.unwrap();
    (res.certification, res.tip_index)
}

async fn test_wrong_canister_id(env: &TestEnv, node_url: Url, root_key_blob: Option<&Blob>) {
    let (_acc1, kp, _pk, pid) = make_user_ed25519(1);

    let some_can_id = CanisterId::unchecked_from_principal(pid);
    let rosetta_api_bin_path = rosetta_api_bin_path();
    let ros = RosettaApiHandle::start(
        env.logger(),
        rosetta_api_bin_path,
        node_url,
        8101,
        some_can_id,
        some_can_id,
        rosetta_workspace_path(),
        root_key_blob,
    )
    .await;

    let acc2 = acc_id(2);

    let err = send_icpts(&ros, Arc::new(kp), acc2, Tokens::from_e8s(1000))
        .await
        .unwrap_err();
    assert_ic_error(&err, 740, 200, &format!("Canister {some_can_id} not found"));
}

fn rosetta_cli_construction_check(conf_file: &str) {
    let rosetta_cli = rosetta_cli_bin_path();
    let output = std::process::Command::new("timeout")
        .args([
            "300s",
            &rosetta_cli,
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
    let rosetta_cli = rosetta_cli_bin_path();
    let output = std::process::Command::new("timeout")
        .args([
            "300s",
            &rosetta_cli,
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

fn rosetta_workspace_path() -> String {
    get_dependency_path("rs/tests/rosetta_workspace")
        .into_os_string()
        .into_string()
        .unwrap()
}

fn rosetta_api_bin_path() -> PathBuf {
    get_dependency_path("rs/rosetta-api/icp/ic-rosetta-api")
}

fn rosetta_cli_bin_path() -> String {
    get_dependency_path_from_env("ROSETTA_CLI_PATH")
        .into_os_string()
        .into_string()
        .unwrap()
}
