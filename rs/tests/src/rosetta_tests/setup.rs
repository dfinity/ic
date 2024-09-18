use crate::rosetta_tests::{lib::hex2addr, rosetta_client::RosettaApiClient};
use candid::Encode;
use canister_test::{Canister, CanisterId, Runtime};
use ic_ledger_core::Tokens;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_governance_api::pb::v1::{Governance, NetworkEconomics, Neuron};
use ic_nns_test_utils::itest_helpers::install_rust_canister;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        ic::InternetComputer,
        resource::AllocatedVm,
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            IcNodeSnapshot, SshSession, SubnetSnapshot,
        },
        universal_vm::{insert_file_to_config, UniversalVm, UniversalVms},
    },
    util::{block_on, runtime_from_url},
};
use icp_ledger::{AccountIdentifier, ArchiveOptions, LedgerCanisterInitPayload};
use prost::Message;
use slog::{debug, error, info, Logger};
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::Read,
    path::Path,
    time::Duration,
};
use url::Url;

/// Transfer fee on the ledger.
pub const TRANSFER_FEE: u64 = 10_000;

/// Set to true to activate journal logs from the VM.
const WITH_JOURNAL_LOGS: bool = false;

pub const ROSETTA_TESTS_OVERALL_TIMEOUT: Duration = Duration::from_secs(18 * 60);
pub const ROSETTA_TESTS_PER_TEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Setup a test environment and return a client for the Rosetta API.
pub fn setup(
    env: &TestEnv,
    port: u32,
    vm_name: &str,
    ledger_balances: Option<HashMap<AccountIdentifier, Tokens>>,
    neurons: Option<BTreeMap<u64, Neuron>>,
) -> RosettaApiClient {
    create_ic(env);
    let subnet_sys = subnet_sys(env);
    let node = subnet_sys.nodes().next().expect("No node in sys subnet.");

    create_dummy_registry_canister(env, &node);
    let governance_id = create_governance_canister(env, &node, neurons);
    let ledger_id = create_ledger_canister(env, &node, &governance_id, ledger_balances);

    // Install the Rosetta API node from a Docker image.
    let vm = install_rosetta(
        env,
        port,
        vm_name,
        ledger_id,
        governance_id,
        node.get_public_url(),
    );
    create_rosetta_client(env, vm, port, ledger_id, governance_id)
}

/// Create an Internet Computer for Rosetta tests.
fn create_ic(env: &TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .setup_and_start(env)
        .expect("Failed to setup IC under test");
    check_nodes_health(env);
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

pub(crate) fn subnet_sys(env: &TestEnv) -> SubnetSnapshot {
    env.topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::System)
        .unwrap()
}

fn create_dummy_registry_canister(env: &TestEnv, node: &IcNodeSnapshot) {
    let logger = env.logger();
    block_on(async move {
        // Reserve the registry canister to ensure that the governance
        // and ledger canisters have the right canister ID.
        // FIXME won't be required anymore after FI-542.
        info!(&logger, "Installing (dummy) registry canister ...");
        let runtime = runtime_from_url(node.get_public_url(), node.effective_canister_id());
        let canister = create_canister(&runtime).await;
        assert_eq!(canister.canister_id(), REGISTRY_CANISTER_ID);
    })
}

fn create_governance_canister(
    env: &TestEnv,
    node: &IcNodeSnapshot,
    neurons: Option<BTreeMap<u64, Neuron>>,
) -> CanisterId {
    let logger = env.logger();
    block_on(async {
        info!(&logger, "Installing governance canister ...");
        let runtime = runtime_from_url(node.get_public_url(), node.effective_canister_id());
        let mut canister = create_canister(&runtime).await;

        let neurons: BTreeMap<u64, Neuron> = neurons.unwrap_or_default();
        // TODO Define common predefined test neurons here (if any?).

        let governance_canister_init = Governance {
            economics: Some(NetworkEconomics::with_default_values()),
            wait_for_quiet_threshold_seconds: 60 * 60 * 24 * 2, // 2 days
            short_voting_period_seconds: 60 * 60 * 12,          // 12 hours
            neurons,
            ..Default::default()
        };

        let mut serialized = Vec::new();
        governance_canister_init
            .encode(&mut serialized)
            .expect("Couldn't serialize init payload.");

        info!(
            &logger,
            "Installing governance canister code on canister {}",
            canister.canister_id().get()
        );
        install_rust_canister(
            &mut canister,
            "governance-canister",
            &["test"],
            Some(serialized),
        )
        .await;

        info!(
            &logger,
            "Created governance canister: {}",
            canister.canister_id()
        );
        canister.canister_id()
    })
}

fn create_ledger_canister(
    env: &TestEnv,
    node: &IcNodeSnapshot,
    governance_id: &CanisterId,
    ledger_balances: Option<HashMap<AccountIdentifier, Tokens>>,
) -> CanisterId {
    let logger = env.logger();
    block_on(async move {
        info!(&logger, "Installing ledger canister ...");
        let runtime = runtime_from_url(node.get_public_url(), node.effective_canister_id());
        let mut canister = create_canister(&runtime).await;

        // Initialization args.
        let mut ledger_balances = ledger_balances.unwrap_or_default();
        // Add ledger balances common to all tests.
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

        let minting_account = AccountIdentifier::new(governance_id.get(), None);
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
        let ledger_init_args = LedgerCanisterInitPayload::builder()
            .minting_account(minting_account)
            .initial_values(ledger_balances)
            .archive_options(archive_options)
            .send_whitelist(std::iter::once(*governance_id).collect())
            .transfer_fee(Tokens::from_e8s(TRANSFER_FEE))
            .token_symbol_and_name("ICP", "Rosetta Test Token")
            .build()
            .unwrap();

        info!(
            &logger,
            "Installing ledger canister code on canister {}",
            canister.canister_id().get()
        );
        let encoded = Encode!(&ledger_init_args).unwrap();
        install_rust_canister(
            &mut canister,
            "ledger-canister",
            &["notify-method"],
            Some(encoded),
        )
        .await;

        canister.canister_id()
    })
}

/// Create an empty canister.
async fn create_canister(runtime: &Runtime) -> Canister<'_> {
    runtime
        .create_canister_max_cycles_with_retries()
        .await
        .expect("Unable to create canister")
}

fn install_rosetta(
    env: &TestEnv,
    port: u32,
    vm_name: &str,
    ledger_id: CanisterId,
    governance_id: CanisterId,
    ic_url: Url,
) -> AllocatedVm {
    let logger = env.logger();
    info!(
        &logger,
        "Setting up configuration for Rosetta test on port {}", port
    );

    // Activate script for code to release.
    let image_file = "/config/rosetta_image.tar";

    // NB: network host required for ipv6.
    let activate_script = format!(
        "#!/bin/sh
echo \"Docker images (before loading Rosetta image):\"
docker images
echo \"Loading Rosetta image...\"
docker load -i {image_file}
echo \"Docker images (after loading Rosetta image):\"
docker images
docker run -d -u $(id -u) \
    -p {port}:{port} \
    --network host \
    --rm -v /home/admin/rosetta/{port}/data:/data \
    --rm -v /home/admin/rosetta/{port}/logs:/home/rosetta/log \
    --name rosetta-{port} \
    bazel/rs/rosetta-api:rosetta_image \
    --blockchain \"{}\" \
    --ic-url \"{}\" \
    --canister-id {} \
    --governance-canister-id {} \
    --address ::0 \
    --port {port}
echo \"Rosetta container started \"
",
        "Internet Computer",
        ic_url,
        ledger_id.get(),
        governance_id.get(),
    );

    let activate_script = activate_script.as_str();
    debug!(
        &logger,
        "Will start Rosetta with script: {}", activate_script
    );

    let config_dir = env
        .single_activate_script_config_dir(vm_name, activate_script)
        .unwrap();

    // Add Rosetta image to config dir.
    let path = get_dependency_path("rs/rosetta-api")
        .into_os_string()
        .into_string()
        .unwrap();
    let path = format!("{path}/rosetta_image.tar");
    let rosetta_image_path = Path::new(path.as_str());
    if !rosetta_image_path.exists() {
        error!(&logger, "Rosetta image not found: {:?}", rosetta_image_path);
    } else {
        info!(&logger, "Rosetta image found! ({:?})", rosetta_image_path);
    }
    assert!(rosetta_image_path.exists(), "Rosetta image not found");

    let _ = insert_file_to_config(
        config_dir.clone(),
        "rosetta_image.tar",
        &get_file_content(&logger, rosetta_image_path),
    );

    UniversalVm::new(String::from(vm_name))
        .with_config_dir(config_dir)
        .start(env)
        .expect("Failed to setup universal VM for Rosetta");

    let deployed_universal_vm = env.get_deployed_universal_vm(vm_name).unwrap();
    let vm = deployed_universal_vm.get_vm().unwrap();
    // let _vm_ipv6 = vm.ipv6;
    let session = deployed_universal_vm
        .block_on_ssh_session()
        .expect("Failed to establish ssh session.");
    let out = deployed_universal_vm
        .block_on_bash_script_from_session(&session, "uname -a")
        .unwrap();
    debug!(&logger, "[Test output] VM running on: {}", out);
    let out = deployed_universal_vm
        .block_on_bash_script_from_session(&session, "pwd")
        .unwrap();
    debug!(&logger, "[Test output] Current working directory: {}", out);
    assert_eq!("/home/admin\n", out);

    // Retrieve Rosetta logs.
    if WITH_JOURNAL_LOGS {
        debug!(&logger, "[journal] journal logs:");
        let script = "journalctl -xu docker.service";
        //.block_on_bash_script_from_session(&session, "journalctl -xu docker.service")
        let out = deployed_universal_vm
            .block_on_bash_script_from_session(&session, script)
            .unwrap();
        out.lines().for_each(|l| debug!(&logger, "[journal] {}", l));
    }

    vm
}

fn get_file_content(logger: &Logger, file_path: &Path) -> Vec<u8> {
    let mut file = File::open(file_path).expect("Cannot open file");
    let mut buf = Vec::new();
    let res = file
        .read_to_end(&mut buf)
        .expect("Error while reading file");
    debug!(&logger, "{} bytes read", res);
    buf
}

fn create_rosetta_client(
    env: &TestEnv,
    vm: AllocatedVm,
    port: u32,
    ledger_id: CanisterId,
    governance_id: CanisterId,
) -> RosettaApiClient {
    let logger = env.logger();
    let client = RosettaApiClient::new(vm, port, ledger_id, governance_id, &logger);
    block_on(async {
        client.wait_for_startup().await;
    });
    client
}
