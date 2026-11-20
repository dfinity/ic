/* tag::catalog[]
Title:: Merging a subnet with the subnet merging tool running on a node of the
subnet it is merged into.

Goal:: Verify that the subnet merging tool (`rs/recovery/subnet_merging`), as
shipped in the GuestOS image and run on a node of the destination subnet the
way operators run `ic-recovery` on a node, i.e. with its directory in
`/var/lib/ic/data`, carries a subnet merge through: it halts both subnets,
downloads their states (the one of its own node locally), merges them on the
node, reroutes the canister ID ranges and proposes the recovery CUP of the
destination subnet at the merged state.

The subnet that is merged away is called `S`, and the Application subnet it is
merged into is called `D`.

Runbook::
0. Set up an IC with a System subnet and two Application subnets `S` and `D`,
   and install the NNS canisters.
1. Install a universal canister on each of `S` and `D`.
2. Run the subnet merging tool on a node of `D`, over SSH, with all its steps
   and without prompts: it downloads the state of `S` from a node of `S` over
   SSH and the state of `D` locally, and merges them on the node.
3. Check that the merged state on the node of `D` is a single checkpoint
   holding the canisters of both `S` and `D`, and that the registry holds the
   recovery CUP of `D` at the height of that checkpoint.

Success:: The tool completes all its steps on the node of `D`, and the
recovery CUP of `D` is at the merged state it assembled there.

end::catalog[] */

use anyhow::Result;
use ic_protobuf::registry::subnet::v1::catch_up_package_contents::CupType;
use ic_recovery::registry_helper::{RegistryHelper, RegistryPollingStrategy};
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::constants::SSH_USERNAME;
use ic_system_test_driver::driver::driver_setup::SSH_AUTHORIZED_PRIV_KEYS_DIR;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, NnsInstallationBuilder,
    SshSession, get_dependency_path_from_env, get_guestos_img_version, scp_send_to,
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{UniversalCanister, assert_create_agent};
use ic_types::{Height, SubnetId};
use slog::info;
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant},
};
use tokio::runtime::Runtime;

/// The number of nodes of each Application subnet.
const SUBNET_SIZE: usize = 4;

/// The DKG interval length of all subnets. Short, so that the subnets reach the
/// CUPs they halt at soon.
const DKG_INTERVAL_LENGTH: u64 = 49;

/// The directory the tool works in on the node, which is also where
/// `ic-recovery` works by default when run on a node.
const NODE_DATA_DIR: &str = "/var/lib/ic/data";

/// The checkpoints directory of the merged state the tool assembles on the node.
const MERGED_CHECKPOINTS_DIR: &str =
    "/var/lib/ic/data/recovery/merged_working_dir/data/ic_state/checkpoints";

/// The tool, as installed in the GuestOS image.
const TOOL_PATH: &str = "/opt/ic/bin/subnet-merging-tool";

/// Where `ic-admin`, which the tool submits its proposals with, is copied to on
/// the node.
const IC_ADMIN_REMOTE_PATH: &str = "/var/lib/admin/ic-admin";

/// Where the admin key, which the tool accesses the node of `S` with, is copied
/// to on the node.
const ADMIN_KEY_REMOTE_PATH: &str = "/var/lib/admin/admin_key";

/// Timeout for `S` to become "merge ready". The ingress history of `S` only
/// becomes free of terminal statuses once the entries of the ingress messages
/// installing its canister are pruned, at their (up to `MAX_INGRESS_TTL` = 5
/// minutes away) expiry times.
const MERGE_READY_TIMEOUT: Duration = Duration::from_secs(600);
/// Timeout for a subnet to reach the CUP it halts at, up to two DKG intervals
/// away, and for the node a state is downloaded from to finish the checkpoint
/// at its height.
const HALT_TIMEOUT: Duration = Duration::from_secs(300);
/// Timeout for the registry to reflect a proposal. Also bounds the wait for the
/// recovery CUP contents of `D`, which the registry only holds once the NNS
/// subnet has completed a fresh DKG for `D`.
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(300);
/// How long the tool waits between two evaluations of a condition it waits for.
const POLL_INTERVAL: Duration = Duration::from_secs(10);
/// How long the tool may run on the node. The tool retries a failing step
/// forever when prompts are skipped, so this is what ends a run that fails.
/// Above the sum of the timeouts of its steps.
const TOOL_TIMEOUT: Duration = Duration::from_secs(1800);

/// Timeouts of the test itself, above `TOOL_TIMEOUT` and `REGISTRY_TIMEOUT`.
/// The overall timeout additionally covers the setup and has to stay below the
/// 3600s of the `eternal` timeout of the Bazel target.
const PER_TEST_TIMEOUT: Duration = Duration::from_secs(2400);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(3000);

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .with_timeout_per_test(PER_TEST_TIMEOUT)
        .with_overall_timeout(OVERALL_TIMEOUT)
        // The nodes of `D` restart their replicas once they see the recovery
        // CUP of `D` in the registry.
        .update_orchestrator_metrics_to_check("orchestrator_processes_start_attempts_total", 2)
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    let logger = env.logger();
    info!(
        logger,
        "Step 0: Setting up the IC and installing the NNS canisters"
    );
    let subnet = |subnet_type, size| {
        Subnet::fast(subnet_type, size).with_dkg_interval_length(Height::from(DKG_INTERVAL_LENGTH))
    };
    InternetComputer::new()
        .add_subnet(subnet(SubnetType::System, 1))
        .add_subnet(subnet(SubnetType::Application, SUBNET_SIZE))
        .add_subnet(subnet(SubnetType::Application, SUBNET_SIZE))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("failed to install NNS canisters");
    info!(
        logger,
        "Step 0 done: the IC is up and the NNS canisters are installed"
    );
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let runtime = Runtime::new().expect("failed to create a tokio runtime");
    let topology = env.topology_snapshot();

    let app_subnets: Vec<_> = topology
        .subnets()
        .filter(|subnet| subnet.subnet_type() == SubnetType::Application)
        .collect();
    let [s_subnet, d_subnet] = app_subnets.as_slice() else {
        panic!(
            "expected exactly 2 Application subnets, got {}",
            app_subnets.len()
        );
    };
    let s_node = s_subnet.nodes().next().unwrap();
    let d_node = d_subnet.nodes().next().unwrap();

    info!(
        logger,
        "Step 1: Installing a universal canister on each of S and D"
    );
    // The names of the directories the checkpoints keep the states of the
    // canisters in, i.e. the hex encodings of their IDs.
    let canisters: BTreeSet<String> = [&s_node, &d_node]
        .into_iter()
        .map(|node| {
            runtime.block_on(async {
                let agent = assert_create_agent(node.get_public_url().as_str()).await;
                let canister = UniversalCanister::new_with_retries(
                    &agent,
                    node.effective_canister_id(),
                    &logger,
                )
                .await;
                hex::encode(canister.canister_id().as_slice())
            })
        })
        .collect();
    info!(logger, "Step 1 done: installed the canisters {canisters:?}");

    run_tool_on_node(
        &env,
        &s_node,
        &d_node,
        s_subnet.subnet_id,
        d_subnet.subnet_id,
    );

    check_merged_state_proposed(&env, &d_node, d_subnet.subnet_id, &canisters);
}

/// Step 2: run the subnet merging tool on `d_node`, with `s_node` as the node
/// of `S`, through all its steps and without prompts.
fn run_tool_on_node(
    env: &TestEnv,
    s_node: &IcNodeSnapshot,
    d_node: &IcNodeSnapshot,
    s_subnet_id: SubnetId,
    d_subnet_id: SubnetId,
) {
    let logger = env.logger();
    let d_node_ip = d_node.get_ip_addr();
    info!(
        logger,
        "Step 2: Running the subnet merging tool on node {d_node_ip} of subnet D"
    );

    let session = d_node.block_on_ssh_session().unwrap();
    scp_send_to(
        logger.clone(),
        &session,
        &get_dependency_path_from_env("IC_ADMIN_PATH"),
        Path::new(IC_ADMIN_REMOTE_PATH),
        0o755,
    );
    scp_send_to(
        logger.clone(),
        &session,
        &env.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
            .join(SSH_USERNAME),
        Path::new(ADMIN_KEY_REMOTE_PATH),
        0o400,
    );

    let nns_url = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .get_public_url();
    // The tool logs to stderr. It is redirected to stdout because the output is
    // read stdout first, stderr only after stdout's end: a full stderr would
    // block the tool, which would then never close stdout.
    let command = format!(
        "IC_ADMIN_PATH={IC_ADMIN_REMOTE_PATH} timeout {tool_timeout} {TOOL_PATH} merge \
         --nns-url {nns_url} \
         --replica-version {replica_version} \
         --dir {NODE_DATA_DIR} \
         --admin-key-file {ADMIN_KEY_REMOTE_PATH} \
         --test \
         --skip-prompts \
         --source-subnet-id {s_subnet_id} \
         --destination-subnet-id {d_subnet_id} \
         --download-node-source {s_node_ip} \
         --download-node-destination local \
         --merge-ready-timeout-secs {merge_ready_timeout} \
         --halt-timeout-secs {halt_timeout} \
         --registry-timeout-secs {registry_timeout} \
         --poll-interval-secs {poll_interval} \
         2>&1",
        tool_timeout = TOOL_TIMEOUT.as_secs(),
        replica_version = get_guestos_img_version(),
        s_node_ip = s_node.get_ip_addr(),
        merge_ready_timeout = MERGE_READY_TIMEOUT.as_secs(),
        halt_timeout = HALT_TIMEOUT.as_secs(),
        registry_timeout = REGISTRY_TIMEOUT.as_secs(),
        poll_interval = POLL_INTERVAL.as_secs(),
    );
    info!(logger, "Executing on node {d_node_ip}: {command}");
    match d_node.block_on_bash_script_from_session(&session, &command) {
        Ok(output) => info!(logger, "The subnet merging tool finished:\n{output}"),
        Err(err) => panic!("The subnet merging tool failed on node {d_node_ip}:\n{err}"),
    }

    info!(
        logger,
        "Step 2 done: the subnet merging tool ran through all its steps on node {d_node_ip}"
    );
}

/// Step 3: check that the tool assembled the merged state in its directory on
/// `d_node`, as a single checkpoint holding (at least) `canisters`, and that
/// the registry holds recovery CUP contents of `D` at the height of that
/// checkpoint.
fn check_merged_state_proposed(
    env: &TestEnv,
    d_node: &IcNodeSnapshot,
    d_subnet_id: SubnetId,
    canisters: &BTreeSet<String>,
) {
    let logger = env.logger();
    let node_ip = d_node.get_ip_addr();
    info!(
        logger,
        "Step 3: Checking the merged state on node {node_ip} and the recovery CUP of subnet D"
    );
    let run = |script: &str| {
        d_node
            .block_on_bash_script(script)
            .unwrap_or_else(|e| panic!("failed to run `{script}` on node {node_ip}: {e}"))
    };

    let checkpoints = run(&format!("sudo ls {MERGED_CHECKPOINTS_DIR}"));
    let checkpoints: Vec<&str> = checkpoints.split_whitespace().collect();
    let [checkpoint] = checkpoints.as_slice() else {
        panic!(
            "expected a single checkpoint in {MERGED_CHECKPOINTS_DIR} on node {node_ip}, got \
             {checkpoints:?}"
        );
    };
    let merged_height = u64::from_str_radix(checkpoint, 16)
        .unwrap_or_else(|e| panic!("checkpoint {checkpoint} is not named by its height: {e}"));

    let in_checkpoint = run(&format!(
        "sudo ls {MERGED_CHECKPOINTS_DIR}/{checkpoint}/canister_states"
    ));
    let in_checkpoint: BTreeSet<String> =
        in_checkpoint.split_whitespace().map(String::from).collect();
    assert!(
        in_checkpoint.is_superset(canisters),
        "merged checkpoint {checkpoint} on node {node_ip} holds the canisters \
         {in_checkpoint:?}, not all of {canisters:?}",
    );

    // The registry only holds the recovery CUP contents once the DKG for `D`
    // has completed, so they are polled for.
    let registry_helper = RegistryHelper::new(
        logger.clone(),
        env.topology_snapshot()
            .root_subnet()
            .nodes()
            .next()
            .unwrap()
            .get_public_url(),
        env.get_path("test_registry_local_store"),
        &env.get_path("nns.pem"),
        RegistryPollingStrategy::WithEveryRead,
    );
    let registry_client = registry_helper.registry_client();
    let deadline = Instant::now() + REGISTRY_TIMEOUT;
    let recovery_height = loop {
        let version = registry_helper
            .latest_registry_version()
            .expect("failed to fetch the latest registry version");
        let cup_type = registry_client
            .get_cup_contents(d_subnet_id, version)
            .unwrap_or_else(|e| {
                panic!("failed to read the CUP contents of subnet D at version {version}: {e}")
            })
            .value
            .unwrap_or_else(|| panic!("no CUP contents of subnet D at version {version}"))
            .cup_type;
        if let Some(CupType::Recovery(recovery_args)) = cup_type {
            break recovery_args.height;
        }
        assert!(
            Instant::now() < deadline,
            "the CUP contents of subnet D are not for a recovery at version {version}: \
             {cup_type:?}",
        );
        std::thread::sleep(POLL_INTERVAL);
    };
    assert_eq!(
        recovery_height, merged_height,
        "the recovery CUP of subnet D is not at the height of the merged checkpoint",
    );

    info!(
        logger,
        "Step 3 done: node {node_ip} holds the merged checkpoint {checkpoint} with the canisters \
         of S and D, and the registry holds the recovery CUP of subnet D at its height"
    );
}
