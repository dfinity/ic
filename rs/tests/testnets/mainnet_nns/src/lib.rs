use anyhow::Result;
use ic_base_types::PrincipalId;
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_consensus_system_test_utils::set_sandbox_env_vars;
use ic_crypto_utils_threshold_sig_der::public_key_der_to_pem;
use ic_limits::DKG_INTERVAL_HEIGHT;
use ic_nervous_system_common::E8;
use ic_nns_common::types::NeuronId;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::constants::SSH_USERNAME;
use ic_system_test_driver::driver::driver_setup::SSH_AUTHORIZED_PRIV_KEYS_DIR;
use ic_system_test_driver::driver::ic::{ImageSizeGiB, InternetComputer, Subnet, VmResources};
use ic_system_test_driver::driver::ic_gateway_vm::{
    HasIcGatewayVm, IC_GATEWAY_VM_NAME, IcGatewayVm,
};
use ic_system_test_driver::driver::test_env::{HasIcPrepDir, TestEnv};
use ic_system_test_driver::driver::test_env_api::*;
use ic_system_test_driver::driver::universal_vm::{DeployedUniversalVm, UniversalVm, UniversalVms};
use ic_system_test_driver::util::block_on;
use ic_types::{ReplicaVersion, SubnetId};
use registry_canister::mutations::do_update_subnet::UpdateSubnetPayload;
use slog::{Logger, info};
use ssh2::Session;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::str::FromStr;
use std::sync::mpsc::{self, Receiver};
use std::{io::Write, process::Command};
use url::Url;

use crate::proposals::NEURON_CONTROLLER;
use crate::proposals::NEURON_SECRET_KEY_PEM;
use crate::proposals::ProposalWithMainnetState;

pub const MAINNET_NODE_VM_RESOURCES: VmResources = VmResources {
    vcpus: None,
    memory_kibibytes: None,
    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(192)),
};

// Default path to the mainnet NNS state tarball on the backup pod. Can be overridden through the
// NNS_STATE_ON_BACKUP_POD environment variable.
const NNS_STATE_ON_BACKUP_POD: &str =
    "dev@zh1-pyr07.zh1.dfinity.network:/home/dev/nns_state.tar.zst";

// Constants for paths used in the test environment
const PATH_STATE_TARBALL: &str = "nns_state.tar.zst";
const PATH_RECOVERY_WORKING_DIR: &str = "recovery/working_dir";
const PATH_NNS_STATE_DIR_PATH: &str = "recovery/working_dir/data";
const PATH_IC_CONFIG_DESTINATION: &str = "recovery/working_dir/ic.json5";
const PATH_IC_CONFIG_SRC_PATH: &str = "/run/ic-node/config/ic.json5";
const PATH_IC_REPLAY: &str = "ic-replay";
const PATH_IC_RECOVERY: &str = "ic-recovery";
const PATH_RECOVERED_NNS_PUBLIC_KEY_PEM: &str = "recovered_nns_public_key.pem";
const PATH_SET_TESTNET_ENV_VARS_SH: &str = "set_testnet_env_variables.sh";

const AUX_NODE_NAME: &str = "aux";

const ORIGINAL_NNS_ID: &str = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";
const MAINNET_NNS_DAPP_CANISTER_ID: &str = "qoctq-giaaa-aaaaa-aaaea-cai";

pub mod proposals;

/// Sets up an IC running mainnet IC-OS nodes running the mainnet NNS
/// on the latest backup of the state of the mainnet NNS subnet.
///
/// The IC consists of a single-node system subnet and one unassigned node.
///
/// The mainnet NNS will be recovered to the unassigned node.
///
/// The single-node system subnet will run an initial NNS
/// that is required to perform the recovery but can be ignored after that.
///
/// At the end of this function, there will be an HTTP gateway connected to an API BN connected to
/// a single-node NNS subnet running mainnet state.
/// The registry of the test environment (as in env.topology_snapshot()) is also patched to reflect
/// mainnet state. This means that subsequent calls will see all subnets and nodes of mainnet,
/// except the root subnet (tdb26), which will contain only the single-node NNS subnet.
/// Proposals can be made (and will instantly execute) using the relevant functions in
/// `crate::proposals`.
pub fn setup(env: TestEnv) {
    // Since we're creating the IC concurrently with fetching the state we use a channel to tell the
    // thread fetching the state when the IC is ready such that it can scp the ic.json5 config file
    // from the NNS node once it's online, used by ic-replay.
    let (tx_finished_ic_setup, rx_finished_ic_setup): (mpsc::Sender<()>, mpsc::Receiver<()>) =
        mpsc::channel();
    // The aux node will be sent to the recovery thread once it's setup.
    let (tx_aux_node, rx_aux_node): (
        std::sync::mpsc::Sender<DeployedUniversalVm>,
        Receiver<DeployedUniversalVm>,
    ) = mpsc::channel();

    // Recover the NNS concurrently:
    let env_clone = env.clone();
    let recover_nns_thread = std::thread::spawn(move || {
        setup_recovered_nns(env_clone, rx_finished_ic_setup, rx_aux_node)
    });

    // Setup and start the aux UVM concurrently:
    let env_clone = env.clone();
    let uvm_thread = std::thread::spawn(move || {
        UniversalVm::new(AUX_NODE_NAME.to_string())
            .start(&env_clone)
            .expect("Failed to start Universal VM")
    });

    let env_clone = env.clone();
    setup_ic(env_clone);

    // Once the IC is setup, we signal the other thread that it can now scp the ic.json5 config file
    tx_finished_ic_setup.send(()).unwrap();

    // Deploy the HTTP gateway
    let env_clone = env.clone();
    let deploy_gateway_thread = std::thread::spawn(move || {
        IcGatewayVm::new(IC_GATEWAY_VM_NAME)
            .start(&env_clone)
            .expect("Failed to setup ic-gateway");

        env_clone
            .get_deployed_ic_gateway(IC_GATEWAY_VM_NAME)
            .unwrap()
    });

    // When the aux host is ready, we send it to the other thread so that it can start the recovery
    uvm_thread.join().unwrap();
    let deployed_universal_vm = env.get_deployed_universal_vm(AUX_NODE_NAME).unwrap();
    tx_aux_node.send(deployed_universal_vm).unwrap();

    let http_gateway = deploy_gateway_thread.join().unwrap();
    let neuron_id = recover_nns_thread.join().unwrap();
    // After the NNS has been recovered and the API BN fixed, we should restart the HTTP gateway to
    // let it fetch the new root public key from the API BN.
    // Alternatively, we could start deploying the HTTP gateway only now. But deploying it in
    // parallel earlier and only having to restart the container now is faster.
    http_gateway
        .block_on_bash_script("docker restart ic-gateway")
        .unwrap();

    let http_gateway_url = http_gateway.get_public_url();
    info!(
        env.logger(),
        "NNS Dapp: https://{MAINNET_NNS_DAPP_CANISTER_ID}.{domain}",
        domain = http_gateway_url.host_str().unwrap()
    );

    write_sh_lib(&env, neuron_id, &http_gateway_url);

    patch_env_local_store(&env);
    patch_env_root_public_key(&env);
    remove_large_files(&env);
}

fn setup_recovered_nns(
    env: TestEnv,
    rx_finished_ic_setup: Receiver<()>,
    rx_aux_node: Receiver<DeployedUniversalVm>,
) -> NeuronId {
    let env_clone = env.clone();
    let fetch_mainnet_ic_replay_thread =
        std::thread::spawn(move || fetch_mainnet_ic_replay(&env_clone));
    let env_clone = env.clone();
    let fetch_mainnet_ic_recovery_thread =
        std::thread::spawn(move || fetch_mainnet_ic_recovery(&env_clone));
    fetch_nns_state_from_backup_pod(&env);

    // Wait until the IC setup is finished such that we can scp the ic.json5 config file from the
    // NNS
    rx_finished_ic_setup.recv().unwrap();

    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let recovered_nns_node = topology.unassigned_nodes().next().unwrap();
    fetch_ic_config(&env, &nns_node);

    // The following ensures ic-replay and ic-recovery know where to get their required dependencies.
    let recovery_dir = get_dependency_path("rs/tests");
    set_sandbox_env_vars(recovery_dir.join("recovery/binaries"));

    // Wait until we have fetched ic-replay before setting the test neuron (which needs ic-replay)
    fetch_mainnet_ic_replay_thread
        .join()
        .unwrap_or_else(|e| panic!("Failed to fetch the mainnet ic-replay because {e:?}"));

    let neuron_id: NeuronId = setup_test_neuron(&env);

    // Wait until the aux node is setup and we have fetched ic-recovery before starting the recovery
    let aux_node = rx_aux_node.recv().unwrap();
    fetch_mainnet_ic_recovery_thread
        .join()
        .unwrap_or_else(|e| panic!("Failed to fetch the mainnet ic-recovery because {e:?}"));

    recover_nns_subnet(&env, &nns_node, &recovered_nns_node, &aux_node);
    ProposalWithMainnetState::write_dictator_neuron_id_to_env(&env, neuron_id);

    test_recovered_nns(&env, &recovered_nns_node);

    info!(
        env.logger(),
        "Successfully recovered NNS at {}. Interact with it using {:?}.",
        nns_node.get_public_url(),
        neuron_id,
    );

    let dkg_interval = std::env::var("DKG_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DKG_INTERVAL_HEIGHT);
    let subnet_config = UpdateSubnetPayload {
        subnet_id: SubnetId::from(PrincipalId::from_str(ORIGINAL_NNS_ID).unwrap()),
        max_ingress_bytes_per_message: None,
        max_ingress_messages_per_block: None,
        max_block_payload_size: None,
        unit_delay_millis: None,
        initial_notary_delay_millis: None,
        dkg_interval_length: Some(dkg_interval),
        dkg_dealings_per_block: None,
        start_as_nns: None,
        subnet_type: None,
        is_halted: None,
        halt_at_cup_height: None,
        features: None,
        chain_key_config: None,
        chain_key_signing_enable: None,
        chain_key_signing_disable: None,
        max_number_of_canisters: None,
        ssh_readonly_access: None,
        ssh_backup_access: None,
        max_artifact_streams_per_peer: None,
        max_chunk_wait_ms: None,
        max_duplicity: None,
        max_chunk_size: None,
        receive_check_cache_size: None,
        pfn_evaluation_period_ms: None,
        registry_poll_period_ms: None,
        retransmission_request_ms: None,
        set_gossip_config_to_default: false,
    };
    block_on(ProposalWithMainnetState::update_subnet_record(
        recovered_nns_node.get_public_url(),
        subnet_config,
    ));

    let recovered_nns_pub_key = fetch_recovered_nns_public_key_pem(&recovered_nns_node);

    info!(
        env.logger(),
        "New NNS public key: {}",
        std::str::from_utf8(&recovered_nns_pub_key).unwrap(),
    );

    std::fs::write(
        env.get_path(PATH_RECOVERED_NNS_PUBLIC_KEY_PEM),
        &recovered_nns_pub_key,
    )
    .unwrap();

    let api_bn = env.topology_snapshot().api_boundary_nodes().next().unwrap();
    patch_api_bn(&env, &recovered_nns_node, &api_bn);

    neuron_id
}

fn fetch_mainnet_ic_replay(env: &TestEnv) {
    // TODO (CON-1624): fetch the mainnet version of ic-replay
    std::fs::copy(
        get_dependency_path(std::env::var("IC_REPLAY_PATH").unwrap()),
        env.get_path(PATH_IC_REPLAY),
    )
    .unwrap();
}

fn fetch_mainnet_ic_recovery(env: &TestEnv) {
    // TODO (CON-1624): fetch the mainnet version of ic-recovery
    std::fs::copy(
        get_dependency_path(std::env::var("IC_RECOVERY_PATH").unwrap()),
        env.get_path(PATH_IC_RECOVERY),
    )
    .unwrap();
}

fn fetch_nns_state_from_backup_pod(env: &TestEnv) {
    let logger: slog::Logger = env.logger();
    let remote_nns_state_path = std::env::var("NNS_STATE_ON_BACKUP_POD")
        .unwrap_or_else(|_| NNS_STATE_ON_BACKUP_POD.to_string());
    let local_nns_state_path = env.get_path(PATH_STATE_TARBALL);
    info!(
        logger,
        "Downloading {} to {:?} ...", remote_nns_state_path, local_nns_state_path
    );
    // TODO: consider using the ssh2 crate (like we do in prometheus_vm.rs)
    // instead of shelling out to scp.
    let mut cmd = Command::new("scp");
    cmd.arg("-oUserKnownHostsFile=/dev/null")
        .arg("-oStrictHostKeyChecking=no")
        .arg(&remote_nns_state_path)
        .arg(&local_nns_state_path);
    info!(env.logger(), "{cmd:?} ...");
    let scp_out = cmd.output().unwrap_or_else(|e| {
        panic!("Could not scp the {PATH_STATE_TARBALL} from the backup pod because: {e:?}!",)
    });
    if !scp_out.status.success() {
        std::io::stdout().write_all(&scp_out.stdout).unwrap();
        std::io::stderr().write_all(&scp_out.stderr).unwrap();
        panic!("Could not scp the {PATH_STATE_TARBALL} from the backup pod!");
    }
    info!(
        logger,
        "Downloaded {remote_nns_state_path} to {:?}, unpacking ...", local_nns_state_path
    );
    let mut cmd = Command::new("tar");
    cmd.arg("xf")
        .arg(&local_nns_state_path)
        .arg("-C")
        .arg(env.base_path())
        .arg(format!(
            "--transform=s|nns_state/|{PATH_NNS_STATE_DIR_PATH}/|"
        ));
    info!(env.logger(), "{cmd:?} ...");
    let tar_out = cmd
        .output()
        .expect("Could not unpack {NNS_STATE_BACKUP_TARBALL_PATH}!");
    if !tar_out.status.success() {
        std::io::stdout().write_all(&tar_out.stdout).unwrap();
        std::io::stderr().write_all(&tar_out.stderr).unwrap();
        panic!("Could not unpack {PATH_STATE_TARBALL}!");
    }
    info!(logger, "Unpacked {:?}", local_nns_state_path);
}

fn fetch_ic_config(env: &TestEnv, nns_node: &IcNodeSnapshot) {
    let logger: slog::Logger = env.logger();
    let nns_node_ip = nns_node.get_ip_addr();
    info!(
        logger,
        "Setting up SSH session to NNS node with IP {nns_node_ip:?} ..."
    );
    let session = nns_node.block_on_ssh_session().unwrap_or_else(|e| {
        panic!("Failed to setup SSH session to NNS node with IP {nns_node_ip:?} because: {e:?}!",)
    });

    let destination_dir = env.get_path(PATH_RECOVERY_WORKING_DIR);
    std::fs::create_dir_all(&destination_dir).unwrap_or_else(|e| {
        panic!("Couldn't create directory {destination_dir:?} because {e}!");
    });
    let destination = env.get_path(PATH_IC_CONFIG_DESTINATION);
    info!(
        logger,
        "scp-ing {nns_node_ip:?}:{PATH_IC_CONFIG_SRC_PATH:} to {destination:?} ..."
    );
    // scp the ic.json5 of the NNS node to the nns_state directory in the local test environment.
    let (mut remote_ic_config_file, _) = session
        .scp_recv(Path::new(PATH_IC_CONFIG_SRC_PATH))
        .unwrap_or_else(|e| {
            panic!("Failed to scp {nns_node_ip:?}:{PATH_IC_CONFIG_SRC_PATH:} because: {e:?}!",)
        });
    let mut destination_file = File::create(&destination)
        .unwrap_or_else(|e| panic!("Failed to open destination {destination:?} because: {e:?}"));
    std::io::copy(&mut remote_ic_config_file, &mut destination_file).unwrap_or_else(|e| {
        panic!(
            "Failed to scp {nns_node_ip:?}:{PATH_IC_CONFIG_SRC_PATH:} to {destination:?} because {e:?}!"
        )
    });
    info!(
        logger,
        "Successfully scp-ed {nns_node_ip:?}:{PATH_IC_CONFIG_SRC_PATH:} to {destination:?}."
    );
}

fn setup_test_neuron(env: &TestEnv) -> NeuronId {
    let neuron_id = with_neuron_for_tests(env);
    with_trusted_neurons_following_neuron_for_tests(env, neuron_id);
    neuron_id
}

fn with_neuron_for_tests(env: &TestEnv) -> NeuronId {
    let logger: slog::Logger = env.logger();
    let controller = PrincipalId::from_str(NEURON_CONTROLLER).unwrap();

    info!(logger, "Create a neuron followed by trusted neurons ...");
    // The neuron's stake must be large enough to be eligible to make proposals (> reject cost fee),
    // but not too large to avoid triggering a voting power spike. Instead, we will make trusted
    // neurons follow this neuron to boost its voting power, see
    // `with_trusted_neurons_following_neuron_for_tests`.
    let neuron_stake_e8s: u64 = 50 * E8;
    let ic_replay_out = ic_replay(env, |cmd| {
        cmd.arg("with-neuron-for-tests")
            .arg(controller.to_string())
            .arg(neuron_stake_e8s.to_string());
    });

    let prefix = "neuron_id=";
    let neuron_id = match std::str::from_utf8(&ic_replay_out.stdout)
        .unwrap()
        .split('\n')
        .filter(|line| line.starts_with(prefix))
        .collect::<Vec<&str>>()
        .first()
        .unwrap()
        .split(prefix)
        .collect::<Vec<&str>>()[..]
    {
        [_, neuron_id_str] => NeuronId(neuron_id_str.parse::<u64>().unwrap()),
        _ => panic!("Line didn't start with \"neuron_id=\"!"),
    };
    info!(logger, "Created neuron with id {neuron_id:?}");
    neuron_id
}

fn with_trusted_neurons_following_neuron_for_tests(env: &TestEnv, neuron_id: NeuronId) {
    let NeuronId(id) = neuron_id;
    let controller = PrincipalId::from_str(NEURON_CONTROLLER).unwrap();
    ic_replay(env, |cmd| {
        cmd.arg("with-trusted-neurons-following-neuron-for-tests")
            .arg(id.to_string())
            .arg(controller.to_string());
    });
}

fn ic_replay(env: &TestEnv, mut mutate_cmd: impl FnMut(&mut Command)) -> Output {
    let logger: slog::Logger = env.logger();
    let ic_replay_path = env.get_path(PATH_IC_REPLAY);
    let subnet_id = SubnetId::from(PrincipalId::from_str(ORIGINAL_NNS_ID).unwrap());
    let nns_state_dir = env.get_path(PATH_NNS_STATE_DIR_PATH);
    let ic_config_file = env.get_path(PATH_IC_CONFIG_DESTINATION);

    let mut cmd = Command::new(ic_replay_path);
    cmd.arg("--subnet-id")
        .arg(subnet_id.to_string())
        .arg("--data-root")
        .arg(&nns_state_dir)
        .arg(&ic_config_file);
    mutate_cmd(&mut cmd);
    info!(logger, "{cmd:?} ...");
    let ic_replay_out = cmd.output().expect(&format!("Failed to run {cmd:?}"));
    if !ic_replay_out.status.success() {
        std::io::stdout().write_all(&ic_replay_out.stdout).unwrap();
        std::io::stderr().write_all(&ic_replay_out.stderr).unwrap();
        panic!("Failed to run {cmd:?}!");
    }
    ic_replay_out
}

fn recover_nns_subnet(
    env: &TestEnv,
    nns_node: &IcNodeSnapshot,
    recovered_nns_node: &IcNodeSnapshot,
    aux_node: &DeployedUniversalVm,
) {
    let logger = env.logger();

    info!(
        logger,
        "Waiting until the {AUX_NODE_NAME} node is reachable over SSH before we run ic-recovery ..."
    );
    let _session = aux_node.block_on_ssh_session();

    info!(logger, "Starting ic-recovery ...");
    let recovery_binaries_path =
        std::fs::canonicalize(get_dependency_path("rs/tests/recovery/binaries")).unwrap();

    let dir = env.base_path();
    std::os::unix::fs::symlink(recovery_binaries_path, dir.join("recovery/binaries")).unwrap();

    let nns_url: Url = nns_node.get_public_url();
    let replica_version = get_guestos_img_version();
    let subnet_id = SubnetId::from(PrincipalId::from_str(ORIGINAL_NNS_ID).unwrap());
    let aux_ip = aux_node.get_vm().unwrap().ipv6;
    let priv_key_path = env
        .get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
        .join(SSH_USERNAME);
    let nns_ip = nns_node.get_ip_addr();
    let upload_ip = recovered_nns_node.get_ip_addr();

    let ic_recovery_path = env.get_path(PATH_IC_RECOVERY);
    let mut cmd = Command::new(ic_recovery_path);
    cmd.arg("--skip-prompts")
        .arg("--dir")
        .arg(dir)
        .arg("--nns-url")
        .arg(nns_url.to_string())
        .arg("--replica-version")
        .arg(replica_version.to_string())
        .arg("--admin-key-file")
        .arg(priv_key_path)
        .arg("--test-mode")
        .arg("nns-recovery-failover-nodes")
        .arg("--subnet-id")
        .arg(subnet_id.to_string())
        .arg("--replica-version")
        .arg(replica_version.to_string())
        .arg("--aux-ip")
        .arg(aux_ip.to_string())
        .arg("--aux-user")
        .arg(SSH_USERNAME)
        .arg("--validate-nns-url")
        .arg(nns_url.to_string())
        .arg("--upload-method")
        .arg(upload_ip.to_string())
        .arg("--parent-nns-host-ip")
        .arg(nns_ip.to_string())
        .arg("--replacement-nodes")
        .arg(recovered_nns_node.node_id.to_string())
        .arg("--skip")
        .arg("DownloadCertifications")
        .arg("--skip")
        .arg("MergeCertificationPools")
        .arg("--skip")
        .arg("ValidateReplayOutput")
        .arg("--skip")
        .arg("Cleanup");
    info!(logger, "{cmd:?} ...");
    let mut ic_recovery_child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("Failed to run {cmd:?} because {e:?}"));

    let exit_status = ic_recovery_child
        .wait()
        .unwrap_or_else(|e| panic!("Failed to wait for {cmd:?} because {e:?}"));

    if !exit_status.success() {
        panic!("{cmd:?} failed!");
    }
    recovered_nns_node
        .await_status_is_healthy()
        .expect("Recovered NNS node should become healthy.");
}

fn test_recovered_nns(env: &TestEnv, nns_node: &IcNodeSnapshot) {
    let logger = env.logger();
    info!(logger, "Testing recovered NNS ...");

    block_on(ProposalWithMainnetState::bless_replica_version(
        &nns_node,
        &ReplicaVersion::try_from("1111111111111111111111111111111111111111").unwrap(),
        &logger,
        "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        None,
        vec![],
    ));
}

fn fetch_recovered_nns_public_key_pem(recovered_nns_node: &IcNodeSnapshot) -> Vec<u8> {
    let recovered_nns_agent = ic_agent::Agent::builder()
        .with_url(recovered_nns_node.get_public_url())
        .build()
        .unwrap();
    block_on(recovered_nns_agent.fetch_root_key()).unwrap();
    let der_encoded = recovered_nns_agent.read_root_key();

    public_key_der_to_pem(der_encoded)
}

fn patch_api_bn(env: &TestEnv, recovered_nns_node: &IcNodeSnapshot, api_bn: &IcNodeSnapshot) {
    let logger = env.logger();
    let recovered_nns_node_ipv6 = recovered_nns_node.get_ip_addr();

    let ssh_session = api_bn.block_on_ssh_session().unwrap();

    // Stop ic-replica
    api_bn
        .block_on_bash_script_from_session(&ssh_session, "sudo systemctl stop ic-replica")
        .expect("Could not stop ic-replica on API BN");

    // Delete local store to let the node reinitialize it during first startup
    delete_local_store(api_bn, &ssh_session).expect("Could not delete local store of API BN");

    // Patch config NNS URLs to point to the recovered NNS node
    patch_config_nns_urls(
        api_bn,
        &ssh_session,
        &[Url::parse(&format!("http://[{recovered_nns_node_ipv6}]:8080/")).unwrap()],
    )
    .expect("Could not patch config NNS URLs of API BN");

    // Path config NNS public key to the recovered NNS public key
    patch_config_nns_public_key(
        &logger,
        api_bn,
        &ssh_session,
        &env.get_path(PATH_RECOVERED_NNS_PUBLIC_KEY_PEM),
    )
    .expect("Could not patch NNS public key of API BN");

    block_on(ProposalWithMainnetState::add_api_boundary_nodes(
        &recovered_nns_node,
        &env.logger(),
        vec![api_bn.node_id],
        get_mainnet_nns_revision().unwrap().to_string(),
    ));

    // Regenerate IC config and start ic-replica
    api_bn
        .block_on_bash_script_from_session(
            &ssh_session,
            "sudo systemctl restart generate-ic-config && sudo systemctl start ic-replica",
        )
        .expect("Could not restart ic-replica on API BN");

    api_bn
        .await_status_is_healthy()
        .expect("API BN did not become healthy after patching");
}

fn delete_local_store(node: &IcNodeSnapshot, session: &Session) -> Result<String> {
    const PROD_LOCAL_STORE: &str = "/var/lib/ic/data/ic_registry_local_store";

    node.block_on_bash_script_from_session(
        session,
        &format!(
            r#"
                set -e
                sudo rm -rf {PROD_LOCAL_STORE}/*
            "#
        ),
    )
}

fn patch_config_nns_urls(
    node: &IcNodeSnapshot,
    session: &Session,
    new_nns_urls: &[Url],
) -> Result<String> {
    const PROD_CONFIG_JSON: &str = "/run/config/config.json";
    const TMP_CONFIG_JSON: &str = "/tmp/config.json";

    let nns_urls_as_str = new_nns_urls
        .iter()
        .map(|url| format!(r#""{}""#, url))
        .collect::<Vec<String>>()
        .join(",");
    node.block_on_bash_script_from_session(
        session,
        &format!(
            r#"
                set -e
                jq '.icos_settings.nns_urls = [{nns_urls_as_str}]' {PROD_CONFIG_JSON} > {TMP_CONFIG_JSON}
                sudo chown --reference={PROD_CONFIG_JSON} {TMP_CONFIG_JSON}
                sudo chmod --reference={PROD_CONFIG_JSON} {TMP_CONFIG_JSON}
                sudo mount --bind {TMP_CONFIG_JSON} {PROD_CONFIG_JSON}
            "#
        ),
    )
}

fn patch_config_nns_public_key(
    logger: &Logger,
    node: &IcNodeSnapshot,
    session: &Session,
    new_nns_public_key_path: &Path,
) -> Result<String> {
    const PROD_NNS_PUBLIC_KEY: &str = "/run/config/nns_public_key.pem";
    const TMP_NNS_PUBLIC_KEY: &str = "/tmp/recovered_nns_public_key.pem";

    scp_send_to(
        logger.clone(),
        &session,
        new_nns_public_key_path,
        &PathBuf::from(TMP_NNS_PUBLIC_KEY),
        0o644,
    );
    node.block_on_bash_script_from_session(
        &session,
        &format!(
            r#"
                set -e
                sudo chown --reference={PROD_NNS_PUBLIC_KEY} {TMP_NNS_PUBLIC_KEY}
                sudo chmod --reference={PROD_NNS_PUBLIC_KEY} {TMP_NNS_PUBLIC_KEY}
                sudo mount --bind {TMP_NNS_PUBLIC_KEY} {PROD_NNS_PUBLIC_KEY}
            "#
        ),
    )
}

fn setup_ic(env: TestEnv) {
    let node_operator_principal =
        PrincipalId::from_str("7532g-cd7sa-3eaay-weltl-purxe-qliyt-hfuto-364ru-b3dsz-kw5uz-kqe")
            .unwrap();

    InternetComputer::new()
        .with_default_vm_resources(MAINNET_NODE_VM_RESOURCES)
        .add_subnet(Subnet::fast_single_node(SubnetType::System))
        .with_api_boundary_nodes(1)
        .with_unassigned_nodes(1)
        .with_unassigned_config()
        .with_node_provider(node_operator_principal)
        .with_node_operator(node_operator_principal)
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

/// Write a shell script containing some environment variable exports.
/// This script can be sourced such that we can easily use the legacy
/// nns-tools shell scripts in /testnet/tools/nns-tools/ with the dynamic
/// testnet deployed by this system-test.
fn write_sh_lib(env: &TestEnv, neuron_id: NeuronId, http_gateway: &Url) {
    let logger: slog::Logger = env.logger();
    let set_testnet_env_vars_sh_path = env.get_path(PATH_SET_TESTNET_ENV_VARS_SH);
    let set_testnet_env_vars_sh_str = set_testnet_env_vars_sh_path.display();
    let ic_admin =
        fs::canonicalize(get_dependency_path("rs/tests/recovery/binaries/ic-admin")).unwrap();
    let pem = env.get_path("neuron_secret_key.pem");
    let mut pem_file = File::create(&pem).unwrap();
    pem_file
        .write_all(NEURON_SECRET_KEY_PEM.as_bytes())
        .unwrap();
    let neuron_id_number = neuron_id.0;
    fs::write(
        &set_testnet_env_vars_sh_path,
        format!(
            "export IC_ADMIN={ic_admin:?};\n\
             export PEM={pem:?};\n\
             export NNS_URL=\"{http_gateway}\";\n\
             export NEURON_ID={neuron_id_number:?};\n\
            "
        ),
    )
    .unwrap_or_else(|e| {
        panic!(
            "Writing {set_testnet_env_vars_sh_str} failed because: {}",
            e
        )
    });
    let canonical_sh_lib_path = fs::canonicalize(set_testnet_env_vars_sh_path).unwrap();
    info!(logger, "source {canonical_sh_lib_path:?}");
}

// Overwrite the local store of the test environment with the new one, corresponding to the
// recovered NNS. Any topology snapshot taken after this will reflect the new topology. This means
// it will contain all mainnet subnets and nodes.
fn patch_env_local_store(env: &TestEnv) {
    let local_store_path = env
        .get_path(PATH_RECOVERY_WORKING_DIR)
        .join("data")
        .join("ic_registry_local_store");
    let mut cp = Command::new("cp");
    cp.arg("-r")
        .arg(local_store_path)
        .arg(env.get_path("tmp_new_local_store"));
    cp.output().expect("Failed to copy local store");

    // Atomically swap the local stores, see `man 2 renameat2` for details.
    nix::fcntl::renameat2(
        None,
        &fs::canonicalize(env.get_path("tmp_new_local_store")).unwrap(),
        None,
        &fs::canonicalize(
            env.prep_dir("")
                .map(|v| v.registry_local_store_path())
                .unwrap(),
        )
        .unwrap(),
        nix::fcntl::RenameFlags::RENAME_EXCHANGE,
    )
    .expect("Failed to atomically swap local stores");

    let mut rm = Command::new("rm");
    rm.arg("-rf").arg(env.get_path("tmp_new_local_store"));
    rm.output()
        .expect("Failed to remove temporary new local store");

    block_on(
        env.topology_snapshot()
            .block_for_newest_mainnet_registry_version(),
    )
    .unwrap();
}

fn patch_env_root_public_key(env: &TestEnv) {
    std::fs::copy(
        env.get_path(PATH_RECOVERED_NNS_PUBLIC_KEY_PEM),
        env.prep_dir("").unwrap().root_public_key_path(),
    )
    .unwrap();
}

fn remove_large_files(env: &TestEnv) {
    let mut rm = Command::new("rm");
    rm.arg("-rf")
        .arg(env.get_path(PATH_STATE_TARBALL))
        .arg(env.get_path("recovery"));
    rm.output().expect("Failed to remove large files");
}
