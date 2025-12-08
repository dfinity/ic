use anyhow::Result;
use dfn_candid::candid_one;
use flate2::read::GzDecoder;
use ic_base_types::PrincipalId;
use ic_canister_client::Sender;
use ic_canister_client_sender::SigKeys;
use ic_consensus_system_test_subnet_recovery::utils::BACKUP_USERNAME;
use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_consensus_system_test_utils::set_sandbox_env_vars;
use ic_consensus_system_test_utils::ssh_access::execute_bash_command;
use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der;
use ic_limits::DKG_INTERVAL_HEIGHT;
use ic_nervous_system_common::E8;
use ic_nested_nns_recovery_common::{
    grant_backup_access_to_all_nns_nodes, replace_nns_with_unassigned_nodes,
};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_governance_api::add_or_remove_node_provider::Change;
use ic_nns_governance_api::manage_neuron::{NeuronIdOrSubaccount, RegisterVote};
use ic_nns_governance_api::manage_neuron_response::Command as CommandResponse;
use ic_nns_governance_api::{
    AddOrRemoveNodeProvider, MakeProposalRequest, ManageNeuronCommandRequest, ManageNeuronRequest,
    ManageNeuronResponse, NnsFunction, NodeProvider, ProposalActionRequest, Vote,
};
use ic_nns_test_utils::governance::submit_external_update_proposal_allowing_error;
use ic_nns_test_utils::governance::wait_for_final_state;
use ic_protobuf::registry::replica_version::v1::GuestLaunchMeasurements;
use ic_registry_client::client::{RegistryClient, RegistryClientImpl};
use ic_registry_client_helpers::crypto::CryptoRegistry;
use ic_registry_local_store::LocalStoreImpl;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::constants::SSH_USERNAME;
use ic_system_test_driver::driver::driver_setup::SSH_AUTHORIZED_PRIV_KEYS_DIR;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{
    AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources,
};
use ic_system_test_driver::driver::ic_gateway_vm::{
    HasIcGatewayVm, IC_GATEWAY_VM_NAME, IcGatewayVm,
};
use ic_system_test_driver::driver::nested::NestedNodes;
use ic_system_test_driver::driver::prometheus_vm::{HasPrometheus, PrometheusVm};
use ic_system_test_driver::driver::test_env::{HasIcPrepDir, SshKeyGen, TestEnv, TestEnvAttribute};
use ic_system_test_driver::driver::test_env_api::*;
use ic_system_test_driver::driver::universal_vm::{DeployedUniversalVm, UniversalVm, UniversalVms};
use ic_system_test_driver::nns::{
    get_governance_canister, submit_update_elected_replica_versions_proposal,
    vote_execute_proposal_assert_executed,
};
use ic_system_test_driver::retry_with_msg;
use ic_system_test_driver::util::{block_on, runtime_from_url};
use ic_types::{Height, NodeId, ReplicaVersion, SubnetId};
use registry_canister::mutations::{
    do_add_api_boundary_nodes::AddApiBoundaryNodesPayload,
    do_add_node_operator::AddNodeOperatorPayload,
};
use serde::{Deserialize, Serialize};
use slog::{Logger, info};
use ssh2::Session;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Cursor;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::{io::Write, process::Command, time::Duration};
use url::Url;

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
const PATH_NODE_OPERATOR_PRIVATE_KEY_PEM: &str = "node_operator_private_key.pem";
const PATH_SET_TESTNET_ENV_VARS_SH: &str = "set_testnet_env_variables.sh";

const AUX_NODE_NAME: &str = "aux";

const ORIGINAL_NNS_ID: &str = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";
const MAINNET_NNS_DAPP_CANISTER_ID: &str = "qoctq-giaaa-aaaaa-aaaea-cai";

// Test neuron secret key and corresponding controller principal
const NEURON_CONTROLLER: &str = "bc7vk-kulc6-vswcu-ysxhv-lsrxo-vkszu-zxku3-xhzmh-iac7m-lwewm-2ae";
const NEURON_SECRET_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIKohpVANxO4xElQYXElAOXZHwJSVHERLE8feXSfoKwxX
oSMDIQBqgs2z86b+S5X9HvsxtE46UZwfDHtebwmSQWSIcKr2ew==
-----END PRIVATE KEY-----";

// Node operator principal and private key for the API BN during registration
const NODE_OPERATOR_PRINCIPAL: &str =
    "7532g-cd7sa-3eaay-weltl-purxe-qliyt-hfuto-364ru-b3dsz-kw5uz-kqe";
const NODE_OPERATOR_PRIVATE_KEY_PEM: &str = "-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIJ61mhHntzgHe39PaCg7JY6QJcbe0g3dvS1UnEEbKVzdoAcGBSuBBAAK
oUQDQgAEKSfx/T3gDtkfdGl1fiONzUHs0N7/hcfQ8zwcqIzwuvHK3qqSJ3EhY5OB
WIgAGf+2BAs2ac0RonxQZdQTmZMvrw==
-----END EC PRIVATE KEY-----";

#[derive(Deserialize, Serialize)]
pub struct RecoveredNnsNodeUrl {
    recovered_nns_node_url: Url,
}

impl TestEnvAttribute for RecoveredNnsNodeUrl {
    fn attribute_name() -> String {
        String::from("recovered_nns_node_url")
    }
}

#[derive(Deserialize, Serialize)]
pub struct RecoveredNnsDictatorNeuron {
    recovered_nns_dictator_neuron_id: NeuronId,
}

impl TestEnvAttribute for RecoveredNnsDictatorNeuron {
    fn attribute_name() -> String {
        String::from("recovered_nns_dictator_neuron_id")
    }
}

/// Sets up an IC running mainnet IC-OS nodes running the mainnet NNS
/// on the latest backup of the state of the mainnet NNS subnet.
///
/// The IC consists of a single-node system subnet and one unassigned node.
///
/// The mainnet NNS will be recovered to the unassigned node.
///
/// The single-node system subnet will run an initial NNS
/// that is required to perform the recovery but can be ignored after that.
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

    // Start a p8s and aux VMs concurrently:
    let env_clone = env.clone();
    let prometheus_thread = std::thread::spawn(move || {
        PrometheusVm::default()
            .start(&env_clone)
            .expect("Failed to start prometheus VM")
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
    // reconnect to the patched API BN.
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

    prometheus_thread.join().unwrap();
    env.sync_with_prometheus();
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
    test_recovered_nns(&env, neuron_id, &recovered_nns_node);

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

    propose_to_turn_into_api_bn(
        &env,
        neuron_id,
        Sender::SigKeys(
            SigKeys::from_pem(NEURON_SECRET_KEY_PEM).expect("Failed to parse secret key"),
        ),
        &recovered_nns_node,
        api_bn.node_id,
    );

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

fn test_recovered_nns(env: &TestEnv, neuron_id: NeuronId, nns_node: &IcNodeSnapshot) {
    let logger: slog::Logger = env.logger();
    info!(logger, "Testing recovered NNS ...");
    let sig_keys = SigKeys::from_pem(NEURON_SECRET_KEY_PEM).expect("Failed to parse secret key");
    let proposal_sender = Sender::SigKeys(sig_keys);
    bless_replica_version(
        &env,
        neuron_id,
        proposal_sender,
        &nns_node,
        &ReplicaVersion::try_from("1111111111111111111111111111111111111111").unwrap(),
        "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        vec![],
        None,
    );
    let recovered_nns_node_url = nns_node.get_public_url();
    RecoveredNnsNodeUrl {
        recovered_nns_node_url: recovered_nns_node_url.clone(),
    }
    .write_attribute(&env);
    RecoveredNnsDictatorNeuron {
        recovered_nns_dictator_neuron_id: neuron_id,
    }
    .write_attribute(&env);
    info!(
        logger,
        "Successfully recovered NNS at {}. Interact with it using {:?}.",
        recovered_nns_node_url,
        neuron_id,
    );
}

fn bless_replica_version(
    env: &TestEnv,
    neuron_id: NeuronId,
    proposal_sender: Sender,
    nns_node: &IcNodeSnapshot,
    replica_version: &ReplicaVersion,
    sha256: String,
    upgrade_urls: Vec<String>,
    guest_launch_measurements: Option<GuestLaunchMeasurements>,
) {
    info!(
        env.logger(),
        "Begin Bless replica version {}", replica_version
    );

    let logger = env.logger();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns_runtime);

    let proposal_id = {
        let logger = logger.clone();
        let replica_version = replica_version.clone();
        block_on(async move {
            let proposal_id = submit_update_elected_replica_versions_proposal(
                &governance_canister,
                proposal_sender,
                neuron_id,
                Some(&replica_version),
                Some(sha256),
                upgrade_urls,
                guest_launch_measurements,
                vec![],
            )
            .await;

            info!(
                logger,
                "Proposal {:?} to bless replica version {:?} has been submitted",
                proposal_id.to_string(),
                replica_version,
            );

            wait_for_final_state(&governance_canister, proposal_id).await;
            proposal_id
        })
    };

    info!(
        logger,
        "SUCCESS! Proposal {:?} to bless replica version {:?} has been executed successfully using neuron {:?}",
        proposal_id.to_string(),
        replica_version,
        neuron_id,
    );
}

fn fetch_recovered_nns_public_key_pem(recovered_nns_node: &IcNodeSnapshot) -> Vec<u8> {
    let recovered_nns_agent = ic_agent::Agent::builder()
        .with_url(recovered_nns_node.get_public_url())
        .build()
        .unwrap();
    block_on(recovered_nns_agent.fetch_root_key()).unwrap();
    let der_encoded = recovered_nns_agent.read_root_key();

    let mut pem = vec![];
    pem.extend_from_slice(b"-----BEGIN PUBLIC KEY-----\n");
    for chunk in base64::encode(der_encoded).as_bytes().chunks(64) {
        pem.extend_from_slice(chunk);
        pem.extend_from_slice(b"\n");
    }
    pem.extend_from_slice(b"-----END PUBLIC KEY-----\n");

    pem
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

    // Upload node operator private key to let the API BN re-register itself to the new registry
    upload_node_operator_private_key(api_bn, &ssh_session)
        .expect("Could not upload node operator private key to API BN");

    // Regenerate IC config and start ic-replica
    api_bn
        .block_on_bash_script_from_session(
            &ssh_session,
            "sudo systemctl restart generate-ic-config && sudo systemctl start ic-replica",
        )
        .expect("Could not restart ic-replica on API BN");

    // TODO: needed?
    info!(
        logger,
        "Waiting 30s for the API BN to restart ic-replica ..."
    );
    std::thread::sleep(Duration::from_secs(30));
}

fn delete_local_store(node: &IcNodeSnapshot, session: &Session) -> Result<String> {
    const PROD_LOCAL_STORE: &str = "/var/lib/ic/data/ic_registry_local_store";
    const TMP_EMPTY_DIR: &str = "/tmp/empty_dir";

    // TODO: replace with rm -rf below if it works
    node.block_on_bash_script_from_session(
        session,
        &format!(
            r#"
                set -e
                mkdir -p {TMP_EMPTY_DIR}
                sudo chown --reference={PROD_LOCAL_STORE} {TMP_EMPTY_DIR}
                sudo chmod --reference={PROD_LOCAL_STORE} {TMP_EMPTY_DIR}
                sudo mount --bind {TMP_EMPTY_DIR} {PROD_LOCAL_STORE}
            "#
        ),
    )
    // node.block_on_bash_script_from_session(
    //     session,
    //     &format!(
    //         r#"
    //             set -e
    //             sudo rm -rf {PROD_LOCAL_STORE}/*
    //         "#
    //     ),
    // )
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

fn upload_node_operator_private_key(node: &IcNodeSnapshot, session: &Session) -> Result<String> {
    const PROD_NODE_OPERATOR_PRIVATE_KEY: &str = "/var/lib/ic/data/node_operator_private_key.pem";

    node.block_on_bash_script_from_session(
        &session,
        &format!(
            r#"
                set -e
                sudo tee {PROD_NODE_OPERATOR_PRIVATE_KEY} >/dev/null <<EOF
{NODE_OPERATOR_PRIVATE_KEY_PEM}
EOF
            "#
        ),
    )
}

fn propose_to_turn_into_api_bn(
    env: &TestEnv,
    neuron_id: NeuronId,
    proposal_sender: Sender,
    nns_node: &IcNodeSnapshot,
    target_node: NodeId,
) {
    info!(
        env.logger(),
        "Submitting proposal to turn node {:?} into an API BN...", target_node
    );

    let logger = env.logger();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns_runtime);

    let proposal_id = {
        let logger = logger.clone();
        block_on(async move {
            let proposal_id = submit_external_update_proposal_allowing_error(
                &governance_canister,
                proposal_sender,
                neuron_id,
                NnsFunction::AddApiBoundaryNodes,
                AddApiBoundaryNodesPayload {
                    node_ids: vec![target_node],
                    version: get_mainnet_nns_revision().unwrap().to_string(),
                },
                format!("Adding node with ID {} as API Boundary Node", target_node),
                "".to_string(),
            )
            .await
            .expect("Failed to submit proposal to turn node into API BN");

            info!(
                logger,
                "Proposal {:?} to turn node {:?} into an API BN has been submitted",
                proposal_id.to_string(),
                target_node
            );

            wait_for_final_state(&governance_canister, proposal_id).await;
            proposal_id
        })
    };

    info!(
        logger,
        "Proposal {:?} to turn node {:?} into an API BN has been executed",
        proposal_id,
        target_node
    );
}

fn setup_ic(env: TestEnv) {
    let node_operator_principal = PrincipalId::from_str(NODE_OPERATOR_PRINCIPAL).unwrap();

    let dkg_interval = std::env::var("DKG_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DKG_INTERVAL_HEIGHT);

    // TODO: Something is fishy with the firewall. API BN is unreachable at port 22
    InternetComputer::new()
        .with_default_vm_resources(VmResources {
            vcpus: Some(NrOfVCPUs::new(16)),
            memory_kibibytes: None,
            boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
        })
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(1)
                .with_dkg_interval_length(Height::from(dkg_interval)),
        )
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
