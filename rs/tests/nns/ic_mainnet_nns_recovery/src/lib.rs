// A small Rust library that exports a setup() function to be used in system-tests,
// like the nns_upgrade_test, which sets up an IC with an NNS which is recovered
// from the latest mainnet backup.
//
// There are tests that use this library. Run them using either:
//
// * rm -rf test_tmpdir; ict testnet create recovered_mainnet_nns --lifetime-mins 120 --set-required-host-features=dc=zh1 --verbose -- --test_tmpdir=test_tmpdir
//
// * rm -rf test_tmpdir; ict test nns_upgrade_test --set-required-host-features=dc=zh1 -- --test_tmpdir=test_tmpdir --flaky_test_attempts=1

use anyhow::Result;

use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use ic_registry_subnet_type::SubnetType;
use ic_tests::driver::universal_vm::UniversalVm;
use ic_types::{PrincipalId, ReplicaVersion, SubnetId};

use ic_canister_client::Sender;
use ic_canister_client_sender::SigKeys;
use ic_nervous_system_common::E8;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_common::types::NeuronId;
use ic_recovery::nns_recovery_failover_nodes::{
    NNSRecoveryFailoverNodes, NNSRecoveryFailoverNodesArgs, StepType,
};
use ic_recovery::RecoveryArgs;
use ic_replay::cmd::{
    ClapSubnetId, ReplayToolArgs, SubCommand, WithTrustedNeuronsFollowingNeuronCmd,
};
use ic_replay::replay;
use ic_tests::driver::boundary_node::BoundaryNodeVm;
use ic_tests::driver::constants::SSH_USERNAME;
use ic_tests::driver::driver_setup::SSH_AUTHORIZED_PRIV_KEYS_DIR;
use ic_tests::driver::universal_vm::DeployedUniversalVm;
use ic_tests::driver::{
    boundary_node::BoundaryNode,
    ic::{ImageSizeGiB, InternetComputer, Subnet, VmResources},
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::{TestEnv, TestEnvAttribute},
    test_env_api::{
        await_boundary_node_healthy, retry, HasDependencies, HasIcDependencies, HasPublicApiUrl,
        HasTopologySnapshot, IcNodeContainer, IcNodeSnapshot, NnsCanisterWasmStrategy,
        NnsCustomizations, SshSession, TopologySnapshot,
    },
    universal_vm::UniversalVms,
};
use ic_tests::nns::{
    get_governance_canister, submit_update_elected_replica_versions_proposal,
    vote_execute_proposal_assert_executed,
};
use ic_tests::orchestrator::utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_tests::orchestrator::utils::subnet_recovery::set_sandbox_env_vars;
use ic_tests::util::{block_on, runtime_from_url};
use serde::{Deserialize, Serialize};
use slog::info;
use ssh2::Session;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::time::Duration;
use url::Url;

pub const OVERALL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
pub const PER_TEST_TIMEOUT: Duration = Duration::from_secs(50 * 60);

// TODO: move this to an environment variable and set this on the CLI using --test_env=NNS_BACKUP_POD=zh1-pyr07.zh1.dfinity.network
const NNS_BACKUP_POD: &str = "zh1-pyr07.zh1.dfinity.network";
const NNS_BACKUP_POD_USER: &str = "dev";
const BOUNDARY_NODE_NAME: &str = "boundary-node-1";
const AUX_NODE_NAME: &str = "aux";
const RECOVERY_WORKING_DIR: &str = "recovery/working_dir";
const IC_CONFIG_DESTINATION: &str = "recovery/working_dir/ic.json5";
const NNS_STATE_DIR_PATH: &str = "recovery/working_dir/data";
const NNS_STATE_BACKUP_TARBALL_PATH: &str = "nns_state.tar.zst";
const CONTROLLER: &str = "bc7vk-kulc6-vswcu-ysxhv-lsrxo-vkszu-zxku3-xhzmh-iac7m-lwewm-2ae";
const ORIGINAL_NNS_ID: &str = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";
const IC_CONFIG_SRC_PATH: &str = "/run/ic-node/config/ic.json5";
const SET_TESTNET_ENV_VARS_SH: &str = "set_testnet_env_variables.sh";

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

pub fn setup(env: TestEnv) {
    let logger = env.logger();
    // Check if there's SSH connectivity to the backup pod.
    info!(
        logger,
        "Setting up SSH session to {NNS_BACKUP_POD_USER}@{NNS_BACKUP_POD} ..."
    );
    let _sess = get_ssh_session_to_backup_pod().unwrap_or_else(|e| {
        panic!(
            "Could not setup SSH session to {NNS_BACKUP_POD_USER}@{NNS_BACKUP_POD} because: {e:?}!",
        )
    });

    // The following ensures ic-replay and ic-recovery know where to get their required dependencies.
    let recovery_dir = env.get_dependency_path("rs/tests");
    set_sandbox_env_vars(recovery_dir.join("recovery/binaries"));

    // Fetch and unpack the NNS mainnet state backup concurrently with setting up the IC.
    // ic-replay also requires the ic.json5 config file of an NNS node.
    // Since we're creating the IC concurrently with fetching the state we use a channel to communicate
    // the IC topology to the thread fetching the backup such that the latter thread can later scp
    // the ic.json5 config file from the NNS node when it's online.
    let (tx_topology, rx_topology): (
        std::sync::mpsc::Sender<TopologySnapshot>,
        Receiver<TopologySnapshot>,
    ) = mpsc::channel();
    let (tx_aux_node, rx_aux_node): (
        std::sync::mpsc::Sender<DeployedUniversalVm>,
        Receiver<DeployedUniversalVm>,
    ) = mpsc::channel();
    let env_clone = env.clone();
    let nns_state_thread = std::thread::spawn(move || {
        fetch_nns_state_from_backup_pod(env_clone.clone());

        let topology = rx_topology.recv().unwrap();
        let nns_node = topology.root_subnet().nodes().next().unwrap();
        let recovered_nns_node = topology.unassigned_nodes().next().unwrap();
        fetch_ic_config(env_clone.clone(), nns_node.clone());

        let neuron_id: NeuronId = prepare_nns_state(env_clone.clone());

        let aux_node = rx_aux_node.recv().unwrap();
        recover_nns_subnet(
            env_clone.clone(),
            nns_node,
            recovered_nns_node.clone(),
            aux_node,
        );
        test_recovered_nns(env_clone.clone(), neuron_id, recovered_nns_node.clone());

        write_sh_lib(env_clone.clone(), neuron_id, recovered_nns_node.clone());

        setup_boundary_node(env_clone, recovered_nns_node);
    });

    // Start a p8s VM concurrently:
    let env_clone = env.clone();
    let prometheus_thread = std::thread::spawn(move || {
        PrometheusVm::default()
            .start(&env_clone)
            .expect("Failed to start prometheus VM");
    });

    let env_clone = env.clone();
    let uvm_thread = std::thread::spawn(move || {
        UniversalVm::new(AUX_NODE_NAME.to_string())
            .start(&env_clone)
            .expect("Failed to start Universal VM");
    });

    // Start an IC, install the NNS and start a Boundary Node:
    InternetComputer::new()
        .with_default_vm_resources(VmResources {
            vcpus: None,
            memory_kibibytes: None,
            boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
        })
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(VmResources {
                    vcpus: None,
                    memory_kibibytes: None,
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                })
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(VmResources {
                    vcpus: None,
                    memory_kibibytes: None,
                    boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
                })
                .add_nodes(1),
        )
        .with_unassigned_nodes(1)
        .with_mainnet_config()
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCanisterWasmStrategy::TakeBuiltFromSources,
        NnsCustomizations::default(),
    );

    {
        let env: TestEnv = env.clone();
        let test_neuron_id = NeuronId(TEST_NEURON_1_ID);
        let topology = env.topology_snapshot();
        let nns_node = topology.root_subnet().nodes().next().unwrap();
        let proposal_sender = Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR);
        bless_replica_version(
            env,
            test_neuron_id,
            proposal_sender,
            nns_node,
            "0000000000000000000000000000000000000000".to_string(),
        );
    }

    let env_clone = env.clone();
    std::thread::spawn(move || {
        // Send the IC topology to the thread fetching the nns state (nns_state_thread)
        // such that it can scp the ic.json5 config file required by ic-replay.
        let topology = env_clone.topology_snapshot();
        tx_topology.send(topology).unwrap();

        uvm_thread.join().unwrap();
        let deployed_universal_vm = env_clone.get_deployed_universal_vm(AUX_NODE_NAME).unwrap();
        tx_aux_node.send(deployed_universal_vm).unwrap();
    });

    prometheus_thread.join().unwrap();
    env.sync_with_prometheus();

    nns_state_thread
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e));
}

fn setup_boundary_node(env: TestEnv, recovered_nns_node: IcNodeSnapshot) {
    let ic_admin_path = env
        .clone()
        .get_dependency_path("rs/tests/recovery/binaries/ic-admin");
    let recovered_nns_url = recovered_nns_node.get_public_url();
    let recovered_nns_nns_public_key = env.clone().get_path("recovered_nns_pubkey.pem");
    Command::new(ic_admin_path)
        .arg("--nns-url")
        .arg(recovered_nns_url.to_string())
        .arg("get-subnet-public-key")
        .arg(ORIGINAL_NNS_ID)
        .arg(recovered_nns_nns_public_key.clone())
        .output()
        .unwrap_or_else(|e| {
            panic!("Could not get the public key of the recovered NNS because {e:?}",)
        });

    BoundaryNode::new(String::from(BOUNDARY_NODE_NAME))
        .allocate_vm(&env)
        .expect("Allocation of BoundaryNode failed.")
        .for_ic(&env, "")
        .with_nns_public_key(recovered_nns_nns_public_key)
        .with_nns_urls(vec![recovered_nns_url])
        .use_real_certs_and_dns()
        .start(&env)
        .expect("failed to setup BoundaryNode VM");

    let boundary_node = env
        .clone()
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    await_boundary_node_healthy(&env, BOUNDARY_NODE_NAME);

    let recovered_nns_node_id = recovered_nns_node.node_id;
    boundary_node.block_on_bash_script(&format!(r#"
        set -e
        cp /etc/nginx/conf.d/002-mainnet-nginx.conf /tmp/
        sed 's/set $subnet_id "$random_route_subnet_id";/set $subnet_id "{ORIGINAL_NNS_ID}";/' -i /tmp/002-mainnet-nginx.conf
        sed 's/set $subnet_type "$random_route_subnet_type";/set $subnet_type "system";/' -i /tmp/002-mainnet-nginx.conf
        sed 's/set $node_id "$random_route_node_id";/set $node_id "{recovered_nns_node_id}";/' -i /tmp/002-mainnet-nginx.conf
        sudo mount --bind /tmp/002-mainnet-nginx.conf /etc/nginx/conf.d/002-mainnet-nginx.conf
        sudo systemctl reload nginx
    "#)).unwrap_or_else(|e| {
        panic!("Could not reconfigure nginx on {BOUNDARY_NODE_NAME} to only route to the recovered NNS because {e:?}",)
    });
    let bn = env.get_deployed_boundary_node(BOUNDARY_NODE_NAME).unwrap();
    let bn_snapshot = bn.get_snapshot().unwrap();
    if let Some(playnet) = bn_snapshot.playnet {
        info!(
            env.logger(),
            "NNS Dapp: https://qoctq-giaaa-aaaaa-aaaea-cai.{playnet}"
        );
    }
}

fn get_ssh_session_to_backup_pod() -> Result<Session> {
    let tcp = TcpStream::connect((NNS_BACKUP_POD, 22))?;
    let mut sess = Session::new()?;
    sess.set_tcp_stream(tcp);
    sess.handshake()?;
    sess.userauth_agent(NNS_BACKUP_POD_USER)?;
    Ok(sess)
}

fn fetch_nns_state_from_backup_pod(env: TestEnv) {
    let target = format!("{NNS_BACKUP_POD_USER}@{NNS_BACKUP_POD}:/home/{NNS_BACKUP_POD_USER}/{NNS_STATE_BACKUP_TARBALL_PATH}");
    let logger: slog::Logger = env.logger();
    let nns_state_backup_path = env.get_path(NNS_STATE_BACKUP_TARBALL_PATH);
    info!(
        logger,
        "Downloading {} to {:?} ...",
        target,
        nns_state_backup_path.clone()
    );
    // TODO: consider using the ssh2 crate (like we do in prometheus_vm.rs)
    // instead of shelling out to scp.
    let tar_out = Command::new("scp")
        .arg("-oUserKnownHostsFile=/dev/null")
        .arg("-oStrictHostKeyChecking=no")
        .arg("-v")
        .arg(target.clone())
        .arg(nns_state_backup_path.clone())
        .output()
        .unwrap_or_else(|e| {
            panic!("Could not scp the {NNS_STATE_BACKUP_TARBALL_PATH} from the backup pod because: {e:?}!",)
        });
    if !tar_out.status.success() {
        std::io::stdout().write_all(&tar_out.stdout).unwrap();
        std::io::stderr().write_all(&tar_out.stderr).unwrap();
        panic!("Could not scp the {NNS_STATE_BACKUP_TARBALL_PATH} from the backup pod!");
    }
    info!(
        logger,
        "Downloaded {target:} to {:?}, unpacking ...", nns_state_backup_path
    );
    let tar_out = Command::new("tar")
        .arg("xf")
        .arg(nns_state_backup_path.clone())
        .arg("-C")
        .arg(env.base_path())
        .arg(format!("--transform=s|nns_state/|{NNS_STATE_DIR_PATH}/|"))
        .output()
        .expect("Could not unpack {NNS_STATE_BACKUP_TARBALL_PATH}!");
    if !tar_out.status.success() {
        std::io::stdout().write_all(&tar_out.stdout).unwrap();
        std::io::stderr().write_all(&tar_out.stderr).unwrap();
        panic!("Could not unpack {NNS_STATE_BACKUP_TARBALL_PATH}!");
    }
    info!(logger, "Unpacked {:?}", nns_state_backup_path);
}

fn fetch_ic_config(env: TestEnv, nns_node: IcNodeSnapshot) {
    let logger: slog::Logger = env.logger();
    let nns_node_ip = nns_node.get_ip_addr();
    info!(
        logger,
        "Setting up SSH session to NNS node with IP {nns_node_ip:?} ..."
    );
    let session = nns_node.block_on_ssh_session().unwrap_or_else(|e| {
        panic!("Failed to setup SSH session to NNS node with IP {nns_node_ip:?} because: {e:?}!",)
    });

    let destination_dir = env.get_path(RECOVERY_WORKING_DIR);
    std::fs::create_dir_all(destination_dir.clone()).unwrap_or_else(|e| {
        panic!("Couldn't create directory {destination_dir:?} because {e}!");
    });
    let destination = env.get_path(IC_CONFIG_DESTINATION);
    info!(
        logger,
        "scp-ing {nns_node_ip:?}:{IC_CONFIG_SRC_PATH:} to {destination:?} ..."
    );
    // scp the ic.json5 of the NNS node to the nns_state directory in the local test environment.
    let (mut remote_ic_config_file, _) = session
        .scp_recv(Path::new(IC_CONFIG_SRC_PATH))
        .unwrap_or_else(|e| {
            panic!("Failed to scp {nns_node_ip:?}:{IC_CONFIG_SRC_PATH:} because: {e:?}!",)
        });
    let mut destination_file = File::create(&destination)
        .unwrap_or_else(|e| panic!("Failed to open destination {destination:?} because: {e:?}"));
    std::io::copy(&mut remote_ic_config_file, &mut destination_file).unwrap_or_else(|e| {
        panic!(
            "Failed to scp {nns_node_ip:?}:{IC_CONFIG_SRC_PATH:} to {destination:?} because {e:?}!"
        )
    });
    info!(
        logger,
        "Successfully scp-ed {nns_node_ip:?}:{IC_CONFIG_SRC_PATH:} to {destination:?}."
    );
}

fn prepare_nns_state(env: TestEnv) -> NeuronId {
    let logger: slog::Logger = env.logger();
    let ic_config_file = env.get_path(IC_CONFIG_DESTINATION);
    let nns_state_dir = env.get_path(NNS_STATE_DIR_PATH);
    let controller = PrincipalId::from_str(CONTROLLER).unwrap();
    let subnet_id = SubnetId::from(PrincipalId::from_str(ORIGINAL_NNS_ID).unwrap());
    let clap_subnet_id = ClapSubnetId(subnet_id);

    info!(logger, "Create a neuron followed by trusted neurons ...");
    let neuron_stake_e8s: u64 = 1_000_000_000 * E8;
    let ic_replay_path = env.get_dependency_path("rs/replay/ic-replay");
    let mut ic_replay_cmd = Command::new(ic_replay_path);
    let ic_replay_cmd = ic_replay_cmd
        .arg("--subnet-id")
        .arg(subnet_id.to_string())
        .arg("--data-root")
        .arg(nns_state_dir.clone())
        .arg(ic_config_file.clone())
        .arg("with-neuron-for-tests")
        .arg(controller.to_string())
        .arg(neuron_stake_e8s.to_string());
    info!(logger, "Running {ic_replay_cmd:?} ...");
    let ic_replay_out = ic_replay_cmd
        .output()
        .expect("Failed to run {ic_replay_cmd:?}");
    if !ic_replay_out.status.success() {
        std::io::stdout().write_all(&ic_replay_out.stdout).unwrap();
        std::io::stderr().write_all(&ic_replay_out.stderr).unwrap();
        panic!("Failed to run {ic_replay_cmd:?}!");
    }
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

    /*
    TODO: replace the above using the ic-replay library:
    replay(ReplayToolArgs {
        config: Some(ic_config_file),
        canister_caller_id: None,
        subcmd: Some(SubCommand::WithNeuronForTests(WithNeuronCmd {
            neuron_controller: controller,
            neuron_stake_e8s: neuron_stake_e8s,
        })),
        subnet_id: Some(clap_subnet_id),
        data_root: Some(nns_state_dir),
        replay_until_height: None,
    })
    .unwrap();
    */

    let NeuronId(id) = neuron_id;
    replay(ReplayToolArgs {
        config: Some(ic_config_file),
        canister_caller_id: None,
        subcmd: Some(SubCommand::WithTrustedNeuronsFollowingNeuronForTests(
            WithTrustedNeuronsFollowingNeuronCmd {
                neuron_id: id,
                neuron_controller: controller,
            },
        )),
        subnet_id: Some(clap_subnet_id),
        data_root: Some(nns_state_dir),
        replay_until_height: None,
    })
    .unwrap();
    neuron_id
}

fn recover_nns_subnet(
    env: TestEnv,
    nns_node: IcNodeSnapshot,
    recovered_nns_node: IcNodeSnapshot,
    aux_node: DeployedUniversalVm,
) {
    let logger = env.logger();

    info!(
        logger,
        "Waiting until the {AUX_NODE_NAME} node is reachable over SSH before we run ic-recovery ..."
    );
    let _session = aux_node.block_on_ssh_session();

    info!(logger, "Starting ic-recovery ...");
    let recovery_binaries_path =
        std::fs::canonicalize(env.get_dependency_path("rs/tests/recovery/binaries")).unwrap();

    let dir = env.base_path();
    std::os::unix::fs::symlink(recovery_binaries_path, dir.join("recovery/binaries")).unwrap();

    let nns_url: url::Url = nns_node.get_public_url();
    let replica_version = env.get_initial_replica_version().unwrap();
    let subnet_id = SubnetId::from(PrincipalId::from_str(ORIGINAL_NNS_ID).unwrap());
    let aux_ip = aux_node.get_vm().unwrap().ipv6;
    let priv_key_path = env
        .get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
        .join(SSH_USERNAME);
    let nns_ip = nns_node.get_ip_addr();
    let upload_ip = recovered_nns_node.get_ip_addr();

    let recovery_args = RecoveryArgs {
        dir,
        nns_url: nns_url.clone(),
        replica_version: Some(replica_version.clone()),
        key_file: Some(priv_key_path),
        test_mode: true,
    };

    let nns_recovery_failover_nodes_args = NNSRecoveryFailoverNodesArgs {
        subnet_id,
        replica_version: Some(replica_version),
        aux_ip: Some(IpAddr::V6(aux_ip)),
        aux_user: Some(SSH_USERNAME.to_string()),
        registry_url: None,
        validate_nns_url: nns_url,
        download_node: None,
        upload_node: Some(upload_ip),
        parent_nns_host_ip: Some(nns_ip),
        replacement_nodes: Some(vec![recovered_nns_node.node_id]),
        next_step: None,
    };

    let nns_recovery_failover_nodes = NNSRecoveryFailoverNodes::new(
        logger.clone(),
        recovery_args,
        None,
        nns_recovery_failover_nodes_args,
        false,
    );

    // go over all steps of the NNS recovery
    for (step_type, step) in nns_recovery_failover_nodes {
        if step_type == StepType::DownloadCertifications
            || step_type == StepType::MergeCertificationPools
            || step_type == StepType::ValidateReplayOutput
        {
            info!(logger, "Skipping step: {:?}", step_type);
            continue;
        }
        info!(logger, "Executing step: {:?}", step_type);
        info!(logger, "{}", step.descr());
        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {:?} failed: {}", step_type, e));
    }

    info!(
        logger.clone(),
        "Recovery done, waiting until the new NNS starts up @ {upload_ip:?} ..."
    );
    retry(
        logger.clone(),
        Duration::from_secs(500),
        Duration::from_secs(5),
        || recovered_nns_node.block_on_bash_script("journalctl | grep -q 'Ready for interaction'"),
    )
    .expect("NNS didn't start up!");

    info!(logger, "NNS @ {upload_ip:?} is ready for interaction.");
}

fn test_recovered_nns(env: TestEnv, neuron_id: NeuronId, nns_node: IcNodeSnapshot) {
    let logger: slog::Logger = env.clone().logger();
    info!(logger, "Testing recovered NNS ...");
    let contents = env
        .clone()
        .read_dependency_to_string("rs/tests/nns/secret_key.pem")
        .expect("Could not read rs/tests/nns/secret_key.pem");
    let sig_keys =
        SigKeys::from_pem(&contents).expect("Failed to parse rs/tests/nns/secret_key.pem");
    let proposal_sender = Sender::SigKeys(sig_keys);
    bless_replica_version(
        env.clone(),
        neuron_id,
        proposal_sender,
        nns_node.clone(),
        "1111111111111111111111111111111111111111".to_string(),
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
        recovered_nns_node_url.clone(),
        neuron_id,
    );
}

/// Write a shell script containing some environment variable exports.
/// This script can be sourced such that we can easily use the legacy
/// nns-tools shell scripts in /testnet/tools/nns-tools/ with the dynamic
/// testnet deployed by this system-test.
fn write_sh_lib(env: TestEnv, neuron_id: NeuronId, nns_node: IcNodeSnapshot) {
    let logger: slog::Logger = env.clone().logger();
    let set_testnet_env_vars_sh_path = env.get_path(SET_TESTNET_ENV_VARS_SH);
    let set_testnet_env_vars_sh_str = set_testnet_env_vars_sh_path.display();
    let ic_admin =
        fs::canonicalize(env.get_dependency_path("rs/tests/recovery/binaries/ic-admin")).unwrap();
    let sns_cli = fs::canonicalize(env.get_dependency_path("rs/sns/cli/sns")).unwrap();
    let pem = fs::canonicalize(env.get_dependency_path("rs/tests/nns/secret_key.pem")).unwrap();
    let recovered_nns_node_url = nns_node.get_public_url();
    let neuron_id_number = neuron_id.0;
    fs::write(
        set_testnet_env_vars_sh_path.clone(),
        format!(
            "export IC_ADMIN={ic_admin:?}; \
             export SNS_CLI={sns_cli:?}; \
             export PEM={pem:?}; \
             export NNS_URL=\"{recovered_nns_node_url}\"; \
             export NEURON_ID={neuron_id_number:?};"
        ),
    )
    .unwrap_or_else(|e| {
        panic!(
            "Writing {set_testnet_env_vars_sh_str} failed because: {}",
            e
        )
    });
    let canonical_sh_lib_path = fs::canonicalize(set_testnet_env_vars_sh_path.clone()).unwrap();
    info!(logger, "source {canonical_sh_lib_path:?}");
}

fn bless_replica_version(
    env: TestEnv,
    neuron_id: NeuronId,
    proposal_sender: Sender,
    nns_node: IcNodeSnapshot,
    replica_version: String,
) {
    info!(
        env.logger(),
        "Begin Bless replica version {}", replica_version
    );

    let logger = env.logger();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns_runtime);
    let sha256 = env.get_ic_os_update_img_sha256().unwrap();
    let upgrade_url = env.get_ic_os_update_img_url().unwrap();

    let proposal_id = {
        let logger = logger.clone();
        let replica_version = replica_version.clone();
        block_on(async move {
            let proposal_id = submit_update_elected_replica_versions_proposal(
                &governance_canister,
                proposal_sender,
                neuron_id,
                ReplicaVersion::try_from(replica_version.clone()).unwrap(),
                sha256,
                vec![upgrade_url.to_string()],
                vec![],
            )
            .await;
            info!(
                logger,
                "Proposal {:?} to bless replica version {:?} has been submitted",
                proposal_id.to_string(),
                replica_version,
            );
            vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
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
