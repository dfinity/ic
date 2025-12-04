// TODO: update docs
// The `nested` testnet is meant to interactively test the HostOS. In particular to test NNS subnet recovery by interacting with the host grub menu during boot.
//
// The testnet will consist of a single system subnet with a single node running the NNS.
//
// Then SUBNET_SIZE VMs are deployed and started booting SetupOS which will install HostOS to their virtual disks
// and eventually boot the GuestOS in a VM nested inside the host VM.
// These GuestOSes will then register with the NNS as unassigned nodes.
// Finally, a proposal will be made to assign them to the NNS subnet while removing the original node.
//
// The driver will print how to reboot the host-1 VM and how to get to its console such that you can interact with its grub:
//
// ```
// $ ict testnet create nns_recovery_external_mainnet_state --lifetime-mins 10 --verbose --set-required-host-features=dc=zh1 -- --test_env=DKG_INTERVAL=499 --test_tmpdir=./nns_recovery_testnet
// ...
// 2025-09-02 18:35:22.985 INFO[log_instructions:rs/tests/testnets/nested.rs:16:0] To reboot the host VM run the following command:
// 2025-09-02 18:35:22.985 INFO[log_instructions:rs/tests/testnets/nested.rs:17:0] curl -X PUT 'https://farm.dfinity.systems/group/nested--1756837630333/vm/host-1/reboot'
// ...
//     {
//       "url": "https://farm.dfinity.systems/group/nested--1756837630333/vm/host-1/console/",
//       "vm_name": "host-1"
//     }
// ```
//
// The testnet is deployed to zh1 through `--set-required-host-features=dc=zh1` to efficiently recover the latest mainnet NNS subnet backup (since this is the DC where the backup pod is located)
// Note that the NNS backup is over 15GB so it will require around 3 minutes to download, 15 minutes to unpack and 59G of disk space.
//
// To get access to P8s and Grafana look for the following lines in the ict console output:
//
//     prometheus: Prometheus Web UI at http://prometheus.nns-recovery--1758812276301.testnet.farm.dfinity.systems,
//     grafana: Grafana at http://grafana.nns-recovery--1758812276301.testnet.farm.dfinity.systems,
//     progress_clock: IC Progress Clock at http://grafana.nns-recovery--1758812276301.testnet.farm.dfinity.systems/d/ic-progress-clock/ic-progress-clock?refresh=10s&from=now-5m&to=now,
//
// Happy testing!

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
use slog::info;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Cursor;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::{io::Write, process::Command, time::Duration};
use url::Url;

// TODO: move this to an environment variable and set this on the CLI using --test_env=NNS_BACKUP_POD=zh1-pyr07.zh1.dfinity.network
const NNS_BACKUP_POD: &str = "zh1-pyr07.zh1.dfinity.network";
const NNS_BACKUP_POD_USER: &str = "dev";
// const BOUNDARY_NODE_NAME: &str = "boundary-node-1";
const AUX_NODE_NAME: &str = "aux";
const RECOVERY_WORKING_DIR: &str = "recovery/working_dir";
const IC_CONFIG_DESTINATION: &str = "recovery/working_dir/ic.json5";
const NNS_STATE_DIR_PATH: &str = "recovery/working_dir/data";
const NNS_STATE_BACKUP_TARBALL_PATH: &str = "nns_state.tar.zst";
const IC_REPLAY: &str = "ic-replay";
const IC_RECOVERY: &str = "ic-recovery";

const CONTROLLER: &str = "bc7vk-kulc6-vswcu-ysxhv-lsrxo-vkszu-zxku3-xhzmh-iac7m-lwewm-2ae";
const ORIGINAL_NNS_ID: &str = "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe";
const IC_CONFIG_SRC_PATH: &str = "/run/ic-node/config/ic.json5";
const SET_TESTNET_ENV_VARS_SH: &str = "set_testnet_env_variables.sh";
// const RECOVERED_NNS: &str = "recovered-nns";
// const MAINNET_GOVERNANCE_CANISTER_ID: &str = "rrkah-fqaaa-aaaaa-aaaaq-cai";
// const MAINNET_SNS_WASM_CANISTER_ID: &str = "qaa6y-5yaaa-aaaaa-aaafa-cai";
const MAINNET_NNS_DAPP_CANISTER_ID: &str = "qoctq-giaaa-aaaaa-aaaea-cai";

const SECRET_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MFMCAQEwBQYDK2VwBCIEIKohpVANxO4xElQYXElAOXZHwJSVHERLE8feXSfoKwxX
oSMDIQBqgs2z86b+S5X9HvsxtE46UZwfDHtebwmSQWSIcKr2ew==
-----END PRIVATE KEY-----";

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
fn setup(env: TestEnv) {
    // Fetch and unpack the NNS mainnet state backup concurrently with setting up the IC.
    // ic-replay also requires the ic.json5 config file of an NNS node.
    // Since we're creating the IC concurrently with fetching the state we use a channel to communicate
    // the new TestEnv to the thread fetching the backup such that the latter thread can later scp
    // the ic.json5 config file from the NNS node when it's online, as well as create an HTTP
    // gateway corresponding to the new topology.
    let (tx_env, rx_env): (std::sync::mpsc::Sender<TestEnv>, Receiver<TestEnv>) = mpsc::channel();
    let (tx_aux_node, rx_aux_node): (
        std::sync::mpsc::Sender<DeployedUniversalVm>,
        Receiver<DeployedUniversalVm>,
    ) = mpsc::channel();

    // Recover the NNS concurrently:
    let env_clone = env.clone();
    let nns_state_thread = std::thread::spawn(move || {
        setup_recovered_nns(env_clone, rx_env, rx_aux_node);
    });

    // Start a p8s VM concurrently:
    let env_clone = env.clone();
    let prometheus_thread = std::thread::spawn(move || {
        // TODO: this panics on determining ipv4 address
        // but not having it just doesn't work
        PrometheusVm::default()
            .disable_ipv4()
            .start(&env_clone)
            .expect("failed to start prometheus VM");
    });

    // Setup and start the aux UVM concurrently:
    let env_clone = env.clone();
    let uvm_thread = std::thread::spawn(move || {
        UniversalVm::new(AUX_NODE_NAME.to_string())
            .start(&env_clone)
            .expect("Failed to start Universal VM");
    });

    let env_clone = env.clone();
    setup_ic(env_clone);

    let env_clone = env.clone();
    std::thread::spawn(move || {
        // Send the TestEnv to the thread fetching the nns state (nns_state_thread)
        // such that it can scp the ic.json5 config file required by ic-replay, as well as create an
        // HTTP gateway corresponding to the new topology.
        tx_env.send(env_clone.clone()).unwrap();

        uvm_thread.join().unwrap();
        let deployed_universal_vm = env_clone.get_deployed_universal_vm(AUX_NODE_NAME).unwrap();
        tx_aux_node.send(deployed_universal_vm).unwrap();
    });

    nns_state_thread
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e));

    prometheus_thread.join().unwrap();

    env.ssh_keygen_for_user(BACKUP_USERNAME)
        .unwrap_or_else(|_| panic!("ssh-keygen failed for {BACKUP_USERNAME} key"));
    env.sync_with_prometheus();
}

fn setup_recovered_nns(
    env: TestEnv,
    rx_env: Receiver<TestEnv>,
    rx_aux_node: Receiver<DeployedUniversalVm>,
) {
    let env_clone = env.clone();
    let fetch_mainnet_ic_replay_thread = std::thread::spawn(move || {
        fetch_mainnet_ic_replay(env_clone);
    });
    let env_clone = env.clone();
    let fetch_mainnet_ic_recovery_thread = std::thread::spawn(move || {
        fetch_mainnet_ic_recovery(env_clone);
    });
    fetch_nns_state_from_backup_pod(env.clone());

    // TODO: no need to pass the env, just pass a flag signaling that the other thread has finished
    let env = rx_env.recv().unwrap();
    let topology = env.topology_snapshot();
    let nns_node = topology.root_subnet().nodes().next().unwrap();
    let recovered_nns_node = topology.unassigned_nodes().next().unwrap();
    fetch_ic_config(env.clone(), nns_node.clone());

    // The following ensures ic-replay and ic-recovery know where to get their required dependencies.
    let recovery_dir = get_dependency_path("rs/tests");
    set_sandbox_env_vars(recovery_dir.join("recovery/binaries"));

    fetch_mainnet_ic_replay_thread
        .join()
        .unwrap_or_else(|e| panic!("Failed to fetch the mainnet ic-replay because {e:?}"));

    let neuron_id: NeuronId = prepare_nns_state(env.clone());

    let aux_node = rx_aux_node.recv().unwrap();

    fetch_mainnet_ic_recovery_thread
        .join()
        .unwrap_or_else(|e| panic!("Failed to fetch the mainnet ic-recovery because {e:?}"));

    recover_nns_subnet(env.clone(), nns_node, recovered_nns_node.clone(), aux_node);
    test_recovered_nns(env.clone(), neuron_id, recovered_nns_node.clone());

    let local_store_path = env
        .get_path(RECOVERY_WORKING_DIR)
        .join("data")
        .join("ic_registry_local_store");
    let local_store = Arc::new(LocalStoreImpl::new(local_store_path));
    let registry_client = RegistryClientImpl::new(local_store.clone(), None);
    registry_client.poll_once().unwrap();
    let recovered_nns_pub_key = registry_client
        .get_threshold_signing_public_key_for_subnet(
            SubnetId::from(PrincipalId::from_str(ORIGINAL_NNS_ID).unwrap()),
            registry_client.get_latest_version(),
        )
        .unwrap()
        .expect("Recovered NNS subnet public key not found in registry!");
    let der_encoded = threshold_sig_public_key_to_der(recovered_nns_pub_key).unwrap();

    let mut pem = vec![];
    pem.extend_from_slice(b"-----BEGIN PUBLIC KEY-----\n");
    for chunk in base64::encode(der_encoded).as_bytes().chunks(64) {
        pem.extend_from_slice(chunk);
        pem.extend_from_slice(b"\n");
    }
    pem.extend_from_slice(b"-----END PUBLIC KEY-----\n");

    std::fs::write(
        env.prep_dir("").map(|v| v.root_public_key_path()).unwrap(),
        pem,
    )
    .unwrap();

    // propose_to_add_new_node_operator(
    //     env.clone(),
    //     neuron_id,
    //     Sender::SigKeys(SigKeys::from_pem(SECRET_KEY_PEM).expect("Failed to parse secret key")),
    //     recovered_nns_node.clone(),
    //     NODE_OPERATOR_PRINCIPAL,
    // );

    let api_bn = env.topology_snapshot().api_boundary_nodes().next().unwrap();
    setup_api_bn(env.clone(), recovered_nns_node.clone(), api_bn.clone());

    propose_to_turn_into_api_bn(
        env.clone(),
        neuron_id,
        Sender::SigKeys(SigKeys::from_pem(SECRET_KEY_PEM).expect("Failed to parse secret key")),
        recovered_nns_node.clone(),
        api_bn.node_id,
    );

    IcGatewayVm::new(IC_GATEWAY_VM_NAME)
        .start(&env)
        .expect("failed to setup ic-gateway");
    let http_gateway_url = env
        .get_deployed_ic_gateway(IC_GATEWAY_VM_NAME)
        .unwrap()
        .get_public_url();

    info!(
        env.logger(),
        "NNS Dapp: https://{MAINNET_NNS_DAPP_CANISTER_ID}.{domain}",
        domain = http_gateway_url.host_str().unwrap()
    );

    write_sh_lib(env.clone(), neuron_id, http_gateway_url);
}

fn setup_ic(env: TestEnv) {
    let principal = PrincipalId::from_str(NODE_OPERATOR_PRINCIPAL).unwrap();

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
        .with_node_provider(principal)
        .with_node_operator(principal)
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

fn setup_api_bn(env: TestEnv, recovered_nns_node: IcNodeSnapshot, api_bn: IcNodeSnapshot) {
    let logger = env.logger();
    let recovered_nns_node_ipv6 = recovered_nns_node.get_ip_addr();

    let ssh_session = api_bn.block_on_ssh_session().unwrap();
    // Reset local store to let it re-initialize it
    api_bn
        .block_on_bash_script_from_session(
            &ssh_session,
            r#"
                mkdir -p /tmp/empty_dir
                #sudo chown ic-replica:ic-registry-local-store /tmp/empty_dir
                #sudo chmod u=rwX,g=rX,o= /tmp/empty_dir
                #sudo chmod g+s /tmp/empty_dir
                sudo chown --reference=/var/lib/ic/data/ic_registry_local_store /tmp/empty_dir
                sudo chmod --reference=/var/lib/ic/data/ic_registry_local_store /tmp/empty_dir
                sudo mount --bind /tmp/empty_dir /var/lib/ic/data/ic_registry_local_store
            "#,
        )
        .unwrap_or_else(|e| {
            panic!(
                "Could not mount empty dir over local store path on {} because {e:?}",
                api_bn.node_id
            );
        });
    // Change NNS URL
    api_bn.block_on_bash_script_from_session(&ssh_session, &format!(r#"
        set -e
        #cp /opt/ic/share/ic-boundary.env /tmp/
        #echo 'REGISTRY_NNS_URLS="https://[TODO]:8080"' | tee -a /tmp/ic-boundary.env
        #sudo mount --bind /tmp/ic-boundary.env /opt/ic/share/ic-boundary.env
        #cp /run/ic-node/config/ic.json5 /tmp/
        #sed -i 's|^\(\s*nns_url:\s*\).*|\1"http://[TODO]:8080",|' /tmp/ic.json5
        #sudo mount --bind /tmp/ic.json5 /run/ic-node/config/ic.json5

        jq '.icos_settings.nns_urls = ["http://[{}]:8080/"]' /run/config/config.json > /tmp/config.json
        sudo chown --reference=/run/config/config.json /tmp/config.json
        sudo chmod --reference=/run/config/config.json /tmp/config.json
        sudo mount --bind /tmp/config.json /run/config/config.json
    "#, recovered_nns_node_ipv6)).unwrap_or_else(|e| {
        panic!("Could not reconfigure ic-boundary on {} to route to the recovered NNS because {e:?}", api_bn.node_id);
    });
    // Copy new NNS public key
    scp_send_to(
        logger.clone(),
        &ssh_session,
        &env.prep_dir("").map(|v| v.root_public_key_path()).unwrap(),
        &PathBuf::from("/tmp/recovered_nns_public_key.pem"),
        0o644,
    );
    api_bn.block_on_bash_script_from_session(
            &ssh_session,
            r#"
                sudo chown --reference=/run/config/nns_public_key.pem /tmp/recovered_nns_public_key.pem
                sudo chmod --reference=/run/config/nns_public_key.pem /tmp/recovered_nns_public_key.pem
                sudo mount --bind /tmp/recovered_nns_public_key.pem /run/config/nns_public_key.pem
            "#,
            // TODO: line below should actually work
            // "sudo mount --bind /tmp/recovered_nns_public_key.pem /opt/ic/share/nns_public_key.pem",
        )
        .unwrap_or_else(|e| {
            panic!(
                "Could not bind recovered NNS public key on {} because {e:?}",
                api_bn.node_id
            );
        });
    // Copy operator private key
    fs::write(
        env.get_path("node_operator_private_key.pem"),
        NODE_OPERATOR_PRIVATE_KEY_PEM,
    )
    .unwrap();
    scp_send_to(
        logger.clone(),
        &ssh_session,
        &env.get_path("node_operator_private_key.pem"),
        &PathBuf::from("/tmp/node_operator_private_key.pem"),
        0o644,
    );
    api_bn
        .block_on_bash_script_from_session(
            &ssh_session,
            r#"
                sudo chmod 644 /tmp/node_operator_private_key.pem
                sudo cp /tmp/node_operator_private_key.pem /var/lib/ic/data/node_operator_private_key.pem
            "#,
        )
        .unwrap_or_else(|e| {
            panic!(
                "Could not bind node operator private key on {} because {e:?}",
                api_bn.node_id
            );
        });
    // Restart orchestrator
    api_bn.block_on_bash_script_from_session(&ssh_session, "sudo systemctl restart ic-replica").unwrap_or_else(|e| {
        panic!("Could not reconfigure ic-boundary on {} to only route to the recovered NNS because {e:?}", api_bn.node_id);
    });

    info!(
        logger,
        "Waiting 30s for the API BN to restart ic-replica ..."
    );
    std::thread::sleep(Duration::from_secs(30));
}

fn propose_to_add_new_node_operator(
    env: TestEnv,
    neuron_id: NeuronId,
    proposal_sender: Sender,
    nns_node: IcNodeSnapshot,
    node_operator_principal: &str,
) {
    info!(
        env.logger(),
        "Submitting proposal to add new node provider {}...", node_operator_principal
    );

    let logger = env.logger();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns_runtime);

    let proposal_id = {
        let logger = logger.clone();
        let proposal_sender = proposal_sender.clone();
        block_on(async move {
            let proposal = MakeProposalRequest {
                title: Some(format!("Add node provider {}", node_operator_principal)),
                summary: format!("Add node provider {}", node_operator_principal),
                url: "".to_string(),
                action: Some(ProposalActionRequest::AddOrRemoveNodeProvider(
                    AddOrRemoveNodeProvider {
                        change: Some(Change::ToAdd(NodeProvider {
                            id: Some(PrincipalId::from_str(node_operator_principal).unwrap()),
                            reward_account: None,
                        })),
                    },
                )),
            };

            let response: ManageNeuronResponse = governance_canister
                .update_from_sender(
                    "manage_neuron",
                    candid_one,
                    ManageNeuronRequest {
                        id: None,
                        command: Some(ManageNeuronCommandRequest::MakeProposal(Box::new(proposal))),
                        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                            neuron_id.clone().into(),
                        )),
                    },
                    &proposal_sender,
                )
                .await
                .expect("Error calling the manage_neuron api.");
            let proposal_id = match response.command.unwrap() {
                CommandResponse::MakeProposal(resp) => ProposalId::from(resp.proposal_id.unwrap()),
                CommandResponse::Error(err) => panic!("Governance returned an error: {:?}", err),
                other => panic!("Unexpected response: {other:?}"),
            };

            info!(
                logger,
                "Proposal {:?} to add new node provider {} has been submitted",
                proposal_id.to_string(),
                node_operator_principal
            );

            vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
            proposal_id
        })
    };

    info!(
        logger,
        "Proposal {:?} to add new node provider {} has been executed",
        proposal_id,
        node_operator_principal
    );

    info!(
        env.logger(),
        "Submitting proposal to add new node operator {}...", node_operator_principal
    );

    let logger = env.logger();
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance_canister = get_governance_canister(&nns_runtime);

    let proposal_id = {
        let logger = logger.clone();
        block_on(async move {
            let proposal_id = submit_external_update_proposal_allowing_error(
                &governance_canister,
                proposal_sender.clone(),
                neuron_id,
                NnsFunction::AssignNoid,
                AddNodeOperatorPayload {
                    node_operator_principal_id: Some(
                        PrincipalId::from_str(node_operator_principal).unwrap(),
                    ),
                    node_allowance: 40,
                    node_provider_principal_id: Some(
                        PrincipalId::from_str(node_operator_principal).unwrap(),
                    ),
                    dc_id: "".to_string(),
                    rewardable_nodes: BTreeMap::new(),
                    ipv6: None,
                    max_rewardable_nodes: Some(BTreeMap::new()),
                },
                format!("Adding node operator {}", node_operator_principal),
                "".to_string(),
            )
            .await
            .expect("Failed to submit proposal to add new node operator");

            info!(
                logger,
                "Proposal {:?} to add new node operator {} has been submitted",
                proposal_id.to_string(),
                node_operator_principal
            );

            vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
            proposal_id
        })
    };

    info!(
        logger,
        "Proposal {:?} to add new node operator {} has been executed",
        proposal_id,
        node_operator_principal
    );
}

fn propose_to_turn_into_api_bn(
    env: TestEnv,
    neuron_id: NeuronId,
    proposal_sender: Sender,
    nns_node: IcNodeSnapshot,
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
                proposal_sender.clone(),
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

            vote_execute_proposal_assert_executed(&governance_canister, proposal_id).await;
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

fn fetch_nns_state_from_backup_pod(env: TestEnv) {
    let target = format!(
        "{NNS_BACKUP_POD_USER}@{NNS_BACKUP_POD}:/home/{NNS_BACKUP_POD_USER}/{NNS_STATE_BACKUP_TARBALL_PATH}"
    );
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
    let mut cmd = Command::new("scp");
    cmd.arg("-oUserKnownHostsFile=/dev/null")
        .arg("-oStrictHostKeyChecking=no")
        .arg(target.clone())
        .arg(nns_state_backup_path.clone());
    info!(env.logger(), "{cmd:?} ...");
    let scp_out = cmd.output().unwrap_or_else(|e| {
        panic!(
            "Could not scp the {NNS_STATE_BACKUP_TARBALL_PATH} from the backup pod because: {e:?}!",
        )
    });
    if !scp_out.status.success() {
        std::io::stdout().write_all(&scp_out.stdout).unwrap();
        std::io::stderr().write_all(&scp_out.stderr).unwrap();
        panic!("Could not scp the {NNS_STATE_BACKUP_TARBALL_PATH} from the backup pod!");
    }
    info!(
        logger,
        "Downloaded {target:} to {:?}, unpacking ...", nns_state_backup_path
    );
    let mut cmd = Command::new("tar");
    cmd.arg("xf")
        .arg(nns_state_backup_path.clone())
        .arg("-C")
        .arg(env.base_path())
        .arg(format!("--transform=s|nns_state/|{NNS_STATE_DIR_PATH}/|"));
    info!(env.logger(), "{cmd:?} ...");
    let tar_out = cmd
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

fn ic_replay(env: TestEnv, mut mutate_cmd: impl FnMut(&mut Command)) -> Output {
    let logger: slog::Logger = env.logger();
    let ic_replay_path = env.get_path(IC_REPLAY);
    let subnet_id = SubnetId::from(PrincipalId::from_str(ORIGINAL_NNS_ID).unwrap());
    let nns_state_dir = env.get_path(NNS_STATE_DIR_PATH);
    let ic_config_file = env.get_path(IC_CONFIG_DESTINATION);

    let mut cmd = Command::new(ic_replay_path);
    cmd.arg("--subnet-id")
        .arg(subnet_id.to_string())
        .arg("--data-root")
        .arg(nns_state_dir.clone())
        .arg(ic_config_file.clone());
    mutate_cmd(&mut cmd);
    info!(logger, "{cmd:?} ...");
    let ic_replay_out = cmd.output().expect(&format!("Failed to run {cmd:?}"));
    std::io::stdout().write_all(&ic_replay_out.stdout).unwrap();
    std::io::stderr().write_all(&ic_replay_out.stderr).unwrap();
    if !ic_replay_out.status.success() {
        // std::io::stdout().write_all(&ic_replay_out.stdout).unwrap();
        // std::io::stderr().write_all(&ic_replay_out.stderr).unwrap();
        panic!("Failed to run {cmd:?}!");
    }
    ic_replay_out
}

fn with_neuron_for_tests(env: TestEnv) -> NeuronId {
    let logger: slog::Logger = env.logger();
    let controller = PrincipalId::from_str(CONTROLLER).unwrap();

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

fn with_trusted_neurons_following_neuron_for_tests(env: TestEnv, neuron_id: NeuronId) {
    let NeuronId(id) = neuron_id;
    let controller = PrincipalId::from_str(CONTROLLER).unwrap();
    ic_replay(env, |cmd| {
        cmd.arg("with-trusted-neurons-following-neuron-for-tests")
            .arg(id.to_string())
            .arg(controller.to_string());
    });
}

fn fetch_mainnet_ic_replay(env: TestEnv) {
    std::fs::copy(
        get_dependency_path(std::env::var("IC_REPLAY_PATH").unwrap()),
        env.get_path(IC_REPLAY),
    )
    .unwrap();

    // TODO: uncomment me
    // let logger = env.logger();
    // let version = get_mainnet_nns_revision().unwrap();
    // let mainnet_ic_replica_url =
    //     format!("https://download.dfinity.systems/ic/{version}/release/ic-replay.gz");
    // let ic_replay_path = env.get_path(IC_REPLAY);
    // let ic_replay_gz_path = env.get_path("ic-replay.gz");
    // // let mut tmp_file = tempfile::tempfile().unwrap();
    // info!(
    //     logger,
    //     "Downloading {mainnet_ic_replica_url:?} to {ic_replay_gz_path:?} ..."
    // );
    // let response = reqwest::blocking::get(mainnet_ic_replica_url.clone())
    //     .unwrap_or_else(|e| panic!("Failed to download {mainnet_ic_replica_url:?} because {e:?}"));
    // if !response.status().is_success() {
    //     panic!("Failed to download {mainnet_ic_replica_url}");
    // }
    // let bytes = response.bytes().unwrap();
    // let mut content = Cursor::new(bytes);
    // let mut ic_replay_gz_file = File::create(ic_replay_gz_path.clone()).unwrap();
    // std::io::copy(&mut content, &mut ic_replay_gz_file).unwrap_or_else(|e| {
    //     panic!("Can't copy {mainnet_ic_replica_url} to {ic_replay_gz_path:?} because {e:?}")
    // });
    // info!(
    //     logger,
    //     "Downloaded {mainnet_ic_replica_url:?} to {ic_replay_gz_path:?}. Uncompressing to {ic_replay_path:?} ..."
    // );
    // let ic_replay_gz_file = File::open(ic_replay_gz_path.clone()).unwrap();
    // let mut gz = GzDecoder::new(&ic_replay_gz_file);
    // let mut ic_replay_file = OpenOptions::new()
    //     .create(true)
    //     .truncate(false)
    //     .write(true)
    //     .mode(0o755)
    //     .open(ic_replay_path.clone())
    //     .unwrap();
    // std::io::copy(&mut gz, &mut ic_replay_file).unwrap_or_else(|e| {
    //     panic!("Can't uncompress {ic_replay_gz_path:?} to {ic_replay_path:?} because {e:?}")
    // });
    // info!(
    //     logger,
    //     "Uncompressed {ic_replay_gz_path:?} to {ic_replay_path:?}"
    // );
}

fn prepare_nns_state(env: TestEnv) -> NeuronId {
    let neuron_id = with_neuron_for_tests(env.clone());
    with_trusted_neurons_following_neuron_for_tests(env.clone(), neuron_id);
    neuron_id
}

fn fetch_mainnet_ic_recovery(env: TestEnv) {
    let logger = env.logger();
    let version = get_mainnet_nns_revision().unwrap();
    let mainnet_ic_recovery_url =
        format!("https://download.dfinity.systems/ic/{version}/release/ic-recovery.gz");
    let ic_recovery_path = env.get_path(IC_RECOVERY);
    let ic_recovery_gz_path = env.get_path("ic-recovery.gz");
    info!(
        logger,
        "Downloading {mainnet_ic_recovery_url:?} to {ic_recovery_gz_path:?} ..."
    );
    let response = reqwest::blocking::get(mainnet_ic_recovery_url.clone())
        .unwrap_or_else(|e| panic!("Failed to download {mainnet_ic_recovery_url:?} because {e:?}"));
    if !response.status().is_success() {
        panic!("Failed to download {mainnet_ic_recovery_url}");
    }
    let bytes = response.bytes().unwrap();
    let mut content = Cursor::new(bytes);
    let mut ic_recovery_gz_file = File::create(ic_recovery_gz_path.clone()).unwrap();
    std::io::copy(&mut content, &mut ic_recovery_gz_file).unwrap_or_else(|e| {
        panic!("Can't copy {mainnet_ic_recovery_url} to {ic_recovery_gz_path:?} because {e:?}")
    });
    info!(
        logger,
        "Downloaded {mainnet_ic_recovery_url:?} to {ic_recovery_gz_path:?}. Uncompressing to {ic_recovery_path:?} ..."
    );
    let ic_recovery_gz_file = File::open(ic_recovery_gz_path.clone()).unwrap();
    let mut gz = GzDecoder::new(&ic_recovery_gz_file);
    let mut ic_recovery_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o755)
        .open(ic_recovery_path.clone())
        .unwrap();
    std::io::copy(&mut gz, &mut ic_recovery_file).unwrap_or_else(|e| {
        panic!("Can't uncompress {ic_recovery_gz_path:?} to {ic_recovery_path:?} because {e:?}")
    });
    info!(
        logger,
        "Uncompressed {ic_recovery_gz_path:?} to {ic_recovery_path:?}"
    );
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

    let ic_recovery_path = env.get_path(IC_RECOVERY);
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

fn test_recovered_nns(env: TestEnv, neuron_id: NeuronId, nns_node: IcNodeSnapshot) {
    let logger: slog::Logger = env.clone().logger();
    info!(logger, "Testing recovered NNS ...");
    let sig_keys = SigKeys::from_pem(SECRET_KEY_PEM).expect("Failed to parse secret key");
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
fn write_sh_lib(env: TestEnv, neuron_id: NeuronId, http_gateway: Url) {
    let logger: slog::Logger = env.clone().logger();
    let set_testnet_env_vars_sh_path = env.get_path(SET_TESTNET_ENV_VARS_SH);
    let set_testnet_env_vars_sh_str = set_testnet_env_vars_sh_path.display();
    let ic_admin =
        fs::canonicalize(get_dependency_path("rs/tests/recovery/binaries/ic-admin")).unwrap();
    let pem = env.get_path("neuron_secret_key.pem");
    let mut pem_file = File::create(&pem).unwrap();
    pem_file.write_all(SECRET_KEY_PEM.as_bytes()).unwrap();
    let neuron_id_number = neuron_id.0;
    fs::write(
        set_testnet_env_vars_sh_path.clone(),
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
    let sha256 = get_guestos_update_img_sha256();
    let upgrade_url = get_guestos_update_img_url();
    let guest_launch_measurements = get_guestos_launch_measurements();

    let proposal_id = {
        let logger = logger.clone();
        let replica_version = replica_version.clone();
        block_on(async move {
            let proposal_id = submit_update_elected_replica_versions_proposal(
                &governance_canister,
                proposal_sender.clone(),
                neuron_id,
                Some(&ReplicaVersion::try_from(replica_version.clone()).unwrap()),
                Some(sha256),
                vec![upgrade_url.to_string()],
                Some(guest_launch_measurements),
                vec![],
            )
            .await;
            info!(
                logger,
                "Proposal {:?} to bless replica version {:?} has been submitted",
                proposal_id.to_string(),
                replica_version,
            );

            let input = ManageNeuronRequest {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    ic_nns_common::pb::v1::NeuronId { id: neuron_id.0 },
                )),
                id: None,
                command: Some(ManageNeuronCommandRequest::RegisterVote(RegisterVote {
                    vote: Vote::Yes as i32,
                    proposal: Some(ic_nns_common::pb::v1::ProposalId { id: proposal_id.0 }),
                })),
            };
            let result: ManageNeuronResponse = governance_canister
                .update_from_sender("manage_neuron", candid_one, input, &proposal_sender)
                .await
                .expect("Vote failed");

            println!("Big neuron vote result: {:?}", result);

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

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_timeout_per_test(Duration::from_secs(90 * 60))
        .with_setup(setup)
        .execute_from_args()?;
    Ok(())
}
