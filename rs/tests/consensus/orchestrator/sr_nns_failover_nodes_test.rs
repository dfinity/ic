/* tag::catalog[]

Title:: Subnet Recovery Test (NNS subnet, with failover nodes)

Goal::

Runbook::
. Start IC with NNS of at least 3 nodes and then break the NNS subnet.
. Start a second IC with a NNS and number of unsassigned nodes equal to the NNS from the old IC.
. Stop the replica from the original NNS and download its state.
. Propose to the new NNS to create a subnet from the unassigned nodes with same ID as the original NNS.
. Wait until the proposed subnet is up and download the parent NNS store.
. Replay the registry content, validate it and update the local store.
. Tar the registry local store and host it for download.
. Propose a CUP and wait until it gets accepted.
. Upload the old NNS state to the child NNS.
. Observe that NNS subnet restarts and continues functioning.

Success::
. NNS subnet is functional after the recovery.

end::catalog[] */

use anyhow::Result;
use canister_http::get_universal_vm_address;
use ic_agent::Agent;
use ic_consensus_system_test_utils::{
    rw_message::{
        can_read_msg, cannot_store_msg, cert_state_makes_progress_with_retries,
        install_nns_and_check_progress, store_message,
    },
    set_sandbox_env_vars,
};
use ic_recovery::nns_recovery_failover_nodes::{
    NNSRecoveryFailoverNodes, NNSRecoveryFailoverNodesArgs, StepType,
};
use ic_recovery::{get_node_metrics, RecoveryArgs};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::constants::SSH_USERNAME;
use ic_system_test_driver::driver::driver_setup::SSH_AUTHORIZED_PRIV_KEYS_DIR;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::universal_vm::{
    insert_file_to_config, UniversalVm, UniversalVms,
};
use ic_system_test_driver::driver::{test_env::TestEnv, test_env_api::*};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::{block_on, MessageCanister};
use ic_types::Height;
use slog::info;
use std::fs;
use url::Url;

const DKG_INTERVAL: u64 = 9;
const SUBNET_SIZE: usize = 3;
pub const UNIVERSAL_VM_NAME: &str = "httpbin";

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .with_name("broken")
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(SUBNET_SIZE),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    InternetComputer::new()
        .with_name("restore")
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(1),
        )
        .with_unassigned_nodes(SUBNET_SIZE)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot_by_name("broken"));
    install_nns_and_check_progress(env.topology_snapshot_by_name("restore"));
}

pub fn test(env: TestEnv) {
    let logger = env.logger();

    let topo_broken_ic = env.topology_snapshot_by_name("broken");
    let topo_restore_ic = env.topology_snapshot_by_name("restore");

    let ic_version = env.get_initial_replica_version().unwrap();
    info!(logger, "IC_VERSION_ID: {:?}", ic_version);

    let ssh_authorized_priv_keys_dir = env.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR);
    info!(
        logger,
        "ssh_authorized_priv_keys_dir: {:?}", ssh_authorized_priv_keys_dir
    );

    // choose a node from the nns subnet
    let mut orig_nns_nodes = topo_broken_ic.root_subnet().nodes();
    let nns_node = orig_nns_nodes.next().expect("there is no NNS node");

    info!(
        logger,
        "Selected NNS node: {} ({:?})",
        nns_node.node_id,
        nns_node.get_ip_addr()
    );

    let download_node = orig_nns_nodes.next().expect("there is no 2. NNS node");
    info!(
        logger,
        "Node for download: {} ({:?})",
        download_node.node_id,
        download_node.get_ip_addr()
    );

    let mut parent_nns_nodes = topo_restore_ic.root_subnet().nodes();
    let parent_nns_node = parent_nns_nodes.next().expect("No node in parent NNS");

    let upload_node = topo_restore_ic
        .unassigned_nodes()
        .next()
        .expect("there is no unsassigned node");
    info!(
        logger,
        "A node for upload: {} ({:?})",
        upload_node.node_id,
        upload_node.get_ip_addr()
    );
    let replacement_nodes = topo_restore_ic
        .unassigned_nodes()
        .map(|n| n.node_id)
        .collect::<Vec<_>>();

    for n in topo_broken_ic.root_subnet().nodes() {
        info!(logger, "Original NNS node: {}", n.get_ip_addr());
    }
    for n in topo_restore_ic.root_subnet().nodes() {
        info!(logger, "Parent NNS node: {}", n.get_ip_addr());
    }
    for n in topo_restore_ic.unassigned_nodes() {
        info!(logger, "Unassigned node: {}", n.get_ip_addr());
    }

    info!(logger, "Ensure NNS subnet is functional");
    let msg = "subnet recovery works!";
    let app_can_id = store_message(
        &download_node.get_public_url(),
        download_node.effective_canister_id(),
        msg,
        &logger,
    );
    assert!(can_read_msg(
        &logger,
        &download_node.get_public_url(),
        app_can_id,
        msg
    ));

    let recovery_dir = get_dependency_path("rs/tests");
    set_sandbox_env_vars(recovery_dir.join("recovery/binaries"));

    let recovery_args = RecoveryArgs {
        dir: recovery_dir,
        nns_url: parent_nns_node.get_public_url(),
        replica_version: Some(ic_version.clone()),
        key_file: Some(ssh_authorized_priv_keys_dir.join(SSH_USERNAME)),
        test_mode: true,
        skip_prompts: true,
    };
    let subnet_args = NNSRecoveryFailoverNodesArgs {
        subnet_id: topo_broken_ic.root_subnet_id(),
        replica_version: Some(ic_version),
        replay_until_height: None,
        aux_ip: None,
        aux_user: None,
        registry_url: None,
        validate_nns_url: nns_node.get_public_url(),
        download_node: Some(download_node.get_ip_addr()),
        upload_node: Some(upload_node.get_ip_addr()),
        parent_nns_host_ip: Some(parent_nns_node.get_ip_addr()),
        replacement_nodes: Some(replacement_nodes),
        next_step: None,
        skip: None,
    };

    let mut subnet_recovery = NNSRecoveryFailoverNodes::new(
        env.logger(),
        recovery_args,
        /*neuron_args=*/ None,
        subnet_args,
    );

    // let's take f+1 nodes and break them.
    let f = (SUBNET_SIZE - 1) / 3;
    info!(
        logger,
        "Breaking the NNS subnet by breaking the replica binary on f+1={} nodes",
        f + 1
    );

    let faulty_nodes = orig_nns_nodes.take(f + 1).collect::<Vec<_>>();
    for node in faulty_nodes {
        subnet_recovery
        .get_recovery_api()
        .execute_ssh_command(
            "admin",
            node.get_ip_addr(),
            "sudo mount --bind /bin/false /opt/ic/bin/replica && sudo systemctl restart ic-replica",
        )
        .expect("couldn't run ssh command");
    }

    info!(logger, "Ensure the subnet works in read mode");
    assert!(can_read_msg(
        &logger,
        &download_node.get_public_url(),
        app_can_id,
        msg
    ));
    info!(
        logger,
        "Ensure the subnet doesn't work in write mode anymore"
    );
    assert!(cannot_store_msg(
        logger.clone(),
        &download_node.get_public_url(),
        app_can_id,
        msg
    ));

    info!(logger, "Check if download node is behind...");
    let ot_node_metrics = block_on(get_node_metrics(&logger, &nns_node.get_ip_addr()))
        .expect("Missing metrics for upload node");
    let dn_node_metrics = block_on(get_node_metrics(&logger, &download_node.get_ip_addr()))
        .expect("Missing metrics for download node");
    if dn_node_metrics.finalization_height < ot_node_metrics.finalization_height {
        info!(logger, "Use the other node for download.");
        subnet_recovery.params.download_node = Some(nns_node.get_ip_addr());
        subnet_recovery.params.validate_nns_url = download_node.get_public_url();
    }

    info!(
        logger,
        "Starting recovery of the NNS subnet {}",
        topo_broken_ic.root_subnet().subnet_id.to_string()
    );

    // go over all steps of the NNS recovery
    while let Some((step_type, step)) = subnet_recovery.next() {
        info!(logger, "Next step: {:?}", step_type);
        info!(logger, "{}", step.descr());

        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {:?} failed: {}", step_type, e));

        if matches!(step_type, StepType::CreateRegistryTar) {
            // and also upload it...
            let tar = subnet_recovery.get_local_store_tar();
            let url_to_file = setup_file_server(&env, &tar);
            let url = Url::parse(&url_to_file).unwrap_or_else(|err| {
                panic!(
                    "Couldn't parse url {} to registry tar: {:?}",
                    url_to_file, err
                )
            });
            info!(logger, "URL: {}", url);
            subnet_recovery.params.registry_url = Some(url);
        }
    }
    info!(logger, "NNS recovery has finished");

    // check that the network functions
    upload_node.await_status_is_healthy().unwrap();

    info!(logger, "Wait for state sync to complete");
    cert_state_makes_progress_with_retries(
        &upload_node.get_public_url(),
        upload_node.effective_canister_id(),
        &logger,
        secs(600),
        secs(10),
    );

    info!(logger, "Ensure the old message is still readable");
    // To verify query response signatures from the root subnet, the agent requires the root subnet_id.
    // This is needed to retrieve the public keys of nodes within the root subnet.
    // Typically, the agent derives the root subnet_id from the root key.
    // However, in the restored root subnet, the root key is different from the original one, but the subnet_id is reused.
    // So we create a new agent that does not verify the query response signatures for the time being.
    // A long-term solution involves modifying the agent to fetch the root subnet_id from the HTTP status endpoint.
    let agent_bypass_signature = Agent::builder()
        .with_url(upload_node.get_public_url())
        .with_verify_query_signatures(false)
        .build()
        .expect("failed to create agent");
    let canister_msg = block_on(
        MessageCanister::from_canister_id(&agent_bypass_signature, app_can_id).try_read_msg(),
    )
    .expect("failed to read message")
    .expect("message should exist");
    assert_eq!(canister_msg, msg);

    let new_msg = "subnet recovery still works!";
    info!(
        logger,
        "Ensure that the subnet is accepting updates after the recovery"
    );
    let topo_restore_ic = block_on(topo_restore_ic.block_for_newer_registry_version())
        .expect("Could not obtain updated registry.");
    let upload_node = topo_restore_ic
        .subnets()
        .flat_map(|s| s.nodes())
        .find(|n| n.node_id == upload_node.node_id)
        .expect("Could not find upload_node in updated registry.");
    let new_app_can_id = store_message(
        &upload_node.get_public_url(),
        upload_node.effective_canister_id(),
        new_msg,
        &logger,
    );
    let canister_msg_new = block_on(
        MessageCanister::from_canister_id(&agent_bypass_signature, new_app_can_id).try_read_msg(),
    )
    .expect("failed to read message")
    .expect("message should exist");
    assert_eq!(canister_msg_new, new_msg);
}

fn setup_file_server(env: &TestEnv, file_path: &std::path::PathBuf) -> String {
    // Set up Universal VM with HTTP Bin testing service
    let activate_script = &read_dependency_to_string(
        "rs/tests/src/orchestrator/orchestrator_universal_vm_activation.sh",
    )
    .expect("File not found")[..];
    let config_dir = env
        .single_activate_script_config_dir(UNIVERSAL_VM_NAME, activate_script)
        .unwrap();

    let _ = insert_file_to_config(
        config_dir.clone(),
        "registry.tar",
        &fs::read(file_path).expect("File not found")[..],
    );

    let path = get_dependency_path("rs/tests/static-file-server.tar");
    let _ = insert_file_to_config(
        config_dir.clone(),
        "static-file-server.tar",
        &fs::read(path).expect("File not found")[..],
    );

    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .with_config_dir(config_dir)
        .start(env)
        .expect("failed to set up universal VM");
    let webserver_ipv6 = get_universal_vm_address(env);
    format!("http://[{webserver_ipv6}]/registry.tar")
}
