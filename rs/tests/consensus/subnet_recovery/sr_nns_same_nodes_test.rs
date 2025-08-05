/* tag::catalog[]

Title:: Subnet Recovery Test (NNS subnet, same nodes)

Goal::
Ensure that the subnet recovery of an NNS subnet without changing the node membership works.

Runbook::
. Start IC with NNS and then break the NNS subnet.
. Use ic-replay to update registry to include a new replica version, and produce a new CUP.
  Note: ic-replay is not used directly in this test; NNSRecoverySameNodes provides most of its functionality. See enum StepType for the list of steps
. Load the new CUP (together with registry local store and canister states) manually on all NNS nodes.
. Observe that NNS subnet restarts and continues functioning.

Success::
. NNS subnet is functional after the recovery.

end::catalog[] */

use anyhow::Result;
use ic_consensus_system_test_utils::{
    impersonate_upstreams::{setup_upstreams_uvm, uvm_serve_recovery_artifacts},
    rw_message::{
        can_read_msg, cannot_store_msg, cert_state_makes_progress_with_retries,
        install_nns_and_check_progress, store_message,
    },
    set_sandbox_env_vars,
    ssh_access::{
        get_updatesubnetpayload_with_keys, update_subnet_record,
        wait_until_authentication_is_granted, AuthMean,
    },
    upgrade::get_assigned_replica_version,
};
use ic_recovery::nns_recovery_same_nodes::{NNSRecoverySameNodes, NNSRecoverySameNodesArgs};
use ic_recovery::{get_node_metrics, util::DataLocation, RecoveryArgs};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::driver_setup::SSH_AUTHORIZED_PRIV_KEYS_DIR;
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::ic::{InternetComputer, Subnet};
use ic_system_test_driver::driver::{
    constants::SSH_USERNAME, driver_setup::SSH_AUTHORIZED_PUB_KEYS_DIR,
};
use ic_system_test_driver::driver::{test_env::TestEnv, test_env_api::*};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_types::{Height, ReplicaVersion};
use slog::info;
use std::{cmp, convert::TryFrom};

const DKG_INTERVAL: u64 = 9;
const SUBNET_SIZE: usize = 4;

pub fn setup(env: TestEnv) {
    setup_upstreams_uvm(&env);

    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(SUBNET_SIZE),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let topo_snapshot = env.topology_snapshot();

    // choose a node from the nns subnet
    let mut nns_nodes = topo_snapshot.root_subnet().nodes();
    let upload_node = nns_nodes.next().expect("there is no NNS node");

    info!(
        logger,
        "Selected NNS node, also for upload: {} ({:?})",
        upload_node.node_id,
        upload_node.get_ip_addr()
    );

    // get another one for the download node
    let download_node = nns_nodes.next().expect("there is no NNS node");
    info!(
        logger,
        "NNS node for download: {} ({:?})",
        download_node.node_id,
        download_node.get_ip_addr()
    );

    // add SSH key as backup key to the registry
    info!(logger, "Update the registry with the backup key");
    let ssh_priv_key_path = env
        .get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR)
        .join(SSH_USERNAME);
    let ssh_priv_key =
        std::fs::read_to_string(&ssh_priv_key_path).expect("Failed to read SSH private key");
    let ssh_pub_key_path = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR).join(SSH_USERNAME);
    let ssh_pub_key =
        std::fs::read_to_string(&ssh_pub_key_path).expect("Failed to read SSH public key");
    let payload = get_updatesubnetpayload_with_keys(
        topo_snapshot.root_subnet_id(),
        None,
        Some(vec![ssh_pub_key]),
    );
    block_on(update_subnet_record(upload_node.get_public_url(), payload));
    let backup_mean = AuthMean::PrivateKey(ssh_priv_key);
    wait_until_authentication_is_granted(&upload_node.get_ip_addr(), "backup", &backup_mean);

    let ic_version =
        get_assigned_replica_version(&upload_node).expect("Failed to get assigned replica version");
    let ic_version = ReplicaVersion::try_from(ic_version).unwrap();
    info!(logger, "IC_VERSION_ID: {:?}", &ic_version);

    // identifies the version of the replica after the recovery
    let working_version =
        ReplicaVersion::try_from(get_guestos_update_img_version().unwrap()).unwrap();
    info!(logger, "Ensure NNS subnet is functional");
    let msg = "subnet recovery works!";
    let app_can_id = store_message(
        &upload_node.get_public_url(),
        upload_node.effective_canister_id(),
        msg,
        &logger,
    );
    assert!(can_read_msg(
        &logger,
        &upload_node.get_public_url(),
        app_can_id,
        msg
    ));

    let recovery_dir = get_dependency_path("rs/tests");
    let output_dir = recovery_dir.join("output");
    set_sandbox_env_vars(recovery_dir.join("recovery/binaries"));

    let recovery_args = RecoveryArgs {
        dir: recovery_dir,
        nns_url: upload_node.get_public_url(),
        replica_version: Some(ic_version),
        key_file: Some(ssh_priv_key_path.clone()),
        test_mode: true,
        skip_prompts: true,
        use_local_binaries: false,
    };

    // unlike during a production recovery using the CLI, here we already know all of parameters
    // ahead of time.
    let subnet_args = NNSRecoverySameNodesArgs {
        subnet_id: topo_snapshot.root_subnet_id(),
        upgrade_version: Some(working_version),
        replay_until_height: None, // We will set this after breaking the subnet, see below
        upgrade_image_url: get_guestos_update_img_url().ok(),
        upgrade_image_hash: get_guestos_update_img_sha256().ok(),
        download_node: Some(download_node.get_ip_addr()),
        upload_method: Some(DataLocation::Remote(upload_node.get_ip_addr())),
        backup_key_file: Some(ssh_priv_key_path),
        output_dir: Some(output_dir.clone()),
        next_step: None,
    };

    let mut subnet_recovery = NNSRecoverySameNodes::new(logger.clone(), recovery_args, subnet_args);

    // let's take f+1 nodes and break them.
    let f = (SUBNET_SIZE - 1) / 3;
    info!(
        logger,
        "Breaking the NNS subnet by breaking the replica binary on f+1={} nodes",
        f + 1
    );

    let faulty_nodes = nns_nodes.take(f + 1).collect::<Vec<_>>();
    for node in faulty_nodes {
        // simulate subnet failure by breaking the replica process, but not the orchestrator
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
        &upload_node.get_public_url(),
        app_can_id,
        msg
    ));
    info!(
        logger,
        "Ensure the subnet doesn't work in write mode anymore"
    );
    assert!(cannot_store_msg(
        logger.clone(),
        &upload_node.get_public_url(),
        app_can_id,
        msg
    ));

    let up_node_metrics = block_on(get_node_metrics(&logger, &upload_node.get_ip_addr()))
        .expect("Missing metrics for upload node");
    let dn_node_metrics = block_on(get_node_metrics(&logger, &download_node.get_ip_addr()))
        .expect("Missing metrics for download node");
    if dn_node_metrics.certification_height < up_node_metrics.certification_height {
        // swap the two nodes, so that download one has highest height in the subnet
        subnet_recovery.params.download_node = Some(upload_node.get_ip_addr());
        subnet_recovery.params.upload_method =
            Some(DataLocation::Remote(download_node.get_ip_addr()));
        subnet_recovery.recovery.admin_helper.nns_url = download_node.get_public_url();
    }

    subnet_recovery.params.replay_until_height = Some(
        cmp::max(
            dn_node_metrics.certification_height,
            up_node_metrics.certification_height,
        )
        .get(),
    );

    info!(
        logger,
        "Starting recovery of the NNS subnet {}",
        topo_snapshot.root_subnet().subnet_id.to_string()
    );

    // go over all steps of the NNS recovery
    for (step_type, step) in subnet_recovery {
        info!(logger, "Next step: {:?}", step_type);

        info!(logger, "{}", step.descr());
        step.exec()
            .unwrap_or_else(|e| panic!("Execution of step {:?} failed: {}", step_type, e));
    }
    info!(logger, "NNS recovery has finished");

    // check that the network functions
    upload_node.await_status_is_healthy().unwrap();

    uvm_serve_recovery_artifacts(
        &env,
        std::fs::read(output_dir.join("recovery.tar.zst")).unwrap(),
        std::fs::read_to_string(output_dir.join("recovery.tar.zst.sha256")).unwrap(),
    )
    .expect("Failed to serve recovery artifacts from UVM");

    // TODO: Host recovery GuestOS image on UVM (this involves some additional dependencies in Bazel)
    // TODO: Spoof the node HostOS DNS (with spoof_node_dns) to point the upstreams to the UVM
    // TODO: Make every replica reboot into GuestOS-recovery-upgrader specifying the version of that
    // image
    // TODO: Once GuestOS is launched, spoof the node GuestOS DNS (with spoof_node_dns) to point the
    // upstreams to the UVM

    info!(logger, "Wait for state sync to complete");
    cert_state_makes_progress_with_retries(
        &upload_node.get_public_url(),
        upload_node.effective_canister_id(),
        &logger,
        secs(600),
        secs(10),
    );

    info!(logger, "Ensure the old message is still readable");
    assert!(can_read_msg(
        &logger,
        &upload_node.get_public_url(),
        app_can_id,
        msg
    ));
    let new_msg = "subnet recovery still works!";
    info!(
        logger,
        "Ensure that the subnet is accepting updates after the recovery"
    );
    let topo_snapshot = block_on(topo_snapshot.block_for_newer_registry_version())
        .expect("Could not obtain updated registry.");
    let upload_node = topo_snapshot
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
    assert!(can_read_msg(
        &logger,
        &upload_node.get_public_url(),
        new_app_can_id,
        new_msg
    ));
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
