/* tag::catalog[]

Title:: Subnet Recovery Test (App subnet, same nodes + failover nodes)

Goal::
Ensure that the subnet recovery of an app subnet works on the same nodes and on failover nodes.


Runbook::
. Deploy an IC with one app subnet (and some unassigned nodes in case of recovery on failover nodes).
. Upgrade the app subnet to a broken replica.
. Make sure the subnet stalls.
. Propose readonly key and confirm ssh access.
. Download IC state of a random node.
. Execute ic-replay to generate a recovery CUP.
. Upgrade the subnet to a working replica.
. Submit a recovery CUP (using failover nodes, if configured).
. Upload replayed state to a node.
. Unhalt the subnet.
. Ensure the subnet resumes.

Success::
. App subnet is functional after the recovery.

end::catalog[] */

use crate::driver::driver_setup::{SSH_AUTHORIZED_PRIV_KEYS_DIR, SSH_AUTHORIZED_PUB_KEYS_DIR};
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::ADMIN;
use crate::nns::NnsExt;
use crate::orchestrator::node_reassignment_test::{can_read_msg, store_message};
use crate::orchestrator::utils::upgrade::assert_assigned_replica_version;
use crate::util::*;
use ic_cup_explorer::get_catchup_content;
use ic_recovery::app_subnet_recovery::{AppSubnetRecovery, AppSubnetRecoveryArgs, StepType};
use ic_recovery::file_sync_helper;
use ic_recovery::steps::Step;
use ic_recovery::RecoveryArgs;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, ReplicaVersion};
use slog::info;
use std::convert::TryFrom;
use std::env;

const DKG_INTERVAL: u64 = 9;
const SUBNET_SIZE: usize = 4;

pub fn config_same_nodes() -> InternetComputer {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .add_nodes(SUBNET_SIZE),
        )
}

pub fn setup_same_nodes(env: TestEnv) {
    config_same_nodes()
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn setup_failover_nodes(env: TestEnv) {
    config_same_nodes()
        .with_unassigned_nodes(4)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

pub fn test(env: TestEnv) {
    let (handle, ctx) = get_ic_handle_and_ctx(env.clone());

    let mut rng = ctx.rng.clone();
    ctx.install_nns_canisters(&handle, true);

    let broken_replica_version = env::var("BROKEN_BLOCKMAKER_GIT_REVISION")
        .expect("Environment variable $BROKEN_BLOCKMAKER_GIT_REVISION is not set!");
    info!(
        ctx.logger,
        "BROKEN_BLOCKMAKER_GIT_REVISION: {}", broken_replica_version
    );

    let master_version = match env::var("IC_VERSION_ID") {
        Ok(ver) => ver,
        Err(_) => panic!("Environment variable $IC_VERSION_ID is not set!"),
    };
    info!(ctx.logger, "IC_VERSION_ID: {}", master_version);

    let working_version = format!("{}-test", master_version);

    let ssh_authorized_priv_keys_dir = env.get_path(SSH_AUTHORIZED_PRIV_KEYS_DIR);
    let ssh_authorized_pub_keys_dir = env.get_path(SSH_AUTHORIZED_PUB_KEYS_DIR);

    info!(
        ctx.logger,
        "ssh_authorized_priv_keys_dir: {:?}", ssh_authorized_priv_keys_dir
    );
    info!(
        ctx.logger,
        "ssh_authorized_pub_keys_dir: {:?}", ssh_authorized_pub_keys_dir
    );

    let nns_node = get_random_nns_node_endpoint(&handle, &mut rng);
    info!(
        ctx.logger,
        "Selected random NNS node: {} ({})",
        nns_node.node_id,
        nns_node.ip_address().unwrap()
    );
    block_on(nns_node.assert_ready(&ctx));

    let app_node = get_random_application_node_endpoint(&handle, &mut rng);
    info!(
        ctx.logger,
        "Selected random application subnet node: {} ({})",
        app_node.node_id,
        app_node.ip_address().unwrap()
    );
    info!(ctx.logger, "app node URL: {}", app_node.url);
    block_on(app_node.assert_ready(&ctx));

    info!(ctx.logger, "Ensure app subnet is functional");
    let msg = "subnet recovery works!";
    let app_can_id = block_on(store_message(&app_node.url, msg));
    assert!(block_on(can_read_msg(
        &ctx.logger,
        &app_node.url,
        app_can_id,
        msg
    )));

    let subnet_id = app_node.subnet_id().expect("No subnet_id found");

    let unassigned_nodes = get_unassinged_nodes_endpoints(&handle)
        .iter()
        .map(|ie| ie.node_id.to_string())
        .collect::<Vec<String>>();

    let upload_node = if !unassigned_nodes.is_empty() {
        get_random_unassigned_node_endpoint(&handle, &mut rng)
    } else {
        get_random_application_node_endpoint(&handle, &mut rng)
    };

    let pub_key = file_sync_helper::read_file(&ssh_authorized_pub_keys_dir.join(ADMIN))
        .expect("Couldn't read public key");

    let tempdir = tempfile::tempdir().expect("Could not create a temp dir");

    let recovery_args = RecoveryArgs {
        dir: tempdir.path().to_path_buf(),
        nns_url: nns_node.url.clone(),
        replica_version: Some(ReplicaVersion::try_from(master_version).unwrap()),
        key_file: Some(ssh_authorized_priv_keys_dir.join(ADMIN)),
    };

    // Unlike during a production recovery using the CLI, here we already know all of parameters ahead of time.
    let subnet_args = AppSubnetRecoveryArgs {
        subnet_id,
        upgrade_version: Some(ReplicaVersion::try_from(working_version.clone()).unwrap()),
        replacement_nodes: Some(unassigned_nodes),
        pub_key: Some(pub_key),
        download_node: Some(app_node.ip_address().unwrap()),
        upload_node: Some(upload_node.ip_address().unwrap()),
    };

    let mut subnet_recovery =
        AppSubnetRecovery::new(ctx.logger.clone(), recovery_args, None, subnet_args);

    info!(ctx.logger, "Confirming admin ssh access to app node");
    assert!(subnet_recovery
        .get_recovery_api()
        .check_ssh_access("admin", app_node.ip_address().unwrap()));

    info!(
        ctx.logger,
        "Breaking the app subnet by upgrading to a broken replica version"
    );
    let broken_version = ReplicaVersion::try_from(broken_replica_version.clone())
        .expect("Couldn't parse broken replica version");
    let bless_broken_version = subnet_recovery
        .get_recovery_api()
        .bless_replica_version(&broken_version)
        .expect("Failed to bless replica version");
    info!(ctx.logger, "{}", bless_broken_version.descr());
    bless_broken_version
        .exec()
        .expect("Execution of step failed");

    let upgrade_to_broken_version = subnet_recovery
        .get_recovery_api()
        .update_subnet_replica_version(subnet_id, &broken_version);
    info!(ctx.logger, "{}", upgrade_to_broken_version.descr());
    upgrade_to_broken_version
        .exec()
        .expect("Execution of step failed");

    assert_assigned_replica_version(app_node, &broken_replica_version, &ctx.logger);
    info!(
        ctx.logger,
        "Successfully upgraded subnet {} to {}", subnet_id, broken_replica_version
    );

    info!(ctx.logger, "Ensure the subnet works in read mode");
    assert!(block_on(can_read_msg(
        &ctx.logger,
        &app_node.url,
        app_can_id,
        msg
    )));
    info!(
        ctx.logger,
        "Ensure the subnet doesn't work in write mode anymore"
    );
    assert!(!can_install_canister(&app_node.url));

    info!(
        ctx.logger,
        "Starting recovery of subnet {}",
        subnet_id.to_string()
    );

    while let Some((step_type, step)) = subnet_recovery.next() {
        info!(ctx.logger, "Next step: {:?}", step_type);
        if matches!(step_type, StepType::ValidateReplayOutput) {
            // Replay output has to be validated differently since prometheus doesn't work here
            let (latest_height, state_hash) = subnet_recovery
                .get_recovery_api()
                .get_replay_output()
                .expect("Failed to get replay output");

            // Sanity check to confirm that replay didn't actually do anything
            let cup_content = block_on(get_catchup_content(&app_node.url))
                .expect("Couldn't fetch catchup package")
                .expect("No CUP found");

            let (cup_height, cup_hash) = (
                Height::from(cup_content.random_beacon.unwrap().height),
                cup_content.state_hash,
            );

            assert_eq!(
                cup_height, latest_height,
                "CUP height and replay height diverged (replay did something)."
            );

            assert_eq!(
                state_hash,
                hex::encode(&cup_hash),
                "Replay hash and CUP hash diverged (replay did something)."
            );

            // Continue, so we don't execute the iterator's ValidateReplayOutput step
            continue;
        }

        info!(ctx.logger, "{}", step.descr());
        step.exec().expect("Execution of step failed");
    }

    assert!(subnet_recovery.success(), "Recovery unsuccessful");

    // Confirm that ALL nodes are now healthy and running on the new version
    assert_assigned_replica_version(upload_node, &working_version, &ctx.logger);
    info!(
        ctx.logger,
        "Healthy upgrade of node {} to {}", upload_node.node_id, working_version
    );
    let mut other_nodes = get_other_subnet_nodes(&handle, upload_node);
    other_nodes.append(&mut get_unassinged_nodes_endpoints(&handle));
    for endpoint in other_nodes {
        assert_assigned_replica_version(upload_node, &working_version, &ctx.logger);
        info!(
            ctx.logger,
            "Healthy upgrade of node {} to {}", endpoint.node_id, working_version
        );
    }

    info!(ctx.logger, "Ensure the old message is still readable");
    assert!(block_on(can_read_msg(
        &ctx.logger,
        &upload_node.url,
        app_can_id,
        msg
    )));
    block_on(upload_node.assert_ready(&ctx));
    let new_msg = "subnet recovery still works!";
    info!(
        ctx.logger,
        "Ensure the the subnet is accepting updates after the recovery"
    );
    let new_app_can_id = block_on(store_message(&upload_node.url, new_msg));
    assert!(block_on(can_read_msg(
        &ctx.logger,
        &upload_node.url,
        new_app_can_id,
        new_msg
    )));
}

fn can_install_canister(url: &url::Url) -> bool {
    block_on(async {
        let agent = assert_create_agent(url.as_str()).await;
        UniversalCanister::try_new(&agent).await.is_ok()
    })
}
