/* tag::catalog[]
Title:: Upgradability to/from oldest prod replica version.

Goal:: Ensure the upgradability of the branch version against the oldest used replica version

Runbook::
. Setup an IC with 4-nodes NNS and 4-nodes app subnet using the code from the branch.
. Enable ECDSA on a subnet.
. Downgrade each type of subnet to the mainnet version.
. During the downgrade simulate a disconnected node and make sure it catches up.

Success:: Upgrades work into both directions for all subnet types.

end::catalog[] */

use super::utils::rw_message::install_nns_and_message_canisters;
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::{test_env::TestEnv, test_env_api::*};
use crate::orchestrator::upgrade_downgrade::{start_node, stop_node, MIN_HASH_LENGTH};
use crate::orchestrator::utils::rw_message::{can_read_msg, store_message};
use crate::orchestrator::utils::upgrade::*;
use crate::tecdsa::tecdsa_signature_test::test_threshold_ecdsa_signature_same_subnet;
use crate::util::block_on;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, SubnetId};
use slog::{info, Logger};
use std::env;

const DKG_INTERVAL: u64 = 19;
const SUBNET_SIZE: usize = 4;

pub fn config(env: TestEnv) {
    env.ensure_group_setup_created();
    InternetComputer::new()
        .add_subnet(
            Subnet::new(SubnetType::System)
                .add_nodes(SUBNET_SIZE)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .add_nodes(SUBNET_SIZE)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_message_canisters(env.topology_snapshot());
}

// Tests a downgrade of the app subnet to the mainnet version.
pub fn downgrade_app_subnet(env: TestEnv) {
    downgrade_test(env, SubnetType::Application);
}

// Downgrades a subnet to $TARGET_VERSION and back to branch version
fn downgrade_test(env: TestEnv, subnet_type: SubnetType) {
    let logger = env.logger();

    // TODO: abandon the TARGET_VERSION approach once run-system-tests.py is deprecated [VER-1818]
    let is_bazel = env::var("TARGET_VERSION").is_err();

    // TODO: [VER-1818]
    let mainnet_version = env::var("TARGET_VERSION")
        .or_else(|_| env.read_dependency_to_string("testnet/mainnet_nns_revision.txt"))
        .unwrap();

    // we expect to get a hash value here, so checking that is a hash number of at least 64 bits size
    assert!(mainnet_version.len() >= 2 * MIN_HASH_LENGTH);
    assert!(hex::decode(&mainnet_version).is_ok());

    // choose a node from the nns subnet
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();

    let original_branch_version = get_assigned_replica_version(&nns_node).unwrap();
    info!(
        &logger,
        "original_branch_version: {:?}", original_branch_version
    );

    // Bless both replica versions
    block_on(bless_public_replica_version(
        &nns_node,
        &mainnet_version,
        UpdateImageType::Image,
        UpdateImageType::Image,
        &logger,
    ));

    if is_bazel {
        let sha256 = env
            .read_dependency_to_string("ic-os/guestos/dev/upgrade.tar.zst.sha256")
            .unwrap();
        block_on(bless_replica_version(
            &nns_node,
            &original_branch_version,
            UpdateImageType::ImageTest,
            &logger,
            &sha256,
        ));
    } else {
        // TODO: [VER-1818]
        block_on(bless_public_replica_version(
            &nns_node,
            &original_branch_version,
            UpdateImageType::ImageTest,
            UpdateImageType::ImageTest,
            &logger,
        ));
    }

    info!(&logger, "Blessed all versions");

    let (handle, ctx) = get_ic_handle_and_ctx(env.clone());
    test_threshold_ecdsa_signature_same_subnet(handle, &ctx);
    downgrade(env, &nns_node, &mainnet_version, subnet_type);
}

// Downgrades a subnet with one faulty node.
fn downgrade(
    env: TestEnv,
    nns_node: &IcNodeSnapshot,
    target_version: &str,
    subnet_type: SubnetType,
) {
    let logger = env.logger();
    let (subnet_id, subnet_node, faulty_node) = if subnet_type == SubnetType::System {
        let subnet = env.topology_snapshot().root_subnet();
        let mut it = subnet.nodes();
        // We don't want to hit the node we're using for sending the proposals
        assert!(it.next().unwrap().node_id == nns_node.node_id);
        (subnet.subnet_id, it.next().unwrap(), it.next().unwrap())
    } else {
        let subnet = env
            .topology_snapshot()
            .subnets()
            .find(|subnet| subnet.subnet_type() == SubnetType::Application)
            .expect("there is no application subnet");
        let mut it = subnet.nodes();
        (subnet.subnet_id, it.next().unwrap(), it.next().unwrap())
    };
    subnet_node.await_status_is_healthy().unwrap();
    faulty_node.await_status_is_healthy().unwrap();

    let msg = "hello world!";
    let can_id = store_message(
        &subnet_node.get_public_url(),
        subnet_node.effective_canister_id(),
        msg,
    );
    assert!(can_read_msg(
        &logger,
        &subnet_node.get_public_url(),
        can_id,
        msg
    ));
    info!(logger, "Could store and read message '{}'", msg);

    stop_node(&logger, &faulty_node);

    upgrade_to(nns_node, subnet_id, &subnet_node, target_version, &logger);

    start_node(&logger, &faulty_node);
    assert_assigned_replica_version(&faulty_node, target_version, env.logger());

    assert!(can_read_msg(
        &logger,
        &faulty_node.get_public_url(),
        can_id,
        msg
    ));
    info!(logger, "After downgrade could read message '{}'", msg);

    let msg_2 = "hello world after downgrade!";
    let can_id_2 = store_message(
        &faulty_node.get_public_url(),
        faulty_node.effective_canister_id(),
        msg_2,
    );
    assert!(can_read_msg(
        &logger,
        &faulty_node.get_public_url(),
        can_id_2,
        msg_2
    ));
    info!(logger, "Could store and read message '{}'", msg_2);
}

fn upgrade_to(
    nns_node: &IcNodeSnapshot,
    subnet_id: SubnetId,
    subnet_node: &IcNodeSnapshot,
    target_version: &str,
    logger: &Logger,
) {
    info!(
        logger,
        "Upgrading subnet {} to {}", subnet_id, target_version
    );
    block_on(update_subnet_replica_version(
        nns_node,
        &ic_types::ReplicaVersion::try_from(target_version).unwrap(),
        subnet_id,
    ));
    assert_assigned_replica_version(subnet_node, target_version, logger.clone());
    info!(
        logger,
        "Successfully upgraded subnet {} to {}", subnet_id, target_version
    );
}
