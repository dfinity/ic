/* tag::catalog[]
Title:: SSH Key Management Test

Goal:: Testing the newly-added registry support for readonly and backup SSH key management.

Coverage::
. adding/removing backup keys,
. adding/removing readonly keys,
. adding/removing a mixture of both,
. the max number of keys cannot be exceeded.

end::catalog[] */

use crate::{
    driver::{test_env::TestEnv, test_env_api::*},
    orchestrator::utils::ssh_access::*,
    util::block_on,
};

use crate::driver::ic::InternetComputer;
use ic_nns_common::registry::MAX_NUM_SSH_KEYS;
use ic_registry_subnet_type::SubnetType;

use std::net::IpAddr;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .with_unassigned_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
}

fn topology_entities(
    topo_snapshot: TopologySnapshot,
) -> (
    IcNodeSnapshot,
    IcNodeSnapshot,
    IcNodeSnapshot,
    SubnetSnapshot,
) {
    // Fetch the nodes
    let nns_node = topo_snapshot
        .root_subnet()
        .nodes()
        .next()
        .expect("there is no NNS node");
    let app_subnet = topo_snapshot
        .subnets()
        .find(|subnet| subnet.subnet_type() == SubnetType::Application)
        .expect("there is no application subnet");
    let app_node = app_subnet
        .nodes()
        .next()
        .expect("there is no application node");
    let unassigned_node = topo_snapshot.unassigned_nodes().next().unwrap();

    // check they are all ready
    nns_node.await_status_is_healthy().unwrap();
    app_node.await_status_is_healthy().unwrap();
    unassigned_node.await_can_login_as_admin_via_ssh().unwrap();

    (nns_node, app_node, unassigned_node, app_subnet)
}

fn fetch_nodes_ips(topo_snapshot: TopologySnapshot) -> (IpAddr, IpAddr, IpAddr) {
    let (nns_node, app_node, unassigned_node, _) = topology_entities(topo_snapshot);

    let nns_node_ip: IpAddr = nns_node.get_ip_addr();
    let app_node_ip: IpAddr = app_node.get_ip_addr();
    let unassigned_node_ip: IpAddr = unassigned_node.get_ip_addr();

    (nns_node_ip, app_node_ip, unassigned_node_ip)
}

pub fn root_cannot_authenticate(env: TestEnv) {
    let (nns_node_ip, app_node_ip, unassigned_node_ip) = fetch_nodes_ips(env.topology_snapshot());

    let mean = AuthMean::Password("root".to_string());
    assert_authentication_fails(&nns_node_ip, "root", &mean);
    assert_authentication_fails(&app_node_ip, "root", &mean);
    assert_authentication_fails(&unassigned_node_ip, "root", &mean);
}

pub fn readonly_cannot_authenticate_without_a_key(env: TestEnv) {
    let (nns_node_ip, app_node_ip, unassigned_node_ip) = fetch_nodes_ips(env.topology_snapshot());

    let mean = AuthMean::None;
    assert_authentication_fails(&nns_node_ip, "readonly", &mean);
    assert_authentication_fails(&app_node_ip, "readonly", &mean);
    assert_authentication_fails(&unassigned_node_ip, "readonly", &mean);
}

pub fn readonly_cannot_authenticate_with_random_key(env: TestEnv) {
    let (nns_node_ip, app_node_ip, unassigned_node_ip) = fetch_nodes_ips(env.topology_snapshot());

    let (private_key, _public_key) = generate_key_strings();
    let mean = AuthMean::PrivateKey(private_key);
    assert_authentication_fails(&nns_node_ip, "readonly", &mean);
    assert_authentication_fails(&app_node_ip, "readonly", &mean);
    assert_authentication_fails(&unassigned_node_ip, "readonly", &mean);
}

pub fn keys_in_the_subnet_record_can_be_updated(env: TestEnv) {
    let (nns_node, app_node, _unassigned_node, app_subnet) =
        topology_entities(env.topology_snapshot());

    nns_node
        .install_nns_canisters()
        .expect("NNS canisters not installed");

    let app_subnet_id = app_subnet.subnet_id;
    let node_ip: IpAddr = app_node.get_ip_addr();

    // Update the registry with two new pairs of keys.
    let (readonly_private_key, readonly_public_key) = generate_key_strings();
    let (backup_private_key, backup_public_key) = generate_key_strings();
    let payload = get_updatesubnetpayload_with_keys(
        app_subnet_id,
        Some(vec![readonly_public_key]),
        Some(vec![backup_public_key]),
    );
    block_on(update_subnet_record(nns_node.get_public_url(), payload));

    let readonly_mean = AuthMean::PrivateKey(readonly_private_key);
    let backup_mean = AuthMean::PrivateKey(backup_private_key);
    // Orchestrator updates checks if there is a new version of the registry every
    // 10 seconds. If so, it updates first the readonly and then the backup
    // keys. If backup key can authenticate we know that the readonly keys are
    // already updated too.
    wait_until_authentication_is_granted(&node_ip, "backup", &backup_mean);
    assert_authentication_works(&node_ip, "readonly", &readonly_mean);

    // Clear the keys in the registry
    let no_key_payload =
        get_updatesubnetpayload_with_keys(app_subnet_id, Some(vec![]), Some(vec![]));
    block_on(update_subnet_record(
        nns_node.get_public_url(),
        no_key_payload,
    ));

    // Check that the access for these keys are also removed.
    wait_until_authentication_fails(&node_ip, "backup", &backup_mean);
    assert_authentication_fails(&node_ip, "readonly", &readonly_mean);
}

pub fn keys_for_unassigned_nodes_can_be_updated(env: TestEnv) {
    let (nns_node, _, unassigned_node, _) = topology_entities(env.topology_snapshot());

    let node_ip: IpAddr = unassigned_node.get_ip_addr();

    // Update the registry with two new pairs of keys.
    let (readonly_private_key, readonly_public_key) = generate_key_strings();
    let payload = get_updateunassignednodespayload(Some(vec![readonly_public_key]));
    block_on(update_ssh_keys_for_all_unassigned_nodes(
        nns_node.get_public_url(),
        payload,
    ));

    let readonly_mean = AuthMean::PrivateKey(readonly_private_key);
    wait_until_authentication_is_granted(&node_ip, "readonly", &readonly_mean);

    // Clear the keys in the registry
    let no_key_payload = get_updateunassignednodespayload(Some(vec![]));
    block_on(update_ssh_keys_for_all_unassigned_nodes(
        nns_node.get_public_url(),
        no_key_payload,
    ));

    // Check that the access for these keys are also removed.
    wait_until_authentication_fails(&node_ip, "readonly", &readonly_mean);
}

pub fn multiple_keys_can_access_one_account(env: TestEnv) {
    let (nns_node, app_node, _, app_subnet) = topology_entities(env.topology_snapshot());

    let app_subnet_id = app_subnet.subnet_id;
    let node_ip: IpAddr = app_node.get_ip_addr();

    // Update the registry with two new pairs of keys.
    let (readonly_private_key1, readonly_public_key1) = generate_key_strings();
    let (readonly_private_key2, readonly_public_key2) = generate_key_strings();
    let (readonly_private_key3, readonly_public_key3) = generate_key_strings();
    let (backup_private_key1, backup_public_key1) = generate_key_strings();
    let (backup_private_key2, backup_public_key2) = generate_key_strings();
    let (backup_private_key3, backup_public_key3) = generate_key_strings();
    let payload = get_updatesubnetpayload_with_keys(
        app_subnet_id,
        Some(vec![
            readonly_public_key1,
            readonly_public_key2,
            readonly_public_key3,
        ]),
        Some(vec![
            backup_public_key1,
            backup_public_key2,
            backup_public_key3,
        ]),
    );
    block_on(update_subnet_record(nns_node.get_public_url(), payload));

    let readonly_mean1 = AuthMean::PrivateKey(readonly_private_key1);
    let readonly_mean2 = AuthMean::PrivateKey(readonly_private_key2);
    let readonly_mean3 = AuthMean::PrivateKey(readonly_private_key3);
    let backup_mean1 = AuthMean::PrivateKey(backup_private_key1);
    let backup_mean2 = AuthMean::PrivateKey(backup_private_key2);
    let backup_mean3 = AuthMean::PrivateKey(backup_private_key3);
    // Orchestrator updates checks if there is a new version of the registry every
    // 10 seconds. If so, it updates first the readonly and then the backup
    // keys. If backup key can authenticate we know that the readonly keys are
    // already updated too.
    wait_until_authentication_is_granted(&node_ip, "backup", &backup_mean1);
    assert_authentication_works(&node_ip, "backup", &backup_mean2);
    assert_authentication_works(&node_ip, "backup", &backup_mean3);
    assert_authentication_works(&node_ip, "readonly", &readonly_mean1);
    assert_authentication_works(&node_ip, "readonly", &readonly_mean2);
    assert_authentication_works(&node_ip, "readonly", &readonly_mean3);
}

pub fn multiple_keys_can_access_one_account_on_unassigned_nodes(env: TestEnv) {
    let (nns_node, _, unassigned_node, _) = topology_entities(env.topology_snapshot());

    let node_ip: IpAddr = unassigned_node.get_ip_addr();

    // Update the registry with two new pairs of keys.
    let (readonly_private_key1, readonly_public_key1) = generate_key_strings();
    let (readonly_private_key2, readonly_public_key2) = generate_key_strings();
    let (readonly_private_key3, readonly_public_key3) = generate_key_strings();
    let payload = get_updateunassignednodespayload(Some(vec![
        readonly_public_key1,
        readonly_public_key2,
        readonly_public_key3,
    ]));
    block_on(update_ssh_keys_for_all_unassigned_nodes(
        nns_node.get_public_url(),
        payload,
    ));

    let readonly_mean1 = AuthMean::PrivateKey(readonly_private_key1);
    let readonly_mean2 = AuthMean::PrivateKey(readonly_private_key2);
    let readonly_mean3 = AuthMean::PrivateKey(readonly_private_key3);
    // Orchestrator updates checks if there is a new version of the registry every
    // 10 seconds. If so, it updates first the readonly and then the backup
    // keys. If backup key can authenticate we know that the readonly keys are
    // already updated too.
    wait_until_authentication_is_granted(&node_ip, "readonly", &readonly_mean1);
    assert_authentication_works(&node_ip, "readonly", &readonly_mean2);
    assert_authentication_works(&node_ip, "readonly", &readonly_mean3);
}

pub fn updating_readonly_does_not_remove_backup_keys(env: TestEnv) {
    let (nns_node, app_node, _, app_subnet) = topology_entities(env.topology_snapshot());

    let app_subnet_id = app_subnet.subnet_id;
    let node_ip: IpAddr = app_node.get_ip_addr();

    // Add a backup key.
    let (backup_private_key, backup_public_key) = generate_key_strings();
    let payload1 =
        get_updatesubnetpayload_with_keys(app_subnet_id, None, Some(vec![backup_public_key]));
    block_on(update_subnet_record(nns_node.get_public_url(), payload1));

    // Check that the backup key can authenticate.
    let backup_mean = AuthMean::PrivateKey(backup_private_key);
    wait_until_authentication_is_granted(&node_ip, "backup", &backup_mean);

    // Now add a readonly key.
    let (readonly_private_key, readonly_public_key) = generate_key_strings();
    let payload2 =
        get_updatesubnetpayload_with_keys(app_subnet_id, Some(vec![readonly_public_key]), None);
    block_on(update_subnet_record(nns_node.get_public_url(), payload2));

    // Check that the readonly key can authenticate now and the backup key can still
    // authenticate too.
    let readonly_mean = AuthMean::PrivateKey(readonly_private_key);
    wait_until_authentication_is_granted(&node_ip, "readonly", &readonly_mean);
    assert_authentication_works(&node_ip, "backup", &backup_mean);

    // Now send a proposal that only removes the readonly keys.
    let payload3 = get_updatesubnetpayload_with_keys(app_subnet_id, Some(vec![]), None);
    block_on(update_subnet_record(nns_node.get_public_url(), payload3));

    // Wait until the readonly key loses its access and ensure backup key still has
    // access.
    wait_until_authentication_fails(&node_ip, "readonly", &readonly_mean);
    assert_authentication_works(&node_ip, "backup", &backup_mean);
}

pub fn can_add_max_number_of_readonly_and_backup_keys(env: TestEnv) {
    let (nns_node, _, _, app_subnet) = topology_entities(env.topology_snapshot());

    let app_subnet_id = app_subnet.subnet_id;

    let (_private_key, public_key) = generate_key_strings();
    // Update the registry with MAX_NUM_SSH_KEYS new pairs of keys.
    let payload_for_subnet = get_updatesubnetpayload_with_keys(
        app_subnet_id,
        Some(vec![public_key.clone(); MAX_NUM_SSH_KEYS]),
        Some(vec![public_key.clone(); MAX_NUM_SSH_KEYS]),
    );
    block_on(update_subnet_record(
        nns_node.get_public_url(),
        payload_for_subnet,
    ));

    // Also do that for unassigned nodes
    let payload_for_the_unassigned = get_updateunassignednodespayload(Some(vec![public_key; 50]));
    block_on(update_ssh_keys_for_all_unassigned_nodes(
        nns_node.get_public_url(),
        payload_for_the_unassigned,
    ));
}

pub fn cannot_add_more_than_max_number_of_readonly_or_backup_keys(env: TestEnv) {
    let (nns_node, _, _, app_subnet) = topology_entities(env.topology_snapshot());
    let app_subnet_id = app_subnet.subnet_id;

    let (_private_key, public_key) = generate_key_strings();

    // Try to update the registry with MAX_NUM_SSH_KEYS+1 readonly keys.
    let readonly_payload = get_updatesubnetpayload_with_keys(
        app_subnet_id,
        Some(vec![public_key.clone(); MAX_NUM_SSH_KEYS + 1]),
        Some(vec![]),
    );
    block_on(fail_to_update_subnet_record(
        nns_node.get_public_url(),
        readonly_payload,
    ));

    // Try to update the registry with MAX_NUM_SSH_KEYS backup keys.
    let backup_payload = get_updatesubnetpayload_with_keys(
        app_subnet_id,
        Some(vec![]),
        Some(vec![public_key.clone(); MAX_NUM_SSH_KEYS + 1]),
    );
    block_on(fail_to_update_subnet_record(
        nns_node.get_public_url(),
        backup_payload,
    ));

    // Also do that for unassigned nodes
    let readonly_payload_for_the_unassigned =
        get_updateunassignednodespayload(Some(vec![public_key; MAX_NUM_SSH_KEYS + 1]));
    block_on(fail_updating_ssh_keys_for_all_unassigned_nodes(
        nns_node.get_public_url(),
        readonly_payload_for_the_unassigned,
    ));
}
