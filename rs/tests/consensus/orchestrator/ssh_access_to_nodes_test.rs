/* tag::catalog[]
Title:: SSH Key Management Test

Goal:: Testing the newly-added registry support for readonly, backup and recovery SSH key management.

Coverage::
. adding/removing readonly keys,
. adding/removing backup keys,
. adding/removing recovery keys,
. adding/removing a mixture of them,
. the max number of keys cannot be exceeded,
. keys are not removed on restart,
. keys are removed when leaving a subnet.

end::catalog[] */

use anyhow::Result;
use ic_consensus_system_test_utils::{
    node::get_node_earliest_topology_version,
    rw_message::install_nns_and_check_progress,
    ssh_access::{
        AuthMean, SshSession, assert_authentication_fails, assert_authentication_works,
        assert_set_subnet_operational_level_fails,
        assert_update_ssh_keys_for_all_unassigned_nodes_fails, assert_update_subnet_record_fails,
        generate_key_strings, get_set_subnet_operational_level_payload_with_keys,
        get_update_ssh_keys_for_all_unassigned_nodes_payload, get_update_subnet_payload_with_keys,
        set_subnet_operational_level, update_ssh_keys_for_all_unassigned_nodes,
        update_subnet_record, wait_until_authentication_fails,
        wait_until_authentication_is_granted,
    },
};
use ic_nns_common::registry::MAX_NUM_SSH_KEYS;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::SystemTestGroup,
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            HasPublicApiUrl, HasRegistryVersion, HasTopologySnapshot, IcNodeSnapshot,
            SshSession as _, SubnetSnapshot, TopologySnapshot,
        },
    },
    nns::remove_nodes_via_endpoint,
    systest,
    util::{block_on, get_app_subnet_and_node, get_nns_node},
};
use ic_types::Height;
use slog::info;
use std::{net::IpAddr, time::Duration};

const ORCHESTRATOR_TASK_CHECK_INTERVAL: Duration = Duration::from_secs(10);

const SSH_USERS: [&str; 5] = ["root", "admin", "readonly", "backup", "recovery"];

fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_subnet(
            Subnet::fast(SubnetType::Application, 2).with_dkg_interval_length(Height::from(49)),
        )
        .with_unassigned_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
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
    let nns_node = get_nns_node(&topo_snapshot);
    let (app_subnet, app_node) = get_app_subnet_and_node(&topo_snapshot);
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

fn generate_key_and_auth_mean() -> (AuthMean, String) {
    let (private_key, public_key) = generate_key_strings();
    (AuthMean::PrivateKey(private_key), public_key)
}

fn generate_keys_and_auth_means(n: usize) -> (Vec<AuthMean>, Vec<String>) {
    (0..n).map(|_| generate_key_and_auth_mean()).unzip()
}

fn assert_no_user_can_authenticate_anywhere(
    env: &TestEnv,
    auth_mean_for: impl Fn(&str) -> AuthMean,
) {
    let (nns_node_ip, app_node_ip, unassigned_node_ip) = fetch_nodes_ips(env.topology_snapshot());
    for user in SSH_USERS {
        let mean = auth_mean_for(user);
        for ip in [&nns_node_ip, &app_node_ip, &unassigned_node_ip] {
            assert_authentication_fails(ip, user, &mean);
        }
    }
}

fn assert_all_authenticate(ip: &IpAddr, username: &str, means: &[AuthMean]) {
    for mean in means {
        assert_authentication_works(ip, username, mean);
    }
}

fn ssh_users_cannot_authenticate_with_easy_password(env: TestEnv) {
    assert_no_user_can_authenticate_anywhere(&env, |user| AuthMean::Password(user.to_string()));
}

fn ssh_users_cannot_authenticate_without_a_key(env: TestEnv) {
    assert_no_user_can_authenticate_anywhere(&env, |_| AuthMean::None);
}

fn ssh_users_cannot_authenticate_with_random_key(env: TestEnv) {
    assert_no_user_can_authenticate_anywhere(&env, |_| {
        let (private_key, _) = generate_key_strings();
        AuthMean::PrivateKey(private_key)
    });
}

fn keys_in_the_subnet_record_can_be_updated(env: TestEnv) {
    let logger = env.logger();
    let (nns_node, app_node, _unassigned_node, app_subnet) =
        topology_entities(env.topology_snapshot());

    let app_subnet_id = app_subnet.subnet_id;
    let node_ip: IpAddr = app_node.get_ip_addr();

    info!(logger, "Updating the registry with new pairs of keys...");
    let (readonly_mean, readonly_public_key) = generate_key_and_auth_mean();
    let (backup_mean, backup_public_key) = generate_key_and_auth_mean();
    let payload = get_update_subnet_payload_with_keys(
        app_subnet_id,
        Some(vec![readonly_public_key]),
        Some(vec![backup_public_key]),
    );
    block_on(update_subnet_record(nns_node.get_public_url(), payload));

    // Orchestrator updates checks if there is a new version of the registry every
    // 10 seconds. If so, it updates first the readonly, then the backup and then
    // the recovery keys. If recovery key can authenticate we know that the
    // readonly and backup keys are already updated too.
    info!(logger, "Waiting for backup authentication to be granted...");
    wait_until_authentication_is_granted(&logger, &node_ip, "backup", &backup_mean);
    info!(
        logger,
        "Readonly authentication should now also be granted."
    );
    assert_authentication_works(&node_ip, "readonly", &readonly_mean);

    // Clear the keys in the registry
    let no_key_payload =
        get_update_subnet_payload_with_keys(app_subnet_id, Some(vec![]), Some(vec![]));
    block_on(update_subnet_record(
        nns_node.get_public_url(),
        no_key_payload,
    ));

    // Check that the access for these keys are also removed.
    wait_until_authentication_fails(&logger, &node_ip, "backup", &backup_mean);
    assert_authentication_fails(&node_ip, "readonly", &readonly_mean);
}

fn keys_in_the_node_record_can_be_updated(env: TestEnv) {
    let logger = env.logger();
    let (nns_node, app_node, _unassigned_node, app_subnet) =
        topology_entities(env.topology_snapshot());

    let app_subnet_id = app_subnet.subnet_id;
    let node_ip: IpAddr = app_node.get_ip_addr();

    info!(logger, "Updating the registry with new pairs of keys...");
    let (recovery_mean, recovery_public_key) = generate_key_and_auth_mean();
    let payload = get_set_subnet_operational_level_payload_with_keys(
        Some(app_subnet_id),
        None,
        Some(vec![(app_node.node_id, vec![recovery_public_key])]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        payload,
    ));

    // Orchestrator updates checks if there is a new version of the registry every
    // 10 seconds.
    info!(
        logger,
        "Waiting for recovery authentication to be granted..."
    );
    wait_until_authentication_is_granted(&logger, &node_ip, "recovery", &recovery_mean);

    // Clear the keys in the registry
    let no_key_payload = get_set_subnet_operational_level_payload_with_keys(
        Some(app_subnet_id),
        None,
        Some(vec![(app_node.node_id, vec![])]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        no_key_payload,
    ));

    // Check that the access for these keys are also removed.
    wait_until_authentication_fails(&logger, &node_ip, "recovery", &recovery_mean);
}

fn set_subnet_operational_level_updates_readonly_and_recovery_keys(env: TestEnv) {
    let logger = env.logger();
    let (nns_node, app_node, _unassigned_node, app_subnet) =
        topology_entities(env.topology_snapshot());

    let app_subnet_id = app_subnet.subnet_id;
    let node_ip: IpAddr = app_node.get_ip_addr();

    info!(logger, "Updating the registry with new pairs of keys...");
    let (readonly_mean, readonly_public_key) = generate_key_and_auth_mean();
    let (recovery_mean, recovery_public_key) = generate_key_and_auth_mean();
    let payload = get_set_subnet_operational_level_payload_with_keys(
        Some(app_subnet_id),
        Some(vec![readonly_public_key]),
        Some(vec![(app_node.node_id, vec![recovery_public_key])]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        payload,
    ));

    // Orchestrator updates checks if there is a new version of the registry every
    // 10 seconds. If so, it updates first the readonly, then the backup and then
    // the recovery keys. If recovery key can authenticate we know that the
    // readonly and backup keys are already updated too.
    info!(
        logger,
        "Waiting for recovery authentication to be granted..."
    );
    wait_until_authentication_is_granted(&logger, &node_ip, "recovery", &recovery_mean);
    info!(
        logger,
        "Readonly authentication should now also be granted."
    );
    assert_authentication_works(&node_ip, "readonly", &readonly_mean);

    // Clear the keys in the registry
    let no_key_payload = get_set_subnet_operational_level_payload_with_keys(
        Some(app_subnet_id),
        Some(vec![]),
        Some(vec![(app_node.node_id, vec![])]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        no_key_payload,
    ));

    // Check that the access for these keys are also removed.
    wait_until_authentication_fails(&logger, &node_ip, "recovery", &recovery_mean);
    assert_authentication_fails(&node_ip, "readonly", &readonly_mean);
}

fn keys_for_unassigned_nodes_can_be_updated(env: TestEnv) {
    let logger = env.logger();
    let (nns_node, _, unassigned_node, _) = topology_entities(env.topology_snapshot());

    let node_ip: IpAddr = unassigned_node.get_ip_addr();

    info!(logger, "Updating the registry with new pairs of keys...");
    let (readonly_mean, readonly_public_key) = generate_key_and_auth_mean();
    let (recovery_mean, recovery_public_key) = generate_key_and_auth_mean();
    let payload = get_update_ssh_keys_for_all_unassigned_nodes_payload(vec![readonly_public_key]);
    block_on(update_ssh_keys_for_all_unassigned_nodes(
        nns_node.get_public_url(),
        payload,
    ));
    let payload = get_set_subnet_operational_level_payload_with_keys(
        None,
        None,
        Some(vec![(unassigned_node.node_id, vec![recovery_public_key])]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        payload,
    ));

    // Orchestrator updates checks if there is a new version of the registry every
    // 10 seconds. If so, it updates first the readonly, then the backup and then
    // the recovery keys. If recovery key can authenticate we know that the
    // readonly and backup keys are already updated too.
    info!(
        logger,
        "Waiting for recovery authentication to be granted..."
    );
    wait_until_authentication_is_granted(&logger, &node_ip, "recovery", &recovery_mean);
    info!(
        logger,
        "Readonly authentication should now also be granted."
    );
    assert_authentication_works(&node_ip, "readonly", &readonly_mean);

    // Clear the keys in the registry
    let no_key_payload = get_update_ssh_keys_for_all_unassigned_nodes_payload(vec![]);
    block_on(update_ssh_keys_for_all_unassigned_nodes(
        nns_node.get_public_url(),
        no_key_payload,
    ));
    let no_key_payload = get_set_subnet_operational_level_payload_with_keys(
        None,
        None,
        Some(vec![(unassigned_node.node_id, vec![])]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        no_key_payload,
    ));

    // Check that the access for these keys are also removed.
    wait_until_authentication_fails(&logger, &node_ip, "recovery", &recovery_mean);
    assert_authentication_fails(&node_ip, "readonly", &readonly_mean);
}

fn multiple_keys_can_access_one_account(env: TestEnv) {
    let logger = env.logger();
    let (nns_node, app_node, _, app_subnet) = topology_entities(env.topology_snapshot());

    let app_subnet_id = app_subnet.subnet_id;
    let node_ip: IpAddr = app_node.get_ip_addr();

    info!(logger, "Updating the registry with new pairs of keys...");
    let (readonly_means, readonly_public_keys) = generate_keys_and_auth_means(3);
    let (backup_means, backup_public_keys) = generate_keys_and_auth_means(3);
    let (recovery_means, recovery_public_keys) = generate_keys_and_auth_means(3);
    let payload = get_update_subnet_payload_with_keys(
        app_subnet_id,
        Some(readonly_public_keys),
        Some(backup_public_keys),
    );
    block_on(update_subnet_record(nns_node.get_public_url(), payload));
    let payload = get_set_subnet_operational_level_payload_with_keys(
        Some(app_subnet_id),
        None,
        Some(vec![(app_node.node_id, recovery_public_keys)]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        payload,
    ));

    // Orchestrator updates checks if there is a new version of the registry every
    // 10 seconds. If so, it updates first the readonly, then the backup and then
    // the recovery keys. If recovery key can authenticate we know that the
    // readonly and backup keys are already updated too.
    info!(
        logger,
        "Waiting for recovery authentication to be granted..."
    );
    wait_until_authentication_is_granted(&logger, &node_ip, "recovery", &recovery_means[0]);
    info!(
        logger,
        "All other authentications should now also be granted."
    );
    assert_all_authenticate(&node_ip, "recovery", &recovery_means[1..]);
    assert_all_authenticate(&node_ip, "backup", &backup_means);
    assert_all_authenticate(&node_ip, "readonly", &readonly_means);
}

fn multiple_keys_can_access_one_account_on_unassigned_nodes(env: TestEnv) {
    let logger = env.logger();
    let (nns_node, _, unassigned_node, _) = topology_entities(env.topology_snapshot());

    let node_ip: IpAddr = unassigned_node.get_ip_addr();

    info!(logger, "Updating the registry with new pairs of keys...");
    let (readonly_means, readonly_public_keys) = generate_keys_and_auth_means(3);
    let (recovery_means, recovery_public_keys) = generate_keys_and_auth_means(3);
    let payload = get_update_ssh_keys_for_all_unassigned_nodes_payload(readonly_public_keys);
    block_on(update_ssh_keys_for_all_unassigned_nodes(
        nns_node.get_public_url(),
        payload,
    ));
    let payload = get_set_subnet_operational_level_payload_with_keys(
        None,
        None,
        Some(vec![(unassigned_node.node_id, recovery_public_keys)]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        payload,
    ));

    // Orchestrator updates checks if there is a new version of the registry every
    // 10 seconds. If so, it updates first the readonly, then the backup and then
    // the recovery keys. If recovery key can authenticate we know that the
    // readonly and backup keys are already updated too.
    info!(
        logger,
        "Waiting for recovery authentication to be granted..."
    );
    wait_until_authentication_is_granted(&logger, &node_ip, "recovery", &recovery_means[0]);
    info!(
        logger,
        "All other authentications should now also be granted."
    );
    assert_all_authenticate(&node_ip, "recovery", &recovery_means[1..]);
    assert_all_authenticate(&node_ip, "readonly", &readonly_means);
}

fn updating_readonly_does_not_remove_backup_keys(env: TestEnv) {
    let logger = env.logger();
    let (nns_node, app_node, _, app_subnet) = topology_entities(env.topology_snapshot());

    let app_subnet_id = app_subnet.subnet_id;
    let node_ip: IpAddr = app_node.get_ip_addr();

    // Add a backup key.
    let (backup_mean, backup_public_key) = generate_key_and_auth_mean();
    let payload1 =
        get_update_subnet_payload_with_keys(app_subnet_id, None, Some(vec![backup_public_key]));
    block_on(update_subnet_record(nns_node.get_public_url(), payload1));

    // Check that the backup key can authenticate.
    wait_until_authentication_is_granted(&logger, &node_ip, "backup", &backup_mean);

    // Now add a readonly key.
    let (readonly_mean, readonly_public_key) = generate_key_and_auth_mean();
    let payload2 =
        get_update_subnet_payload_with_keys(app_subnet_id, Some(vec![readonly_public_key]), None);
    block_on(update_subnet_record(nns_node.get_public_url(), payload2));

    // Check that the readonly key can authenticate now and the backup key can still
    // authenticate too.
    wait_until_authentication_is_granted(&logger, &node_ip, "readonly", &readonly_mean);
    assert_authentication_works(&node_ip, "backup", &backup_mean);

    // Now send a proposal that only removes the readonly keys.
    let payload3 = get_update_subnet_payload_with_keys(app_subnet_id, Some(vec![]), None);
    block_on(update_subnet_record(nns_node.get_public_url(), payload3));

    // Wait until the readonly key loses its access and ensure backup key still has
    // access.
    wait_until_authentication_fails(&logger, &node_ip, "readonly", &readonly_mean);
    assert_authentication_works(&node_ip, "backup", &backup_mean);
}

fn updating_recovery_does_not_remove_readonly_and_backup_keys(env: TestEnv) {
    let logger = env.logger();
    let (nns_node, app_node, _, app_subnet) = topology_entities(env.topology_snapshot());

    let app_subnet_id = app_subnet.subnet_id;
    let node_ip: IpAddr = app_node.get_ip_addr();

    // Add readonly and backup keys.
    let (readonly_mean, readonly_public_key) = generate_key_and_auth_mean();
    let (backup_mean, backup_public_key) = generate_key_and_auth_mean();
    let payload1 = get_update_subnet_payload_with_keys(
        app_subnet_id,
        Some(vec![readonly_public_key]),
        Some(vec![backup_public_key]),
    );
    block_on(update_subnet_record(nns_node.get_public_url(), payload1));

    // Check that the keys can authenticate.
    wait_until_authentication_is_granted(&logger, &node_ip, "backup", &backup_mean);
    assert_authentication_works(&node_ip, "readonly", &readonly_mean);

    // Now add a recovery key.
    let (recovery_mean, recovery_public_key) = generate_key_and_auth_mean();
    let payload2 = get_set_subnet_operational_level_payload_with_keys(
        Some(app_subnet_id),
        None,
        Some(vec![(app_node.node_id, vec![recovery_public_key])]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        payload2,
    ));

    // Check that the recovery key can authenticate now and the previous keys can still
    // authenticate too.
    wait_until_authentication_is_granted(&logger, &node_ip, "recovery", &recovery_mean);
    assert_authentication_works(&node_ip, "backup", &backup_mean);
    assert_authentication_works(&node_ip, "readonly", &readonly_mean);

    // Now send a proposal that only removes the recovery keys.
    let payload3 = get_set_subnet_operational_level_payload_with_keys(
        Some(app_subnet_id),
        None,
        Some(vec![(app_node.node_id, vec![])]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        payload3,
    ));

    // Wait until the recovery key loses its access and ensure previous keys still have
    // access.
    wait_until_authentication_fails(&logger, &node_ip, "recovery", &recovery_mean);
    assert_authentication_works(&node_ip, "backup", &backup_mean);
    assert_authentication_works(&node_ip, "readonly", &readonly_mean);
}

fn can_add_max_number_of_keys(env: TestEnv) {
    let (nns_node, app_node, unassigned_node, app_subnet) =
        topology_entities(env.topology_snapshot());

    let app_subnet_id = app_subnet.subnet_id;

    let (_private_key, public_key) = generate_key_strings();
    // Update the registry with MAX_NUM_SSH_KEYS new pairs of keys.
    let payload_for_subnet = get_update_subnet_payload_with_keys(
        app_subnet_id,
        Some(vec![public_key.clone(); MAX_NUM_SSH_KEYS]),
        Some(vec![public_key.clone(); MAX_NUM_SSH_KEYS]),
    );
    block_on(update_subnet_record(
        nns_node.get_public_url(),
        payload_for_subnet,
    ));
    let payload_for_assigned_recovery_keys = get_set_subnet_operational_level_payload_with_keys(
        Some(app_subnet_id),
        None,
        Some(vec![(
            app_node.node_id,
            vec![public_key.clone(); MAX_NUM_SSH_KEYS],
        )]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        payload_for_assigned_recovery_keys,
    ));

    // Also do that for unassigned nodes
    let payload_for_the_unassigned = get_update_ssh_keys_for_all_unassigned_nodes_payload(vec![
            public_key.clone();
            MAX_NUM_SSH_KEYS
        ]);
    block_on(update_ssh_keys_for_all_unassigned_nodes(
        nns_node.get_public_url(),
        payload_for_the_unassigned,
    ));
    let payload_for_unassigned_recovery_keys = get_set_subnet_operational_level_payload_with_keys(
        None,
        None,
        Some(vec![(
            unassigned_node.node_id,
            vec![public_key; MAX_NUM_SSH_KEYS],
        )]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        payload_for_unassigned_recovery_keys,
    ));
}

fn cannot_add_more_than_max_number_of_keys(env: TestEnv) {
    let (nns_node, app_node, unassigned_node, app_subnet) =
        topology_entities(env.topology_snapshot());
    let app_subnet_id = app_subnet.subnet_id;

    let (_private_key, public_key) = generate_key_strings();

    // Try to update the registry with MAX_NUM_SSH_KEYS+1 readonly keys.
    let readonly_payload = get_update_subnet_payload_with_keys(
        app_subnet_id,
        Some(vec![public_key.clone(); MAX_NUM_SSH_KEYS + 1]),
        Some(vec![]),
    );
    block_on(assert_update_subnet_record_fails(
        nns_node.get_public_url(),
        readonly_payload,
    ));

    // Try to update the registry with MAX_NUM_SSH_KEYS backup keys.
    let backup_payload = get_update_subnet_payload_with_keys(
        app_subnet_id,
        Some(vec![]),
        Some(vec![public_key.clone(); MAX_NUM_SSH_KEYS + 1]),
    );
    block_on(assert_update_subnet_record_fails(
        nns_node.get_public_url(),
        backup_payload,
    ));

    // Try to update the registry with MAX_NUM_SSH_KEYS recovery keys.
    let recovery_payload = get_set_subnet_operational_level_payload_with_keys(
        Some(app_subnet_id),
        None,
        Some(vec![(
            app_node.node_id,
            vec![public_key.clone(); MAX_NUM_SSH_KEYS + 1],
        )]),
    );
    block_on(assert_set_subnet_operational_level_fails(
        nns_node.get_public_url(),
        recovery_payload,
    ));

    // Also do that for unassigned nodes
    let readonly_payload_for_the_unassigned =
        get_update_ssh_keys_for_all_unassigned_nodes_payload(vec![
            public_key.clone();
            MAX_NUM_SSH_KEYS + 1
        ]);
    block_on(assert_update_ssh_keys_for_all_unassigned_nodes_fails(
        nns_node.get_public_url(),
        readonly_payload_for_the_unassigned,
    ));
    let recovery_payload_for_the_unassigned = get_set_subnet_operational_level_payload_with_keys(
        None,
        None,
        Some(vec![(
            unassigned_node.node_id,
            vec![public_key; MAX_NUM_SSH_KEYS + 1],
        )]),
    );
    block_on(assert_set_subnet_operational_level_fails(
        nns_node.get_public_url(),
        recovery_payload_for_the_unassigned,
    ));
}

fn node_does_not_remove_keys_on_restart(env: TestEnv) {
    let logger = env.logger();
    let (nns_node, app_node, unassigned_node, app_subnet) =
        topology_entities(env.topology_snapshot());

    let app_subnet_id = app_subnet.subnet_id;
    let node_ip: IpAddr = app_node.get_ip_addr();
    let unassigned_node_ip: IpAddr = unassigned_node.get_ip_addr();

    info!(logger, "Updating the registry with new pairs of keys...");
    let (readonly_mean, readonly_public_key) = generate_key_and_auth_mean();
    let (backup_mean, backup_public_key) = generate_key_and_auth_mean();
    let (recovery_mean, recovery_public_key) = generate_key_and_auth_mean();

    info!(logger, "Updating app subnet record...");
    let payload = get_update_subnet_payload_with_keys(
        app_subnet_id,
        Some(vec![readonly_public_key.clone()]),
        Some(vec![backup_public_key]),
    );
    block_on(update_subnet_record(nns_node.get_public_url(), payload));
    info!(logger, "Updating app node record...");
    let payload = get_set_subnet_operational_level_payload_with_keys(
        Some(app_subnet_id),
        None,
        Some(vec![(app_node.node_id, vec![recovery_public_key.clone()])]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        payload,
    ));

    info!(logger, "Updating unassigned nodes record...");
    let payload = get_update_ssh_keys_for_all_unassigned_nodes_payload(vec![readonly_public_key]);
    block_on(update_ssh_keys_for_all_unassigned_nodes(
        nns_node.get_public_url(),
        payload,
    ));
    info!(logger, "Updating unassigned node record...");
    let payload = get_set_subnet_operational_level_payload_with_keys(
        None,
        None,
        Some(vec![(unassigned_node.node_id, vec![recovery_public_key])]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        payload,
    ));

    // Orchestrator updates checks if there is a new version of the registry every
    // 10 seconds. If so, it updates first the readonly, then the backup and then
    // the recovery keys. If recovery key can authenticate we know that the
    // readonly and backup keys are already updated too.
    info!(
        logger,
        "Waiting for recovery authentication to be granted on app node..."
    );
    wait_until_authentication_is_granted(&logger, &node_ip, "recovery", &recovery_mean);
    info!(
        logger,
        "Readonly and backup authentication should now also be granted on app node."
    );
    assert_authentication_works(&node_ip, "backup", &backup_mean);
    assert_authentication_works(&node_ip, "readonly", &readonly_mean);
    info!(
        logger,
        "Waiting for recovery authentication to be granted on unassigned node..."
    );
    wait_until_authentication_is_granted(&logger, &unassigned_node_ip, "recovery", &recovery_mean);
    info!(
        logger,
        "Readonly authentication should now also be granted on unassigned node."
    );
    assert_authentication_works(&unassigned_node_ip, "readonly", &readonly_mean);

    info!(logger, "Restarting the app node orchestrator...");
    app_node
        .block_on_bash_script("sudo systemctl restart ic-replica")
        .unwrap();
    info!(logger, "Restarting the unassigned node orchestrator...");
    unassigned_node
        .block_on_bash_script("sudo systemctl restart ic-replica")
        .unwrap();

    info!(
        logger,
        "Making sure that the app and unassigned nodes still accept connections until the app replica \
        is healthy again..."
    );
    const CHECK_INTERVAL: Duration = Duration::from_secs(2);
    while !app_node.status_is_healthy().is_ok_and(|healthy| healthy) {
        assert_authentication_works(&node_ip, "recovery", &recovery_mean);
        assert_authentication_works(&node_ip, "backup", &backup_mean);
        assert_authentication_works(&node_ip, "readonly", &readonly_mean);
        assert_authentication_works(&unassigned_node_ip, "recovery", &recovery_mean);
        assert_authentication_works(&unassigned_node_ip, "readonly", &readonly_mean);
        // Unassigned nodes do not have backup keys
        assert_authentication_fails(&unassigned_node_ip, "backup", &backup_mean);

        std::thread::sleep(CHECK_INTERVAL);
    }
    // In the unlucky case where the app replica became healthy so fast that the orchestrators did
    // not even have the chance to update their keys (i.e. possibly remove), we check again for 10
    // seconds.
    info!(logger, "Checking again for longer to be sure...");
    for _ in 0..((ORCHESTRATOR_TASK_CHECK_INTERVAL.as_secs() + 1) / CHECK_INTERVAL.as_secs()) {
        assert_authentication_works(&node_ip, "recovery", &recovery_mean);
        assert_authentication_works(&node_ip, "backup", &backup_mean);
        assert_authentication_works(&node_ip, "readonly", &readonly_mean);
        assert_authentication_works(&unassigned_node_ip, "recovery", &recovery_mean);
        assert_authentication_works(&unassigned_node_ip, "readonly", &readonly_mean);
        // Unassigned nodes do not have backup keys
        assert_authentication_fails(&unassigned_node_ip, "backup", &backup_mean);

        std::thread::sleep(CHECK_INTERVAL);
    }
}

fn node_keeps_keys_until_it_completely_leaves_its_subnet(env: TestEnv) {
    let logger = env.logger();
    let topology = env.topology_snapshot();
    let (nns_node, app_node, _, app_subnet) = topology_entities(topology.clone());

    let app_subnet_id = app_subnet.subnet_id;
    let node_ip: IpAddr = app_node.get_ip_addr();

    info!(logger, "Updating the registry with new pairs of keys...");
    let (readonly_mean, readonly_public_key) = generate_key_and_auth_mean();
    let (backup_mean, backup_public_key) = generate_key_and_auth_mean();
    let (recovery_mean, recovery_public_key) = generate_key_and_auth_mean();
    let payload = get_update_subnet_payload_with_keys(
        app_subnet_id,
        Some(vec![readonly_public_key]),
        Some(vec![backup_public_key]),
    );
    block_on(update_subnet_record(nns_node.get_public_url(), payload));
    let payload = get_set_subnet_operational_level_payload_with_keys(
        Some(app_subnet_id),
        None,
        Some(vec![(app_node.node_id, vec![recovery_public_key])]),
    );
    block_on(set_subnet_operational_level(
        nns_node.get_public_url(),
        payload,
    ));
    let topology = block_on(topology.block_for_newer_registry_version()).unwrap();

    // Orchestrator updates checks if there is a new version of the registry every
    // 10 seconds. If so, it updates first the readonly, then the backup and then
    // the recovery keys. If recovery key can authenticate we know that the
    // readonly and backup keys are already updated too.
    info!(
        logger,
        "Waiting for recovery authentication to be granted..."
    );
    wait_until_authentication_is_granted(&logger, &node_ip, "recovery", &recovery_mean);
    info!(
        logger,
        "Readonly and backup authentication should now also be granted."
    );
    assert_authentication_works(&node_ip, "backup", &backup_mean);
    assert_authentication_works(&node_ip, "readonly", &readonly_mean);

    info!(logger, "Removing the node from its subnet...");
    block_on(remove_nodes_via_endpoint(
        nns_node.get_public_url(),
        &[app_node.node_id],
    ))
    .expect("Failed to remove node from subnet");
    let registry_version_without_node = block_on(topology.block_for_newer_registry_version())
        .unwrap()
        .get_registry_version();
    info!(
        logger,
        "Registry version without the node: {}", registry_version_without_node
    );

    // The node should keep its current keys until it completely leaves the subnet, i.e. until the
    // oldest registry version in use is greater or equal to the version where the node was
    // removed. In practice, this will be in one of the following DKG intervals.
    loop {
        // Once the node leaves the subnet, the orchestrator shuts down the replica, including the
        // metrics endpoint, in which case the below call would be an Err. But if that is the case,
        // and after waiting 2 check intervals below, then we should not be able to login and we
        // should break out of the loop. And if we don't, then the `expect` afterwards will catch
        // that.
        let maybe_earliest_registry_version_in_use = get_node_earliest_topology_version(&app_node);

        info!(
            logger,
            "Node's earliest registry version in use: {:?}. Waiting a bit for the orchestrator to \
            update its keys if it is time to do so...",
            maybe_earliest_registry_version_in_use
        );

        // We wait for the orchestrator to 1) read the CUP and 2) check for new keys to give it the
        // chance to remove the keys when finally leaving the subnet.
        std::thread::sleep(2 * ORCHESTRATOR_TASK_CHECK_INTERVAL + Duration::from_secs(1));

        if SshSession::default()
            .login(&node_ip, "backup", &backup_mean)
            .is_err()
        {
            break;
        }

        info!(logger, "Backup authentication still works.");

        let earliest_registry_version_in_use = maybe_earliest_registry_version_in_use.expect(
            "The node kept access to the backup account even though it left the subnet. Indeed, \
            the metrics endpoint is down, so the replica process must have been stopped.",
        );

        assert!(
            earliest_registry_version_in_use < registry_version_without_node,
            "The node kept access to the backup account even though it should have detected by \
            the oldest registry version in use that it left the subnet.",
        );
    }
    // "readonly" access is removed first, so this must hold
    assert_authentication_fails(&node_ip, "readonly", &readonly_mean);

    // Now that the node has removed its SSH access, it must be that the replica process has been
    // stopped, so the metrics endpoints should be down.
    let maybe_earliest_registry_version_in_use = get_node_earliest_topology_version(&app_node);
    assert!(
        maybe_earliest_registry_version_in_use.is_err(),
        "The node removed access to the backup account before completely leaving the subnet"
    );

    // Finally, recovery access should still work because it is not a subnet property, but a node
    // property instead.
    assert_authentication_works(&node_ip, "recovery", &recovery_mean);
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(ssh_users_cannot_authenticate_with_easy_password))
        .add_test(systest!(ssh_users_cannot_authenticate_without_a_key))
        .add_test(systest!(ssh_users_cannot_authenticate_with_random_key))
        .add_test(systest!(keys_in_the_subnet_record_can_be_updated))
        .add_test(systest!(keys_in_the_node_record_can_be_updated))
        .add_test(systest!(
            set_subnet_operational_level_updates_readonly_and_recovery_keys
        ))
        .add_test(systest!(keys_for_unassigned_nodes_can_be_updated))
        .add_test(systest!(multiple_keys_can_access_one_account))
        .add_test(systest!(
            multiple_keys_can_access_one_account_on_unassigned_nodes
        ))
        .add_test(systest!(updating_readonly_does_not_remove_backup_keys))
        .add_test(systest!(
            updating_recovery_does_not_remove_readonly_and_backup_keys
        ))
        .add_test(systest!(can_add_max_number_of_keys))
        .add_test(systest!(cannot_add_more_than_max_number_of_keys))
        .add_test(systest!(node_does_not_remove_keys_on_restart))
        .add_test(systest!(
            node_keeps_keys_until_it_completely_leaves_its_subnet
        ))
        .execute_from_args()?;

    Ok(())
}
