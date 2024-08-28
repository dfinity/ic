/* tag::catalog[]

Title:: Upgrade with alternative URL

Goal:: Orchestrator can download the release package, even when the replica version record
contains many faulty and only one valid URLs download URLs.

Description::
We deploy a fast single node subnet. Then, we make a proposal and bless a replica version
with one valid and multiple invalid download URLs. Then, we propose to upgrade the replica
version of that subnet to the newly blessed version. We expect that the orchestrator can
download the release image via the valid URL.

Runbook::
. Deploy an IC with a single-node root subnet.
. Bless the test replica version with multiple URLs, among which only one is correct.
. Upgrade the replica version of the subnet to the newly blessed replica version.

Success::
. The replica restarts, which is a sign of the node having downloaded and verified the new
replica version package.

end::catalog[] */

use ic_consensus_system_test_utils::rw_message::install_nns_and_check_progress;
use ic_consensus_system_test_utils::upgrade::{
    assert_assigned_replica_version, bless_replica_version_with_urls,
    deploy_guestos_to_all_subnet_nodes, get_assigned_replica_version, UpdateImageType,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::*,
    },
    util::{block_on, get_nns_node},
};
use ic_types::{Height, ReplicaVersion};
use slog::info;
use std::convert::TryFrom;

const DKG_INTERVAL: u64 = 9;

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(
            Subnet::fast_single_node(SubnetType::System)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL)),
        )
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    install_nns_and_check_progress(env.topology_snapshot());
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let nns_node = get_nns_node(&env.topology_snapshot());
    let subnet_id = env.topology_snapshot().root_subnet_id();

    let original_version = get_assigned_replica_version(&nns_node).unwrap();
    info!(logger, "Original replica version: {}", original_version);

    let upgrade_url = get_ic_os_update_img_test_url().expect("no image URL");
    info!(logger, "Upgrade URL: {}", upgrade_url);

    // A list of URLs, among which only one is valid:
    let release_package_urls = vec![
        "http://invalid.test-url.dfinity.network:0001".to_string(),
        "http://invalid.test-url.dfinity.network:0002".to_string(),
        upgrade_url.to_string(),
        "http://invalid.test-url.dfinity.network:0004".to_string(),
        "http://invalid.test-url.dfinity.network:0005".to_string(),
    ];

    info!(
        logger,
        "Blessing the test replica version with multiple URLs: {:?}", release_package_urls
    );
    block_on(bless_replica_version_with_urls(
        &nns_node,
        &original_version,
        UpdateImageType::ImageTest,
        release_package_urls,
        get_ic_os_update_img_test_sha256().expect("no SHA256 hash"),
        &logger,
    ));

    info!(logger, "Proposing to upgrade the subnet replica version");
    let test_version = format!("{}-test", original_version);
    block_on(deploy_guestos_to_all_subnet_nodes(
        &nns_node,
        &ReplicaVersion::try_from(test_version.clone()).unwrap(),
        subnet_id,
    ));

    info!(logger, "Waiting until the subnet is upgraded");

    // Wait until the subnet is upgraded.
    assert_assigned_replica_version(&nns_node, &test_version, logger);
}
