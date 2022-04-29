//! This module contains "API" tests. On the one hand, it tests basic methods
//! provided by the test API. On the other, it acts as a showcase for the API
//! itself.
//!
//! For more information about the Test Environment API itself, please see
//! [crate::driver::test_env_api].

use crate::driver::{
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
    test_env_api::*,
};
use ic_registry_subnet_type::SubnetType;
use slog::info;
use std::fs::File;

/// The following setup function demonstrates how to create more than one
/// Internet Computer instances within a setup function.
pub fn setup_two_ics(test_env: TestEnv) {
    // In most test scenarios, only a single IC is required. The following is an
    // example of an Internet Computer with a single subnet of type `System`
    // with four nodes.
    let mut ic = InternetComputer::new().add_subnet(Subnet::new(SubnetType::System).add_nodes(4));
    ic.setup_and_start(&test_env)
        .expect("Could not start no-name IC");

    // The `InternetComputer` builder pattern provides a method
    // `.with_name(name: &str)`. If more than one Internet Computer is started,
    // their names must be different. Not providing a name is equivalent to
    // calling `.with_name()` with an empty string.
    InternetComputer::new()
        .with_name("two_subnets")
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&test_env)
        .expect("Could not start second IC");
}

/// The following test demonstrates how to access the topology of both, a named
/// and unnamed Internet Computer instance.
///
/// See the [TopologySnapshot] and the documentation in the
/// [crate::driver::test_env_api] for more information.
pub fn ics_have_correct_subnet_count(test_env: TestEnv) {
    let topo_snapshot = test_env.topology_snapshot();
    assert_eq!(topo_snapshot.subnets().count(), 1);

    let topo_snapshot2 = test_env.topology_snapshot_by_name("two_subnets");
    assert_eq!(topo_snapshot2.subnets().count(), 2);
}

/// Farm can be used to upload auxiliary files and make them available [to the
/// system under test] via http.
///
/// This is used, e.g., in recovery tests to publish recovery CUPs that are
/// referenced via HTTP in governance proposals.
pub fn upload_file_to_farm(test_env: TestEnv) {
    test_env
        .write_json_object("uploaded", &String::from("magic"))
        .expect("failed to write to env");
    let fm = test_env.http_file_store();
    let fh = fm
        .upload(test_env.get_json_path("uploaded"))
        .expect("failed to upload file to farm");
    let sink =
        File::create(test_env.get_json_path("downloaded")).expect("cannot create output file");
    fh.download(Box::new(sink))
        .expect("failed to download file from farm");

    let uploaded: String = test_env.read_json_object("uploaded").unwrap();
    let downloaded: String = test_env.read_json_object("downloaded").unwrap();
    assert_eq!(uploaded, downloaded);
}

/// Entities that are instantiated as Virtual Machines (such as IC Nodes,
/// Boundary Nodes, etc.) implement the `HasVm` trait.
///
/// NOTE: If this test will most likely interfere with other tests that run in
/// parallel to this test.
pub fn vm_control(test_env: TestEnv) {
    let logger = test_env.logger();
    info!(&logger, "Checking readiness of all nodes...");
    for subnet in test_env.topology_snapshot_by_name("two_subnets").subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy().unwrap();
        }
    }
    info!(logger, "All nodes are ready starting test...");
    // get one node per subnet, then restart them
    let nodes: Vec<_> = test_env
        .topology_snapshot_by_name("two_subnets")
        .subnets()
        .map(|s| s.nodes().next().unwrap())
        .collect();
    nodes.iter().for_each(|n| {
        info!(logger, "Killing the node {:?} ...", n.node_id);
        n.vm().kill();
        info!(logger, "Node killed, assert health status is error ...");
        assert!(n.status_is_healthy().is_err());
        info!(logger, "Starting the node ...");
        n.vm().start();
        info!(
            logger,
            "Waiting for the node to become healthy after starting ..."
        );
        n.await_status_is_healthy()
            .expect("Node did not report healthy status");
        info!(logger, "Rebooting the node ...");
        n.vm().reboot();
        info!(
            logger,
            "Waiting for the node to become healthy after reboot ..."
        );
        n.await_status_is_healthy()
            .expect("Node did not report healthy status");
    });
}

/// Install a counter canister by loading the corresponding `counter.wat` from
/// the artifacts directory.
pub fn install_counter_canister(test_env: TestEnv) {
    let topo_snapshot = test_env.topology_snapshot();

    let node = topo_snapshot
        .subnets()
        .next()
        .unwrap()
        .nodes()
        .next()
        .unwrap();
    node.await_status_is_healthy().unwrap();
    let canister_id = node.create_and_install_canister_with_arg("counter.wat", None);

    let counter_state = node.with_default_agent(move |agent| async move {
        agent.query(&canister_id, "read").call().await.unwrap()
    });

    assert_eq!(counter_state, vec![0; 4]);
}
