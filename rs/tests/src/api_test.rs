/* tag::catalog[]
Title:: System test API tests

Goal:: Ensure that API works as expected

Runbook::
. Set up two ICs
. Verify that the number of subnets is as expected
. Verify that nodes can be killed, started and rebooted
. Verify that files can be uploaded and downloaded

end::catalog[] */

use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::*;
//use crate::driver::test_env::TestEnv;
//use crate::driver::test_env_api::{HasHttpFileStore};
use ic_registry_subnet_type::SubnetType;
use slog::{info, Logger};
use std::fs::File;

/// Create two ICs, a no-name IC and a named one which differ in their topology.
pub fn two_ics(test_env: TestEnv) {
    let mut ic = InternetComputer::new().add_subnet(Subnet::new(SubnetType::System).add_nodes(4));
    ic.setup_and_start(&test_env)
        .expect("Could not start no-name IC");

    let mut ic2 = InternetComputer::new()
        .with_name("two_subnets")
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application);
    ic2.setup_and_start(&test_env)
        .expect("Could not start second IC");
}

pub fn ics_have_correct_subnet_count(test_env: TestEnv, _logger: Logger) {
    let topo_snapshot = test_env.topology_snapshot();
    assert_eq!(topo_snapshot.subnets().count(), 1);

    let topo_snapshot2 = test_env.topology_snapshot_by_name("two_subnets");
    assert_eq!(topo_snapshot2.subnets().count(), 2);
}

pub fn upload_file_to_farm(test_env: TestEnv, _: Logger) {
    test_env
        .write_object("uploaded", &String::from("magic"))
        .expect("failed to write to env");
    let fm = test_env.http_file_store();
    let fh = fm
        .upload(test_env.get_path("uploaded"))
        .expect("failed to upload file to farm");
    let sink = File::create(test_env.get_path("downloaded")).expect("cannot create output file");
    fh.download(Box::new(sink))
        .expect("failed to download file from farm");

    let uploaded: String = test_env.read_object("uploaded").unwrap();
    let downloaded: String = test_env.read_object("downloaded").unwrap();
    assert_eq!(uploaded, downloaded);
}

pub fn vm_control(test_env: TestEnv, logger: Logger) {
    info!(&logger, "Checking readiness of all nodes...");
    for subnet in test_env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy().unwrap();
        }
    }
    info!(logger, "All nodes are ready starting test...");
    // get one node per subnet, then restart them
    let nodes: Vec<_> = test_env
        .topology_snapshot()
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
        assert!(n.status_is_healthy().unwrap(), "{}", true);
        info!(logger, "Rebooting the node ...");
        n.vm().reboot();
        info!(
            logger,
            "Waiting for the node to become healthy after reboot ..."
        );
        n.await_status_is_healthy()
            .expect("Node did not report healthy status");
        assert!(n.status_is_healthy().unwrap(), "{}", true);
    });
}
