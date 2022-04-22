/* tag::catalog[]
Title:: Boundary nodes integration test
end::catalog[] */

use crate::driver::boundary_node::{BoundaryNode, BoundaryNodeVm};
use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::pot_dsl::get_ic_handle_and_ctx;
use crate::driver::test_env::{HasIcPrepDir, TestEnv};
use crate::driver::test_env_api::{
    HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationExt, RetrieveIpv4Addr,
    SshSession, ADMIN,
};
use std::io::Read;
use std::net::Ipv4Addr;

use ic_registry_subnet_type::SubnetType;
use slog::info;

const BOUNDARY_NODE_NAME: &str = "boundary-node-1";

pub fn config(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(4))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let (handle, _ctx) = get_ic_handle_and_ctx(env.clone(), env.logger());

    env.topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap()
        .install_nns_canisters()
        .expect("Could not install NNS canisters");

    let nns_urls = handle
        .public_api_endpoints
        .iter()
        .filter(|ep| ep.is_root_subnet)
        .map(|ep| ep.url.clone())
        .collect();

    BoundaryNode::new(String::from(BOUNDARY_NODE_NAME))
        .with_nns_urls(nns_urls)
        .with_nns_public_key(env.prep_dir("").unwrap().root_public_key_path())
        .start(&env)
        .expect("failed to setup universal VM");
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let deployed_boundary_node = env.get_deployed_boundary_node(BOUNDARY_NODE_NAME).unwrap();
    let boundary_node_vm = deployed_boundary_node.get_vm().unwrap();
    info!(
        &logger,
        "Boundary node {BOUNDARY_NODE_NAME} has IPv6: {:?}", boundary_node_vm.ipv6
    );

    let boundary_node_ipv4: Ipv4Addr = deployed_boundary_node.block_on_ipv4().unwrap();
    info!(
        &logger,
        "Boundary node {BOUNDARY_NODE_NAME} has IPv4 {:?}", boundary_node_ipv4
    );

    // Example of SSH access to Boundary Nodes:
    let sess = deployed_boundary_node.block_on_ssh_session(ADMIN).unwrap();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("uname -a").unwrap();
    let mut uname = String::new();
    channel.read_to_string(&mut uname).unwrap();
    channel.wait_close().unwrap();
    info!(
        logger,
        "uname of {BOUNDARY_NODE_NAME} = '{}'. Exit status = {}",
        uname.trim(),
        channel.exit_status().unwrap()
    );

    info!(&logger, "Checking readiness of all nodes...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy().unwrap();

            // Example of SSH access to IC nodes:
            let sess = node.block_on_ssh_session(ADMIN).unwrap();
            let mut channel = sess.channel_session().unwrap();
            channel.exec("hostname").unwrap();
            let mut hostname = String::new();
            channel.read_to_string(&mut hostname).unwrap();
            info!(
                logger,
                "Hostname of node {:?} = '{}'",
                node.node_id,
                hostname.trim()
            );
            channel.wait_close().unwrap();
        }
    }
}

/* tag::catalog[]
Title:: Boundary nodes nginx test

Goal:: Verify that nginx configuration is correct by running `nginx -T` on the boundary node.

Runbook:
. Set up a subnet with 4 nodes and a boundary node.
. SSH into the boundary node and execute `sudo nginx -t`

Success:: The output contains the string
`nginx: configuration file /etc/nginx/nginx.conf test is successful`

Coverage:: NGINX configuration is not broken

end::catalog[] */

pub fn nginx_test(env: TestEnv) {
    let logger = env.logger();
    let deployed_boundary_node = env.get_deployed_boundary_node(BOUNDARY_NODE_NAME).unwrap();

    // SSH into Boundary Nodes:
    let sess = deployed_boundary_node.block_on_ssh_session(ADMIN).unwrap();
    let mut channel = sess.channel_session().unwrap();
    channel.exec("sudo nginx -t 2>&1").unwrap();
    let mut nginx_result = String::new();
    channel.read_to_string(&mut nginx_result).unwrap();
    channel.wait_close().unwrap();
    info!(
        logger,
        "nginx test result = '{}'. Exit status = {}",
        nginx_result.trim(),
        channel.exit_status().unwrap()
    );
    if !nginx_result.trim().contains("test is successful") {
        panic!("NGINX test failed.");
    }
}
