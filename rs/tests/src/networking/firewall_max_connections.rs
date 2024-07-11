/* tag::catalog[]
Title:: Firewall limit connection count.

Goal:: Verify that nodes set a hard limit on number of simultaneous connections from a single IP addresses as defined in the firewall.

Runbook::
. Set up a test net, application typ, with 2 nodes.
. Set up a universal vm with default config.
. Set `max_simultaneous_connections_per_ip_address` to the configured value `max_simultaneous_connections_per_ip_address` in template file
`ic.json5.template`.
. Create `max_simultaneous_connections_per_ip_address` tcp connections from the driver simultaneously to a node and keep the connections alive.
. Verify that the universal vm can create a tcp connection the node.
. Verify the driver is unable to create new tcp connections to the node.
. Terminate one of the active connections the driver has to the node.
. Verify the node now accepts one connection at a time on ports [8080, 9090, 9091, 9100] from the driver.
. All connectivity tests succeed as expected

end::catalog[] */

use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, SshSession},
        universal_vm::{UniversalVm, UniversalVms},
    },
    util::block_on,
};
use slog::{debug, info};
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;

/// This value reflects the value `max_simultaneous_connections_per_ip_address` in the firewall config file.
const MAX_SIMULTANEOUS_CONNECTIONS_PER_IP_ADDRESS: usize = 1000;

const UNIVERSAL_VM_NAME: &str = "httpbin";

const TCP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

pub fn config(env: TestEnv) {
    let log = env.logger();

    info!(log, "Starting new universal VM");
    UniversalVm::new(String::from(UNIVERSAL_VM_NAME))
        .start(&env)
        .expect("failed to setup universal VM");

    info!(log, "Universal VM successfully deployed.");
    InternetComputer::new()
        .add_subnet(Subnet::fast(SubnetType::Application, 2))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let topology = env.topology_snapshot();
    topology.subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn connection_count_test(env: TestEnv) {
    let log = env.logger();
    let topology = env.topology_snapshot();

    let node_with_firewall = topology
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .nodes()
        .next()
        .unwrap();

    let deployed_universal_vm = env
        .get_deployed_universal_vm(UNIVERSAL_VM_NAME)
        .expect("unable to get deployed VM.");

    let universal_vm = deployed_universal_vm.get_vm().unwrap();

    let node_ip_addr = node_with_firewall.get_ip_addr();

    debug!(
        log,
        "`max_simultaneous_connections_per_ip_address` = {}, VM IP = {}, node Ip = {}",
        MAX_SIMULTANEOUS_CONNECTIONS_PER_IP_ADDRESS,
        universal_vm.ipv6,
        node_ip_addr
    );

    info!(
        log,
        "Attempting to create `max_simultaneous_connections_per_ip_address` tcp connections from driver to the node."
    );

    let mut streams = Vec::with_capacity(MAX_SIMULTANEOUS_CONNECTIONS_PER_IP_ADDRESS);

    for connection_number in 0..MAX_SIMULTANEOUS_CONNECTIONS_PER_IP_ADDRESS {
        let stream = block_on(create_tcp_connection(node_ip_addr, 9090));
        match stream {
            Ok(stream) => streams.push(stream),
            Err(_) => {
                panic!("Could not create connection {}#. Connection is below the limit of active connections defined in the firewall, and should be accepted", connection_number);
            }
        }
    }

    info!(
        log,
        "Created `max_simultaneous_connections_per_ip_address` tcp connections successfully. Now attempting to perform tcp handshakes from the virtual vm to the node."
    );

    //  Connect to VM with SSH and establish TCP connection to the node.

    let script = format!("nc -z {} {}", node_ip_addr, 9090);

    let result: String = deployed_universal_vm
        .block_on_bash_script(&script)
        .expect("Couldn't run bash script over ssh.");

    info!(
        log,
        "Universal VM successfully connected the the node. STDOUT: {}", result
    );

    //  Make connections from driver to node that should be rejected.

    info!(
        log,
        "Making a connection from driver to the node that should be rejected by the firewall!"
    );

    let ports = vec![8080, 9090, 9091, 9100];

    for port in &ports {
        debug!(log, "Attempting connection on port: {}", *port);
        let connection = block_on(create_tcp_connection(node_ip_addr, *port));
        assert!(
            connection.is_err(),
            "Was able to make more requests than the configured firewall limit"
        );
    }
    info!(
        log,
        "{} {}",
        "All connection attempts over firewall limit were rejected by the node.",
        "Terminating an existing connection, to verify new one can be established."
    );

    drop(streams.pop());

    for port in &ports {
        debug!(log, "Attempting connection on port: {}", *port);
        let connection = block_on(create_tcp_connection(node_ip_addr, *port));
        assert!(
            connection.is_ok(),
            "Was not able to make new connection after dropping previous connections",
        );
    }
}

/// Helper function to make a tcp connection where the server
/// can drop incoming connections.
async fn create_tcp_connection(ip_addr: IpAddr, port: u16) -> Result<TcpStream, ()> {
    let tcp =
        tokio::time::timeout(TCP_HANDSHAKE_TIMEOUT, TcpStream::connect((ip_addr, port))).await;

    match tcp {
        Ok(Ok(stream)) => Ok(stream),
        _ => Err(()),
    }
}
