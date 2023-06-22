/* tag::catalog[]
Title:: Boundary nodes integration test

Goal:: Test if the Boundary handles raw and non-raw traffic as expected.

Runbook::
. Setup:
    . A running BN VM.
    . A subnet with 1 HTTP canister and 1 non-HTTP canister, both counters.
. Call into the non-HTTP canister, expecting the counter to increment.
. Call into the HTTP canister, expecting the counter to increment.
. Update the denylist to block the HTTP canister.
. Call into the HTTP canister again, but expecting a 451.

Success::
. The calls succeed with the expected values.
end::catalog[] */

use crate::driver::{
    api_boundary_node::{ApiBoundaryNode, ApiBoundaryNodeVm},
    ic::{InternetComputer, Subnet},
    test_env::TestEnv,
    test_env_api::{
        retry_async, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer, NnsInstallationBuilder,
        RetrieveIpv4Addr, SshSession, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
    },
};

use std::{convert::TryFrom, io::Read, time::Duration};

use anyhow::{Context, Error};
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::routing_table::v1::RoutingTable as PbRoutingTable;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use slog::info;

const API_BOUNDARY_NODE_NAME: &str = "boundary-node-1";

struct PanicHandler {
    env: TestEnv,
    is_enabled: bool,
}

impl PanicHandler {
    fn new(env: TestEnv) -> Self {
        Self {
            env,
            is_enabled: true,
        }
    }

    fn disable(&mut self) {
        self.is_enabled = false;
    }
}

impl Drop for PanicHandler {
    fn drop(&mut self) {
        if !self.is_enabled {
            return;
        }

        std::thread::sleep(Duration::from_secs(60));

        let logger = self.env.logger();

        let boundary_node = self
            .env
            .get_deployed_api_boundary_node(API_BOUNDARY_NODE_NAME)
            .unwrap()
            .get_snapshot()
            .unwrap();

        let (list_dependencies, exit_status) = exec_ssh_command(
            &boundary_node,
            "systemctl list-dependencies systemd-sysusers.service --all --reverse --no-pager",
        )
        .unwrap();

        info!(
            logger,
            "systemctl {API_BOUNDARY_NODE_NAME} = '{list_dependencies}'. Exit status = {}",
            exit_status,
        );
    }
}

fn exec_ssh_command(vm: &dyn SshSession, command: &str) -> Result<(String, i32), Error> {
    let mut channel = vm.block_on_ssh_session()?.channel_session()?;

    channel.exec(command)?;

    let mut output = String::new();
    channel.read_to_string(&mut output)?;
    channel.wait_close()?;

    Ok((output, channel.exit_status()?))
}

#[derive(Copy, Clone)]
pub enum ApiBoundaryNodeHttpsConfig {
    /// Acquire a playnet certificate (or fail if all have been acquired already)
    /// for the domain `ic{ix}.farm.dfinity.systems`
    /// where `ix` is the index of the acquired playnet.
    ///
    /// Then create an AAAA record pointing
    /// `ic{ix}.farm.dfinity.systems` to the IPv6 address of the BN.
    ///
    /// Also add CNAME records for
    /// `*.ic{ix}.farm.dfinity.systems` and
    /// `*.raw.ic{ix}.farm.dfinity.systems`
    /// pointing to `ic{ix}.farm.dfinity.systems`.
    ///
    /// If IPv4 has been enabled for the BN (`has_ipv4`),
    /// also add a corresponding A record pointing to the IPv4 address of the BN.
    ///
    /// Finally configure the BN with the playnet certificate.
    ///
    /// Note that if multiple BNs are created within the same
    /// farm-group, they will share the same certificate and
    /// domain name.
    /// Also all their IPv6 addresses will be added to the AAAA record
    /// and all their IPv4 addresses will be added to the A record.
    UseRealCertsAndDns,

    /// Don't create real certificates and DNS records,
    /// instead dangerously accept self-signed certificates and
    /// resolve domains on the client-side without quering DNS.
    AcceptInvalidCertsAndResolveClientSide,
}

pub fn mk_setup(api_bn_https_config: ApiBoundaryNodeHttpsConfig) -> impl Fn(TestEnv) {
    move |env: TestEnv| {
        setup(api_bn_https_config, env);
    }
}

fn setup(api_bn_https_config: ApiBoundaryNodeHttpsConfig, env: TestEnv) {
    let logger = env.logger();

    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .install(&nns_node, &env)
        .expect("Could not install NNS canisters");

    let api_bn = ApiBoundaryNode::new(String::from(API_BOUNDARY_NODE_NAME))
        .allocate_vm(&env)
        .unwrap()
        .for_ic(&env, "");
    let api_bn = match api_bn_https_config {
        ApiBoundaryNodeHttpsConfig::UseRealCertsAndDns => api_bn.use_real_certs_and_dns(),
        ApiBoundaryNodeHttpsConfig::AcceptInvalidCertsAndResolveClientSide => api_bn,
    };
    api_bn
        .start(&env)
        .expect("failed to setup ApiBoundaryNode VM");

    // Await Replicas
    info!(&logger, "Checking readiness of all replica nodes...");
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy()
                .expect("Replica did not come up healthy.");
        }
    }

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    info!(&logger, "Polling registry");
    let registry = RegistryCanister::new(api_bn.nns_node_urls);
    let (latest, routes) = rt.block_on(retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
        let (bytes, latest) = registry.get_value(make_routing_table_record_key().into(), None).await
            .context("Failed to `get_value` from registry")?;
        let routes = PbRoutingTable::decode(bytes.as_slice())
            .context("Failed to decode registry routes")?;
        let routes = RoutingTable::try_from(routes)
            .context("Failed to convert registry routes")?;
        Ok((latest, routes))
    }))
    .expect("Failed to poll registry. This is not a Boundary Node error. It is a test environment issue.");
    info!(&logger, "Latest registry {latest}: {routes:?}");

    // Await Boundary Node
    let api_boundary_node = env
        .get_deployed_api_boundary_node(API_BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    info!(
        &logger,
        "API Boundary node {API_BOUNDARY_NODE_NAME} has IPv6 {:?}",
        api_boundary_node.ipv6()
    );
    info!(
        &logger,
        "API Boundary node {API_BOUNDARY_NODE_NAME} has IPv4 {:?}",
        api_boundary_node.block_on_ipv4().unwrap()
    );

    info!(&logger, "Waiting for routes file");
    let routes_path = "/var/opt/nginx/ic/ic_routes.js";
    let sleep_command = format!("while grep -q '// PLACEHOLDER' {routes_path}; do sleep 5; done");
    let (cmd_output, exit_status) = exec_ssh_command(&api_boundary_node, &sleep_command).unwrap();
    info!(
        logger,
        "{API_BOUNDARY_NODE_NAME} ran `{sleep_command}`: '{}'. Exit status = {exit_status}",
        cmd_output.trim(),
    );

    info!(&logger, "Checking API BN health");
    api_boundary_node
        .await_status_is_healthy()
        .expect("Boundary node did not come up healthy.");
}

/* tag::catalog[]
Title:: API BN no-op test

Goal:: None

Runbook:
. N/A

Success:: Solar flares don't cause this test to crash

Coverage:: 1+1 still equals 2

end::catalog[] */

pub fn noop_test(env: TestEnv) {
    let logger = env.logger();

    let mut panic_handler = PanicHandler::new(env.clone());

    let _api_boundary_node = env
        .get_deployed_api_boundary_node(API_BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        info!(&logger, "Nothing...");
    });

    panic_handler.disable();
}
