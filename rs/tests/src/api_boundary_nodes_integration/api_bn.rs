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

use crate::{
    driver::{
        api_boundary_node::{ApiBoundaryNode, ApiBoundaryNodeVm},
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            retry_async, HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer,
            IcNodeSnapshot, NnsInstallationBuilder, RetrieveIpv4Addr, SshSession, TopologySnapshot,
            READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    util::{assert_create_agent, block_on},
};
use std::{convert::TryFrom, io::Read, net::SocketAddrV6, time::Duration};

use anyhow::{anyhow, bail, Context, Error};
use futures::{future::join_all, stream::FuturesUnordered};
use ic_agent::{agent::http_transport::ReqwestHttpReplicaV2Transport, export::Principal, Agent};
use ic_base_types::PrincipalId;
use ic_interfaces_registry::RegistryValue;
use ic_protobuf::registry::routing_table::v1::RoutingTable as PbRoutingTable;
use ic_registry_keys::make_routing_table_record_key;
use ic_registry_nns_data_provider::registry::RegistryCanister;
use ic_registry_routing_table::RoutingTable;
use ic_registry_subnet_type::SubnetType;
use ic_utils::interfaces::ManagementCanister;
use serde::Deserialize;
use slog::{error, info};
use tokio::runtime::Runtime;

const API_BOUNDARY_NODE_NAME: &str = "api-boundary-node-1";
const COUNTER_CANISTER_WAT: &str = include_str!("../counter.wat");

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

fn get_install_url(env: &TestEnv) -> Result<(url::Url, PrincipalId), Error> {
    let subnet = env
        .topology_snapshot()
        .subnets()
        .next()
        .ok_or_else(|| anyhow!("missing subnet"))?;

    let node = subnet
        .nodes()
        .next()
        .ok_or_else(|| anyhow!("missing node"))?;

    Ok((node.get_public_url(), node.effective_canister_id()))
}

async fn create_canister(
    agent: &Agent,
    effective_canister_id: PrincipalId,
    canister_bytes: &[u8],
    arg: Option<Vec<u8>>,
) -> Result<Principal, String> {
    // Create a canister.
    let mgr = ManagementCanister::create(agent);
    let canister_id = mgr
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait()
        .await
        .map_err(|err| format!("Couldn't create canister with provisional API: {}", err))?
        .0;

    let mut install_code = mgr.install_code(&canister_id, canister_bytes);
    if let Some(arg) = arg {
        install_code = install_code.with_raw_arg(arg)
    }

    install_code
        .call_and_wait()
        .await
        .map_err(|err| format!("Couldn't install canister: {}", err))?;

    Ok::<_, String>(canister_id)
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
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
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
    .expect("Failed to poll registry. This is not an API Boundary Node error. It is a test environment issue.");
    info!(&logger, "Latest registry {latest}: {routes:?}");

    // Await API Boundary Node
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
Title:: API BN binary canister test

Goal:: Install and query a binary canister

Runbook:
. Set up a subnet with 4 nodes and an API Boundary node.

Success:: The canister installs successfully and calls against it
return the expected responses

Coverage:: binary canisters behave as expected

end::catalog[] */

pub fn canister_test(env: TestEnv) {
    let logger = env.logger();

    let mut panic_handler = PanicHandler::new(env.clone());

    let mut install_node = None;
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            install_node = Some((node.get_public_url(), node.effective_canister_id()));
        }
    }

    let api_boundary_node = env
        .get_deployed_api_boundary_node(API_BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        info!(&logger, "Creating replica agent...");
        let agent = assert_create_agent(install_node.as_ref().unwrap().0.as_str()).await;

        info!(&logger, "installing canister");
        let canister_id = create_canister(
            &agent,
            install_node.unwrap().1,
            wat::parse_str(COUNTER_CANISTER_WAT).unwrap().as_slice(),
            None,
        )
        .await
        .expect("Could not create counter canister");

        info!(&logger, "created canister={canister_id}");

        // Wait for the canisters to finish installing
        // TODO: maybe this should be status calls?
        tokio::time::sleep(Duration::from_secs(5)).await;

        info!(&logger, "Creating BN agent...");
        let agent = retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            Ok(api_boundary_node.try_build_default_agent_async().await?)
        })
        .await
        .expect("Failed to create agent.");

        info!(&logger, "Calling read...");
        // We must retry the first request to a canister.
        // This is because a new canister might take a few seconds to show up in the BN's routing tables
        let read_result = retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            Ok(agent.query(&canister_id, "read").call().await?)
        })
        .await
        .unwrap();

        assert_eq!(read_result, [0; 4]);
    });

    panic_handler.disable();
}

/* tag::catalog[]
Title:: Handle incoming canister calls by the API boundary node.

Goal:: Verify that ic-boundary service of the API boundary node routes canister requests (query/call/read_state) on different subnets correctly.

Runbook:
. Setup:
    . Subnets(>=2) with node/s(>=1) on each subnet.
    . A single API boundary node.
. Install three counter canisters on each subnet.
. Set unique counter values on each canister via update (`write`) calls. All calls are executed via boundary node agent.
. Verify an OK execution status of each update call via read_state call.
. Retrieve counter values from each canister via query (`read`) call.
. Assert that retrieved values match the expected ones.

end::catalog[] */

pub fn canister_routing_test(env: TestEnv) {
    let log: slog::Logger = env.logger();
    let topology = env.topology_snapshot();
    let canisters_per_subnet = 3;
    let subnets = topology.subnets().count() as u32;
    assert!(subnets >= 2);
    // These values will be set via update `write` call. Each counter value is chosen to be unique.
    let canister_values: Vec<u32> = (0..canisters_per_subnet * subnets).collect();
    info!(
        log,
        "Installing {canisters_per_subnet} canisters on each of the {subnets} subnets ...",
    );
    let canister_ids: Vec<Principal> = block_on(async {
        install_canisters(
            topology,
            wat::parse_str(COUNTER_CANISTER_WAT).unwrap().as_slice(),
            canisters_per_subnet,
        )
        .await
    });
    info!(
        log,
        "All {} canisters ({canisters_per_subnet} per subnet) were successfully installed",
        canister_ids.len()
    );
    // As creating an agent requires a status call, the status endpoint is implicitly tested.
    let bn_agent = {
        let api_boundary_node = env
            .get_deployed_api_boundary_node(API_BOUNDARY_NODE_NAME)
            .unwrap()
            .get_snapshot()
            .unwrap();
        api_boundary_node.build_default_agent()
    };
    info!(
        log,
        "Incrementing counters on canisters via BN agent update calls ..."
    );
    block_on(set_counters_on_canisters(
        bn_agent.clone(),
        canister_ids.clone(),
        canister_values.clone(),
    ));
    info!(
        log,
        "Asserting expected counters on canisters via BN agent query calls ... "
    );
    let counters = block_on(read_counters_on_canisters(bn_agent, canister_ids));
    assert_eq!(counters, canister_values);
}

/* tag::catalog[]
Title:: API Boundary nodes valid Nginx configuration test

Goal:: Verify that nginx configuration is valid by running `nginx -T` on the API BN.

Runbook:
. Set up a subnet with 4 nodes and a API BN.
. SSH into the API BN and execute `sudo nginx -t`

Success:: The output contains the string
`nginx: configuration file /etc/nginx/nginx.conf test is successful`

Coverage:: NGINX configuration is not broken

end::catalog[] */

pub fn nginx_valid_config_test(env: TestEnv) {
    let logger = env.logger();

    let api_boundary_node = env
        .get_deployed_api_boundary_node(API_BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let (cmd_output, exit_status) =
        exec_ssh_command(&api_boundary_node, "sudo nginx -t 2>&1").unwrap();

    info!(
        logger,
        "nginx test result = '{}'. Exit status = {}",
        cmd_output.trim(),
        exit_status,
    );

    if !cmd_output.trim().contains("test is successful") {
        panic!("nginx config failed validation");
    }
}

pub fn redirect_http_to_https_test(env: TestEnv) {
    let logger = env.logger();

    let mut panic_handler = PanicHandler::new(env.clone());

    let api_boundary_node = env
        .get_deployed_api_boundary_node(API_BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let client_builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());
    let (client_builder, host) = if let Some(playnet) = api_boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(api_boundary_node.ipv6(), 443, 0, 0);
        let client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .resolve(host, bn_addr.into());
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    let futs = FuturesUnordered::new();

    futs.push(rt.spawn({
        let name = "redirect http to https";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client.get(format!("http://{host}/")).send().await?;

            if res.status() != reqwest::StatusCode::MOVED_PERMANENTLY {
                bail!("{name} failed: {}", res.status())
            }

            let location_hdr = res.headers().get("Location").unwrap().to_str().unwrap();
            if location_hdr != format!("https://{host}/") {
                bail!("{name} failed: wrong location header: {}", location_hdr)
            }

            Ok(())
        }
    }));

    rt.block_on(async move {
        let mut cnt_err = 0;
        info!(&logger, "waiting for subtests");

        for fut in futs {
            match fut.await {
                Ok(Err(err)) => {
                    error!(logger, "test failed: {}", err);
                    cnt_err += 1;
                }
                Err(err) => {
                    error!(logger, "test paniced: {}", err);
                    cnt_err += 1;
                }
                _ => {}
            }
        }

        match cnt_err {
            0 => Ok(()),
            _ => bail!("failed with {cnt_err} errors"),
        }
    })
    .expect("test suite failed");

    panic_handler.disable();
}

pub fn direct_to_replica_test(env: TestEnv) {
    let logger = env.logger();

    let mut panic_handler = PanicHandler::new(env.clone());

    let api_boundary_node = env
        .get_deployed_api_boundary_node(API_BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .expect("failed to get BN snapshot");

    let client_builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = api_boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(api_boundary_node.ipv6(), 443, 0, 0);
        let client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .resolve(host, bn_addr.into());
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let (install_url, effective_canister_id) =
        get_install_url(&env).expect("failed to get install url");

    let rt = Runtime::new().expect("failed to create tokio runtime");

    let futs = FuturesUnordered::new();

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "status from random node";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!("https://{host}/api/v2/status"))
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            #[derive(Deserialize)]
            struct Status {
                replica_health_status: String,
            }

            let body = res.bytes().await?;

            let Status {
                replica_health_status,
            } = serde_cbor::from_slice::<Status>(&body)?;

            if replica_health_status != "healthy" {
                bail!("{name} failed: status check failed: {replica_health_status}")
            }

            Ok(())
        }
    }));

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let logger = logger.clone();
        let client = client.clone();
        let install_url = install_url.clone();
        let name = "query random node";
        info!(&logger, "Starting subtest {}", name);

        async move {
            info!(&logger, "creating management agent");
            let agent = assert_create_agent(install_url.as_str()).await;

            info!(&logger, "creating canister");
            let cid = create_canister(
                &agent,
                effective_canister_id,
                wat::parse_str(COUNTER_CANISTER_WAT).unwrap().as_slice(),
                None,
            )
            .await
            .map_err(|err| anyhow!(format!("failed to create canister: {}", err)))?;

            // Wait for the canister to finish installing
            tokio::time::sleep(Duration::from_secs(5)).await;

            info!(&logger, "creating agent");
            let transport = ReqwestHttpReplicaV2Transport::create_with_client(
                format!("https://{host}/"),
                client,
            )?;

            let agent = Agent::builder().with_transport(transport).build()?;
            agent.fetch_root_key().await?;

            let out = agent.query(&cid, "read").call().await?;
            if !out.eq(&[0, 0, 0, 0]) {
                bail!(
                    "{name} failed: read failed with output {:?}, expected {:?}",
                    out,
                    &[0, 0, 0, 0],
                )
            }

            Ok(())
        }
    }));

    let host = host_orig;
    futs.push(rt.spawn({
        let logger = logger.clone();
        let client = client;
        let install_url = install_url;
        let name = "update random node";
        info!(&logger, "Starting subtest {}", name);

        async move {
            info!(&logger, "creating management agent");
            let agent = assert_create_agent(install_url.as_str()).await;

            info!(&logger, "creating canister");
            let cid = create_canister(
                &agent,
                effective_canister_id,
                wat::parse_str(COUNTER_CANISTER_WAT).unwrap().as_slice(),
                None,
            )
            .await
            .map_err(|err| anyhow!(format!("failed to create canister: {}", err)))?;

            // Wait for the canister to finish installing
            tokio::time::sleep(Duration::from_secs(5)).await;

            info!(&logger, "creating agent");
            let transport = ReqwestHttpReplicaV2Transport::create_with_client(
                format!("https://{host}/"),
                client,
            )?;

            let agent = Agent::builder().with_transport(transport).build()?;
            agent.fetch_root_key().await?;

            info!(&logger, "updating canister");
            agent.update(&cid, "write").call_and_wait().await?;

            info!(&logger, "querying canister");
            let out = agent.query(&cid, "read").call().await?;
            if !out.eq(&[1, 0, 0, 0]) {
                bail!(
                    "{name} failed: read failed with output {:?}, expected {:?}",
                    out,
                    &[1, 0, 0, 0],
                )
            }

            Ok(())
        }
    }));

    rt.block_on(async move {
        let mut cnt_err = 0;
        info!(&logger, "Waiting for subtests");

        for fut in futs {
            match fut.await {
                Ok(Err(err)) => {
                    error!(logger, "test failed: {}", err);
                    cnt_err += 1;
                }
                Err(err) => {
                    error!(logger, "test panicked: {}", err);
                    cnt_err += 1;
                }
                _ => {}
            }
        }

        match cnt_err {
            0 => Ok(()),
            _ => bail!("failed with {cnt_err} errors"),
        }
    })
    .expect("test suite failed");

    panic_handler.disable();
}

pub fn direct_to_replica_options_test(env: TestEnv) {
    let logger = env.logger();

    let mut panic_handler = PanicHandler::new(env.clone());

    let api_boundary_node = env
        .get_deployed_api_boundary_node(API_BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .expect("failed to get BN snapshot");

    let client_builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = api_boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(api_boundary_node.ipv6(), 443, 0, 0);
        let client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .resolve(host, bn_addr.into());
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let (install_url, effective_canister_id) =
        get_install_url(&env).expect("failed to get install url");

    let rt = Runtime::new().expect("failed to create tokio runtime");

    let cid = rt
        .block_on(async {
            info!(&logger, "creating management agent");
            let agent = assert_create_agent(install_url.as_str()).await;

            info!(&logger, "creating canister");
            let cid = create_canister(
                &agent,
                effective_canister_id,
                wat::parse_str(COUNTER_CANISTER_WAT).unwrap().as_slice(),
                None,
            )
            .await
            .map_err(|err| anyhow!(format!("failed to create canister: {}", err)))?;

            // Wait for the canister to finish installing
            tokio::time::sleep(Duration::from_secs(5)).await;

            let out: Result<Principal, Error> = Ok(cid);
            out
        })
        .expect("failed to initialize test");

    let futs = FuturesUnordered::new();

    struct TestCase {
        name: String,
        path: String,
        allowed_methods: String,
    }

    let test_cases = [
        TestCase {
            name: "status OPTIONS".into(),
            path: "/api/v2/status".into(),
            allowed_methods: "HEAD, GET".into(),
        },
        TestCase {
            name: "query OPTIONS".into(),
            path: format!("/api/v2/canister/{cid}/query"),
            allowed_methods: "HEAD, POST".into(),
        },
        TestCase {
            name: "call OPTIONS".into(),
            path: format!("/api/v2/canister/{cid}/call"),
            allowed_methods: "HEAD, POST".into(),
        },
        TestCase {
            name: "read_status OPTIONS".into(),
            path: format!("/api/v2/canister/{cid}/read_state"),
            allowed_methods: "HEAD, POST".into(),
        },
    ];

    for tc in test_cases {
        let client = client.clone();
        let logger = logger.clone();

        let TestCase {
            name,
            path,
            allowed_methods,
        } = tc;

        let host = host_orig.clone();
        futs.push(rt.spawn(async move {
            info!(&logger, "Starting subtest {}", name);

            let mut url = reqwest::Url::parse(&format!("https://{host}"))?;
            url.set_path(&path);

            let req = reqwest::Request::new(reqwest::Method::OPTIONS, url);

            let res = client.execute(req).await?;

            if res.status() != reqwest::StatusCode::NO_CONTENT {
                bail!("{name} failed: {}", res.status())
            }

            for (k, v) in [
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Methods", &allowed_methods),
                ("Access-Control-Allow-Headers", "DNT,User-Agent,X-Requested-With,If-None-Match,If-Modified-Since,Cache-Control,Content-Type,Range,Cookie"),
                ("Access-Control-Expose-Headers", "Accept-Ranges,Content-Length,Content-Range"),
                ("Access-Control-Max-Age", "600"),
            ] {
                let hdr = res
                    .headers()
                    .get(k)
                    .ok_or_else(|| anyhow!("missing {k} header"))?.to_str()?;

                if hdr != v {
                    bail!("wrong {k} header: {hdr}, expected {v}")
                }
            }

            Ok(())
        }));
    }

    rt.block_on(async move {
        let mut cnt_err = 0;
        info!(&logger, "Waiting for subtests");

        for fut in futs {
            match fut.await {
                Ok(Err(err)) => {
                    error!(logger, "test failed: {}", err);
                    cnt_err += 1;
                }
                Err(err) => {
                    error!(logger, "test paniced: {}", err);
                    cnt_err += 1;
                }
                _ => {}
            }
        }

        match cnt_err {
            0 => Ok(()),
            _ => bail!("failed with {cnt_err} errors"),
        }
    })
    .expect("test suite failed");

    panic_handler.disable();
}

/* tag::catalog[]
Title:: API Boundary nodes reboot test

Goal:: Reboot a API boundary node

Runbook:
Start a API boundary node and reboot it.

Success:: The API boundary node reboots and continues to answer requests.

Coverage:: API boundary nodes survive reboots

end::catalog[] */

pub fn reboot_test(env: TestEnv) {
    let logger = env.logger();

    let mut panic_handler = PanicHandler::new(env.clone());

    let api_boundary_node = env
        .get_deployed_api_boundary_node(API_BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    info!(&logger, "Rebooting the API boundary node VM.");
    api_boundary_node.vm().reboot();

    info!(
        &logger,
        "Waiting for the API boundary node to get an IPv4 address."
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
        .expect("API Boundary node did not come up healthy.");

    panic_handler.disable();
}

async fn install_canisters(
    topology: TopologySnapshot,
    canister_bytes: &[u8],
    canisters_count: u32,
) -> Vec<Principal> {
    // Select one node from each subnet.
    let nodes: Vec<IcNodeSnapshot> = topology
        .subnets()
        .map(|subnet| subnet.nodes().next().unwrap())
        .collect();
    // Install canisters in parallel via joining multiple futures.
    let mut futures = vec![];
    for node in nodes.iter() {
        for _ in 0..canisters_count {
            futures.push(async {
                let agent = node.build_default_agent_async().await;
                let effective_canister_id = node.effective_canister_id();
                let mgr = ManagementCanister::create(&agent);
                let (canister_id,) = mgr
                    .create_canister()
                    .as_provisional_create_with_amount(None)
                    .with_effective_canister_id(effective_canister_id)
                    .call_and_wait()
                    .await
                    .map_err(|err| {
                        format!("Couldn't create canister with provisional API: {}", err)
                    })
                    .unwrap();
                let install_code = mgr.install_code(&canister_id, canister_bytes);
                install_code
                    .call_and_wait()
                    .await
                    .map_err(|err| format!("Couldn't install canister: {}", err))
                    .unwrap();
                canister_id
            });
        }
    }
    join_all(futures).await
}

async fn set_counters_on_canisters(
    agent: Agent,
    canisters: Vec<Principal>,
    counter_values: Vec<u32>,
) {
    // Perform update calls in parallel via multiple futures.
    let mut futures = Vec::new();
    for (idx, canister_id) in canisters.iter().enumerate() {
        let agent = agent.clone();
        let calls = counter_values[idx];
        futures.push(async move {
            for call in 1..calls + 1 {
                let res = agent
                    .update(canister_id, "write")
                    .call_and_wait()
                    .await
                    .unwrap();
                let counter = u32::from_le_bytes(
                    res.as_slice()
                        .try_into()
                        .expect("slice with incorrect length"),
                );
                assert_eq!(call, counter);
            }
        });
    }
    join_all(futures).await;
}

async fn read_counters_on_canisters(agent: Agent, canisters: Vec<Principal>) -> Vec<u32> {
    // Perform query calls in parallel via multiple futures.
    let mut futures = Vec::new();
    for canister_id in canisters {
        let agent = agent.clone();
        futures.push(async move {
            let res = agent.query(&canister_id, "read").call().await.unwrap();
            u32::from_le_bytes(
                res.as_slice()
                    .try_into()
                    .expect("slice with incorrect length"),
            )
        });
    }
    join_all(futures).await
}
