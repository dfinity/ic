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
        boundary_node::{BoundaryNode, BoundaryNodeVm},
        ic::{InternetComputer, Subnet},
        pot_dsl::get_ic_handle_and_ctx,
        test_env::{HasIcPrepDir, TestEnv},
        test_env_api::{
            retry_async, HasArtifacts, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            NnsInstallationExt, RetrieveIpv4Addr, SshSession, ADMIN, RETRY_BACKOFF, RETRY_TIMEOUT,
        },
    },
    util::{assert_create_agent, delay},
};
use anyhow::{bail, Error};
use ic_agent::{export::Principal, Agent};
use ic_registry_client::client::{RegistryClient, RegistryClientImpl};
use ic_registry_subnet_type::SubnetType;
use ic_utils::interfaces::ManagementCanister;
use slog::info;
use std::{io::Read, net::SocketAddrV6, time::Duration};

const BOUNDARY_NODE_NAME: &str = "boundary-node-1";

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

        let boundary_node_vm = self
            .env
            .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
            .unwrap()
            .get_snapshot()
            .unwrap();

        let (journalbeat_output, exit_status) =
            exec_ssh_command(&boundary_node_vm, "systemctl status journalbeat").unwrap();

        info!(
            logger,
            "journalbeat status {BOUNDARY_NODE_NAME} = '{journalbeat_output}'. Exit status = {}",
            exit_status,
        );
    }
}

fn exec_ssh_command(vm: &dyn SshSession, command: &str) -> Result<(String, i32), Error> {
    let mut channel = vm.block_on_ssh_session(ADMIN)?.channel_session()?;

    channel.exec(command)?;

    let mut output = String::new();
    channel.read_to_string(&mut output)?;
    channel.wait_close()?;

    Ok((output, channel.exit_status()?))
}

async fn create_canister(
    agent: &Agent,
    canister_bytes: &[u8],
    arg: Option<Vec<u8>>,
) -> Result<Principal, String> {
    // Create a canister.
    let mgr = ManagementCanister::create(agent);
    let canister_id = mgr
        .create_canister()
        .as_provisional_create_with_amount(None)
        .call_and_wait(delay())
        .await
        .map_err(|err| format!("Couldn't create canister with provisional API: {}", err))?
        .0;

    let mut install_code = mgr.install_code(&canister_id, canister_bytes);
    if let Some(arg) = arg {
        install_code = install_code.with_raw_arg(arg)
    }
    install_code
        .call_and_wait(delay())
        .await
        .map_err(|err| format!("Couldn't install canister: {}", err))?;
    Ok::<_, String>(canister_id)
}

pub fn config(env: TestEnv) {
    let logger = env.logger();

    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .setup_and_start(&env)
        .expect("failed to setup IC under test");

    let (handle, _ctx) = get_ic_handle_and_ctx(env.clone());

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
    let registry_data_provider = RegistryClientImpl::new(
        ic_registry_nns_data_provider::create_nns_data_provider(
            rt.handle().clone(),
            env.topology_snapshot()
                .root_subnet()
                .nodes()
                .map(|node| node.get_public_url())
                .collect(),
            None,
        ),
        None,
    );

    registry_data_provider.try_polling_latest_version(100)
        .expect("Failed to poll registry. This is not a Boundary Node error. It is a test environment issue.");

    info!(
        &logger,
        "Latest registry = {}",
        registry_data_provider.get_latest_version()
    );

    // Await Boundary Node
    let boundary_node_vm = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    info!(&logger, "Checking BN health");
    boundary_node_vm
        .await_status_is_healthy()
        .expect("Boundary node did not come up healthy.");

    info!(
        &logger,
        "Boundary node {BOUNDARY_NODE_NAME} has IPv4 {:?} and IPv6 {:?}",
        boundary_node_vm.block_on_ipv4().unwrap(),
        boundary_node_vm.ipv6()
    );
}

/* tag::catalog[]
Title:: Boundary nodes binary canister test

Goal:: Install and query a binary canister

Runbook:
. Set up a subnet with 4 nodes and a boundary node.

Success:: The canister installs successfully and calls against it
return the expected responses

Coverage:: binary canisters behave as expected

end::catalog[] */

pub fn canister_test(env: TestEnv) {
    let logger = env.logger();

    let mut panic_handler = PanicHandler::new(env.clone());

    let mut install_url = None;
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            install_url = Some(node.get_public_url());
        }
    }

    let boundary_node_vm = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        info!(&logger, "Creating replica agent...");
        let agent = assert_create_agent(install_url.unwrap().as_str()).await;

        let counter_canister = env.load_wasm("counter.wat");

        info!(&logger, "installing canister");
        let canister_id = create_canister(&agent, &counter_canister, None)
            .await
            .expect("Could not create counter canister");

        info!(&logger, "created canister={canister_id}");

        // Wait for the canisters to finish installing
        // TODO: maybe this should be status calls?
        tokio::time::sleep(Duration::from_secs(5)).await;

        info!(&logger, "Creating BN agent...");
        let agent = retry_async(&logger, RETRY_TIMEOUT, RETRY_BACKOFF, || async {
            Ok(boundary_node_vm.try_build_default_agent_async().await?)
        })
        .await
        .expect("Failed to create agent.");

        info!(&logger, "Calling read...");
        // We must retry the first request to a canister.
        // This is because a new canister might take a few seconds to show up in the BN's routing tables
        let read_result = retry_async(&logger, RETRY_TIMEOUT, RETRY_BACKOFF, || async {
            Ok(agent.query(&canister_id, "read").call().await?)
        })
        .await
        .unwrap();

        assert_eq!(read_result, [0; 4]);
    });

    panic_handler.disable();
}

/* tag::catalog[]
Title:: Boundary nodes HTTP canister test

Goal:: Install and query an HTTP canister

Runbook:
. Set up a subnet with 4 nodes and a boundary node.

Success:: The canister installs successfully and HTTP calls against it
return the expected responses

Coverage:: HTTP Canisters behave as expected

end::catalog[] */

pub fn http_canister_test(env: TestEnv) {
    let logger = env.logger();

    let mut panic_handler = PanicHandler::new(env.clone());

    let mut install_url = None;
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            install_url = Some(node.get_public_url());
        }
    }

    let boundary_node_vm = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        info!(&logger, "Creating replica agent...");
        let agent = assert_create_agent(install_url.unwrap().as_str()).await;

        let http_counter_canister = env.load_wasm("http_counter.wasm");

        info!(&logger, "installing canister");
        let canister_id = create_canister(&agent, &http_counter_canister, None)
            .await
            .expect("Could not create http_counter canister");

        info!(&logger, "created canister={canister_id}");

        // Wait for the canisters to finish installing
        // TODO: maybe this should be status calls?
        tokio::time::sleep(Duration::from_secs(5)).await;

        let host = format!("{}.raw.ic0.app", canister_id);
        let client = reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .resolve(
                &host,
                SocketAddrV6::new(boundary_node_vm.ipv6(), 443, 0, 0).into(),
            )
            .resolve(
                "invalid-canister-id.raw.ic0.app",
                SocketAddrV6::new(boundary_node_vm.ipv6(), 443, 0, 0).into(),
            )
            .build()
            .unwrap();

        retry_async(&logger, RETRY_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{}/", host))
                .send()
                .await?
                .text()
                .await?;

            if res != "Counter is 0\n" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        retry_async(&logger, RETRY_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{}/stream", host))
                .send()
                .await?
                .text()
                .await?;

            if res != "Counter is 0 streaming\n" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        // Check that `canisterId` parameters go unused
        retry_async(&logger, RETRY_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!(
                    "https://invalid-canister-id.raw.ic0.app/?canisterId={}",
                    canister_id
                ))
                .send()
                .await?
                .text()
                .await?;

            if res != "Could not find a canister id to forward to." {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();
    });

    panic_handler.disable();
}

/* tag::catalog[]
Title:: Boundary nodes valid Nginx configuration test

Goal:: Verify that nginx configuration is valid by running `nginx -T` on the boundary node.

Runbook:
. Set up a subnet with 4 nodes and a boundary node.
. SSH into the boundary node and execute `sudo nginx -t`

Success:: The output contains the string
`nginx: configuration file /etc/nginx/nginx.conf test is successful`

Coverage:: NGINX configuration is not broken

end::catalog[] */

pub fn nginx_valid_config_test(env: TestEnv) {
    let logger = env.logger();

    let boundary_node_vm = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let (cmd_output, exit_status) =
        exec_ssh_command(&boundary_node_vm, "sudo nginx -t 2>&1").unwrap();

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

/* tag::catalog[]
Title:: Boundary nodes denylist blocking test

Goal:: Ensure that access to a canister specified in the denylist is blocked

Runbook:
. Set up a subnet with 4 nodes and a boundary node.
. ?

Success:: ?

Coverage:: Blocking requests based on the denylist works

end::catalog[] */

pub fn denylist_test(env: TestEnv) {
    let logger = env.logger();

    let mut panic_handler = PanicHandler::new(env.clone());

    let mut install_url = None;
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            install_url = Some(node.get_public_url());
        }
    }

    let boundary_node_vm = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        info!(&logger, "creating replica agent");
        let agent = assert_create_agent(install_url.unwrap().as_str()).await;

        let http_counter_canister = env.load_wasm("http_counter.wasm");

        info!(&logger, "installing canister");
        let canister_id = create_canister(&agent, &http_counter_canister, None)
            .await
            .expect("Could not create http_counter canister");

        // wait for canister to finish installing
        tokio::time::sleep(Duration::from_secs(5)).await;

        info!(&logger, "created canister={canister_id}");

        // Update the denylist and reload nginx
        let denylist_command = format!(r#"printf "{} 1;\n" | sudo tee /etc/nginx/denylist.map && sudo service nginx reload"#, canister_id);
        let (cmd_output, exit_status) = exec_ssh_command(&boundary_node_vm, &denylist_command).unwrap();
        info!(
            logger,
            "update denylist {BOUNDARY_NODE_NAME} with {denylist_command} to '{}'. Exit status = {}",
            cmd_output.trim(),
            exit_status,
        );

        // Wait a bit for the reload to complete
        tokio::time::sleep(Duration::from_secs(2)).await;

        let client = reqwest::ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .resolve(
                &format!("{}.raw.ic0.app", canister_id),
                SocketAddrV6::new(boundary_node_vm.ipv6(), 443, 0, 0).into(),
            )
            .build()
            .unwrap();

        // Probe the blocked canister, we should get a 451
        retry_async(&logger, RETRY_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{}.raw.ic0.app/", canister_id))
                .send()
                .await?
                .status();

            if res != reqwest::StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS {
                bail!(res)
            }

            Ok(())
        }).await.unwrap();
    });

    panic_handler.disable();
}

/* tag::catalog[]
Title:: Boundary nodes nginx request/response test

Goal:: Perform a series of requests via Nginx and ensure the expected responses are returned

Runbook:
. Set up a subnet with 4 nodes and a boundary node.
. ?

Success:: ?

Coverage:: NGINX configuration is not broken

end::catalog[] */

pub fn nginx_request_response_test(env: TestEnv) {
    let logger = env.logger();

    let mut panic_handler = PanicHandler::new(env.clone());

    let boundary_node_vm = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        // redirect http to https
        retry_async(&logger, RETRY_TIMEOUT, RETRY_BACKOFF, || async {
            let client = reqwest::ClientBuilder::new()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::none())
                .resolve(
                    "ic0.app",
                    SocketAddrV6::new(boundary_node_vm.ipv6(), 443, 0, 0).into(),
                )
                .build()
                .unwrap();

            let res = client.get("http://ic0.app/").send().await?;

            if res.status() != reqwest::StatusCode::MOVED_PERMANENTLY {
                bail!(res.status())
            }

            let location_hdr = res.headers().get("Location").unwrap().to_str().unwrap();
            if location_hdr != "https://ic0.app/" {
                bail!("wrong location header: {}", location_hdr)
            }

            Ok(())
        })
        .await
        .unwrap();
    });

    panic_handler.disable();
}
