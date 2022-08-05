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
use anyhow::bail;
use ic_agent::{export::Principal, Agent};
use ic_registry_subnet_type::SubnetType;
use ic_utils::interfaces::ManagementCanister;
use slog::info;
use std::{
    io::Read,
    net::{Ipv4Addr, SocketAddrV6},
    time::Duration,
};

const BOUNDARY_NODE_NAME: &str = "boundary-node-1";

struct PanicStruct<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> PanicStruct<F> {
    fn forget(mut self) {
        self.0 = None;
    }
}

impl<F: FnOnce()> Drop for PanicStruct<F> {
    fn drop(&mut self) {
        if let Some(v) = self.0.take() {
            v()
        }
    }
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
}

pub fn test(env: TestEnv) {
    let counter_canister = env.load_wasm("counter.wat");
    let http_counter_canister = env.load_wasm("http_counter.wasm");

    let logger = env.logger();
    let deployed_boundary_node = env.get_deployed_boundary_node(BOUNDARY_NODE_NAME).unwrap();
    let boundary_node_vm = deployed_boundary_node.get_snapshot().unwrap();
    info!(
        &logger,
        "Boundary node {BOUNDARY_NODE_NAME} has IPv6: {:?}",
        boundary_node_vm.ipv6()
    );

    let boundary_node_ipv4: Ipv4Addr = boundary_node_vm.block_on_ipv4().unwrap();
    info!(
        &logger,
        "Boundary node {BOUNDARY_NODE_NAME} has IPv4 {:?}", boundary_node_ipv4
    );

    // Example of SSH access to Boundary Nodes:
    let sess = boundary_node_vm.block_on_ssh_session(ADMIN).unwrap();
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

    let panic_struct = {
        let logger = env.logger();
        let deployed_boundary_node = env.get_deployed_boundary_node(BOUNDARY_NODE_NAME).unwrap();
        let boundary_node_vm = deployed_boundary_node.get_snapshot().unwrap();
        PanicStruct(Some(move || {
            std::thread::sleep(Duration::from_secs(60));

            let sess = boundary_node_vm.block_on_ssh_session(ADMIN).unwrap();
            let mut channel = sess.channel_session().unwrap();
            channel.exec("systemctl status journalbeat").unwrap();
            let mut journalbeat = String::new();
            channel.read_to_string(&mut journalbeat).unwrap();
            channel.wait_close().unwrap();
            info!(
                logger,
                "journalbeat status {BOUNDARY_NODE_NAME} = '{journalbeat}'. Exit status = {}",
                channel.exit_status().unwrap()
            );
        }))
    };

    info!(&logger, "Checking readiness of all nodes...");
    let mut install_url = None;
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            node.await_status_is_healthy()
                .expect("Replica did not come up healthy.");

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
            install_url = Some(node.get_public_url());
            channel.wait_close().unwrap();
        }
    }
    boundary_node_vm
        .await_status_is_healthy()
        .expect("Boundary node did not come up healthy.");

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        info!(&logger, "Creating replica agent...");
        let agent = assert_create_agent(install_url.unwrap().as_str()).await;

        info!(&logger, "Installing canisters...");
        let counter_canister_id = create_canister(&agent, &counter_canister, None)
            .await
            .expect("Could not create counter canister");

        let http_counter_canister_id = create_canister(&agent, &http_counter_canister, None)
            .await
            .expect("Could not create http_counter canister");

        info!(&logger, "Created counter={counter_canister_id} and http_counter={http_counter_canister_id}.");

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
            Ok(agent.query(&counter_canister_id, "read").call().await?)
        })
        .await
        .unwrap();

        assert_eq!(read_result, [0; 4]);

        let host = format!("{}.raw.ic0.app", http_counter_canister_id);
        let client = reqwest::ClientBuilder::new()
            // FIXME: use `ClientBuilder::add_root_certificate` instead
            .danger_accept_invalid_certs(true)
            .resolve(
                "invalid-canister-id.raw.ic0.app",
                SocketAddrV6::new(boundary_node_vm.ipv6(), 443, 0, 0).into(),
            )
            .resolve(
                &host,
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
        }).await.unwrap();

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
        }).await.unwrap();

        // Check that `canisterId` parameters go unused
        retry_async(&logger, RETRY_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://invalid-canister-id.raw.ic0.app/?canisterId={}", http_counter_canister_id))
                .send()
                .await?
                .text()
                .await?;
            if res != "Could not find a canister id to forward to." {
                bail!(res)
            }
            Ok(())
        }).await.unwrap();

        // Update the denylist and reload nginx
        let denylist_command = format!(r#"printf "ryjl3-tyaaa-aaaaa-aaaba-cai 1;\n{} 1;\n" | sudo tee /etc/nginx/denylist.map && sudo service nginx reload"#, http_counter_canister_id);
        let sess = boundary_node_vm.block_on_ssh_session(ADMIN).unwrap();
        let mut channel = sess.channel_session().unwrap();
        channel.exec(denylist_command.as_str()).unwrap();
        let mut output = String::new();
        channel.read_to_string(&mut output).unwrap();
        channel.wait_close().unwrap();
        info!(
            logger,
            "update denylist {BOUNDARY_NODE_NAME} with {denylist_command} to '{}'. Exit status = {}",
            output.trim(),
            channel.exit_status().unwrap()
        );

        // Wait a bit for the reload to complete
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Probe the (now-blocked) canister again, we should get a 451
        retry_async(&logger, RETRY_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{}/", host))
                .send()
                .await?
                .status();
            if res != reqwest::StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS {
                bail!(res)
            }
            Ok(())
        }).await.unwrap();
    });

    panic_struct.forget();
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
    let boundary_node_vm = deployed_boundary_node.get_snapshot().unwrap();

    // SSH into Boundary Nodes:
    let sess = boundary_node_vm.block_on_ssh_session(ADMIN).unwrap();
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
