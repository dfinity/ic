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

use crate::boundary_nodes::{
    constants::{BOUNDARY_NODE_NAME, COUNTER_CANISTER_WAT},
    helpers::{
        create_canister, get_install_url, install_canisters, read_counters_on_counter_canisters,
        set_counters_on_counter_canisters,
    },
};
use ic_system_test_driver::{
    driver::{
        asset_canister::{DeployAssetCanister, UploadAssetRequest},
        boundary_node::BoundaryNodeVm,
        test_env::TestEnv,
        test_env_api::{
            load_wasm, HasPublicApiUrl, HasTopologySnapshot, HasVm, IcNodeContainer,
            RetrieveIpv4Addr, SshSession, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    util::{
        agent_observes_canister_module, agent_using_call_v2_endpoint, assert_create_agent, block_on,
    },
};
use std::{env, iter, net::SocketAddrV6, time::Duration};

use anyhow::{anyhow, bail, Error};
use futures::stream::FuturesUnordered;
use ic_agent::{
    agent::http_transport::{
        hyper_transport::hyper::StatusCode,
        reqwest_transport::{reqwest, ReqwestTransport},
    },
    export::Principal,
    Agent,
};
use serde::Deserialize;
use slog::{error, info, Logger};
use tokio::runtime::Runtime;
const CANISTER_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const CANISTER_RETRY_BACKOFF: Duration = Duration::from_secs(2);

async fn install_canister(env: TestEnv, logger: Logger, path: &str) -> Result<Principal, Error> {
    let install_node = env
        .topology_snapshot()
        .subnets()
        .next()
        .unwrap()
        .nodes()
        .next()
        .map(|node| (node.get_public_url(), node.effective_canister_id()))
        .unwrap();

    info!(
        &logger,
        "creating replica agent {}",
        install_node.0.as_str()
    );
    let agent = assert_create_agent(install_node.0.as_str()).await;

    let canister = load_wasm(path);

    info!(&logger, "installing canister from path {}", path);
    let canister_id = create_canister(&agent, install_node.1, &canister, None)
        .await
        .expect("Could not create http_counter canister");

    info!(&logger, "Waiting for canisters to finish installing...");
    ic_system_test_driver::retry_with_msg_async!(
        format!(
            "agent of {} observes canister module {}",
            install_node.0.to_string(),
            canister_id.to_string()
        ),
        &logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            match agent_observes_canister_module(&agent, &canister_id).await {
                true => Ok(()),
                false => panic!("Canister module not available yet"),
            }
        }
    )
    .await
    .unwrap();

    info!(&logger, "created canister {canister_id}");

    Ok::<_, Error>(canister_id)
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

    let mut install_node = None;
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            install_node = Some((node.get_public_url(), node.effective_canister_id()));
        }
    }

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
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
            install_node.clone().unwrap().1,
            wat::parse_str(COUNTER_CANISTER_WAT).unwrap().as_slice(),
            None,
        )
        .await
        .expect("Could not create counter canister");

        info!(&logger, "created canister={canister_id}");

        info!(&logger, "Waiting for canisters to finish installing...");
        ic_system_test_driver::retry_with_msg_async!(
            format!(
                "agent of {} observes canister module {}",
                install_node.as_ref().unwrap().0.to_string(),
                canister_id.to_string()
            ),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                match agent_observes_canister_module(&agent, &canister_id).await {
                    true => Ok(()),
                    false => panic!("Canister module not available yet"),
                }
            }
        )
        .await
        .unwrap();

        info!(&logger, "Creating BN agent...");
        let agent = ic_system_test_driver::retry_with_msg_async!(
            format!(
                "build agent for BoundaryNode {}",
                boundary_node.get_public_url().to_string()
            ),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async { Ok(boundary_node.try_build_default_agent_async().await?) }
        )
        .await
        .expect("Failed to create agent.");

        info!(&logger, "Calling read...");
        // We must retry the first request to a canister.
        // This is because a new canister might take a few seconds to show up in the BN's routing tables
        let read_result = ic_system_test_driver::retry_with_msg_async!(
            format!(
                "calling read on canister {} on BoundaryNode {}",
                canister_id.to_string(),
                boundary_node.get_public_url().to_string()
            ),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async { Ok(agent.query(&canister_id, "read").call().await?) }
        )
        .await
        .unwrap();

        assert_eq!(read_result, [0; 4]);
    });
}

/* tag::catalog[]
Title:: Boundary nodes asset canister test

Goal:: Install and query an asset canister

Runbook:
. Set up a subnet with 4 nodes and a boundary node.

Success:: The canister installs successfully and HTTP calls against it
return the expected responses

Coverage:: asset Canisters behave as expected

end::catalog[] */

pub fn asset_canister_test(env: TestEnv) {
    let logger = env.logger();
    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        info!(&logger, "Deploying asset canister...");
        let asset_canister = env
            .deploy_asset_canister()
            .await
            .expect("Could not install asset canister");


        let http_client_builder = reqwest::ClientBuilder::new();
        let (client_builder, host) = if let Some(playnet) = boundary_node.get_playnet() {
            (
                http_client_builder,
                format!("{0}.{playnet}", asset_canister.canister_id),
            )
        } else {
            let host = format!("{0}.ic0.app", asset_canister.canister_id);
            let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0).into();
            let client_builder = http_client_builder
                .danger_accept_invalid_certs(true)
                .resolve(&host, bn_addr);
            (client_builder, host)
        };
        let http_client = client_builder.build().unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            "Requesting a small asset with the correct hash succeeds and is verified without streaming",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let hello_world = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];

                info!(&logger, "Uploading hello world asset...");
                asset_canister
                    .upload_asset(&UploadAssetRequest {
                        key: "/hello-world.txt".to_string(),
                        content: hello_world.clone(),
                        content_type: "text/plain".to_string(),
                        content_encoding: "identity".to_string(),
                        sha_override: None,
                    })
                    .await?;

                info!(&logger, "Requesting hello world asset...");
                let res = http_client
                    .get(format!("https://{host}/hello-world.txt"))
                    .header("accept-encoding", "gzip")
                    .send()
                    .await?
                    .bytes()
                    .await?
                    .to_vec();

                if res != hello_world {
                    bail!("hello world response did not match uploaded content")
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            "Requesting a small, gzipped asset with the correct hash succeeds and is verified without streaming",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let hello_world_gzip = vec![
                    31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 243, 72, 205, 201, 201, 87, 8, 207, 47, 202, 73,
                    81, 4, 0, 163, 28, 41, 28, 12, 0, 0, 0,
                ];

                info!(&logger, "Uploading gzipped hello world asset...");
                asset_canister
                    .upload_asset(&UploadAssetRequest {
                        key: "/hello-world-gzipped.txt".to_string(),
                        content: hello_world_gzip.clone(),
                        content_type: "text/plain".to_string(),
                        content_encoding: "gzip".to_string(),
                        sha_override: None,
                    })
                    .await?;

                info!(&logger, "Requesting gzipped hello world asset...");
                let res = http_client
                    .get(format!("https://{host}/hello-world-gzipped.txt"))
                    .header("accept-encoding", "gzip")
                    .send()
                    .await?
                    .bytes()
                    .await?
                    .to_vec();

                if res != hello_world_gzip {
                    bail!("gzipped hello world response did not match uploaded content")
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            "Requesting a 4mb asset with the correct hash succeeds and is within the limit that we can safely verify while streaming so it is verified",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let hello_world = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
                // 12 bytes * 86 = 1024 bytes
                let req_body = iter::repeat(hello_world)
                    .take(86 * 4 * 1024)
                    .flatten()
                    .collect::<Vec<_>>();

                info!(&logger, "Uploading 4mb asset...");
                asset_canister
                    .upload_asset(&UploadAssetRequest {
                        key: "/4mb.txt".to_string(),
                        content: req_body.clone(),
                        content_type: "text/plain".to_string(),
                        content_encoding: "identity".to_string(),
                        sha_override: None,
                    })
                    .await?;

                info!(&logger, "Requesting 4mb asset...");
                let res = http_client
                    .get(format!("https://{host}/4mb.txt"))
                    .header("accept-encoding", "gzip")
                    .send()
                    .await?
                    .bytes()
                    .await?
                    .to_vec();

                if res != req_body {
                    bail!("4mb response did not match uploaded content")
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            "Requesting a 6mb asset with the correct hash succeeds and is within the limit that we can safely verify while streaming so it is verified".to_string(),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let hello_world = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
                // 12 bytes * 86 = 1024 bytes
                let req_body = iter::repeat(hello_world)
                    .take(86 * 6 * 1024)
                    .flatten()
                    .collect::<Vec<_>>();

                info!(&logger, "Uploading 6mb asset...");
                asset_canister
                    .upload_asset(&UploadAssetRequest {
                        key: "/6mb.txt".to_string(),
                        content: req_body.clone(),
                        content_type: "text/plain".to_string(),
                        content_encoding: "identity".to_string(),
                        sha_override: None,
                    })
                    .await?;

                info!(&logger, "Requesting 6mb asset...");
                let res = http_client
                    .get(format!("https://{host}/6mb.txt"))
                    .header("accept-encoding", "gzip")
                    .send()
                    .await?
                    .bytes()
                    .await?
                    .to_vec();

                if res != req_body {
                    bail!("6mb response did not match uploaded content")
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            "Requesting an 8mb asset with the correct hash succeeds and is within the limit that we can safely verify while streaming so it is verified",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let hello_world = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
                // 12 bytes * 86 = 1024 bytes
                let req_body = iter::repeat(hello_world)
                    .take(86 * 8 * 1024)
                    .flatten()
                    .collect::<Vec<_>>();

                info!(&logger, "Uploading 8mb asset...");
                asset_canister
                    .upload_asset(&UploadAssetRequest {
                        key: "/8mb.txt".to_string(),
                        content: req_body.clone(),
                        content_type: "text/plain".to_string(),
                        content_encoding: "identity".to_string(),
                        sha_override: None,
                    })
                    .await?;

                info!(&logger, "Requesting 8mb asset...");
                let res = http_client
                    .get(format!("https://{host}/8mb.txt"))
                    .header("accept-encoding", "gzip")
                    .send()
                    .await?
                    .bytes()
                    .await?
                    .to_vec();

                if res != req_body {
                    bail!("8mb response did not match uploaded content")
                }

                Ok(())
            })
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            "Requesting a 10mb asset with the correct hash succeeds but the asset is larger than the limit that we can safely verify while streaming so it is not verified",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let hello_world = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
                // 12 bytes * 86 = 1024 bytes
                let req_body = iter::repeat(hello_world)
                    .take(86 * 10 * 1024)
                    .flatten()
                    .collect::<Vec<_>>();

                info!(&logger, "Uploading 10mb asset...");
                asset_canister
                    .upload_asset(&UploadAssetRequest {
                        key: "/10mb.txt".to_string(),
                        content: req_body.clone(),
                        content_type: "text/plain".to_string(),
                        content_encoding: "identity".to_string(),
                        sha_override: None,
                    })
                    .await?;

                info!(&logger, "Requesting 10mb asset...");
                let res = http_client
                    .get(format!("https://{host}/10mb.txt"))
                    .header("accept-encoding", "gzip")
                    .send()
                    .await?
                    .bytes()
                    .await?
                    .to_vec();

                if res != req_body {
                    bail!("10mb response did not match uploaded content")
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            "Requesting a 4mb asset with the incorrect hash fails because the asset is within the limit that we can safely verify while streaming",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let hello_world = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
                // 12 bytes * 86 = 1024 bytes
                let req_body = iter::repeat(hello_world)
                    .take(86 * 4 * 1024)
                    .flatten()
                    .collect::<Vec<_>>();

                info!(&logger, "Uploading invalid 4mb asset...");
                asset_canister
                    .upload_asset(&UploadAssetRequest {
                        key: "/invalid-4mb.txt".to_string(),
                        content: req_body.clone(),
                        content_type: "text/plain".to_string(),
                        content_encoding: "identity".to_string(),
                        sha_override: Some(vec![0; 32]),
                    })
                    .await?;

                info!(&logger, "Requesting invalid 4mb asset...");
                let res = http_client
                    .get(format!("https://{host}/invalid-4mb.txt"))
                    .header("accept-encoding", "gzip")
                    .send()
                    .await?
                    .text()
                    .await?;

                if res != "Body does not pass verification" {
                    bail!("invalid 4mb asset did not fail verification")
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            "Requesting a 10mb asset with an invalid hash succeeds because the asset is larger than what we can safely verify while streaming",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let hello_world = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
                // 12 bytes * 86 = 1024 bytes
                let req_body = iter::repeat(hello_world)
                    .take(86 * 10 * 1024)
                    .flatten()
                    .collect::<Vec<_>>();

                info!(&logger, "Uploading invalid 10mb asset...");
                asset_canister
                    .upload_asset(&UploadAssetRequest {
                        key: "/invalid-10mb.txt".to_string(),
                        content: req_body.clone(),
                        content_type: "text/plain".to_string(),
                        content_encoding: "identity".to_string(),
                        sha_override: Some(vec![0; 32]),
                    })
                    .await?;

                info!(&logger, "Requesting invalid 10mb asset...");
                let res = http_client
                    .get(format!("https://{host}/invalid-10mb.txt"))
                    .header("accept-encoding", "gzip")
                    .send()
                    .await?
                    .bytes()
                    .await?
                    .to_vec();

                if res != req_body {
                    bail!("invalid 10mb response did not match uploaded content")
                }

                Ok(())
            }
        )
        .await
        .unwrap();
    });
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

    let mut install_node = None;
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            install_node = Some((node.get_public_url(), node.effective_canister_id()));
        }
    }
    let install_node = install_node.expect("No install node");

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        info!(&logger, "Creating replica agent...");
        let agent = assert_create_agent(install_node.0.as_str()).await;
        let kv_store_canister =
            load_wasm(env::var("KV_STORE_WASM_PATH").expect("KV_STORE_WASM_PATH not set"));

        info!(&logger, "installing canister");
        let canister_id = create_canister(&agent, install_node.1, &kv_store_canister, None)
            .await
            .expect("Could not create kv_store canister");

        info!(&logger, "created kv_store canister={canister_id}");

        // Wait for the canisters to finish installing
        // TODO: maybe this should be status calls?
        tokio::time::sleep(Duration::from_secs(5)).await;

        let client_builder = reqwest::ClientBuilder::new();
        let (client_builder, host, invalid_host) =
            if let Some(playnet) = boundary_node.get_playnet() {
                (
                    client_builder,
                    format!("{canister_id}.raw.{playnet}"),
                    format!("invalid-canister-id.raw.{playnet}"),
                )
            } else {
                let host = format!("{canister_id}.raw.ic0.app");
                let invalid_host = "invalid-canister-id.raw.ic0.app".to_string();
                let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0).into();
                let client_builder = client_builder
                    .danger_accept_invalid_certs(true)
                    .resolve(&host, bn_addr)
                    .resolve(&invalid_host, bn_addr);
                (client_builder, host, invalid_host)
            };
        let client = client_builder.build().unwrap();

        let url = &format!("https://{host}/foo");
        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting not found)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client
                    .get(url)
                    .header("x-ic-test", "no-certificate")
                    .send()
                    .await?
                    .text()
                    .await?;

                if res != "'/foo' not found" {
                    bail!("expected not found");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        // "x-ic-test", "no-certificate"
        // "x-ic-test", "streaming-callback"
        // "x-icx-require-certification", "1"

        ic_system_test_driver::retry_with_msg_async!(
            format!("PUT {}", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client.put(url).body("bar").send().await?.text().await?;

                if res != "'/foo' set to 'bar'" {
                    bail!("exptected set to bar");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting bar)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client.get(url).send().await?.text().await?;

                if res != "bar" {
                    bail!("expected bar");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting bar)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client
                    .get(url)
                    .header("x-ic-test", "streaming-callback")
                    .send()
                    .await?
                    .text()
                    .await?;

                if res != "bar" {
                    bail!("expected bar");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        // Check that `canisterId` parameters go unused
        let url = &format!("https://{invalid_host}/?canisterId={canister_id}");
        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting 400)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client.get(url).send().await?;

                if res.status() != StatusCode::BAD_REQUEST {
                    bail!("expected 400");
                }

                Ok(())
            }
        )
        .await
        .unwrap();
    });
}

/* tag::catalog[]
Title:: Boundary nodes prefix HTTP canister test

Goal:: Install an HTTP canister and query using (ignored prefix)--(canister id)

Runbook:
. Set up a subnet with 4 nodes and a boundary node.

Success:: The canister installs successfully and HTTP calls against it
return the expected responses

Coverage:: Canisters can be queried using some ignored prefix

end::catalog[] */

pub fn prefix_canister_id_test(env: TestEnv) {
    let logger = env.logger();

    let mut install_node = None;
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            install_node = Some((node.get_public_url(), node.effective_canister_id()));
        }
    }
    let install_node = install_node.expect("No install node");

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        info!(&logger, "Creating replica agent...");
        let agent = assert_create_agent(install_node.0.as_str()).await;
        let kv_store_canister =
            load_wasm(env::var("KV_STORE_WASM_PATH").expect("KV_STORE_WASM_PATH not set"));

        info!(&logger, "installing canister");
        let canister_id = create_canister(&agent, install_node.1, &kv_store_canister, None)
            .await
            .expect("Could not create kv_store canister");

        info!(&logger, "created kv_store canister={canister_id}");

        info!(&logger, "Waiting for canisters to finish installing...");
        ic_system_test_driver::retry_with_msg_async!(
            format!(
                "agent of {} observes canister module {}",
                install_node.0.to_string(),
                canister_id.to_string()
            ),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                match agent_observes_canister_module(&agent, &canister_id).await {
                    true => Ok(()),
                    false => panic!("Canister module not available yet"),
                }
            }
        )
        .await
        .unwrap();

        let client_builder = reqwest::ClientBuilder::new();
        let (client_builder, host) = if let Some(playnet) = boundary_node.get_playnet() {
            (
                client_builder,
                format!("ignored-prefix--{canister_id}.raw.{playnet}"),
            )
        } else {
            let host = format!("ignored-prefix--{canister_id}.raw.ic0.app");
            let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0).into();
            let client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .resolve(&host, bn_addr);
            (client_builder, host)
        };
        let client = client_builder.build().unwrap();

        let url = &format!("https://{host}/foo");
        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting foo not found)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client
                    .get(url)
                    .header("x-ic-test", "no-certificate")
                    .send()
                    .await?
                    .text()
                    .await?;

                if res != "'/foo' not found" {
                    bail!("expected foo not found");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        // "x-ic-test", "no-certificate"
        // "x-ic-test", "streaming-callback"
        // "x-icx-require-certification", "1"

        ic_system_test_driver::retry_with_msg_async!(
            format!("PUT {} (expecting set to bar)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client.put(url).body("bar").send().await?.text().await?;

                if res != "'/foo' set to 'bar'" {
                    bail!("expected set to bar");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting bar)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client.get(url).send().await?.text().await?;

                if res != "bar" {
                    bail!("expected bar");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting bar)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client
                    .get(format!("https://{host}/foo"))
                    .header("x-ic-test", "streaming-callback")
                    .send()
                    .await?
                    .text()
                    .await?;

                if res != "bar" {
                    bail!("expected bar");
                }

                Ok(())
            }
        )
        .await
        .unwrap();
    });
}

/* tag::catalog[]
Title:: Boundary nodes HTTP canister test

Goal:: Install and query an HTTP canister using the proxy

Runbook:
. Set up a subnet with 4 nodes and a boundary node.

Success:: The canister installs successfully and HTTP calls against it
return the expected responses

Coverage:: HTTP Canisters behave as expected using the proxy

end::catalog[] */

pub fn proxy_http_canister_test(env: TestEnv) {
    let logger = env.logger();

    let mut install_node = None;
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            install_node = Some((node.get_public_url(), node.effective_canister_id()));
        }
    }
    let install_node = install_node.expect("No install node");

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    rt.block_on(async move {
        info!(&logger, "Creating replica agent...");
        let agent = assert_create_agent(install_node.0.as_str()).await;
        let kv_store_canister =
            load_wasm(env::var("KV_STORE_WASM_PATH").expect("KV_STORE_WASM_PATH not set"));

        info!(&logger, "installing canister");
        let canister_id = create_canister(&agent, install_node.1, &kv_store_canister, None)
            .await
            .expect("Could not create kv_store canister");

        info!(&logger, "created kv_store canister={canister_id}");

        // Wait for the canisters to finish installing
        // TODO: maybe this should be status calls?
        tokio::time::sleep(Duration::from_secs(5)).await;

        let client_builder = reqwest::ClientBuilder::new();
        let (client_builder, host, invalid_host) =
            if let Some(playnet) = boundary_node.get_playnet() {
                (
                    client_builder,
                    format!("{canister_id}.raw.{playnet}"),
                    format!("invalid-canister-id.raw.{playnet}"),
                )
            } else {
                let host = format!("{canister_id}.raw.ic0.app");
                let invalid_host = "invalid-canister-id.raw.ic0.app".to_string();
                let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0).into();
                let client_builder = client_builder
                    .danger_accept_invalid_certs(true)
                    .resolve(&host, bn_addr)
                    .resolve(&invalid_host, bn_addr);
                (client_builder, host, invalid_host)
            };
        let proxy = format!("http://{host}:8888");
        info!(&logger, "using proxy={proxy}");
        let proxy = reqwest::Proxy::http(proxy).expect("Could not create proxy");
        let client = client_builder.proxy(proxy).build().unwrap();

        let url = &format!("https://{host}/foo");
        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting foo not found)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client
                    .get(url)
                    .header("x-ic-test", "no-certificate")
                    .send()
                    .await?
                    .text()
                    .await?;

                if res != "'/foo' not found" {
                    bail!("expected foo not found");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        // "x-ic-test", "no-certificate"
        // "x-ic-test", "streaming-callback"
        // "x-icx-require-certification", "1"

        ic_system_test_driver::retry_with_msg_async!(
            format!("PUT {} (expecting set to bar)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client.put(url).body("bar").send().await?.text().await?;

                if res != "'/foo' set to 'bar'" {
                    bail!("expected set to bar");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting bar)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client.get(url).send().await?.text().await?;

                if res != "bar" {
                    bail!("expected bar");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting bar)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client
                    .get(url)
                    .header("x-ic-test", "streaming-callback")
                    .send()
                    .await?
                    .text()
                    .await?;

                if res != "bar" {
                    bail!("expected bar");
                };

                Ok(())
            }
        )
        .await
        .unwrap();

        // Check that `canisterId` parameters go unused
        let url = &format!("https://{invalid_host}/?canisterId={canister_id}");
        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting 400)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client.get(url).send().await?;

                if res.status() != StatusCode::BAD_REQUEST {
                    bail!("expected 400");
                }

                Ok(())
            }
        )
        .await
        .unwrap();
    });
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

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let cmd_output = boundary_node
        .block_on_bash_script("sudo nginx -t 2>&1")
        .unwrap();

    info!(logger, "nginx test result = '{}'", cmd_output.trim());

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

    let mut install_node = None;
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            install_node = Some((node.get_public_url(), node.effective_canister_id()));
        }
    }

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        info!(&logger, "creating replica agent");
        let agent = assert_create_agent(install_node.as_ref().unwrap().0.as_str()).await;

        let http_counter_canister = load_wasm(env::var("HTTP_COUNTER_WASM_PATH").expect("HTTP_COUNTER_WASM_PATH not set"));

        info!(&logger, "installing canister");
        let canister_id = create_canister(&agent, install_node.clone().unwrap().1, &http_counter_canister, None)
            .await
            .expect("Could not create http_counter canister");

        info!(&logger, "Waiting for canisters to finish installing...");
        ic_system_test_driver::retry_with_msg_async!(
            format!(
                "agent of {} observes canister module {}",
                install_node.as_ref().unwrap().0,
                canister_id.to_string()
            ),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                match agent_observes_canister_module(&agent, &canister_id).await {
                    true => Ok(()),
                    false => panic!("Canister module not available yet"),
                }
            }
        )
        .await
        .unwrap();

        info!(&logger, "created canister={canister_id}");

        // Update the denylist and restart icx-proxy
        let denylist_command = format!(r#"echo "{{\"canisters\":{{\"{}\": {{}}}}}}" | sudo tee /run/ic-node/etc/icx-proxy/denylist.json && sudo service icx-proxy restart"#, canister_id);
        info!(
            logger,
            "update denylist {BOUNDARY_NODE_NAME} with {denylist_command}"
        );
        if let Err(e) = boundary_node.block_on_bash_script(&denylist_command) {
            panic!("bash script failed: {:?}", e);
        }

        // Wait a bit for the restart to complete
        tokio::time::sleep(Duration::from_secs(3)).await;

        let client_builder = reqwest::ClientBuilder::new();
        let (client_builder, host) = if let Some(playnet) = boundary_node.get_playnet() {
            (client_builder, playnet)
        } else {
            let host = "ic0.app";
            let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0);
            let client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .resolve(&format!("{canister_id}.raw.{host}"),bn_addr.into());
            (client_builder, host.to_string())
        };
        let client = client_builder.build().unwrap();

        // Probe the blocked canister, we should get a 451
        let url = &format!("https://{canister_id}.raw.{host}/");
        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting 451)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client
                    .get(url)
                    .send()
                    .await?
                    .status();

                if res != reqwest::StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS {
                    bail!("expected 451, got {res}");
                }

                Ok(())
            }
        ).await.unwrap();
    });
}

/* tag::catalog[]
Title:: Boundary nodes canister-allowlist blocking test

Goal:: Ensure that the canister-allowlist overrides the denylist

Success::
    A canister being present in the Allowlist overrides the restriction
    due to that canister being present in the denylist.

end::catalog[] */

pub fn canister_allowlist_test(env: TestEnv) {
    let logger = env.logger();

    let mut install_node = None;
    for subnet in env.topology_snapshot().subnets() {
        for node in subnet.nodes() {
            install_node = Some((node.get_public_url(), node.effective_canister_id()));
        }
    }

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        info!(&logger, "creating replica agent");
        let agent = assert_create_agent(install_node.as_ref().unwrap().0.as_str()).await;

        let http_counter_canister = load_wasm(env::var("HTTP_COUNTER_WASM_PATH").expect("HTTP_COUNTER_WASM_PATH not set"));

        info!(&logger, "installing canister");
        let canister_id = create_canister(&agent, install_node.clone().unwrap().1, &http_counter_canister, None)
            .await
            .expect("Could not create http_counter canister");

        info!(&logger, "Waiting for canisters to finish installing...");
        ic_system_test_driver::retry_with_msg_async!(
            format!(
                "agent of {} observes canister module {}",
                install_node.as_ref().unwrap().0,
                canister_id.to_string()
            ),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                match agent_observes_canister_module(&agent, &canister_id).await {
                    true => Ok(()),
                    false => panic!("Canister module not available yet"),
                }
            }
        )
        .await
        .unwrap();

        info!(&logger, "created canister={canister_id}");

        let client_builder = reqwest::ClientBuilder::new();
        let (client_builder, host) = if let Some(playnet) = boundary_node.get_playnet() {
            (client_builder, playnet)
        } else {
            let host = "ic0.app";
            let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0);
            let client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .resolve(&format!("{canister_id}.raw.{host}"), bn_addr.into());
            (client_builder, host.to_string())
        };
        let client = client_builder.build().unwrap();

        // Check canister is available
        let url = &format!("https://{canister_id}.raw.{host}/");
        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {}", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client
                    .get(url)
                    .send()
                    .await
                    .expect("Could not perform get request.")
                    .status();

                if res != reqwest::StatusCode::OK {
                    bail!("expected OK, got {}", res);
                }

                Ok(())
            }
        ).await.unwrap();

        // Update the denylist and restart icx-proxy
        let denylist_command = format!(r#"echo "{{\"canisters\":{{\"{}\": {{}}}}}}" | sudo tee /run/ic-node/etc/icx-proxy/denylist.json && sudo service icx-proxy restart"#, canister_id);
        info!(
            logger,
            "update denylist {BOUNDARY_NODE_NAME} with {denylist_command}"
        );
        if let Err(e) = boundary_node.block_on_bash_script(&denylist_command) {
            panic!("bash script failed: {:?}", e);
        }

        // Wait a bit for the restart to complete
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Check canister is restricted
        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {} (expecting 451)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client
                    .get(url)
                    .send()
                    .await
                    .expect("Could not perform get request.")
                    .status();

                if res != reqwest::StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS {
                    bail!("expected 451, got {}", res);
                }

                Ok(())
            }
        ).await.unwrap();

        // Update the allowlist and restart icx-proxy
        let allowlist_command = format!(r#"echo "{}" | sudo tee /run/ic-node/etc/icx-proxy/allowlist.txt && sudo service icx-proxy restart"#, canister_id);
        info!(
            logger,
            "update allowlist {BOUNDARY_NODE_NAME} with {allowlist_command}"
        );
        if let Err(e) = boundary_node.block_on_bash_script(&allowlist_command) {
            panic!("bash script failed: {:?}", e);
        }

        // Wait a bit for the restart to complete
        tokio::time::sleep(Duration::from_secs(3)).await;

        // Check canister is available
        ic_system_test_driver::retry_with_msg_async!(
            format!("GET {}", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client
                    .get(url)
                    .send()
                    .await
                    .expect("Could not perform get request.")
                    .status();

                if res != reqwest::StatusCode::OK {
                    bail!("expected OK, got {}", res);
                }

                Ok(())
            }
        ).await.unwrap();
    });
}

pub fn redirect_http_to_https_test(env: TestEnv) {
    let logger = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let client_builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0);
        let client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .resolve(host, bn_addr.into())
            .resolve(&format!("raw.{host}"), bn_addr.into());
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    let futs = FuturesUnordered::new();

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
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

    let host = host_orig;
    futs.push(rt.spawn({
        let client = client;
        let name = "redirect raw http to https";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client.get(format!("http://raw.{host}/")).send().await?;

            if res.status() != reqwest::StatusCode::MOVED_PERMANENTLY {
                bail!("{name} failed: {}", res.status())
            }

            let location_hdr = res.headers().get("Location").unwrap().to_str().unwrap();
            if location_hdr != format!("https://raw.{host}/") {
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
}

pub fn redirect_to_dashboard_test(env: TestEnv) {
    let logger = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let client_builder = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(boundary_node.uses_snake_oil_certs())
        .redirect(reqwest::redirect::Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0);
        let client_builder = client_builder
            .resolve(host, bn_addr.into())
            .resolve(&format!("raw.{host}"), bn_addr.into());
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    let futs = FuturesUnordered::new();

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "redirect to dashboard";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client.get(format!("https://{host}/")).send().await?;

            if res.status() != reqwest::StatusCode::FOUND {
                bail!("{name} failed: {}", res.status())
            }

            let location_hdr = res.headers().get("Location").unwrap().to_str().unwrap();
            if location_hdr != "https://dashboard.internetcomputer.org/" {
                bail!("{name} failed: wrong location header: {}", location_hdr)
            }

            Ok(())
        }
    }));

    let host = host_orig;
    futs.push(rt.spawn({
        let client = client;
        let name = "redirect raw to dashboard";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client.get(format!("https://raw.{host}/")).send().await?;

            if res.status() != reqwest::StatusCode::FOUND {
                bail!("{name} failed: {}", res.status())
            }

            let location_hdr = res.headers().get("Location").unwrap().to_str().unwrap();
            if location_hdr != "https://dashboard.internetcomputer.org/" {
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
}

pub fn redirect_to_non_raw_test(env: TestEnv) {
    let logger = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let client_builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0);
        let client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .resolve(&format!("raw.{host}"), bn_addr.into());
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    let futs = FuturesUnordered::new();

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "redirect status to non-raw domain";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!("https://raw.{host}/api/v2/status"))
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::TEMPORARY_REDIRECT {
                bail!("{name} failed: {}", res.status())
            }

            let location_hdr = res.headers().get("Location").unwrap().to_str().unwrap();
            if location_hdr != format!("https://{host}/api/v2/status") {
                bail!("{name} failed: wrong location header: {}", location_hdr)
            }

            Ok(())
        }
    }));

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "redirect query to non-raw domain";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .post(format!("https://raw.{host}/api/v2/canister/CID/query"))
                .body("body")
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::TEMPORARY_REDIRECT {
                bail!("{name} failed: {}", res.status())
            }

            let location_hdr = res.headers().get("Location").unwrap().to_str().unwrap();
            if location_hdr != format!("https://{host}/api/v2/canister/CID/query") {
                bail!("{name} failed: wrong location header: {}", location_hdr)
            }

            Ok(())
        }
    }));

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "redirect call to non-raw domain";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .post(format!("https://raw.{host}/api/v2/canister/CID/call"))
                .body("body")
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::TEMPORARY_REDIRECT {
                bail!("{name} failed: {}", res.status())
            }

            let location_hdr = res.headers().get("Location").unwrap().to_str().unwrap();
            if location_hdr != format!("https://{host}/api/v2/canister/CID/call") {
                bail!("{name} failed: wrong location header: {}", location_hdr)
            }

            Ok(())
        }
    }));

    let host = host_orig;
    futs.push(rt.spawn({
        let client = client;
        let name = "redirect read_state to non-raw domain";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .post(format!("https://raw.{host}/api/v2/canister/CID/read_state"))
                .body("body")
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::TEMPORARY_REDIRECT {
                bail!("{name} failed: {}", res.status())
            }

            let location_hdr = res.headers().get("Location").unwrap().to_str().unwrap();
            if location_hdr != format!("https://{host}/api/v2/canister/CID/read_state") {
                bail!("{name} failed: wrong location header: {}", location_hdr)
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
}

// this tests the HTTP endpoint of the boundary node (anything that goes to icx-proxy)
pub fn http_endpoint_test(env: TestEnv) {
    let logger_orig = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    let asset_canister_orig = rt.block_on(env.deploy_asset_canister()).unwrap();

    let client_builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0);
        let client_builder = client_builder.danger_accept_invalid_certs(true).resolve(
            &format!("{0}.{host}", asset_canister_orig.canister_id),
            bn_addr.into(),
        );
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let futs = FuturesUnordered::new();

    // fetching standard assets (html page, JS script) through icx-proxy
    let host = host_orig.clone();
    let logger = logger_orig.clone();
    let asset_canister = asset_canister_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "get index.html with response verification";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let hello_world = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
            info!(&logger, "Uploading hello world response...");
            asset_canister
                .upload_asset(&UploadAssetRequest {
                    key: "/".to_string(),
                    content: hello_world.clone(),
                    content_type: "text/plain".to_string(),
                    content_encoding: "identity".to_string(),
                    sha_override: None,
                })
                .await?;

            let res = client
                .get(format!("https://{0}.{host}/", asset_canister.canister_id))
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains("Hello World!") {
                bail!("{name} failed: expected icx-response but got {body}")
            }

            let hello_world_js = vec![
                99, 111, 110, 115, 111, 108, 101, 46, 108, 111, 103, 40, 34, 72, 101, 108, 108,
                111, 32, 87, 111, 114, 108, 100, 33, 34, 41,
            ];
            info!(&logger, "Uploading hello world JS response...");
            asset_canister
                .upload_asset(&UploadAssetRequest {
                    key: "/foo.js".to_string(),
                    content: hello_world_js.clone(),
                    content_type: "application/javascript".to_string(),
                    content_encoding: "identity".to_string(),
                    sha_override: None,
                })
                .await?;

            let res = client
                .get(format!(
                    "https://{0}.{host}/foo.js",
                    asset_canister.canister_id
                ))
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains(r#"console.log("Hello World!")"#) {
                bail!("{name} failed: expected icx-response but got {body}")
            }

            Ok(())
        }
    }));

    // fetching assets from non-root path
    let host = host_orig.clone();
    let logger = logger_orig.clone();
    let asset_canister = asset_canister_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "get from non-root path";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let a_b_c = vec![
                68, 111, 32, 114, 101, 32, 109, 105, 44, 32, 65, 32, 66, 32, 67, 44, 32, 49, 32,
                50, 32, 51,
            ];
            info!(&logger, "Uploading A B C response...");
            asset_canister
                .upload_asset(&UploadAssetRequest {
                    key: "/a/b/c".to_string(),
                    content: a_b_c.clone(),
                    content_type: "text/plain".to_string(),
                    content_encoding: "identity".to_string(),
                    sha_override: None,
                })
                .await?;

            let res = client
                .get(format!(
                    "https://{}.{host}/a/b/c",
                    asset_canister.canister_id
                ))
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains("Do re mi, A B C, 1 2 3") {
                bail!("{name} failed: expected icx-response but got {body}")
            }

            Ok(())
        }
    }));

    let logger = logger_orig.clone();
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
}

pub fn icx_proxy_test(env: TestEnv) {
    let logger = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    let canister_id = rt
        .block_on(install_canister(
            env.clone(),
            logger.clone(),
            &env::var("HTTP_COUNTER_WASM_PATH").expect("HTTP_COUNTER_WASM_PATH not set"),
        ))
        .unwrap();

    let client_builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0);
        let client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .resolve(&format!("{canister_id}.{host}"), bn_addr.into())
            .resolve(&format!("{canister_id}.raw.{host}"), bn_addr.into());
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let futs = FuturesUnordered::new();

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "get sent to icx-proxy via /_/raw/";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!("https://{canister_id}.{host}/_/raw/"))
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::INTERNAL_SERVER_ERROR {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains("Body does not pass verification") {
                bail!("{name} failed: expected 'Body does not pass verification' but got {body}")
            }

            Ok(())
        }
    }));

    let host = host_orig;
    futs.push(rt.spawn({
        let client = client;
        let name = "get sent to icx-proxy via raw domain";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!("https://{canister_id}.raw.{host}/"))
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains("Counter is 0") {
                bail!("{name} failed: expected icx-response but got {body}")
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
}

pub fn direct_to_replica_test(env: TestEnv) {
    let logger = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .expect("failed to get BN snapshot");

    let client_builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0);
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

            info!(&logger, "Waiting for canisters to finish installing...");
            ic_system_test_driver::retry_with_msg_async!(
                format!(
                    "agent of {} observes canister module {}",
                    install_url.to_string(),
                    cid.to_string()
                ),
                &logger,
                READY_WAIT_TIMEOUT,
                RETRY_BACKOFF,
                || async {
                    match agent_observes_canister_module(&agent, &cid).await {
                        true => Ok(()),
                        false => panic!("Canister module not available yet"),
                    }
                }
            )
            .await
            .unwrap();

            info!(&logger, "creating agent");
            let transport =
                ReqwestTransport::create_with_client(format!("https://{host}/"), client)?;

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

            info!(&logger, "Waiting for canisters to finish installing...");
            ic_system_test_driver::retry_with_msg_async!(
                format!(
                    "agent of {} observes canister module {}",
                    install_url.to_string(),
                    cid.to_string()
                ),
                &logger,
                READY_WAIT_TIMEOUT,
                RETRY_BACKOFF,
                || async {
                    match agent_observes_canister_module(&agent, &cid).await {
                        true => Ok(()),
                        false => panic!("Canister module not available yet"),
                    }
                }
            )
            .await
            .unwrap();

            info!(&logger, "creating agent");
            let transport =
                ReqwestTransport::create_with_client(format!("https://{host}/"), client)?;

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
}

pub fn direct_to_replica_options_test(env: TestEnv) {
    let logger = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .expect("failed to get BN snapshot");

    let client_builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0);
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

            info!(&logger, "Waiting for canisters to finish installing...");
            ic_system_test_driver::retry_with_msg_async!(
                format!(
                    "agent of {} observes canister module {}",
                    install_url.to_string(),
                    cid.to_string()
                ),
                &logger,
                READY_WAIT_TIMEOUT,
                RETRY_BACKOFF,
                || async {
                    match agent_observes_canister_module(&agent, &cid).await {
                        true => Ok(()),
                        false => panic!("Canister module not available yet"),
                    }
                }
            )
            .await
            .unwrap();

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
                ("Access-Control-Allow-Headers", "DNT,User-Agent,X-Requested-With,If-None-Match,If-Modified-Since,Cache-Control,Content-Type,Range,Cookie,X-Ic-Canister-Id"),
                ("Access-Control-Expose-Headers", "Accept-Ranges,Content-Length,Content-Range,X-Request-Id,X-Ic-Canister-Id"),
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
}

pub fn direct_to_replica_rosetta_test(env: TestEnv) {
    let logger = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .expect("failed to get BN snapshot");

    let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0);

    let client = reqwest::ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .resolve("rosetta.dfinity.network", bn_addr.into())
        .build()
        .expect("failed to build http client");

    let (install_url, effective_canister_id) =
        get_install_url(&env).expect("failed to get install url");

    let rt = Runtime::new().expect("failed to create tokio runtime");

    let futs = FuturesUnordered::new();

    futs.push(rt.spawn({
        let client = client.clone();
        let name = "rosetta: status from random node";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get("https://rosetta.dfinity.network/api/v2/status")
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

    futs.push(rt.spawn({
        let logger = logger.clone();
        let client = client.clone();
        let install_url = install_url.clone();
        let name = "rosetta: query random node";
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

            info!(&logger, "Waiting for canisters to finish installing...");
            ic_system_test_driver::retry_with_msg_async!(
                format!(
                    "agent of {} observes canister module {}",
                    install_url.to_string(),
                    cid.to_string()
                ),
                &logger,
                READY_WAIT_TIMEOUT,
                RETRY_BACKOFF,
                || async {
                    match agent_observes_canister_module(&agent, &cid).await {
                        true => Ok(()),
                        false => panic!("Canister module not available yet"),
                    }
                }
            )
            .await
            .unwrap();

            info!(&logger, "creating agent");
            let transport =
                ReqwestTransport::create_with_client("https://rosetta.dfinity.network/", client)?;

            let agent = Agent::builder().with_transport(transport).build()?;
            agent.fetch_root_key().await?;

            info!(&logger, "querying canister");
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

    futs.push(rt.spawn({
        let logger = logger.clone();
        let client = client;
        let name = "rosetta: update random node";
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

            info!(&logger, "Waiting for canisters to finish installing...");
            ic_system_test_driver::retry_with_msg_async!(
                format!(
                    "agent of {} observes canister module {}",
                    install_url.to_string(),
                    cid.to_string()
                ),
                &logger,
                READY_WAIT_TIMEOUT,
                RETRY_BACKOFF,
                || async {
                    match agent_observes_canister_module(&agent, &cid).await {
                        true => Ok(()),
                        false => panic!("Canister module not available yet"),
                    }
                }
            )
            .await
            .unwrap();

            info!(&logger, "creating agent");
            let transport =
                ReqwestTransport::create_with_client("https://rosetta.dfinity.network/", client)?;

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
}

pub fn seo_test(env: TestEnv) {
    let logger_orig = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");

    // create an asset canister for the test
    let asset_canister_orig = rt.block_on(env.deploy_asset_canister()).unwrap();

    let client_builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0);
        let client_builder = client_builder.danger_accept_invalid_certs(true).resolve(
            &format!("{0}.{host}", asset_canister_orig.canister_id),
            bn_addr.into(),
        );
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let futs = FuturesUnordered::new();

    let host = host_orig;
    let logger = logger_orig.clone();
    let asset_canister = asset_canister_orig.clone();

    futs.push(rt.spawn({
        let name = "get sent to icx-proxy if you're a bot";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let hello_world = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
            info!(&logger, "Uploading hello world response...");
            asset_canister
                .upload_asset(&UploadAssetRequest {
                    key: "/".to_string(),
                    content: hello_world.clone(),
                    content_type: "text/plain".to_string(),
                    content_encoding: "identity".to_string(),
                    sha_override: None,
                })
                .await?;

            let res = client
                .get(format!("https://{0}.{host}/", asset_canister.canister_id))
                .header(
                    "User-Agent",
                    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                )
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains("Hello World!") {
                bail!("{name} failed: expected icx-response but got {body}")
            }

            Ok(())
        }
    }));

    rt.block_on(async move {
        let mut cnt_err = 0;
        info!(&logger_orig, "Waiting for subtests");

        for fut in futs {
            match fut.await {
                Ok(Err(err)) => {
                    error!(logger_orig, "test failed: {}", err);
                    cnt_err += 1;
                }
                Err(err) => {
                    error!(logger_orig, "test panicked: {}", err);
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
}

/* tag::catalog[]
Title:: Boundary nodes reboot test

Goal:: Reboot a boundary node

Runbook:
Start a boundary node and reboot it.

Success:: The boundary node reboots and continues to answer requests.

Coverage:: boundary nodes survive reboots

end::catalog[] */

pub fn reboot_test(env: TestEnv) {
    let logger = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    info!(&logger, "Rebooting the boundary node VM.");
    boundary_node.vm().reboot();

    info!(
        &logger,
        "Waiting for the boundary node to get an IPv4 address."
    );
    info!(
        &logger,
        "Boundary node {BOUNDARY_NODE_NAME} has IPv4 {:?}",
        boundary_node.block_on_ipv4().unwrap()
    );

    info!(&logger, "Checking BN health");
    boundary_node
        .await_status_is_healthy()
        .expect("Boundary node did not come up healthy.");
}

/* tag::catalog[]
Title:: Handle incoming canister calls by the boundary node.

Goal:: Verify that ic-boundary service of the boundary node routes canister requests (query/call/read_state) on different subnets correctly.

Runbook:
. Setup:
    . Subnets(>=2) with node/s(>=1) on each subnet.
    . A single boundary node.
. Install three counter canisters on each subnet.
. Set unique counter values on each canister via update (`write`) calls. All calls are executed via boundary node agent.
. Verify an OK execution status of each update call via read_state call.
. Retrieve counter values from each canister via query (`read`) call.
. Assert that retrieved values match the expected ones.

end::catalog[] */

pub fn canister_routing_test(env: TestEnv) {
    let log = env.logger();
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
        let boundary_node = env
            .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
            .unwrap()
            .get_snapshot()
            .unwrap();

        block_on(agent_using_call_v2_endpoint(
            boundary_node.get_public_url().as_ref(),
            boundary_node.ipv6().into(),
        ))
        .expect("Agent can be created")
    };

    info!(
        log,
        "Incrementing counters on canisters via BN agent update calls ..."
    );
    block_on(set_counters_on_counter_canisters(
        &log,
        bn_agent.clone(),
        canister_ids.clone(),
        canister_values.clone(),
        CANISTER_RETRY_BACKOFF,
        CANISTER_RETRY_TIMEOUT,
    ));
    info!(
        log,
        "Asserting expected counters on canisters via BN agent query calls ... "
    );
    let counters = block_on(read_counters_on_counter_canisters(
        &log,
        bn_agent,
        canister_ids,
        CANISTER_RETRY_BACKOFF,
        CANISTER_RETRY_TIMEOUT,
    ));
    assert_eq!(counters, canister_values);
}

pub fn read_state_via_subnet_path_test(env: TestEnv) {
    let log = env.logger();
    let bn_agent = {
        let boundary_node = env
            .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
            .unwrap()
            .get_snapshot()
            .unwrap();
        boundary_node.build_default_agent()
    };
    let subnet_id: Principal = env
        .topology_snapshot()
        .subnets()
        .next()
        .expect("no subnets found")
        .subnet_id
        .get()
        .0;
    let metrics = block_on(bn_agent.read_state_subnet_metrics(subnet_id))
        .expect("Call to read_state via /api/v2/subnet/{subnet_id}/read_state failed.");
    info!(log, "subnet metrics are {:?}", metrics);
}

/* tag::catalog[]
Title:: Boundary nodes headers test

Goal:: Make sure the boundary node sets the content-type, x-content-type-options, x-frame-options ehaders

end::catalog[] */

pub fn headers_test(env: TestEnv) {
    let logger = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        let http_client_builder = reqwest::ClientBuilder::new();
        let (client_builder, host) = if let Some(playnet) = boundary_node.get_playnet() {
            (http_client_builder, playnet)
        } else {
            let host = "ic0.app";
            let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 443, 0, 0).into();
            let client_builder = http_client_builder
                .danger_accept_invalid_certs(true)
                .resolve(host, bn_addr);
            (client_builder, host.to_string())
        };
        let http_client = client_builder.build().unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            "Making a status call to inspect the headers",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                info!(&logger, "Requesting status endpoint...");
                let res = http_client
                    .get(format!("https://{host}/api/v2/status"))
                    .send()
                    .await
                    .unwrap();

                let headers = res.headers();
                assert!(
                    headers.contains_key("content-type"),
                    "Header content-type is missing"
                );
                assert_eq!(
                    headers.get("content-type").unwrap(),
                    "application/cbor",
                    "Header content-type does not match expected value: application/cbor"
                );

                assert!(
                    headers.contains_key("x-content-type-options"),
                    "Header x-content-type-options is missing"
                );
                assert_eq!(
                    headers.get("x-content-type-options").unwrap(),
                    "nosniff",
                    "Header x-content-type-options does not match expected value: nosniff",
                );

                assert!(
                    headers.contains_key("x-frame-options"),
                    "Header x-frame-options is missing"
                );
                assert_eq!(
                    headers.get("x-frame-options").unwrap(),
                    "DENY",
                    "Header x-frame-options does not match expected value: DENY",
                );
                Ok(())
            }
        )
        .await
        .unwrap();
    });
}
