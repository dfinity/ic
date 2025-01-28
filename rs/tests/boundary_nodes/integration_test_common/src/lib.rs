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

use ic_boundary_nodes_system_test_utils::{
    constants::{BOUNDARY_NODE_NAME, COUNTER_CANISTER_WAT},
    helpers::{create_canister, get_install_url},
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
    retry_with_msg_async,
    util::{agent_observes_canister_module, assert_create_agent, block_on},
};
use ic_types::PrincipalId;
use std::{env, iter, net::SocketAddrV6, time::Duration};

use anyhow::{anyhow, bail, Context, Error};
use futures::stream::FuturesUnordered;
use ic_agent::{export::Principal, Agent};
use reqwest::{redirect::Policy, ClientBuilder, Method, StatusCode};
use serde::Deserialize;
use slog::{error, info, Logger};
use tokio::{runtime::Runtime, time::sleep};
use v2_call_transport::V2CallAgent;

mod v2_call_transport;

fn runtime() -> Runtime {
    Runtime::new().expect("Could not create tokio runtime")
}

async fn install_counter_canister(env: TestEnv, logger: Logger) -> Result<Principal, Error> {
    info!(&logger, "creating management agent");
    let (install_url, effective_canister_id) =
        get_install_url(&env).expect("failed to get install url");

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
    retry_with_msg_async!(
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
    .await?;

    info!(&logger, "created canister {cid}");

    Ok::<_, Error>(cid)
}

fn setup_client(env: TestEnv) -> Result<(reqwest::Client, String), Error> {
    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .expect("failed to get BN snapshot");

    let client_builder = ClientBuilder::new().redirect(Policy::none());
    let (client_builder, host) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 0, 0, 0);
        let client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .resolve(host, bn_addr.into());
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    Ok((client, host))
}

/* tag::catalog[]
Title:: Boundary Nodes API Endpoints Test - Status

Goal:: api/v2/status - just make a status call against the boundary node

end::catalog[] */
pub fn api_status_test(env: TestEnv) {
    let name = "api/v2/status";
    let logger = env.logger();
    info!(&logger, "Starting {name} test");

    let (client, host) = setup_client(env).expect("failed to setup client");

    block_on(async move {
        let res = client
            .get(format!("https://{host}/api/v2/status"))
            .send()
            .await?;

        if res.status() != StatusCode::OK {
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
    })
    .unwrap();
}

/* tag::catalog[]
Title:: Boundary Nodes API Endpoints Test - Query

Goal:: api/v2/query - install a counter canister and query it

end::catalog[] */
pub fn api_query_test(env: TestEnv) {
    let name = "api/v2/query - query counter";
    let logger = env.logger();
    info!(&logger, "Starting {name} test");

    let (client, host) = setup_client(env.clone()).expect("failed to setup client");

    block_on(async move {
        let cid = install_counter_canister(env, logger.clone()).await?;

        let agent = Agent::builder()
            .with_url(format!("https://{host}/"))
            .with_http_client(client)
            .build()?;
        agent.fetch_root_key().await?;

        let out = agent.query(&cid, "read").call().await?;
        if !out.eq(&[0, 0, 0, 0]) {
            bail!("{name} failed: got {:?}, expected {:?}", out, &[0, 0, 0, 0],)
        }

        Ok(())
    })
    .unwrap();
}

/* tag::catalog[]
Title:: Boundary Nodes API Endpoints Test - Call

Goal:: api/v2/call - install a counter canister and update it

end::catalog[] */
pub fn api_call_test(env: TestEnv) {
    let name = "api/v2/call - update counter";
    let logger = env.logger();
    info!(&logger, "Starting {name} test");

    let (client, host) = setup_client(env.clone()).expect("failed to setup client");

    block_on(async move {
        let cid = install_counter_canister(env, logger.clone()).await?;
        let canister_principal_id = PrincipalId(cid);

        // update call
        let v2_test_agent = V2CallAgent::new(client.clone(), host.clone(), logger.clone());
        v2_test_agent
            .call(canister_principal_id, "write".to_string())
            .await
            .unwrap();

        // check that the update call went through
        let agent = Agent::builder()
            .with_url(format!("https://{host}/"))
            .with_http_client(client)
            .build()?;
        agent.fetch_root_key().await?;

        let out = agent.query(&cid, "read").call().await?;
        if !out.eq(&[1, 0, 0, 0]) {
            bail!("{name} failed: got {:?}, expected {:?}", out, &[1, 0, 0, 0],)
        }

        Ok(())
    })
    .unwrap();
}

/* tag::catalog[]
Title:: Boundary Nodes API Endpoints Test - Sync Call

Goal:: api/v3/call - install a counter canister and update it

end::catalog[] */
pub fn api_sync_call_test(env: TestEnv) {
    let name = "api/v3/call - update counter";
    let logger = env.logger();
    info!(&logger, "Starting {name} test");

    let (client, host) = setup_client(env.clone()).expect("failed to setup client");

    block_on(async move {
        let cid = install_counter_canister(env.clone(), logger.clone()).await?;

        let agent = Agent::builder()
            .with_url(format!("https://{host}/"))
            .with_http_client(client)
            .build()?;
        agent.fetch_root_key().await?;

        // update call
        agent.update(&cid, "write").call_and_wait().await?;

        // check that the update call went through
        let out = agent.query(&cid, "read").call().await?;
        if !out.eq(&[1, 0, 0, 0]) {
            bail!("{name} failed: got {:?}, expected {:?}", out, &[1, 0, 0, 0],)
        }
        Ok(())
    })
    .unwrap();
}

/* tag::catalog[]
Title:: Boundary Nodes API Endpoints Test - Read State Canister Path

Goal:: api/v2/read_state canister path - install a counter canister and request the module hash of the canister from the state

end::catalog[] */
pub fn api_canister_read_state_test(env: TestEnv) {
    let name = "api/v2/read state - canister path";
    let logger = env.logger();
    info!(&logger, "Starting {name} test");

    let (client, host) = setup_client(env.clone()).expect("failed to setup client");

    block_on(async move {
        let cid = install_counter_canister(env.clone(), logger.clone()).await?;

        let agent = Agent::builder()
            .with_url(format!("https://{host}/"))
            .with_http_client(client)
            .build()?;
        agent.fetch_root_key().await?;

        let _ = agent.read_state_canister_info(cid, "module_hash").await?;

        Ok::<(), Error>(())
    })
    .unwrap();
}

/* tag::catalog[]
Title:: Boundary Nodes API Endpoints Test - Read State Subnet Path

Goal:: api/v2/read_state subnet path - request the subnet metrics from the certified state

end::catalog[] */
pub fn api_subnet_read_state_test(env: TestEnv) {
    let name = "api/v2/read state - subnet path";
    let logger = env.logger();
    info!(&logger, "Starting {name} test");

    let (client, host) = setup_client(env.clone()).expect("failed to setup client");

    block_on(async move {
        let agent = Agent::builder()
            .with_url(format!("https://{host}/"))
            .with_http_client(client)
            .build()?;
        agent.fetch_root_key().await?;

        let subnet_id: Principal = env
            .topology_snapshot()
            .subnets()
            .next()
            .expect("no subnets found")
            .subnet_id
            .get()
            .0;
        let metrics = agent.read_state_subnet_metrics(subnet_id).await?;
        info!(&logger, "subnet metrics are {:?}", metrics);

        Ok::<(), Error>(())
    })
    .expect("{name} failed");
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

pub fn legacy_asset_canister_test(env: TestEnv) {
    let logger_orig = env.logger();
    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = runtime();

    info!(&logger_orig, "Creating asset canister");
    let asset_canister_orig = rt
        .block_on(env.deploy_legacy_asset_canister())
        .expect("Could not install asset canister");

    let http_client_builder = ClientBuilder::new();
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (
            http_client_builder,
            format!("{0}.{playnet}", asset_canister_orig.canister_id),
        )
    } else {
        let host = format!("{0}.ic0.app", asset_canister_orig.canister_id);
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 0, 0, 0).into();
        let client_builder = http_client_builder
            .danger_accept_invalid_certs(true)
            .resolve(&host, bn_addr);
        (client_builder, host)
    };
    let http_client = client_builder.build().unwrap();

    let futs = FuturesUnordered::new();
    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let http_client = http_client.clone();
        let name = "Requesting a small asset with the correct hash succeeds and is verified without streaming";
        info!(&logger, "Starting subtest {}", name);

        async move {
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
    }));

    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let http_client = http_client.clone();
        let name = "Requesting a small, gzipped asset with the correct hash succeeds and is verified without streaming";
        info!(&logger, "Starting subtest {}", name);

        async move {
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
    }));

    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let http_client = http_client.clone();
        let name = "Requesting a 4mb asset with the correct hash succeeds and is within the limit that we can safely verify while streaming so it is verified";
        info!(&logger, "Starting subtest {}", name);

        async move {
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
                .await.context("unable to upload asset")?;

            info!(&logger, "Requesting 4mb asset...");
            let res = http_client
                .get(format!("https://{host}/4mb.txt"))
                .header("accept-encoding", "gzip")
                .send()
                .await.context("unable to request asset")?
                .bytes()
                .await.context("unable to download asset body")?
                .to_vec();

            if res != req_body {
                bail!("4mb response did not match uploaded content: expected size: {}, got: {}", req_body.len(), res.len())
            }

            Ok(())
        }
    }));

    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let http_client = http_client.clone();
        let name = "Requesting a 6mb asset with the correct hash succeeds and is within the limit that we can safely verify while streaming so it is verified";
        info!(&logger, "Starting subtest {}", name);

        async move {
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
                .await.context("unable to upload asset")?;

            info!(&logger, "Requesting 6mb asset...");
            let res = http_client
                .get(format!("https://{host}/6mb.txt"))
                .header("accept-encoding", "gzip")
                .send()
                .await.context("unable to request asset")?
                .bytes()
                .await.context("unable to download asset body")?
                .to_vec();

            if res != req_body {
                bail!("6mb response did not match uploaded content: expected size: {}, got: {}", req_body.len(), res.len())
            }

            Ok(())
        }
    }));

    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let http_client = http_client.clone();
        let name = "Requesting an 8mb asset with the correct hash succeeds and is within the limit that we can safely verify while streaming so it is verified";
        info!(&logger, "Starting subtest {}", name);

        async move {
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
                .await.context("unable to upload asset")?;

            info!(&logger, "Requesting 8mb asset...");
            let res = http_client
                .get(format!("https://{host}/8mb.txt"))
                .header("accept-encoding", "gzip")
                .send()
                .await.context("unable to request asset")?
                .bytes()
                .await.context("unable to download asset body")?
                .to_vec();

            if res != req_body {
                bail!("8mb response did not match uploaded content: expected size: {}, got: {}", req_body.len(), res.len())
            }

            Ok(())
        }
    }));

    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let http_client = http_client.clone();
        let name = "Requesting a 10mb asset with the correct hash succeeds but the asset is larger than the limit that we can safely verify while streaming so it is not verified";
        info!(&logger, "Starting subtest {}", name);

        async move {
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
                    .await.context("unable to upload asset")?;

                info!(&logger, "Requesting 10mb asset...");
                let res = http_client
                    .get(format!("https://{host}/10mb.txt"))
                    .header("accept-encoding", "gzip")
                    .send()
                    .await.context("unable to request asset")?
                    .bytes()
                    .await.context("unable to download asset body")?
                    .to_vec();

                if res != req_body {
                    bail!("10mb response did not match uploaded content: expected size: {}, got: {}", req_body.len(), res.len())
                }

            Ok(())
        }
    }));

    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let http_client = http_client.clone();
        let name = "Requesting a 4mb asset with the incorrect hash fails because the asset is within the limit that we can safely verify while streaming";
        info!(&logger, "Starting subtest {}", name);

        async move {
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
                    .await.context("unable to upload asset")?;

                info!(&logger, "Requesting invalid 4mb asset...");
                let res = http_client
                    .get(format!("https://{host}/invalid-4mb.txt"))
                    .header("accept-encoding", "gzip")
                    .send()
                    .await.context("unable to request asset")?;

                if res.status() != StatusCode::SERVICE_UNAVAILABLE {
                    bail!("invalid 4mb asset did not fail verification")
                }

                Ok(())
        }
    }));

    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let http_client = http_client.clone();
        let name = "Requesting a 10mb asset with an invalid hash succeeds because the asset is larger than what we can safely verify while streaming";
        info!(&logger, "Starting subtest {}", name);

        async move {
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
                    .await.context("unable to upload asset")?;

                info!(&logger, "Requesting invalid 10mb asset...");
                let res = http_client
                    .get(format!("https://{host}/invalid-10mb.txt"))
                    .header("accept-encoding", "gzip")
                    .send()
                    .await.context("unable to request asset")?
                    .bytes()
                    .await.context("unable to download asset body")?
                    .to_vec();

                if res != req_body {
                    bail!("invalid 10mb response did not match uploaded content: expected size: {}, got: {}", req_body.len(), res.len())
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

// Constants copied from long asset canister:
const ASSET_CHUNK_SIZE: usize = 2_000_000;

const ONE_CHUNK_ASSET_LEN: usize = ASSET_CHUNK_SIZE;
const TWO_CHUNKS_ASSET_LEN: usize = ASSET_CHUNK_SIZE + 1;
const SIX_CHUNKS_ASSET_LEN: usize = 5 * ASSET_CHUNK_SIZE + 12;

pub fn long_asset_canister_test(env: TestEnv) {
    let logger_orig = env.logger();
    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = runtime();

    info!(&logger_orig, "Creating asset canister");
    let asset_canister_orig = rt
        .block_on(env.deploy_long_asset_canister())
        .expect("Could not install asset canister");

    let http_client_builder = ClientBuilder::new();
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (
            http_client_builder,
            format!("{0}.{playnet}", asset_canister_orig.canister_id),
        )
    } else {
        let host = format!("{0}.ic0.app", asset_canister_orig.canister_id);
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 0, 0, 0).into();
        let client_builder = http_client_builder
            .danger_accept_invalid_certs(true)
            .resolve(&host, bn_addr);
        (client_builder, host)
    };
    let http_client = client_builder.build().unwrap();

    let futs = FuturesUnordered::new();
    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let http_client = http_client.clone();
        let name = "Requesting a single chunk asset";
        info!(&logger, "Starting subtest {}", name);

        async move {
            info!(&logger, "Requesting /long_asset_one_chunk ...");
            let res = http_client
                .get(format!("https://{host}/long_asset_one_chunk"))
                .header("accept-encoding", "gzip")
                .send()
                .await?
                .bytes()
                .await?
                .to_vec();

            if res.len() != ONE_CHUNK_ASSET_LEN {
                bail!("/long_asset_one_chunk response did not match uploaded content")
            }

            Ok(())
        }
    }));

    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let http_client = http_client.clone();
        let name = "Requesting a two chunk asset";
        info!(&logger, "Starting subtest {}", name);

        async move {
            info!(&logger, "Requesting /long_asset_two_chunks ...");
            let res = http_client
                .get(format!("https://{host}/long_asset_two_chunks"))
                .header("accept-encoding", "gzip")
                .send()
                .await?
                .bytes()
                .await?
                .to_vec();

            if res.len() != TWO_CHUNKS_ASSET_LEN {
                bail!("/long_asset_two_chunks response did not match uploaded content")
            }

            Ok(())
        }
    }));

    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let http_client = http_client.clone();
        let name = "Requesting a six chunk asset";
        info!(&logger, "Starting subtest {}", name);

        async move {
            info!(&logger, "Requesting /long_asset_six_chunks ...");
            let res = http_client
                .get(format!("https://{host}/long_asset_six_chunks"))
                .header("accept-encoding", "gzip")
                .send()
                .await?
                .bytes()
                .await?
                .to_vec();

            if res.len() != SIX_CHUNKS_ASSET_LEN {
                bail!("/long_asset_six_chunks response did not match uploaded content")
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

    let rt = runtime();
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
        sleep(Duration::from_secs(5)).await;

        let client_builder = ClientBuilder::new();
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
                let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 0, 0, 0).into();
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
        retry_with_msg_async!(
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
                    bail!("expected 'foo not found' got '{res}'");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        // "x-ic-test", "no-certificate"
        // "x-ic-test", "streaming-callback"

        retry_with_msg_async!(
            format!("PUT {} (expecting set to bar)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client.put(url).body("bar").send().await?.text().await?;

                if res != "'/foo' set to 'bar'" {
                    bail!("expected \"'/foo' set to 'bar'\" to bar, got '{res}'");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        retry_with_msg_async!(
            format!("GET {} (expecting bar)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client.get(url).send().await?.text().await?;

                if res != "bar" {
                    bail!("expected 'bar' got '{res}'");
                }

                Ok(())
            }
        )
        .await
        .unwrap();

        retry_with_msg_async!(
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
                    bail!("expected 'bar' got '{res}'");
                };

                Ok(())
            }
        )
        .await
        .unwrap();

        // Check that `canisterId` parameters go unused
        let url = &format!("https://{invalid_host}/?canisterId={canister_id}");
        retry_with_msg_async!(
            format!("GET {} (expecting 400)", url),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let res = client.get(url).send().await?;

                if res.status() != StatusCode::BAD_REQUEST {
                    bail!("expected 400 got '{}'", res.status());
                }

                Ok(())
            }
        )
        .await
        .unwrap();
    });
}

/* tag::catalog[]
Title:: Boundary Nodes Denylist Test

Goal:: Ensure that the denylist blocks requests to canisters and the allowlist
overrides the denylist.

end::catalog[] */

pub fn canister_denylist_test(env: TestEnv) {
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

    let rt = runtime();
    rt.block_on(async move {
        info!(&logger, "creating replica agent");
        let agent = assert_create_agent(install_node.as_ref().unwrap().0.as_str()).await;

        let http_counter_canister = load_wasm(env::var("HTTP_COUNTER_WASM_PATH").expect("HTTP_COUNTER_WASM_PATH not set"));

        info!(&logger, "installing canister");
        let canister_id = create_canister(&agent, install_node.clone().unwrap().1, &http_counter_canister, None)
            .await
            .expect("Could not create http_counter canister");

        info!(&logger, "Waiting for canisters to finish installing...");
        retry_with_msg_async!(
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

        let client_builder = ClientBuilder::new();
        let (client_builder, host) = if let Some(playnet) = boundary_node.get_playnet() {
            (client_builder, playnet)
        } else {
            let host = "ic0.app";
            let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 0, 0, 0);
            let client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .resolve(&format!("{canister_id}.raw.{host}"), bn_addr.into());
            (client_builder, host.to_string())
        };
        let client = client_builder.build().unwrap();

        // Check canister is available
        let url = &format!("https://{canister_id}.raw.{host}/");
        retry_with_msg_async!(
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

                if res != StatusCode::OK {
                    bail!("expected OK, got {}", res);
                }

                Ok(())
            }
        ).await.unwrap();

        // Update the denylist and restart ic-gateway
        let denylist_command = format!(r#"echo "{{\"canisters\":{{\"{}\": {{}}}}}}" | sudo tee /run/ic-node/etc/ic-gateway/denylist.json && sudo service ic-gateway restart"#, canister_id);
        info!(
            logger,
            "update denylist {BOUNDARY_NODE_NAME} with {denylist_command}"
        );
        if let Err(e) = boundary_node.block_on_bash_script(&denylist_command) {
            panic!("bash script failed: {:?}", e);
        }

        // Wait a bit for the restart to complete
        sleep(Duration::from_secs(3)).await;

        // Check canister is restricted
        retry_with_msg_async!(
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

                if res != StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS {
                    bail!("expected 451, got {}", res);
                }

                Ok(())
            }
        ).await.unwrap();

        // Update the allowlist and restart ic-gateway
        let allowlist_command = format!(r#"echo "{}" | sudo tee /run/ic-node/etc/ic-gateway/allowlist.txt && sudo service ic-gateway restart"#, canister_id);
        info!(
            logger,
            "update allowlist {BOUNDARY_NODE_NAME} with {allowlist_command}"
        );
        if let Err(e) = boundary_node.block_on_bash_script(&allowlist_command) {
            panic!("bash script failed: {:?}", e);
        }

        // Wait a bit for the restart to complete
        sleep(Duration::from_secs(3)).await;

        // Check canister is available
        retry_with_msg_async!(
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

                if res != StatusCode::OK {
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

    let client_builder = ClientBuilder::new().redirect(Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 0, 0, 0);
        let client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .resolve(host, bn_addr.into())
            .resolve(&format!("raw.{host}"), bn_addr.into());
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let rt = runtime();

    let futs = FuturesUnordered::new();

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "redirect http to https";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client.get(format!("http://{host}/")).send().await?;

            if res.status() != StatusCode::PERMANENT_REDIRECT {
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

            if res.status() != StatusCode::PERMANENT_REDIRECT {
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

    let client_builder = ClientBuilder::new()
        .danger_accept_invalid_certs(boundary_node.uses_snake_oil_certs())
        .redirect(Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 0, 0, 0);
        let client_builder = client_builder
            .resolve(host, bn_addr.into())
            .resolve(&format!("raw.{host}"), bn_addr.into());
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let rt = runtime();

    let futs = FuturesUnordered::new();

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "redirect to dashboard";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client.get(format!("https://{host}/")).send().await?;

            if res.status() != StatusCode::TEMPORARY_REDIRECT {
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

            if res.status() != StatusCode::TEMPORARY_REDIRECT {
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

/* tag::catalog[]
Title:: Boundary Nodes HTTP Endpoints Test

Goal:: Check all HTTP endpoints

Runbook:
There are 5 subtests:
* / - fetch the root (certified)
* /foo.js - fetch a JS asset (certified)
* /a/b/c - fetch from the non-root path (certified)
* /invalid_data.txt - try to fetch an asset with broken certification
* /invalid_data.txt - fetch an asset over raw with broken certification
* prefix - fetch an asset with a prefixed URL {PREFIX}--{CANISTER_ID}.ic0.app

end::catalog[] */
pub fn http_endpoints_test(env: TestEnv) {
    let logger_orig = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .unwrap();

    let rt = runtime();

    info!(&logger_orig, "Creating asset canister");
    let asset_canister_orig = rt.block_on(env.deploy_legacy_asset_canister()).unwrap();

    info!(&logger_orig, "Uploading static assets");
    #[derive(Clone)]
    struct StaticAsset {
        path: String,
        content: String,
        content_type: String,
        content_encoding: String,
        sha_override: Option<Vec<u8>>,
    }

    let hello_world = StaticAsset {
        path: "/".to_string(),
        content: "Hello World!".to_string(),
        content_type: "text/plain".to_string(),
        content_encoding: "identity".to_string(),
        sha_override: None,
    };

    let foo_js = StaticAsset {
        path: "/foo.js".to_string(),
        content: r#"console.log("Hello World!")"#.to_string(),
        content_type: "application/javascript".to_string(),
        content_encoding: "identity".to_string(),
        sha_override: None,
    };

    let a_b_c = StaticAsset {
        path: "/a/b/c".to_string(),
        content: "Do re mi, A B C, 1 2 3".to_string(),
        content_type: "text/plain".to_string(),
        content_encoding: "identity".to_string(),
        sha_override: None,
    };

    let invalid_data_txt = StaticAsset {
        path: "/invalid_data.txt".to_string(),
        content: "This doesn't checkout".to_string(),
        content_type: "text/plain".to_string(),
        content_encoding: "identity".to_string(),
        sha_override: Some(vec![0; 32]),
    };

    let static_assets = vec![
        hello_world.clone(),
        foo_js.clone(),
        a_b_c.clone(),
        invalid_data_txt.clone(),
    ];

    let logger = logger_orig.clone();
    let asset_canister = asset_canister_orig.clone();
    rt.block_on(async move {
        for asset in static_assets {
            info!(&logger, "Uploading {}", asset.path);
            asset_canister
                .upload_asset(&UploadAssetRequest {
                    key: asset.path,
                    content: asset.content.as_bytes().to_vec(),
                    content_type: asset.content_type,
                    content_encoding: asset.content_encoding,
                    sha_override: asset.sha_override,
                })
                .await?;
        }

        Ok::<(), Error>(())
    })
    .expect("test suite failed");

    info!(&logger_orig, "Creating the client");
    let client_builder = ClientBuilder::new().redirect(Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 0, 0, 0);
        let client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .resolve(
                &format!("{0}.{host}", asset_canister_orig.canister_id),
                bn_addr.into(),
            )
            .resolve(
                &format!("{0}.raw.{host}", asset_canister_orig.canister_id),
                bn_addr.into(),
            )
            .resolve(
                &format!(
                    "ignored-prefix--{0}.{host}",
                    asset_canister_orig.canister_id
                ),
                bn_addr.into(),
            );
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let futs = FuturesUnordered::new();

    // fetching standard assets (html page)
    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let hello_world = hello_world.clone();
        let client = client.clone();
        let name = "get index.html with response verification";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!(
                    "https://{}.{host}{}",
                    asset_canister.canister_id, hello_world.path
                ))
                .send()
                .await?;

            if res.status() != StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains(hello_world.content.as_str()) {
                bail!("{name} failed: expected response but got {body}")
            }

            Ok(())
        }
    }));

    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let foo_js = foo_js.clone();
        let client = client.clone();
        let name = "get foo.js with response verification";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!(
                    "https://{}.{host}{}",
                    asset_canister.canister_id, foo_js.path,
                ))
                .send()
                .await?;

            if res.status() != StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            if let Some(v) = res.headers().get("x-ic-canister-id") {
                let hdr = v.to_str().unwrap();
                let id = asset_canister.canister_id.to_string();
                if hdr != id {
                    bail!("{name} failed: header x-ic-canister-id is incorrect ({hdr} != {id})",);
                }
            } else {
                bail!("{name} failed: header x-ic-canister-id not found");
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains(foo_js.content.as_str()) {
                bail!("{name} failed: expected response but got {body}")
            }

            Ok(())
        }
    }));

    // fetching assets from non-root path
    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let a_b_c = a_b_c.clone();
        let client = client.clone();
        let name = "get from non-root path with response verification";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!(
                    "https://{}.{host}{}",
                    asset_canister.canister_id, a_b_c.path,
                ))
                .send()
                .await?;

            if res.status() != StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains(a_b_c.content.as_str()) {
                bail!("{name} failed: expected response but got {body}")
            }

            Ok(())
        }
    }));

    // fetching assets with prefixed URL
    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let a_b_c = a_b_c.clone();
        let client = client.clone();
        let name = "get from prefixed URL with response verification";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!(
                    "https://ignored-prefix--{}.{host}{}",
                    asset_canister.canister_id, a_b_c.path,
                ))
                .send()
                .await?;

            if res.status() != StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains(a_b_c.content.as_str()) {
                bail!("{name} failed: expected response but got {body}")
            }

            Ok(())
        }
    }));

    // invalid certificate over raw
    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let invalid_data_txt = invalid_data_txt.clone();
        let client = client.clone();
        let name = "get over raw with broken certification";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!(
                    "https://{}.raw.{host}{}",
                    asset_canister.canister_id, invalid_data_txt.path,
                ))
                .send()
                .await?;

            if res.status() != StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains(invalid_data_txt.content.as_str()) {
                bail!("{name} failed: expected response but got {body}")
            }

            Ok(())
        }
    }));

    // fail response verification
    futs.push(rt.spawn({
        let host = host_orig.clone();
        let logger = logger_orig.clone();
        let asset_canister = asset_canister_orig.clone();
        let invalid_data_txt = invalid_data_txt.clone();
        let client = client.clone();
        let name = "get with broken certification";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!(
                    "https://{}.{host}{}",
                    asset_canister.canister_id, invalid_data_txt.path,
                ))
                .send()
                .await?;

            if res.status() != StatusCode::SERVICE_UNAVAILABLE {
                bail!("{name} failed: {}", res.status())
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
Title:: Boundary nodes headers test

Goal:: Make sure the boundary node sets the all the correct headers both for the
CORS preflight requests (OPTIONS) and the actual requests.

For the preflight requests, we expect the following CORS headers:
Access-Control-Allow-Origin, Access-Control-Allow-Methods,
Access-Control-Allow-Headers, Access-Control-Max-Age

For the actual requests, we expect the following headers:
Access-Control-Allow-Origin, Access-Control-Expose-Headers,

end::catalog[] */

pub fn cors_headers_test(env: TestEnv) {
    let logger = env.logger();

    let boundary_node = env
        .get_deployed_boundary_node(BOUNDARY_NODE_NAME)
        .unwrap()
        .get_snapshot()
        .expect("failed to get BN snapshot");

    let client_builder = ClientBuilder::new().redirect(Policy::none());
    let (client_builder, host_orig) = if let Some(playnet) = boundary_node.get_playnet() {
        (client_builder, playnet)
    } else {
        let host = "ic0.app";
        let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 0, 0, 0);
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
            retry_with_msg_async!(
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
        method: Method,
        expect: StatusCode,
        allowed_methods: String,
    }

    let test_cases = [
        TestCase {
            name: "status".into(),
            method: Method::GET,
            expect: StatusCode::OK,
            path: "/api/v2/status".into(),
            allowed_methods: "HEAD, GET".into(),
        },
        TestCase {
            name: "query".into(),
            method: Method::POST,
            expect: StatusCode::BAD_REQUEST,
            path: format!("/api/v2/canister/{cid}/query"),
            allowed_methods: "POST".into(),
        },
        TestCase {
            name: "call".into(),
            method: Method::POST,
            expect: StatusCode::BAD_REQUEST,
            path: format!("/api/v2/canister/{cid}/call"),
            allowed_methods: "POST".into(),
        },
        TestCase {
            name: "read_state".into(),
            method: Method::POST,
            expect: StatusCode::BAD_REQUEST,
            path: format!("/api/v2/canister/{cid}/read_state"),
            allowed_methods: "POST".into(),
        },
    ];

    for tc in test_cases {
        let client = client.clone();
        let logger = logger.clone();

        let TestCase {
            name,
            method,
            expect,
            path,
            allowed_methods,
        } = tc;

        let host = host_orig.clone();
        futs.push(rt.spawn(async move {
            info!(&logger, "Starting subtest {}", name);

            let mut url = reqwest::Url::parse(&format!("https://{host}"))?;
            url.set_path(&path);
            let req = reqwest::Request::new(Method::OPTIONS, url);
            let res = client.execute(req).await?;

            // Both 200 and 204 are valid OPTIONS codes
            if ![StatusCode::NO_CONTENT, StatusCode::OK].contains(&res.status())  {
                bail!("{name} OPTIONS failed: {}", res.status())
            }

            // Normalize & sort header values so that they can be compared regardless of their order
            fn normalize(hdr: &str) -> String {
                let mut hdr = hdr.split(',').map(|x| x.trim().to_ascii_lowercase()).collect::<Vec<_>>();
                hdr.sort();
                hdr.join(",")
            }

            // Check pre-flight CORS headers
            for (k, v) in [
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Methods", &allowed_methods),
                ("Access-Control-Allow-Headers", "DNT,User-Agent,X-Requested-With,If-None-Match,If-Modified-Since,Cache-Control,Content-Type,Range,Cookie,X-Ic-Canister-Id"),
                ("Access-Control-Max-Age", "600"),
            ] {
                let hdr = res
                    .headers()
                    .get(k)
                    .ok_or_else(|| anyhow!("{name} OPTIONS failed: missing {k} header"))?.to_str()?;

                let hdr = normalize(hdr);
                let expect = normalize(v);

                if hdr != expect {
                    bail!("{name} OPTIONS failed: wrong {k} header: {hdr} expected {expect}")
                }
            }

            // Check non-pre-flight CORS headers
            let mut url = reqwest::Url::parse(&format!("https://{host}"))?;
            url.set_path(&path);
            let req = reqwest::Request::new(method, url);
            let res = client.execute(req).await?;

            if res.status() != expect {
                bail!("{name} failed: expected {expect}, got {}", res.status())
            }

            for (k, v) in [
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Expose-Headers", "Accept-Ranges,Content-Length,Content-Range,X-Request-Id,X-Ic-Canister-Id"),
            ] {
                let hdr = res
                    .headers()
                    .get(k)
                    .ok_or_else(|| anyhow!("{name} failed: missing {k} header"))?.to_str()?;

                let hdr = normalize(hdr);
                let expect = normalize(v);

                if hdr != expect {
                    bail!("{name} failed: wrong {k} header: {hdr} expected {expect}")
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

/* tag::catalog[]
Title:: Boundary nodes headers test

Goal:: Make sure the boundary node sets the content-type, x-content-type-options, x-frame-options headers

end::catalog[] */

pub fn content_type_headers_test(env: TestEnv) {
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
            let bn_addr = SocketAddrV6::new(boundary_node.ipv6(), 0, 0, 0).into();
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
