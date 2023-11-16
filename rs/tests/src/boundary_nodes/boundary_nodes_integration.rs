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
        boundary_node::BoundaryNodeVm,
        test_env::TestEnv,
        test_env_api::{
            retry_async, HasPublicApiUrl, HasTopologySnapshot, HasVm, HasWasm, IcNodeContainer,
            RetrieveIpv4Addr, SshSession, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    util::{assert_create_agent, block_on},
};

use crate::boundary_nodes::{
    constants::{BOUNDARY_NODE_NAME, COUNTER_CANISTER_WAT},
    helpers::{
        create_canister, get_install_url, install_canisters, read_counters_on_counter_canisters,
        set_counters_on_counter_canisters,
    },
};
use std::{net::SocketAddrV6, time::Duration};

use anyhow::{anyhow, bail, Error};
use futures::stream::FuturesUnordered;
use ic_agent::{agent::http_transport::ReqwestHttpReplicaV2Transport, export::Principal, Agent};

use serde::Deserialize;
use slog::{error, info, Logger};
use tokio::runtime::Runtime;

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

    let canister = env.load_wasm(path);

    info!(&logger, "installing canister from path {}", path);
    let canister_id = create_canister(&agent, install_node.1, &canister, None)
        .await
        .expect("Could not create http_counter canister");

    // wait for canister to finish installing
    tokio::time::sleep(Duration::from_secs(5)).await;

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
            Ok(boundary_node.try_build_default_agent_async().await?)
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
        let kv_store_canister = env.load_wasm("rs/tests/test_canisters/kv_store/kv_store.wasm");

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

        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{host}/foo"))
                .header("x-ic-test", "no-certificate")
                .send()
                .await?
                .text()
                .await?;

            if res != "'/foo' not found" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        // "x-ic-test", "no-certificate"
        // "x-ic-test", "streaming-callback"
        // "x-icx-require-certification", "1"

        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .put(format!("https://{host}/foo"))
                .body("bar")
                .send()
                .await?
                .text()
                .await?;

            if res != "'/foo' set to 'bar'" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{host}/foo"))
                .send()
                .await?
                .text()
                .await?;

            if res != "bar" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{host}/foo"))
                .header("x-ic-test", "streaming-callback")
                .send()
                .await?
                .text()
                .await?;

            if res != "bar" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        // Check that `canisterId` parameters go unused
        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{invalid_host}/?canisterId={canister_id}"))
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
        let kv_store_canister = env.load_wasm("rs/tests/test_canisters/kv_store/kv_store.wasm");

        info!(&logger, "installing canister");
        let canister_id = create_canister(&agent, install_node.1, &kv_store_canister, None)
            .await
            .expect("Could not create kv_store canister");

        info!(&logger, "created kv_store canister={canister_id}");

        // Wait for the canisters to finish installing
        // TODO: maybe this should be status calls?
        tokio::time::sleep(Duration::from_secs(5)).await;

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

        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{host}/foo"))
                .header("x-ic-test", "no-certificate")
                .send()
                .await?
                .text()
                .await?;

            if res != "'/foo' not found" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        // "x-ic-test", "no-certificate"
        // "x-ic-test", "streaming-callback"
        // "x-icx-require-certification", "1"

        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .put(format!("https://{host}/foo"))
                .body("bar")
                .send()
                .await?
                .text()
                .await?;

            if res != "'/foo' set to 'bar'" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{host}/foo"))
                .send()
                .await?
                .text()
                .await?;

            if res != "bar" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{host}/foo"))
                .header("x-ic-test", "streaming-callback")
                .send()
                .await?
                .text()
                .await?;

            if res != "bar" {
                bail!(res)
            }

            Ok(())
        })
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
        let kv_store_canister = env.load_wasm("rs/tests/test_canisters/kv_store/kv_store.wasm");

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

        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{host}/foo"))
                .header("x-ic-test", "no-certificate")
                .send()
                .await?
                .text()
                .await?;

            if res != "'/foo' not found" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        // "x-ic-test", "no-certificate"
        // "x-ic-test", "streaming-callback"
        // "x-icx-require-certification", "1"

        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .put(format!("https://{host}/foo"))
                .body("bar")
                .send()
                .await?
                .text()
                .await?;

            if res != "'/foo' set to 'bar'" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{host}/foo"))
                .send()
                .await?
                .text()
                .await?;

            if res != "bar" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{host}/foo"))
                .header("x-ic-test", "streaming-callback")
                .send()
                .await?
                .text()
                .await?;

            if res != "bar" {
                bail!(res)
            }

            Ok(())
        })
        .await
        .unwrap();

        // Check that `canisterId` parameters go unused
        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(format!("https://{invalid_host}/?canisterId={canister_id}"))
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

        let http_counter_canister = env.load_wasm("rs/tests/test_canisters/http_counter/http_counter.wasm");

        info!(&logger, "installing canister");
        let canister_id = create_canister(&agent, install_node.unwrap().1, &http_counter_canister, None)
            .await
            .expect("Could not create http_counter canister");

        // wait for canister to finish installing
        tokio::time::sleep(Duration::from_secs(5)).await;

        info!(&logger, "created canister={canister_id}");

        // Update the denylist and reload nginx
        let denylist_command = format!(r#"printf "\"~^{} .*$\" \"1\";\n" | sudo tee /var/opt/nginx/denylist/denylist.map && sudo service nginx reload"#, canister_id);
        let cmd_output = boundary_node.block_on_bash_script(&denylist_command).unwrap();
        info!(
            logger,
            "update denylist {BOUNDARY_NODE_NAME} with {denylist_command} to \n'{}'\n",
            cmd_output,
        );

        // Wait a bit for the reload to complete
        tokio::time::sleep(Duration::from_secs(2)).await;

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
        retry_async(&logger, READY_WAIT_TIMEOUT, RETRY_BACKOFF, || async {
            let res = client
                .get(&format!("https://{canister_id}.raw.{host}/"))
                .send()
                .await?
                .status();

            if res != reqwest::StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS {
                bail!(res)
            }


            Ok(())
        }).await.unwrap();
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

        let http_counter_canister = env.load_wasm("rs/tests/test_canisters/http_counter/http_counter.wasm");

        info!(&logger, "installing canister");
        let canister_id = create_canister(&agent, install_node.unwrap().1, &http_counter_canister, None)
            .await
            .expect("Could not create http_counter canister");

        // wait for canister to finish installing
        tokio::time::sleep(Duration::from_secs(5)).await;

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
        let res = client
            .get(format!("https://{canister_id}.raw.{host}/"))
            .send()
            .await
            .expect("Could not perform get request.")
            .status();

        assert_eq!(res, reqwest::StatusCode::OK, "expected OK, got {}", res);

        // Update denylist with canister ID
        let cmd_output = boundary_node.block_on_bash_script(
            &format!(
                r#"printf "\"~^{} .*$\" 1;\n" | sudo tee /var/opt/nginx/denylist/denylist.map"#,
                canister_id
            ),
        )
        .unwrap();

        info!(
            logger,
            "update denylist {BOUNDARY_NODE_NAME}: '{}'",
            cmd_output.trim(),
        );

        // Reload Nginx
        let cmd_output = boundary_node.block_on_bash_script(
            "sudo service nginx restart",
        )
        .unwrap();

        info!(
            logger,
            "reload nginx on {BOUNDARY_NODE_NAME}: '{}'",
            cmd_output.trim(),
        );

        tokio::time::sleep(Duration::from_secs(5)).await;

        // Check canister is restricted
        let res = client
            .get(format!("https://{canister_id}.raw.{host}/"))
            .send()
            .await
            .expect("Could not perform get request.")
            .status();

        assert_eq!(res, reqwest::StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS, "expected 451, got {}", res);

        // Update allowlist with canister ID
        let cmd_output = boundary_node.block_on_bash_script(
            &format!(r#"printf "{} 1;\n" | sudo tee /run/ic-node/allowlist_canisters.map && sudo mount -o ro,bind /run/ic-node/allowlist_canisters.map /etc/nginx/allowlist_canisters.map"#, canister_id),
        )
        .unwrap();

        info!(
            logger,
            "update allowlist {BOUNDARY_NODE_NAME}: '{}'",
            cmd_output.trim(),
        );

        // Reload Nginx
        let cmd_output = boundary_node.block_on_bash_script(
            "sudo service nginx restart",
        )
        .unwrap();

        info!(
            logger,
            "reload nginx on {BOUNDARY_NODE_NAME}: '{}'",
            cmd_output.trim(),
        );

        tokio::time::sleep(Duration::from_secs(5)).await;

        // Check canister is available
        let res = client
            .get(format!("https://{canister_id}.raw.{host}/"))
            .send()
            .await
            .expect("Could not perform get request.")
            .status();

        assert_eq!(res, reqwest::StatusCode::OK, "expected OK, got {}", res);
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

pub fn sw_test(env: TestEnv) {
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
            "rs/tests/test_canisters/http_counter/http_counter.wasm",
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
            .resolve(&format!("{canister_id}.{host}"), bn_addr.into());
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let futs = FuturesUnordered::new();

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "get index.html with sw.js include from root path";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!("https://{canister_id}.{host}/"))
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            let body_valid = body.contains("Internet Computer Loading")
                && body.contains(r#"<script defer src="/install-script.js">"#);
            if !body_valid {
                bail!("{name} failed: expected Service Worker loading page but got {body}")
            }

            let res = client
                .get(format!("https://{canister_id}.{host}/foo.js"))
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            let body_valid = body.contains("Internet Computer Loading")
                && body.contains(r#"<script defer src="/install-script.js">"#);
            if !body_valid {
                bail!("{name} failed: expected Service Worker loading page but got {body}")
            }

            Ok(())
        }
    }));

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "get index.html with sw.js include from non-root path";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!("https://{canister_id}.{host}/a/b/c"))
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            let body_valid = body.contains("Internet Computer Loading")
                && body.contains(r#"<script defer src="/install-script.js">"#);
            if !body_valid {
                bail!("{name} failed: expected Service Worker loading page but got {body}")
            }

            Ok(())
        }
    }));

    let host = host_orig.clone();
    futs.push(rt.spawn({
        let client = client.clone();
        let name = "get service-worker bundle";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!("https://{canister_id}.{host}/sw.js"))
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            if !res
                .headers()
                .get("Content-Type")
                .unwrap()
                .as_bytes()
                .eq(b"application/javascript")
            {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains("sourceMappingURL=sw.js.map") {
                bail!("{name} failed: expected sw.js but got {body}")
            }

            Ok(())
        }
    }));

    let host = host_orig;
    futs.push(rt.spawn({
        let client = client;
        let name = "get uninstall script";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!("https://{canister_id}.{host}/anything.js"))
                .header("Service-Worker", "script")
                .send()
                .await?;

            if res.status() != reqwest::StatusCode::OK {
                bail!("{name} failed: {}", res.status())
            }

            if !res
                .headers()
                .get("Content-Type")
                .unwrap()
                .as_bytes()
                .eq(b"application/javascript")
            {
                bail!("{name} failed: {}", res.status())
            }

            let body = res.bytes().await?.to_vec();
            let body = String::from_utf8_lossy(&body);

            if !body.contains("unregister()") {
                bail!("{name} failed: expected uninstall script but got {body}")
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
            "rs/tests/test_canisters/http_counter/http_counter.wasm",
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
                ("Access-Control-Expose-Headers", "Accept-Ranges,Content-Length,Content-Range,X-Request-Id"),
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

            // Wait for the canister to finish installing
            tokio::time::sleep(Duration::from_secs(5)).await;

            info!(&logger, "creating agent");
            let transport = ReqwestHttpReplicaV2Transport::create_with_client(
                "https://rosetta.dfinity.network/",
                client,
            )?;

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

            // Wait for the canister to finish installing
            tokio::time::sleep(Duration::from_secs(5)).await;

            info!(&logger, "creating agent");
            let transport = ReqwestHttpReplicaV2Transport::create_with_client(
                "https://rosetta.dfinity.network/",
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
}

pub fn seo_test(env: TestEnv) {
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
            "rs/tests/test_canisters/http_counter/http_counter.wasm",
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
            .resolve(&format!("{canister_id}.{host}"), bn_addr.into());
        (client_builder, host.to_string())
    };
    let client = client_builder.build().unwrap();

    let futs = FuturesUnordered::new();

    let host = host_orig;
    futs.push(rt.spawn({
        let name = "get sent to icx-proxy if you're a bot";
        info!(&logger, "Starting subtest {}", name);

        async move {
            let res = client
                .get(format!("https://{canister_id}.{host}/"))
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

            if !body.contains("Counter is 0") {
                bail!("{name} failed: expected icx-response but got {body}")
            }

            // Test *.js to see if we end up in the nginx 404
            let res = client
                .get(format!("https://{canister_id}.{host}/foo.js"))
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
        boundary_node.build_default_agent()
    };
    info!(
        log,
        "Incrementing counters on canisters via BN agent update calls ..."
    );
    block_on(set_counters_on_counter_canisters(
        bn_agent.clone(),
        canister_ids.clone(),
        canister_values.clone(),
    ));
    info!(
        log,
        "Asserting expected counters on canisters via BN agent query calls ... "
    );
    let counters = block_on(read_counters_on_counter_canisters(bn_agent, canister_ids));
    assert_eq!(counters, canister_values);
}
