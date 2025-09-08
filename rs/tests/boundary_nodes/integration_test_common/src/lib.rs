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

use anyhow::{Error, anyhow, bail};
use ic_agent::{Agent, export::Principal};
use ic_boundary_nodes_system_test_utils::{
    constants::COUNTER_CANISTER_WAT,
    helpers::{create_canister, get_install_url},
};
use ic_system_test_driver::{
    driver::{
        test_env::TestEnv,
        test_env_api::{HasTopologySnapshot, READY_WAIT_TIMEOUT, RETRY_BACKOFF},
    },
    retry_with_msg_async,
    util::{agent_observes_canister_module, assert_create_agent, block_on},
};
use ic_types::PrincipalId;
use reqwest::{
    ClientBuilder, Method, Request, StatusCode,
    header::{
        ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
        ACCESS_CONTROL_MAX_AGE, CACHE_CONTROL, CONTENT_TYPE, COOKIE, DNT, IF_MODIFIED_SINCE,
        IF_NONE_MATCH, RANGE, USER_AGENT,
    },
    redirect::Policy,
};
use serde::Deserialize;
use slog::{Logger, info};
use std::net::SocketAddr;
use v2_call_transport::V2CallAgent;

mod v2_call_transport;

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
    let api_boundary_node = env
        .topology_snapshot()
        .api_boundary_nodes()
        .next()
        .expect("failed to get API BN snapshot");

    let client_builder = ClientBuilder::new().redirect(Policy::none());
    let host = api_boundary_node
        .get_domain()
        .expect("failed to get API BN domain name");

    let api_bn_addr = SocketAddr::new(api_boundary_node.get_ip_addr(), 0);
    let client_builder = client_builder
        .danger_accept_invalid_certs(true)
        .resolve(host.as_str(), api_bn_addr);
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
    info!(&logger, "Connecting to the API BN via {host}");

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
    info!(&logger, "Connecting to the API BN via {host}");

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
    info!(&logger, "Connecting to the API BN via {host}");

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
    info!(&logger, "Connecting to the API BN via {host}");

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
    info!(&logger, "Connecting to the API BN via {host}");

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
    info!(&logger, "Connecting to the API BN via {host}");

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
Title:: Boundary nodes headers test

Goal:: Make sure the boundary node sets the content-type, x-content-type-options, x-frame-options headers

end::catalog[] */

pub fn content_type_headers_test(env: TestEnv) {
    let logger = env.logger();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        let (http_client, host) = setup_client(env.clone()).expect("failed to setup client");
        info!(&logger, "Connecting to the API BN via {host}");

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

/* tag::catalog[]
Title:: Boundary nodes websocket CORS test

Goal:: Make sure the boundary node sets correct CORS headers on the Websocket logs endpoint

end::catalog[] */

pub fn logs_websocket_cors_test(env: TestEnv) {
    let logger = env.logger();

    let rt = tokio::runtime::Runtime::new().expect("Could not create tokio runtime.");
    rt.block_on(async move {
        let (http_client, host) = setup_client(env.clone()).expect("failed to setup client");
        info!(&logger, "Connecting to the API BN via {host}");

        ic_system_test_driver::retry_with_msg_async!(
            "Making a call to inspect the headers",
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                info!(&logger, "Requesting websocket logs endpoint...");
                let req = Request::new(
                    Method::OPTIONS,
                    format!("https://{host}/logs/canister/aaaaa-aa")
                        .parse()
                        .unwrap(),
                );

                let res = http_client.execute(req).await.unwrap();

                let headers = res.headers();
                assert_eq!(
                    headers.get(ACCESS_CONTROL_ALLOW_METHODS).unwrap(),
                    "HEAD,GET,POST",
                    "Header ACCESS_CONTROL_ALLOW_METHODS does not match expected value: HEAD,GET,POST"
                );

                assert_eq!(
                    headers.get(ACCESS_CONTROL_MAX_AGE).unwrap(),
                    "7200",
                    "Header ACCESS_CONTROL_MAX_AGE does not match expected value: 7200"
                );

                assert_eq!(
                    headers.get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
                    "*",
                    "Header ACCESS_CONTROL_ALLOW_ORIGIN does not match expected value: *"
                );

                let expected_headers = &[
                    USER_AGENT,
                    DNT,
                    IF_NONE_MATCH,
                    IF_MODIFIED_SINCE,
                    CACHE_CONTROL,
                    CONTENT_TYPE,
                    RANGE,
                    COOKIE
                ];
                let allow_headers = headers.get(ACCESS_CONTROL_ALLOW_HEADERS).unwrap().to_str().unwrap().to_ascii_lowercase();

                for x in expected_headers {
                    assert!(
                        allow_headers.contains(&x.to_string().to_ascii_lowercase()),
                        "Header ACCESS_CONTROL_ALLOW_HEADERS does not contain header {x}"
                    );
                }

                Ok(())
            }
        )
        .await
        .unwrap();
    });
}
