use crate::boundary_nodes::{
    constants::{API_BOUNDARY_NODE_NAME, COUNTER_CANISTER_WAT},
    helpers::{
        create_canister, get_install_url, install_canisters, read_counters_on_counter_canisters,
        set_counters_on_counter_canisters,
    },
};
use crate::{
    driver::{
        api_boundary_node::ApiBoundaryNodeVm,
        test_env::TestEnv,
        test_env_api::{
            retry_async, GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, HasVm,
            IcNodeContainer, RetrieveIpv4Addr, SshSession, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    nns::{self, vote_execute_proposal_assert_executed},
    util::{assert_create_agent, block_on, runtime_from_url},
};
use anyhow::{anyhow, bail, Error};
use discower_bowndary::api_nodes_discovery::{Fetch, RegistryFetcher};
use futures::stream::FuturesUnordered;
use ic_agent::{agent::http_transport::ReqwestHttpReplicaV2Transport, export::Principal, Agent};
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_common::types::NeuronId;
use ic_nns_governance::pb::v1::NnsFunction;
use ic_nns_test_utils::governance::submit_external_update_proposal;
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use registry_canister::mutations::do_add_api_boundary_node::AddApiBoundaryNodePayload;
use serde::Deserialize;
use slog::{error, info};
use std::{net::SocketAddrV6, time::Duration};
use tokio::runtime::Runtime;

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

    let cmd_output = api_boundary_node
        .block_on_bash_script("sudo nginx -t 2>&1")
        .unwrap();

    info!(logger, "nginx test result = '{}'", cmd_output.trim());

    if !cmd_output.trim().contains("test is successful") {
        panic!("nginx config failed validation");
    }
}

pub fn redirect_http_to_https_test(env: TestEnv) {
    let logger = env.logger();

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
}

pub fn direct_to_replica_options_test(env: TestEnv) {
    let logger = env.logger();

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
    let cmd_output = api_boundary_node
        .block_on_bash_script(&sleep_command)
        .unwrap();
    info!(
        logger,
        "{API_BOUNDARY_NODE_NAME} ran `{sleep_command}`: '{}'",
        cmd_output.trim(),
    );

    info!(&logger, "Checking API BN health");
    api_boundary_node
        .await_status_is_healthy()
        .expect("API Boundary node did not come up healthy.");
}

/* tag::catalog[]
Title:: API Boundary Nodes Decentralization

Goal:: Verify that API Boundary Nodes added to the registry via proposals are functional

Runbook:
. IC with two unassigned nodes
. Both unassigned nodes are converted to the API Boundary Nodes via proposals
. Assert that API BN records are present in the registry
. TODO: assert that calls to the IC via the domains of the newly added API BN are successful

end::catalog[] */

pub fn decentralization_test(env: TestEnv) {
    let log = env.logger();
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let nns_url = nns_node.get_public_url();
    let unassigned_nodes: Vec<_> = env.topology_snapshot().unassigned_nodes().collect();
    info!(log, "Asserting no API BN domains exist in the registry");
    let fetcher = RegistryFetcher::new(nns_url);
    let api_domains: Vec<String> =
        block_on(fetcher.api_node_domains_from_registry()).expect("failed to get API BN domains");
    assert_eq!(api_domains, Vec::<&str>::new());
    info!(
        log,
        "Adding two API BNs from the unassigned nodes to the registry via proposals"
    );
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = nns::get_governance_canister(&nns_runtime);
    let version = block_on(crate::nns::get_software_version_from_snapshot(&nns_node))
        .expect("could not obtain replica software version");
    for (idx, node) in unassigned_nodes.iter().enumerate() {
        let domain = format!("api{}.com", idx + 1);
        let proposal_payload = AddApiBoundaryNodePayload {
            node_id: node.node_id,
            version: version.clone().into(),
            domain,
        };
        let proposal_id = block_on(submit_external_update_proposal(
            &governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::AddApiBoundaryNode,
            proposal_payload,
            String::from("add api boundary node"),
            "Motivation: api bn decentralization testing".to_string(),
        ));
        block_on(vote_execute_proposal_assert_executed(
            &governance,
            proposal_id,
        ));
        info!(
            log,
            "Proposal with id={} for unassigned node with id={} has been executed successfully",
            proposal_id,
            node.node_id
        );
    }
    info!(
        log,
        "Asserting API BN domains are now present in the registry"
    );
    let api_domains: Vec<String> =
        block_on(fetcher.api_node_domains_from_registry()).expect("failed to get API BN domains");
    assert_eq!(api_domains, vec!["api1.com", "api2.com"]);
}
