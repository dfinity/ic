use discower_bowndary::{
    check::{HealthCheck, HealthCheckImpl},
    fetch::{NodesFetcher, NodesFetcherImpl},
    node::Node,
    route_provider::HealthCheckRouteProvider,
    snapshot_health_based::HealthBasedSnapshot,
    transport::{TransportProvider, TransportProviderImpl},
};
use ic_base_types::NodeId;
use k256::SecretKey;
use std::{collections::HashSet, time::Instant};
use tokio::time::sleep;

use crate::boundary_nodes::{
    constants::{BOUNDARY_NODE_NAME, COUNTER_CANISTER_WAT},
    helpers::{
        install_canisters, read_counters_on_counter_canisters, set_counters_on_counter_canisters,
    },
    setup::TEST_PRIVATE_KEY,
};
use candid::{Decode, Encode};
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::types::NeuronId;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_governance_api::pb::v1::NnsFunction;
use ic_nns_test_utils::governance::submit_external_update_proposal;
use ic_system_test_driver::{
    driver::{
        boundary_node::BoundaryNodeVm,
        test_env::TestEnv,
        test_env_api::{
            GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeSnapshot,
            SshSession, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    nns::{self, vote_execute_proposal_assert_executed},
    util::{block_on, runtime_from_url},
};
use itertools::Itertools;
use registry_canister::mutations::{
    do_add_api_boundary_nodes::AddApiBoundaryNodesPayload,
    do_remove_api_boundary_nodes::RemoveApiBoundaryNodesPayload,
    node_management::do_update_node_domain_directly::UpdateNodeDomainDirectlyPayload,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::bail;
use ic_agent::{
    agent::{
        http_transport::{
            reqwest_transport::reqwest::{redirect::Policy, Client, ClientBuilder},
            route_provider::RouteProvider,
            ReqwestTransport,
        },
        ApiBoundaryNode,
    },
    export::Principal,
    identity::{AnonymousIdentity, Secp256k1Identity},
    Agent,
};

use slog::{debug, info};
const CANISTER_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const CANISTER_RETRY_BACKOFF: Duration = Duration::from_secs(2);
const API_BN_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(90);
const ROUTE_CALL_INTERVAL: Duration = Duration::from_secs(5);

/* tag::catalog[]
Title:: API Boundary Nodes Decentralization

Goal:: Verify that API Boundary Nodes added to the registry via proposals are functional

Runbook:
. IC with four unassigned nodes
. Convert two (out of four unassigned nodes) into the API Boundary Nodes via proposals
. Assert both API BNs are present in the state tree
. Assert nftables firewall rules are working for these API BNs
. Instantiate an agent with a HealthCheckRouteProvider service, which dynamically discovers and routes requests to existing (and healthy) API BNs
. Assert calls to IC via this agent are successful and are routed via newly added API BNs (api1.com, api2.com)
. Convert two remaining unassigned nodes into the API Boundary Nodes via proposals and also remove the first two existing ones
. Assert state tree now has the following two API BNs - api3.com and api4.com
. Assert calls to IC via agent are successful and are routed via newly discovered API BNs (api3.com, api4.com)

end::catalog[] */

pub fn decentralization_test(env: TestEnv) {
    block_on(test(env))
}

async fn test(env: TestEnv) {
    let log = env.logger();
    let nns_node = env.get_first_healthy_nns_node_snapshot();
    let unassigned_nodes: Vec<_> = env.topology_snapshot().unassigned_nodes().collect();
    let eff_canister_id: Principal = nns_node.effective_canister_id().into();

    // Identity is needed to execute `update_node_domain_directly` as the caller is checked.
    let agent_with_identity = {
        let mut agent = nns_node.build_default_agent_async().await;
        let identity = Secp256k1Identity::from_private_key(
            SecretKey::from_sec1_pem(TEST_PRIVATE_KEY).unwrap(),
        );
        agent.set_identity(identity);
        agent
    };

    info!(
        log,
        "Assert: no API BNs are initially present in the state tree"
    );

    let api_bns = agent_with_identity
        .fetch_api_boundary_nodes_by_canister_id(eff_canister_id)
        .await
        .expect("failed to fetch API BNs");

    assert!(api_bns.is_empty());

    info!(
        log,
        "Converting two unassigned nodes into API BNs via proposals"
    );

    let all_api_domains = ["api1.com", "api2.com", "api3.com", "api4.com"];

    let all_api_bns: Vec<ApiBoundaryNode> = unassigned_nodes
        .iter()
        .enumerate()
        .map(|(idx, node)| ApiBoundaryNode {
            domain: all_api_domains[idx].to_string(),
            ipv6_address: node.get_ip_addr().to_string(),
            ipv4_address: None,
        })
        .collect();

    add_api_boundary_nodes_via_proposal(
        &log,
        nns_node.clone(),
        agent_with_identity.clone(),
        unassigned_nodes[..2].to_vec(),
        all_api_domains[..2].to_vec(),
    )
    .await;

    info!(
        log,
        "Assert: two API BNs {:?} are now present in the state tree",
        &all_api_domains[..2]
    );

    assert_api_bns_present_in_state_tree(
        &log,
        agent_with_identity.clone(),
        nns_node.clone(),
        all_api_bns[..2].to_vec(),
    )
    .await;

    info!(log, "Creating an HTTP client with custom domain resolution");

    // HTTP client with a custom domain resolution policy, as API domains are not registered in system-tests.
    let http_client = {
        let mut client_builder = ClientBuilder::new()
            .redirect(Policy::none())
            .danger_accept_invalid_certs(true);

        for (idx, node) in unassigned_nodes.iter().enumerate() {
            let ipv6 = node.get_ip_addr();
            let node_addr = SocketAddr::new(ipv6, 0);
            let domain = all_api_domains[idx];
            client_builder = client_builder.resolve(domain, node_addr);
            info!(log, "Resolve: domain={domain} to ipv6={node_addr}");
        }

        client_builder.build().expect("failed to build http client")
    };

    info!(
        log,
        "Assert: API BNs {:?} are healthy ...",
        &all_api_domains[..2]
    );

    assert_api_bns_healthy(&log, http_client.clone(), all_api_domains[..2].to_vec()).await;

    info!(
        log,
        "Checking nftables with firewall settings enabled on API BNs ..."
    );

    for node in unassigned_nodes.iter() {
        let rules = node
            .block_on_bash_script("sudo nft list ruleset")
            .expect("unable to read nft ruleset");
        assert!(rules.contains("ct state new add @rate_limit"));
        assert!(rules.contains("ct state new add @connection_limit"));
    }

    info!(
        log,
        "Creating an agent with a HealthCheckRouteProvider to route requests against discovered and healthy API BNs",
    );

    let route_provider = {
        let subnet_id = env
            .topology_snapshot()
            .subnets()
            .next()
            .unwrap()
            .subnet_id
            .get();
        let api_bn_fetch_interval = Duration::from_secs(5);
        let transport_provider =
            Arc::new(TransportProviderImpl::new(http_client.clone())) as Arc<dyn TransportProvider>;
        let fetcher = Arc::new(NodesFetcherImpl::new(transport_provider, subnet_id.into()));
        let health_timeout = Duration::from_secs(5);
        let check_interval = Duration::from_secs(1);
        let checker = Arc::new(HealthCheckImpl::new(http_client.clone(), health_timeout));
        let seed_nodes = vec![Node::new("api1.com"), Node::new("api2.com")];
        let snapshot = HealthBasedSnapshot::new();
        let route_provider = Arc::new(HealthCheckRouteProvider::new(
            snapshot,
            Arc::clone(&fetcher) as Arc<dyn NodesFetcher>,
            api_bn_fetch_interval,
            Arc::clone(&checker) as Arc<dyn HealthCheck>,
            check_interval,
            seed_nodes,
        ));

        route_provider.run().await;

        info!(
            log,
            "Assert: HealthCheckRouteProvider has discovered API BNs {:?} and routes calls correctly", &all_api_domains[..2]
        );

        assert_routing_via_domains(
            &log,
            Arc::clone(&route_provider) as Arc<dyn RouteProvider>,
            all_api_domains[..2].to_vec(),
            API_BN_DISCOVERY_TIMEOUT,
            ROUTE_CALL_INTERVAL,
        )
        .await;

        route_provider
    };

    let api_bn_agent = {
        // This agent routes directly via ipv6 addresses and doesn't employ domain names.
        // Ideally, domains with valid certificates should be used in testing.
        let transport = ReqwestTransport::create_with_client_route(
            Arc::clone(&route_provider) as Arc<dyn RouteProvider>,
            http_client.clone(),
        )
        .unwrap();

        let agent = Agent::builder()
            .with_transport(transport)
            .with_identity(AnonymousIdentity {})
            .build()
            .unwrap();

        ic_system_test_driver::retry_with_msg_async!(
            "fetch_root_key",
            &log,
            Duration::from_secs(30),
            Duration::from_secs(2),
            || async {
                if agent.fetch_root_key().await.is_ok() {
                    return Ok(());
                }
                bail!("Failed to fetch root key");
            }
        )
        .await
        .expect("Failed to fetch root key");

        agent
    };

    info!(
        log,
        "Agent with HealthCheckRouteProvider created successfully"
    );

    info!(log, "Installing counter canisters ...");

    let canister_ids: Vec<Principal> = install_canisters(
        env.topology_snapshot(),
        wat::parse_str(COUNTER_CANISTER_WAT).unwrap().as_slice(),
        1,
    )
    .await;

    info!(
        log,
        "Successfully installed {} counter canisters",
        canister_ids.len()
    );

    info!(log, "Incrementing counters on canisters for the first time");

    let canister_increments: Vec<u32> = vec![1, 3];

    set_counters_on_counter_canisters(
        &log,
        api_bn_agent.clone(),
        canister_ids.clone(),
        canister_increments.clone(),
        CANISTER_RETRY_BACKOFF,
        CANISTER_RETRY_TIMEOUT,
    )
    .await;

    info!(
        log,
        "Assert: expected counter values on canisters after first increment"
    );

    let counters = read_counters_on_counter_canisters(
        &log,
        api_bn_agent.clone(),
        canister_ids.clone(),
        CANISTER_RETRY_BACKOFF,
        CANISTER_RETRY_TIMEOUT,
    )
    .await;

    assert_eq!(counters, vec![1, 3]);

    info!(
        log,
        "Converting two other unassigned nodes into API BNs via proposals"
    );

    add_api_boundary_nodes_via_proposal(
        &log,
        nns_node.clone(),
        agent_with_identity.clone(),
        unassigned_nodes[2..4].to_vec(),
        all_api_domains[2..4].to_vec(),
    )
    .await;

    assert_api_bns_present_in_state_tree(
        &log,
        agent_with_identity.clone(),
        nns_node.clone(),
        all_api_bns[..4].to_vec(),
    )
    .await;

    assert_routing_via_domains(
        &log,
        Arc::clone(&route_provider) as Arc<dyn RouteProvider>,
        all_api_domains[..4].to_vec(),
        API_BN_DISCOVERY_TIMEOUT,
        ROUTE_CALL_INTERVAL,
    )
    .await;

    let node_ids = unassigned_nodes
        .iter()
        .take(2)
        .map(|n| n.node_id)
        .collect::<Vec<_>>();

    info!(
        log,
        "Removing two initial API BNs with ids {node_ids:?} via proposal"
    );

    remove_api_boundary_nodes_via_proposal(&log, nns_node.clone(), node_ids).await;

    info!(
        log,
        "Assert: two new API BNs {:?} are now present in the state tree",
        &all_api_domains[2..4]
    );

    assert_api_bns_present_in_state_tree(
        &log,
        agent_with_identity.clone(),
        nns_node.clone(),
        all_api_bns[2..4].to_vec(),
    )
    .await;

    info!(
        log,
        "Assert: two new API BNs {:?} are healthy ...",
        &all_api_domains[2..4]
    );

    assert_api_bns_healthy(&log, http_client.clone(), all_api_domains[2..4].to_vec()).await;

    info!(
        log,
        "Assert: HealthCheckRouteProvider discovered added/removed API BNs and routes calls correctly"
    );

    assert_routing_via_domains(
        &log,
        Arc::clone(&route_provider) as Arc<dyn RouteProvider>,
        all_api_domains[2..4].to_vec(),
        API_BN_DISCOVERY_TIMEOUT,
        ROUTE_CALL_INTERVAL,
    )
    .await;

    info!(
        log,
        "Incrementing counters on canisters for the second time"
    );

    set_counters_on_counter_canisters(
        &log,
        api_bn_agent.clone(),
        canister_ids.clone(),
        canister_increments,
        CANISTER_RETRY_BACKOFF,
        CANISTER_RETRY_TIMEOUT,
    )
    .await;

    info!(
        log,
        "Assert: expected counter values on canisters after second increment"
    );

    let counters = read_counters_on_counter_canisters(
        &log,
        api_bn_agent,
        canister_ids,
        CANISTER_RETRY_BACKOFF,
        CANISTER_RETRY_TIMEOUT,
    )
    .await;

    assert_eq!(counters, vec![2, 6]);

    info!(log, "Gracefully stopping HealthCheckRouteProvider");

    route_provider.stop().await;
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

async fn remove_api_boundary_nodes_via_proposal(
    log: &slog::Logger,
    nns_node: IcNodeSnapshot,
    node_ids: Vec<NodeId>,
) {
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());

    let governance = nns::get_governance_canister(&nns_runtime);

    let proposal_payload = RemoveApiBoundaryNodesPayload { node_ids };

    let proposal_id = submit_external_update_proposal(
        &governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::RemoveApiBoundaryNodes,
        proposal_payload,
        String::from("Remove API boundary nodes"),
        "Motivation: API boundary node testing".to_string(),
    )
    .await;

    vote_execute_proposal_assert_executed(&governance, proposal_id).await;

    info!(
        log,
        "Proposal with id={} for removing API BNs has been executed successfully", proposal_id,
    );
}

async fn add_api_boundary_nodes_via_proposal(
    log: &slog::Logger,
    nns_node: IcNodeSnapshot,
    agent: Agent,
    unassigned_nodes: Vec<IcNodeSnapshot>,
    domains: Vec<&str>,
) {
    let nns_runtime = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let governance = nns::get_governance_canister(&nns_runtime);
    let version = ic_system_test_driver::nns::get_software_version_from_snapshot(&nns_node)
        .await
        .expect("could not obtain replica software version");

    for (idx, node) in unassigned_nodes.iter().enumerate() {
        let domain = domains[idx];

        // Create an empty ACME json to signal ic-boundary that we don't need to create a new ACME account
        // Create self-signed certificate & update permissions
        node.block_on_bash_script(&format!(
            "sudo openssl req -x509 -newkey rsa:2048 \
            -keyout /var/lib/ic/data/ic-boundary-tls.key \
            -out /var/lib/ic/data/ic-boundary-tls.crt -sha256 -days 3650 -nodes \
            -subj \"/C=CH/ST=Zurich/L=Zurich/O=DFINITY/OU=BoundaryNodes/CN={}\" && \
            sudo chmod +r /var/lib/ic/data/ic-boundary-tls.key",
            domain
        ))
        .expect("unable to setup TLS files");

        let update_domain_payload = UpdateNodeDomainDirectlyPayload {
            node_id: node.node_id,
            domain: Some(domain.to_string()),
        };

        info!(
            log,
            "Setting domain name of the unassigned node with id={} to {} ...", node.node_id, domain
        );

        let call_result: Vec<u8> = agent
            .update(&REGISTRY_CANISTER_ID.into(), "update_node_domain_directly")
            .with_arg(Encode!(&update_domain_payload).unwrap())
            .call_and_wait()
            .await
            .expect("Could not change domain name of the node");

        assert_eq!(Decode!(&call_result, Result<(), String>).unwrap(), Ok(()));

        info!(
            log,
            "Successfully updated domain name of the unassigned node with id={}", node.node_id
        );

        let proposal_payload = AddApiBoundaryNodesPayload {
            node_ids: vec![node.node_id],
            version: version.clone().into(),
        };

        let proposal_id = submit_external_update_proposal(
            &governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::AddApiBoundaryNodes,
            proposal_payload,
            String::from("Add an API boundary node"),
            "Motivation: API boundary node testing".to_string(),
        )
        .await;

        vote_execute_proposal_assert_executed(&governance, proposal_id).await;

        info!(
            log,
            "Proposal with id={} for unassigned node with id={} has been executed successfully",
            proposal_id,
            node.node_id
        );
    }
}

async fn assert_api_bns_healthy(log: &slog::Logger, http_client: Client, api_domains: Vec<&str>) {
    for domain in api_domains.iter() {
        ic_system_test_driver::retry_with_msg_async!(
            "check_api_bns_health",
            log,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let response = http_client
                    .get(format!("https://{domain}/health"))
                    .send()
                    .await?;

                if response.status().is_success() {
                    info!(log, "API BN with domain {domain} came up healthy");
                    return Ok(());
                }

                bail!("API BN with domain {domain} is not yet healthy");
            }
        )
        .await
        .expect("API BNs didn't report healthy");
    }
}

async fn assert_api_bns_present_in_state_tree(
    log: &slog::Logger,
    agent: Agent,
    nns_node: IcNodeSnapshot,
    expected_api_bns: Vec<ApiBoundaryNode>,
) {
    ic_system_test_driver::retry_with_msg_async!(
        "assert_api_bns_present_in_state_tree",
        log,
        Duration::from_secs(70),
        Duration::from_secs(5),
        || async {
            let api_bns = agent
                .fetch_api_boundary_nodes_by_canister_id(nns_node.effective_canister_id().into())
                .await
                .expect("failed to fetch API BNs");

            let api_bns_sorted = api_bns
                .into_iter()
                .sorted_by(|a, b| Ord::cmp(&a.domain, &b.domain))
                .collect::<Vec<_>>();

            let are_expected_bns = api_bns_sorted
                .iter()
                .enumerate()
                .map(|(idx, bn)| {
                    bn.domain == expected_api_bns[idx].domain
                        && bn.ipv6_address == expected_api_bns[idx].ipv6_address
                })
                .all(|is_match| is_match);

            if !are_expected_bns {
                bail!("Expected API BNs haven't yet appeared in the state tree ...");
            }

            Ok(())
        }
    )
    .await
    .expect("API BNs haven't appeared in the state tree");
}

async fn assert_routing_via_domains(
    log: &slog::Logger,
    route_provider: Arc<dyn RouteProvider>,
    domains: Vec<&str>,
    timeout: Duration,
    route_call_interval: Duration,
) {
    if domains.is_empty() {
        panic!("Expected routing domains can't be empty");
    }

    info!(log, "Assert: only domains {domains:?} are used for routing");

    let expected_domains = HashSet::from_iter(domains.into_iter().map(|d| d.to_string()));
    let route_calls = 30;
    let start = Instant::now();

    while start.elapsed() < timeout {
        let routed_domains = (0..route_calls)
            .map(|_| {
                route_provider.route().map(|url| {
                    let domain = url.domain().expect("no domain name in url");
                    domain.to_string()
                })
            })
            .collect::<Result<HashSet<String>, _>>()
            .unwrap_or_default();

        if expected_domains == routed_domains {
            info!(
                log,
                "All expected domains {expected_domains:?} used for routing"
            );
            return;
        }

        debug!(
            log,
            "Actual routed domains {routed_domains:?} are not equal to expected {expected_domains:?}"
        );

        sleep(route_call_interval).await;
    }
    panic!("Expected routes {expected_domains:?} were not observed over {route_calls} consecutive routing calls");
}
