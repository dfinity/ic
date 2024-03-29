use k256::SecretKey;

use crate::boundary_nodes::{
    constants::{BOUNDARY_NODE_NAME, COUNTER_CANISTER_WAT},
    helpers::{
        install_canisters, read_counters_on_counter_canisters, set_counters_on_counter_canisters,
    },
    setup::TEST_PRIVATE_KEY,
};
use crate::{
    driver::{
        boundary_node::BoundaryNodeVm,
        test_env::TestEnv,
        test_env_api::{
            retry_async, GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot,
            SshSession, READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    nns::{self, vote_execute_proposal_assert_executed},
    util::{block_on, runtime_from_url},
};
use candid::{Decode, Encode};
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_common::types::NeuronId;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_nns_governance::{init::TEST_NEURON_1_ID, pb::v1::NnsFunction};
use ic_nns_test_utils::governance::submit_external_update_proposal;
use itertools::Itertools;
use registry_canister::mutations::{
    do_add_api_boundary_node::AddApiBoundaryNodePayload,
    node_management::do_update_node_domain_directly::UpdateNodeDomainDirectlyPayload,
};
use reqwest::{redirect::Policy, ClientBuilder};
use std::net::Ipv6Addr;
use std::{net::SocketAddr, time::Duration};

use anyhow::bail;
use ic_agent::{
    agent::http_transport::{route_provider::RoundRobinRouteProvider, ReqwestTransport},
    export::Principal,
    identity::{AnonymousIdentity, Secp256k1Identity},
    Agent,
};

use slog::info;
const CANISTER_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const CANISTER_RETRY_BACKOFF: Duration = Duration::from_secs(2);

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
    let unassigned_nodes: Vec<_> = env.topology_snapshot().unassigned_nodes().collect();
    let eff_canister_id: Principal = nns_node.effective_canister_id().into();
    // Identity is needed to execute `update_node_domain_directly` as the caller is checked.
    let agent_with_identity = {
        let mut agent = nns_node.build_default_agent();
        let identity = Secp256k1Identity::from_private_key(
            SecretKey::from_sec1_pem(TEST_PRIVATE_KEY).unwrap(),
        );
        agent.set_identity(identity);
        agent
    };

    info!(
        log,
        "Asserting that no API BNs are present in the state tree"
    );
    let api_bns = block_on(agent_with_identity.fetch_api_boundary_nodes(eff_canister_id))
        .expect("failed to fetch API BNs");
    assert!(api_bns.is_empty());

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

        // Create an empty ACME json to signal ic-boundary that we don't need to create a new ACME account
        // Create self-signed certificate & update permissions
        node.block_on_bash_script(&format!(
            "sudo touch /var/lib/ic/data/ic-boundary-acme.json && \
            sudo openssl req -x509 -newkey rsa:2048 \
            -keyout /var/lib/ic/data/ic-boundary-tls.key \
            -out /var/lib/ic/data/ic-boundary-tls.crt -sha256 -days 3650 -nodes \
            -subj \"/C=CH/ST=Zurich/L=Zurich/O=DFINITY/OU=BoundaryNodes/CN={}\" && \
            sudo chmod +r /var/lib/ic/data/ic-boundary-tls.key",
            domain
        ))
        .expect("unable to setup TLS files");

        let update_domain_payload = UpdateNodeDomainDirectlyPayload {
            node_id: node.node_id,
            domain: Some(domain.clone()),
        };
        info!(
            log,
            "Setting domain name of the unassigned node with id={} to {} ...", node.node_id, domain
        );
        let call_result: Vec<u8> = block_on(
            agent_with_identity
                .update(&REGISTRY_CANISTER_ID.into(), "update_node_domain_directly")
                .with_arg(Encode!(&update_domain_payload).unwrap())
                .call_and_wait(),
        )
        .expect("Could not change domain name of the node");
        assert_eq!(Decode!(&call_result, Result<(), String>).unwrap(), Ok(()));
        info!(
            log,
            "Successfully updated domain name of the unassigned node with id={}", node.node_id
        );
        let proposal_payload = AddApiBoundaryNodePayload {
            node_id: node.node_id,
            version: version.clone().into(),
        };
        let proposal_id = block_on(submit_external_update_proposal(
            &governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::AddApiBoundaryNode,
            proposal_payload,
            String::from("Add an API boundary node"),
            "Motivation: API boundary node testing".to_string(),
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
        "Asserting that two API BNs are now present in the state tree"
    );
    let api_bns = block_on(retry_async(
        "fetch_api_bns",
        &log,
        Duration::from_secs(70),
        Duration::from_secs(5),
        || async {
            let api_bns = agent_with_identity
                .fetch_api_boundary_nodes(nns_node.effective_canister_id().into())
                .await
                .expect("failed to fetch API BNs");
            if api_bns.len() != 2 {
                bail!("Two API BNs haven't yet appeared in the state tree ...");
            }
            Ok(api_bns)
        },
    ))
    .expect("API BNs haven't appeared in the state tree");
    let api_domains = api_bns
        .iter()
        .map(|bn| &bn.domain)
        .sorted()
        .collect::<Vec<_>>();
    assert_eq!(api_domains, vec!["api1.com", "api2.com"]);
    info!(
        log,
        "API BNs with expected domains are present in the state tree"
    );

    // This is temporary until we complete the firewall for API BNs in the orchestrator
    info!(log, "Opening the firewall ports ...");
    for node in unassigned_nodes.iter() {
        node.block_on_bash_script(&indoc::formatdoc! {r#"
            sudo nft add rule ip6 filter INPUT tcp dport 443 accept
        "#})
            .expect("unable to open firewall port");
    }

    info!(log, "Create an HTTP client for the two API BNs ...");
    let http_client = {
        let mut client_builder = ClientBuilder::new()
            .redirect(Policy::none())
            .danger_accept_invalid_certs(true);

        for api_bn in api_bns.iter() {
            let ipv6 = api_bn.ipv6_address.parse::<Ipv6Addr>().unwrap();
            let node_addr = SocketAddr::new(ipv6.into(), 0);
            client_builder = client_builder.resolve(&api_bn.domain, node_addr);
            info!(
                log,
                "API BN: url {:?}, node addr {node_addr}", api_bn.domain
            );
        }

        client_builder.build().expect("failed to build http client")
    };

    info!(log, "Checking API BNs health ...");
    for api_bn in api_bns.iter() {
        block_on(retry_async(
            "check_api_bns_health",
            &log,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let response = http_client
                    .get(format!("https://{}/health", api_bn.domain))
                    .send()
                    .await?;
                if response.status().is_success() {
                    info!(log, "API BN with domain {} came up healthy", api_bn.domain);
                    return Ok(());
                }
                bail!("API BN with domain {} is not yet healthy", api_bn.domain);
            },
        ))
        .expect("API BNs didn't report healthy");
    }

    info!(log, "Installing counter canisters ...");
    let canister_values: Vec<u32> = vec![1, 3];
    let canister_ids: Vec<Principal> = block_on(install_canisters(
        env.topology_snapshot(),
        wat::parse_str(COUNTER_CANISTER_WAT).unwrap().as_slice(),
        1,
    ));

    info!(
        log,
        "Successfully installed {} counter canisters",
        canister_ids.len()
    );
    let api_bn_agent = {
        // This agent routes directly via ipv6 addresses and doesn't employ domain names.
        // Ideally, domains with valid certificates should be used in testing.
        info!(log, "Creating an agent with routing over both API BNs ...");
        let api_bn_urls: Vec<String> = api_bns
            .into_iter()
            .map(|bn| format!("https://[{}]", bn.ipv6_address.parse::<Ipv6Addr>().unwrap()))
            .collect();
        let route_provider = RoundRobinRouteProvider::new(api_bn_urls).unwrap();
        let transport =
            ReqwestTransport::create_with_client_route(Box::new(route_provider), http_client)
                .unwrap();
        let agent = Agent::builder()
            .with_transport(transport)
            .with_identity(AnonymousIdentity {})
            .build()
            .unwrap();
        block_on(agent.fetch_root_key()).unwrap();
        agent
    };

    info!(log, "Incrementing counters on canisters");
    block_on(set_counters_on_counter_canisters(
        &log,
        api_bn_agent.clone(),
        canister_ids.clone(),
        canister_values.clone(),
        CANISTER_RETRY_BACKOFF,
        CANISTER_RETRY_TIMEOUT,
    ));

    info!(log, "Asserting expected counter values on canisters");
    let counters = block_on(read_counters_on_counter_canisters(
        &log,
        api_bn_agent,
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
