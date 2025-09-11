use super::Step;

use anyhow::bail;
use ic_agent::{
    Agent,
    agent::http_transport::reqwest_transport::reqwest::{Client, ClientBuilder, redirect::Policy},
    export::Principal,
    identity::AnonymousIdentity,
};
use ic_boundary_nodes_system_test_utils::constants::COUNTER_CANISTER_WAT;
use ic_nns_constants::REGISTRY_CANISTER_ID;
use ic_system_test_driver::{
    driver::test_env_api::{
        GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeSnapshot,
    },
    retry_with_msg_async,
};
use ic_utils::interfaces::ManagementCanister;
use slog::{Logger, info};
use std::{net::SocketAddr, time::Duration};

const READY_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_BACKOFF: Duration = Duration::from_secs(2);

const CANISTER_RETRY_TIMEOUT: Duration = Duration::from_secs(30);
const CANISTER_RETRY_BACKOFF: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct Workload {
    pub message_size: usize,
    pub rps: f64,
}

impl Step for Workload {
    fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        rt: tokio::runtime::Handle,
    ) -> anyhow::Result<()> {
        // Small messages
        ic_consensus_system_test_utils::performance::test_with_rt_handle(
            env,
            self.message_size,
            self.rps,
            rt,
            false,
        )
        .map(|_| ())
    }
}

#[derive(Clone)]
pub struct ApiBoundaryNodeWorkload {}

impl Step for ApiBoundaryNodeWorkload {
    fn execute(
        &self,
        env: ic_system_test_driver::driver::test_env::TestEnv,
        rt: tokio::runtime::Handle,
    ) -> anyhow::Result<()> {
        let logger = env.logger();

        let api_boundary_nodes: Vec<IcNodeSnapshot> =
            env.topology_snapshot().api_boundary_nodes().collect();

        info!(
            logger,
            "Create HTTP client to talk to the API boundary nodes"
        );
        let http_client = {
            let mut client_builder = ClientBuilder::new()
                .redirect(Policy::none())
                .danger_accept_invalid_certs(true);

            for api_boundary_node in &api_boundary_nodes {
                let ipv6 = api_boundary_node.get_ip_addr();
                let node_addr = SocketAddr::new(ipv6, 0);
                let domain = api_boundary_node
                    .get_domain()
                    .expect("API BN has no domain");
                client_builder = client_builder.resolve(domain.as_str(), node_addr);
                info!(logger, "Resolve: domain={domain} to ipv6={node_addr}");
            }

            client_builder.build().expect("failed to build http client")
        };

        info!(logger, "Install the counter canister");
        let counter_canister_id: Principal = rt.block_on(install_counter_canister(env.clone()))?;

        let domains: Vec<String> = api_boundary_nodes
            .iter()
            .map(|node| node.get_domain().expect("API BN has no domain"))
            .collect();

        for (index, domain) in domains.into_iter().enumerate() {
            info!(logger, "Test API BN with domain {domain}");
            rt.block_on(test_api_boundary_node(
                index.try_into().unwrap(),
                domain,
                counter_canister_id,
                http_client.clone(),
                logger.clone(),
            ))?;
        }

        Ok(())
    }
}

async fn install_counter_canister(
    env: ic_system_test_driver::driver::test_env::TestEnv,
) -> anyhow::Result<Principal> {
    // install a counter canister on an app subnet
    let node = env.get_first_healthy_application_node_snapshot();

    let agent = node.build_default_agent_async().await;
    let effective_canister_id = node.effective_canister_id();
    let mgr = ManagementCanister::create(&agent);
    let (canister_id,) = mgr
        .create_canister()
        .as_provisional_create_with_amount(None)
        .with_effective_canister_id(effective_canister_id)
        .call_and_wait()
        .await
        .map_err(|err| format!("Couldn't create canister with provisional API: {err}"))
        .unwrap();
    let canister_code = wat::parse_str(COUNTER_CANISTER_WAT).unwrap();
    let install_code = mgr.install_code(&canister_id, canister_code.as_slice());
    install_code
        .call_and_wait()
        .await
        .map_err(|err| format!("Couldn't install canister: {err}"))
        .unwrap();

    Ok(canister_id)
}

async fn test_api_boundary_node(
    index: u32,
    domain: String,
    counter_canister_id: Principal,
    http_client: Client,
    logger: Logger,
) -> anyhow::Result<()> {
    info!(logger, "Health check the API BN");
    retry_with_msg_async!(
        "check_api_bns_health",
        &logger,
        READY_WAIT_TIMEOUT,
        RETRY_BACKOFF,
        || async {
            let response = http_client
                .get(format!("https://{domain}/health"))
                .send()
                .await?;

            if response.status().is_success() {
                info!(logger, "API BN with domain {domain} came up healthy");
                return Ok(());
            }

            bail!("API BN with domain {domain} is not yet healthy");
        }
    )
    .await
    .expect("API BN didn't come up healthy");

    // create an agent
    let bn_agent = Agent::builder()
        .with_url(format!("https://{domain}"))
        .with_http_client(http_client.clone())
        .with_identity(AnonymousIdentity {})
        .build()
        .unwrap();

    info!(
        logger,
        "api/v2/status - implicit status call to fetch the root key"
    );
    let _ = bn_agent.fetch_root_key().await;

    info!(
        logger,
        "api/v2/query - issue a query call (read the current counter value)"
    );
    let read_result = retry_with_msg_async!(
        format!("query call on canister={counter_canister_id}"),
        &logger,
        CANISTER_RETRY_TIMEOUT,
        CANISTER_RETRY_BACKOFF,
        || async {
            let read_result = bn_agent.query(&counter_canister_id, "read").call().await;
            if let Ok(bytes) = read_result {
                Ok(bytes)
            } else {
                bail!(
                    "querying the counter canister ({counter_canister_id}) failed, err: {:?}",
                    read_result.unwrap_err()
                )
            }
        }
    )
    .await
    .expect("querying the counter canister ({counter_canister_id}) failed after {max_attempts} attempts");

    let counter = u32::from_le_bytes(
        read_result
            .as_slice()
            .try_into()
            .expect("slice with incorrect length"),
    );

    assert_eq!(counter, index);

    info!(
        logger,
        "api/v3/call - issue an update call (increase the counter value)"
    );
    retry_with_msg_async!(
        format!("update call on canister={counter_canister_id}"),
        &logger,
        CANISTER_RETRY_TIMEOUT,
        CANISTER_RETRY_BACKOFF,
        || async {
            let result = bn_agent.update(&counter_canister_id, "write").call_and_wait().await;
            if let Ok(bytes) = result {
                Ok(bytes)
            } else {
                bail!(
                    "updating the counter canister ({counter_canister_id}) failed, err: {:?}",
                    result.unwrap_err()
                )
            }
        }
    )
    .await
    .expect("querying the counter canister ({counter_canister_id}) failed after {max_attempts} attempts");

    info!(
        logger,
        "api/v3/read_state - issue a read state to fetch the API BNs"
    );
    //  the canister ID is just needed for the API BN to route it to a subnet
    let _ = bn_agent
        .fetch_api_boundary_nodes_by_canister_id(REGISTRY_CANISTER_ID.into())
        .await
        .expect("read_state failed");

    Ok(())
}
