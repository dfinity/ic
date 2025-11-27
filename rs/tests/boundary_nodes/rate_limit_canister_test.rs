/* tag::catalog[]
Title:: Rate-limit canister integration with API boundary nodes

Goal:: Ensure rate-limit rules can be added to the canister and are properly enforced by API Boundary Nodes.

Runbook:
1.  Set up an Internet Computer (IC) with a system-subnet and an API boundary node.
2.  Install the rate-limit canister at a specified mainnet ID, without specifying an authorized_principal in the payload argument.
3.  Install the counter canister, which is used for testing enforced rate-limits.
4.  Create an `ic-agent` instance associated with an API boundary node.
5.  Verify that initially the agent can successfully interact with the counter canister by sending e.g. an update call.
6.  Try to add two rate-limit rules to the rate-limit canister, which completely block requests to two canisters: counter and rate-limit (self blocking).
7.  Assert canister call fails (rejected), as authorized_principal is unset for the rate-limit canister.
8.  Upgrade rate-limit canister code via proposal, specifying authorized_principal in the payload.
9.  Retry step 6 and assert it succeeds.
10. Verify that the agent can no longer send requests to the counter canister after API boundary node enforces the new rule.
11. Add a rate-limit rule, which explicitly unblocks requests to the counter canister.
    Setting this rule should still be possible despite the rate-limit canister being blocked itself (as there is an explicit allow-rule in the ic-boundary).
12. Verify that the agent can send requests to the counter canister again, ensuring that updated rate-limit rules are enforced correctly by API boundary nodes.

end::catalog[] */

use anyhow::{Result, bail};
use async_trait::async_trait;
use candid::{Decode, Encode, Principal};
use canister_test::{Canister, Wasm};
use ic_base_types::PrincipalId;
use ic_boundary_nodes_system_test_utils::{
    constants::COUNTER_CANISTER_WAT, helpers::install_canisters,
};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_test_utils::{
    common::modify_wasm_bytes, governance::upgrade_nns_canister_by_proposal,
    itest_helpers::install_rust_canister_from_path,
};
use k256::elliptic_curve::SecretKey;
use rand::{SeedableRng, rngs::OsRng};
use rand_chacha::ChaChaRng;
use slog::info;
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use tokio::runtime::Runtime;

use ic_agent::{
    Agent, AgentError, Identity,
    agent::{
        HttpService,
        http_transport::reqwest_transport::reqwest::{Client, Request, Response},
    },
    identity::Secp256k1Identity,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::test_env_api::NnsInstallationBuilder,
    driver::{
        group::SystemTestGroup,
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{
            GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            get_dependency_path,
        },
    },
    retry_with_msg_async, systest,
    util::runtime_from_url,
};
use rate_limits_api::{
    AddConfigResponse, InitArg, InputConfig, InputRule,
    v1::{Action, RateLimitRule},
};

const RATE_LIMIT_CANISTER_ID: &str = "u637p-5aaaa-aaaaq-qaaca-cai";

pub fn setup(env: TestEnv) {
    info!(
        &env.logger(),
        "Step 1. Set up an Internet Computer (IC) with a system-subnet and an API boundary node"
    );
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .use_specified_ids_allocation_range()
        .with_api_boundary_nodes(1)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    let nns_node = env
        .topology_snapshot()
        .root_subnet()
        .nodes()
        .next()
        .unwrap();
    NnsInstallationBuilder::new()
        .at_ids()
        .install(&nns_node, &env)
        .expect("could not install NNS canisters");
    info!(&env.logger(), "Checking readiness of all replica nodes ...");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

async fn test_async(env: TestEnv) {
    let logger = env.logger();

    let mut rng = ChaChaRng::from_rng(OsRng).unwrap();
    let full_access_identity = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let full_access_principal = full_access_identity.sender().unwrap();

    let nns_node = env.get_first_healthy_system_node_snapshot();
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());

    let rate_limit_id = Principal::from_text(RATE_LIMIT_CANISTER_ID).unwrap();

    info!(
        &logger,
        "Step 2. Install the rate-limit canister at a specified mainnet ID {rate_limit_id} (do not set any authorized_principal)"
    );

    let mut rate_limit_canister = nns
        .create_canister_at_id(PrincipalId(rate_limit_id))
        .await
        .unwrap();

    let path_to_wasm = get_dependency_path(
        env::var("RATE_LIMIT_CANISTER_WASM_PATH").expect("RATE_LIMIT_CANISTER_WASM_PATH not set"),
    );

    let wasm: Wasm = Wasm::from_file(path_to_wasm.clone());

    let args = Encode!(&InitArg {
        registry_polling_period_secs: 5,
        authorized_principal: None,
    })
    .unwrap();

    info!(
        &logger,
        "Installing rate-limit canister wasm (with unset authorized_principal)..."
    );

    install_rust_canister_from_path(&mut rate_limit_canister, path_to_wasm, Some(args)).await;

    info!(
        &logger,
        "Rate-limit canister with id={rate_limit_id} installed successfully"
    );

    let root = Canister::new(&nns, ROOT_CANISTER_ID);

    // set the root principal as the controller of the canister
    rate_limit_canister
        .set_controller(ROOT_CANISTER_ID.into())
        .await
        .unwrap();

    info!(&logger, "Step 3. Installing counter canister ...");

    let counter_canister_id = install_canisters(
        env.topology_snapshot(),
        wat::parse_str(COUNTER_CANISTER_WAT).unwrap().as_slice(),
        1,
    )
    .await[0];

    info!(
        &logger,
        "Step 4. Create an `ic-agent` instance associated with an API boundary node"
    );

    let api_bn_agent = {
        let api_bn = env.topology_snapshot().api_boundary_nodes().next().unwrap();
        let api_bn_ipv6 = SocketAddr::new(api_bn.get_ip_addr(), 0);
        let api_bn_domain = api_bn.get_domain().unwrap();
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .resolve(&api_bn_domain, api_bn_ipv6)
            .build()
            .expect("Could not create HTTP client.");
        let agent = Agent::builder()
            .with_url(format!("https://{api_bn_domain}"))
            .with_identity(full_access_identity.clone())
            .with_arc_http_middleware(Arc::new(HttpServiceNoRetry { client })) // do not use inbuilt retry logic for 429 responses
            .build()
            .unwrap();
        agent.fetch_root_key().await.unwrap();
        agent
    };

    info!(
        &logger,
        "Step 5. Verify that agent can successfully interact with counter canister"
    );

    api_bn_agent
        .update(&counter_canister_id, "write")
        .call_and_wait()
        .await
        .expect("failed to increment the counter on canister");

    info!(
        &logger,
        "Step 6. Try to add two rate-limit rules that block requests to counter and rate-limit canisters"
    );

    let result = set_rate_limit_rules(
        &api_bn_agent,
        rate_limit_id,
        vec![
            InputRule {
                incident_id: "b97730ac-4879-47f2-9fea-daf20b8d4b64".to_string(),
                rule_raw: RateLimitRule {
                    canister_id: Some(counter_canister_id),
                    limit: Action::Block,
                    ..Default::default()
                }
                .to_bytes_json()
                .unwrap(),
                description: "Block requests to counter canister".to_string(),
            },
            InputRule {
                incident_id: "34bb6dee-9646-4543-ba62-af546ea5565b".to_string(),
                rule_raw: RateLimitRule {
                    canister_id: Some(rate_limit_id),
                    limit: Action::Block,
                    ..Default::default()
                }
                .to_bytes_json()
                .unwrap(),
                description: "Block requests to rate-limit canister".to_string(),
            },
        ],
    )
    .await;

    info!(
        &logger,
        "Step 7. Assert canister call fails (rejected), as authorized_principal is unset for the rate-limit canister",
    );

    assert!(result.unwrap_err().contains("reject"));

    info!(
        &logger,
        "Step 8. Upgrade rate-limit canister code via proposal, specifying authorized_principal in the payload",
    );

    let args = Encode!(&InitArg {
        registry_polling_period_secs: 5,
        authorized_principal: Some(full_access_principal),
    })
    .unwrap();

    // apply a no-impact WASM modification and reinstall the canister
    let new_wasm = modify_wasm_bytes(wasm.bytes().as_slice(), 42);

    upgrade_nns_canister_by_proposal(
        &rate_limit_canister,
        &Canister::new(&nns, GOVERNANCE_CANISTER_ID),
        &root,
        true,
        Wasm::from_bytes(new_wasm),
        Some(args),
    )
    .await;

    info!(
        &logger,
        "Step 9. Assert adding two rate-limit rules to the rate-limit canister now succeeds"
    );

    set_rate_limit_rules(
        &api_bn_agent,
        rate_limit_id,
        vec![
            InputRule {
                incident_id: "b97730ac-4879-47f2-9fea-daf20b8d4b64".to_string(),
                rule_raw: RateLimitRule {
                    canister_id: Some(counter_canister_id),
                    limit: Action::Block,
                    ..Default::default()
                }
                .to_bytes_json()
                .unwrap(),
                description: "Block requests to counter canister".to_string(),
            },
            InputRule {
                incident_id: "34bb6dee-9646-4543-ba62-af546ea5565b".to_string(),
                rule_raw: RateLimitRule {
                    canister_id: Some(rate_limit_id),
                    limit: Action::Block,
                    ..Default::default()
                }
                .to_bytes_json()
                .unwrap(),
                description: "Block requests to rate-limit canister".to_string(),
            },
        ],
    )
    .await
    .unwrap();

    info!(
        &logger,
        "Step 10. Verify that the api_bn_agent can no longer send requests to the counter canister"
    );

    retry_with_msg_async!(
        "check_counter_canister_becomes_unreachable".to_string(),
        &logger,
        Duration::from_secs(180),
        Duration::from_secs(5),
        || async {
            match api_bn_agent
                .update(&counter_canister_id, "write")
                .call()
                .await
            {
                Ok(_) => {
                    bail!("counter canister is still reachable, retrying");
                }
                Err(error) => {
                    // We should observe 403 http error, as all requests are blocked
                    if let AgentError::HttpError(ref payload) = error
                        && payload.status == 403
                    {
                        return Ok(());
                    }
                    bail!("update call failed with unexpected error: {error:?}");
                }
            }
        }
    )
    .await
    .expect("failed to check that canister becomes unreachable");

    info!(
        &logger,
        "Step 11. Add a rate-limit rule, which unblocks requests to the counter canister"
    );

    // api_bn_agent can't communicate with canister after blocking, hence we use nns_agent
    let mut nns_agent = nns_node.build_default_agent_async().await;
    nns_agent.set_identity(full_access_identity);

    set_rate_limit_rules(
        &nns_agent,
        rate_limit_id,
        vec![InputRule {
            incident_id: "e6a27788-01a5-444a-9035-ab3af3ad84f3".to_string(),
            rule_raw: RateLimitRule {
                canister_id: Some(counter_canister_id),
                limit: Action::Limit(300, Duration::from_secs(60)),
                ..Default::default()
            }
            .to_bytes_json()
            .unwrap(),
            description: "Unblock requests to the counter canister".to_string(),
        }],
    )
    .await
    .unwrap();

    info!(
        &logger,
        "Step 12. Verify that agent can send requests to the counter canister again"
    );

    retry_with_msg_async!(
        "check_counter_canister_becomes_reachable".to_string(),
        &logger,
        Duration::from_secs(180),
        Duration::from_secs(5),
        || async {
            match api_bn_agent
                .update(&counter_canister_id, "write")
                .call()
                .await
            {
                Ok(response) => {
                    info!(&logger, "update call succeeded with response: {response:?}");
                    Ok(())
                }
                Err(error) => {
                    info!(&logger, "update call failed with error: {error:?}");
                    bail!("counter canister is still unreachable, retrying");
                }
            }
        }
    )
    .await
    .expect("failed to check that canister becomes reachable");
}

async fn set_rate_limit_rules(
    agent: &Agent,
    rate_limit_canister_id: Principal,
    rules: Vec<InputRule>,
) -> Result<(), String> {
    let args = Encode!(&InputConfig {
        schema_version: 1,
        rules,
    })
    .unwrap();

    let result = agent
        .update(&rate_limit_canister_id, "add_config")
        .with_arg(args)
        .call_and_wait()
        .await
        .map_err(|err| err.to_string())?;

    Decode!(&result, AddConfigResponse)
        .expect("failed to deserialize response")
        .map_err(|err| format!("{err:?}"))
}

fn test(env: TestEnv) {
    let rt = Runtime::new().expect("Could not create tokio runtime");
    rt.block_on(test_async(env));
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}

// The default HttpService in ic-agent retries on 429 errors, but we expect these and don't want retries.
#[derive(Debug)]
struct HttpServiceNoRetry {
    client: Client,
}

#[async_trait]
impl HttpService for HttpServiceNoRetry {
    async fn call<'a>(
        &'a self,
        req: &'a (dyn Fn() -> Result<Request, AgentError> + Send + Sync),
        _max_tcp_retries: usize,
    ) -> Result<Response, AgentError> {
        Ok(self.client.call(req, _max_tcp_retries).await?)
    }
}
