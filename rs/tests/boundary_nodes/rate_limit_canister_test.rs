/* tag::catalog[]
Title:: Setting rate-limits on the API boundary nodes via rate-limit canister (status WIP)

Goal:: NOTE: this is a WIP system-test. Verify that API boundary nodes can dynamically fetch rate-limit configurations from the canister and enforce them for ingress messages.

Runbook:
. Set up an rate-limit canister.
. Test that the rate-limit canister API works.
. TODO: test that API boundary node can successfully fetch/apply rate-limit configurations.

Success:: The rate-limit canister is installed and the API works.

Coverage:: The rate-limit canister interface works as expected.

end::catalog[] */

use anyhow::bail;
use anyhow::Result;
use candid::{Decode, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_nns_test_utils::itest_helpers::install_rust_canister_from_path;
use ic_system_test_driver::driver::test_env_api::NnsInstallationBuilder;
use ic_system_test_driver::retry_with_msg_async;
use k256::elliptic_curve::SecretKey;
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaChaRng;
use slog::{info, Logger};
use std::time::Duration;
use std::{env, net::SocketAddr};
use tokio::runtime::Runtime;
use tokio::time::timeout;

use ic_agent::{
    agent::http_transport::{reqwest_transport::reqwest::Client, ReqwestTransport},
    identity::Secp256k1Identity,
    Agent, Identity,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::{SystemTestGroup, SystemTestSubGroup},
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot,
            IcNodeContainer,
        },
    },
    systest,
    util::runtime_from_url,
};
use rate_limits_api::{
    v1::{Action, RateLimitRule},
    AddConfigResponse, GetConfigResponse, InitArg, InputConfig, InputRule, RuleId, Version,
};

const RATE_LIMIT_CANISTER_ID: &str = "u637p-5aaaa-aaaaq-qaaca-cai";

/* tag::catalog[]
Title:: Rate-limit canister integration with API boundary nodes

Goal:: Ensure rate-limit rules can be added to the canister and are properly enforced by API Boundary Nodes.

Runbook:
1. Set up an Internet Computer (IC) with a system-subnet and an API boundary node.
2. Install the rate-limit canister at a specified mainnet ID.
3. Create two `ic-agent` instances:
   - nns_agent associated with an NNS node.
   - api_bn_agent associated with an API boundary node.
4. Verify that both agents can successfully read configurations from the rate-limit canister.
5. Add a rate-limit rule to the canister that blocks requests to itself.
6. Verify that the api_bn_agent can no longer send requests to the rate-limit canister.
7. Update the rate-limit rule via nns_agent, which unblocks requests to the canister.
8. Verify that the api_bn_agent can send requests to the rate-limit canister again.

end::catalog[] */

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

pub fn complete_flow_test(env: TestEnv) {
    let logger = env.logger();

    let mut rng = ChaChaRng::from_rng(OsRng).unwrap();
    let full_access_identity = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let full_access_principal = full_access_identity.sender().unwrap();

    let nns_node = env.get_first_healthy_system_node_snapshot();
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());
    let mut nns_agent = nns_node.build_default_agent();
    nns_agent.set_identity(full_access_identity.clone());

    let canister_id = Principal::from_text(RATE_LIMIT_CANISTER_ID).unwrap();

    info!(
        &logger,
        "Step 2. Install the rate-limit canister at a specified mainnet ID {canister_id}"
    );

    let rt = Runtime::new().expect("Could not create tokio runtime.");

    let mut rate_limit_canister = rt
        .block_on(nns.create_canister_at_id(PrincipalId(canister_id)))
        .unwrap();

    let args = Encode!(&InitArg {
        registry_polling_period_secs: 60,
        authorized_principal: Some(full_access_principal),
    })
    .unwrap();

    info!(&logger, "Installing rate-limit canister wasm ...");

    rt.block_on(install_rust_canister_from_path(
        &mut rate_limit_canister,
        get_dependency_path(
            env::var("RATE_LIMIT_CANISTER_WASM_PATH")
                .expect("RATE_LIMIT_CANISTER_WASM_PATH not set"),
        ),
        Some(args),
    ));

    info!(
        &logger,
        "Rate-limit canister with id={canister_id} installed successfully"
    );

    info!(
        &logger,
        "Step 3. Create two ic-agent instances, one for nns-node and one API node"
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
        let transport =
            ReqwestTransport::create_with_client(format!("https://{api_bn_domain}"), client)
                .unwrap();
        let agent = Agent::builder()
            .with_transport(transport)
            .with_identity(full_access_identity)
            .build()
            .unwrap();
        let _ = rt.block_on(agent.fetch_root_key());
        agent
    };

    rt.block_on(async move {
        info!(
                &logger,
                "Step 4. Verify that both agents can successfully read configurations from the rate-limit canister"
            );

        let _ = read_config(logger.clone(), &api_bn_agent, 1, canister_id).await;
        let _ = read_config(logger.clone(), &nns_agent, 1, canister_id).await;

        info!(
            &logger,
            "Step 5. Add a rate-limit rule to the canister that blocks access to itself"
        );
        add_config(logger.clone(), &api_bn_agent, canister_id, Action::Block).await;

        info!(
            &logger,
            "Step 6. Verify canister becomes unreachable for the agent associated with API node"
        );

        retry_with_msg_async!(
            "check_canister_becomes_unreachable".to_string(),
            &logger,
            Duration::from_secs(180),
            Duration::from_secs(5),
            || async {
                match timeout(
                    Duration::from_secs(2),
                    read_config(logger.clone(), &api_bn_agent, 2, canister_id),
                )
                .await
                {
                    Ok(_) => bail!("rate-limit canister is still reachable, retrying"),
                    Err(_) => Ok(()),
                }
            }
        )
        .await
        .expect("failed to check that canister becomes unreachable");

        info!(
            &logger,
            "Step 7. Update the rate-limit rule to unblock access to the canister"
        );

        add_config(
            logger.clone(),
            &nns_agent,
            canister_id,
            Action::Limit(300, Duration::from_secs(60)),
        )
        .await;

        info!(
            &logger,
            "Step 8. Verify canister becomes reachable for the agent associated with API node"
        );

        retry_with_msg_async!(
            "check_canister_becomes_reachable".to_string(),
            &logger,
            Duration::from_secs(180),
            Duration::from_secs(5),
            || async {
                match timeout(
                    Duration::from_secs(2),
                    read_config(logger.clone(), &api_bn_agent, 3, canister_id),
                )
                .await
                {
                    Ok(_) => Ok(()),
                    Err(_) => bail!("rate-limit canister is still unreachable, retrying"),
                }
            }
        )
        .await
        .expect("failed to check that canister becomes reachable");
    });
}

async fn add_config(logger: Logger, agent: &Agent, canister_id: Principal, action: Action) {
    let rule = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: None,
        request_types: None,
        limit: action,
    };

    let args = Encode!(&InputConfig {
        schema_version: 1,
        rules: vec![InputRule {
            incident_id: "b97730ac-4879-47f2-9fea-daf20b8d4b64".to_string(),
            rule_raw: rule.to_bytes_json().unwrap(),
            description: "Setting a rate-limit rule for the canister".to_string(),
        },],
    })
    .unwrap();

    let result = agent
        .update(&canister_id, "add_config")
        .with_arg(args)
        .call_and_wait()
        .await
        .unwrap();

    let decoded = Decode!(&result, AddConfigResponse).unwrap();

    info!(&logger, "Response to add_config() call: {decoded:#?}");
}

async fn read_config(
    logger: Logger,
    agent: &Agent,
    version: Version,
    canister_id: Principal,
) -> Vec<RuleId> {
    let args = Encode!(&Some(version)).unwrap();

    let response = agent
        .query(&canister_id, "get_config")
        .with_arg(args)
        .call()
        .await
        .expect("query call failed");

    let decoded = Decode!(&response, GetConfigResponse)
        .expect("failed to decode candid response")
        .unwrap();

    info!(&logger, "Response to get_config() call: {}", decoded);

    decoded
        .config
        .rules
        .into_iter()
        .map(|rule| rule.id)
        .collect()
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(SystemTestSubGroup::new().add_test(systest!(complete_flow_test)))
        .execute_from_args()?;
    Ok(())
}
