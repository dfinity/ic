/* tag::catalog[]
Title:: Rate-limit canister integration with API boundary nodes

Goal:: Ensure rate-limit rules can be added to the canister and are properly enforced by API Boundary Nodes.

Runbook:
1. Set up an Internet Computer (IC) with a system-subnet and an API boundary node.
2. Install the rate-limit canister at a specified mainnet ID.
3. Install the counter canister, which is used for testing enforced rate-limits.
4. Create an `ic-agent` instance associated with an API boundary node.
5. Verify that initially the agent can successfully interact with the counter canister by sending e.g. an update call.
6. Add a rate-limit rule to the rate-limit canister, which completely blocks requests to the counter canister.
// TODO: BOUN-1330 - investigate the reason of flakiness in Step 7, temporarily disable steps below.
7. Verify that the agent can no longer send requests to the counter canister after API boundary node enforces the new rule.
8. Add a rate-limit rule, which unblocks requests to the counter canister.
9. Verify that the agent can send requests to the counter canister again, ensuring that updated rate-limit rules are enforced correctly by API boundary nodes.

end::catalog[] */

use anyhow::Result;
use candid::{Decode, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_boundary_nodes_system_test_utils::{
    constants::COUNTER_CANISTER_WAT, helpers::install_canisters,
};
use ic_nns_test_utils::itest_helpers::install_rust_canister_from_path;
use k256::elliptic_curve::SecretKey;
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaChaRng;
use slog::info;
use std::{env, net::SocketAddr};
use tokio::runtime::Runtime;

use ic_agent::{
    agent::http_transport::reqwest_transport::reqwest::Client, identity::Secp256k1Identity, Agent,
    Identity,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::test_env_api::NnsInstallationBuilder,
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
    AddConfigResponse, InitArg, InputConfig, InputRule,
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
        "Step 2. Install the rate-limit canister at a specified mainnet ID {rate_limit_id}"
    );

    let mut rate_limit_canister = nns
        .create_canister_at_id(PrincipalId(rate_limit_id))
        .await
        .unwrap();

    let args = Encode!(&InitArg {
        registry_polling_period_secs: 5,
        authorized_principal: Some(full_access_principal),
    })
    .unwrap();

    info!(&logger, "Installing rate-limit canister wasm ...");

    install_rust_canister_from_path(
        &mut rate_limit_canister,
        get_dependency_path(
            env::var("RATE_LIMIT_CANISTER_WASM_PATH")
                .expect("RATE_LIMIT_CANISTER_WASM_PATH not set"),
        ),
        Some(args),
    )
    .await;

    info!(
        &logger,
        "Rate-limit canister with id={rate_limit_id} installed successfully"
    );

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
            .with_http_client(client)
            .with_identity(full_access_identity)
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
        "Step 6. Add a rate-limit rule that blocks requests to counter canister"
    );

    set_rate_limit_rule(
        &api_bn_agent,
        rate_limit_id,
        RateLimitRule {
            canister_id: Some(counter_canister_id),
            limit: Action::Block,
            ..Default::default()
        },
    )
    .await;

    // TODO: BOUN-1330 - investigate the reason of flakiness in Step 7, temporarily disable steps below.

    // info!(
    //     &logger,
    //     "Step 7. Verify that the api_bn_agent can no longer send requests to the counter canister"
    // );

    // retry_with_msg_async!(
    //     "check_counter_canister_becomes_unreachable".to_string(),
    //     &logger,
    //     Duration::from_secs(180),
    //     Duration::from_secs(5),
    //     || async {
    //         match timeout(
    //             Duration::from_secs(2),
    //             api_bn_agent.update(&counter_canister_id, "write").call(),
    //         )
    //         .await
    //         {
    //             Ok(_) => bail!("counter canister is still reachable, retrying"),
    //             Err(_) => Ok(()),
    //         }
    //     }
    // )
    // .await
    // .expect("failed to check that canister becomes unreachable");

    // info!(
    //     &logger,
    //     "Step 8. Add a rate-limit rule, which unblocks requests to the counter canister"
    // );

    // set_rate_limit_rule(
    //     &api_bn_agent,
    //     rate_limit_id,
    //     RateLimitRule {
    //         canister_id: Some(counter_canister_id),
    //         limit: Action::Limit(300, Duration::from_secs(60)),
    //         ..Default::default()
    //     },
    // )
    // .await;

    // info!(
    //     &logger,
    //     "Step 9. Verify that agent can send requests to the counter canister again"
    // );

    // retry_with_msg_async!(
    //     "check_counter_canister_becomes_reachable".to_string(),
    //     &logger,
    //     Duration::from_secs(180),
    //     Duration::from_secs(5),
    //     || async {
    //         match timeout(
    //             Duration::from_secs(2),
    //             api_bn_agent.update(&counter_canister_id, "write").call(),
    //         )
    //         .await
    //         {
    //             Ok(_) => Ok(()),
    //             Err(_) => bail!("counter canister is still unreachable, retrying"),
    //         }
    //     }
    // )
    // .await
    // .expect("failed to check that canister becomes reachable");
}

async fn set_rate_limit_rule(
    agent: &Agent,
    rate_limit_canister_id: Principal,
    rule: RateLimitRule,
) {
    let args = Encode!(&InputConfig {
        schema_version: 1,
        rules: vec![InputRule {
            incident_id: "b97730ac-4879-47f2-9fea-daf20b8d4b64".to_string(),
            rule_raw: rule.to_bytes_json().unwrap(),
            description: "Setting a rate-limit rule for testing".to_string(),
        },],
    })
    .unwrap();

    let result = agent
        .update(&rate_limit_canister_id, "add_config")
        .with_arg(args)
        .call_and_wait()
        .await
        .unwrap();

    let _ = Decode!(&result, AddConfigResponse).expect("failed to add new rate-limit config");
}

fn test(env: TestEnv) {
    let rt = Runtime::new().expect("Could not create tokio runtime");
    rt.block_on(test_async(env));
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(SystemTestSubGroup::new().add_test(systest!(test)))
        .execute_from_args()?;
    Ok(())
}
