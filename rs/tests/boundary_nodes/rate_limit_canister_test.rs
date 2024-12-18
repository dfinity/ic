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

use anyhow::Result;
use candid::{Decode, Encode, Principal};
use ic_base_types::PrincipalId;
use ic_nns_test_utils::itest_helpers::install_rust_canister_from_path;
use ic_system_test_driver::{
    driver::test_env_api::NnsInstallationBuilder,
    util::{assert_create_agent, create_agent_mapping},
};
use k256::elliptic_curve::SecretKey;
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaChaRng;
use slog::{info, Logger};
use std::{env, net::{SocketAddr, SocketAddrV6}};
use std::time::Duration;
use tokio::{runtime::Runtime, time::sleep};

use ic_agent::{
    agent::http_transport::{reqwest_transport::reqwest::Client, ReqwestTransport}, identity::{AnonymousIdentity, Secp256k1Identity}, Agent, Identity
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
use regex::Regex;

use rate_limits_api::{
    v1::{Action, RateLimitRule, RequestType},
    AddConfigResponse, DiscloseRulesArg, DiscloseRulesResponse, GetConfigResponse,
    GetRuleByIdResponse, IncidentId, InitArg, InputConfig, InputRule, OutputRuleMetadata, RuleId,
    Version,
};

pub fn setup(env: TestEnv) {
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

    let rt = Runtime::new().expect("Could not create tokio runtime.");

    let mut rng = ChaChaRng::from_rng(OsRng).unwrap();
    let full_access_identity = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let full_access_principal = full_access_identity.sender().unwrap();
    let api_bn = env.topology_snapshot().api_boundary_nodes().next().unwrap();

    let api_bn_url = api_bn.get_public_url();
    let api_bn_ipv6 = api_bn.get_ip_addr();
    let ipv6 = SocketAddr::new(api_bn_ipv6, 0).into();
    let api_bn_domain = api_bn.get_domain().unwrap();
    info!(
        &logger,
        "API BN url {api_bn_url}, ipv6 {api_bn_ipv6}, domain {api_bn_domain:?}"
    );

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve(&api_bn_domain, ipv6)
        .build()
        .expect("Could not create HTTP client.");

    let transport = ReqwestTransport::create_with_client(format!("https://{api_bn_domain}"), client).unwrap();
    let mut api_bn_agent = Agent::builder()
        .with_transport(transport)
        .with_identity(full_access_identity.clone())
        .build()
        .unwrap();
    let_ = rt.block_on(api_bn_agent.fetch_root_key());

    info!(&logger, "installing rate-limit canister ...");

    let canister_id = Principal::from_text("u637p-5aaaa-aaaaq-qaaca-cai").unwrap();

    let nns_node = env.get_first_healthy_system_node_snapshot();
    let nns = runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id());

    info!(
        &logger,
        "creating rate-limit canister at specific id={canister_id} ..."
    );

    let mut rate_limit_canister = rt
        .block_on(nns.create_canister_at_id(PrincipalId(canister_id)))
        .unwrap();

    let args = Encode!(&InitArg {
        registry_polling_period_secs: 60,
        authorized_principal: Some(full_access_principal),
    })
    .unwrap();

    info!(&logger, "installing rate-limit canister wasm");

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
        "rate-limit canister with id={canister_id} installed successfully"
    );

    rt.block_on(async move {
        info!(&logger, "Reading a config from rate-limit canister");
        let config = read_config(logger.clone(), &api_bn_agent, 1, canister_id).await;
        info!(&logger, "Add a new config (version = 2) containing some rules (FullAccess level of the caller is required)");
        add_config_1(logger.clone(), &api_bn_agent, canister_id).await;
        let config = read_config(logger.clone(), &api_bn_agent, 2, canister_id).await;
        loop {
            info!(&logger, "Trying to read config ...");
            let config = read_config(logger.clone(), &api_bn_agent, 2, canister_id).await;
            sleep(Duration::from_secs(5)).await;
        }
    });
}

async fn create_agent<I: Identity + 'static>(identity: I, domain: String) -> Agent {
    let agent = Agent::builder()
        .with_url(domain)
        .with_identity(identity)
        .build()
        .expect("failed to build the agent");
    agent.fetch_root_key().await.unwrap();
    agent
}

async fn add_config_1(logger: Logger, agent: &Agent, canister_id: Principal) {
    let rule = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: None,
        request_types: None,
        limit: Action::Block,
    };

    let args = Encode!(&InputConfig {
        schema_version: 1,
        rules: vec![InputRule {
            incident_id: "b97730ac-4879-47f2-9fea-daf20b8d4b64".to_string(),
            rule_raw: rule.to_bytes_json().unwrap(),
            description:
                "Some vulnerability #1 discovered, temporarily rate-limiting the canister calls"
                    .to_string(),
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

async fn add_config_2(logger: Logger, agent: &Agent, canister_id: Principal) {
    // This config differs from config 1 by rule_3 at index = 2, see comment below.
    let rule_1 = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: Some(Regex::new(r"^(method_1)$").unwrap()),
        request_types: Some(vec![RequestType::Call]),
        limit: Action::Limit(1, Duration::from_secs(60)),
    };

    let rule_2 = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: Some(Regex::new(r"^(method_2)$").unwrap()),
        request_types: Some(vec![RequestType::Query]),
        limit: Action::Limit(2, Duration::from_secs(60)),
    };

    // only this rule is different from config_1
    let rule_3 = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: Some(Regex::new(r"^(method_33)$").unwrap()),
        request_types: None,
        limit: Action::Limit(33, Duration::from_secs(60)),
    };

    let rule_4 = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: Some(Regex::new(r"^(method_4)$").unwrap()),
        request_types: Some(vec![RequestType::ReadState]),
        limit: Action::Limit(4, Duration::from_secs(60)),
    };

    let args = Encode!(&InputConfig {
        schema_version: 1,
        rules: vec![
            InputRule {
                incident_id: "b97730ac-4879-47f2-9fea-daf20b8d4b64".to_string(),
                rule_raw: rule_1.to_bytes_json().unwrap(),
                description:
                    "Some vulnerability #1 discovered, temporarily rate-limiting the canister calls"
                        .to_string(),
            },
            InputRule {
                incident_id: "f63c821c-9320-476a-bc89-94cb99d04639".to_string(),
                rule_raw: rule_2.to_bytes_json().unwrap(),
                description: "Some vulnerability #2 discovered".to_string(),
            },
            // Only this rule is different from config 1, it also has another incident_id and description
            // It means that the old rule is removed (not mutated) and this new rule is applied instead.
            InputRule {
                incident_id: "ebe7dbb1-63c9-420e-980d-eb0f8c20a9fb".to_string(),
                rule_raw: rule_3.to_bytes_json().unwrap(),
                description: "Some vulnerability #4 discovered".to_string(),
            },
            InputRule {
                incident_id: "389bbff8-bffa-4430-bb70-8ce1ea399c07".to_string(),
                rule_raw: rule_4.to_bytes_json().unwrap(),
                description: "Some vulnerability #3 discovered".to_string(),
            },
        ],
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

async fn disclose_incident(
    logger: Logger,
    agent: &Agent,
    incident_id: IncidentId,
    canister_id: Principal,
) {
    let disclose_arg = DiscloseRulesArg::IncidentIds(vec![incident_id]);
    let args = Encode!(&disclose_arg).unwrap();

    let response = agent
        .update(&canister_id, "disclose_rules")
        .with_arg(args)
        .call_and_wait()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, DiscloseRulesResponse).unwrap();

    info!(&logger, "Response to disclose_rules() call: {decoded:#?}");
}

async fn read_rule(
    logger: Logger,
    agent: &Agent,
    rule_id: &RuleId,
    canister_id: Principal,
) -> OutputRuleMetadata {
    let args = Encode!(rule_id).unwrap();

    let response = agent
        .query(&canister_id, "get_rule_by_id")
        .with_arg(args)
        .call()
        .await
        .expect("update call failed");

    let rule_metadata = Decode!(&response, GetRuleByIdResponse).unwrap().unwrap();

    info!(
        &logger,
        "Response to get_rule_by_id() call: {rule_metadata}"
    );

    rule_metadata
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_parallel(SystemTestSubGroup::new().add_test(systest!(complete_flow_test)))
        .execute_from_args()?;
    Ok(())
}
