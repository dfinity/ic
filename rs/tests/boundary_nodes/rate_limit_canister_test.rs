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

use anyhow::{bail, Result};
use candid::{Decode, Encode, Principal};
use k256::elliptic_curve::SecretKey;
use rand::{rngs::OsRng, SeedableRng};
use rand_chacha::ChaChaRng;
use slog::{info, Logger};
use std::env;
use tokio::runtime::Runtime;

use ic_agent::{
    identity::{AnonymousIdentity, Secp256k1Identity},
    Agent, Identity,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        group::{SystemTestGroup, SystemTestSubGroup},
        ic::InternetComputer,
        test_env::TestEnv,
        test_env_api::{
            GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            READY_WAIT_TIMEOUT, RETRY_BACKOFF,
        },
    },
    retry_with_msg_async, systest,
    util::agent_observes_canister_module,
};
use rate_limits_api::{
    v1::{RateLimitRule, RequestType},
    AddConfigResponse, DiscloseRulesArg, DiscloseRulesResponse, GetConfigResponse,
    GetRuleByIdResponse, IncidentId, InitArg, InputConfig, InputRule, OutputRuleMetadata, RuleId,
    Version,
};

pub fn setup(env: TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(&env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
}

pub fn complete_flow_test(env: TestEnv) {
    let logger = env.logger();

    info!(&logger, "installing canister");

    let mut rng = ChaChaRng::from_rng(OsRng).unwrap();
    let full_access_identity = Secp256k1Identity::from_private_key(SecretKey::random(&mut rng));
    let full_access_principal = full_access_identity.sender().unwrap();

    let args = Encode!(&InitArg {
        registry_polling_period_secs: 60,
        authorized_principal: Some(full_access_principal),
    })
    .unwrap();

    let app_node = env.get_first_healthy_application_node_snapshot();
    let canister_id = app_node.create_and_install_canister_with_arg(
        &env::var("RATE_LIMIT_CANISTER_WASM_PATH").expect("RATE_LIMIT_CANISTER_WASM_PATH not set"),
        Some(args),
    );

    let rt = Runtime::new().expect("Could not create tokio runtime.");
    let agent_node = app_node.build_default_agent();

    rt.block_on(async move {
        // wait for canister to finish installing
        retry_with_msg_async!(
            format!(
                "agent of {} observes canister module {}",
                app_node.get_public_url().to_string(),
                canister_id.to_string()
            ),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                match agent_observes_canister_module(&agent_node, &canister_id).await {
                    true => Ok(()),
                    false => bail!("Canister module not available yet"),
                }
            }
        )
        .await
        .unwrap();
        info!(&logger, "installed rate-limit canister ({canister_id})");

        info!(&logger, "creating two agents with different access rights");
        let app_node_url = app_node.get_public_url().to_string();
        let agent_full_access = create_agent(full_access_identity, app_node_url.clone()).await;
        let agent_restricted_read = create_agent(AnonymousIdentity {}, app_node_url).await;

        info!(&logger, "Call 1. Add a new config (version = 2) containing some rules (FullAccess level of the caller is required)");
        add_config_1(logger.clone(), &agent_full_access, canister_id).await;

        info!(&logger, "Call 2. Read config by privileged user (FullAccess or FullRead caller level). Response will expose rules/descriptions in their full form");
        let version = 2;
        read_config(logger.clone(), &agent_full_access, version, canister_id).await;

        info!(&logger, "Call 3. Read config by non-privileged user (RestrictedRead level). Rules and descriptions are hidden in the response");
        let rule_ids = read_config(logger.clone(), &agent_restricted_read, version, canister_id).await;

        info!(&logger, "Call 4. Inspect the metadata of a rule before its disclosure. Some metadata fields should be hidden");
        let rule_metadata = read_rule(logger.clone(), &agent_restricted_read, &rule_ids[2], canister_id).await;
        assert!(rule_metadata.rule_raw.is_none());
        assert!(rule_metadata.description.is_none());

        info!(&logger, "Call 5. Disclose two rules linked to one incident");
        let incident_id = "b97730ac-4879-47f2-9fea-daf20b8d4b64".to_string();
        disclose_incident(logger.clone(), &agent_full_access, incident_id, canister_id).await;

        info!(&logger, "Call 6. Read config by non-privileged user again. Now rules related to the disclosed incident are fully visible");
        let _ = read_config(logger.clone(), &agent_restricted_read, version, canister_id).await;

        info!(&logger, "Call 7. Add another config (version = 3) with one newly added rule, and one remove rule");
        add_config_2(logger.clone(), &agent_full_access, canister_id).await;

        info!(&logger, "Call 8. Read config by privileged user (FullAccess or FullRead caller level). Response will expose rules/descriptions in their full form");
        let version = 3;
        let _ = read_config(logger.clone(), &agent_full_access, version, canister_id).await;

        info!(&logger, "Call 9. Inspect the metadata of the removed rule. All metadata fields should be visible, including versions when the rule was added/removed");
        let rule_metadata = read_rule(logger.clone(), &agent_restricted_read, &rule_ids[2], canister_id).await;
        assert!(rule_metadata.rule_raw.is_some());
        assert!(rule_metadata.description.is_some());
        assert_eq!(rule_metadata.added_in_version, 2);
        assert_eq!(rule_metadata.removed_in_version, Some(3));
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
    // Note two rules (indices = [0, 2]) are linked to the same incident_id_1
    // RuleIds are generated randomly on the canister side
    let rule_1 = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: Some(r"^(method_1)$".to_string()),
        request_type: Some(RequestType::Call),
        limit: "1req/s".to_string(),
    };

    let rule_2 = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: Some(r"^(method_2)$".to_string()),
        request_type: Some(RequestType::Query),
        limit: "2req/s".to_string(),
    };

    let rule_3 = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: Some(r"^(method_3)$".to_string()),
        request_type: None,
        limit: "3req/s".to_string(),
    };

    let rule_4 = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: Some(r"^(method_4)$".to_string()),
        request_type: Some(RequestType::ReadState),
        limit: "4req/s".to_string(),
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
            InputRule {
                incident_id: "b97730ac-4879-47f2-9fea-daf20b8d4b64".to_string(),
                rule_raw: rule_3.to_bytes_json().unwrap(),
                description:
                    "Some vulnerability #1 discovered, temporarily rate-limiting the canister calls"
                        .to_string(),
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

async fn add_config_2(logger: Logger, agent: &Agent, canister_id: Principal) {
    // This config differs from config 1 by rule_3 at index = 2, see comment below.
    let rule_1 = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: Some(r"^(method_1)$".to_string()),
        request_type: Some(RequestType::Call),
        limit: "1req/s".to_string(),
    };

    let rule_2 = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: Some(r"^(method_2)$".to_string()),
        request_type: Some(RequestType::Query),
        limit: "2req/s".to_string(),
    };

    // only this rule is different from config_1
    let rule_3 = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: Some(r"^(method_33)$".to_string()),
        request_type: None,
        limit: "33req/s".to_string(),
    };

    let rule_4 = RateLimitRule {
        canister_id: Some(canister_id),
        subnet_id: None,
        methods_regex: Some(r"^(method_4)$".to_string()),
        request_type: Some(RequestType::ReadState),
        limit: "4req/s".to_string(),
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
        .update(&canister_id, "get_config")
        .with_arg(args)
        .call_and_wait()
        .await
        .expect("update call failed");

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
        .update(&canister_id, "get_rule_by_id")
        .with_arg(args)
        .call_and_wait()
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
