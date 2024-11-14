use candid::{Decode, Encode, Principal};
use ic_agent::{
    identity::{AnonymousIdentity, Secp256k1Identity},
    Agent, Identity,
};
use rate_limits_api::{
    v1::{RateLimitRule, RequestType},
    AddConfigResponse, DiscloseRulesArg, DiscloseRulesResponse, GetConfigResponse,
    GetRuleByIdResponse, IncidentId, InputConfig, InputRule, RuleId, Version,
};

const IC_DOMAIN: &str = "https://ic0.app";

use k256::elliptic_curve::SecretKey;

const TEST_PRIVATE_KEY: &str = "-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIBzyyJ32Kdjixx+ZJvNeUWsqAzSQZfLsOyXKgxc7aH9oAcGBSuBBAAK
oUQDQgAECWc6ZRn9bBP96RM1G6h8ZAtbryO65dKg6cw0Oij2XbnAlb6zSPhU+4hh
gc2Q0JiGrqKks1AVi+8wzmZ+2PQXXA==
-----END EC PRIVATE KEY-----";
// Corresponding principal: imx2d-dctwe-ircfz-emzus-bihdn-aoyzy-lkkdi-vi5vw-npnik-noxiy-mae

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let canister_id = Principal::from_text(args[1].clone())
        .expect("failed to parse canister_id from the command-line argument");

    let agent_full_access = create_agent(Secp256k1Identity::from_private_key(
        SecretKey::from_sec1_pem(TEST_PRIVATE_KEY).unwrap(),
    ))
    .await;

    let agent_restricted_read = create_agent(AnonymousIdentity {}).await;

    println!("Call 1. Add a new config (version = 2) containing some rules (FullAccess level of the caller is required)");
    add_config_1(&agent_full_access, canister_id).await;

    println!("Call 2. Read config by privileged user (FullAccess or FullRead caller level). Response will expose rules/descriptions in their full form");
    let version = 2;
    read_config(&agent_full_access, version, canister_id).await;

    println!("Call 3. Read config by non-privileged user (RestrictedRead level). Rules and descriptions are hidden in the response");
    let rule_ids = read_config(&agent_restricted_read, version, canister_id).await;

    println!("Call 4. Inspect the metadata of a rule before disclosure. Some metadata fields should be hidden");
    read_rule(&agent_restricted_read, &rule_ids[2], canister_id).await;

    println!("Call 5. Disclose rules (two rules in this case) linked to a single incident");
    let incident_id = "b97730ac-4879-47f2-9fea-daf20b8d4b64".to_string();
    disclose_incident(&agent_full_access, incident_id, canister_id).await;

    println!("Call 6. Read config by non-privileged user again. Now rules related to the disclosed incident are fully visible");
    let _ = read_config(&agent_restricted_read, version, canister_id).await;

    println!("Call 7. Add another config (version = 3) with one newly added rule, one remove rule");
    add_config_2(&agent_full_access, canister_id).await;

    println!("Call 8. Read config by privileged user (FullAccess or FullRead caller level). Response will expose rules/descriptions in their full form");
    let version = 3;
    let _ = read_config(&agent_full_access, version, canister_id).await;

    println!("Call 9. Inspect the metadata of the removed rule. All metadata fields should be visible, including versions when the rule was added/removed");
    read_rule(&agent_restricted_read, &rule_ids[2], canister_id).await;
}

async fn create_agent<I: Identity + 'static>(identity: I) -> Agent {
    let agent = Agent::builder()
        .with_url(IC_DOMAIN)
        .with_identity(identity)
        .build()
        .expect("failed to build the agent");
    agent.fetch_root_key().await.unwrap();
    agent
}

async fn add_config_1(agent: &Agent, canister_id: Principal) {
    // Note two rules (indices = [0, 2]) are linked to the same incident_id_1
    // RuleIds are generated on the server side based on the hash(rule_raw + description)
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
            // incident_id for this rule is identical to rule[0]
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

    println!("Response to add_config() call: {decoded:#?}");
}

async fn add_config_2(agent: &Agent, canister_id: Principal) {
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

    println!("Response to add_config() call: {decoded:#?}");
}

async fn read_config(agent: &Agent, version: Version, canister_id: Principal) -> Vec<RuleId> {
    let args = Encode!(&Some(version)).unwrap();

    let response = agent
        .query(&canister_id, "get_config")
        .with_arg(args)
        .call()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, GetConfigResponse)
        .expect("failed to decode candid response")
        .unwrap();

    println!("Response to get_config() call: {}", decoded);

    decoded
        .config
        .rules
        .into_iter()
        .map(|rule| rule.id)
        .collect()
}

async fn disclose_incident(agent: &Agent, incident_id: IncidentId, canister_id: Principal) {
    let disclose_arg = DiscloseRulesArg::IncidentIds(vec![incident_id]);
    let args = Encode!(&disclose_arg).unwrap();

    let response = agent
        .update(&canister_id, "disclose_rules")
        .with_arg(args)
        .call_and_wait()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, DiscloseRulesResponse).unwrap();

    println!("Response to disclose_rules() call: {decoded:#?}");
}

async fn read_rule(agent: &Agent, rule_id: &RuleId, canister_id: Principal) {
    let args = Encode!(rule_id).unwrap();

    let response = agent
        .query(&canister_id, "get_rule_by_id")
        .with_arg(args)
        .call()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, GetRuleByIdResponse).unwrap().unwrap();

    println!("Response to get_rule_by_id() call: {decoded}");
}
