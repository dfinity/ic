use candid::{Decode, Encode, Principal};
use ic_agent::{
    identity::{AnonymousIdentity, Secp256k1Identity},
    Agent, Identity,
};
use rate_limits_api::{
    AddConfigResponse, DiscloseRulesArg, DiscloseRulesResponse, GetConfigResponse,
    GetRuleByIdResponse, IncidentId, InputConfig, InputRule, RuleId, Version,
};

const RATE_LIMIT_CANISTER_ID: &str = "un4fu-tqaaa-aaaab-qadjq-cai";
const IC_DOMAIN: &str = "https://ic0.app";

use k256::elliptic_curve::SecretKey;

const TEST_PRIVATE_KEY: &str = "";

#[tokio::main]
async fn main() {
    let agent_full_access = create_agent(Secp256k1Identity::from_private_key(
        SecretKey::from_sec1_pem(TEST_PRIVATE_KEY).unwrap(),
    ))
    .await;

    let agent_restricted_read = create_agent(AnonymousIdentity {}).await;

    let canister_id = Principal::from_text(RATE_LIMIT_CANISTER_ID).unwrap();

    println!("Call 1. Add a new config (version = 2) containing some rules (FullAccess level of the caller is required)");
    add_config_1(&agent_full_access, canister_id).await;

    println!("Call 2. Read config by privileged user (FullAccess or FullRead caller level). Response will expose rules/descriptions in their full form");
    let version = 2;
    read_config(&agent_full_access, version, canister_id).await;

    println!("Call 3. Read config by non-privileged user (RestrictedRead level). Rules and descriptions are hidden in the response");
    read_config(&agent_restricted_read, version, canister_id).await;

    println!("Call 4. Disclose rules (two rules in this case) linked to a single incident");
    let incident_id = "incident_id_1".to_string();
    disclose_incident(&agent_full_access, incident_id, canister_id).await;

    println!("Call 5. Read config by non-privileged user again. Now rules related to the disclosed incident are fully shown");
    read_config(&agent_restricted_read, version, canister_id).await;

    println!("Call 6. Add another config (version = 3) with one newly added rule, one remove rule");
    add_config_2(&agent_full_access, canister_id).await;

    println!("Call 7. Inspect the metadata of the removed rule. All metadata fields should be visible, including versions when the rule was added/removed");
    let rule_id = "bc652fa8460f9456edb068ef4b8dd4761ebcf298478d00dac8ba3d4e491bf2ff".to_string();
    read_rule(&agent_restricted_read, rule_id, canister_id).await;
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
    let args = Encode!(&InputConfig {
        schema_version: 1,
        rules: vec![
            InputRule {
                incident_id: "incident_id_1".to_string(),
                rule_raw: b"{\"canister_id\": \"abcd-efgh\",\"limit\": \"10req/s\"}".to_vec(),
                description:
                    "Some vulnerability #1 discovered, temporarily rate-limiting the canister calls"
                        .to_string(),
            },
            InputRule {
                incident_id: "incident_id_2".to_string(),
                rule_raw: b"{\"subnet_id\": \"kjahd-zcsd\",\"limit\": \"5/s\"}".to_vec(),
                description: "Some vulnerability #2 discovered".to_string(),
            },
            InputRule {
                incident_id: "incident_id_1".to_string(),
                rule_raw: b"{\"canister_id\": \"klmo-pqfs\",\"limit\": \"20req/s\"}".to_vec(),
                description:
                    "Some vulnerability #1 discovered, temporarily rate-limiting the canister calls"
                        .to_string(),
            },
            InputRule {
                incident_id: "incident_id_3".to_string(),
                rule_raw: b"{\"canister_id\": \"oiaus-zmnxb\",\"limit\": \"20req/s\"}".to_vec(),
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
    // This config differs from config 1 by one rule at index = 2, see comment below.
    let args = Encode!(&InputConfig {
        schema_version: 1,
        rules: vec![
            InputRule {
                incident_id: "incident_id_1".to_string(),
                rule_raw: b"{\"canister_id\": \"abcd-efgh\",\"limit\": \"10req/s\"}".to_vec(),
                description:
                    "Some vulnerability #1 discovered, temporarily rate-limiting the canister calls"
                        .to_string(),
            },
            InputRule {
                incident_id: "incident_id_2".to_string(),
                rule_raw: b"{\"subnet_id\": \"kjahd-zcsd\",\"limit\": \"5/s\"}".to_vec(),
                description: "Some vulnerability #2 discovered".to_string(),
            },
            // Only this rule is different from config 1.
            // It means that the old rule is removed (not mutated) and this new rule is applied instead.
            InputRule {
                incident_id: "incident_id_4".to_string(),
                rule_raw: b"{\"canister_id\": \"aaaa-bbbb\",\"limit\": \"50req/s\"}".to_vec(),
                description: "Some vulnerability #4 discovered".to_string(),
            },
            InputRule {
                incident_id: "incident_id_3".to_string(),
                rule_raw: b"{\"canister_id\": \"oiaus-zmnxb\",\"limit\": \"20req/s\"}".to_vec(),
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

async fn read_config(agent: &Agent, version: Version, canister_id: Principal) {
    let args = Encode!(&Some(version)).unwrap();

    let response = agent
        .update(&canister_id, "get_config")
        .with_arg(args)
        .call_and_wait()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, GetConfigResponse).expect("failed to decode candid response");

    println!("Response to get_config() call: {decoded:#?}");
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

async fn read_rule(agent: &Agent, rule_id: RuleId, canister_id: Principal) {
    let args = Encode!(&rule_id).unwrap();

    let response = agent
        .update(&canister_id, "get_rule_by_id")
        .with_arg(args)
        .call_and_wait()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, GetRuleByIdResponse).unwrap();

    println!("Response to get_rule_by_id() call: {decoded:#?}");
}
