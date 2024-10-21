use candid::{Decode, Encode, Principal};
use ic_agent::{
    identity::{AnonymousIdentity, Secp256k1Identity},
    Agent, Identity,
};
use rate_limits_api::{
    AddConfigResponse, DiscloseRulesArg, DiscloseRulesResponse, GetConfigResponse, IncidentId,
    InputConfig, InputRule, Version,
};

const RATE_LIMIT_CANISTER_ID: &str = "v3x57-gaaaa-aaaab-qadmq-cai";
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

    // Call 1. Add a new config containing some rules (FullAccess level of the caller is required)
    add_config_with_four_rules(&agent_full_access, canister_id).await;

    // Call 2. Read config by privileged user (FullAccess or FullRead caller level). Response will expose rules/descriptions in their full form.
    let version = 2;
    read_config(&agent_full_access, version, canister_id).await;

    // Call 3. Read config by non-privileged user (RestrictedRead). Rules/descriptions are hidden in response.
    read_config(&agent_restricted_read, version, canister_id).await;

    // Call 4. Disclose rules linked to one single incident.
    let incident_id = "incident_id_1".to_string();
    disclose_incident(&agent_full_access, incident_id, canister_id).await;

    // Call 5. Read config by non-privileged user again. Now rules related to the disclosed incident are shown in the full form.
    read_config(&agent_restricted_read, version, canister_id).await;
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

async fn add_config_with_four_rules(agent: &Agent, canister_id: Principal) {
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

    println!("Response to add_config(): {decoded:#?}");
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

    println!("Response to get_config(): {decoded:#?}");
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

    println!("Response to disclose_rules(): {decoded:#?}");
}
