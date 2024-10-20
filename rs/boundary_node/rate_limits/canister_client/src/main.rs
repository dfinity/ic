use candid::{Decode, Encode, Principal};
use ic_agent::{
    identity::{AnonymousIdentity, Secp256k1Identity},
    Agent,
};
use rate_limits_api::{
    AddConfigResponse, DiscloseRulesArg, DiscloseRulesResponse, GetConfigResponse,
    GetRuleByIdResponse, InputConfig, InputRule,
};

const RATE_LIMIT_CANISTER_ID: &str = "ud6i4-iaaaa-aaaab-qadiq-cai";
const IC_DOMAIN: &str = "https://ic0.app";

use k256::elliptic_curve::SecretKey;

const TEST_PRIVATE_KEY: &str = "-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIBzyyJ32Kdjixx+ZJvNeUWsqAzSQZfLsOyXKgxc7aH9oAcGBSuBBAAK
oUQDQgAECWc6ZRn9bBP96RM1G6h8ZAtbryO65dKg6cw0Oij2XbnAlb6zSPhU+4hh
gc2Q0JiGrqKks1AVi+8wzmZ+2PQXXA==
-----END EC PRIVATE KEY-----";

#[tokio::main]
async fn main() {
    let agent_authorized = Agent::builder()
        .with_url(IC_DOMAIN)
        .with_identity(AnonymousIdentity {})
        .build()
        .expect("failed to build the agent");
    agent_authorized.fetch_root_key().await.unwrap();

    let mut agent_unauthorized = Agent::builder()
        .with_url(IC_DOMAIN)
        .build()
        .expect("failed to build the agent");
    agent_unauthorized.set_identity(Secp256k1Identity::from_private_key(
        SecretKey::from_sec1_pem(TEST_PRIVATE_KEY).unwrap(),
    ));
    agent_unauthorized.fetch_root_key().await.unwrap();

    let canister_id = Principal::from_text(RATE_LIMIT_CANISTER_ID).unwrap();

    // Call 1: overwrite_config by authorized
    let args = Encode!(&InputConfig {
        schema_version: 1,
        rules: vec![
            InputRule {
                incident_id: "id1".to_string(),
                rule_raw: b"{\"canister_id\": 3}".to_vec(),
                description: "canister rate-limit".to_string(),
            },
            InputRule {
                incident_id: "id1".to_string(),
                rule_raw: b"{\"subnet_id\": 2}".to_vec(),
                description: "subnet rate-limit".to_string(),
            },
            InputRule {
                incident_id: "id3".to_string(),
                rule_raw: b"{\"subnet_id\": 3}".to_vec(),
                description: "another subnet rate-limit".to_string(),
            },
            InputRule {
                incident_id: "id6".to_string(),
                rule_raw: b"{\"subnet_id\": 34}".to_vec(),
                description: "another subnet rate-limit".to_string(),
            },
        ],
    })
    .unwrap();

    let result = agent_authorized
        .update(&canister_id, "add_config")
        .with_arg(args)
        .call_and_wait()
        .await
        .unwrap();

    let decoded = Decode!(&result, AddConfigResponse).unwrap();

    println!("add_config response: {decoded:#?}");

    // Call 2: get_config by unauthorized user
    let version = 2u64;
    let args = Encode!(&Some(version)).unwrap();

    let response = agent_unauthorized
        .update(&canister_id, "get_config")
        .with_arg(args)
        .call_and_wait()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, GetConfigResponse).expect("failed to decode candid response");

    println!("get_config response: {decoded:#?}");

    // Call 3: get_rule_by_id unauthorized
    let rule_id = "d2f84ec0331266ff19cf0c889b03794232905d39eaff88504ac47939890c8d38".to_string();
    let args = Encode!(&rule_id).unwrap();

    let response = agent_unauthorized
        .query(&canister_id, "get_rule_by_id")
        .with_arg(args)
        .call()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, GetRuleByIdResponse).unwrap();

    println!("get_rule_by_id response: {decoded:#?}");

    // Call 4: disclose_rules by authorized
    let disclose_arg = DiscloseRulesArg::RuleIds(vec![rule_id.clone()]);
    let args = Encode!(&disclose_arg).unwrap();

    let response = agent_authorized
        .update(&canister_id, "disclose_rules")
        .with_arg(args)
        .call_and_wait()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, DiscloseRulesResponse).unwrap();

    println!("disclose_rules response: {decoded:#?}");

    // Call 5: get_rule_by_id after disclose() for unauthorized
    let args = Encode!(&rule_id).unwrap();

    let response = agent_unauthorized
        .query(&canister_id, "get_rule_by_id")
        .with_arg(args)
        .call()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, GetRuleByIdResponse).unwrap();

    println!("get_rule_by_id response: {decoded:#?}");

    // Call 6: disclose_rules by authorized
    let disclose_arg = DiscloseRulesArg::IncidentIds(vec!["id2".to_string(), "id3".to_string()]);
    let args = Encode!(&disclose_arg).unwrap();

    let response = agent_authorized
        .update(&canister_id, "disclose_rules")
        .with_arg(args)
        .call_and_wait()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, DiscloseRulesResponse).unwrap();

    println!("disclose_rules response: {decoded:#?}");

    // Call 7: get_config by unauthorized user
    let version = 2u64;
    let args = Encode!(&Some(version)).unwrap();

    let response = agent_unauthorized
        .update(&canister_id, "get_config")
        .with_arg(args)
        .call_and_wait()
        .await
        .expect("update call failed");

    let decoded = Decode!(&response, GetConfigResponse).expect("failed to decode candid response");

    println!("get_config response: {decoded:#?}");
}
