use candid::{Encode, Principal};
use ic_crypto_sha2::Sha256;
use ic_nns_test_utils::common::modify_wasm_bytes;
use rate_limit_canister_integration_tests::pocket_ic_helpers::{
    canister_call, get_installed_wasm_hash, install_rate_limit_canister_on_ii_subnet,
    setup_subnets_and_registry_canister,
};
use rate_limits_api::{
    AddConfigResponse, DiscloseRulesArg, DiscloseRulesResponse, GetConfigResponse,
    GetRulesByIncidentIdResponse, InitArg, InputConfig, InputRule, Version,
};

const PRINCIPAL_1: &str = "imx2d-dctwe-ircfz-emzus-bihdn-aoyzy-lkkdi-vi5vw-npnik-noxiy-mae";

const PRINCIPAL_2: &str = "rwlgt-iiaaa-aaaaa-aaaaa-cai";

// Test scenario:
// 0. Setup:
//    - Two system subnets: NNS and II
//    - Install the registry canister on the NNS subnet
//    - Install the rate-limit canister on the II subnet with an init payload containing PRINCIPAL_1 (permitting write operations to this principal)
// 1. Verify `inspect_message()` works correctly and unauthorized calls are rejected early in the pre-consensus phase:
//   1.a. As an anonymous principal, try executing the `add_config()` update call; assert the canister call is rejected
//   1.b. As an unauthorized principal, try executing `get_config()` query as an update call; assert this call is also rejected
// 2. As an authorized principal, execute the `add_config()` update call (add config with two rate-limit rules with different incident_ids)
// 3. As an authorized principal, execute `disclose_rules()` and disclose one of the two incidents
// 4. Upgrade the canister wasm code, also setting the authorized principal to PRINCIPAL_2 (PRINCIPAL_1 is now unauthorized)
//    All calls below will ensure data persistency in stable memory after the code upgrade and also that newly granted permissions to PRINCIPAL_2 and revoked ones from PRINCIPAL_1 are working
// 5. As an unauthorized principal, execute the `get_config()` query method; assert the config contains two rules, where one is hidden and one is visible
// 6. As an authorized principal, execute the `get_config()` query method as an update call; assert the config contains two rules, both fully visible
// 7. As an unauthorized principal, execute the `get_rules_by_incident_id()` query method for an undisclosed incident; assert the response contains one hidden rule

#[tokio::test]
async fn main() {
    // 0. Setup
    let authorized_principal = Principal::from_text(PRINCIPAL_1).unwrap();
    let initial_payload = InitArg {
        authorized_principal: Some(authorized_principal),
        registry_polling_period_secs: 1,
    };
    let pocket_ic = setup_subnets_and_registry_canister().await;
    let (canister_id, wasm) =
        install_rate_limit_canister_on_ii_subnet(&pocket_ic, initial_payload.clone()).await;

    // 1. Verify `inspect_message()` works correctly and unauthorized calls are rejected early in the pre-consensus phase:
    // 1.a. As an anonymous principal, try executing the `add_config()` update call; assert the canister call is rejected
    let incident_id_1 = "b97730ac-4879-47f2-9fea-daf20b8d4b64".to_string();
    let incident_id_2 = "389bbff8-bffa-4430-bb70-8ce1ea399c07".to_string();
    let input_config = Encode!(&InputConfig {
        schema_version: 2,
        rules: vec![
            InputRule {
                incident_id: incident_id_1.clone(),
                rule_raw: b"{\"a\": 1, \"b\": []}".to_vec(),
                description: "some verbose description of rule #1".to_string()
            },
            InputRule {
                incident_id: incident_id_2.clone(),
                rule_raw: b"{\"c\": 2, \"d\": {\"e\": []}}".to_vec(),
                description: "some verbose description of rule #2".to_string()
            }
        ],
    })
    .unwrap();

    let response: Result<(), String> = canister_call(
        &pocket_ic,
        "add_config",
        "update",
        canister_id,
        Principal::anonymous(),
        input_config.clone(),
    )
    .await;

    let err_msg = response.unwrap_err();
    assert!(err_msg.contains("message_inspection_failed: unauthorized caller"));

    // 1.b. As an unauthorized principal, try executing `get_config()` query as an update call; assert this call is also rejected
    let input_version = Encode!(&None::<Version>).unwrap();
    let response: Result<(), String> = canister_call(
        &pocket_ic,
        "get_config",
        "update",
        canister_id,
        Principal::from_text(PRINCIPAL_2).unwrap(),
        input_version,
    )
    .await;

    let err_msg = response.unwrap_err();
    assert!(
        err_msg.contains(
            "message_inspection_failed: method call is prohibited in the current context"
        )
    );

    // 2. As an authorized principal, execute the `add_config()` update call (add config with two rate-limit rules with different incident_ids)
    let response: AddConfigResponse = canister_call(
        &pocket_ic,
        "add_config",
        "update",
        canister_id,
        authorized_principal,
        input_config,
    )
    .await
    .unwrap();

    assert!(response.is_ok());

    // 3. As an authorized principal, execute `disclose_rules()` and disclose one of the two incidents
    let disclose_rules_arg =
        Encode!(&DiscloseRulesArg::IncidentIds(vec![incident_id_2.clone()])).unwrap();
    let response: DiscloseRulesResponse = canister_call(
        &pocket_ic,
        "disclose_rules",
        "update",
        canister_id,
        authorized_principal,
        disclose_rules_arg,
    )
    .await
    .unwrap();

    assert!(response.is_ok());

    // 4. Upgrade the canister wasm code, also setting the authorized principal to PRINCIPAL_2 (PRINCIPAL_1 is now unauthorized)
    let authorized_principal = Principal::from_text(PRINCIPAL_2).unwrap();
    let initial_payload = InitArg {
        authorized_principal: Some(authorized_principal),
        registry_polling_period_secs: 1,
    };
    let current_wasm_hash = get_installed_wasm_hash(&pocket_ic, canister_id).await;
    let new_wasm = modify_wasm_bytes(&wasm.clone().bytes(), 42);
    let new_wasm_hash = Sha256::hash(&new_wasm.clone());

    assert_ne!(current_wasm_hash, new_wasm_hash);

    pocket_ic
        .upgrade_canister(
            canister_id,
            new_wasm,
            Encode!(&initial_payload).unwrap(),
            None,
        )
        .await
        .unwrap();

    assert_eq!(
        get_installed_wasm_hash(&pocket_ic, canister_id).await,
        new_wasm_hash,
    );
    // 5. As an unauthorized principal, execute the `get_config()` query method
    // assert the config contains two rules, where one is hidden and one is visible
    let input_version = Encode!(&None::<Version>).unwrap();

    let response: GetConfigResponse = canister_call(
        &pocket_ic,
        "get_config",
        "query",
        canister_id,
        Principal::from_text(PRINCIPAL_1).unwrap(), // note now this principal is unauthorized
        input_version,
    )
    .await
    .unwrap();

    let config = response.unwrap().config;

    assert_eq!(config.schema_version, 2);
    assert!(config.is_redacted);
    let rules = config.rules;
    // A non-disclosed rule related to incident_1 is still hidden
    assert_eq!(rules[0].incident_id, incident_id_1);
    assert_eq!(rules[0].rule_raw, None);
    assert_eq!(rules[0].description, None);
    // A disclosed rule related to incident_2 is now visible
    assert_eq!(rules[1].incident_id, incident_id_2);
    assert_eq!(
        rules[1].rule_raw,
        Some(b"{\"c\": 2, \"d\": {\"e\": []}}".to_vec())
    );
    assert_eq!(
        rules[1].description,
        Some("some verbose description of rule #2".to_string())
    );
    // 6. As an authorized principal, execute the `get_config()` query method as an update call
    // assert the config contains two rules, both fully visible
    let input_version = Encode!(&Some(2)).unwrap();

    let response: GetConfigResponse = canister_call(
        &pocket_ic,
        "get_config",
        "update", // executed query as a replicate query call
        canister_id,
        authorized_principal,
        input_version,
    )
    .await
    .unwrap();

    let config = response.unwrap().config;
    assert_eq!(config.schema_version, 2);
    assert!(!config.is_redacted);
    let rules = config.rules;
    // Both rules are fully visible
    assert_eq!(rules[0].incident_id, incident_id_1);
    assert_eq!(rules[0].rule_raw, Some(b"{\"a\": 1, \"b\": []}".to_vec()));
    assert_eq!(
        rules[0].description,
        Some("some verbose description of rule #1".to_string())
    );
    assert_eq!(rules[1].incident_id, incident_id_2);
    assert_eq!(
        rules[1].rule_raw,
        Some(b"{\"c\": 2, \"d\": {\"e\": []}}".to_vec())
    );
    assert_eq!(
        rules[1].description,
        Some("some verbose description of rule #2".to_string())
    );
    // 7. As an unauthorized principal, execute the `get_rules_by_incident_id()` query method for an undisclosed incident
    // assert the response contains one hidden rule
    let response: GetRulesByIncidentIdResponse = canister_call(
        &pocket_ic,
        "get_rules_by_incident_id",
        "query",
        canister_id,
        Principal::from_text(PRINCIPAL_1).unwrap(), // note now this principal is unauthorized
        Encode!(&incident_id_1).unwrap(),
    )
    .await
    .unwrap();

    let rules = response.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].rule_raw, None);
    assert_eq!(rules[0].description, None);
}
