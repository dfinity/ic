use crate::{
    pb::v1::{ExecuteNnsFunction, NnsFunction},
    proposals::{
        ValidProposalAction,
        execute_nns_function::{ValidExecuteNnsFunction, ValidNnsFunction},
    },
    test_utils::{ExpectedCallCanisterMethodCallArguments, MockEnvironment},
};
use candid::{Encode, Nat};
use ic_base_types::CanisterId;
use ic_management_canister_types_private::{CanisterMetadataRequest, CanisterMetadataResponse};
use ic_nns_constants::CYCLES_MINTING_CANISTER_ID;
use ic_nns_governance_api::SelfDescribingValue;
use maplit::hashmap;
use std::sync::Arc;

#[test]
fn test_execute_nns_function_try_from_errors() {
    let test_execute_nns_function_try_from_error =
        |execute_nns_function: ExecuteNnsFunction, error_message: String| {
            // Test that TryFrom fails with the expected error message
            let result = ValidExecuteNnsFunction::try_from(execute_nns_function);
            let err = result.unwrap_err();
            assert!(
                err.error_message.contains(&error_message),
                "Expected error message to contain '{}', but got '{}'",
                error_message,
                err
            );
        };

    // Test cases that should fail during TryFrom
    let try_from_error_test_cases = vec![
        (
            ExecuteNnsFunction {
                nns_function: i32::MAX,
                payload: vec![],
            },
            "Invalid NnsFunction id: 2147483647".to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::IcpXdrConversionRate as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_ICP_XDR_CONVERSION_RATE is obsolete as conversion rates are now \
            provided by the exchange rate canister automatically."
                .to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::UpdateAllowedPrincipals as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_UPDATE_ALLOWED_PRINCIPALS is only used for the old SNS initialization \
            mechanism, which is now obsolete. Use CREATE_SERVICE_NERVOUS_SYSTEM instead."
                .to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::UpdateApiBoundaryNodesVersion as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_UPDATE_API_BOUNDARY_NODES_VERSION is obsolete. Use \
            NNS_FUNCTION_DEPLOY_GUESTOS_TO_SOME_API_BOUNDARY_NODES instead."
                .to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::UpdateUnassignedNodesConfig as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_UPDATE_UNASSIGNED_NODES_CONFIG is obsolete. Use \
            NNS_FUNCTION_DEPLOY_GUESTOS_TO_ALL_UNASSIGNED_NODES/NNS_FUNCTION_UPDATE_SSH_READONLY_ACCESS_FOR_ALL_UNASSIGNED_NODES \
            instead."
                .to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::UpdateElectedHostosVersions as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_UPDATE_ELECTED_HOSTOS_VERSIONS is obsolete. Use \
            NNS_FUNCTION_REVISE_ELECTED_HOSTOS_VERSIONS instead."
                .to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::UpdateNodesHostosVersion as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_UPDATE_NODES_HOSTOS_VERSION is obsolete. Use \
            NNS_FUNCTION_DEPLOY_HOSTOS_TO_SOME_NODES instead."
                .to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::NnsCanisterUpgrade as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_NNS_CANISTER_UPGRADE is obsolete. Use InstallCode instead."
                .to_string(),
        ),
        (
            ExecuteNnsFunction {
                nns_function: NnsFunction::NnsRootUpgrade as i32,
                payload: vec![],
            },
            "NNS_FUNCTION_NNS_ROOT_UPGRADE is obsolete. Use InstallCode instead."
                .to_string(),
        ),
    ];

    for (execute_nns_function, error_message) in try_from_error_test_cases {
        test_execute_nns_function_try_from_error(execute_nns_function, error_message);
    }
}

#[tokio::test]
async fn test_to_self_describing_update_subnet_type() {
    // Minimal CMC candid file with only update_subnet_type method
    let cmc_candid = r#"
type UpdateSubnetTypeArgs = variant {
  Add : text;
  Remove : text;
};

service : {
  update_subnet_type : (UpdateSubnetTypeArgs) -> ();
}
"#;

    // Create the UpdateSubnetTypeArgs::Add variant
    #[derive(candid::CandidType)]
    #[allow(dead_code)]
    enum UpdateSubnetTypeArgs {
        Add(String),
        Remove(String),
    }

    let arg = UpdateSubnetTypeArgs::Add("application".to_string());
    let payload = Encode!(&arg).unwrap();

    let execute_nns_function = ValidExecuteNnsFunction {
        nns_function: ValidNnsFunction::UpdateSubnetType,
        payload,
    };

    // Mock the canister_metadata call
    let metadata_request =
        CanisterMetadataRequest::new(CYCLES_MINTING_CANISTER_ID, "candid:service".to_string());
    let metadata_response = CanisterMetadataResponse::new(cmc_candid.as_bytes().to_vec());

    let expected_metadata_call = ExpectedCallCanisterMethodCallArguments::new(
        CanisterId::ic_00(),
        "canister_metadata",
        Encode!(&metadata_request).unwrap(),
    );

    let env = Arc::new(MockEnvironment::new(
        vec![(
            expected_metadata_call,
            Ok(Encode!(&metadata_response).unwrap()),
        )],
        0,
    ));

    // Test through ValidProposalAction::to_self_describing
    let proposal_action = ValidProposalAction::ExecuteNnsFunction(execute_nns_function);
    let result = proposal_action.to_self_describing(env).await.unwrap();

    // Verify the type name and description
    assert_eq!(result.type_name, "Update Subnet Type");
    assert!(
        result
            .type_description
            .contains("Add or remove a subnet type")
    );

    // Verify the value
    let self_describing_value = SelfDescribingValue::from(result.value.unwrap());
    assert_eq!(
        self_describing_value,
        SelfDescribingValue::Map(hashmap! {
            "Add".to_string() => SelfDescribingValue::Text("application".to_string()),
        })
    );
}

#[tokio::test]
async fn test_to_self_describing_uninstall_code() {
    // Create the uninstall_code_args payload
    #[derive(candid::CandidType)]
    struct UninstallCodeArgs {
        canister_id: CanisterId,
        sender_canister_version: Option<u64>,
    }

    let target_canister = CanisterId::from_u64(123);
    let arg = UninstallCodeArgs {
        canister_id: target_canister,
        sender_canister_version: Some(42),
    };
    let payload = Encode!(&arg).unwrap();

    let execute_nns_function = ValidExecuteNnsFunction {
        nns_function: ValidNnsFunction::UninstallCode,
        payload,
    };

    // No canister_metadata call expected a hard-coded DID file is used instead.
    let env = Arc::new(MockEnvironment::new(vec![], 0));

    let proposal_action = ValidProposalAction::ExecuteNnsFunction(execute_nns_function);
    let result = proposal_action.to_self_describing(env).await.unwrap();

    assert_eq!(result.type_name, "Uninstall Code");
    assert!(
        result
            .type_description
            .contains("Uninstall code of a canister")
    );
    assert_eq!(
        SelfDescribingValue::from(result.value.unwrap()),
        SelfDescribingValue::Map(hashmap! {
            "canister_id".to_string() => SelfDescribingValue::Text(target_canister.to_string()),
            "sender_canister_version".to_string() => SelfDescribingValue::Array(vec![
                SelfDescribingValue::Nat(Nat::from(42_u64)),
            ]),
        })
    );
}
