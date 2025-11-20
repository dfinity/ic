use crate::pb::v1::{ExecuteNnsFunction, NnsFunction};
use crate::proposals::execute_nns_function::ValidExecuteNnsFunction;

#[test]
fn test_execute_nns_function_try_from_errors() {
    let test_execute_nns_function_try_from_error =
        |execute_nns_function: ExecuteNnsFunction, error_message: String| {
            // Test that TryFrom fails with the expected error message
            let result = ValidExecuteNnsFunction::try_from(execute_nns_function);
            let err = result.unwrap_err();
            assert!(
                err.contains(&error_message),
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
