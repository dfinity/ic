use crate::{
    pb::v1::{ExecuteNnsFunction, NnsFunction},
    proposals::{
        ValidProposalAction,
        execute_nns_function::{ValidExecuteNnsFunction, ValidNnsFunction},
    },
    test_utils::{ExpectedCallCanisterMethodCallArguments, MockEnvironment},
};
use candid::{Decode, Encode};
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_management_canister_types_private::{CanisterMetadataRequest, CanisterMetadataResponse};
use ic_nervous_system_root::change_canister::AddCanisterRequest;
use ic_nns_constants::{BITCOIN_MAINNET_CANISTER_ID, CYCLES_MINTING_CANISTER_ID};
use ic_nns_governance_api::{
    SelfDescribingValue,
    bitcoin::{BitcoinNetwork, BitcoinSetConfigProposal},
    subnet_rental::{RentalConditionId, SubnetRentalRequest},
};
use ic_nns_handler_lifeline_interface::HardResetNnsRootToVersionPayload;
use ic_sns_wasm::pb::v1::{AddWasmRequest, SnsCanisterType, SnsWasm};
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

// This tests a "normal" NNS function where the payload is translated through a candid file fetched
// by the `canister_metadata` method on the management canister.
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
            "Add".to_string() => SelfDescribingValue::from("application"),
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
            "canister_id".to_string() => SelfDescribingValue::from(target_canister.to_string()),
            "sender_canister_version".to_string() => SelfDescribingValue::from(42_u64),
        })
    );
}

#[tokio::test]
async fn test_to_self_describing_bitcoin_set_config() {
    let bitcoin_payload = vec![1, 2, 3, 4, 5];
    let arg = BitcoinSetConfigProposal {
        network: BitcoinNetwork::Mainnet,
        payload: bitcoin_payload.clone(),
    };
    let payload = Encode!(&arg).unwrap();

    let execute_nns_function = ValidExecuteNnsFunction {
        nns_function: ValidNnsFunction::BitcoinSetConfig,
        payload,
    };

    // No canister_metadata call expected - BitcoinSetConfig uses static conversion.
    let env = Arc::new(MockEnvironment::new(vec![], 0));

    let proposal_action = ValidProposalAction::ExecuteNnsFunction(execute_nns_function);
    let result = proposal_action.to_self_describing(env).await.unwrap();

    assert_eq!(result.type_name, "Set Bitcoin Config");
    assert!(
        result
            .type_description
            .contains("Set the configuration of the underlying Bitcoin Canister")
    );
    assert_eq!(
        SelfDescribingValue::from(result.value.unwrap()),
        SelfDescribingValue::Map(hashmap! {
            "canister_id".to_string() => SelfDescribingValue::from(BITCOIN_MAINNET_CANISTER_ID.to_string()),
            "method_name".to_string() => SelfDescribingValue::from("set_config"),
            "payload".to_string() => SelfDescribingValue::from(bitcoin_payload),
        })
    );
}

#[tokio::test]
async fn test_to_self_describing_subnet_rental_request() {
    let user = PrincipalId::new_user_test_id(123);
    let rental_condition_id = RentalConditionId::App13CH;

    let arg = SubnetRentalRequest {
        user,
        rental_condition_id,
    };
    let payload = Encode!(&arg).unwrap();

    let execute_nns_function = ValidExecuteNnsFunction {
        nns_function: ValidNnsFunction::SubnetRentalRequest,
        payload,
    };

    // No canister_metadata call expected - SubnetRentalRequest uses static conversion.
    let env = Arc::new(MockEnvironment::new(vec![], 0));

    let proposal_action = ValidProposalAction::ExecuteNnsFunction(execute_nns_function);
    let result = proposal_action.to_self_describing(env).await.unwrap();

    assert_eq!(result.type_name, "Subnet Rental Request");
    assert!(
        result
            .type_description
            .contains("Rent a subnet on the Internet Computer")
    );
    assert_eq!(
        SelfDescribingValue::from(result.value.unwrap()),
        SelfDescribingValue::Map(hashmap! {
            "user".to_string() => SelfDescribingValue::Text(user.to_string()),
            "rental_condition_id".to_string() => SelfDescribingValue::Text("App13CH".to_string()),
        })
    );
}

#[tokio::test]
async fn test_to_self_describing_add_sns_wasm() {
    let wasm_bytes = vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0];
    let canister_type = SnsCanisterType::Root as i32;
    let hash = vec![1, 2, 3, 4];

    let arg = AddWasmRequest {
        wasm: Some(SnsWasm {
            wasm: wasm_bytes.clone(),
            canister_type,
            proposal_id: None, // Will be set by the NNS function
        }),
        hash: hash.clone(),
        skip_update_latest_version: Some(false),
    };
    let payload = Encode!(&arg).unwrap();

    let execute_nns_function = ValidExecuteNnsFunction {
        nns_function: ValidNnsFunction::AddSnsWasm,
        payload,
    };

    // No canister_metadata call expected - AddSnsWasm uses static conversion.
    let env = Arc::new(MockEnvironment::new(vec![], 0));

    let proposal_action = ValidProposalAction::ExecuteNnsFunction(execute_nns_function);
    let result = proposal_action.to_self_describing(env).await.unwrap();

    assert_eq!(
        SelfDescribingValue::from(result.value.unwrap()),
        SelfDescribingValue::Map(hashmap! {
            "wasm".to_string() => SelfDescribingValue::Map(hashmap! {
                "wasm_hash".to_string() => SelfDescribingValue::from(Sha256::hash(&wasm_bytes).to_vec()),
                "canister_type".to_string() => SelfDescribingValue::from("Root"),
            }),
            "hash".to_string() => SelfDescribingValue::from(hash),
            "skip_update_latest_version".to_string() => SelfDescribingValue::from(false),
        })
    );
}

#[test]
fn test_re_encode_payload_to_target_canister_sets_proposal_id_for_add_wasm() {
    let proposal_id = 42;
    let wasm = vec![1, 2, 3];
    let canister_type = 3;
    let hash = vec![1, 2, 3, 4];
    let payload = Encode!(&AddWasmRequest {
        wasm: Some(SnsWasm {
            proposal_id: None,
            wasm: wasm.clone(),
            canister_type,
        }),
        hash: hash.clone(),
        skip_update_latest_version: Some(false),
    })
    .unwrap();

    let execute_nns_function = ValidExecuteNnsFunction {
        nns_function: ValidNnsFunction::AddSnsWasm,
        payload,
    };

    let effective_payload = execute_nns_function
        .re_encode_payload_to_target_canister(proposal_id, 0)
        .unwrap();

    let decoded = Decode!(&effective_payload, AddWasmRequest).unwrap();
    assert_eq!(
        decoded,
        AddWasmRequest {
            wasm: Some(SnsWasm {
                proposal_id: Some(proposal_id), // The proposal_id should be set
                wasm,
                canister_type
            }),
            hash,
            skip_update_latest_version: Some(false),
        }
    );
}

#[test]
fn test_re_encode_payload_to_target_canister_overrides_proposal_id_for_add_wasm() {
    let proposal_id = 42;
    let payload = Encode!(&AddWasmRequest {
        wasm: Some(SnsWasm {
            proposal_id: Some(proposal_id - 1),
            ..SnsWasm::default()
        }),
        ..AddWasmRequest::default()
    })
    .unwrap();

    let execute_nns_function = ValidExecuteNnsFunction {
        nns_function: ValidNnsFunction::AddSnsWasm,
        payload,
    };

    let effective_payload = execute_nns_function
        .re_encode_payload_to_target_canister(proposal_id, 0)
        .unwrap();

    let decoded = Decode!(&effective_payload, AddWasmRequest).unwrap();
    assert_eq!(decoded.wasm.unwrap().proposal_id.unwrap(), proposal_id);
}

#[tokio::test]
async fn test_to_self_describing_nns_canister_install() {
    let root_candid =
        std::fs::read_to_string("rs/nns/handlers/root/impl/canister/root.did").unwrap();

    let wasm_module = vec![0_u8, 0x61, 0x73, 0x6D, 1_u8, 0_u8, 0_u8, 0_u8];
    let arg = vec![1_u8, 2_u8, 3_u8];

    let request = AddCanisterRequest {
        name: "test-canister".to_string(),
        wasm_module: wasm_module.clone(),
        arg: arg.clone(),
        initial_cycles: 1_000_000_000_000_u64,
        compute_allocation: None,
        memory_allocation: None,
    };
    let payload = Encode!(&request).unwrap();

    let execute_nns_function = ValidExecuteNnsFunction {
        nns_function: ValidNnsFunction::NnsCanisterInstall,
        payload,
    };

    let metadata_request = CanisterMetadataRequest::new(
        ic_nns_constants::ROOT_CANISTER_ID,
        "candid:service".to_string(),
    );
    let metadata_response = CanisterMetadataResponse::new(root_candid.as_bytes().to_vec());

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
        0_u64,
    ));

    let proposal_action = ValidProposalAction::ExecuteNnsFunction(execute_nns_function);
    let result = proposal_action.to_self_describing(env).await.unwrap();

    let wasm_hash = Sha256::hash(&wasm_module).to_vec();
    let arg_hash = Sha256::hash(&arg).to_vec();

    assert_eq!(
        SelfDescribingValue::from(result.value.unwrap()),
        SelfDescribingValue::Map(hashmap! {
            "wasm_module_hash".to_string() => SelfDescribingValue::from(wasm_hash),
            "arg_hash".to_string() => SelfDescribingValue::from(arg_hash),
            "initial_cycles".to_string() => SelfDescribingValue::from(1_000_000_000_000_u64),
            "name".to_string() => SelfDescribingValue::from("test-canister"),
            "memory_allocation".to_string() => SelfDescribingValue::Null,
            "compute_allocation".to_string() => SelfDescribingValue::Null,
        })
    );
}

#[tokio::test]
async fn test_to_self_describing_hard_reset_nns_root_to_version() {
    let lifeline_candid =
        std::fs::read_to_string("rs/nns/handlers/lifeline/impl/lifeline.did").unwrap();

    let wasm_module = vec![0_u8, 0x61, 0x73, 0x6D, 1_u8, 0_u8, 0_u8, 0_u8];
    let init_arg = vec![4_u8, 5_u8, 6_u8];

    let request = HardResetNnsRootToVersionPayload {
        wasm_module: wasm_module.clone(),
        init_arg: init_arg.clone(),
    };
    let payload = Encode!(&request).unwrap();

    let execute_nns_function = ValidExecuteNnsFunction {
        nns_function: ValidNnsFunction::HardResetNnsRootToVersion,
        payload,
    };

    let metadata_request = CanisterMetadataRequest::new(
        ic_nns_constants::LIFELINE_CANISTER_ID,
        "candid:service".to_string(),
    );
    let metadata_response = CanisterMetadataResponse::new(lifeline_candid.as_bytes().to_vec());

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
        0_u64,
    ));

    let proposal_action = ValidProposalAction::ExecuteNnsFunction(execute_nns_function);
    let result = proposal_action.to_self_describing(env).await.unwrap();

    let wasm_hash = Sha256::hash(&wasm_module).to_vec();
    let init_arg_hash = Sha256::hash(&init_arg).to_vec();

    assert_eq!(
        SelfDescribingValue::from(result.value.unwrap()),
        SelfDescribingValue::Map(hashmap! {
            "wasm_module_hash".to_string() => SelfDescribingValue::from(wasm_hash),
            "init_arg_hash".to_string() => SelfDescribingValue::from(init_arg_hash),
        })
    );
}
