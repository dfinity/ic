use candid::Encode;
use common::{install_sns_wasm, set_up_state_machine_with_nns};
use ic_nns_constants::SNS_WASM_CANISTER_ID;
use ic_nns_test_utils::{
    common::{build_mainnet_sns_wasms_wasm, build_sns_wasms_wasm, NnsInitPayloadsBuilder},
    sns_wasm::{
        self, add_wasm, add_wasm_via_proposal, build_root_sns_wasm, get_wasm, get_wasm_metadata,
    },
    state_test_helpers,
};
use ic_sns_wasm::pb::v1::{
    add_wasm_response, get_wasm_metadata_response, GetWasmMetadataResponse, GetWasmResponse,
    MetadataSection, SnsWasmError,
};
use ic_state_machine_tests::StateMachine;

pub mod common;

#[test]
fn test_sns_wasms_can_be_added_via_nns_proposal() {
    let machine = set_up_state_machine_with_nns();

    let root_wasm = build_root_sns_wasm();
    let root_hash = root_wasm.sha256_hash();
    let root_wasm = add_wasm_via_proposal(&machine, root_wasm);

    let response = sns_wasm::get_wasm(&machine, SNS_WASM_CANISTER_ID, &root_hash);
    let sns_wasm = response.wasm.unwrap();
    assert_eq!(sns_wasm, root_wasm)
}

#[test]
fn test_add_wasm_cannot_be_called_directly() {
    let machine = set_up_state_machine_with_nns();

    let root_wasm = build_root_sns_wasm();
    let root_hash = root_wasm.sha256_hash();
    let response = add_wasm(&machine, SNS_WASM_CANISTER_ID, root_wasm, &root_hash);

    assert_eq!(
        response.result.unwrap(),
        add_wasm_response::Result::Error(SnsWasmError {
            message: "add_wasm can only be called by NNS Governance".into()
        })
    );
}

#[test]
fn test_add_wasm_can_be_called_directly_if_access_controls_are_disabled() {
    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = StateMachine::new();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .with_sns_wasm_access_controls(false)
        .build();

    let sns_wasm_canister_id = install_sns_wasm(&machine, &nns_init_payload);

    let root_wasm = build_root_sns_wasm();
    let root_hash = root_wasm.sha256_hash();
    let response = add_wasm(&machine, sns_wasm_canister_id, root_wasm, &root_hash);

    assert_eq!(
        response.result.unwrap(),
        add_wasm_response::Result::Hash(root_hash.to_vec())
    );
}

// TODO[NNS1-3289]: Remove this test. Alternatively, change it to check that the metadata is still
// there after an upgrade.
#[test]
fn test_metadata_migration() {
    use get_wasm_metadata_response::{Ok, Result};

    // Prepare a WASM module to be stored inside SNS-W. Make sure it has known metadata.
    let (root_hash, root_wasm, expected_metadata) = {
        use ic_wasm::{metadata, utils};

        let root_wasm = build_root_sns_wasm();
        let root_hash = root_wasm.sha256_hash();
        let wasm_module = utils::parse_wasm(&root_wasm.wasm, false).unwrap();

        let sections = metadata::list_metadata(&wasm_module);
        assert_eq!(
            sections,
            vec!["icp:public candid:service", "icp:public git_commit_id"]
        );

        // The following expected values for the metadata contents were obtained experimentally.
        let candid_service = metadata::get_metadata(&wasm_module, "candid:service")
            .unwrap()
            .to_vec();
        assert!(
            !candid_service.is_empty(),
            "Expected some bytes for candid:service, got none."
        );

        let git_commit_id = metadata::get_metadata(&wasm_module, "git_commit_id")
            .unwrap()
            .to_vec();
        assert!(
            !git_commit_id.is_empty(),
            "Expected some bytes for git_commit_id, got none."
        );

        let expected_metadata = vec![
            MetadataSection {
                visibility: Some("icp:public".to_string()),
                name: Some("candid:service".to_string()),
                contents: Some(candid_service),
            },
            MetadataSection {
                visibility: Some("icp:public".to_string()),
                name: Some("git_commit_id".to_string()),
                contents: Some(git_commit_id),
            },
        ];

        (root_hash, root_wasm, expected_metadata)
    };

    state_test_helpers::reduce_state_machine_logging_unless_env_set();
    let machine = StateMachine::new();

    let nns_init_payload = NnsInitPayloadsBuilder::new()
        .with_sns_dedicated_subnets(machine.get_subnet_ids())
        .with_sns_wasm_access_controls(false)
        .build();

    let mainnet_wasm = build_mainnet_sns_wasms_wasm();
    let sns_wasm_canister_id = machine
        .install_canister(
            mainnet_wasm.bytes(),
            Encode!(&nns_init_payload.sns_wasms.clone()).unwrap(),
            None,
        )
        .unwrap();

    // Add a WASM to the mainnet SNS-W.
    {
        let root_wasm = root_wasm.clone();
        let response = add_wasm(&machine, sns_wasm_canister_id, root_wasm, &root_hash);
        assert_eq!(
            response.result,
            Some(add_wasm_response::Result::Hash(root_hash.to_vec()))
        );
    }

    // Check tha the metadata is not yet available.
    {
        let response = get_wasm_metadata(&machine, sns_wasm_canister_id, &root_hash);
        assert_eq!(
            response,
            GetWasmMetadataResponse {
                result: Some(Result::Error(SnsWasmError {
                    message: "get_wasm_metadata is not implemented yet.".to_string(),
                })),
            }
        );
    }

    // Upgrade SNS-W; this should trigger the metadata migration.
    {
        let migration_wasm = build_sns_wasms_wasm();
        machine
            .upgrade_canister(sns_wasm_canister_id, migration_wasm.bytes(), vec![])
            .unwrap();
    }

    // Check that the metadata is now populated.
    {
        let response = get_wasm_metadata(&machine, sns_wasm_canister_id, &root_hash);
        let GetWasmMetadataResponse {
            result: Some(Result::Ok(Ok { sections })),
        } = response
        else {
            panic!(
                "Unexpected response from SnsW.get_wasm_metadata: {:?}",
                response
            );
        };
        assert_eq!(sections, expected_metadata);
    }

    // Check that the WASM can still be fetched. This is just a smoke check.
    {
        let response = get_wasm(&machine, sns_wasm_canister_id, &root_hash);
        assert_eq!(
            response,
            GetWasmResponse {
                wasm: Some(root_wasm),
            }
        );
    }
}
