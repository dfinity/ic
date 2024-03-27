// TODO(NNS1-2962) remove this file once it's published
use candid::{Decode, Encode, Principal};
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_integration_tests::{
    pocket_ic_helpers,
    pocket_ic_helpers::{
        add_wasm_via_nns_proposal, install_sns_directly_with_snsw_versions, sns, SnsTestCanisterIds,
    },
};
use ic_nns_governance::governance::ONE_MONTH_SECONDS;
use ic_nns_test_utils::sns_wasm::{
    build_governance_sns_wasm, build_ledger_sns_wasm, ensure_sns_wasm_gzipped,
};
use ic_sns_governance::pb::v1::{
    neuron::DissolveState, Neuron, NeuronPermission, NeuronPermissionType,
};
use ic_sns_test_utils::itest_helpers::SnsTestsInitPayloadBuilder;
use icrc_ledger_types::icrc::generic_metadata_value::MetadataValue;
use pocket_ic::WasmResult;
use std::{str::FromStr, string::ToString};

const DRAGGINZ_LOGO: &str =  "data:image/png;base64,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";

#[test]
fn test_dragginz_ledger_params_update_on_upgrade() {
    let pocket_ic = pocket_ic_helpers::pocket_ic_for_sns_tests_with_mainnet_versions();

    let sns_init_payload = SnsTestsInitPayloadBuilder::new()
        .with_initial_neurons(vec![Neuron {
            id: Some(sns::governance::new_sns_neuron_id(
                PrincipalId::new_user_test_id(1234),
                0,
            )),
            permissions: vec![NeuronPermission {
                principal: Some(PrincipalId::new_user_test_id(1234)),
                permission_type: NeuronPermissionType::all(),
            }],
            cached_neuron_stake_e8s: 1_000_000_000_000,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(ONE_MONTH_SECONDS * 7)),
            voting_power_percentage_multiplier: 100,
            ..Default::default()
        }])
        .build();

    let SnsTestCanisterIds {
        root_canister_id: _,
        governance_canister_id,
        ledger_canister_id,
        swap_canister_id: _,
        index_canister_id: _,
    } = install_sns_directly_with_snsw_versions(
        &pocket_ic,
        sns_init_payload,
        Some(SnsTestCanisterIds {
            root_canister_id: CanisterId::unchecked_from_principal(
                PrincipalId::from_str("zxeu2-7aaaa-aaaaq-aaafa-cai").unwrap(),
            ),
            governance_canister_id: CanisterId::unchecked_from_principal(
                PrincipalId::from_str("zqfso-syaaa-aaaaq-aaafq-cai").unwrap(),
            ),
            ledger_canister_id: CanisterId::unchecked_from_principal(
                PrincipalId::from_str("zfcdd-tqaaa-aaaaq-aaaga-cai").unwrap(),
            ),
            swap_canister_id: CanisterId::unchecked_from_principal(
                PrincipalId::from_str("zcdfx-6iaaa-aaaaq-aaagq-cai").unwrap(),
            ),
            index_canister_id: CanisterId::unchecked_from_principal(
                PrincipalId::from_str("zlaol-iaaaa-aaaaq-aaaha-cai").unwrap(),
            ),
        }),
    );

    assert_eq!(
        ledger_canister_id.get(),
        PrincipalId::from_str("zfcdd-tqaaa-aaaaq-aaaga-cai").unwrap()
    );

    let wasm = build_governance_sns_wasm();
    let wasm = ensure_sns_wasm_gzipped(wasm);
    let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
    assert_eq!(proposal_info.failure_reason, None);

    let wasm = build_ledger_sns_wasm();
    let wasm = ensure_sns_wasm_gzipped(wasm);
    let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
    assert_eq!(proposal_info.failure_reason, None);

    // Upgrade it
    sns::governance::propose_to_upgrade_sns_to_next_version_and_wait(
        &pocket_ic,
        governance_canister_id.get(),
    );

    sns::governance::propose_to_upgrade_sns_to_next_version_and_wait(
        &pocket_ic,
        governance_canister_id.get(),
    );

    fn decode_result_as_or_panic<T>(result: WasmResult) -> T
    where
        T: for<'a> candid::Deserialize<'a> + candid::CandidType,
    {
        let result = match result {
            WasmResult::Reply(reply) => reply,
            WasmResult::Reject(reject) => {
                panic!(
                    "could not decode reply because the call was rejected: {:?}",
                    reject
                )
            }
        };
        Decode!(&result, T).unwrap()
    }

    let token_name = pocket_ic
        .query_call(
            ledger_canister_id.get().0,
            Principal::anonymous(),
            "icrc1_name",
            Encode!().unwrap(),
        )
        .unwrap();
    let token_name = decode_result_as_or_panic::<String>(token_name);

    let token_symbol = pocket_ic
        .query_call(
            ledger_canister_id.get().0,
            Principal::anonymous(),
            "icrc1_symbol",
            Encode!().unwrap(),
        )
        .unwrap();
    let token_symbol = decode_result_as_or_panic::<String>(token_symbol);

    assert_eq!(token_name, "Draggin Karma Points");
    assert_eq!(token_symbol, "DKP");

    // Get metadata from both canisters
    let ledger_metadata = pocket_ic
        .query_call(
            ledger_canister_id.get().0,
            Principal::anonymous(),
            "icrc1_metadata",
            Encode!().unwrap(),
        )
        .unwrap();
    let ledger_metadata =
        decode_result_as_or_panic::<Vec<(String, MetadataValue)>>(ledger_metadata);

    let logo = ledger_metadata
        .into_iter()
        .find(|(key, _)| key == "icrc1:logo")
        .unwrap()
        .1;

    assert_eq!(logo, MetadataValue::Text(DRAGGINZ_LOGO.to_string()));
}

#[test]
fn test_non_dragginz_ledger_params_do_not_update_on_upgrade() {
    let pocket_ic = pocket_ic_helpers::pocket_ic_for_sns_tests_with_mainnet_versions();

    let sns_init_payload = SnsTestsInitPayloadBuilder::new()
        .with_initial_neurons(vec![Neuron {
            id: Some(sns::governance::new_sns_neuron_id(
                PrincipalId::new_user_test_id(1234),
                0,
            )),
            permissions: vec![NeuronPermission {
                principal: Some(PrincipalId::new_user_test_id(1234)),
                permission_type: NeuronPermissionType::all(),
            }],
            cached_neuron_stake_e8s: 1_000_000_000_000,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(ONE_MONTH_SECONDS * 7)),
            voting_power_percentage_multiplier: 100,
            ..Default::default()
        }])
        .build();

    let SnsTestCanisterIds {
        root_canister_id: _,
        governance_canister_id,
        ledger_canister_id,
        swap_canister_id: _,
        index_canister_id: _,
    } = install_sns_directly_with_snsw_versions(&pocket_ic, sns_init_payload, None);

    assert_ne!(
        ledger_canister_id.get(),
        PrincipalId::from_str("zfcdd-tqaaa-aaaaq-aaaga-cai").unwrap()
    );

    let wasm = build_governance_sns_wasm();
    let wasm = ensure_sns_wasm_gzipped(wasm);
    let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
    assert_eq!(proposal_info.failure_reason, None);

    let wasm = build_ledger_sns_wasm();
    let wasm = ensure_sns_wasm_gzipped(wasm);
    let proposal_info = add_wasm_via_nns_proposal(&pocket_ic, wasm).unwrap();
    assert_eq!(proposal_info.failure_reason, None);

    // Upgrade it
    sns::governance::propose_to_upgrade_sns_to_next_version_and_wait(
        &pocket_ic,
        governance_canister_id.get(),
    );

    sns::governance::propose_to_upgrade_sns_to_next_version_and_wait(
        &pocket_ic,
        governance_canister_id.get(),
    );

    fn decode_result_as_or_panic<T>(result: WasmResult) -> T
    where
        T: for<'a> candid::Deserialize<'a> + candid::CandidType,
    {
        let result = match result {
            WasmResult::Reply(reply) => reply,
            WasmResult::Reject(reject) => {
                panic!(
                    "could not decode reply because the call was rejected: {:?}",
                    reject
                )
            }
        };
        Decode!(&result, T).unwrap()
    }

    let token_name = pocket_ic
        .query_call(
            ledger_canister_id.get().0,
            Principal::anonymous(),
            "icrc1_name",
            Encode!().unwrap(),
        )
        .unwrap();
    let token_name = decode_result_as_or_panic::<String>(token_name);

    let token_symbol = pocket_ic
        .query_call(
            ledger_canister_id.get().0,
            Principal::anonymous(),
            "icrc1_symbol",
            Encode!().unwrap(),
        )
        .unwrap();
    let token_symbol = decode_result_as_or_panic::<String>(token_symbol);

    assert_ne!(token_name, "Draggin Karma Points");
    assert_ne!(token_symbol, "DKP");

    // Get metadata from both canisters
    let ledger_metadata = pocket_ic
        .query_call(
            ledger_canister_id.get().0,
            Principal::anonymous(),
            "icrc1_metadata",
            Encode!().unwrap(),
        )
        .unwrap();
    let ledger_metadata =
        decode_result_as_or_panic::<Vec<(String, MetadataValue)>>(ledger_metadata);

    let logo_option = ledger_metadata
        .into_iter()
        .find(|(key, _)| key == "icrc1:logo");

    assert_eq!(logo_option, None);
}
