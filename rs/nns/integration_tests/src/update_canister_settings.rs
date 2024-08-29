use candid::Nat;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_clients::canister_status::{DefiniteCanisterSettings, LogVisibility};
use ic_nns_constants::{LIFELINE_CANISTER_ID, REGISTRY_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_governance_api::pb::v1::{
    manage_neuron_response::Command,
    update_canister_settings::{
        CanisterSettings, Controllers, LogVisibility as GovernanceLogVisibility,
    },
    MakeProposalRequest, ProposalActionRequest, UpdateCanisterSettings,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    neuron_helpers::get_neuron_1,
    state_test_helpers::{
        get_canister_status, nns_governance_make_proposal, nns_wait_for_proposal_execution,
        setup_nns_canisters, state_machine_builder_for_nns_tests,
    },
};

fn test_update_canister_settings_proposal(
    target_canister_id: CanisterId,
    controller_canister_id: CanisterId,
) {
    // Step 1: Set up the NNS canisters and get the neuron.
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    let n1 = get_neuron_1();

    // Step 2: Define the target settings and make sure they are different from the current ones.
    let target_controllers = vec![
        controller_canister_id.get(),
        PrincipalId::new_user_test_id(1),
    ];
    let target_memory_allocation = 1u64 << 33;
    let target_compute_allocation = 10u64;
    let target_freezing_threshold = 100_000u64;
    let target_wasm_memory_limit = 1u64 << 32;
    let target_log_visibility = Some(LogVisibility::Public);
    let canister_settings = || -> DefiniteCanisterSettings {
        get_canister_status(
            &state_machine,
            controller_canister_id.get(),
            target_canister_id,
            CanisterId::ic_00(),
        )
        .unwrap()
        .settings
    };
    let original_settings = canister_settings();
    assert_ne!(original_settings.controllers, target_controllers);
    assert_ne!(
        original_settings.memory_allocation,
        Some(Nat::from(target_memory_allocation))
    );
    assert_ne!(
        original_settings.compute_allocation,
        Some(Nat::from(target_compute_allocation))
    );
    assert_ne!(
        original_settings.freezing_threshold,
        Some(Nat::from(target_freezing_threshold))
    );
    assert_ne!(
        original_settings.wasm_memory_limit,
        Some(Nat::from(target_wasm_memory_limit))
    );
    assert_ne!(original_settings.log_visibility, target_log_visibility);

    // Step 3: Make a proposal to update settings of the registry canister and make sure the
    // proposal execution succeeds.
    let propose_response = nns_governance_make_proposal(
        &state_machine,
        n1.principal_id,
        n1.neuron_id,
        &MakeProposalRequest {
            title: Some("Update canister settings".to_string()),
            action: Some(ProposalActionRequest::UpdateCanisterSettings(
                UpdateCanisterSettings {
                    canister_id: Some(target_canister_id.get()),
                    settings: Some(CanisterSettings {
                        controllers: Some(Controllers {
                            controllers: target_controllers.clone(),
                        }),
                        memory_allocation: Some(target_memory_allocation),
                        compute_allocation: Some(target_compute_allocation),
                        freezing_threshold: Some(target_freezing_threshold),
                        wasm_memory_limit: Some(target_wasm_memory_limit),
                        log_visibility: Some(GovernanceLogVisibility::Public as i32),
                    }),
                },
            )),
            ..Default::default()
        },
    );
    let proposal_id = match propose_response.command.unwrap() {
        Command::MakeProposal(response) => response.proposal_id.unwrap(),
        _ => panic!("Propose didn't return MakeProposal"),
    };
    nns_wait_for_proposal_execution(&state_machine, proposal_id.id);

    // Step 4: Make sure the settings have been updated.
    let updated_settings = canister_settings();
    assert_eq!(updated_settings.controllers, target_controllers);
    assert_eq!(
        updated_settings.memory_allocation,
        Some(Nat::from(target_memory_allocation))
    );
    assert_eq!(
        updated_settings.compute_allocation,
        Some(Nat::from(target_compute_allocation))
    );
    assert_eq!(
        updated_settings.freezing_threshold,
        Some(Nat::from(target_freezing_threshold))
    );
    assert_eq!(
        updated_settings.wasm_memory_limit,
        Some(Nat::from(target_wasm_memory_limit))
    );
    assert_eq!(updated_settings.log_visibility, target_log_visibility);
}

#[test]
fn test_update_canister_settings_proposal_non_root() {
    test_update_canister_settings_proposal(REGISTRY_CANISTER_ID, ROOT_CANISTER_ID);
}

#[test]
fn test_update_canister_settings_proposal_root() {
    test_update_canister_settings_proposal(ROOT_CANISTER_ID, LIFELINE_CANISTER_ID);
}
