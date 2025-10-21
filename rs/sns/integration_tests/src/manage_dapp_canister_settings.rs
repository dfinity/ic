use candid::Encode;
use canister_test::Wasm;
use ic_base_types::PrincipalId;
use ic_ledger_core::Tokens;
use ic_management_canister_types_private::CanisterSettingsArgsBuilder;
use ic_nervous_system_clients::canister_status::DefiniteCanisterSettingsArgs;
use ic_nervous_system_common::ONE_YEAR_SECONDS;
use ic_nns_test_utils::state_test_helpers::{
    create_canister, sns_claim_staked_neuron, sns_get_proposal, sns_make_proposal,
    sns_stake_neuron, sns_wait_for_proposal_executed_or_failed, sns_wait_for_proposal_execution,
};
use ic_sns_governance::pb::v1::{
    LogVisibility, ManageDappCanisterSettings, NervousSystemParameters, NeuronPermissionList,
    NeuronPermissionType, Proposal, proposal::Action,
};
use ic_sns_test_utils::{
    itest_helpers::SnsTestsInitPayloadBuilder,
    state_test_helpers::{
        setup_sns_canisters, sns_root_register_dapp_canisters, state_machine_builder_for_sns_tests,
    },
};
use lazy_static::lazy_static;
use tokio::time::Duration;

// The minimum WASM payload.
lazy_static! {
    pub static ref EMPTY_WASM: Vec<u8> = vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0];
}

#[test]
fn test_manage_dapp_canister_settings_successful() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    // Step 1.1: Boot up SNS with one user.
    let user = PrincipalId::new_user_test_id(0);
    let alloc = Tokens::from_tokens(1000).unwrap();

    let system_params = NervousSystemParameters {
        neuron_claimer_permissions: Some(NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        }),
        ..NervousSystemParameters::with_default_values()
    };

    // Step 1.2: Set up the SNS canisters.
    let sns_init_payload = SnsTestsInitPayloadBuilder::new()
        .with_ledger_account(user.0.into(), alloc)
        .with_nervous_system_parameters(system_params)
        .build();
    let canister_ids = setup_sns_canisters(&state_machine, sns_init_payload);

    // Step 1.3: Set up a Dapp canister.
    let dapp_canister_id = create_canister(
        &state_machine,
        Wasm::from_bytes(EMPTY_WASM.clone()),
        Some(Encode!().unwrap()),
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![canister_ids.root_canister_id.get()])
                .with_compute_allocation(50)
                .with_memory_allocation(1 << 30)
                .with_freezing_threshold(100_000)
                .with_reserved_cycles_limit(1_000_000_000_000)
                .with_log_visibility(ic_management_canister_types_private::LogVisibilityV2::Public)
                .with_wasm_memory_limit(1_000_000_000)
                .build(),
        ),
    );

    // Step 1.4: Set up a neuron for making proposals.
    sns_stake_neuron(
        &state_machine,
        canister_ids.governance_canister_id,
        canister_ids.ledger_canister_id,
        user,
        Tokens::from_tokens(1).unwrap(),
        1,
    );
    let neuron_id = sns_claim_staked_neuron(
        &state_machine,
        canister_ids.governance_canister_id,
        user,
        1,
        Some(ONE_YEAR_SECONDS as u32),
    );

    // Step 1.5: Register the Dapp canister.
    sns_root_register_dapp_canisters(
        &state_machine,
        canister_ids.root_canister_id,
        canister_ids.governance_canister_id,
        vec![dapp_canister_id],
    );

    // Step 1.6: Make sure the Dapp canister has the right settings.
    let status = state_machine
        .canister_status_as(canister_ids.root_canister_id.get(), dapp_canister_id)
        .unwrap()
        .unwrap();
    let dapp_settings: DefiniteCanisterSettingsArgs = status.settings().into();
    assert_eq!(
        dapp_settings,
        DefiniteCanisterSettingsArgs::new(
            vec![canister_ids.root_canister_id.get()],
            50,
            Some(1 << 30),
            100_000,
            Some(1_000_000_000),
            Some(0),
        ),
    );

    // Step 2: Make the ManageDappCanisterSettings and make sure it's executed.
    let proposal = Proposal {
        title: "Manage dapp canister settings".into(),
        action: Some(Action::ManageDappCanisterSettings(
            ManageDappCanisterSettings {
                canister_ids: vec![dapp_canister_id.get()],
                compute_allocation: Some(0),
                memory_allocation: Some(0),
                freezing_threshold: Some(0),
                reserved_cycles_limit: Some(0),
                log_visibility: Some(LogVisibility::Controllers as i32),
                wasm_memory_limit: Some(2_000_000_000),
                wasm_memory_threshold: Some(0),
            },
        )),
        ..Default::default()
    };
    let proposal_id = sns_make_proposal(
        &state_machine,
        canister_ids.governance_canister_id,
        user,
        neuron_id,
        proposal,
    )
    .unwrap();
    sns_wait_for_proposal_execution(
        &state_machine,
        canister_ids.governance_canister_id,
        proposal_id,
    );
    for _ in 1..100 {
        state_machine.advance_time(Duration::from_secs(1));
        state_machine.tick();
    }

    // Step 3: Verify that the Dapp canister settings have been changed.
    let status = state_machine
        .canister_status_as(canister_ids.root_canister_id.get(), dapp_canister_id)
        .unwrap()
        .unwrap();
    let dapp_settings: DefiniteCanisterSettingsArgs = status.settings().into();
    assert_eq!(
        dapp_settings,
        DefiniteCanisterSettingsArgs::new(
            vec![canister_ids.root_canister_id.get()],
            0,
            Some(0),
            0,
            Some(2_000_000_000),
            Some(0),
        ),
    );
}

#[test]
fn test_manage_dapp_canister_settings_failure() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    // Step 1.1: Boot up SNS with one user.
    let user = PrincipalId::new_user_test_id(0);
    let alloc = Tokens::from_tokens(1000).unwrap();

    let system_params = NervousSystemParameters {
        neuron_claimer_permissions: Some(NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        }),
        ..NervousSystemParameters::with_default_values()
    };

    // Step 1.2: Set up the SNS canisters.
    let sns_init_payload = SnsTestsInitPayloadBuilder::new()
        .with_ledger_account(user.0.into(), alloc)
        .with_nervous_system_parameters(system_params)
        .build();
    let canister_ids = setup_sns_canisters(&state_machine, sns_init_payload);

    // Step 1.3: Set up a Dapp canister.
    let dapp_canister_id = create_canister(
        &state_machine,
        Wasm::from_bytes(EMPTY_WASM.clone()),
        Some(Encode!().unwrap()),
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![canister_ids.root_canister_id.get()])
                .with_compute_allocation(50)
                .with_memory_allocation(1 << 30)
                .with_freezing_threshold(100_000)
                .with_reserved_cycles_limit(1_000_000_000_000)
                .with_wasm_memory_limit(1_000_000_000)
                .with_log_visibility(ic_management_canister_types_private::LogVisibilityV2::Public)
                .build(),
        ),
    );

    // Step 1.4: Set up a neuron for making proposals.
    sns_stake_neuron(
        &state_machine,
        canister_ids.governance_canister_id,
        canister_ids.ledger_canister_id,
        user,
        Tokens::from_tokens(1).unwrap(),
        1,
    );
    let neuron_id = sns_claim_staked_neuron(
        &state_machine,
        canister_ids.governance_canister_id,
        user,
        1,
        Some(ONE_YEAR_SECONDS as u32),
    );

    // Step 1.5: Make sure the Dapp canister has the right settings.
    let status = state_machine
        .canister_status_as(canister_ids.root_canister_id.get(), dapp_canister_id)
        .unwrap()
        .unwrap();
    let dapp_settings: DefiniteCanisterSettingsArgs = status.settings().into();
    assert_eq!(
        dapp_settings,
        DefiniteCanisterSettingsArgs::new(
            vec![canister_ids.root_canister_id.get()],
            50,
            Some(1 << 30),
            100_000,
            Some(1_000_000_000),
            Some(0),
        ),
    );

    // Step 1.6: Get the canister status of the ledger canister.
    let original_ledger_canister_status = state_machine
        .canister_status_as(
            canister_ids.root_canister_id.get(),
            canister_ids.ledger_canister_id,
        )
        .unwrap()
        .unwrap();

    // Step 2: Make the ManageDappCanisterSettings proposal but include the ledger canister in the
    // list of canisters.
    let proposal = Proposal {
        title: "Manage dapp canister settings".into(),
        action: Some(Action::ManageDappCanisterSettings(
            ManageDappCanisterSettings {
                canister_ids: vec![
                    dapp_canister_id.get(),
                    canister_ids.ledger_canister_id.get(),
                ],
                compute_allocation: Some(0),
                ..Default::default()
            },
        )),
        ..Default::default()
    };
    let proposal_id = sns_make_proposal(
        &state_machine,
        canister_ids.governance_canister_id,
        user,
        neuron_id,
        proposal,
    )
    .unwrap();
    sns_wait_for_proposal_executed_or_failed(
        &state_machine,
        canister_ids.governance_canister_id,
        proposal_id,
    );
    for _ in 1..100 {
        state_machine.advance_time(Duration::from_secs(1));
        state_machine.tick();
    }

    // Step 3.1 Verify that the proposal has failed with the right failure message.
    let proposal = sns_get_proposal(
        &state_machine,
        canister_ids.governance_canister_id,
        proposal_id,
    )
    .unwrap();
    let failure_reason = proposal.failure_reason.unwrap().error_message;
    assert!(failure_reason.contains("not registered dapp canisters"));
    assert!(failure_reason.contains(&canister_ids.ledger_canister_id.get().to_string()));

    // Step 3.2: Verify that the Dapp canister settings have not been changed.
    let dapp_canister_status = state_machine
        .canister_status_as(canister_ids.root_canister_id.get(), dapp_canister_id)
        .unwrap()
        .unwrap();
    let dapp_settings: DefiniteCanisterSettingsArgs = dapp_canister_status.settings().into();
    assert_eq!(
        dapp_settings,
        DefiniteCanisterSettingsArgs::new(
            vec![canister_ids.root_canister_id.get()],
            50,
            Some(1 << 30),
            100_000,
            Some(1_000_000_000),
            Some(0),
        ),
    );

    // Step 3.3: Verify that the ledger canister settings have not been changed.
    let new_ledger_canister_status = state_machine
        .canister_status_as(
            canister_ids.root_canister_id.get(),
            canister_ids.ledger_canister_id,
        )
        .unwrap()
        .unwrap();
    // Ignore the canister version in the comparison because it's irrelevant for the
    // canister settings and changes with every update call.
    assert_eq!(
        new_ledger_canister_status.ignore_version(),
        original_ledger_canister_status.ignore_version()
    );
}
