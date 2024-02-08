// TODO(NNS1-2835): Remove this file after changes published.

use candid::Encode;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ic00_types::{CanisterInstallMode, CanisterSettingsArgsBuilder};
use ic_nervous_system_common::ONE_TRILLION;
use ic_nns_constants::ROOT_CANISTER_ID as NNS_ROOT_CANISTER_ID;
use ic_nns_test_utils::{
    sns_wasm::{
        build_archive_sns_wasm, build_governance_sns_wasm, build_index_sns_wasm,
        build_ledger_sns_wasm, build_root_sns_wasm, build_swap_sns_wasm,
    },
    state_test_helpers::set_controllers,
};
use ic_registry_subnet_type::SubnetType;
use ic_sns_governance::pb::v1::{
    governance::Version, NervousSystemParameters, NeuronPermissionList, NeuronPermissionType,
};
use ic_sns_init::SnsCanisterInitPayloads;
use ic_sns_test_utils::itest_helpers::{populate_canister_ids, SnsTestsInitPayloadBuilder};
use ic_state_machine_tests::StateMachineBuilder;
use ic_types::Cycles;

#[test]
fn test_reset_memory_allocation_for_sns() {
    let system_params = NervousSystemParameters {
        neuron_claimer_permissions: Some(NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        }),
        ..NervousSystemParameters::with_default_values()
    };
    let mut payloads = SnsTestsInitPayloadBuilder::new()
        .with_nervous_system_parameters(system_params)
        .build();

    let state_machine = StateMachineBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .with_default_canister_range()
        .build();

    let create_canister = || {
        state_machine.create_canister_with_cycles(
            None,
            Cycles::new(3 * ONE_TRILLION as u128),
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_memory_allocation(1 << 30)
                    .build(),
            ),
        )
    };
    let install_canister = |canister_id, wasm, payload| {
        state_machine
            .install_wasm_in_mode(canister_id, CanisterInstallMode::Install, wasm, payload)
            .unwrap()
    };

    let root_canister_id = create_canister();
    let governance_canister_id = create_canister();
    let ledger_canister_id = create_canister();
    let swap_canister_id = create_canister();
    let index_canister_id = create_canister();
    let archive_canister_id = create_canister();

    set_controllers(
        &state_machine,
        PrincipalId::new_anonymous(),
        root_canister_id,
        vec![governance_canister_id.into()],
    );
    set_controllers(
        &state_machine,
        PrincipalId::new_anonymous(),
        governance_canister_id,
        vec![root_canister_id.into()],
    );
    set_controllers(
        &state_machine,
        PrincipalId::new_anonymous(),
        ledger_canister_id,
        vec![root_canister_id.into()],
    );
    set_controllers(
        &state_machine,
        PrincipalId::new_anonymous(),
        swap_canister_id,
        vec![NNS_ROOT_CANISTER_ID.into(), swap_canister_id.into()],
    );
    set_controllers(
        &state_machine,
        PrincipalId::new_anonymous(),
        index_canister_id,
        vec![root_canister_id.into()],
    );
    set_controllers(
        &state_machine,
        PrincipalId::new_anonymous(),
        archive_canister_id,
        vec![root_canister_id.into()],
    );

    populate_canister_ids(
        root_canister_id,
        governance_canister_id,
        ledger_canister_id,
        swap_canister_id,
        index_canister_id,
        vec![archive_canister_id],
        &mut payloads,
    );

    let SnsCanisterInitPayloads {
        mut governance,
        root,
        ..
    } = payloads;

    let (
        root_sns_wasm,
        governance_sns_wasm,
        ledger_sns_wasm,
        swap_sns_wasm,
        index_sns_wasm,
        archive_sns_wasm,
    ) = (
        build_root_sns_wasm(),
        build_governance_sns_wasm(),
        build_ledger_sns_wasm(),
        build_swap_sns_wasm(),
        build_index_sns_wasm(),
        build_archive_sns_wasm(),
    );

    let deployed_version = Version {
        root_wasm_hash: root_sns_wasm.sha256_hash().to_vec(),
        governance_wasm_hash: governance_sns_wasm.sha256_hash().to_vec(),
        ledger_wasm_hash: ledger_sns_wasm.sha256_hash().to_vec(),
        swap_wasm_hash: swap_sns_wasm.sha256_hash().to_vec(),
        archive_wasm_hash: archive_sns_wasm.sha256_hash().to_vec(), // tests don't need it for now so we don't compile it.
        index_wasm_hash: index_sns_wasm.sha256_hash().to_vec(),
    };

    governance.deployed_version = Some(deployed_version);

    // Assert all the memory allocations are 1GiB
    let get_status = |canister_id: CanisterId| {
        state_machine
            .canister_status_as(canister_id.get(), canister_id)
            .unwrap()
            .unwrap()
    };

    assert_eq!(
        get_status(root_canister_id).memory_allocation(),
        1024 * 1024 * 1024
    );
    assert_eq!(
        get_status(governance_canister_id).memory_allocation(),
        1024 * 1024 * 1024
    );
    assert_eq!(
        get_status(ledger_canister_id).memory_allocation(),
        1024 * 1024 * 1024
    );
    assert_eq!(
        get_status(swap_canister_id).memory_allocation(),
        1024 * 1024 * 1024
    );
    assert_eq!(
        get_status(index_canister_id).memory_allocation(),
        1024 * 1024 * 1024
    );
    assert_eq!(
        get_status(archive_canister_id).memory_allocation(),
        1024 * 1024 * 1024
    );

    install_canister(
        root_canister_id,
        root_sns_wasm.wasm,
        Encode!(&root).unwrap(),
    );
    install_canister(
        governance_canister_id,
        governance_sns_wasm.wasm,
        Encode!(&governance).unwrap(),
    );

    for _ in 0..10 {
        state_machine.tick();
    }

    // Assert that all the memory allocations are now set to unbounded.
    assert_eq!(get_status(governance_canister_id).memory_allocation(), 0);
    assert_eq!(get_status(ledger_canister_id).memory_allocation(), 0);
    assert_eq!(get_status(index_canister_id).memory_allocation(), 0);
    assert_eq!(get_status(root_canister_id).memory_allocation(), 0);
    assert_eq!(get_status(archive_canister_id).memory_allocation(), 0);

    // Ensure it only runs 1x by changing the settings again, then seeing if more heartbeats fixes it.

    let settings = CanisterSettingsArgsBuilder::new()
        .with_memory_allocation(1 << 30)
        .build();

    state_machine
        .update_settings(&root_canister_id, settings.clone())
        .unwrap();
    state_machine
        .update_settings(&governance_canister_id, settings)
        .unwrap();

    // Assert that the settings are correct
    assert_eq!(
        get_status(governance_canister_id).memory_allocation(),
        1 << 30
    );
    assert_eq!(get_status(root_canister_id).memory_allocation(), 1 << 30);

    for _ in 0..10 {
        state_machine.tick();
    }

    // Assert that the settings have not changed again
    assert_eq!(
        get_status(governance_canister_id).memory_allocation(),
        1 << 30
    );
    assert_eq!(get_status(root_canister_id).memory_allocation(), 1 << 30);
}
