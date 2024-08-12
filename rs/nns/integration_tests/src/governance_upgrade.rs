//! Test where the governance canister goes through several self-upgrades in a
//! row.
//!
//! This is to make sure that the previous stable memory content does not have
//! a detrimental impact on future upgrades.

use canister_test::Project;
use dfn_candid::candid_one;
use ic_base_types::PrincipalId;
use ic_canister_client_sender::Sender;
use ic_management_canister_types::{
    CanisterIdRecord, CanisterInstallMode, CanisterSettingsArgsBuilder,
};
use ic_nervous_system_clients::canister_status::{CanisterStatusResult, CanisterStatusType};
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET, ROOT_CANISTER_ID,
};
use ic_nns_governance_api::pb::v1::{
    manage_neuron::{configure, Command, Configure, NeuronIdOrSubaccount, RemoveHotKey},
    ManageNeuron, ManageNeuronResponse,
};
use ic_nns_governance_init::GovernanceCanisterInitPayloadBuilder;
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    itest_helpers::{install_governance_canister, state_machine_test_on_nns_subnet},
    state_test_helpers::{
        create_canister_id_at_position, setup_nns_root_with_correct_canister_id,
        state_machine_builder_for_nns_tests, update_with_sender,
    },
};
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use std::time::Duration;

/// This is a regression test: it used to be that, if two upgrades happened in a
/// row, with the stable memory of the second being smaller than for the first,
/// the second upgrade would read too many bytes from stable memory, resulting
/// in a trap in post_upgrade.
#[test]
fn test_upgrade_after_state_shrink() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        let mut governance_proto = GovernanceCanisterInitPayloadBuilder::new()
            .with_test_neurons()
            .build();
        let hot_key = PrincipalId::new_self_authenticating(b"this is the pub key of the hot key");
        governance_proto
            .neurons
            .get_mut(&TEST_NEURON_1_ID)
            .unwrap()
            .hot_keys
            .push(hot_key);

        let mut canister = runtime
            .create_canister_at_id_max_cycles_with_retries(GOVERNANCE_CANISTER_ID.get())
            .await
            .unwrap();
        install_governance_canister(&mut canister, governance_proto).await;

        // First let's do a self-upgrade
        canister.stop().await.unwrap();
        canister.upgrade_to_self_binary(Vec::new()).await.unwrap();
        canister.start().await.unwrap();

        // Now make the state smaller
        let _remove_hot_res: ManageNeuronResponse = canister
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronIdProto {
                        id: TEST_NEURON_1_ID,
                    })),
                    id: None,
                    command: Some(Command::Configure(Configure {
                        operation: Some(configure::Operation::RemoveHotKey(RemoveHotKey {
                            hot_key_to_remove: Some(hot_key),
                        })),
                    })),
                },
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .unwrap();

        // Now, one more self-upgrade
        canister.stop().await.unwrap();
        canister.upgrade_to_self_binary(Vec::new()).await.unwrap();
        canister.start().await.unwrap();

        Ok(())
    });
}

#[test]
fn test_root_restarts_canister_during_upgrade_canister_with_stop_canister_timeout() {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let governance_id = create_canister_id_at_position(
        &state_machine,
        GOVERNANCE_CANISTER_INDEX_IN_NNS_SUBNET,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![ROOT_CANISTER_ID.get()])
                .build(),
        ),
    );

    let unstoppable_canister =
        Project::cargo_bin_maybe_from_env("unstoppable-canister", &[]).bytes();

    state_machine
        .install_wasm_in_mode(
            governance_id,
            CanisterInstallMode::Install,
            unstoppable_canister,
            vec![],
        )
        .unwrap();
    let nns_init_payload = NnsInitPayloadsBuilder::new().build();
    setup_nns_root_with_correct_canister_id(&state_machine, nns_init_payload.root);

    let wasm_module = UNIVERSAL_CANISTER_WASM.to_vec();

    let proposal = ChangeCanisterRequest {
        stop_before_installing: true,
        mode: CanisterInstallMode::Upgrade,
        canister_id: GOVERNANCE_CANISTER_ID,
        wasm_module,
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
    };

    let _: () = update_with_sender(
        &state_machine,
        ROOT_CANISTER_ID,
        "change_nns_canister",
        candid_one,
        proposal,
        GOVERNANCE_CANISTER_ID.get(),
    )
    .expect("root change_nns_canister call failed");

    state_machine.tick();

    // After 60 seconds, canister is still trying to stop...
    state_machine.advance_time(Duration::from_secs(60));

    state_machine.tick();

    let status: CanisterStatusResult = update_with_sender(
        &state_machine,
        ROOT_CANISTER_ID,
        "canister_status",
        candid_one,
        CanisterIdRecord::from(GOVERNANCE_CANISTER_ID),
        PrincipalId::new_anonymous(),
    )
    .unwrap();

    assert_eq!(status.status, CanisterStatusType::Stopping);

    // canister_stop times out, we now need to make sure it got restarted
    state_machine.advance_time(Duration::from_secs(241));
    state_machine.tick();
    state_machine.tick();

    let status: CanisterStatusResult = update_with_sender(
        &state_machine,
        ROOT_CANISTER_ID,
        "canister_status",
        candid_one,
        CanisterIdRecord::from(GOVERNANCE_CANISTER_ID),
        PrincipalId::new_anonymous(),
    )
    .unwrap();

    // Check latest status.
    assert_eq!(status.status, CanisterStatusType::Running);
}
