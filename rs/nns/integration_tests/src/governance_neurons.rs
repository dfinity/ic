//! Test neuron operations using the governance and other NNS canisters.

use canister_test::Runtime;
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_base_types::PrincipalId;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_ID,
    TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;
use ic_nns_governance_api::pb::v1::{
    governance_error::ErrorType,
    manage_neuron::{Command, Merge, NeuronIdOrSubaccount, Spawn},
    manage_neuron_response::{
        Command as CommandResponse, {self},
    },
    neuron::DissolveState,
    GovernanceError, ListNeurons, ManageNeuron, ManageNeuronResponse, Neuron, NeuronState,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    itest_helpers::{state_machine_test_on_nns_subnet, NnsCanisters},
    state_test_helpers::{
        list_neurons, list_neurons_by_principal, nns_add_hot_key, nns_claim_or_refresh_neuron,
        nns_disburse_neuron, nns_governance_get_full_neuron, nns_governance_get_neuron_info,
        nns_join_community_fund, nns_leave_community_fund, nns_remove_hot_key,
        nns_send_icp_to_claim_or_refresh_neuron, setup_nns_canisters,
        state_machine_builder_for_nns_tests,
    },
};
use icp_ledger::{tokens_from_proto, AccountBalanceArgs, AccountIdentifier, Tokens};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_merge_neurons_and_simulate_merge_neurons() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        const TWELVE_MONTHS_SECONDS: u64 = 30 * 12 * 24 * 60 * 60;

        //
        // Build the testing environment
        //

        let mut nns_builder = NnsInitPayloadsBuilder::new();
        nns_builder.with_test_neurons();

        // Add another neuron owned by the same owner as the first test
        // neuron.
        let neuron_id_4 = NeuronIdProto::from(nns_builder.governance.new_neuron_id());
        let neuron_4_subaccount = nns_builder.governance.make_subaccount().into();
        assert_eq!(
            nns_builder.governance.proto.neurons.insert(
                neuron_id_4.id,
                Neuron {
                    id: Some(neuron_id_4),
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        TWELVE_MONTHS_SECONDS
                    )),
                    cached_neuron_stake_e8s: 123_000_000_000,
                    account: neuron_4_subaccount,
                    not_for_profit: true,
                    ..Default::default()
                }
            ),
            None,
            "There is more than one neuron with the same id."
        );

        //
        // Bootstrap the environment from the details above
        //

        let nns_init_payload = nns_builder.build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        //
        // Execute operations to be tested
        //

        // The balance of the main account should be 0.
        let user_balance: Tokens = nns_canisters
            .ledger
            .query_(
                "account_balance_pb",
                protobuf,
                AccountBalanceArgs {
                    account: AccountIdentifier::from(*TEST_NEURON_1_OWNER_PRINCIPAL),
                },
            )
            .await
            .map(tokens_from_proto)?;
        assert_eq!(Tokens::from_e8s(0), user_balance);

        // Let us transfer ICP into the main account, and stake two neurons
        // owned by TEST_NEURON_1_OWNER_PRINCIPAL.

        let mgmt_request = ManageNeuron {
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronIdProto {
                id: TEST_NEURON_1_ID,
            })),
            id: None,
            command: Some(Command::Merge(Merge {
                source_neuron_id: Some(neuron_id_4),
            })),
        };

        let simulate_1_res: ManageNeuronResponse = nns_canisters
            .governance
            .query_from_sender(
                "manage_neuron",
                candid_one,
                mgmt_request.clone(),
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .unwrap();

        let merge1_res: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                mgmt_request,
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .unwrap();

        // assert simulated response is identical
        let ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Merge(merge_simulate)),
        } = simulate_1_res
        else {
            panic!("Wrong response");
        };
        let ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Merge(merge_real)),
        } = merge1_res
        else {
            panic!("Wrong response");
        };

        // We test we're getting the same info. neuron_info is derived and tested
        // in unit tests.
        // That the results are correct is tested in nns/governance/tests/governance.rs
        assert_eq!(merge_real.source_neuron, merge_simulate.source_neuron);
        assert_eq!(merge_real.target_neuron, merge_simulate.target_neuron);

        Ok(())
    });
}

#[test]
fn test_spawn_neuron() {
    state_machine_test_on_nns_subnet(|runtime| async move {
        const TWELVE_MONTHS_SECONDS: u64 = 30 * 12 * 24 * 60 * 60;

        let mut nns_builder = NnsInitPayloadsBuilder::new();

        // Add another neuron owned by the same owner as the first test
        // neuron.
        let neuron_id = NeuronIdProto::from(nns_builder.governance.new_neuron_id());
        let neuron_subaccount = nns_builder.governance.make_subaccount().into();
        assert_eq!(
            nns_builder.governance.proto.neurons.insert(
                neuron_id.id,
                Neuron {
                    id: Some(neuron_id),
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        TWELVE_MONTHS_SECONDS
                    )),
                    cached_neuron_stake_e8s: 123_000_000_000,
                    account: neuron_subaccount,
                    not_for_profit: true,
                    maturity_e8s_equivalent: 1_000_000_000, // Equivalent to 10 ICP
                    ..Default::default()
                }
            ),
            None,
            "There is more than one neuron with the same id."
        );
        let nns_init_payload = nns_builder.build();
        let nns_canisters = NnsCanisters::set_up(&runtime, nns_init_payload).await;

        let spawn_res: ManageNeuronResponse = nns_canisters
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id)),
                    id: None,
                    command: Some(Command::Spawn(Spawn {
                        new_controller: None,
                        nonce: None,
                        percentage_to_spawn: None,
                    })),
                },
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .unwrap();

        let spawned_neuron_id = match spawn_res.clone().command.unwrap() {
            CommandResponse::Spawn(res) => res.created_neuron_id.unwrap(),
            _ => panic!("Unexpected response: {:?}", spawn_res),
        };

        // Neuron should now exist and be in "spawning" state.
        let response: Result<Neuron, GovernanceError> = nns_canisters
            .governance
            .query_from_sender(
                "get_full_neuron",
                candid_one,
                spawned_neuron_id.id,
                &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            )
            .await
            .unwrap();

        let spawned_neuron = response.unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        assert_eq!(spawned_neuron.state(now), NeuronState::Spawning);
        assert_eq!(spawned_neuron.cached_neuron_stake_e8s, 0);
        assert_eq!(spawned_neuron.maturity_e8s_equivalent, 1_000_000_000);

        // Advance the time in the governance canister.
        match &runtime {
            Runtime::StateMachine(sm) => {
                sm.advance_time(std::time::Duration::from_secs(86400 * 7 + 1));
                sm.tick();
                sm.tick();
            }
            Runtime::Remote(_) | Runtime::Local(_) => {
                nns_canisters
                    .set_time_warp((86400 * 7 + 1) as i64)
                    .await
                    .expect(r#"Expected set_time_warp to succeed"#);
            }
        }
        // Now loop a few times and expect the neuron's stake to be minted and for the
        // neuron to be dissolved.
        for _i in 0..10 {
            let response: Result<Neuron, GovernanceError> = nns_canisters
                .governance
                .update_from_sender(
                    "get_full_neuron",
                    candid_one,
                    spawned_neuron_id.id,
                    &Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
                )
                .await
                .unwrap();

            let spawned_neuron = response.unwrap();

            if spawned_neuron.spawn_at_timestamp_seconds.is_none() {
                assert!(
                    spawned_neuron.cached_neuron_stake_e8s > 950_000_000
                        && spawned_neuron.cached_neuron_stake_e8s < 1_050_000_000
                );
                assert_eq!(spawned_neuron.maturity_e8s_equivalent, 0);
                return Ok(());
            } else {
                println!("Neuron not spawned yet: {:?}", spawned_neuron);
            }
        }

        Err("Spawned neuron's stake did not show up.".to_string())
    });
}

/// If a neuron's controller is added as a hot key and then removed, assert that Governance
/// still associates this neuron with the given controller (e.g. returns the neuron in a call
/// to list_neurons).
#[test]
fn test_neuron_controller_is_not_removed_from_principal_to_neuron_index() {
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let list_neurons_response =
        list_neurons_by_principal(&state_machine, *TEST_NEURON_2_OWNER_PRINCIPAL);
    assert_eq!(list_neurons_response.full_neurons.len(), 1);

    let neuron_id = NeuronIdProto {
        id: TEST_NEURON_2_ID,
    };

    let response = nns_add_hot_key(
        &state_machine,
        *TEST_NEURON_2_OWNER_PRINCIPAL,
        neuron_id,
        *TEST_NEURON_2_OWNER_PRINCIPAL,
    );

    match response.command {
        Some(manage_neuron_response::Command::Configure(_)) => (),
        _ => panic!("Failed to add hot key: {:#?}", response),
    };

    let list_neurons_response =
        list_neurons_by_principal(&state_machine, *TEST_NEURON_2_OWNER_PRINCIPAL);
    assert_eq!(list_neurons_response.full_neurons.len(), 1);

    let response = nns_remove_hot_key(
        &state_machine,
        *TEST_NEURON_2_OWNER_PRINCIPAL,
        neuron_id,
        *TEST_NEURON_2_OWNER_PRINCIPAL,
    );

    match response.command {
        Some(manage_neuron_response::Command::Configure(_)) => (),
        _ => panic!("Failed to remove hot key: {:#?}", response),
    };

    let list_neurons_response =
        list_neurons_by_principal(&state_machine, *TEST_NEURON_2_OWNER_PRINCIPAL);
    assert_eq!(list_neurons_response.full_neurons.len(), 1);
}

#[test]
fn test_hotkey_can_join_and_leave_community_fund() {
    // Step 1: Prepare the world.

    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new().with_test_neurons().build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let neuron_1_id = NeuronIdProto {
        id: TEST_NEURON_1_ID,
    };
    let hotkey = PrincipalId::new_user_test_id(622_907);

    nns_add_hot_key(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        neuron_1_id,
        hotkey,
    );

    // Step 2a: Call the code under test (indirectly). To wit, is_authorized_to_configure_or_err.
    let join_response = nns_join_community_fund(&state_machine, hotkey, neuron_1_id);

    // Step 3a: Inspect result. Expect success.
    fn assert_ok(manage_neuron_response: &ManageNeuronResponse) {
        match manage_neuron_response {
            ManageNeuronResponse {
                command:
                    Some(manage_neuron_response::Command::Configure(
                        manage_neuron_response::ConfigureResponse {},
                    )),
            } => (),
            _ => panic!("{:#?}", manage_neuron_response),
        }
    }
    assert_ok(&join_response);

    // Step 2b: Instead of joining NF, leave it.
    let leave_response = nns_leave_community_fund(&state_machine, hotkey, neuron_1_id);

    // Step 3b: Again, expect success.
    assert_ok(&leave_response);

    // Step 2c: Call code under test, but this is a sad scenario: Other neuron
    // configure operations (besides Neuron Fund membership changes) by hotkey
    // are verboten.
    let add_hot_key_response = nns_add_hot_key(
        &state_machine,
        hotkey,
        neuron_1_id,
        PrincipalId::new_user_test_id(289_896),
    );
    match add_hot_key_response {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Error(error)),
        } => {
            assert_eq!(
                ErrorType::try_from(error.error_type),
                Ok(ErrorType::NotAuthorized),
                "{:?}",
                error
            );
            assert!(
                error.error_message.contains("must be the controller"),
                "{:?}",
                error
            );
        }
        _ => panic!(
            "Unexpected response to AddHotKey:\n{:#?}",
            add_hot_key_response
        ),
    }

    // Steps 2d, 3d: Controller can perform any neuron configure operation.
    assert_ok(&nns_join_community_fund(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        neuron_1_id,
    ));
    assert_ok(&nns_leave_community_fund(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        neuron_1_id,
    ));
    assert_ok(&nns_add_hot_key(
        &state_machine,
        *TEST_NEURON_1_OWNER_PRINCIPAL,
        neuron_1_id,
        PrincipalId::new_user_test_id(331_685),
    ));
}

#[test]
fn test_claim_neuron() {
    // Step 1: Prepare the world by setting up NNS canisters and transfer 1 ICP to a Governance
    // canister subaccount.
    let state_machine = state_machine_builder_for_nns_tests().build();
    let test_user_principal = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let nonce = 123_456;
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_account(
            AccountIdentifier::new(test_user_principal, None),
            Tokens::from_e8s(2_000_000_000),
        )
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);
    nns_send_icp_to_claim_or_refresh_neuron(
        &state_machine,
        test_user_principal,
        Tokens::from_e8s(1_000_000_000),
        nonce,
    );

    // Step 2: Call the code under test - claim a neuron.
    let neuron_id = nns_claim_or_refresh_neuron(&state_machine, test_user_principal, nonce);

    // Step 3.1: Inspect the claimed neuron as a full neuron.
    let full_neuron =
        nns_governance_get_full_neuron(&state_machine, test_user_principal, neuron_id.id).unwrap();
    assert_eq!(full_neuron.controller, Some(test_user_principal));
    let created_timestamp_seconds = full_neuron.created_timestamp_seconds;
    assert!(created_timestamp_seconds > 0);
    assert_eq!(
        full_neuron.dissolve_state,
        Some(DissolveState::WhenDissolvedTimestampSeconds(
            created_timestamp_seconds
        ))
    );
    assert_eq!(full_neuron.aging_since_timestamp_seconds, u64::MAX);
    assert_eq!(full_neuron.cached_neuron_stake_e8s, 1_000_000_000);

    // Step 3.2: Inspect the claimed neuron as neuron info.
    let neuron_info =
        nns_governance_get_neuron_info(&state_machine, PrincipalId::new_anonymous(), neuron_id.id)
            .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolved as i32);
    assert_eq!(neuron_info.dissolve_delay_seconds, 0);
    assert_eq!(neuron_info.age_seconds, 0);
    assert_eq!(neuron_info.stake_e8s, 1_000_000_000);
}

#[test]
fn test_list_neurons() {
    // Step 1.1: Prepare the world by setting up NNS canisters with 2 princials both with 10 ICP.
    let state_machine = state_machine_builder_for_nns_tests().build();
    let principal_1 = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let principal_2 = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_accounts(vec![
            (
                AccountIdentifier::new(principal_1, None),
                Tokens::from_e8s(1_000_000_000),
            ),
            (
                AccountIdentifier::new(principal_2, None),
                Tokens::from_e8s(1_000_000_000),
            ),
        ])
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // Step 1.2: Claim 3 neurons - principal 1 has 2 neurons, principal 2 has 1 neuron. All with 2 ICPs.
    nns_send_icp_to_claim_or_refresh_neuron(
        &state_machine,
        principal_1,
        Tokens::from_e8s(200_000_000),
        1,
    );
    let neuron_id_1 = nns_claim_or_refresh_neuron(&state_machine, principal_1, 1);
    nns_send_icp_to_claim_or_refresh_neuron(
        &state_machine,
        principal_1,
        Tokens::from_e8s(200_000_000),
        2,
    );
    let neuron_id_2 = nns_claim_or_refresh_neuron(&state_machine, principal_1, 2);
    nns_send_icp_to_claim_or_refresh_neuron(
        &state_machine,
        principal_2,
        Tokens::from_e8s(200_000_000),
        3,
    );
    let neuron_id_3 = nns_claim_or_refresh_neuron(&state_machine, principal_2, 3);

    // Step 1.3: disburse neuron 2 so that it's empty.
    nns_disburse_neuron(&state_machine, principal_1, neuron_id_2, 200_000_000, None);

    // Step 2: test listing neurons by ids with an anonymous principal.
    let list_neurons_response = list_neurons(
        &state_machine,
        PrincipalId::new_anonymous(),
        ListNeurons {
            neuron_ids: vec![neuron_id_1.id, neuron_id_2.id, neuron_id_3.id],
            include_neurons_readable_by_caller: false,
            include_empty_neurons_readable_by_caller: Some(false),
            include_public_neurons_in_full_neurons: None,
        },
    );
    assert_eq!(list_neurons_response.neuron_infos.len(), 3);
    assert_eq!(list_neurons_response.full_neurons.len(), 0);

    // Step 3: test listing neurons by ids with principal 1 including empty neurons.
    let list_neurons_response = list_neurons(
        &state_machine,
        principal_1,
        ListNeurons {
            neuron_ids: vec![],
            include_neurons_readable_by_caller: true,
            include_empty_neurons_readable_by_caller: Some(true),
            include_public_neurons_in_full_neurons: None,
        },
    );
    assert_eq!(list_neurons_response.neuron_infos.len(), 2);
    assert_eq!(list_neurons_response.full_neurons.len(), 2);

    // Step 4: test listing neurons by ids with principal 1 not including empty neurons.
    let list_neurons_response = list_neurons(
        &state_machine,
        principal_1,
        ListNeurons {
            neuron_ids: vec![],
            include_neurons_readable_by_caller: true,
            include_empty_neurons_readable_by_caller: Some(false),
            include_public_neurons_in_full_neurons: None,
        },
    );
    assert_eq!(list_neurons_response.neuron_infos.len(), 1);
    assert_eq!(list_neurons_response.full_neurons.len(), 1);

    // Step 5: test listing neurons by ids with principal 1 without specifying whether to include
    // empty neurons, also specifying neuron 3 which the caller does not control.
    let list_neurons_response = list_neurons(
        &state_machine,
        principal_1,
        ListNeurons {
            neuron_ids: vec![neuron_id_3.id],
            include_neurons_readable_by_caller: true,
            include_empty_neurons_readable_by_caller: None,
            include_public_neurons_in_full_neurons: None,
        },
    );
    assert_eq!(list_neurons_response.neuron_infos.len(), 3);
    assert_eq!(list_neurons_response.full_neurons.len(), 2);
}
