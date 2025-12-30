//! Test neuron operations using the governance and other NNS canisters.

use canister_test::Runtime;
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_base_types::PrincipalId;
use ic_canister_client_sender::Sender;
use ic_nervous_system_common::{
    ONE_DAY_SECONDS, ONE_YEAR_SECONDS, ledger::compute_neuron_staking_subaccount_bytes,
};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_ID,
    TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_nns_governance::governance::INITIAL_NEURON_DISSOLVE_DELAY;
use ic_nns_governance_api::{
    Account as GovernanceAccount, GovernanceError, ListNeurons, MakeProposalRequest,
    ManageNeuronCommandRequest, ManageNeuronRequest, ManageNeuronResponse, Motion, Neuron,
    NeuronState, ProposalActionRequest, Topic,
    governance_error::ErrorType,
    list_neurons::NeuronSubaccount,
    manage_neuron::{DisburseMaturity, Merge, NeuronIdOrSubaccount, Spawn},
    manage_neuron_response::{self, Command as CommandResponse},
    neuron::DissolveState,
};
use ic_nns_test_utils::{
    common::NnsInitPayloadsBuilder,
    itest_helpers::{NnsCanisters, state_machine_test_on_nns_subnet},
    state_test_helpers::{
        ledger_account_balance, list_neurons, list_neurons_by_principal, nns_add_hot_key,
        nns_claim_or_refresh_neuron, nns_disburse_maturity, nns_disburse_neuron,
        nns_governance_get_full_neuron, nns_governance_get_neuron_info,
        nns_governance_make_proposal, nns_increase_dissolve_delay, nns_join_community_fund,
        nns_leave_community_fund, nns_make_neuron_public, nns_remove_hot_key,
        nns_send_icp_to_claim_or_refresh_neuron, nns_set_auto_stake_maturity,
        nns_set_followees_for_neuron, nns_start_dissolving, setup_nns_canisters,
        state_machine_builder_for_nns_tests,
    },
};
use ic_state_machine_tests::StateMachine;
use icp_ledger::{
    AccountBalanceArgs, AccountIdentifier, BinaryAccountBalanceArgs, Subaccount, Tokens,
    protobuf::AccountIdentifier as AccountIdentifierProto, tokens_from_proto,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "tla")]
use ic_nns_constants::GOVERNANCE_CANISTER_ID;

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

        let mgmt_request = ManageNeuronRequest {
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronIdProto {
                id: TEST_NEURON_1_ID,
            })),
            id: None,
            command: Some(ManageNeuronCommandRequest::Merge(Merge {
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
                ManageNeuronRequest {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id)),
                    id: None,
                    command: Some(ManageNeuronCommandRequest::Spawn(Spawn {
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
            _ => panic!("Unexpected response: {spawn_res:?}"),
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
                println!("Neuron not spawned yet: {spawned_neuron:?}");
            }
        }

        Err("Spawned neuron's stake did not show up.".to_string())
    });
}

fn create_neuron_with_stake(
    state_machine: &StateMachine,
    neuron_controller: PrincipalId,
    stake: Tokens,
) -> NeuronIdProto {
    let nonce = 123_456;
    nns_send_icp_to_claim_or_refresh_neuron(state_machine, neuron_controller, stake, nonce);
    let neuron_id = nns_claim_or_refresh_neuron(state_machine, neuron_controller, nonce);
    nns_make_neuron_public(state_machine, neuron_controller, neuron_id)
        .expect("Failed to make neuron public");
    neuron_id
}

/// Creates a neuron with some maturity, and returns the neuron id. This is done by (1) sending some
/// ICPs to a governance subaccount for staking (2) claim the neuron (3) increase the dissolve delay
/// (4) make a proposal, and (5) wait for a few days so that the neuron gets voting rewards. This is
/// the "normal" way of getting maturity in production.
fn create_neuron_with_maturity(
    state_machine: &StateMachine,
    neuron_controller: PrincipalId,
    stake: Tokens,
    auto_stake: bool,
) -> NeuronIdProto {
    let neuron_id = create_neuron_with_stake(state_machine, neuron_controller, stake);
    nns_increase_dissolve_delay(
        state_machine,
        neuron_controller,
        neuron_id,
        ONE_YEAR_SECONDS * 7,
    )
    .unwrap();
    if auto_stake {
        nns_set_auto_stake_maturity(state_machine, neuron_controller, neuron_id, true)
            .panic_if_error("Failed to set auto stake maturity to true");
    }
    nns_governance_make_proposal(
        state_machine,
        neuron_controller,
        neuron_id,
        &MakeProposalRequest {
            title: Some("some title".to_string()),
            url: "".to_string(),
            summary: "some summary".to_string(),
            action: Some(ProposalActionRequest::Motion(Motion {
                motion_text: "some motion text".to_string(),
            })),
        },
    )
    .panic_if_error("Failed to make proposal");
    state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS * 5));
    for _ in 0..100 {
        state_machine.advance_time(Duration::from_secs(1));
        state_machine.tick();
    }

    let neuron = nns_governance_get_full_neuron(state_machine, neuron_controller, neuron_id.id)
        .expect("Failed to get neuron");
    if auto_stake {
        assert!(neuron.staked_maturity_e8s_equivalent.unwrap() > 0);
    } else {
        assert!(neuron.maturity_e8s_equivalent > 0);
    }

    neuron_id
}

fn get_balance_e8s_of_disburse_destination(
    state_machine: &StateMachine,
    account_identifier: AccountIdentifier,
) -> u64 {
    ledger_account_balance(
        state_machine,
        LEDGER_CANISTER_ID,
        &BinaryAccountBalanceArgs {
            account: account_identifier.to_address(),
        },
    )
    .get_e8s()
}

/// In this test, we create 3 maturity disbursements with 2 neurons with 3 days between each
/// disbursement, and assert that the disbursements can be created, as well as finalized at the
/// right time.
#[test]
fn test_neuron_disburse_maturity() {
    // Step 1.1: Prepare the world by setting up NNS canisters with 2000 ICP in 2 ledger accounts.
    let state_machine = state_machine_builder_for_nns_tests().build();
    let neuron_1_controller = PrincipalId::new_self_authenticating(b"neuron_1_controller");
    let neuron_2_controller = PrincipalId::new_self_authenticating(b"neuron_2_controller");
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_accounts(vec![
            (
                AccountIdentifier::new(neuron_1_controller, None),
                Tokens::from_tokens(2000).unwrap(),
            ),
            (
                AccountIdentifier::new(neuron_2_controller, None),
                Tokens::from_tokens(2000).unwrap(),
            ),
        ])
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // Step 1.2: Create 2 neurons with some maturity.
    let neuron_id_1 = create_neuron_with_maturity(
        &state_machine,
        neuron_1_controller,
        Tokens::from_tokens(1000).unwrap(),
        false,
    );
    let neuron_id_2 = create_neuron_with_maturity(
        &state_machine,
        neuron_2_controller,
        Tokens::from_tokens(1000).unwrap(),
        false,
    );

    // Step 1.3: check that both neurons have no maturity disbursement in progress, and record their
    // original maturity.
    let neuron_1 =
        nns_governance_get_full_neuron(&state_machine, neuron_1_controller, neuron_id_1.id)
            .expect("Failed to get neuron");
    let original_neuron_1_maturity_e8s_equivalent = neuron_1.maturity_e8s_equivalent;
    assert_eq!(neuron_1.maturity_disbursements_in_progress, Some(vec![]));
    let neuron_2 =
        nns_governance_get_full_neuron(&state_machine, neuron_2_controller, neuron_id_2.id)
            .expect("Failed to get neuron");
    let original_neuron_2_maturity_e8s_equivalent = neuron_2.maturity_e8s_equivalent;
    assert_eq!(neuron_2.maturity_disbursements_in_progress, Some(vec![]));

    // Step 2.1: Disburse 30% of maturity for neuron 1
    let disburse_destination_1_principal =
        PrincipalId::new_self_authenticating(b"disburse_destination_1");
    let disburse_destination_1 = AccountIdentifier::from(disburse_destination_1_principal);
    let disburse_response = nns_disburse_maturity(
        &state_machine,
        neuron_1_controller,
        neuron_id_1,
        DisburseMaturity {
            percentage_to_disburse: 30,
            to_account: Some(GovernanceAccount {
                owner: Some(disburse_destination_1_principal),
                subaccount: None,
            }),
            to_account_identifier: None,
        },
    )
    .panic_if_error("Failed to disburse maturity");

    // Step 2.2: Check the disbursement response.
    let Some(CommandResponse::DisburseMaturity(disburse_maturity_response)) =
        disburse_response.command
    else {
        panic!("Failed to disburse maturity: {disburse_response:#?}")
    };
    assert!(disburse_maturity_response.amount_disbursed_e8s.unwrap() > 0);

    // Step 2.3: Check that the disbursement is recorded in the neuron 1 and maturity is reduced.
    let neuron =
        nns_governance_get_full_neuron(&state_machine, neuron_1_controller, neuron_id_1.id)
            .expect("Failed to get neuron");
    let maturity_disbursement_1 = neuron
        .maturity_disbursements_in_progress
        .unwrap()
        .first()
        .cloned()
        .unwrap();
    assert_eq!(
        maturity_disbursement_1.amount_e8s.unwrap(),
        disburse_maturity_response.amount_disbursed_e8s.unwrap()
    );
    assert_eq!(
        neuron.maturity_e8s_equivalent,
        original_neuron_1_maturity_e8s_equivalent
            - disburse_maturity_response.amount_disbursed_e8s.unwrap()
    );

    // Step 3: Wait for 3 days.
    state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS * 3));

    // Step 4.1: Disburse 100% of maturity for neuron 2 through account identifier.
    let disburse_destination_2_hex =
        "807077e900000000000000000000000000000000000000000000000000000000";
    let disburse_destination_2 = AccountIdentifier::from_hex(disburse_destination_2_hex).unwrap();
    let disburse_response = nns_disburse_maturity(
        &state_machine,
        neuron_2_controller,
        neuron_id_2,
        DisburseMaturity {
            percentage_to_disburse: 100,
            to_account: None,
            to_account_identifier: Some(AccountIdentifierProto::from(disburse_destination_2)),
        },
    )
    .panic_if_error("Failed to disburse maturity");

    // Step 4.2: Check the disbursement response.
    let Some(CommandResponse::DisburseMaturity(disburse_maturity_response)) =
        disburse_response.command
    else {
        panic!("Failed to disburse maturity: {disburse_response:#?}")
    };
    assert!(disburse_maturity_response.amount_disbursed_e8s.unwrap() > 0);

    // Step 4.3: Check that the disbursement is recorded in the neuron 2 and maturity is reduced to 0.
    let neuron_2 =
        nns_governance_get_full_neuron(&state_machine, neuron_2_controller, neuron_id_2.id)
            .expect("Failed to get neuron");
    let maturity_disbursement_2 = neuron_2
        .maturity_disbursements_in_progress
        .unwrap()
        .first()
        .cloned()
        .unwrap();
    assert_eq!(
        maturity_disbursement_2.amount_e8s.unwrap(),
        disburse_maturity_response.amount_disbursed_e8s.unwrap()
    );
    assert_eq!(
        maturity_disbursement_2.amount_e8s.unwrap(),
        original_neuron_2_maturity_e8s_equivalent
    );
    assert_eq!(
        maturity_disbursement_2
            .account_identifier_to_disburse_to
            .unwrap()
            .hash,
        hex::decode(disburse_destination_2_hex).unwrap()
    );
    assert_eq!(neuron_2.maturity_e8s_equivalent, 0);

    // Step 5: Wait for 3 days.
    state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS * 3));

    // Step 6.1: Disburse maturity the remaining maturity for neuron 1 to its controller.
    let disburse_destination_3_principal =
        PrincipalId::new_self_authenticating(b"disburse_destination_3");
    let disburse_destination_3_subaccount = [1u8; 32];
    let disburse_destination_3 = AccountIdentifier::new(
        disburse_destination_3_principal,
        Some(Subaccount(disburse_destination_3_subaccount)),
    );
    let disburse_response = nns_disburse_maturity(
        &state_machine,
        neuron_1_controller,
        neuron_id_1,
        // Both to_account and to_account_identifier are None, so the disbursement will be
        // made to the neuron's controller.
        DisburseMaturity {
            percentage_to_disburse: 100,
            to_account: Some(GovernanceAccount {
                owner: Some(disburse_destination_3_principal),
                subaccount: Some(disburse_destination_3_subaccount.to_vec()),
            }),
            to_account_identifier: None,
        },
    )
    .panic_if_error("Failed to disburse maturity");

    // Step 6.2: Check the disbursement response.
    let Some(CommandResponse::DisburseMaturity(disburse_maturity_response)) =
        disburse_response.command
    else {
        panic!("Failed to disburse maturity: {disburse_response:#?}")
    };
    assert!(disburse_maturity_response.amount_disbursed_e8s.unwrap() > 0);

    // Step 6.3: Check that the disbursement is recorded in the neuron 1 and maturity is reduced to 0. Note that the 1st disbursement
    // is not finalized yet, so there are 2 maturity disbursements in progress, where the new one is at the end of the list.
    let neuron_1 =
        nns_governance_get_full_neuron(&state_machine, neuron_1_controller, neuron_id_1.id)
            .expect("Failed to get neuron");
    let maturity_disbursement_3 = neuron_1
        .maturity_disbursements_in_progress
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    assert_eq!(
        maturity_disbursement_3.amount_e8s.unwrap(),
        disburse_maturity_response.amount_disbursed_e8s.unwrap()
    );
    assert_eq!(neuron_1.maturity_e8s_equivalent, 0);

    // Step 7: Check that all 3 disbursement destinations are empty, as it's still 6 days after the first disbursement.
    assert_eq!(
        get_balance_e8s_of_disburse_destination(&state_machine, disburse_destination_1),
        0
    );
    assert_eq!(
        get_balance_e8s_of_disburse_destination(&state_machine, disburse_destination_2),
        0
    );
    assert_eq!(
        get_balance_e8s_of_disburse_destination(&state_machine, disburse_destination_3),
        0
    );

    // Step 8.1: Advance time by 1 day and tick the state machine to finalize the disbursement.
    state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS));
    for _ in 0..20 {
        state_machine.advance_time(Duration::from_secs(1));
        state_machine.tick();
    }

    // Step 8.2: Check that the destination account of the first disbursement has enough balance.
    let disburse_destination_1_balance =
        get_balance_e8s_of_disburse_destination(&state_machine, disburse_destination_1);
    assert!(
        disburse_destination_1_balance as f64
            > maturity_disbursement_1.amount_e8s.unwrap() as f64 * 0.95,
        "Disbursement 1 balance is too low: {disburse_destination_1_balance}"
    );

    // Step 8.3: Check that the neuron 1 still has one disbursement in progress, which is the second one.
    let neuron_1 =
        nns_governance_get_full_neuron(&state_machine, neuron_1_controller, neuron_id_1.id)
            .expect("Failed to get neuron");
    assert_eq!(
        neuron_1.maturity_disbursements_in_progress.unwrap().len(),
        1
    );

    // Step 8.4: Check that the destination account of the second disbursement is still empty.
    assert_eq!(
        get_balance_e8s_of_disburse_destination(&state_machine, disburse_destination_2),
        0
    );

    // Step 9.1: Advance 3 days and tick the state machine to finalize the second disbursement.
    state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS * 3));
    for _ in 0..20 {
        state_machine.advance_time(Duration::from_secs(1));
        state_machine.tick();
    }

    // Step 9.2: Check that the destination account of the second disbursement has enough balance.
    let disburse_destination_2_balance =
        get_balance_e8s_of_disburse_destination(&state_machine, disburse_destination_2);
    assert!(
        disburse_destination_2_balance as f64
            > maturity_disbursement_2.amount_e8s.unwrap() as f64 * 0.95,
        "Disbursement 2 balance is too low: {disburse_destination_2_balance}"
    );

    // Step 9.3: Check that the neuron 2 has no maturity disbursement in progress.
    let neuron_2 =
        nns_governance_get_full_neuron(&state_machine, neuron_2_controller, neuron_id_2.id)
            .expect("Failed to get neuron");
    assert_eq!(
        neuron_2.maturity_disbursements_in_progress.unwrap().len(),
        0
    );

    // Step 9.4: Check that the destination account of the third disbursement is still empty.
    assert_eq!(
        get_balance_e8s_of_disburse_destination(&state_machine, disburse_destination_3),
        0
    );

    // Step 10.1: Advance 3 days and tick the state machine to finalize the third disbursement.
    state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS * 3));
    for _ in 0..20 {
        state_machine.advance_time(Duration::from_secs(1));
        state_machine.tick();
    }

    // Step 10.2: Check that the destination account of the third disbursement has enough balance.
    let disburse_destination_3_balance =
        get_balance_e8s_of_disburse_destination(&state_machine, disburse_destination_3);
    assert!(
        disburse_destination_3_balance as f64
            > maturity_disbursement_3.amount_e8s.unwrap() as f64 * 0.95,
        "Disbursement 3 balance is too low: {disburse_destination_3_balance}"
    );

    // Step 10.3: Check that the neuron 1 has no maturity disbursement in progress.
    let neuron_1 =
        nns_governance_get_full_neuron(&state_machine, neuron_1_controller, neuron_id_1.id)
            .expect("Failed to get neuron");

    assert_eq!(
        neuron_1.maturity_disbursements_in_progress.unwrap().len(),
        0
    );

    #[cfg(feature = "tla")]
    check_state_machine_tla_traces(&state_machine, GOVERNANCE_CANISTER_ID);
}

#[cfg(feature = "tla")]
fn check_state_machine_tla_traces(
    sm: &ic_state_machine_tests::StateMachine,
    gov_canister_id: ic_base_types::CanisterId,
) {
    use candid::{Decode, Encode};
    use canister_test::WasmResult;
    use ic_nns_governance::governance::tla::{UpdateTrace, perform_trace_check};
    let wasm_res = sm
        .query(
            gov_canister_id,
            "get_tla_traces",
            Encode!(&()).expect("Couldn't encode get_tla_traces request"),
        )
        .expect("Couldn't call get_tla_traces");
    let traces = match wasm_res {
        WasmResult::Reject(r) => panic!("get_tla_traces failed: {r}"),
        WasmResult::Reply(r) => {
            Decode!(&r, Vec<UpdateTrace>).expect("Couldn't decode get_tla_traces response")
        }
    };
    perform_trace_check(traces)
}

#[test]
fn test_neuron_disburse_maturity_through_neuron_management_proposal() {
    // Step 1.1: Prepare the world by setting up NNS canisters with 2000 ICP in a ledger account.
    let state_machine = state_machine_builder_for_nns_tests().build();
    let managed_neuron_controller = PrincipalId::new_self_authenticating(b"managed_neuron");
    let neuron_manager_controller = PrincipalId::new_self_authenticating(b"neuron_manager");
    let disburse_destination = AccountIdentifier::from(managed_neuron_controller);
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_accounts(vec![
            (
                AccountIdentifier::new(managed_neuron_controller, None),
                Tokens::new(1000, 10000).unwrap(),
            ),
            (
                AccountIdentifier::new(neuron_manager_controller, None),
                Tokens::from_tokens(2).unwrap(),
            ),
        ])
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    // Step 1.2: Create a neuron with some maturity.
    let managed_neuron_id = create_neuron_with_maturity(
        &state_machine,
        managed_neuron_controller,
        Tokens::from_tokens(1000).unwrap(),
        false,
    );

    // Step 1.3: check that the neuron has no maturity disbursement in progress, and record its
    // original maturity.
    let neuron = nns_governance_get_full_neuron(
        &state_machine,
        managed_neuron_controller,
        managed_neuron_id.id,
    )
    .expect("Failed to get neuron");
    assert_eq!(neuron.maturity_disbursements_in_progress, Some(vec![]));

    // Step 1.4: create another neuron.
    let neuron_manager_id = create_neuron_with_stake(
        &state_machine,
        neuron_manager_controller,
        Tokens::from_tokens(1).unwrap(),
    );

    // Step 1.5 set the neuron manager as the followee of the managed neuron on topic 1.
    nns_set_followees_for_neuron(
        &state_machine,
        managed_neuron_controller,
        managed_neuron_id,
        &[neuron_manager_id],
        Topic::NeuronManagement as i32,
    )
    .panic_if_error("Failed to set followees");

    // Step 2: Call the code under test - make a neuron management proposal to disburse maturity.
    nns_governance_make_proposal(
        &state_machine,
        neuron_manager_controller,
        neuron_manager_id,
        &MakeProposalRequest {
            title: Some("some title".to_string()),
            url: "".to_string(),
            summary: "some summary".to_string(),
            action: Some(ProposalActionRequest::ManageNeuron(Box::new(
                ManageNeuronRequest {
                    id: Some(managed_neuron_id),
                    neuron_id_or_subaccount: None,
                    command: Some(ManageNeuronCommandRequest::DisburseMaturity(
                        DisburseMaturity {
                            percentage_to_disburse: 100,
                            to_account: None,
                            to_account_identifier: None,
                        },
                    )),
                },
            ))),
        },
    )
    .panic_if_error("Failed to make proposal");

    // Step 3.1: check that maturity disbursement for managed neuron exists, by getting full neuron
    // through the manager's controller.
    let neuron = nns_governance_get_full_neuron(
        &state_machine,
        neuron_manager_controller,
        managed_neuron_id.id,
    )
    .expect("Failed to get neuron");
    assert_eq!(neuron.maturity_disbursements_in_progress.unwrap().len(), 1);

    // Step 3.2: check that the destination account is empty before the disbursement is finalized.
    for _ in 0..7 {
        assert_eq!(
            get_balance_e8s_of_disburse_destination(&state_machine, disburse_destination),
            0
        );
        state_machine.advance_time(Duration::from_secs(ONE_DAY_SECONDS));
        for _ in 0..20 {
            state_machine.advance_time(Duration::from_secs(1));
            state_machine.tick();
        }
    }

    // Step 4: check that the disbursement was successful after 7 days and the maturity disbursement
    // is removed from the neuron.
    let balance = get_balance_e8s_of_disburse_destination(&state_machine, disburse_destination);
    assert!(balance > 0, "{}", balance);
    let neuron = nns_governance_get_full_neuron(
        &state_machine,
        neuron_manager_controller,
        managed_neuron_id.id,
    )
    .expect("Failed to get neuron");
    assert_eq!(neuron.maturity_disbursements_in_progress.unwrap().len(), 0);
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
        _ => panic!("Failed to add hot key: {response:#?}"),
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
        _ => panic!("Failed to remove hot key: {response:#?}"),
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
            _ => panic!("{manage_neuron_response:#?}"),
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
                error.error_type,
                ErrorType::NotAuthorized as i32,
                "{error:?}"
            );
            assert!(
                error.error_message.contains("must be the controller"),
                "{error:?}"
            );
        }
        _ => panic!("Unexpected response to AddHotKey:\n{add_hot_key_response:#?}"),
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
        Some(DissolveState::DissolveDelaySeconds(
            INITIAL_NEURON_DISSOLVE_DELAY
        ))
    );
    assert_eq!(
        full_neuron.aging_since_timestamp_seconds,
        created_timestamp_seconds
    );
    assert_eq!(full_neuron.cached_neuron_stake_e8s, 1_000_000_000);

    // Step 3.2: Inspect the claimed neuron as neuron info.
    let neuron_info =
        nns_governance_get_neuron_info(&state_machine, PrincipalId::new_anonymous(), neuron_id.id)
            .unwrap();
    assert_eq!(neuron_info.state, NeuronState::NotDissolving as i32);
    assert_eq!(
        neuron_info.dissolve_delay_seconds,
        INITIAL_NEURON_DISSOLVE_DELAY
    );
    assert_eq!(neuron_info.age_seconds, 0);
    assert_eq!(neuron_info.stake_e8s, 1_000_000_000);
}

#[test]
fn test_unstake_maturity_of_dissolved_neurons() {
    // Step 1: Prepare the world.
    let controller = PrincipalId::new_self_authenticating(b"controller");
    let state_machine = state_machine_builder_for_nns_tests().build();
    let nns_init_payloads = NnsInitPayloadsBuilder::new()
        .with_ledger_account(
            AccountIdentifier::new(controller, None),
            Tokens::from_tokens(2000).unwrap(),
        )
        .build();
    setup_nns_canisters(&state_machine, nns_init_payloads);

    let neuron_id = create_neuron_with_maturity(
        &state_machine,
        controller,
        Tokens::from_tokens(1000).unwrap(),
        true,
    );

    // Step 2: Create a neuron with some staked maturity.
    let full_neuron =
        nns_governance_get_full_neuron(&state_machine, controller, neuron_id.id).unwrap();
    assert_eq!(full_neuron.auto_stake_maturity, Some(true));
    assert!(full_neuron.staked_maturity_e8s_equivalent.unwrap() > 0);
    let dissolve_state = full_neuron.dissolve_state.unwrap();
    let dissolve_delay = match dissolve_state {
        DissolveState::DissolveDelaySeconds(dissolve_delay) => {
            // The dissolve delay here should be around 7 years, but in the test we only want to make sure
            // it's reasonably large enough for the test to continue.
            assert!(
                dissolve_delay > 3600,
                "The dissolve delay should be much greater than 1 hour"
            );
            dissolve_delay
        }
        _ => panic!("Unexpected dissolve state: {dissolve_state:#?}"),
    };

    // Step 2: Start dissolving the neuron and advance time to be close to the dissolve delay.
    nns_start_dissolving(&state_machine, controller, neuron_id).unwrap();
    state_machine.advance_time(Duration::from_secs(dissolve_delay - 3600));
    for _ in 0..20 {
        state_machine.advance_time(Duration::from_secs(5));
        state_machine.tick();
    }

    // Step 3: Check that the neuron still has some maturity staked.
    let full_neuron =
        nns_governance_get_full_neuron(&state_machine, controller, neuron_id.id).unwrap();
    assert!(full_neuron.staked_maturity_e8s_equivalent.unwrap() > 0);

    // Step 4: Advance time to be after the dissolve delay.
    state_machine.advance_time(Duration::from_secs(3600));
    for _ in 0..20 {
        state_machine.advance_time(Duration::from_secs(5));
        state_machine.tick();
    }

    // Step 5: Check that the neuron has no maturity staked.
    let full_neuron =
        nns_governance_get_full_neuron(&state_machine, controller, neuron_id.id).unwrap();
    assert_eq!(full_neuron.staked_maturity_e8s_equivalent, None);
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
    nns_start_dissolving(&state_machine, principal_1, neuron_id_2)
        .expect("Failed to start dissolving neuron");
    state_machine.advance_time(Duration::from_secs(INITIAL_NEURON_DISSOLVE_DELAY + 1));
    state_machine.tick();
    let disburse_result = nns_disburse_neuron(
        &state_machine,
        principal_1,
        neuron_id_2,
        Some(200_000_000),
        None,
    );

    match disburse_result {
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Disburse(_)),
        } => (),
        disburse_result => panic!("Failed to disburse neuron: {disburse_result:#?}"),
    }

    // Step 2: test listing neurons by ids with an anonymous principal.
    let list_neurons_response = list_neurons(
        &state_machine,
        PrincipalId::new_anonymous(),
        ListNeurons {
            neuron_ids: vec![neuron_id_1.id, neuron_id_2.id, neuron_id_3.id],
            include_neurons_readable_by_caller: false,
            include_empty_neurons_readable_by_caller: Some(false),
            include_public_neurons_in_full_neurons: None,
            page_number: None,
            page_size: None,
            neuron_subaccounts: None,
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
            page_number: None,
            page_size: None,
            neuron_subaccounts: None,
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
            page_number: None,
            page_size: None,
            neuron_subaccounts: Some(vec![]), // Should be equivalent to None
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
            include_empty_neurons_readable_by_caller: Some(true),
            include_public_neurons_in_full_neurons: None,
            page_number: None,
            page_size: None,
            neuron_subaccounts: Some(vec![]),
        },
    );
    assert_eq!(list_neurons_response.neuron_infos.len(), 3);
    assert_eq!(list_neurons_response.full_neurons.len(), 2);

    // Step 6: Same but specify neuron 3 by subaccount.
    // empty neurons, also specifying neuron 3 which the caller does not control.

    let subaccount = compute_neuron_staking_subaccount_bytes(principal_2, 3);
    let list_neurons_response = list_neurons(
        &state_machine,
        principal_1,
        ListNeurons {
            neuron_ids: vec![],
            include_neurons_readable_by_caller: true,
            include_empty_neurons_readable_by_caller: Some(true),
            include_public_neurons_in_full_neurons: None,
            page_number: None,
            page_size: None,
            neuron_subaccounts: Some(vec![NeuronSubaccount {
                subaccount: subaccount.to_vec(),
            }]),
        },
    );
    assert_eq!(list_neurons_response.neuron_infos.len(), 3);
    assert_eq!(list_neurons_response.full_neurons.len(), 2);
}
