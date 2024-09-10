use dfn_candid::candid_one;
use ic_canister_client_sender::Sender;
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{ONE_DAY_SECONDS, ONE_YEAR_SECONDS};
use ic_nervous_system_common_test_keys::{
    TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR, TEST_USER3_KEYPAIR, TEST_USER4_KEYPAIR,
    TEST_USER5_KEYPAIR,
};
use ic_sns_governance::pb::v1::{
    proposal::Action, Motion, NervousSystemParameters, NeuronPermissionList, NeuronPermissionType,
    Proposal,
};
use ic_sns_test_utils::{
    itest_helpers::{local_test_on_sns_subnet, SnsCanisters, SnsTestsInitPayloadBuilder},
    now_seconds,
};

/// Tests that Governance can be initialized with `NervousSystemParameters` and that any
/// unspecified fields are populated by defaults.
#[test]
fn test_init_with_sys_params() {
    local_test_on_sns_subnet(|runtime| async move {
        let system_params = NervousSystemParameters {
            transaction_fee_e8s: Some(100_000),
            reject_cost_e8s: Some(0),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_nervous_system_parameters(system_params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let live_sys_params: NervousSystemParameters = sns_canisters
            .governance
            .query_("get_nervous_system_parameters", candid_one, ())
            .await?;

        assert_eq!(live_sys_params, system_params);

        Ok(())
    });
}

#[test]
fn test_existing_proposals_unaffected_by_sns_parameter_changes() {
    local_test_on_sns_subnet(|runtime| {
        async move {
            // The `initial_voting_period_seconds` will change, so this is the `initial_initial_voting_period_seconds` :P
            let initial_initial_voting_period_seconds = ONE_DAY_SECONDS * 4;

            // Initialize the ledger with three users (each will create its own neuron).
            let user_1 = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let user_2 = Sender::from_keypair(&TEST_USER2_KEYPAIR);
            let user_3 = Sender::from_keypair(&TEST_USER3_KEYPAIR);
            // We're going to make some dummy users to cast inconsequential votes,
            // just to trigger process_proposal (which gets called on heartbeats
            // and new votes).
            let user_4 = Sender::from_keypair(&TEST_USER4_KEYPAIR);
            let user_5 = Sender::from_keypair(&TEST_USER5_KEYPAIR);

            // We want user_1 to have more voting weight than user_2,
            // and we need a 3rd user with even more weight so that user_1
            // doesn't immediately have an absolute majority
            let user_1_tokens = Tokens::from_tokens(30000).unwrap();
            let user_2_tokens = Tokens::from_tokens(10000).unwrap();
            let user_3_tokens = Tokens::from_tokens(40000).unwrap();
            let user_4_tokens = Tokens::from_tokens(1000).unwrap();
            let user_5_tokens = Tokens::from_tokens(1000).unwrap();

            let system_params = NervousSystemParameters {
                neuron_claimer_permissions: Some(NeuronPermissionList {
                    permissions: NeuronPermissionType::all(),
                }),
                initial_voting_period_seconds: Some(initial_initial_voting_period_seconds),
                wait_for_quiet_deadline_increase_seconds: Some(ONE_DAY_SECONDS / 8),
                ..NervousSystemParameters::with_default_values()
            };

            let sns_init_payload = SnsTestsInitPayloadBuilder::new()
                .with_ledger_account(user_1.get_principal_id().0.into(), user_1_tokens)
                .with_ledger_account(user_2.get_principal_id().0.into(), user_2_tokens)
                .with_ledger_account(user_3.get_principal_id().0.into(), user_3_tokens)
                .with_ledger_account(user_4.get_principal_id().0.into(), user_4_tokens)
                .with_ledger_account(user_5.get_principal_id().0.into(), user_5_tokens)
                .with_nervous_system_parameters(system_params.clone())
                .build();

            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await; // slow

            // Create neurons.
            let transaction_fee_e8s = system_params.transaction_fee_e8s();
            let stake_amount =
                Tokens::from_e8s(user_1_tokens.get_e8s() - transaction_fee_e8s).get_tokens();
            let user_1_neuron_id = sns_canisters
                .stake_and_claim_neuron_with_tokens(
                    &user_1,
                    Some(ONE_YEAR_SECONDS as u32),
                    stake_amount,
                )
                .await;
            let user_1_subaccount = user_1_neuron_id.subaccount().unwrap();

            let stake_amount =
                Tokens::from_e8s(user_2_tokens.get_e8s() - transaction_fee_e8s).get_tokens();
            let user_2_neuron_id = sns_canisters
                .stake_and_claim_neuron_with_tokens(
                    &user_2,
                    Some(ONE_YEAR_SECONDS as u32),
                    stake_amount,
                )
                .await;
            let user_2_subaccount = user_2_neuron_id.subaccount().unwrap();

            // Need a third neuron or the vote ends too soon
            let stake_amount =
                Tokens::from_e8s(user_3_tokens.get_e8s() - transaction_fee_e8s).get_tokens();
            let _user_3_neuron_id = sns_canisters
                .stake_and_claim_neuron_with_tokens(
                    &user_3,
                    Some(ONE_YEAR_SECONDS as u32),
                    stake_amount,
                )
                .await;

            // These two are required for the two inconsequential votes for process_proposal
            let stake_amount =
                Tokens::from_e8s(user_4_tokens.get_e8s() - transaction_fee_e8s).get_tokens();
            let user_4_neuron_id = sns_canisters
                .stake_and_claim_neuron_with_tokens(
                    &user_4,
                    Some(ONE_YEAR_SECONDS as u32),
                    stake_amount,
                )
                .await;
            let user_4_subaccount = user_4_neuron_id.subaccount().unwrap();

            let stake_amount =
                Tokens::from_e8s(user_5_tokens.get_e8s() - transaction_fee_e8s).get_tokens();
            let user_5_neuron_id = sns_canisters
                .stake_and_claim_neuron_with_tokens(
                    &user_5,
                    Some(ONE_YEAR_SECONDS as u32),
                    stake_amount,
                )
                .await;
            let user_5_subaccount = user_5_neuron_id.subaccount().unwrap();

            // Make a proposal.
            let proposal_id = sns_canisters
                .make_proposal(
                    &user_1,
                    &user_1_subaccount,
                    Proposal {
                        title: "We'll let a couple users vote, then wait to see when the proposal closes on its own".into(),
                        action: Some(Action::Motion(Motion::default())),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();

            {
                // Proposal hasn't been decided yet (nor has it been executed)
                let proposal = sns_canisters.get_proposal(proposal_id).await;
                assert_eq!(proposal.decided_timestamp_seconds, 0);
                assert_eq!(proposal.executed_timestamp_seconds, 0);
                // There should be a vote for yes (since voting `yes` for a
                // proposal you created is automatic)
                assert!(proposal.latest_tally.clone().unwrap().yes > 0);
                assert_eq!(proposal.latest_tally.unwrap().no, 0);
            }

            // User 2 votes against.
            sns_canisters
                .vote(
                    &user_2,
                    &user_2_subaccount,
                    proposal_id,
                    false, /* i.e. reject */
                )
                .await;

            {
                // Proposal still hasn't been decided yet (nor has it been executed)...
                let proposal = sns_canisters.get_proposal(proposal_id).await;
                assert_eq!(proposal.decided_timestamp_seconds, 0);
                assert_eq!(proposal.executed_timestamp_seconds, 0);
                // `yes` should be winning because we gave user_1 more voting weight than user_2.
                assert!(
                    proposal.latest_tally.clone().unwrap().yes > proposal.latest_tally.unwrap().no
                );
            }

            // Let's reduce the voting period in the sns parameters.
            // We're testing that this does not affect the existing proposal.
            sns_canisters
                .manage_nervous_system_parameters(
                    &user_1,
                    &user_1_subaccount,
                    NervousSystemParameters {
                        initial_voting_period_seconds: Some(ONE_DAY_SECONDS),
                        ..system_params
                    },
                )
                .await
                .expect("Expected updating NervousSystemParameters to succeed");

            // Now let's advance time three days, and assert that the
            // proposal hasn't been decided.
            let delta_s = ONE_DAY_SECONDS * 3;
            sns_canisters
                .set_time_warp(delta_s as i64)
                .await
                .expect("Expected set_time_warp to succeed");

            // Proposal should still not be decided, even though it's been
            // longer than the initial voting period.
            {
                // User 4 votes to accept, just to trigger process_proposal.
                sns_canisters
                    .vote(&user_4, &user_4_subaccount, proposal_id, true)
                    .await;

                let proposal = sns_canisters.get_proposal(proposal_id).await;
                let parameters = sns_canisters.get_nervous_system_parameters().await;
                let now_seconds = now_seconds(Some(delta_s));
                assert_eq!(proposal.decided_timestamp_seconds, 0);
                assert_eq!(proposal.executed_timestamp_seconds, 0);
                assert!(
                    proposal.proposal_creation_timestamp_seconds
                        + parameters.initial_voting_period_seconds.unwrap()
                        > now_seconds
                );
                // `proposal.initial_voting_period_seconds` should not have been modified from its initial value
                assert_eq!(
                    proposal.initial_voting_period_seconds,
                    initial_initial_voting_period_seconds
                );
                // Just double checking that the time that's passed and
                // the current `initial_voting_period_seconds` would be enough to
                // end the proposal
                assert!(
                    proposal.proposal_creation_timestamp_seconds
                        + proposal.initial_voting_period_seconds
                        > now_seconds
                );
            }

            // Now let's move time forward again, to a point where it should
            // have ended
            let delta_s = ONE_DAY_SECONDS * 10;
            sns_canisters
                .set_time_warp(delta_s as i64)
                .await
                .expect("Expected set_time_warp to succeed");

            {
                // User 5 votes to accept, just to trigger process_proposal.
                sns_canisters
                    .vote(&user_5, &user_5_subaccount, proposal_id, true)
                    .await;

                // Assert that the proposal has been accepted and executed.
                let proposal = sns_canisters.get_proposal(proposal_id).await;
                println!("{:#?}", proposal.latest_tally);
                assert_ne!(proposal.decided_timestamp_seconds, 0);
                assert_ne!(proposal.executed_timestamp_seconds, 0);
                // assert that it didn't just end because we got an absolute majority
                assert!(
                    proposal.latest_tally.clone().unwrap().yes * 2
                        < proposal.latest_tally.unwrap().total
                );
            }

            Ok(())
        }
    });
}
