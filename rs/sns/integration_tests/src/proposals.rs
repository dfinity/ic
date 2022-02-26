use std::time::{SystemTime, UNIX_EPOCH};

use ic_canister_client::Sender;
use ic_nns_constants::ids::{TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR, TEST_USER3_KEYPAIR};
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::{Motion, Proposal, Vote};
use ic_sns_governance::types::ONE_YEAR_SECONDS;
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder,
};
use ledger_canister::Tokens;

/// Assert that Motion proposals can be submitted, voted on, and executed
#[test]
fn test_motion_proposal_execution() {
    local_test_on_sns_subnet(|runtime| {
        async move {
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);

            let alloc = Tokens::from_tokens(1000).unwrap();
            let sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user.get_principal_id().into(), alloc)
                .build();

            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            let neuron_id = sns_canisters
                .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
                .await;

            let subaccount = match neuron_id.subaccount() {
                Ok(s) => s,
                Err(e) => panic!("Error creating the subaccount, {}", e),
            };

            let proposal_payload = Proposal {
                title: "Test Motion proposal".into(),
                action: Some(Action::Motion(Motion {
                    motion_text: "Spoon".into(),
                })),
                ..Default::default()
            };

            // Submit a motion proposal. It should then be executed because the
            // submitter has a majority stake and submitting also votes automatically.
            let proposal_id = sns_canisters
                .make_proposal(&user, &subaccount, proposal_payload)
                .await;

            let proposal = sns_canisters.get_proposal(proposal_id).await;

            assert_eq!(proposal.action, 1);
            assert_ne!(proposal.decided_timestamp_seconds, 0);
            assert_ne!(proposal.executed_timestamp_seconds, 0);

            match proposal.proposal.unwrap().action.unwrap() {
                Action::Motion(motion) => {
                    assert_eq!(motion.motion_text, "Spoon".to_string());
                }
                _ => panic!("Proposal has unexpected action"),
            }

            assert_eq!(proposal.ballots.len(), 1);
            let (ballot_neuron_id, _ballot) = proposal.ballots.iter().next().unwrap();
            assert_eq!(*ballot_neuron_id, neuron_id.to_string());

            Ok(())
        }
    })
}

#[test]
fn test_voting_with_three_neurons_with_the_same_stake() {
    fn now_seconds() -> f64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64()
    }

    local_test_on_sns_subnet(|runtime| {
        async move {
            // Initialize the ledger with three users (each will create its own neuron).
            let user_1 = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let user_2 = Sender::from_keypair(&TEST_USER2_KEYPAIR);
            let user_3 = Sender::from_keypair(&TEST_USER3_KEYPAIR);

            let tokens = Tokens::from_tokens(1000).unwrap();
            let sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user_1.get_principal_id().into(), tokens)
                .with_ledger_account(user_2.get_principal_id().into(), tokens)
                .with_ledger_account(user_3.get_principal_id().into(), tokens)
                .build();

            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            // Create neurons.
            let user_1_neuron_id = sns_canisters
                .stake_and_claim_neuron(&user_1, Some(ONE_YEAR_SECONDS as u32))
                .await;
            let user_1_subaccount = user_1_neuron_id.subaccount().unwrap();

            let user_2_neuron_id = sns_canisters
                .stake_and_claim_neuron(&user_2, Some(ONE_YEAR_SECONDS as u32))
                .await;
            let user_2_subaccount = user_2_neuron_id.subaccount().unwrap();

            let user_3_neuron_id = sns_canisters
                .stake_and_claim_neuron(&user_3, Some(ONE_YEAR_SECONDS as u32))
                .await;
            let user_3_subaccount = user_3_neuron_id.subaccount().unwrap();

            // Make a proposal.
            let proposal_id = sns_canisters
                .make_proposal(
                    &user_1,
                    &user_1_subaccount,
                    Proposal {
                        title: "This time, we need more than one user to vote".into(),
                        action: Some(Action::Motion(Motion {
                            motion_text: "Make the Internet Computer AMAZING!".into(),
                        })),
                        ..Default::default()
                    },
                )
                .await;

            // Proposal hasn't been decided yet (nor has it been executed).
            let proposal = sns_canisters.get_proposal(proposal_id).await;
            assert_eq!(proposal.decided_timestamp_seconds, 0);
            assert_eq!(proposal.executed_timestamp_seconds, 0);

            // User 2 votes against.
            sns_canisters
                .vote(
                    &user_2,
                    &user_2_subaccount,
                    proposal_id,
                    false, /* i.e. reject */
                )
                .await;

            // Proposal still hasn't been decided yet
            let proposal = sns_canisters.get_proposal(proposal_id).await;
            assert_eq!(proposal.decided_timestamp_seconds, 0);
            assert_eq!(proposal.executed_timestamp_seconds, 0);

            // Finally, the last user (user_3) votes in favor of the proposal,
            // pushing it past the finish line with 2/3 of the voting power in
            // favor.
            sns_canisters
                .vote(
                    &user_3,
                    &user_3_subaccount,
                    proposal_id,
                    true, /* i.e. accept */
                )
                .await;

            // Assert that the proposal has been accepted and executed.
            let proposal = sns_canisters.get_proposal(proposal_id).await;
            assert_ne!(proposal.decided_timestamp_seconds, 0);
            assert_ne!(proposal.executed_timestamp_seconds, 0);

            // Inspect the ballots.
            let ballots = &proposal.ballots;
            assert_eq!(ballots.len(), 3, "{:?}", ballots);
            for (neuron_id, accept) in [
                (user_1_neuron_id, true),
                (user_2_neuron_id, false),
                (user_3_neuron_id, true),
            ] {
                let ballot = ballots.get(&neuron_id.to_string()).unwrap();
                let vote = if accept { Vote::Yes } else { Vote::No };
                assert_eq!(ballot.vote, vote as i32);

                // Inspect ballot ages.
                let age_seconds = now_seconds() - ballot.cast_timestamp_seconds as f64;
                assert!(
                    0.0 < age_seconds,
                    "age_seconds = {}. ballot = {:?}",
                    age_seconds,
                    ballot
                );
                assert!(
                    age_seconds < 5.0,
                    "age_seconds = {}. ballot = {:?}",
                    age_seconds,
                    ballot
                );
            }

            // Inspect tally.
            {
                let tally = &proposal.latest_tally.as_ref().unwrap();

                let total = tally.total as f64;
                let yes = tally.yes as f64;
                let no = tally.no as f64;

                // In this scenario, these happen add up to 1.0, because all the
                // voting power has voted, but in general, that need not be the
                // case. E.g. majority is achieved before everyone votes, or time
                // runs out.
                let approval_rating = yes / total;
                let disapproval_rating = no / total;

                let epsilon = 1e-9;
                assert!(
                    (2.0 / 3.0 - approval_rating).abs() < epsilon,
                    "{:?}",
                    proposal
                );
                assert!(
                    (1.0 / 3.0 - disapproval_rating).abs() < epsilon,
                    "{:?}",
                    proposal
                );
            }

            Ok(())
        }
    });
}
