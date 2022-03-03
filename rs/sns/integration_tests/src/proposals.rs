use std::time::{SystemTime, UNIX_EPOCH};

use dfn_candid::{candid, candid_one};
use ic_canister_client::Sender;
use ic_nns_constants::ids::{TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR, TEST_USER3_KEYPAIR};
use ic_sns_governance::pb::v1::get_proposal_response::Result::Error;
use ic_sns_governance::pb::v1::get_proposal_response::Result::Proposal as ResponseProposal;
use ic_sns_governance::pb::v1::governance_error::ErrorType;
use ic_sns_governance::pb::v1::governance_error::ErrorType::PreconditionFailed;
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::{
    GetProposal, GetProposalResponse, Motion, NervousSystemParameters, NeuronPermissionList,
    NeuronPermissionType, Proposal, ProposalId, Vote,
};
use ic_sns_governance::types::ONE_YEAR_SECONDS;
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder,
};
use ledger_canister::Tokens;
use on_wire::bytes;

/// Assert that Motion proposals can be submitted, voted on, and executed
#[test]
fn test_motion_proposal_execution() {
    local_test_on_sns_subnet(|runtime| {
        async move {
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let alloc = Tokens::from_tokens(1000).unwrap();

            let system_params = NervousSystemParameters {
                neuron_claimer_permissions: Some(NeuronPermissionList {
                    permissions: NeuronPermissionType::all(),
                }),
                ..NervousSystemParameters::with_default_values()
            };

            let sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user.get_principal_id().into(), alloc)
                .with_nervous_system_parameters(system_params)
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
                .await
                .unwrap();

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

/// Assert that ManageNervousSystemParameters proposals can be submitted, voted on, and executed
#[test]
fn test_manage_nervous_system_parameters_proposal_execution() {
    local_test_on_sns_subnet(|runtime| {
        async move {
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let alloc = Tokens::from_tokens(1000).unwrap();

            let sys_params = NervousSystemParameters {
                neuron_claimer_permissions: Some(NeuronPermissionList {
                    permissions: NeuronPermissionType::all(),
                }),
                ..NervousSystemParameters::with_default_values()
            };

            let sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user.get_principal_id().into(), alloc)
                .with_nervous_system_parameters(sys_params)
                .build();

            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            let neuron_id = sns_canisters
                .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
                .await;

            let subaccount = match neuron_id.subaccount() {
                Ok(s) => s,
                Err(e) => panic!("Error creating the subaccount, {}", e),
            };

            // Assert that invalid params are rejected on proposal submission
            let proposal_payload = Proposal {
                title: "Test invalid ManageNervousSystemParameters proposal".into(),
                action: Some(Action::ManageNervousSystemParameters(
                    NervousSystemParameters {
                        max_number_of_neurons: Some(
                            NervousSystemParameters::MAX_NUMBER_OF_NEURONS_CEILING + 1,
                        ),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            };

            let error = sns_canisters
                .make_proposal(&user, &subaccount, proposal_payload)
                .await
                .unwrap_err();

            assert_eq!(error.error_type, ErrorType::InvalidProposal as i32);

            // Assert that valid params cause Governance system parameters to be updated
            let proposal_payload = Proposal {
                title: "Test valid ManageNervousSystemParameters proposal".into(),
                action: Some(Action::ManageNervousSystemParameters(
                    NervousSystemParameters {
                        transaction_fee_e8s: Some(120_001),
                        neuron_minimum_stake_e8s: Some(398_002_900),
                        ..Default::default()
                    },
                )),
                ..Default::default()
            };

            // Submit a proposal. It should then be executed because the submitter
            // has a majority stake and submitting also votes automatically.
            let proposal_id = sns_canisters
                .make_proposal(&user, &subaccount, proposal_payload)
                .await
                .unwrap();

            let proposal = sns_canisters.get_proposal(proposal_id).await;

            assert_eq!(proposal.action, 2);
            assert_ne!(proposal.decided_timestamp_seconds, 0);
            assert_ne!(proposal.executed_timestamp_seconds, 0);

            let live_sys_params: NervousSystemParameters = sns_canisters
                .governance
                .query_("get_nervous_system_parameters", candid_one, ())
                .await?;

            assert_eq!(live_sys_params.transaction_fee_e8s, Some(120_001));
            assert_eq!(live_sys_params.neuron_minimum_stake_e8s, Some(398_002_900));

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

            let system_params = NervousSystemParameters {
                neuron_claimer_permissions: Some(NeuronPermissionList {
                    permissions: NeuronPermissionType::all(),
                }),
                ..NervousSystemParameters::with_default_values()
            };

            let sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user_1.get_principal_id().into(), tokens)
                .with_ledger_account(user_2.get_principal_id().into(), tokens)
                .with_ledger_account(user_3.get_principal_id().into(), tokens)
                .with_nervous_system_parameters(system_params)
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
                .await
                .unwrap();

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

#[test]
fn test_bad_proposal_id_candid_type() {
    local_test_on_sns_subnet(|runtime| {
        async move {
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let alloc = Tokens::from_tokens(1000).unwrap();

            let sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user.get_principal_id().into(), alloc)
                .build();
            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            // get_proposal requires a ProposalId argument. Here instead the caller is
            // sending a PrincipalId. This is also valid Candid, but with the
            // wrong type.
            let res: Result<Option<GetProposalResponse>, String> = sns_canisters
                .governance
                .query_("get_proposal", candid, (user.get_principal_id(),))
                .await;
            match res {
                Err(e) => assert!(e.contains("Fail to decode argument")),
                Ok(_) => panic!("get_proposal should fail to decode argument"),
            };

            Ok(())
        }
    });
}

#[test]
fn test_bad_proposal_id_candid_encoding() {
    local_test_on_sns_subnet(|runtime| {
        async move {
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let alloc = Tokens::from_tokens(1000).unwrap();

            let sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user.get_principal_id().into(), alloc)
                .build();
            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            let res: Result<Vec<u8>, String> = sns_canisters
                .governance
                .query_("get_proposal", bytes, b"This is not valid candid!".to_vec())
                .await;

            match res {
                Err(e) => assert!(e.contains("Deserialization Failed")),
                Ok(_) => panic!("get_proposal should fail to deserialize"),
            };
            Ok(())
        }
    });
}

#[test]
fn test_non_existent_proposal_id_is_not_a_bad_input() {
    local_test_on_sns_subnet(|runtime| {
        async move {
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let alloc = Tokens::from_tokens(1000).unwrap();

            let sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user.get_principal_id().into(), alloc)
                .build();
            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            let req = GetProposal {
                proposal_id: Some(ProposalId { id: 23 }),
            };

            // There is no proposal 23. This should return and error
            let res: Result<Option<GetProposalResponse>, String> = sns_canisters
                .governance
                .query_("get_proposal", candid, (req,))
                .await;

            let get_proposal_response = res.unwrap().unwrap().result.unwrap();
            match get_proposal_response {
                Error(e) => assert_eq!(e.error_type, PreconditionFailed as i32),
                ResponseProposal(_) => {
                    panic!("Proposal does not exist. get_proposal should return an error")
                }
            };
            Ok(())
        }
    });
}
