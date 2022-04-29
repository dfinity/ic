use canister_test::Canister;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use dfn_candid::{candid, candid_one};
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::{
    TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR, TEST_USER3_KEYPAIR, TEST_USER4_KEYPAIR,
};
use ic_sns_governance::pb::v1::get_proposal_response::Result::Error;
use ic_sns_governance::pb::v1::get_proposal_response::Result::Proposal as ResponseProposal;
use ic_sns_governance::pb::v1::governance_error::ErrorType;
use ic_sns_governance::pb::v1::governance_error::ErrorType::PreconditionFailed;
use ic_sns_governance::pb::v1::manage_neuron_response::Command;
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::{
    Ballot, GetProposal, GetProposalResponse, ListProposals, ListProposalsResponse,
    ManageNeuronResponse, Motion, NervousSystemParameters, NeuronId, NeuronPermissionList,
    NeuronPermissionType, Proposal, ProposalData, ProposalDecisionStatus, ProposalId, Vote,
};
use ic_sns_governance::proposal::{
    PROPOSAL_MOTION_TEXT_BYTES_MAX, PROPOSAL_SUMMARY_BYTES_MAX, PROPOSAL_TITLE_BYTES_MAX,
    PROPOSAL_URL_CHAR_MAX,
};
use ic_sns_governance::types::{ONE_DAY_SECONDS, ONE_MONTH_SECONDS, ONE_YEAR_SECONDS};
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder, UserInfo,
};
use ledger_canister::{AccountIdentifier, Tokens};
use on_wire::bytes;

const MOTION_PROPOSAL_ACTION_TYPE: u64 = 1;

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
                .with_nervous_system_parameters(system_params.clone())
                .build();

            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            let neuron_id = sns_canisters
                .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
                .await;

            let subaccount = neuron_id
                .subaccount()
                .expect("Error creating the subaccount");

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

            let proposal_data = sns_canisters.get_proposal(proposal_id).await;

            assert_eq!(proposal_data.action, 1);
            assert_ne!(proposal_data.decided_timestamp_seconds, 0);
            assert_ne!(proposal_data.executed_timestamp_seconds, 0);

            match proposal_data.proposal.unwrap().action.unwrap() {
                Action::Motion(motion) => {
                    assert_eq!(motion.motion_text, "Spoon".to_string());
                }
                _ => panic!("Proposal has unexpected action"),
            }

            assert_eq!(proposal_data.ballots.len(), 1);
            let (ballot_neuron_id, _ballot) = proposal_data.ballots.iter().next().unwrap();
            assert_eq!(*ballot_neuron_id, neuron_id.to_string());

            // ProposalData.executed_timestamp_seconds is not set until the end of the voting period.
            // Use TimeWarp to shift time to the end of the voting period for this proposal.
            let initial_voting_period = system_params.initial_voting_period.unwrap();
            let delta_s = (initial_voting_period + 1) as i64;
            sns_canisters
                .set_time_warp(delta_s)
                .await
                .expect("Expected set_time_warp to succeed");

            let proposal_data = sns_canisters.get_proposal(proposal_id).await;
            // Assert the proposal is accepted and executed.
            assert!(proposal_data.decided_timestamp_seconds > 0);
            assert!(proposal_data.executed_timestamp_seconds > 0);
            assert_eq!(proposal_data.failure_reason, None);
            assert_eq!(proposal_data.failed_timestamp_seconds, 0);
            assert_eq!(
                proposal_data.status(),
                ProposalDecisionStatus::ProposalStatusExecuted
            );

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

            let subaccount = neuron_id
                .subaccount()
                .expect("Error creating the subaccount");

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
                    age_seconds < 30.0,
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

                // This may seem a bit generous, but it's actually hard to
                // precisely predict neuron voting power, because it slowly
                // grows over time.
                let epsilon = 10.0e-9;
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

#[test]
fn test_list_proposals_determinism() {
    local_test_on_sns_subnet(|runtime| async move {
        // Initialize the ledger with an account for a user.
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let alloc = Tokens::from_tokens(1000).unwrap();
        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(user.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params)
            .build();
        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let neuron_id = sns_canisters
            .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
            .await;

        let subaccount = neuron_id
            .subaccount()
            .expect("Error creating the subaccount");

        let mut proposals = vec![];
        for i in 0..10 {
            proposals.push(Proposal {
                title: format!("Test Motion proposal-{}", i),
                action: Some(Action::Motion(Motion {
                    motion_text: format!("Motion-{}", i),
                })),
                ..Default::default()
            });
        }

        for proposal in proposals {
            sns_canisters
                .make_proposal(&user, &subaccount, proposal)
                .await
                .unwrap();
        }

        let list_proposal_response: ListProposalsResponse = sns_canisters
            .governance
            .query_from_sender(
                "list_proposals",
                candid_one,
                ListProposals {
                    limit: 20,
                    before_proposal: None,
                    ..Default::default()
                },
                &user,
            )
            .await
            .expect("Error calling the list_proposals api");

        let expected = list_proposal_response.proposals;
        let actual =
            list_all_proposals_through_pagination(&sns_canisters.governance, &user, 1_usize).await;

        assert_eq!(expected, actual);

        Ok(())
    });
}

async fn list_all_proposals_through_pagination(
    governance_canister: &Canister<'_>,
    user: &Sender,
    limit: usize,
) -> Vec<ProposalData> {
    let mut all_proposals = vec![];
    let mut last_proposal_id: Option<ProposalId> = None;

    loop {
        let list_proposals_response: ListProposalsResponse = governance_canister
            .query_from_sender(
                "list_proposals",
                candid_one,
                ListProposals {
                    limit: limit as u32,
                    before_proposal: last_proposal_id,
                    ..Default::default()
                },
                user,
            )
            .await
            .expect("Error calling the list_proposals api");

        let len = list_proposals_response.proposals.len();
        let is_last = len < limit;
        assert!(len <= limit);

        if !list_proposals_response.proposals.is_empty() {
            last_proposal_id = Some(
                *list_proposals_response.proposals[list_proposals_response.proposals.len() - 1]
                    .id
                    .as_ref()
                    .unwrap(),
            );
            all_proposals.extend(list_proposals_response.proposals);
        }

        if is_last {
            return all_proposals;
        }
    }
}

#[test]
fn test_proposal_format_validation() {
    local_test_on_sns_subnet(|runtime| async move {
        // Initialize the ledger with an account for a user.
        let user = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));

        let alloc = Tokens::from_tokens(1000).unwrap();
        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(user.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params)
            .build();
        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        sns_canisters
            .stake_and_claim_neuron(&user.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // Create a proposal with an illegal number of characters in the motion text
        let mut proposal = Proposal {
            action: Some(Action::Motion(Motion {
                motion_text: "X".repeat(PROPOSAL_MOTION_TEXT_BYTES_MAX + 1),
            })),
            ..Default::default()
        };

        // Submit a proposal and expect an error
        let expected_error = sns_canisters
            .make_proposal(&user.sender, &user.subaccount, proposal.clone())
            .await
            .expect_err("Expected make_proposal to error");

        assert_eq!(expected_error.error_type, ErrorType::InvalidProposal as i32);

        // Set the motion text to default and update the proposal with an illegal number of
        // characters in the proposal title
        proposal.action = Some(Action::Motion(Motion {
            motion_text: String::from(""),
        }));
        proposal.title = "X".repeat(PROPOSAL_TITLE_BYTES_MAX + 1);

        // Submit a proposal and expect an error
        let expected_error = sns_canisters
            .make_proposal(&user.sender, &user.subaccount, proposal.clone())
            .await
            .expect_err("Expected make_proposal to error");

        assert_eq!(expected_error.error_type, ErrorType::InvalidProposal as i32);

        // Set the title text to default and update the proposal with an illegal number of
        // characters in the proposal summary
        proposal.title = String::from("");
        proposal.summary = "X".repeat(PROPOSAL_SUMMARY_BYTES_MAX + 1);

        // Submit a proposal and expect an error
        let expected_error = sns_canisters
            .make_proposal(&user.sender, &user.subaccount, proposal.clone())
            .await
            .expect_err("Expected make_proposal to error");

        assert_eq!(expected_error.error_type, ErrorType::InvalidProposal as i32);

        // Set the summary text to default and update the proposal with an illegal number of
        // characters in the proposal url
        proposal.summary = String::from("");
        proposal.url = "X".repeat(PROPOSAL_URL_CHAR_MAX + 1);

        // Submit a proposal and expect an error
        let expected_error = sns_canisters
            .make_proposal(&user.sender, &user.subaccount, proposal.clone())
            .await
            .expect_err("Expected make_proposal to error");

        assert_eq!(expected_error.error_type, ErrorType::InvalidProposal as i32);

        // The proposal should now be created with a legal amount of characters
        proposal.url = String::from("");

        let proposal_id = sns_canisters
            .make_proposal(&user.sender, &user.subaccount, proposal.clone())
            .await
            .expect("Proposal is valid and should not have errored.");

        let expected_proposal = sns_canisters
            .get_proposal(proposal_id)
            .await
            .proposal
            .expect("Expected a proposal to be returned");

        assert_eq!(proposal, expected_proposal);

        Ok(())
    });
}

#[test]
fn test_neuron_configuration_needed_for_proposals() {
    local_test_on_sns_subnet(|runtime| async move {
        // Initialize the ledger with an account for a user.
        let user = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();
        let neuron_minimum_dissolve_delay_to_vote_seconds = ONE_YEAR_SECONDS;

        // Create the SNS with NervousSystemParameters that require neurons to have a minimum
        // dissolve delay of 1 year to be able to vote and make proposals
        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            neuron_minimum_dissolve_delay_to_vote_seconds: Some(
                neuron_minimum_dissolve_delay_to_vote_seconds,
            ),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(user.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake the neuron with only 1 governance token (100000000 e8s) and the
        // dissolve delay set to 1 month.
        sns_canisters
            .stake_and_claim_neuron_with_tokens(&user.sender, Some(ONE_MONTH_SECONDS as u32), 1)
            .await;

        let proposal = Proposal {
            action: Some(Action::Motion(Motion {
                motion_text: String::from(""),
            })),
            ..Default::default()
        };

        // Submitting a proposal should fail if the dissolve delay is not set greater than or
        // equal to neuron_minimum_dissolve_delay_to_vote_seconds
        let expected_error = sns_canisters
            .make_proposal(&user.sender, &user.subaccount, proposal.clone())
            .await
            .expect_err("Expected make_proposal to error");

        assert_eq!(
            expected_error.error_type,
            ErrorType::PreconditionFailed as i32
        );

        // Increase the dissolve delay to the value required by NervousSystemParameters
        sns_canisters
            .increase_dissolve_delay(
                &user.sender,
                &user.subaccount,
                neuron_minimum_dissolve_delay_to_vote_seconds as u32,
            )
            .await;

        // After increasing the dissolve delay, submitting a proposal should succeed for the neuron
        sns_canisters
            .make_proposal(&user.sender, &user.subaccount, proposal.clone())
            .await
            .expect("Expected make_proposal to succeed");

        // Update the NervousSystemParameters to contain a reject_cost_e8s greater than the
        // amount staked in the neuron
        let update_to_nervous_system_params = NervousSystemParameters {
            reject_cost_e8s: Some(200_000_000),
            ..Default::default()
        };

        sns_canisters
            .manage_nervous_system_parameters(
                &user.sender,
                &user.subaccount,
                update_to_nervous_system_params,
            )
            .await
            .expect("Expected updating NervousSystemParameters to succeed");

        // Submitting a proposal should fail due to the minimum stake not being greater
        // than reject_costs_e8s
        let expected_error = sns_canisters
            .make_proposal(&user.sender, &user.subaccount, proposal.clone())
            .await
            .expect_err("Expected make_proposal to error");

        assert_eq!(
            expected_error.error_type,
            ErrorType::PreconditionFailed as i32
        );

        // A second call to the claim_neuron api with 1 token (100000000 e8s) will refresh
        // the neuron with the additional stake, bringing the stake of the neuron
        // above the minimum needed in NervousSystemParameters.reject_cost_e8s
        sns_canisters
            .stake_and_claim_neuron_with_tokens(&user.sender, None, 1)
            .await;

        // Submitting a proposal should now succeed
        let proposal_id = sns_canisters
            .make_proposal(&user.sender, &user.subaccount, proposal.clone())
            .await
            .expect("The neuron's state is valid and make_proposal should not have errored.");

        let expected_proposal = sns_canisters
            .get_proposal(proposal_id)
            .await
            .proposal
            .expect("Expected a proposal to be returned");

        assert_eq!(proposal, expected_proposal);

        Ok(())
    });
}

#[test]
fn test_ballots_set_for_multiple_neurons() {
    local_test_on_sns_subnet(|runtime| async move {
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let users = vec![
            UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR)),
            UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR)),
            UserInfo::new(Sender::from_keypair(&TEST_USER3_KEYPAIR)),
            UserInfo::new(Sender::from_keypair(&TEST_USER4_KEYPAIR)),
        ];

        let account_identifiers = users
            .iter()
            .map(|user| AccountIdentifier::from(user.sender.get_principal_id()))
            .collect();

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_accounts(account_identifiers, alloc)
            .with_nervous_system_parameters(params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        for user in &users {
            sns_canisters
                .stake_and_claim_neuron(&user.sender, Some(ONE_YEAR_SECONDS as u32))
                .await;
        }

        // Just need a single user to be the proposer
        let proposer = users[0].clone();

        let proposal = Proposal {
            action: Some(Action::Motion(Motion {
                motion_text: String::from(""),
            })),
            ..Default::default()
        };

        let proposal_id = sns_canisters
            .make_proposal(&proposer.sender, &proposer.subaccount, proposal)
            .await
            .expect("Expected make_proposal to succeed");

        let proposal = sns_canisters.get_proposal(proposal_id).await;

        // Given that all neurons are able to vote, there should be a ballot for each one
        let ballots = proposal.ballots;
        assert_eq!(ballots.len(), users.len());

        for user in users {
            let neuron_id = user.neuron_id;
            // Assert that all neuron_ids are accounted for, and that each ballot has voting power
            let ballot = ballots
                .get(neuron_id.to_string().as_str())
                .expect("Expected NeuronId to have a ballot");
            assert!(ballot.voting_power > 0);

            // The neuron of the proposer automatically voted after proposal submission
            if neuron_id == proposer.neuron_id {
                assert_eq!(ballot.vote, Vote::Yes as i32);
                assert!(ballot.cast_timestamp_seconds > 0);
            // The rest should be unspecified
            } else {
                assert_eq!(ballot.vote, Vote::Unspecified as i32);
                assert_eq!(ballot.cast_timestamp_seconds, 0)
            }
        }

        let neuron = sns_canisters.get_neuron(&proposer.neuron_id).await;

        // The proposer should be docked the correct amount of fees
        assert_eq!(neuron.neuron_fees_e8s, params.reject_cost_e8s.unwrap());

        Ok(())
    });
}

#[test]
fn test_vote_on_non_existent_proposal() {
    local_test_on_sns_subnet(|runtime| async move {
        // Initialize the ledger with an account for a user.
        let user = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(user.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        sns_canisters
            .stake_and_claim_neuron(&user.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // Voting on a non-existent proposal should produce an error
        let vote_response = sns_canisters
            .vote(&user.sender, &user.subaccount, ProposalId { id: 1 }, true)
            .await;

        let expected_error = match vote_response.command.unwrap() {
            Command::RegisterVote(_) => {
                panic!("Registering vote on non-existent proposal should fail")
            }
            Command::Error(err) => err,
            response => panic!(
                "Unexpected response when registering a vote: {:?}",
                response
            ),
        };

        assert_eq!(expected_error.error_type, ErrorType::NotFound as i32);

        Ok(())
    });
}

#[test]
fn test_ineligible_neuron_voting_fails() {
    local_test_on_sns_subnet(|runtime| async move {
        // Initialize the ledger with an account for a user who will propose and a user who will vote
        let proposer = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let voter = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(proposer.sender.get_principal_id().into(), alloc)
            .with_ledger_account(voter.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron for the proposer
        sns_canisters
            .stake_and_claim_neuron(&proposer.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        let proposal = Proposal {
            action: Some(Action::Motion(Motion {
                motion_text: String::from(""),
            })),
            ..Default::default()
        };

        // Submit the proposal before the voting neuron is staked so it is not included in the
        // ballot calculation
        let proposal_id = sns_canisters
            .make_proposal(&proposer.sender, &proposer.subaccount, proposal)
            .await
            .expect("Expected make_proposal to succeed");

        sns_canisters
            .stake_and_claim_neuron(&voter.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        let response = sns_canisters
            .vote(&voter.sender, &voter.subaccount, proposal_id, true)
            .await;

        assert_voting_error(&response, ErrorType::NotAuthorized);

        Ok(())
    });
}

#[test]
fn test_repeated_voting_fails() {
    local_test_on_sns_subnet(|runtime| async move {
        let yes_voter = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let no_voter = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));

        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(yes_voter.sender.get_principal_id().into(), alloc)
            .with_ledger_account(no_voter.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron for the proposer who will vote yes
        sns_canisters
            .stake_and_claim_neuron(&yes_voter.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // Stake and claim a neuron for the voter who will vote no
        sns_canisters
            .stake_and_claim_neuron(&no_voter.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        let proposal = Proposal {
            action: Some(Action::Motion(Motion {
                motion_text: String::from(""),
            })),
            ..Default::default()
        };

        // Submit the proposal which will result in a yes vote from the yes_voter user
        let proposal_id = sns_canisters
            .make_proposal(&yes_voter.sender, &yes_voter.subaccount, proposal)
            .await
            .expect("Expected make_proposal to succeed");

        // Submit a No vote for the no_voter
        sns_canisters
            .vote(&no_voter.sender, &no_voter.subaccount, proposal_id, false)
            .await;

        let proposal_data = sns_canisters.get_proposal(proposal_id).await;

        let ballots = proposal_data.ballots;
        assert_ballot_is_cast(&ballots, &yes_voter.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &no_voter.neuron_id, Vote::No);

        // Voting no again should fail
        let response = sns_canisters
            .vote(&no_voter.sender, &no_voter.subaccount, proposal_id, false)
            .await;

        assert_voting_error(&response, ErrorType::PreconditionFailed);

        // Changing a vote to yes should fail as well
        let response = sns_canisters
            .vote(&no_voter.sender, &no_voter.subaccount, proposal_id, true)
            .await;

        assert_voting_error(&response, ErrorType::PreconditionFailed);

        // Voting yes again should fail
        let response = sns_canisters
            .vote(&yes_voter.sender, &yes_voter.subaccount, proposal_id, true)
            .await;

        assert_voting_error(&response, ErrorType::PreconditionFailed);

        // Changing a vote to no should fail as well
        let response = sns_canisters
            .vote(&yes_voter.sender, &yes_voter.subaccount, proposal_id, false)
            .await;

        assert_voting_error(&response, ErrorType::PreconditionFailed);

        // Get the ballots after all the failed revoting to assert nothing has changed since
        // the original votes
        let proposal_data = sns_canisters.get_proposal(proposal_id).await;
        assert_eq!(proposal_data.ballots, ballots);

        Ok(())
    });
}

// This test will create a follow graph and verify that when voting the correct ballots will be
// cast as a result of follow relationships. The follow graph will look like this:
//
//   A <- B <- C
//         \
//          D
#[test]
fn test_following_and_voting() {
    local_test_on_sns_subnet(|runtime| async move {
        let a = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let b = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));
        let c = UserInfo::new(Sender::from_keypair(&TEST_USER3_KEYPAIR));
        let d = UserInfo::new(Sender::from_keypair(&TEST_USER4_KEYPAIR));

        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(a.sender.get_principal_id().into(), alloc)
            .with_ledger_account(b.sender.get_principal_id().into(), alloc)
            .with_ledger_account(c.sender.get_principal_id().into(), alloc)
            .with_ledger_account(d.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        sns_canisters
            .stake_and_claim_neuron(&a.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;
        sns_canisters
            .stake_and_claim_neuron(&b.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;
        sns_canisters
            .stake_and_claim_neuron(&c.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;
        sns_canisters
            .stake_and_claim_neuron(&d.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // The follow graph being created in the next block
        //
        //   A <- B <- C
        //         \
        //          D
        sns_canisters
            .follow(
                &d.sender,
                &d.subaccount,
                vec![b.neuron_id.clone()],
                MOTION_PROPOSAL_ACTION_TYPE,
            )
            .await;

        sns_canisters
            .follow(
                &c.sender,
                &c.subaccount,
                vec![b.neuron_id.clone()],
                MOTION_PROPOSAL_ACTION_TYPE,
            )
            .await;

        sns_canisters
            .follow(
                &b.sender,
                &b.subaccount,
                vec![a.neuron_id.clone()],
                MOTION_PROPOSAL_ACTION_TYPE,
            )
            .await;

        let proposal = Proposal {
            action: Some(Action::Motion(Motion {
                motion_text: String::from(""),
            })),
            ..Default::default()
        };

        // Submit the proposal with the A neuron which should result in all neurons voting yes
        let proposal_id = sns_canisters
            .make_proposal(&a.sender, &a.subaccount, proposal.clone())
            .await
            .expect("Expected make_proposal to succeed");

        let proposal_data = sns_canisters.get_proposal(proposal_id).await;
        let ballots = proposal_data.ballots;
        assert_ballot_is_cast(&ballots, &a.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &b.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &c.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &d.neuron_id, Vote::Yes);

        // Submit the proposal with the B neuron which should result in all except A voting yes
        let proposal_id = sns_canisters
            .make_proposal(&b.sender, &b.subaccount, proposal.clone())
            .await
            .expect("Expected make_proposal to succeed");

        let proposal_data = sns_canisters.get_proposal(proposal_id).await;
        let ballots = proposal_data.ballots;
        assert_ballot_is_cast(&ballots, &a.neuron_id, Vote::Unspecified);
        assert_ballot_is_cast(&ballots, &b.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &c.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &d.neuron_id, Vote::Yes);

        // Submit the proposal with the C neuron which should result in only C voting yes
        let proposal_id = sns_canisters
            .make_proposal(&c.sender, &c.subaccount, proposal.clone())
            .await
            .expect("Expected make_proposal to succeed");

        let proposal_data = sns_canisters.get_proposal(proposal_id).await;
        let ballots = proposal_data.ballots;
        assert_ballot_is_cast(&ballots, &a.neuron_id, Vote::Unspecified);
        assert_ballot_is_cast(&ballots, &b.neuron_id, Vote::Unspecified);
        assert_ballot_is_cast(&ballots, &c.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &d.neuron_id, Vote::Unspecified);

        Ok(())
    });
}

// This test will create a follow graph and verify that when voting the correct ballots will be
// cast as a result of follow relationships. The follow graph will look like this:
//
//   A
//
//   B <- C
#[test]
fn test_following_and_voting_from_non_proposer() {
    local_test_on_sns_subnet(|runtime| async move {
        let a = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let b = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));
        let c = UserInfo::new(Sender::from_keypair(&TEST_USER3_KEYPAIR));

        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(a.sender.get_principal_id().into(), alloc)
            .with_ledger_account(b.sender.get_principal_id().into(), alloc)
            .with_ledger_account(c.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        sns_canisters
            .stake_and_claim_neuron(&a.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;
        sns_canisters
            .stake_and_claim_neuron(&b.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;
        sns_canisters
            .stake_and_claim_neuron(&c.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // The follow graph being created in the next block
        //
        //   A
        //
        //   B <- C
        sns_canisters
            .follow(
                &c.sender,
                &c.subaccount,
                vec![b.neuron_id.clone()],
                MOTION_PROPOSAL_ACTION_TYPE,
            )
            .await;

        let proposal = Proposal {
            action: Some(Action::Motion(Motion {
                motion_text: String::from(""),
            })),
            ..Default::default()
        };

        // Submit the proposal with the A neuron which should result in just A voting yes
        let proposal_id = sns_canisters
            .make_proposal(&a.sender, &a.subaccount, proposal.clone())
            .await
            .expect("Expected make_proposal to succeed");

        let proposal_data = sns_canisters.get_proposal(proposal_id).await;
        let ballots = proposal_data.ballots;
        assert_ballot_is_cast(&ballots, &a.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &b.neuron_id, Vote::Unspecified);
        assert_ballot_is_cast(&ballots, &c.neuron_id, Vote::Unspecified);

        // Submit a No vote with the B which should result in the B Neuron and the C Neuron voting No
        sns_canisters
            .vote(&b.sender, &b.subaccount, proposal_id, false)
            .await;

        let proposal_data = sns_canisters.get_proposal(proposal_id).await;
        let ballots = proposal_data.ballots;
        assert_ballot_is_cast(&ballots, &a.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &b.neuron_id, Vote::No);
        assert_ballot_is_cast(&ballots, &c.neuron_id, Vote::No);

        Ok(())
    });
}

// This test will create a follow graph and verify that when voting the correct ballots will be
// cast as a result of follow relationships. The follow graph will look like this:
//
//   A
//     \
//   B <--- D
//     /
//   C
#[test]
fn test_following_multiple_neurons_reach_majority() {
    local_test_on_sns_subnet(|runtime| async move {
        let a = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let b = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));
        let c = UserInfo::new(Sender::from_keypair(&TEST_USER3_KEYPAIR));
        let d = UserInfo::new(Sender::from_keypair(&TEST_USER4_KEYPAIR));

        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(a.sender.get_principal_id().into(), alloc)
            .with_ledger_account(b.sender.get_principal_id().into(), alloc)
            .with_ledger_account(c.sender.get_principal_id().into(), alloc)
            .with_ledger_account(d.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        sns_canisters
            .stake_and_claim_neuron(&a.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;
        sns_canisters
            .stake_and_claim_neuron(&b.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;
        sns_canisters
            .stake_and_claim_neuron(&c.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;
        sns_canisters
            .stake_and_claim_neuron(&d.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // The follow graph being created in the next block
        //
        //   A
        //     \
        //   B <--- D
        //     /
        //   C
        sns_canisters
            .follow(
                &d.sender,
                &d.subaccount,
                vec![
                    c.neuron_id.clone(),
                    b.neuron_id.clone(),
                    a.neuron_id.clone(),
                ],
                MOTION_PROPOSAL_ACTION_TYPE,
            )
            .await;

        let proposal = Proposal {
            action: Some(Action::Motion(Motion {
                motion_text: String::from(""),
            })),
            ..Default::default()
        };

        // Submit the proposal with the A neuron which should result in A voting yes, and D staying
        // unspecified as a majority of it's followees haven't reached consensus
        let proposal_id = sns_canisters
            .make_proposal(&a.sender, &a.subaccount, proposal.clone())
            .await
            .expect("Expected make_proposal to succeed");

        let proposal_data = sns_canisters.get_proposal(proposal_id).await;
        let ballots = proposal_data.ballots;
        assert_ballot_is_cast(&ballots, &a.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &b.neuron_id, Vote::Unspecified);
        assert_ballot_is_cast(&ballots, &c.neuron_id, Vote::Unspecified);
        assert_ballot_is_cast(&ballots, &d.neuron_id, Vote::Unspecified);

        // Submit a No vote with the B Neuron which should result in B voting No, and D staying
        // unspecified as a majority of it's followees haven't reached consensus
        sns_canisters
            .vote(&b.sender, &b.subaccount, proposal_id, false)
            .await;

        let proposal_data = sns_canisters.get_proposal(proposal_id).await;
        let ballots = proposal_data.ballots;
        assert_ballot_is_cast(&ballots, &a.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &b.neuron_id, Vote::No);
        assert_ballot_is_cast(&ballots, &c.neuron_id, Vote::Unspecified);
        assert_ballot_is_cast(&ballots, &d.neuron_id, Vote::Unspecified);

        // Submit a Yes vote with the C Neuron which should result in C voting Yes, and
        // D voting yes as a majority of its followees have reached consensus
        sns_canisters
            .vote(&c.sender, &c.subaccount, proposal_id, true)
            .await;

        let proposal_data = sns_canisters.get_proposal(proposal_id).await;
        let ballots = proposal_data.ballots;
        assert_ballot_is_cast(&ballots, &a.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &b.neuron_id, Vote::No);
        assert_ballot_is_cast(&ballots, &c.neuron_id, Vote::Yes);
        assert_ballot_is_cast(&ballots, &d.neuron_id, Vote::Yes);

        Ok(())
    });
}

#[test]
fn test_proposal_rejection() {
    local_test_on_sns_subnet(|runtime| async move {
        // Initialize the ledger with an account for a user who will propose and a user who will vote
        let proposer = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let voter = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(proposer.sender.get_principal_id().into(), alloc)
            .with_ledger_account(voter.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron for the proposer
        sns_canisters
            .stake_and_claim_neuron_with_tokens(
                &proposer.sender,
                Some(ONE_YEAR_SECONDS as u32),
                100,
            )
            .await;

        // Stake and claim a neuron for the voter with significantly more voting power
        sns_canisters
            .stake_and_claim_neuron_with_tokens(&voter.sender, Some(ONE_YEAR_SECONDS as u32), 900)
            .await;

        // Submitting a proposal that is rejected results in lost fees. Assert the fees are 0 before
        // the proposal.
        let neuron = sns_canisters.get_neuron(&proposer.neuron_id).await;
        assert_eq!(neuron.neuron_fees_e8s, 0);

        let proposal = Proposal {
            action: Some(Action::Motion(Motion {
                motion_text: String::from(""),
            })),
            ..Default::default()
        };

        let proposal_id = sns_canisters
            .make_proposal(&proposer.sender, &proposer.subaccount, proposal.clone())
            .await
            .expect("Expected make_proposal to succeed");

        let neuron = sns_canisters.get_neuron(&proposer.neuron_id).await;

        // Assert the fees are deducted when the proposal is created.
        assert_eq!(neuron.neuron_fees_e8s, params.reject_cost_e8s.unwrap());

        // Vote to reject the proposal with the neuron that has more voting power to reject the
        // proposal
        sns_canisters
            .vote(&voter.sender, &voter.subaccount, proposal_id, false)
            .await;

        // ProposalData.executed_timestamp_seconds is not set until the end of the voting period.
        // Use TimeWarp to shift time to the end of the voting period for this proposal.
        let initial_voting_period = params.initial_voting_period.unwrap();
        let delta_s = (initial_voting_period + 1) as i64;
        sns_canisters
            .set_time_warp(delta_s)
            .await
            .expect("Expected set_time_warp to succeed");

        let proposal_data = sns_canisters.get_proposal(proposal_id).await;

        // Assert the proposal is rejected.
        assert!(proposal_data.decided_timestamp_seconds > 0);
        assert_eq!(proposal_data.executed_timestamp_seconds, 0);
        assert_eq!(
            proposal_data.status(),
            ProposalDecisionStatus::ProposalStatusRejected
        );

        // Assert that because the proposal was rejected, the neuron does not have it's
        // reject fees returned.
        let neuron = sns_canisters.get_neuron(&proposer.neuron_id).await;

        assert_eq!(neuron.neuron_fees_e8s, params.reject_cost_e8s.unwrap());

        Ok(())
    });
}

fn assert_ballot_is_cast(ballots: &BTreeMap<String, Ballot>, neuron_id: &NeuronId, vote: Vote) {
    let ballot = ballots
        .get(neuron_id.to_string().as_str())
        .expect("Expected there to be a ballot");
    assert_eq!(
        ballot.vote,
        vote as i32,
        "NeuronId {} expected '{:?}', actual '{:?}'",
        neuron_id,
        vote,
        Vote::from_i32(ballot.vote).unwrap()
    );
}

fn assert_voting_error(
    manage_neuron_response: &ManageNeuronResponse,
    error_type_to_match: ErrorType,
) {
    let error = match manage_neuron_response.command.as_ref().unwrap() {
        Command::RegisterVote(_) => {
            panic!("Using this method expects the RegisterVote to return an error")
        }
        Command::Error(err) => err,
        _ => panic!("Unexpected response from RegisterVote"),
    };

    assert_eq!(error.error_type, error_type_to_match as i32);
}

#[test]
fn test_proposal_garbage_collection() {
    local_test_on_sns_subnet(|runtime| async move {
        // Initialize the ledger with an account for a user who will make proposals
        let user = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        // Create NervousSystemParameters with max_proposals_to_keep_per_action set to 1 so
        // garbage_collection will remove additional proposals.
        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            max_proposals_to_keep_per_action: Some(1),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(user.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron for the user
        sns_canisters
            .stake_and_claim_neuron_with_tokens(&user.sender, Some(ONE_YEAR_SECONDS as u32), 100)
            .await;

        // Create a vector of proposals that can be submitted and then garbage collected
        let proposals: Vec<Proposal> = (0..10)
            .map(|i| Proposal {
                title: format!("Motion-{}", i),
                action: Some(Action::Motion(Motion {
                    motion_text: format!("Motion-{}", i),
                })),
                ..Default::default()
            })
            .collect();

        // Submit the generated proposals and track their proposal_ids for assertions later
        let mut proposal_ids = vec![];
        for proposal in &proposals {
            let proposal_id = sns_canisters
                .make_proposal(&user.sender, &user.subaccount, proposal.clone())
                .await
                .expect("Expected make_proposal to succeed");
            proposal_ids.push(proposal_id);
        }

        let proposal_count = list_all_proposals_through_pagination(
            &sns_canisters.governance,
            &user.sender,
            100_usize,
        )
        .await
        .len();

        // Since none of the proposal's voting periods have passed, all proposals should
        // still exist in the SNS
        assert_eq!(proposal_count, proposal_ids.len());

        // Advance time initial_voting_period + 1 days:
        // - initial_voting_period so a proposal can be settled
        // - Additional 1 day since garbage collection happens every 24 hours
        let delta_s = (params.initial_voting_period.unwrap() as i64) + (ONE_DAY_SECONDS as i64);
        sns_canisters
            .set_time_warp(delta_s)
            .await
            .expect("Expected set_time_warp to succeed");

        // Proposals should have been garbage_collected. Get all the proposals kept in the current
        // SNS
        let proposals_after_gc = list_all_proposals_through_pagination(
            &sns_canisters.governance,
            &user.sender,
            100_usize,
        )
        .await;

        // After GC, if no other proposals are open, number of proposals should be equal to
        // max_proposals_to_keep_per_action (which is > 0)
        assert_eq!(
            proposals_after_gc.len(),
            params.max_proposals_to_keep_per_action.unwrap() as usize
        );
        assert!(proposals_after_gc.len() < proposals.len());
        // Assert that only the latest proposal is kept in the SNS
        assert_eq!(
            proposals_after_gc[0].id.as_ref().unwrap(),
            proposal_ids.last().unwrap()
        );

        Ok(())
    });
}
