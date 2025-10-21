use canister_test::Canister;
use dfn_candid::{candid, candid_one};
use ic_canister_client_sender::Sender;
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{ONE_DAY_SECONDS, ONE_MONTH_SECONDS, ONE_YEAR_SECONDS, i2d};
use ic_nervous_system_common_test_keys::{
    TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR, TEST_USER3_KEYPAIR, TEST_USER4_KEYPAIR,
};
use ic_sns_governance::{
    pb::v1::{
        Ballot, GetProposal, GetProposalResponse, ListProposals, ListProposalsResponse,
        ManageNeuronResponse, Motion, NervousSystemParameters, NeuronId, NeuronPermissionList,
        NeuronPermissionType, Proposal, ProposalData, ProposalDecisionStatus, ProposalId,
        ProposalRewardStatus, RewardEvent, Vote, VotingRewardsParameters,
        get_proposal_response::Result::{Error, Proposal as ResponseProposal},
        governance_error::ErrorType::{self, PreconditionFailed},
        manage_neuron_response::Command,
        proposal::Action,
    },
    proposal::{
        PROPOSAL_MOTION_TEXT_BYTES_MAX, PROPOSAL_SUMMARY_BYTES_MAX, PROPOSAL_TITLE_BYTES_MAX,
        PROPOSAL_URL_CHAR_MAX,
    },
    reward,
};
use ic_sns_test_utils::{
    itest_helpers::{
        SnsCanisters, SnsTestsInitPayloadBuilder, UserInfo, state_machine_test_on_sns_subnet,
    },
    now_seconds,
};
use icrc_ledger_types::icrc1::account::Account;
use on_wire::bytes;
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

const EXPECTED_MAX_BALLOT_AGE: f64 = 60.0;

const MOTION_PROPOSAL_ACTION_TYPE: u64 = 1;

const VOTING_REWARDS_PARAMETERS: VotingRewardsParameters = VotingRewardsParameters {
    round_duration_seconds: Some(2 * ONE_DAY_SECONDS),
    reward_rate_transition_duration_seconds: Some(90 * ONE_DAY_SECONDS),
    initial_reward_rate_basis_points: Some(200),
    final_reward_rate_basis_points: Some(200),
};

/// Assert that Motion proposals can be submitted, voted on, and executed
#[test]
fn test_motion_proposal_execution() {
    state_machine_test_on_sns_subnet(|runtime| {
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

            let sns_init_payload = SnsTestsInitPayloadBuilder::new()
                .with_ledger_account(user.get_principal_id().0.into(), alloc)
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
            let initial_voting_period_seconds =
                system_params.initial_voting_period_seconds.unwrap();
            let delta_s = (initial_voting_period_seconds + 1) as i64;
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
            assert_eq!(proposal_data.status(), ProposalDecisionStatus::Executed);

            Ok(())
        }
    })
}

/// Assert that ManageNervousSystemParameters proposals can be submitted, voted on, and executed
#[test]
fn test_manage_nervous_system_parameters_proposal_execution() {
    state_machine_test_on_sns_subnet(|runtime| {
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

            let sns_init_payload = SnsTestsInitPayloadBuilder::new()
                .with_ledger_account(user.get_principal_id().0.into(), alloc)
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

    state_machine_test_on_sns_subnet(|runtime| {
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

            let sns_init_payload = SnsTestsInitPayloadBuilder::new()
                .with_ledger_account(user_1.get_principal_id().0.into(), tokens)
                .with_ledger_account(user_2.get_principal_id().0.into(), tokens)
                .with_ledger_account(user_3.get_principal_id().0.into(), tokens)
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
            assert_eq!(ballots.len(), 3, "{ballots:?}");
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
                    "age_seconds = {age_seconds}. ballot = {ballot:?}"
                );
                assert!(
                    age_seconds < EXPECTED_MAX_BALLOT_AGE,
                    "age_seconds = {age_seconds}. ballot = {ballot:?}"
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
                    "{proposal:?}"
                );
                assert!(
                    (1.0 / 3.0 - disapproval_rating).abs() < epsilon,
                    "{proposal:?}"
                );
            }

            Ok(())
        }
    });
}

#[test]
fn test_bad_proposal_id_candid_type() {
    state_machine_test_on_sns_subnet(|runtime| {
        async move {
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let alloc = Tokens::from_tokens(1000).unwrap();

            let sns_init_payload = SnsTestsInitPayloadBuilder::new()
                .with_ledger_account(user.get_principal_id().0.into(), alloc)
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
    state_machine_test_on_sns_subnet(|runtime| {
        async move {
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let alloc = Tokens::from_tokens(1000).unwrap();

            let sns_init_payload = SnsTestsInitPayloadBuilder::new()
                .with_ledger_account(user.get_principal_id().0.into(), alloc)
                .build();
            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            let res: Result<Vec<u8>, String> = sns_canisters
                .governance
                .query_("get_proposal", bytes, b"This is not valid candid!".to_vec())
                .await;

            let expected_error = "Cannot parse header";
            match res {
                Err(e) => assert!(
                    e.contains(expected_error),
                    "Expected error string \"{expected_error}\" not present in actual error. Error was: {e:?}"
                ),
                Ok(_) => panic!("get_proposal should fail to deserialize"),
            };
            Ok(())
        }
    });
}

#[test]
fn test_non_existent_proposal_id_is_not_a_bad_input() {
    state_machine_test_on_sns_subnet(|runtime| {
        async move {
            // Initialize the ledger with an account for a user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let alloc = Tokens::from_tokens(1000).unwrap();

            let sns_init_payload = SnsTestsInitPayloadBuilder::new()
                .with_ledger_account(user.get_principal_id().0.into(), alloc)
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
    state_machine_test_on_sns_subnet(|runtime| async move {
        // Initialize the ledger with an account for a user.
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let alloc = Tokens::from_tokens(1000).unwrap();
        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(user.get_principal_id().0.into(), alloc)
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
                title: format!("Test Motion proposal-{i}"),
                action: Some(Action::Motion(Motion {
                    motion_text: format!("Motion-{i}"),
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
    state_machine_test_on_sns_subnet(|runtime| async move {
        // Initialize the ledger with an account for a user.
        let user = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));

        let alloc = Tokens::from_tokens(1000).unwrap();
        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(user.sender.get_principal_id().0.into(), alloc)
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
    state_machine_test_on_sns_subnet(|runtime| async move {
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(user.sender.get_principal_id().0.into(), alloc)
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
    state_machine_test_on_sns_subnet(|runtime| async move {
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
            .map(|user| Account {
                owner: user.sender.get_principal_id().0,
                subaccount: None,
            })
            .collect();

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
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
    state_machine_test_on_sns_subnet(|runtime| async move {
        // Initialize the ledger with an account for a user.
        let user = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(user.sender.get_principal_id().0.into(), alloc)
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
            response => panic!("Unexpected response when registering a vote: {response:?}"),
        };

        assert_eq!(expected_error.error_type, ErrorType::NotFound as i32);

        Ok(())
    });
}

#[test]
fn test_ineligible_neuron_voting_fails() {
    state_machine_test_on_sns_subnet(|runtime| async move {
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(proposer.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(voter.sender.get_principal_id().0.into(), alloc)
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
    state_machine_test_on_sns_subnet(|runtime| async move {
        let yes_voter = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        let no_voter = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));

        let alloc = Tokens::from_tokens(1000).unwrap();

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(yes_voter.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(no_voter.sender.get_principal_id().0.into(), alloc)
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
    state_machine_test_on_sns_subnet(|runtime| async move {
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(a.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(b.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(c.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(d.sender.get_principal_id().0.into(), alloc)
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
    state_machine_test_on_sns_subnet(|runtime| async move {
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(a.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(b.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(c.sender.get_principal_id().0.into(), alloc)
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
    state_machine_test_on_sns_subnet(|runtime| async move {
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(a.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(b.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(c.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(d.sender.get_principal_id().0.into(), alloc)
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
    state_machine_test_on_sns_subnet(|runtime| async move {
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(proposer.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(voter.sender.get_principal_id().0.into(), alloc)
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
        let initial_voting_period_seconds = params.initial_voting_period_seconds.unwrap();
        let delta_s = (initial_voting_period_seconds + 1) as i64;
        sns_canisters
            .set_time_warp(delta_s)
            .await
            .expect("Expected set_time_warp to succeed");

        let proposal_data = sns_canisters.get_proposal(proposal_id).await;

        // Assert the proposal is rejected.
        assert!(proposal_data.decided_timestamp_seconds > 0);
        assert_eq!(proposal_data.executed_timestamp_seconds, 0);
        assert_eq!(proposal_data.status(), ProposalDecisionStatus::Rejected);

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
        Vote::try_from(ballot.vote).unwrap()
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
    state_machine_test_on_sns_subnet(|runtime| async move {
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(user.sender.get_principal_id().0.into(), alloc)
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
                title: format!("Motion-{i}"),
                action: Some(Action::Motion(Motion {
                    motion_text: format!("Motion-{i}"),
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

        // Advance time initial_voting_period_seconds + 1 days:
        // - initial_voting_period_seconds so a proposal can be settled
        // - Additional 1 day since garbage collection happens every 24 hours
        let delta_s =
            (params.initial_voting_period_seconds.unwrap() as i64) + (ONE_DAY_SECONDS as i64);
        sns_canisters
            .set_time_warp(delta_s)
            .await
            .expect("Expected set_time_warp to succeed");

        sns_canisters
            .run_periodic_tasks_now()
            .await
            .expect("Expected run_periodic_tasks_now to succeed");

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

#[test]
fn test_change_voting_rewards_round_duration() {
    state_machine_test_on_sns_subnet(|runtime| async move {
        // Initialize the ledger with an account for a user who will make proposals
        let proposer = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        // Initialize the ledger with an account for a user who will vote so we can control when
        // proposals are executed
        let voter = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let original_voting_rewards_round_duration_seconds =
            VOTING_REWARDS_PARAMETERS.round_duration_seconds.unwrap();
        let mut current_voting_rewards_round_duration_seconds =
            original_voting_rewards_round_duration_seconds;
        let initial_voting_period_seconds = original_voting_rewards_round_duration_seconds / 2;
        let critical_proposal_initial_voting_period_seconds =
            initial_voting_period_seconds.max(5 * ONE_DAY_SECONDS);

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            voting_rewards_parameters: Some(VotingRewardsParameters {
                ..VOTING_REWARDS_PARAMETERS
            }),
            initial_voting_period_seconds: Some(initial_voting_period_seconds),
            wait_for_quiet_deadline_increase_seconds: Some(initial_voting_period_seconds / 4), // The default of one day is too short
            ..NervousSystemParameters::with_default_values()
        };

        let genesis_timestamp_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(proposer.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(voter.sender.get_principal_id().0.into(), alloc)
            .with_nervous_system_parameters(params.clone())
            .with_genesis_timestamp_seconds(genesis_timestamp_seconds)
            .build();
        let total_token_supply_e8s = 2 * alloc.get_e8s();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron for the proposer
        sns_canisters
            .stake_and_claim_neuron_with_tokens(
                &proposer.sender,
                Some(ONE_YEAR_SECONDS as u32),
                100,
            )
            .await;

        // Stake and claim a neuron for the voter
        sns_canisters
            .stake_and_claim_neuron_with_tokens(&voter.sender, Some(ONE_YEAR_SECONDS as u32), 100)
            .await;

        // Step 2: Run code under test.

        // How far ahead in the future governance currently is.
        let mut delta_s: i64 = 0;

        // Step 2.1: Real work.
        //
        // After each proposal is made, voter votes in favor of it, causing it
        // to be decided and executed. Then, time is advanced by the (current)
        // voting rewards round duration (VRRD).
        //
        // Three proposals will be made:
        //   1. Using the original VRRD.
        //   2. Change to half the original VRRD.
        //   3. Change to double the original VRRD.
        //
        // Notice that proposals 2 and 3 will be subject to their own VRRD.
        let reward_event_0 = sns_canisters.get_latest_reward_event().await;

        // Step 2.1: proposal 1.
        let proposal_1_id = {
            let proposal = Proposal {
                action: Some(Action::Motion(Motion::default())),
                ..Default::default()
            };

            sns_canisters
                .make_proposal(&proposer.sender, &proposer.subaccount, proposal)
                .await
                .unwrap()
        };
        // Make proposal 1 pass.
        sns_canisters
            .vote(&voter.sender, &voter.subaccount, proposal_1_id, true)
            .await;

        // Wait for rewards.
        delta_s += current_voting_rewards_round_duration_seconds as i64;
        sns_canisters.set_time_warp(delta_s).await.unwrap();
        let reward_event_1 = sns_canisters
            .await_reward_event_after(reward_event_0.end_timestamp_seconds.unwrap())
            .await;

        // Step 2.2: proposal 2.
        current_voting_rewards_round_duration_seconds =
            original_voting_rewards_round_duration_seconds / 2;
        let proposal_2_id = {
            let action = NervousSystemParameters {
                voting_rewards_parameters: Some(VotingRewardsParameters {
                    round_duration_seconds: Some(current_voting_rewards_round_duration_seconds),
                    ..VOTING_REWARDS_PARAMETERS
                }),
                // Don't change anything else.
                ..Default::default()
            };

            let proposal = Proposal {
                action: Some(Action::ManageNervousSystemParameters(action)),
                ..Default::default()
            };

            sns_canisters
                .make_proposal(&proposer.sender, &proposer.subaccount, proposal)
                .await
                .unwrap()
        };
        // Make proposal 2 pass.
        sns_canisters
            .vote(&voter.sender, &voter.subaccount, proposal_2_id, true)
            .await;

        // Wait for rewards.
        delta_s += critical_proposal_initial_voting_period_seconds as i64;
        sns_canisters.set_time_warp(delta_s).await.unwrap();
        let reward_event_2 = sns_canisters
            .await_reward_event_after(reward_event_1.end_timestamp_seconds.unwrap())
            .await;

        // Step 2.3: proposal 3.
        current_voting_rewards_round_duration_seconds =
            original_voting_rewards_round_duration_seconds * 2;
        let proposal_3_id = {
            let action = NervousSystemParameters {
                voting_rewards_parameters: Some(VotingRewardsParameters {
                    round_duration_seconds: Some(current_voting_rewards_round_duration_seconds),
                    ..VOTING_REWARDS_PARAMETERS
                }),
                // Don't change anything else.
                ..Default::default()
            };

            let proposal = Proposal {
                action: Some(Action::ManageNervousSystemParameters(action)),
                ..Default::default()
            };

            sns_canisters
                .make_proposal(&proposer.sender, &proposer.subaccount, proposal)
                .await
                .unwrap()
        };
        // Make proposal 3 pass.
        sns_canisters
            .vote(&voter.sender, &voter.subaccount, proposal_3_id, true)
            .await;
        // Wait for rewards.
        delta_s += critical_proposal_initial_voting_period_seconds as i64;
        sns_canisters.set_time_warp(delta_s).await.unwrap();
        let reward_event_3 = sns_canisters
            .await_reward_event_after(reward_event_2.end_timestamp_seconds.unwrap())
            .await;

        // Step 3: Inspect results.
        let reward_events = vec![
            reward_event_1.clone(),
            reward_event_2.clone(),
            reward_event_3.clone(),
        ];

        // Step 3.1: Inspect RewardEvent proposals.
        assert_eq!(reward_event_1.settled_proposals, vec![proposal_1_id],);
        assert_eq!(reward_event_2.settled_proposals, vec![proposal_2_id],);
        assert_eq!(reward_event_3.settled_proposals, vec![proposal_3_id],);

        // Step 3.2: Inspect reward amounts
        // Step 3.2.1: Inspect reward amount 2.
        let reward_rate_2 =
            VOTING_REWARDS_PARAMETERS.reward_rate_at(reward::Instant::from_seconds_since_genesis(
                i2d(reward_event_2.end_timestamp_seconds.unwrap() - genesis_timestamp_seconds),
            ));
        let reward_purse_2_e8s = reward_rate_2
            * reward::Duration::from_secs(i2d(critical_proposal_initial_voting_period_seconds))
            * i2d(total_token_supply_e8s);
        let undistributed_reward_purse_2_e8s =
            i2d(reward_event_2.distributed_e8s_equivalent) - reward_purse_2_e8s;
        assert!(
            // We need a little leeway, because apportionment is hard.
            (-i2d(10)..=i2d(0)).contains(&undistributed_reward_purse_2_e8s),
            "{} vs. {}",
            reward_event_2.distributed_e8s_equivalent,
            reward_purse_2_e8s,
        );
        // Step 3.2.1: Inspect reward amount 3.
        let reward_rate_3 =
            VOTING_REWARDS_PARAMETERS.reward_rate_at(reward::Instant::from_seconds_since_genesis(
                i2d(reward_event_3.end_timestamp_seconds.unwrap() - genesis_timestamp_seconds),
            ));
        let reward_purse_3_e8s = reward_rate_3
            * reward::Duration::from_secs(i2d(original_voting_rewards_round_duration_seconds * 2))
            * i2d(total_token_supply_e8s);
        let undistributed_reward_purse_3_e8s =
            i2d(reward_event_3.distributed_e8s_equivalent) - reward_purse_3_e8s;
        assert!(
            // We need a little leeway, because apportionment is hard.
            (-i2d(10)..=i2d(0)).contains(&undistributed_reward_purse_3_e8s),
            "{} vs. {}",
            reward_event_3.distributed_e8s_equivalent,
            reward_purse_3_e8s,
        );

        // Step 3.3: Assert that round numbers are as expected.
        assert_eq!(reward_event_1.round, 1, "{reward_events:#?}",);
        assert_eq!(
            reward_event_2.round,
            1 + (critical_proposal_initial_voting_period_seconds / ONE_DAY_SECONDS),
            "{reward_events:#?}",
        );
        assert_eq!(
            reward_event_3.round,
            2 + (critical_proposal_initial_voting_period_seconds / ONE_DAY_SECONDS),
            "{reward_events:#?}",
        );

        // Step 3.4: Inspect the times of reward_event_(2|3) to see that the new
        // voting rewards round duration of those proposals was put into effect.
        let delay_2_seconds = reward_event_2.end_timestamp_seconds.unwrap()
            - reward_event_1.end_timestamp_seconds.unwrap();
        assert_eq!(
            delay_2_seconds, critical_proposal_initial_voting_period_seconds,
            "{reward_events:#?}",
        );
        let delay_3_seconds = reward_event_3.end_timestamp_seconds.unwrap()
            - reward_event_2.end_timestamp_seconds.unwrap();
        assert_eq!(
            delay_3_seconds,
            original_voting_rewards_round_duration_seconds * 2,
            "{reward_events:#?}",
        );

        // Step 3.5: Verify that all proposals have been marked as
        // "rewarded". This based on the reward_event_end_timestamp_seconds.
        let proposal_data_1 = sns_canisters.get_proposal(proposal_1_id).await;
        let proposal_data_2 = sns_canisters.get_proposal(proposal_2_id).await;
        let proposal_data_3 = sns_canisters.get_proposal(proposal_3_id).await;
        assert_eq!(
            proposal_data_1.reward_event_end_timestamp_seconds.unwrap(),
            reward_event_1.end_timestamp_seconds.unwrap(),
        );
        assert_eq!(
            proposal_data_2.reward_event_end_timestamp_seconds.unwrap(),
            reward_event_2.end_timestamp_seconds.unwrap(),
        );
        assert_eq!(
            proposal_data_3.reward_event_end_timestamp_seconds.unwrap(),
            reward_event_3.end_timestamp_seconds.unwrap(),
        );
        assert_eq!(proposal_data_1.reward_event_round, reward_event_1.round,);
        assert_eq!(proposal_data_2.reward_event_round, reward_event_2.round,);
        assert_eq!(proposal_data_3.reward_event_round, reward_event_3.round,);

        Ok(())
    })
}

/// Test that when there are no proposals submitted during reward_distribution_period_seconds,
/// that RewardEvents are still generated, proposals can still be processed afterwards, and
/// that garbage collection can still take place.
///
/// Narrative Outline:
///
///     1. Three proposals are made and immediately voted in, one after another.
///
///     2. Between the first two proposals, there is a "long dry spell" (i.e. the period
///        between the first two proposals is much greater than one reward round).
///
///     3. Because of the retention policy, the first proposal gets garbage
///        collected some time after the third proposal.
///
///  After each proposal, the fact that they are rewarded is verified by inspecting
///
///      1. their reward_event_* fields, and
///
///      2. the settled_proposals field of latest_reward_event, which should contain just the
///         ID of the most recent proposal.
#[test]
fn test_intermittent_proposal_submission() {
    state_machine_test_on_sns_subnet(|runtime| async move {
        // Chapter 0: Prepare the world.

        // Initialize the ledger with an account for a user who will make proposals
        let proposer = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        // Initialize the ledger with an account for a user who will vote so we can control when
        // proposals are executed
        let voter = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        // Set the reward_round_duration_seconds to the double the initial_voting_period
        // (initial_voting_period must be at least one day) so that proposals can be submitted and
        // settled within a single period.
        let reward_round_duration_seconds =
            VOTING_REWARDS_PARAMETERS.round_duration_seconds.unwrap();
        let initial_voting_period_seconds = reward_round_duration_seconds / 2;

        let params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            voting_rewards_parameters: Some(VotingRewardsParameters {
                ..VOTING_REWARDS_PARAMETERS
            }),
            initial_voting_period_seconds: Some(initial_voting_period_seconds),
            wait_for_quiet_deadline_increase_seconds: Some(initial_voting_period_seconds / 4), // The default of one day is too short
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(proposer.sender.get_principal_id().0.into(), alloc)
            .with_ledger_account(voter.sender.get_principal_id().0.into(), alloc)
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

        // Stake and claim a neuron for the voter
        let voter_neuron_id = sns_canisters
            .stake_and_claim_neuron_with_tokens(&voter.sender, Some(ONE_YEAR_SECONDS as u32), 100)
            .await;

        // Chapter 1: The first proposal is made.
        //
        // (Incidentally, this occurs very early in the life of the SNS. The
        // story really begins here.)

        // Make the first proposal, and vote it in (immediately).
        let motion_proposal = Proposal {
            action: Some(Action::Motion(Motion::default())),
            ..Default::default()
        };
        let p1_id = sns_canisters
            .make_proposal(
                &proposer.sender,
                &proposer.subaccount,
                motion_proposal.clone(),
            )
            .await
            .unwrap();
        sns_canisters
            .vote(&voter.sender, &voter.subaccount, p1_id, true)
            .await;

        // Verify that the proposal was voted in.
        let proposal_data = sns_canisters.get_proposal(p1_id).await;
        assert!(proposal_data.decided_timestamp_seconds > 0);
        assert!(proposal_data.executed_timestamp_seconds > 0);
        // Even though the proposal is executed, it still accepts votes.
        assert_eq!(proposal_data.reward_event_end_timestamp_seconds, None);
        assert_eq!(proposal_data.reward_event_round, 0);
        assert_eq!(
            proposal_data.reward_status(now_seconds(None)),
            ProposalRewardStatus::AcceptVotes
        );

        // Advance time to when the proposal's voting period is over.
        let mut delta_s = initial_voting_period_seconds as i64;
        sns_canisters.set_time_warp(delta_s).await?;

        // Now that voting is over, the proposal CAN now be rewarded.
        let proposal_data = sns_canisters.get_proposal(p1_id).await;
        assert_eq!(
            proposal_data.reward_status(now_seconds(Some(delta_s as u64))),
            ProposalRewardStatus::ReadyToSettle
        );
        // It has not been rewarded yet though, because a reward round has not yet elapsed.
        assert_eq!(proposal_data.reward_event_end_timestamp_seconds, None);
        assert_eq!(proposal_data.reward_event_round, 0);

        // Since no reward rounds have elapsed yet, the round of the latest
        // reward event should (still) be 0.
        let genesis_reward_event = sns_canisters.get_latest_reward_event().await;
        assert_eq!(genesis_reward_event.round, 0);

        // Advance time by a reward round.
        delta_s = reward_round_duration_seconds as i64;
        sns_canisters.set_time_warp(delta_s).await?;

        // Wait for the first real RewardEvent.
        let current_reward_event = sns_canisters
            .await_reward_event_after(genesis_reward_event.end_timestamp_seconds.unwrap())
            .await;
        // It should include the first proposal.
        assert_eq!(current_reward_event.settled_proposals, vec![p1_id]);

        // Asserts that current is more advanced than previous. Inspects the
        // round and end_timestamp_seconds fields.
        let assert_reward_event_incremented =
            |previous_reward_event: &RewardEvent, current_reward_event: &RewardEvent| {
                let delay_seconds = current_reward_event.end_timestamp_seconds.unwrap()
                    - previous_reward_event.end_timestamp_seconds.unwrap();

                // The delay between reward events should be a whole number of rounds.
                assert_eq!(
                    delay_seconds % reward_round_duration_seconds,
                    0,
                    "current_reward_event = {current_reward_event:#?}\n\
                 previous_reward_event = {previous_reward_event:#?}\n\
                 reward_round_duration_seconds = {reward_round_duration_seconds}",
                );

                let delay_rounds = delay_seconds / reward_round_duration_seconds;
                assert!(
                    // Normally, just one reward round passes, but we have some
                    // nondeterminism in our tests. Therefore, we relax this requirement
                    // to avoid flakes.
                    0 < delay_rounds && delay_rounds <= 3,
                    "current_reward_event = {current_reward_event:#?}\n
                 previous_reward_event = {previous_reward_event:#?}\n
                 reward_round_duration_seconds = {reward_round_duration_seconds}",
                );

                // Assert that the round field in RewardEvent is consistent with the
                // end_timestamp_seconds field.
                assert_eq!(
                    current_reward_event.round,
                    previous_reward_event.round + delay_rounds
                );
            };

        assert_reward_event_incremented(&genesis_reward_event, &current_reward_event);

        // Along with RewardEvents, the proposal should be updated with what RewardEvent
        // distributed its voting rewards.
        let proposal = sns_canisters.await_proposal_rewarding(p1_id).await;
        assert_eq!(
            proposal.reward_event_end_timestamp_seconds.unwrap(),
            current_reward_event.end_timestamp_seconds.unwrap(),
        );
        assert_eq!(proposal.reward_event_round, current_reward_event.round);
        let mut previous_reward_event = current_reward_event;

        // Chapter 2: The second proposal is made after a long hiatus.
        //
        // Even when there are no proposals, RewardEvents are still generated.
        // Furthermore, rewards are rolled over via the
        // total_available_e8s_equivalent field in RewardEvent.

        for i in 0..7 {
            // Advance time by a reward round.
            delta_s += reward_round_duration_seconds as i64;
            sns_canisters.set_time_warp(delta_s).await?;

            let current_reward_event = sns_canisters
                .await_reward_event_after(previous_reward_event.end_timestamp_seconds.unwrap())
                .await;

            // Assert rewards are rolled over during empty reward rounds. This
            // does not apply in the first iteration, because the RewardEvent
            // before this loop actually has a proposal, and therefore, does not
            // contribute any roll over.
            if i != 0 {
                assert!(
                    current_reward_event.total_available_e8s_equivalent
                        > previous_reward_event.total_available_e8s_equivalent,
                    "current_reward_event = {current_reward_event:#?}\n
                     previous_reward_event = {previous_reward_event:#?}",
                );
            }

            assert_eq!(current_reward_event.settled_proposals, vec![]);

            assert_reward_event_incremented(&previous_reward_event, &current_reward_event);

            previous_reward_event = current_reward_event;
        }

        // Record maturity of voter so that we can later see that it is indeed
        // rewarded for their voting.
        let voter_maturity_e8s_equivalent_before = sns_canisters
            .get_neuron(&voter_neuron_id)
            .await
            .maturity_e8s_equivalent;

        // Now that the SNS has experienced a hiatus in proposals, make and
        // immediately vote in the second proposal.
        let p2_id = sns_canisters
            .make_proposal(
                &proposer.sender,
                &proposer.subaccount,
                motion_proposal.clone(),
            )
            .await
            .unwrap();
        sns_canisters
            .vote(&voter.sender, &voter.subaccount, p2_id, true)
            .await;
        // Advance time past the voting deadline of the second proposal.
        delta_s += initial_voting_period_seconds as i64;
        sns_canisters.set_time_warp(delta_s).await?;
        // Assert that the second proposal has been executed (like the first).
        let proposal = sns_canisters.get_proposal(p2_id).await;
        assert!(proposal.decided_timestamp_seconds > 0);
        assert!(proposal.executed_timestamp_seconds > 0);

        // Advance time to the middle of the next reward period.
        delta_s += reward_round_duration_seconds as i64;
        sns_canisters.set_time_warp(delta_s).await?;

        // The second proposal should have been rewarded (and a new RewardEvent recorded).
        let proposal = sns_canisters.await_proposal_rewarding(p2_id).await;

        let current_reward_event = sns_canisters
            .await_reward_event_after(proposal.reward_event_end_timestamp_seconds.unwrap() - 1)
            .await;
        assert_eq!(current_reward_event.settled_proposals, vec![p2_id]);
        assert_reward_event_incremented(&previous_reward_event, &current_reward_event);

        // Inspect proposal 2, comparing it against current_reward_event.
        assert_eq!(
            proposal.reward_event_end_timestamp_seconds.unwrap(),
            current_reward_event.end_timestamp_seconds.unwrap(),
            "proposal:\n{proposal:#?}\n***\nRewardEvent:\n{current_reward_event:#?}",
        );
        assert_eq!(proposal.reward_event_round, current_reward_event.round);

        // Assert that voter has been rewarded.
        let voter_maturity_e8s_equivalent_after = sns_canisters
            .get_neuron(&voter_neuron_id)
            .await
            .maturity_e8s_equivalent;
        assert!(
            voter_maturity_e8s_equivalent_after > voter_maturity_e8s_equivalent_before,
            "{voter_maturity_e8s_equivalent_after} vs. {voter_maturity_e8s_equivalent_before}",
        );

        // Chapter 3: Make and pass the third proposal, causing proposal 1 to be
        // garbage collected.

        // Adjust the GC policy via proposal. This should result in the demise
        // of proposal 1 (verified later).
        let proposal = Proposal {
            title: "Change max_proposals_to_keep_per_action".into(),
            action: Some(Action::ManageNervousSystemParameters(
                NervousSystemParameters {
                    max_proposals_to_keep_per_action: Some(1),
                    ..Default::default()
                },
            )),
            ..Default::default()
        };
        let p3_id = sns_canisters
            .make_proposal(&proposer.sender, &proposer.subaccount, proposal)
            .await
            .unwrap();

        // Assert that there are 3 proposals. (The third one has not been voted in yet.)
        let mut proposals = sns_canisters.list_proposals(&proposer.sender).await;
        let proposal_ids: Vec<ProposalId> = proposals.iter().map(|p| p.id.unwrap()).collect();
        assert_eq!(proposal_ids, vec![p3_id, p2_id, p1_id]);

        // Vote in the GC policy change.
        sns_canisters
            .vote(&voter.sender, &voter.subaccount, p3_id, true)
            .await;

        // Advance time such that GC is performed.
        delta_s += ONE_DAY_SECONDS as i64;
        sns_canisters.set_time_warp(delta_s).await?;

        // Wait for the number of proposals to decrease.
        for _ in 0..250 {
            proposals = sns_canisters.list_proposals(&proposer.sender).await;
            if proposals.len() < 3 {
                // GC occurred
                break;
            }
            runtime.tick().await;
        }

        // Assert that proposal 1 has disappeared.
        let proposal_ids: Vec<ProposalId> = proposals.iter().map(|p| p.id.unwrap()).collect();
        assert_eq!(proposal_ids, vec![p3_id, p2_id]);

        Ok(())
    });
}
