use ic_nervous_system_proto::pb::v1::Percentage;
use ic_sns_governance::pb::v1::{ProposalData, Tally, Vote};
use proptest::proptest;

mod early_decision {
    use ic_sns_governance::pb::v1::NervousSystemParameters;

    use super::*;

    proptest! {
        // If a proposal can be adopted by 50% absolute majority, flipping the "yes/no" votes should be sufficient to reject the decision
        #[test]
        fn flips_when_votes_flip(
            minimum_yes_proportion_of_total in 0u64..5_000,
            yes in 0u64..1_000_000,
            no in 0u64..1_000_000,
            uncast in 0u64..1_000_000,
        ) {
            let total = yes + no + uncast;
            let base_proposal = ProposalData {
                latest_tally: Some(Tally {
                    yes,
                    no,
                    total,
                    timestamp_seconds: 1,
                }),
                proposal_creation_timestamp_seconds: 1,
                initial_voting_period_seconds: 10,
                minimum_yes_proportion_of_total: Some(Percentage::from_basis_points(
                    minimum_yes_proportion_of_total,
                )),
                minimum_yes_proportion_of_exercised: Some(Percentage::from_basis_points(
                    5000,
                )),
                ..Default::default()
            };
            let base_proposal_decision = base_proposal.early_decision();

            let flipped_proposal = ProposalData {
                latest_tally: Some(Tally {
                    yes: no,
                    no: yes,
                    total,
                    timestamp_seconds: 1,
                }),
                ..base_proposal.clone()
            };
            let flipped_proposal_decision = flipped_proposal.early_decision();

            assert_eq!(
                base_proposal_decision,
                flipped_proposal_decision.opposite(),
                "Flipping the votes should change the decision. \
                 base_proposal's decision: {base_proposal_decision:?}, flipped_proposal's decision: {flipped_proposal_decision:?}.\n
                 base_proposal: {base_proposal:?}, P2: {flipped_proposal:?}",
            );
        }

        // If minimum_yes_proportion_of_total or minimum_yes_proportion_of_exercised
        // are None, the proposal logic should assume the default values
        #[test]
        fn assumes_default_voting_thresholds_when_not_present(
            yes in 0u64..1_000_000,
            no in 0u64..1_000_000,
            uncast in 0u64..1_000_000,
        ) {
            let total = yes + no + uncast;
            let base_proposal = ProposalData {
                latest_tally: Some(Tally {
                    yes,
                    no,
                    total,
                    timestamp_seconds: 1,
                }),
                proposal_creation_timestamp_seconds: 1,
                initial_voting_period_seconds: 10,
                ..Default::default()
            };
            let specified_proposal = ProposalData {
                minimum_yes_proportion_of_total: Some(
                    NervousSystemParameters::DEFAULT_MINIMUM_YES_PROPORTION_OF_TOTAL_VOTING_POWER,
                ),
                minimum_yes_proportion_of_exercised: Some(
                    NervousSystemParameters::DEFAULT_MINIMUM_YES_PROPORTION_OF_EXERCISED_VOTING_POWER,
                ),
                ..base_proposal.clone()
            };
            assert_eq!(base_proposal.early_decision(), specified_proposal.early_decision());
            assert_eq!(base_proposal.is_accepted(), specified_proposal.is_accepted());
            assert_eq!(base_proposal.can_make_decision(1), specified_proposal.can_make_decision(1));
        }


        // Once a decision has been made, casting more votes in either direction
        // should not change the decision
        #[test]
        fn monotonic(
            minimum_yes_proportion_of_total in 0u64..5_000,
            minimum_yes_proportion_of_exercised in 5_000u64..9_999,
            yes in 0u64..1_000_000,
            no in 0u64..1_000_000,
            uncast in 0u64..1_000_000,
            extra_percent in 0u64..100u64,
        ) {
            let total = yes + no + uncast;
            let base_proposal = ProposalData {
                latest_tally: Some(Tally {
                    yes,
                    no,
                    total,
                    timestamp_seconds: 1,
                }),
                proposal_creation_timestamp_seconds: 1,
                initial_voting_period_seconds: 10,
                minimum_yes_proportion_of_total: Some(Percentage::from_basis_points(
                    minimum_yes_proportion_of_total,
                )),
                minimum_yes_proportion_of_exercised: Some(Percentage::from_basis_points(
                    minimum_yes_proportion_of_exercised,
                )),
                ..Default::default()
            };
            let base_proposal_decision = base_proposal.early_decision();

            let votes_to_cast = ((extra_percent as f64 / 100.) * (uncast as f64)) as u64;

            let base_proposal_with_more_votes = match base_proposal_decision {
                Vote::Yes => ProposalData {
                    latest_tally: Some(Tally {
                        yes,
                        no: no + votes_to_cast,
                        total,
                        timestamp_seconds: 1,
                    }),
                    ..base_proposal.clone()
                },
                Vote::No => ProposalData {
                    latest_tally: Some(Tally {
                        yes: yes + votes_to_cast,
                        no,
                        total,
                        timestamp_seconds: 1,
                    }),
                    ..base_proposal.clone()
                },
                Vote::Unspecified => return Ok(()),
            };
            let base_proposal_with_more_votes_decision = base_proposal_with_more_votes.early_decision();

            assert_eq!(
                base_proposal_decision,
                base_proposal_with_more_votes_decision,
                "Adding extra votes should not change the decision. base_proposal's decision: {base_proposal_decision:?},\
                base_proposal_with_more_votes_decision's decision: {base_proposal_with_more_votes_decision:?}.\
                \nbase_proposal: {base_proposal:?}, base_proposal_with_more_votes: {base_proposal_with_more_votes:?}",
            );

            // Check that is_accepted is also monotonic
            assert_eq!(
                base_proposal.is_accepted(),
                base_proposal_with_more_votes.is_accepted(),
            );
        }

        // If early_decision is unspecified, it should be able to go
        // "either way" by casting the remaining votes
        #[test]
        fn could_go_either_way(
            minimum_yes_proportion_of_total in 0u64..5_000,
            minimum_yes_proportion_of_exercised in 5_000u64..9_999,
            yes in 0u64..1_000_000,
            no in 0u64..1_000_000,
            uncast in 0u64..1_000_000,
        ) {
            let total = yes + no + uncast;
            let base_proposal = ProposalData {
                latest_tally: Some(Tally {
                    yes,
                    no,
                    total,
                    timestamp_seconds: 1,
                }),
                proposal_creation_timestamp_seconds: 1,
                initial_voting_period_seconds: 10,
                minimum_yes_proportion_of_total: Some(Percentage::from_basis_points(
                    minimum_yes_proportion_of_total,
                )),
                minimum_yes_proportion_of_exercised: Some(Percentage::from_basis_points(
                    minimum_yes_proportion_of_exercised,
                )),
                ..Default::default()
            };
            let base_proposal_decision = base_proposal.early_decision();

            if base_proposal_decision != Vote::Unspecified { return Ok(()); }

            let base_proposal_with_more_yes_votes = ProposalData {
                latest_tally: Some(Tally {
                    yes: yes + uncast,
                    no,
                    total,
                    timestamp_seconds: 1,
                }),
                ..base_proposal.clone()
            };
            let base_proposal_with_more_yes_votes_decision = base_proposal_with_more_yes_votes.early_decision();
            assert_eq!(base_proposal_with_more_yes_votes_decision, Vote::Yes);

            let base_proposal_with_more_no_votes = ProposalData {
                latest_tally: Some(Tally {
                    yes,
                    no: no + uncast,
                    total,
                    timestamp_seconds: 1,
                }),
                ..base_proposal.clone()
            };
            let base_proposal_with_more_no_votes_decision = base_proposal_with_more_no_votes.early_decision();
            assert_eq!(base_proposal_with_more_no_votes_decision, Vote::No);
        }

        // base_proposal.is_accepted() should agree with base_proposal.early_decision()
        #[test]
        fn early_decision_implies_accepted(
            minimum_yes_proportion_of_total in 0u64..5_000,
            minimum_yes_proportion_of_exercised in 5_000u64..9_999,
            yes in 0u64..1_000_000,
            no in 0u64..1_000_000,
            uncast in 0u64..1_000_000,
        ) {
            let total = yes + no + uncast;
            let base_proposal = ProposalData {
                latest_tally: Some(Tally {
                    yes,
                    no,
                    total,
                    timestamp_seconds: 1,
                }),
                proposal_creation_timestamp_seconds: 1,
                initial_voting_period_seconds: 10,
                minimum_yes_proportion_of_total: Some(Percentage::from_basis_points(
                    minimum_yes_proportion_of_total,
                )),
                minimum_yes_proportion_of_exercised: Some(Percentage::from_basis_points(
                    minimum_yes_proportion_of_exercised,
                )),
                ..Default::default()
            };
            let base_proposal_decision = base_proposal.early_decision();

            match base_proposal_decision {
                Vote::Unspecified => {},
                Vote::Yes => assert!(base_proposal.is_accepted()),
                Vote::No => assert!(!base_proposal.is_accepted()),
            }
        }
    }

    #[test]
    fn unspecified_when_empty_votes() {
        let proposal = ProposalData {
            proposal_creation_timestamp_seconds: 1,
            latest_tally: Some(Tally {
                timestamp_seconds: 1,
                yes: 0,
                no: 0,
                total: 1000,
            }),
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_basis_points(0)),
            ..Default::default()
        };

        assert_eq!(proposal.early_decision(), Vote::Unspecified);
    }

    #[test]
    fn doesnt_overflow() {
        let proposal_all_yes_votes = ProposalData {
            latest_tally: Some(Tally {
                yes: u64::MAX,
                no: 0,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_basis_points(0)),
            ..Default::default()
        };
        assert_eq!(proposal_all_yes_votes.early_decision(), Vote::Yes);

        let proposal_all_no_votes = ProposalData {
            latest_tally: Some(Tally {
                yes: 0,
                no: u64::MAX,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_basis_points(0)),
            ..Default::default()
        };
        assert_eq!(proposal_all_no_votes.early_decision(), Vote::No);

        let proposal_split_votes = ProposalData {
            latest_tally: Some(Tally {
                yes: u64::MAX / 2,
                no: u64::MAX / 2,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_basis_points(300)),
            ..Default::default()
        };
        assert_eq!(proposal_split_votes.early_decision(), Vote::Unspecified);
    }

    #[test]
    fn decision_transitions() {
        let now_seconds = 1;

        // Test case 1: Just on the edge of being unspecified vs yes
        let undecided_proposal = ProposalData {
            latest_tally: Some(Tally {
                yes: 5,
                no: 4,
                total: 10, // One undecided voter whose decision determines the result
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_basis_points(0)),
            minimum_yes_proportion_of_exercised: Some(Percentage::from_basis_points(5_000)),
            ..Default::default()
        };
        assert_eq!(undecided_proposal.early_decision(), Vote::Unspecified);
        assert!(!undecided_proposal.can_make_decision(now_seconds));

        // Test case 1 cont.: Without that undecided voter, the result would be Yes
        let yes_proposal = ProposalData {
            latest_tally: Some(Tally {
                yes: 5,
                no: 4,
                total: 9,
                timestamp_seconds: 1,
            }),
            ..undecided_proposal.clone()
        };
        assert_eq!(yes_proposal.early_decision(), Vote::Yes);
        assert!(yes_proposal.can_make_decision(now_seconds));

        // Test case 2: The decision should be Unspecified as the yes votes are not greater than 50% of the total, but could be if the undecided voter voted
        let undecided_proposal_2 = ProposalData {
            latest_tally: Some(Tally {
                yes: 5,
                no: 5,
                total: 11, // One undecided voter who could break the tie
                timestamp_seconds: 1,
            }),
            ..undecided_proposal.clone()
        };
        assert_eq!(undecided_proposal_2.early_decision(), Vote::Unspecified);
        assert!(!undecided_proposal_2.can_make_decision(now_seconds));

        // Test case 2 cont.: Without that undecided voter, the result would be No
        let no_proposal = ProposalData {
            latest_tally: Some(Tally {
                yes: 5,
                no: 5,
                total: 10, // Total is exactly equal to the sum of yes and no
                timestamp_seconds: 1,
            }),
            ..undecided_proposal.clone()
        };
        assert_eq!(no_proposal.early_decision(), Vote::No);
        assert!(no_proposal.can_make_decision(now_seconds));

        // Test case 3: A very narrow victory for Yes...
        let yes_proposal = ProposalData {
            latest_tally: Some(Tally {
                yes: 5_001,
                no: 4_999,
                total: 10_000,
                timestamp_seconds: 1,
            }),
            minimum_yes_proportion_of_exercised: Some(Percentage::from_basis_points(5_000)),
            ..undecided_proposal.clone()
        };
        assert_eq!(yes_proposal.early_decision(), Vote::Yes);
        assert!(yes_proposal.can_make_decision(now_seconds));

        // Test case 3 cont.: ...becomes undecided if we were missing one `yes` vote
        let yes_proposal = ProposalData {
            latest_tally: Some(Tally {
                yes: 5_000,
                no: 4_999,
                total: 10_000,
                timestamp_seconds: 1,
            }),
            minimum_yes_proportion_of_exercised: Some(Percentage::from_basis_points(5_000)),
            ..undecided_proposal.clone()
        };
        assert_eq!(yes_proposal.early_decision(), Vote::Unspecified);
        assert!(!yes_proposal.can_make_decision(now_seconds));

        // Test case 4: Another very narrow victory for Yes...
        let yes_proposal = ProposalData {
            latest_tally: Some(Tally {
                yes: 7_501,
                no: 2_499,
                total: 10_000,
                timestamp_seconds: 1,
            }),
            minimum_yes_proportion_of_exercised: Some(Percentage::from_basis_points(7_500)),
            ..undecided_proposal.clone()
        };
        assert_eq!(yes_proposal.early_decision(), Vote::Yes);
        assert!(yes_proposal.can_make_decision(now_seconds));

        // Test case 4 cont.: ...becomes a loss if minimum_yes_proportion_of_exercised is increased
        let yes_proposal = ProposalData {
            latest_tally: Some(Tally {
                yes: 7_501,
                no: 2_499,
                total: 10_000,
                timestamp_seconds: 1,
            }),
            minimum_yes_proportion_of_exercised: Some(Percentage::from_basis_points(7_501)),
            ..undecided_proposal.clone()
        };
        assert_eq!(yes_proposal.early_decision(), Vote::No);
        assert!(yes_proposal.can_make_decision(now_seconds));
    }

    // Once an absolute majority has been achieved, it cannot be changed, regardless of additional voting.
    fn assert_early_decision_is_monotonic(initial_proposal: ProposalData) {
        let initial_decision = initial_proposal.early_decision();
        assert_ne!(
            initial_decision,
            Vote::Unspecified,
            "Initial tally does not have an absolute majority: {initial_proposal:#?}."
        );
        assert!(initial_proposal.can_make_decision(1));

        let Tally {
            yes,
            no,
            total,
            timestamp_seconds: _,
        } = initial_proposal.latest_tally.unwrap();

        // Ramp up yes votes.
        let max_yes = total - no;
        let mut later_proposal = initial_proposal.clone();
        for new_yes in yes..=max_yes {
            later_proposal.latest_tally.as_mut().unwrap().yes = new_yes;
            assert_eq!(
                later_proposal.early_decision(),
                initial_decision,
                "failed at new_yes={new_yes}. initial_proposal:\n{initial_proposal:#?}"
            );
            assert!(later_proposal.can_make_decision(1));
        }

        // Ramp up no votes.
        let max_no: u64 = total - yes;
        let mut later_proposal = initial_proposal.clone();
        for new_no in no..=max_no {
            later_proposal.latest_tally.as_mut().unwrap().no = new_no;
            assert_eq!(
                later_proposal.early_decision(),
                initial_decision,
                "failed at new_no={new_no}. initial_proposal:\n{initial_proposal:#?}"
            );
            assert!(later_proposal.can_make_decision(1));
        }
    }

    #[test]
    fn test_early_decision_is_monotonic() {
        let minimum_yes_proportion_of_total = Percentage::from_basis_points(0);

        // Absolute majority is Yes (barely), so no addition votes in either direction changes that.
        let yes_proposal = ProposalData {
            latest_tally: Some(Tally {
                yes: 5,
                no: 0,
                total: 9,
                ..Default::default()
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(minimum_yes_proportion_of_total),
            ..Default::default()
        };
        assert_eq!(yes_proposal.early_decision(), Vote::Yes);
        assert_early_decision_is_monotonic(yes_proposal);

        // Same for No.
        let no_proposal = ProposalData {
            latest_tally: Some(Tally {
                yes: 0,
                no: 5,
                total: 10,
                ..Default::default()
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(minimum_yes_proportion_of_total),
            ..Default::default()
        };
        assert_eq!(no_proposal.early_decision(), Vote::No);
        assert_early_decision_is_monotonic(no_proposal);
    }
}

mod can_make_decision {
    use super::*;

    proptest! {
        #[test]
        fn implied_by_early_decision(
            minimum_yes_proportion_of_total in 0u64..5_000,
            yes in 0u64..1_000_000,
            no in 0u64..1_000_000,
            uncast in 0u64..1_000_000,
        ) {
            let total = yes + no + uncast;
            let now_seconds = 2;
            let proposal = ProposalData {
                latest_tally: Some(
                    Tally {
                        yes,
                        no,
                        total,
                        timestamp_seconds: 1,
                    }
                ),
                proposal_creation_timestamp_seconds: 1,
                initial_voting_period_seconds: 10,
                minimum_yes_proportion_of_total: Some(Percentage::from_basis_points(minimum_yes_proportion_of_total)),
                ..Default::default()
            };
            let decision = proposal.early_decision();

            if decision != Vote::Unspecified {
                assert!(
                    proposal.can_make_decision(now_seconds)
                );
            }
        }
    }

    #[test]
    fn doesnt_overflow() {
        let now_seconds = 2;
        let yes_proposal = ProposalData {
            latest_tally: Some(Tally {
                yes: u64::MAX,
                no: 0,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(0.0)),
            ..Default::default()
        };
        assert!(yes_proposal.can_make_decision(now_seconds));

        let no_proposal = ProposalData {
            latest_tally: Some(Tally {
                yes: 0,
                no: u64::MAX,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(0.0)),
            ..Default::default()
        };
        assert!(no_proposal.can_make_decision(now_seconds));

        let split_proposal = ProposalData {
            latest_tally: Some(Tally {
                yes: u64::MAX / 2,
                no: u64::MAX / 2,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(3.0)),
            ..Default::default()
        };
        assert!(!split_proposal.can_make_decision(now_seconds));
    }
}

mod is_accepted {

    use super::*;

    proptest! {
        #[test]
        fn quorum_size_50_equivalent_to_absolute_majority(
            yes in 0u64..1_000_000,
            no in 0u64..1_000_000,
            uncast in 0u64..1_000_000,
        ) {
            let total = yes + no + uncast;
            let proposal = ProposalData {
                latest_tally: Some(
                    Tally {
                        yes,
                        no,
                        total,
                        timestamp_seconds: 1,
                    }
                ),
                proposal_creation_timestamp_seconds: 1,
                initial_voting_period_seconds: 10,
                minimum_yes_proportion_of_total: Some(Percentage::from_basis_points(5_000)),
                ..Default::default()
            };
            let early_decision = proposal.early_decision();
            let is_accepted_decision = proposal.is_accepted();

            assert_eq!(
                is_accepted_decision, early_decision == Vote::Yes,
                "Expected proposal.is_accepted() ({is_accepted_decision}) to be equivalent to proposal.early_decision() ({early_decision:?}) == Vote::Yes"
            );
        }
    }

    #[test]
    fn doesnt_overflow() {
        let p1 = ProposalData {
            latest_tally: Some(Tally {
                yes: u64::MAX,
                no: 0,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(0.0)),
            ..Default::default()
        };

        let p2 = ProposalData {
            latest_tally: Some(Tally {
                yes: 0,
                no: u64::MAX,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(0.0)),
            ..Default::default()
        };

        let p3 = ProposalData {
            latest_tally: Some(Tally {
                yes: u64::MAX / 2,
                no: u64::MAX / 2,
                total: u64::MAX,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(3.0)),
            ..Default::default()
        };

        assert!(p1.is_accepted());
        assert!(!p2.is_accepted());
        assert!(!p3.is_accepted());
    }

    #[test]
    fn quorum_size_variation() {
        let p0 = ProposalData {
            latest_tally: Some(Tally {
                yes: 0,
                no: 0,
                total: 10,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(0.0)),
            ..Default::default()
        };

        let p1 = ProposalData {
            latest_tally: Some(Tally {
                yes: 2,
                no: 0,
                total: 10,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(0.0)),
            ..Default::default()
        };

        let p2 = ProposalData {
            latest_tally: Some(Tally {
                yes: 2,
                no: 0,
                total: 10,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(10.0)),
            ..Default::default()
        };

        let p3 = ProposalData {
            latest_tally: Some(Tally {
                yes: 2,
                no: 0,
                total: 10,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(20.0)),
            ..Default::default()
        };

        let p4 = ProposalData {
            latest_tally: Some(Tally {
                yes: 2,
                no: 0,
                total: 10,
                timestamp_seconds: 1,
            }),
            proposal_creation_timestamp_seconds: 1,
            initial_voting_period_seconds: 10,
            minimum_yes_proportion_of_total: Some(Percentage::from_percentage(30.0)),
            ..Default::default()
        };

        assert!(!p0.is_accepted());
        assert!(p1.is_accepted());
        assert!(p2.is_accepted());
        assert!(p3.is_accepted());
        assert!(!p4.is_accepted());
    }
}
