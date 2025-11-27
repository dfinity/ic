use super::*;

#[test]
fn test_can_be_purged_retain_recent_transfer_sns_treasury_funds() {
    // Step 1: Prepare the world. In this case, that just consists of constructing a ProposalData to
    // use as input to the code under test.

    let now_timestamp_seconds = 123_456_789;

    let settled_proposal = ProposalData {
        decided_timestamp_seconds: now_timestamp_seconds - 15,
        executed_timestamp_seconds: now_timestamp_seconds - 10,
        reward_event_end_timestamp_seconds: Some(now_timestamp_seconds - 5),
        proposal: Some(Proposal {
            action: Some(Action::Motion(Default::default())),
            ..Default::default()
        }),
        // When reward_event_end_timestamp_seconds is Some (set above), there is a debug_assert that
        // says this field must be set like so.
        is_eligible_for_rewards: true,
        ..Default::default()
    };

    // Here, we are not exercising the code under test. Rather, this is to make sure that the usual
    // behavior of can_be_purged is different in the special case of TransferSnsTreasuryFunds.
    let status = settled_proposal.status();
    let reward_status = settled_proposal.reward_status(now_timestamp_seconds);
    assert!(status.is_final(), "{status:?}");
    assert!(reward_status.is_final(), "{status:?}");

    // Ordinarily (e.g. when the proposal is of type Motion), when the is_final methods of status
    // and reward_status return true, can_be_purged is supposed to return true.
    assert!(settled_proposal.can_be_purged(now_timestamp_seconds));

    // Change the proposal (from Motion) to TransferSnsTreasuryFunds.
    let settled_proposal = ProposalData {
        proposal: Some(Proposal {
            action: Some(Action::TransferSnsTreasuryFunds(Default::default())),
            ..Default::default()
        }),
        ..settled_proposal
    };

    // status and reward_status are supposed to be unaffected by action.
    let status = settled_proposal.status();
    let reward_status = settled_proposal.reward_status(now_timestamp_seconds);
    assert!(status.is_final(), "{status:?}");
    assert!(reward_status.is_final(), "{status:?}");

    // Step 2: Run the code under test under various scenarios.

    // Situation A: Proposal was executed "recently" (within the past 7 days). In this case, it is
    // supposed to be retained; thus, we want can_be_purged to return false.
    {
        // Substep 1: Run the code under test.
        let can_be_purged = settled_proposal.can_be_purged(now_timestamp_seconds);

        // Substep 2: Inspect the result.
        assert!(!can_be_purged);
    }

    // Situation B: Advance time by 7 days. Now, the proposal does not need to be retained anymore.
    {
        // Substep 1: Run the code under test, but now, at a later time.
        let can_be_purged =
            settled_proposal.can_be_purged(now_timestamp_seconds + 7 * ONE_DAY_SECONDS);

        // Substep 2: Unlike before, the proposal no longer needs to be retained.
        assert!(can_be_purged);
    }

    // Situation C: Proposal execution failed. In this case, there is no need to retain the proposal
    // (i.e. can_be_purged is supposed to return true here).
    {
        // Substep 1: Swap executed and failed timestamps.
        let t = settled_proposal.executed_timestamp_seconds;
        let failed_proposal = ProposalData {
            executed_timestamp_seconds: 0,
            failed_timestamp_seconds: t,
            ..settled_proposal
        };

        // Although the change we just made affects status, status.is_final() is still supposed to
        // be true.
        let status = failed_proposal.status();
        let reward_status = failed_proposal.reward_status(now_timestamp_seconds);
        assert!(status.is_final(), "{status:?}");
        assert!(reward_status.is_final(), "{status:?}");

        // Substep 2: Run the code under test.
        let can_be_purged = failed_proposal.can_be_purged(now_timestamp_seconds);

        // Substep 3: Inspect the result.
        assert!(can_be_purged);
    }
}

#[test]
fn test_total_treasury_transfer_amount_tokens() {
    let min_executed_timestamp_seconds = 123_456_789;

    let transfer_sns_treasury_funds = TransferSnsTreasuryFunds {
        from_treasury: TransferFrom::IcpTreasury as i32,
        amount_e8s: 999_000_000,
        // The following fields are not actually used, but are populated for realism.
        memo: None,
        to_principal: Some(PrincipalId::new_user_test_id(42)),
        to_subaccount: None,
    };

    let new_action = |transfer_sns_treasury_funds: TransferSnsTreasuryFunds| -> Option<Action> {
        Some(Action::TransferSnsTreasuryFunds(
            transfer_sns_treasury_funds.clone(),
        ))
    };

    let proposals = vec![
        // Skip because not of type TransferSnsTreasuryFunds.
        ProposalData {
            proposal: Some(Proposal {
                action: Some(Action::Motion(Default::default())),
                ..Default::default()
            }),
            executed_timestamp_seconds: min_executed_timestamp_seconds,
            ..Default::default()
        },
        // Skip because too old.
        ProposalData {
            proposal: Some(Proposal {
                action: new_action(transfer_sns_treasury_funds.clone()),
                ..Default::default()
            }),

            executed_timestamp_seconds: min_executed_timestamp_seconds - 1,
            ..Default::default()
        },
        // Skip because wrong type of token (SNS instead of ICP).
        ProposalData {
            proposal: Some(Proposal {
                action: new_action(TransferSnsTreasuryFunds {
                    from_treasury: TransferFrom::SnsTokenTreasury as i32,
                    ..transfer_sns_treasury_funds.clone()
                }),
                ..Default::default()
            }),

            executed_timestamp_seconds: min_executed_timestamp_seconds,
            ..Default::default()
        },
        // Ok.
        ProposalData {
            proposal: Some(Proposal {
                action: new_action(TransferSnsTreasuryFunds {
                    amount_e8s: 1,
                    ..transfer_sns_treasury_funds.clone()
                }),
                ..Default::default()
            }),

            executed_timestamp_seconds: min_executed_timestamp_seconds,
            ..Default::default()
        },
        // Ok.
        ProposalData {
            proposal: Some(Proposal {
                action: new_action(TransferSnsTreasuryFunds {
                    amount_e8s: 20,
                    ..transfer_sns_treasury_funds.clone()
                }),
                ..Default::default()
            }),

            executed_timestamp_seconds: min_executed_timestamp_seconds + 1,
            ..Default::default()
        },
        // Ok.
        ProposalData {
            proposal: Some(Proposal {
                action: new_action(TransferSnsTreasuryFunds {
                    amount_e8s: 300,
                    ..transfer_sns_treasury_funds.clone()
                }),
                ..Default::default()
            }),

            executed_timestamp_seconds: min_executed_timestamp_seconds + 123_456,
            ..Default::default()
        },
        // Pathological data: executed_timestamp_seconds is MAX. Still, the behavior of the code
        // under test is well-defined here. Therefore, we throw this in anyway.
        ProposalData {
            proposal: Some(Proposal {
                action: new_action(TransferSnsTreasuryFunds {
                    amount_e8s: 4000,
                    ..transfer_sns_treasury_funds.clone()
                }),
                ..Default::default()
            }),

            executed_timestamp_seconds: u64::MAX,
            ..Default::default()
        },
    ];

    assert_eq!(
        total_treasury_transfer_amount_tokens(
            proposals.iter(),
            TransferFrom::IcpTreasury,
            min_executed_timestamp_seconds,
        ),
        Ok(Decimal::from(4321) / Decimal::from(E8)),
    );

    // No time limit. This causes just one additional ProposalData to be included in the total. It
    // has the prototypical amount: 999_000_000, so the result here should be greater than the
    // previous result by this amount.
    assert_eq!(
        total_treasury_transfer_amount_tokens(
            proposals.iter(),
            TransferFrom::IcpTreasury,
            // This is somewhat pathological, but the behavior is still well-defined. Therefore, the
            // code under test should be able to handle this even though we do not expect to see
            // this in practice.
            0,
        ),
        Ok(Decimal::from(999_004_321) / Decimal::from(E8)),
    );

    // Add data to proposals that causes the total to be u64::MAX e8s.
    let proposals = {
        let mut result = proposals;

        let amount_e8s = u64::MAX - 4_321;
        result.push(ProposalData {
            proposal: Some(Proposal {
                action: new_action(TransferSnsTreasuryFunds {
                    amount_e8s,
                    ..transfer_sns_treasury_funds.clone()
                }),
                ..Default::default()
            }),

            executed_timestamp_seconds: min_executed_timestamp_seconds,
            ..Default::default()
        });

        result
    };

    // Assert result is MAX.
    assert_eq!(
        total_treasury_transfer_amount_tokens(
            proposals.iter(),
            TransferFrom::IcpTreasury,
            min_executed_timestamp_seconds,
        ),
        Ok(Decimal::from(u64::MAX) / Decimal::from(E8)),
    );

    // Add another proposal such that the total amount > u64::MAX.
    let proposals = {
        let mut result = proposals;
        result.push(ProposalData {
            proposal: Some(Proposal {
                action: new_action(TransferSnsTreasuryFunds {
                    amount_e8s: 1,
                    ..transfer_sns_treasury_funds.clone()
                }),
                ..Default::default()
            }),

            executed_timestamp_seconds: min_executed_timestamp_seconds,
            ..Default::default()
        });

        result
    };

    // Assert result is u64::MAX + 1.
    assert_eq!(
        total_treasury_transfer_amount_tokens(
            proposals.iter(),
            TransferFrom::IcpTreasury,
            min_executed_timestamp_seconds,
        ),
        Ok((Decimal::from(u64::MAX) + Decimal::from(1)) / Decimal::from(E8)),
    );
}
