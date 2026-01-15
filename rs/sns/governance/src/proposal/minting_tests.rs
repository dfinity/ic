use super::*;

// This is a copy n' paste of test_can_be_purged_retain_recent_transfer_sns_treasury_funds with some
// modifications for TransferSnsTreasuryFunds -> MintSnsTokens.
#[test]
fn test_can_be_purged_retain_recent_mint_sns_tokens() {
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
    // behavior of can_be_purged is different in the special case of MintSnsTokens.
    let status = settled_proposal.status();
    let reward_status = settled_proposal.reward_status(now_timestamp_seconds);
    assert!(status.is_final(), "{status:?}");
    assert!(reward_status.is_final(), "{status:?}");

    // Ordinarily (e.g. when the proposal is of type Motion), when the is_final methods of status
    // and reward_status return true, can_be_purged is supposed to return true.
    assert!(settled_proposal.can_be_purged(now_timestamp_seconds));

    // Change the proposal (from Motion) to MintSnsTokens.
    let settled_proposal = ProposalData {
        proposal: Some(Proposal {
            action: Some(Action::MintSnsTokens(Default::default())),
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

// This is a copy n' paste from ./treasury_tests.rs with some modifications for
// TransferSnsTreasuryFunds -> MintSnsTokens.
#[test]
fn test_total_minting_amount_tokens() {
    let min_executed_timestamp_seconds = 123_456_789;

    let mint_sns_tokens = MintSnsTokens {
        amount_e8s: Some(999_000_000),

        memo: None,
        to_principal: Some(PrincipalId::new_user_test_id(42)),
        to_subaccount: None,
    };

    let new_proposal =
        |mint_sns_tokens: MintSnsTokens, executed_timestamp_seconds: u64| -> ProposalData {
            let proposal = Some(Proposal {
                action: Some(Action::MintSnsTokens(mint_sns_tokens)),
                ..Default::default()
            });

            ProposalData {
                proposal,
                executed_timestamp_seconds,
                ..Default::default()
            }
        };

    let proposals = [
        // Skip because not of type MintSnsTokens.
        ProposalData {
            proposal: Some(Proposal {
                action: Some(Action::Motion(Default::default())),
                ..Default::default()
            }),
            executed_timestamp_seconds: min_executed_timestamp_seconds,
            ..Default::default()
        },
        // Skip because too old.
        new_proposal(mint_sns_tokens.clone(), min_executed_timestamp_seconds - 1),
        // Ok.
        new_proposal(
            MintSnsTokens {
                amount_e8s: Some(1),
                ..mint_sns_tokens.clone()
            },
            min_executed_timestamp_seconds,
        ),
        // Ok.
        new_proposal(
            MintSnsTokens {
                amount_e8s: Some(20),
                ..mint_sns_tokens.clone()
            },
            min_executed_timestamp_seconds + 1,
        ),
        // Ok.
        new_proposal(
            MintSnsTokens {
                amount_e8s: Some(300),
                ..mint_sns_tokens.clone()
            },
            min_executed_timestamp_seconds + 123_456,
        ),
        // Pathological data: executed_timestamp_seconds is MAX. Still, the behavior of the code
        // under test is well-defined here. Therefore, we throw this in anyway.
        new_proposal(
            MintSnsTokens {
                amount_e8s: Some(4000),
                ..mint_sns_tokens.clone()
            },
            u64::MAX,
        ),
    ];

    assert_eq!(
        total_minting_amount_tokens(proposals.iter(), min_executed_timestamp_seconds,),
        Ok(Decimal::from(4321) / Decimal::from(E8)),
    );
}
