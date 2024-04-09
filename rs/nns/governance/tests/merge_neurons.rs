//! The unit tests for `Governance` use *test fixtures*. The fixtures
//! are defi data_source: (), timestamp_seconds: ()ned as small but
//! complex/weird configurations of neurons and proposals against which several
//! tests are run.

use assert_matches::assert_matches;
#[cfg(feature = "test")]
use comparable::{Changed, MapChange, OptionChange, U64Change};
#[cfg(feature = "test")]
use fixtures::NNSStateChange;
use fixtures::{principal, NNSBuilder, NeuronBuilder};
use futures::future::FutureExt;
use ic_nns_common::pb::v1::NeuronId;
#[cfg(feature = "test")]
use ic_nns_governance::{
    governance::{governance_minting_account, Environment},
    pb::v1::{neuron::DissolveStateChange, GovernanceChange, NeuronChange},
};
use ic_nns_governance::{
    governance::{
        MAX_DISSOLVE_DELAY_SECONDS, MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
        ONE_YEAR_SECONDS,
    },
    pb::v1::{
        governance_error::ErrorType::{self, NotAuthorized, NotFound, PreconditionFailed},
        manage_neuron::{
            claim_or_refresh::By, ClaimOrRefresh, Command, Follow, Merge, NeuronIdOrSubaccount,
        },
        manage_neuron_response::{Command as CommandResponse, MergeResponse},
        neuron::{
            DissolveState,
            DissolveState::{DissolveDelaySeconds, WhenDissolvedTimestampSeconds},
            Followees,
        },
        proposal::{self},
        Empty, GovernanceError, ManageNeuron, ManageNeuronResponse, NetworkEconomics, Neuron,
        NeuronType, Topic,
    },
};
use ic_sns_swap::pb::v1::governance_error::ErrorType::RequiresNotDissolving;
use proptest::prelude::{proptest, TestCaseError};

// Using a `pub mod` works around spurious dead code warnings; see
// https://github.com/rust-lang/rust/issues/46379
pub mod fixtures;

const DEFAULT_TEST_START_TIMESTAMP_SECONDS: u64 = 999_111_000_u64;

/// Converts a number of ICP to e8s.
fn icp_to_e8s(amount: u64) -> u64 {
    amount * 100_000_000
}

/// Checks that merge_neurons fails if the preconditions are not met. In
/// particular, an attempt to merge a neuron fails if:
/// * 1. the source and target neuron's do not have the same controller.
/// In all these cases it must thus hold that:
/// * the correct error is returned
/// * the source and target neuron's are unchanged
/// * the list of all neurons is unchanged
/// * the list of accounts is unchanged
#[test]
fn test_merge_neurons_fails() {
    let mut nns = NNSBuilder::new()
        .set_economics(NetworkEconomics::with_default_values())
        .add_account_for(principal(1), icp_to_e8s(1))
        .add_account_for(principal(11), icp_to_e8s(100)) // in order to propose
        .add_neuron(
            NeuronBuilder::new(1, icp_to_e8s(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS)
                .set_maturity(icp_to_e8s(123))
                .set_aging_since_timestamp(0)
                .set_creation_timestamp(10)
                .set_kyc_verified(true)
                .set_not_for_profit(true),
        )
        .add_neuron(
            NeuronBuilder::new(2, icp_to_e8s(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp_to_e8s(456))
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .set_kyc_verified(false)
                .set_not_for_profit(false),
        )
        .add_neuron(
            NeuronBuilder::new(3, icp_to_e8s(4_560), principal(2))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_hotkeys(vec![principal(1)])
                .set_maturity(icp_to_e8s(456))
                .set_not_for_profit(true)
                .set_aging_since_timestamp(10),
        )
        .add_neuron(
            NeuronBuilder::new(4, icp_to_e8s(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp_to_e8s(456))
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .set_kyc_verified(true)
                .set_not_for_profit(false),
        )
        .add_neuron(
            NeuronBuilder::new(5, icp_to_e8s(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp_to_e8s(456))
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .set_kyc_verified(true)
                .set_not_for_profit(true)
                .set_joined_community_fund(10),
        )
        .add_neuron(
            NeuronBuilder::new(6, icp_to_e8s(3_456), principal(123))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4),
        )
        .add_neuron(
            NeuronBuilder::new(7, icp_to_e8s(3_456), principal(123))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_neuron_type(NeuronType::Seed),
        )
        .add_neuron(
            NeuronBuilder::new(8, icp_to_e8s(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp_to_e8s(456))
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .set_kyc_verified(true)
                .set_not_for_profit(true),
        )
        .add_neuron(
            NeuronBuilder::new(9, 1, principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp_to_e8s(456))
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .set_kyc_verified(true)
                .set_not_for_profit(true),
        )
        .add_neuron(
            NeuronBuilder::new(10, icp_to_e8s(4_560), principal(11))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp_to_e8s(456))
                .set_aging_since_timestamp(10),
        )
        .add_neuron(
            NeuronBuilder::new(11, icp_to_e8s(4_560), principal(11))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp_to_e8s(456))
                .set_aging_since_timestamp(50),
        )
        .add_neuron(
            NeuronBuilder::new(12, icp_to_e8s(4_560), principal(11))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp_to_e8s(456))
                .set_aging_since_timestamp(10),
        )
        .add_neuron(
            NeuronBuilder::new(13, icp_to_e8s(4_560), principal(11))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp_to_e8s(456))
                .set_aging_since_timestamp(10),
        )
        .add_neuron(
            NeuronBuilder::new(14, icp_to_e8s(3_456), principal(123))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4),
        )
        .add_neuron(
            NeuronBuilder::new(15, icp_to_e8s(3_456), principal(123))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4),
        )
        .add_neuron(
            NeuronBuilder::new(16, icp_to_e8s(1_234), principal(123))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .insert_managers(Followees {
                    followees: vec![NeuronId { id: 14 }],
                }),
        )
        .add_neuron(
            NeuronBuilder::new(17, icp_to_e8s(2_345), principal(123))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .insert_managers(Followees {
                    followees: vec![NeuronId { id: 15 }],
                }),
        )
        .add_neuron(
            NeuronBuilder::new(18, icp_to_e8s(3_456), principal(123))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4),
        )
        .add_neuron(
            NeuronBuilder::new(19, icp_to_e8s(1_234), principal(1))
                .set_spawn_at_timestamp_seconds(Some(100)),
        )
        .add_neuron(
            NeuronBuilder::new(20, icp_to_e8s(1_234), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS)
                .set_maturity(icp_to_e8s(123))
                .set_aging_since_timestamp(0)
                .set_creation_timestamp(10)
                .set_kyc_verified(true)
                .set_not_for_profit(true),
        )
        .add_neuron(
            NeuronBuilder::new(21, icp_to_e8s(1_234), principal(2))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS)
                .set_maturity(icp_to_e8s(123))
                .set_aging_since_timestamp(0)
                .set_creation_timestamp(10)
                .set_kyc_verified(true)
                .set_not_for_profit(true),
        )
        .create();

    // 1. Source id and target id cannot be the same
    // Previous iteration of this test looked for a message "Cannot merge a neuron into itself"
    // but we are now doing the lock_neuron_for_command calls before we get to that validation rule.
    // If the two neurons have the same ID, we will hit an error that there is already an in-flight
    // command for that NeuronId.  Thus, we are here checking that we in fact still prevent merging
    // a neuron into itself, but we are looking for an error message where you try to acquire a lock
    // for a neuron that already has a lock outstanding.
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 1 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == ErrorType::InvalidCommand as i32 &&
           msg == "Source id and target id cannot be the same");

    // 2. Target neuron must be owned by the caller
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 3 },
            &principal(1),
            &NeuronId { id: 1 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == NotAuthorized as i32 &&
           msg == "Target neuron must be owned by the caller");

    // 3. Source neuron must be owned by the caller
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 3 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == NotAuthorized as i32 &&
           msg == "Source neuron must be owned by the caller");

    // 4. Source neuron must be hotkey controlled if different controllers
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 21 },
            &principal(1),
            &NeuronId { id: 20 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == NotAuthorized as i32 &&
           msg == "Caller must be hotkey or controller of the target neuron");

    // 5. Target neuron must be hotkey controlled if different controllers
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 20 },
            &principal(1),
            &NeuronId { id: 21 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == NotAuthorized as i32 &&
           msg == "Caller must be hotkey or controller of the source neuron");

    // 6. Source neuron cannot be spawning
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 19 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "Can't perform operation on neuron: Source neuron is spawning.");

    // 7. Target neuron cannot be spawning
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 19 },
            &principal(1),
            &NeuronId { id: 1 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "Can't perform operation on neuron: Target neuron is spawning.");

    // 8. Source neuron's kyc_verified field must match target
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 2 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "Source neuron's kyc_verified field does not match target");

    // 9. Source neuron's not_for_profit field must match target
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 4 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "Source neuron's not_for_profit field does not match target");

    // 10. Cannot merge neurons that have been dedicated to the Neurons' Fund
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 5 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "Cannot merge neurons that have been dedicated to the Neurons' Fund");

    // 10b. Switch source and destination to ensure condition still holds
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 5 },
            &principal(1),
            &NeuronId { id: 1 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "Cannot merge neurons that have been dedicated to the Neurons' Fund");

    // 11. Neither neuron can be the proposer of an open proposal
    let _pid = nns.propose_and_vote("-----------P", "the unique proposal".to_string());
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 10 },
            &principal(11),
            &NeuronId { id: 11 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "Cannot merge neurons that are involved in open proposals");

    // 12. Neither neuron can be the subject of a MergeNeuron proposal
    nns.governance
        .manage_neuron(
            &principal(11),
            &ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 12 })),
                id: None,
                command: Some(Command::Follow(Follow {
                    topic: Topic::NeuronManagement as i32,
                    followees: (0..=11).map(|id| NeuronId { id }).collect(),
                })),
            },
        )
        .now_or_never()
        .unwrap();
    nns.governance
        .manage_neuron(
            &principal(11),
            &ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 13 })),
                id: None,
                command: Some(Command::Follow(Follow {
                    topic: Topic::NeuronManagement as i32,
                    followees: (0..=11).map(|id| NeuronId { id }).collect(),
                })),
            },
        )
        .now_or_never()
        .unwrap();
    let _pid = nns.propose_with_action(
        // We will have Neuron 11, not involved in the upcoming merge,
        // proposal a neuron management proposal for Neuron 12.
        &"-----------P".into(),
        "another unique proposal".to_string(),
        proposal::Action::ManageNeuron(Box::new(ManageNeuron {
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 12 })),
            id: None,
            command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                by: Some(By::NeuronIdOrSubaccount(Empty {})),
            })),
        })),
    );
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 12 },
            &principal(11),
            &NeuronId { id: 13 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "Cannot merge neurons that are involved in open proposals");

    // 13. Source neuron must exist
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 100 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == NotFound as i32 &&
           msg == "Source neuron not found");

    // 14. Target neuron must exist
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 100 },
            &principal(1),
            &NeuronId { id: 8 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == NotFound as i32 &&
           msg == "Target neuron not found");

    // 15. Neurons with different ManageNeuron lists cannot be merged
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 16 },
            &principal(123),
            &NeuronId { id: 17 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "ManageNeuron following of source and target does not match");

    // 16. Neurons with resp. without ManageNeuron cannot be merged
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 16 },
            &principal(123),
            &NeuronId { id: 18 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "ManageNeuron following of source and target does not match");

    // 17. Neurons with unequal NeuronType can't be merged
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 6 },
            &principal(123),
            &NeuronId { id: 7 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
            msg == "Source neuron's neuron_type field does not match target");
}

#[test]
fn test_merge_neurons_only_works_for_non_dissolving_neurons_with_dissolve_delay() {
    fn try_merging_dissolve_states(
        source_dissolve_state: Option<DissolveState>,
        target_dissolve_state: Option<DissolveState>,
    ) -> Result<(), GovernanceError> {
        let start_time = DEFAULT_TEST_START_TIMESTAMP_SECONDS;
        let mut nns = NNSBuilder::new()
            .set_start_time(start_time)
            .set_economics(NetworkEconomics::with_default_values())
            .with_supply(0) // causes minting account to be created
            .add_account_for(principal(1), 0)
            .add_neuron(
                NeuronBuilder::new(1, icp_to_e8s(1), principal(1))
                    .set_dissolve_state(source_dissolve_state),
            )
            .add_neuron(
                NeuronBuilder::new(2, icp_to_e8s(1), principal(1))
                    .set_dissolve_state(target_dissolve_state),
            )
            .create();

        nns.merge_neurons(&NeuronId { id: 2 }, &principal(1), &NeuronId { id: 1 })
    }
    let start_time = DEFAULT_TEST_START_TIMESTAMP_SECONDS;

    // Successful responses as precondition
    assert_eq!(
        try_merging_dissolve_states(Some(DissolveDelaySeconds(1)), Some(DissolveDelaySeconds(1))),
        Ok(())
    );

    let cases = [
        // None DissolveState
        (None, None),
        (Some(DissolveDelaySeconds(1)), None),
        (None, Some(DissolveDelaySeconds(1))),
        // 0 DissolveDelaySeconds
        (Some(DissolveDelaySeconds(0)), Some(DissolveDelaySeconds(0))),
        (Some(DissolveDelaySeconds(1)), Some(DissolveDelaySeconds(0))),
        (Some(DissolveDelaySeconds(0)), Some(DissolveDelaySeconds(1))),
        // Dissolving
        (
            Some(WhenDissolvedTimestampSeconds(start_time + 100)),
            Some(WhenDissolvedTimestampSeconds(start_time + 100)),
        ),
        (
            Some(DissolveDelaySeconds(1)),
            Some(WhenDissolvedTimestampSeconds(start_time + 100)),
        ),
        (
            Some(WhenDissolvedTimestampSeconds(start_time + 100)),
            Some(DissolveDelaySeconds(1)),
        ),
        // Dissolved
        (
            Some(WhenDissolvedTimestampSeconds(start_time - 100)),
            Some(WhenDissolvedTimestampSeconds(start_time - 100)),
        ),
        (
            Some(DissolveDelaySeconds(1)),
            Some(WhenDissolvedTimestampSeconds(start_time - 100)),
        ),
        (
            Some(WhenDissolvedTimestampSeconds(start_time - 100)),
            Some(DissolveDelaySeconds(1)),
        ),
    ];

    for (source, dest) in cases {
        assert_matches!(try_merging_dissolve_states(source, dest),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == RequiresNotDissolving as i32 &&
           msg == "Only two non-dissolving neurons with a dissolve delay greater than 0 can be merged.");
    }
}

#[test]
fn test_simulate_merge_neuron_allowed_for_hotkey_controlled_neurons() {
    let mut nns = NNSBuilder::new()
        .set_economics(NetworkEconomics::with_default_values())
        .add_account_for(principal(1), icp_to_e8s(1))
        .add_account_for(principal(11), icp_to_e8s(100)) // in order to propose
        .add_neuron(
            NeuronBuilder::new(1, icp_to_e8s(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS)
                .set_maturity(icp_to_e8s(123))
                .set_aging_since_timestamp(0)
                .set_creation_timestamp(10)
                .set_kyc_verified(true)
                .set_not_for_profit(true),
        )
        .add_neuron(
            NeuronBuilder::new(2, icp_to_e8s(1), principal(2))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp_to_e8s(456))
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .set_kyc_verified(true)
                .set_not_for_profit(false),
        )
        .add_neuron(
            NeuronBuilder::new(3, icp_to_e8s(1), principal(2))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp_to_e8s(456))
                .set_hotkeys(vec![principal(1)])
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .set_kyc_verified(true)
                .set_not_for_profit(true),
        )
        .create();

    // Error for Source
    assert_matches!(
        nns.simulate_merge_neurons(&NeuronId { id: 1 }, &principal(1), &NeuronId { id: 2 },),
        ManageNeuronResponse {
            command: Some(CommandResponse::Error(GovernanceError {
                error_type: code,
                error_message: msg,
            }))
        }
        if code == NotAuthorized as i32 &&
           msg == "Caller must be hotkey or controller of the source neuron"
    );

    // Error for target
    assert_matches!(
        nns.simulate_merge_neurons(&NeuronId { id: 2 }, &principal(1), &NeuronId { id: 1 },),
        ManageNeuronResponse {
            command: Some(CommandResponse::Error(GovernanceError {
                error_type: code,
                error_message: msg,
            }))
        }
        if code == NotAuthorized as i32 &&
           msg == "Caller must be hotkey or controller of the target neuron"
    );

    // Successful responses
    assert_matches!(
        nns.simulate_merge_neurons(&NeuronId { id: 1 }, &principal(1), &NeuronId { id: 3 },),
        ManageNeuronResponse {
            command: Some(CommandResponse::Merge(_))
        }
    );

    assert_matches!(
        nns.simulate_merge_neurons(&NeuronId { id: 3 }, &principal(1), &NeuronId { id: 1 },),
        ManageNeuronResponse {
            command: Some(CommandResponse::Merge(_))
        }
    );
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::vec_init_then_push)]
fn do_test_merge_neurons(
    mut n1_cached_stake: u64,
    n1_maturity: u64,
    n1_fees: u64,
    n1_dissolve: u64,
    n1_age: u64,
    mut n2_cached_stake: u64,
    n2_maturity: u64,
    n2_fees: u64,
    n2_dissolve: u64,
    n2_age: u64,
) -> Result<(), TestCaseError> {
    // Ensure that the cached_stake includes the fees
    n1_cached_stake += n1_fees;
    n2_cached_stake += n2_fees;

    // Start the NNS 20 years after genesis, to give lots of time for aging.
    let epoch = DEFAULT_TEST_START_TIMESTAMP_SECONDS + (20 * ONE_YEAR_SECONDS);

    let mut nns = NNSBuilder::new()
        .set_start_time(epoch)
        .set_economics(NetworkEconomics::with_default_values())
        .with_supply(0) // causes minting account to be created
        .add_account_for(principal(1), 0)
        // the source
        .add_neuron(
            NeuronBuilder::new(1, n1_cached_stake, principal(1))
                .set_dissolve_delay(n1_dissolve)
                .set_maturity(n1_maturity)
                .set_neuron_fees(n1_fees)
                .set_aging_since_timestamp(epoch.saturating_sub(n1_age)),
        )
        // the target
        .add_neuron(
            NeuronBuilder::new(2, n2_cached_stake, principal(1))
                .set_dissolve_delay(n2_dissolve)
                .set_maturity(n2_maturity)
                .set_neuron_fees(n2_fees)
                .set_aging_since_timestamp(epoch.saturating_sub(n2_age)),
        )
        .create();

    // advance by a year, just to spice things up
    nns.advance_time_by(ONE_YEAR_SECONDS);

    // First simulate
    let simulate_neuron_response = nns
        .governance
        .simulate_manage_neuron(
            &principal(1),
            ManageNeuron {
                id: Some(NeuronId { id: 2 }),
                neuron_id_or_subaccount: None,
                command: Some(Command::Merge(Merge {
                    source_neuron_id: Some(NeuronId { id: 1 }),
                })),
            },
        )
        .now_or_never()
        .unwrap();

    // Assert no changes (except time) after simulate.
    #[cfg(feature = "test")]
    prop_assert_changes!(
        nns,
        Changed::Changed(vec![NNSStateChange::Now(U64Change(
            epoch,
            epoch + ONE_YEAR_SECONDS
        ))])
    );

    let merge_neuron_response = nns
        .governance
        .merge_neurons(
            &NeuronId { id: 2 },
            &principal(1),
            &Merge {
                source_neuron_id: Some(NeuronId { id: 1 }),
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    // Assert simulated result is the same as actual result
    pretty_assertions::assert_eq!(merge_neuron_response, simulate_neuron_response);

    //Assert that simulate response gives correct outputs
    match merge_neuron_response.command.unwrap() {
        CommandResponse::Merge(m) => {
            let MergeResponse {
                source_neuron,
                target_neuron,
                source_neuron_info,
                target_neuron_info,
            } = m;
            let source_neuron = source_neuron.unwrap();
            let target_neuron = target_neuron.unwrap();
            let source_neuron_info = source_neuron_info.unwrap();
            let target_neuron_info = target_neuron_info.unwrap();

            let source_neuron_id = source_neuron.id.unwrap();
            let target_neuron_id = target_neuron.id.unwrap();

            pretty_assertions::assert_eq!(
                source_neuron,
                nns.governance
                    .neuron_store
                    .with_neuron(&source_neuron_id, |n| Neuron::from(n.clone()))
                    .unwrap()
            );
            pretty_assertions::assert_eq!(
                target_neuron,
                nns.governance
                    .neuron_store
                    .with_neuron(&target_neuron_id, |n| Neuron::from(n.clone()))
                    .unwrap()
            );
            pretty_assertions::assert_eq!(
                source_neuron_info,
                nns.governance.get_neuron_info(&source_neuron_id).unwrap()
            );
            pretty_assertions::assert_eq!(
                target_neuron_info,
                nns.governance.get_neuron_info(&target_neuron_id).unwrap()
            );
        }
        CommandResponse::Error(e) => panic!("Received Error: {}", e),
        _ => panic!("Wrong response received"),
    }

    #[cfg(feature = "test")]
    let fee = nns
        .governance
        .heap_data
        .economics
        .as_ref()
        .unwrap()
        .transaction_fee_e8s;

    // Test internal changes
    #[cfg(feature = "test")]
    prop_assert_changes!(
        nns,
        Changed::Changed({
            let stake_to_transfer = if n1_cached_stake > fee {
                n1_cached_stake.saturating_sub(n1_fees).saturating_sub(fee)
            } else {
                0
            };

            let cached_stake_remaining;
            if n1_fees > fee {
                if n1_cached_stake.saturating_sub(n1_fees) > fee {
                    cached_stake_remaining = 0;
                } else {
                    cached_stake_remaining = n1_cached_stake.saturating_sub(n1_fees);
                }
            } else if n1_cached_stake.saturating_sub(n1_fees) > fee {
                cached_stake_remaining = n1_fees;
            } else {
                cached_stake_remaining = n1_cached_stake;
            }

            let mut changes = Vec::new();

            let account_changes = {
                let mut changes = Vec::new();

                if stake_to_transfer > 0 {
                    changes.push(MapChange::Changed(
                        nns.get_neuron_account_id(2),
                        U64Change(n2_cached_stake, n2_cached_stake + stake_to_transfer),
                    ));
                }

                if n1_fees > fee {
                    changes.push(MapChange::Changed(
                        governance_minting_account(),
                        U64Change(0, n1_fees),
                    ));
                }

                if n1_cached_stake != cached_stake_remaining {
                    changes.push(MapChange::Changed(
                        nns.get_neuron_account_id(1),
                        U64Change(n1_cached_stake, cached_stake_remaining),
                    ));
                }

                changes
            };

            let neuron_changes = {
                let neuron1_changes = {
                    let mut changes = Vec::new();

                    if n1_cached_stake != cached_stake_remaining {
                        changes.push(NeuronChange::CachedNeuronStakeE8S(U64Change(
                            n1_cached_stake,
                            cached_stake_remaining,
                        )));
                    }

                    if n1_fees > fee {
                        changes.push(NeuronChange::NeuronFeesE8S(U64Change(n1_fees, 0)));
                    }

                    let old_age = epoch.saturating_sub(n1_age);
                    let new_age = if stake_to_transfer > 0 {
                        nns.now()
                    } else {
                        old_age
                    };
                    if old_age != new_age {
                        changes.push(NeuronChange::AgingSinceTimestampSeconds(U64Change(
                            old_age, new_age,
                        )));
                    }

                    if n1_maturity > 0 {
                        changes.push(NeuronChange::MaturityE8SEquivalent(U64Change(
                            n1_maturity,
                            0,
                        )));
                    }

                    changes
                };
                let neuron2_changes = {
                    let mut changes = Vec::new();

                    if stake_to_transfer > 0 {
                        changes.push(NeuronChange::CachedNeuronStakeE8S(U64Change(
                            n2_cached_stake,
                            n2_cached_stake + stake_to_transfer,
                        )));
                    }

                    let old_age = epoch.saturating_sub(n2_age);
                    let new_age = {
                        let n1_age_seconds = if n1_dissolve == 0 {
                            0
                        } else {
                            nns.now().saturating_sub(epoch.saturating_sub(n1_age))
                        };
                        let n2_age_seconds = if n2_dissolve == 0 {
                            0
                        } else {
                            nns.now().saturating_sub(old_age)
                        };
                        let (_new_cached_stake, new_age_seconds) =
                            ic_nns_governance::governance::combine_aged_stakes(
                                n2_cached_stake,
                                n2_age_seconds,
                                n1_cached_stake.saturating_sub(n1_fees).saturating_sub(fee),
                                n1_age_seconds,
                            );
                        nns.now().saturating_sub(new_age_seconds)
                    };

                    if old_age != new_age {
                        changes.push(NeuronChange::AgingSinceTimestampSeconds(U64Change(
                            old_age, new_age,
                        )));
                    }

                    if n1_maturity > 0 {
                        changes.push(NeuronChange::MaturityE8SEquivalent(U64Change(
                            n2_maturity,
                            n2_maturity + n1_maturity,
                        )));
                    }

                    if n1_dissolve > n2_dissolve {
                        changes.push(NeuronChange::DissolveState(OptionChange::BothSome(
                            DissolveStateChange::BothDissolveDelaySeconds(U64Change(
                                n2_dissolve,
                                n1_dissolve,
                            )),
                        )));
                    }

                    changes
                };
                let mut changes = Vec::new();
                if !neuron1_changes.is_empty() {
                    changes.push(MapChange::Changed(1, neuron1_changes));
                }
                if !neuron2_changes.is_empty() {
                    changes.push(MapChange::Changed(2, neuron2_changes));
                }
                changes
            };

            if !account_changes.is_empty() {
                changes.push(NNSStateChange::Accounts(account_changes));
            }
            if !neuron_changes.is_empty() {
                changes.push(NNSStateChange::GovernanceProto(vec![
                    GovernanceChange::Neurons(neuron_changes),
                ]));
            }

            changes
        })
    );

    Ok(())
}

proptest! {

#[test]
fn test_merge_neurons_small(
    n1_stake in 0u64..50_000,
    n1_maturity in 0u64..500_000_000,
    n1_fees in 0u64..20_000,
    n1_dissolve in 1u64..MAX_DISSOLVE_DELAY_SECONDS,
    n1_age in 0u64..315_360_000,
    n2_stake in 0u64..50_000,
    n2_maturity in 0u64..500_000_000,
    n2_fees in 0u64..20_000,
    n2_dissolve in 1u64..MAX_DISSOLVE_DELAY_SECONDS,
    n2_age in 0u64..315_360_000
) {
    do_test_merge_neurons(
        n1_stake,
        n1_maturity,
        n1_fees,
        n1_dissolve,
        n1_age,
        n2_stake,
        n2_maturity,
        n2_fees,
        n2_dissolve,
        n2_age,
    )?;
}

#[test]
fn test_merge_neurons_normal(
    n1_stake in 0u64..500_000_000,

    n1_maturity in 0u64..500_000_000,
    n1_fees in 0u64..20_000,
    n1_dissolve in 1u64..MAX_DISSOLVE_DELAY_SECONDS,
    n1_age in 0u64..315_360_000,
    n2_stake in 0u64..500_000_000,
    n2_maturity in 0u64..500_000_000,
    n2_fees in 0u64..20_000,
    n2_dissolve in 1u64..MAX_DISSOLVE_DELAY_SECONDS,
    n2_age in 0u64..315_360_000
) {
    do_test_merge_neurons(
        n1_stake,
        n1_maturity,
        n1_fees,
        n1_dissolve,
        n1_age,
        n2_stake,
        n2_maturity,
        n2_fees,
        n2_dissolve,
        n2_age,
    )?;
}

}

#[test]
// Test that two neurons that have the same ManageNeuron following can be merged
fn test_neuron_merge_follow() {
    fn icp(amount: u64) -> u64 {
        amount * 100_000_000
    }

    let n1_stake = icp(1);
    let n2_stake = icp(10);
    let n3_stake = icp(10);

    let mut nns = NNSBuilder::new()
        .set_economics(NetworkEconomics::with_default_values())
        .with_supply(0) // causes minting account to be created
        .add_account_for(principal(1), 0)
        // the controller
        .add_neuron(
            NeuronBuilder::new(1, n1_stake, principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4),
        )
        // the source
        .add_neuron(
            NeuronBuilder::new(2, n2_stake, principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_aging_since_timestamp(DEFAULT_TEST_START_TIMESTAMP_SECONDS)
                .insert_managers(Followees {
                    followees: vec![NeuronId { id: 1 }],
                }),
        )
        // the target
        .add_neuron(
            NeuronBuilder::new(3, n3_stake, principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_aging_since_timestamp(DEFAULT_TEST_START_TIMESTAMP_SECONDS)
                .insert_managers(Followees {
                    followees: vec![NeuronId { id: 1 }],
                }),
        )
        .create();

    nns.governance
        .merge_neurons(
            &NeuronId { id: 3 },
            &principal(1),
            &Merge {
                source_neuron_id: Some(NeuronId { id: 2 }),
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    #[cfg(feature = "test")]
    let fee = nns
        .governance
        .heap_data
        .economics
        .as_ref()
        .unwrap()
        .transaction_fee_e8s;

    #[cfg(feature = "test")]
    assert_changes!(
        nns,
        Changed::Changed(vec![
            NNSStateChange::Accounts(vec![
                MapChange::Changed(nns.get_neuron_account_id(2), U64Change(n2_stake, 0)),
                MapChange::Changed(
                    nns.get_neuron_account_id(3),
                    U64Change(n3_stake, n3_stake + n2_stake.saturating_sub(fee)),
                ),
            ]),
            NNSStateChange::GovernanceProto(vec![GovernanceChange::Neurons(vec![
                MapChange::Changed(
                    2,
                    vec![NeuronChange::CachedNeuronStakeE8S(U64Change(n2_stake, 0)),],
                ),
                MapChange::Changed(
                    3,
                    vec![NeuronChange::CachedNeuronStakeE8S(U64Change(
                        n3_stake,
                        n3_stake + n2_stake.saturating_sub(fee),
                    )),],
                ),
            ])]),
        ])
    );
}
