//! The unit tests for `Governance` use *test fixtures*. The fixtures
//! are defi data_source: (), timestamp_seconds: ()ned as small but
//! complex/weird configurations of neurons and proposals against which several
//! tests are run.

use assert_matches::assert_matches;
use candid::Encode;
#[cfg(feature = "test")]
use comparable::{Changed, I32Change, MapChange, OptionChange, StringChange, U64Change, VecChange};
use futures::future::FutureExt;
use ic_base_types::PrincipalId;
use ic_crypto_sha::Sha256;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_common::types::UpdateIcpXdrConversionRatePayload;
use ic_nns_constants::ids::{TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
#[cfg(feature = "test")]
use ic_nns_governance::governance::governance_minting_account;
#[cfg(feature = "test")]
use ic_nns_governance::pb::v1::{
    governance::GovernanceCachedMetricsChange, neuron::DissolveStateChange, proposal::ActionDesc,
    BallotChange, BallotInfoChange, GovernanceChange, NeuronChange, ProposalChange,
    ProposalDataChange, TallyChange, WaitForQuietStateDesc,
};
use ic_nns_governance::{
    governance::{
        subaccount_from_slice, validate_proposal_title, Environment, Governance,
        EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX,
        MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS, PROPOSAL_MOTION_TEXT_BYTES_MAX,
        REWARD_DISTRIBUTION_PERIOD_SECONDS, WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS,
    },
    init::GovernanceCanisterInitPayloadBuilder,
    pb::v1::{
        add_or_remove_node_provider::Change,
        governance_error::ErrorType::{
            self, External, InsufficientFunds, InvalidCommand, NotAuthorized, PreconditionFailed,
        },
        manage_neuron,
        manage_neuron::claim_or_refresh::{By, MemoAndController},
        manage_neuron::configure::Operation,
        manage_neuron::disburse::Amount,
        manage_neuron::ClaimOrRefresh,
        manage_neuron::Command,
        manage_neuron::Configure,
        manage_neuron::Disburse,
        manage_neuron::DisburseToNeuron,
        manage_neuron::Follow,
        manage_neuron::IncreaseDissolveDelay,
        manage_neuron::JoinCommunityFund,
        manage_neuron::Merge,
        manage_neuron::NeuronIdOrSubaccount,
        manage_neuron::SetDissolveTimestamp,
        manage_neuron::Spawn,
        manage_neuron::Split,
        manage_neuron::StartDissolving,
        manage_neuron_response,
        manage_neuron_response::Command as CommandResponse,
        neuron,
        neuron::DissolveState,
        neuron::Followees,
        proposal,
        reward_node_provider::{RewardMode, RewardToAccount, RewardToNeuron},
        AddOrRemoveNodeProvider, Ballot, BallotInfo, Empty, ExecuteNnsFunction,
        Governance as GovernanceProto, GovernanceError, KnownNeuron, KnownNeuronData, ListNeurons,
        ListNeuronsResponse, ListProposalInfo, ManageNeuron, Motion, NetworkEconomics, Neuron,
        NeuronState, NnsFunction, NodeProvider, Proposal, ProposalData, ProposalStatus,
        RewardEvent, RewardNodeProvider, SetDefaultFollowees, Tally, Topic, Vote,
    },
};
use ledger_canister::{AccountIdentifier, Memo, Tokens};
use maplit::hashmap;
use proptest::prelude::proptest;
use registry_canister::mutations::do_add_node_operator::AddNodeOperatorPayload;

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::iter;
use std::iter::once;
use std::path::PathBuf;

use dfn_protobuf::ToProto;
use ic_nns_governance::governance::{
    MAX_DISSOLVE_DELAY_SECONDS, MAX_NEURON_AGE_FOR_AGE_BONUS, MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS,
    ONE_DAY_SECONDS, ONE_YEAR_SECONDS,
};
use ic_nns_governance::pb::v1::governance::GovernanceCachedMetrics;
use ic_nns_governance::pb::v1::governance_error::ErrorType::{NotFound, ResourceExhausted};
use ic_nns_governance::pb::v1::manage_neuron::MergeMaturity;
use ic_nns_governance::pb::v1::manage_neuron_response::MergeMaturityResponse;
use ic_nns_governance::pb::v1::proposal::Action;
use ic_nns_governance::pb::v1::ProposalRewardStatus::{AcceptVotes, ReadyToSettle};
use ic_nns_governance::pb::v1::ProposalStatus::Rejected;
use ic_nns_governance::pb::v1::{ProposalRewardStatus, RewardNodeProviders, UpdateNodeProvider};
use ledger_canister::Subaccount;

/// The 'fake' module is the old scheme for providing NNS test fixtures, aka
/// the FakeDriver. It is being used here until the older tests have been
/// ported to the new 'fixtures' module.
mod fake;

// Using a `pub mod` works around spurious dead code warnings; see
// https://github.com/rust-lang/rust/issues/46379
pub mod fixtures;

use fixtures::{principal, NNSBuilder, NeuronBuilder};
#[cfg(feature = "test")]
use fixtures::{prorated_neuron_age, LedgerBuilder, NNSStateChange, ProposalNeuronBehavior, NNS};

// Using a `pub mod` works around spurious dead code warnings; see
// https://github.com/rust-lang/rust/issues/46379
pub mod common;

use common::increase_dissolve_delay_raw;
use ic_nervous_system_common::ledger::Ledger;

const DEFAULT_TEST_START_TIMESTAMP_SECONDS: u64 = 999_111_000_u64;

#[cfg(feature = "test")]
fn check_proposal_status_after_voting_and_after_expiration_new(
    neurons: impl IntoIterator<Item = Neuron>,
    behavior: impl Into<ProposalNeuronBehavior>,
    expected_after_voting: ProposalStatus,
    expected_after_expiration: ProposalStatus,
) -> NNS {
    let expiration_seconds = 17; // Arbitrary duration
    let mut nns = NNSBuilder::new()
        .set_wait_for_quiet_threshold_seconds(expiration_seconds)
        .set_economics(NetworkEconomics {
            reject_cost_e8s: 0,          // It's the default, but specify for emphasis
            neuron_minimum_stake_e8s: 0, // It's the default, but specify for emphasis
            ..NetworkEconomics::default()
        })
        .add_neurons(neurons.into_iter().zip(0_u64..))
        .create();

    let pid = nns.propose_and_vote(behavior, "the unique proposal".to_string());
    let after_voting = nns.governance.get_proposal_data(pid).unwrap().clone();

    assert_eq!(
        after_voting.status(),
        expected_after_voting,
        "After voting: {:?}",
        after_voting
    );

    nns.advance_time_by(expiration_seconds - 1)
        .run_periodic_tasks();
    // The proposal should still be open for voting, so nothing should have changed
    assert_eq!(
        *nns.governance.get_proposal_data(pid).unwrap(),
        after_voting
    );

    // One more second brings us to proposal expiration
    nns.advance_time_by(1);
    nns.governance.run_periodic_tasks().now_or_never();
    let after_expiration = nns.governance.get_proposal_data(pid).unwrap();

    assert_eq!(
        after_expiration.status(),
        expected_after_expiration,
        "After expiration: {:?}",
        after_expiration
    );

    nns
}

const NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE: Option<DissolveState> = Some(
    DissolveState::DissolveDelaySeconds(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS),
);

const NOTDISSOLVING_MAX_DISSOLVE_DELAY: Option<DissolveState> = Some(
    DissolveState::DissolveDelaySeconds(MAX_DISSOLVE_DELAY_SECONDS),
);

// To avoid this failure, you need to run cargo test with --features test. The
// reason we require that flag is to ensure that release builds are within the
// required size (3 MB). That goal is achieved by culling test-only libraries
// (specifically, comparable).
#[cfg(not(feature = "test"))]
#[allow(clippy::assertions_on_constants)]
#[test]
fn tests_must_be_run_with_test_feature_enabled() {
    assert!(false);
}

#[cfg(feature = "test")]
#[test]
fn test_single_neuron_proposal_new() {
    let mut nns = check_proposal_status_after_voting_and_after_expiration_new(
        vec![Neuron {
            dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
            cached_neuron_stake_e8s: 1,
            ..Neuron::default()
        }],
        "P",
        ProposalStatus::Executed,
        ProposalStatus::Executed,
    );
    assert_changes!(
        nns,
        Changed::Changed(vec![
            NNSStateChange::Now(U64Change(999111000, 999111017)),
            NNSStateChange::GovernanceProto(vec![
                GovernanceChange::Neurons(vec![MapChange::Changed(
                    0,
                    vec![NeuronChange::RecentBallots(vec![VecChange::Added(
                        0,
                        vec![
                            BallotInfoChange::ProposalId(OptionChange::Different(
                                None,
                                Some(ProposalId { id: 1 }),
                            )),
                            BallotInfoChange::Vote(I32Change(0, 1)),
                        ],
                    )])],
                )]),
                GovernanceChange::Proposals(vec![MapChange::Added(
                    1,
                    vec![
                        ProposalDataChange::Id(OptionChange::Different(
                            None,
                            Some(ProposalId { id: 1 }),
                        )),
                        ProposalDataChange::Proposer(OptionChange::Different(
                            None,
                            Some(NeuronId { id: 0 }),
                        )),
                        ProposalDataChange::Proposal(OptionChange::Different(
                            None,
                            Some(vec![
                                ProposalChange::Title(OptionChange::Different(
                                    None,
                                    Some("A Reasonable Title".to_string())
                                )),
                                ProposalChange::Summary(StringChange(
                                    "".to_string(),
                                    "the unique proposal".to_string(),
                                )),
                                ProposalChange::Action(OptionChange::Different(
                                    None,
                                    Some(ActionDesc::ManageNetworkEconomics(NetworkEconomics {
                                        ..Default::default()
                                    })),
                                )),
                            ]),
                        )),
                        ProposalDataChange::ProposalTimestampSeconds(U64Change(0, 999111000)),
                        ProposalDataChange::Ballots(vec![MapChange::Added(
                            0,
                            Ballot {
                                vote: Vote::Yes as i32,
                                voting_power: 1,
                            },
                        )]),
                        ProposalDataChange::LatestTally(OptionChange::Different(
                            None,
                            Some(Tally {
                                timestamp_seconds: 999111000,
                                yes: 1,
                                no: 0,
                                total: 1,
                            }),
                        )),
                        ProposalDataChange::DecidedTimestampSeconds(U64Change(0, 999111000)),
                        ProposalDataChange::ExecutedTimestampSeconds(U64Change(0, 999111000)),
                        ProposalDataChange::WaitForQuietState(OptionChange::Different(
                            None,
                            Some(WaitForQuietStateDesc {
                                current_deadline_timestamp_seconds: 999111017,
                            }),
                        )),
                    ],
                )]),
                GovernanceChange::Metrics(OptionChange::Different(
                    None,
                    Some(vec![
                        GovernanceCachedMetricsChange::TimestampSeconds(U64Change(0, 999111016)),
                        GovernanceCachedMetricsChange::NotDissolvingNeuronsCount(U64Change(0, 1)),
                        GovernanceCachedMetricsChange::NotDissolvingNeuronsE8SBuckets(vec![
                            MapChange::Added(0, 1.0),
                        ]),
                        GovernanceCachedMetricsChange::NotDissolvingNeuronsCountBuckets(vec![
                            MapChange::Added(0, 1),
                        ]),
                        GovernanceCachedMetricsChange::GarbageCollectableNeuronsCount(U64Change(
                            0, 1
                        )),
                        GovernanceCachedMetricsChange::TotalStakedE8S(U64Change(0, 1)),
                    ]),
                )),
            ]),
        ])
    );
}

/// Submits a proposal, votes on it as instructed, and then verifies:
/// - that the proposal status, immediately after voting, is as expected
/// - that the proposal status, after proposal expiration, is as expected
///
/// To simplify test setup:
/// - The rejection fee is set to zero
/// - all votes happen at proposal creation time.
/// - uses an arbtrary duration for proposal expiration time.
fn check_proposal_status_after_voting_and_after_expiration(
    neurons: impl IntoIterator<Item = Neuron>,
    behavior: impl Into<fake::ProposalNeuronBehavior>,
    expected_after_voting: ProposalStatus,
    expected_after_expiration: ProposalStatus,
) {
    let expiration_seconds = 17; // Arbitrary duration
    let econ = NetworkEconomics {
        reject_cost_e8s: 0,          // It's the default, but specify for emphasis
        neuron_minimum_stake_e8s: 0, // It's the default, but specify for emphasis
        ..NetworkEconomics::default()
    };
    let mut fake_driver = fake::FakeDriver::default();
    let fixture = GovernanceProto {
        neurons: neurons
            .into_iter()
            .zip(0_u64..)
            .map(|(neuron, i)| {
                (
                    i,
                    Neuron {
                        id: Some(NeuronId { id: i }),
                        controller: Some(principal(i)),
                        account: fake_driver.get_fake_env().random_byte_array().to_vec(),
                        ..neuron
                    },
                )
            })
            .collect(),
        wait_for_quiet_threshold_seconds: expiration_seconds,
        economics: Some(econ),
        ..Default::default()
    };
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );

    let pid = behavior
        .into()
        .propose_and_vote(&mut gov, "the unique proposal".to_string());

    let after_voting = gov.get_proposal_data(pid).unwrap().clone();

    assert_eq!(
        after_voting.status(),
        expected_after_voting,
        "After voting: {:?}",
        after_voting
    );

    fake_driver.advance_time_by(expiration_seconds - 1);
    gov.run_periodic_tasks().now_or_never();
    // The proposal should still be open for voting, so nothing should have changed
    assert_eq!(*gov.get_proposal_data(pid).unwrap(), after_voting);

    // One more second brings us to proposal expiration
    fake_driver.advance_time_by(1);
    gov.run_periodic_tasks().now_or_never();
    let after_expiration = gov.get_proposal_data(pid).unwrap();

    assert_eq!(
        after_expiration.status(),
        expected_after_expiration,
        "After expiration: {:?}",
        after_expiration
    );
}

/// Here we test that, if there is a single neuron, any proposed proposal is
/// accepted.
#[test]
fn test_single_neuron_proposal() {
    check_proposal_status_after_voting_and_after_expiration(
        vec![Neuron {
            dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
            cached_neuron_stake_e8s: 1,
            ..Neuron::default()
        }],
        "P",
        ProposalStatus::Executed,
        ProposalStatus::Executed,
    );
}

// Here one neuron proposes and another votes yes -- the proposal should be
// accepted.
#[test]
fn test_two_neuron_agreement_proposal_should_be_accepted() {
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..Neuron::default()
            },
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..Neuron::default()
            },
        ],
        "Py",
        ProposalStatus::Executed,
        ProposalStatus::Executed,
    );
}

/// Here two neurons with identical stake, age, and dissolve delay disagree. The
/// proposal should be rejected.
#[test]
fn test_two_neuron_disagree_identical_voting_power_proposal_should_be_rejected() {
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..Neuron::default()
            },
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..Neuron::default()
            },
        ],
        "Pn",
        ProposalStatus::Rejected,
        ProposalStatus::Rejected,
    );
}

// Tests that, upon proposal expiration, proposals are rejected if they have not
// reached absolute majority, counting the eligible neurons that did not vote.
#[test]
fn test_two_neuron_disagree_identical_voting_power_one_does_not_vote_proposal_should_rejected_at_expiration(
) {
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..Neuron::default()
            },
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 40,
                ..Neuron::default()
            },
        ],
        "P-",
        ProposalStatus::Open,
        ProposalStatus::Rejected,
    );
}

/// Here 2 neurons with same age, same dissolve period, but different stakes.
/// The one with the largest stake should win.
#[test]
fn test_two_neuron_disagree_largest_stake_wins() {
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 8,
                ..Neuron::default()
            },
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 7,
                ..Neuron::default()
            },
        ],
        "P-",
        ProposalStatus::Executed,
        ProposalStatus::Executed,
    );
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 400,
                ..Neuron::default()
            },
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 7,
                ..Neuron::default()
            },
        ],
        "nP",
        ProposalStatus::Rejected,
        ProposalStatus::Rejected,
    );
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 400,
                ..Neuron::default()
            },
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 7,
                ..Neuron::default()
            },
        ],
        "-P",
        ProposalStatus::Open,
        ProposalStatus::Rejected,
    );
}

/// Here 2 neurons with same age and same stake disagree. The one with the
/// longest dissolve period should win.
#[test]
fn test_two_neuron_disagree_identical_stake_longer_dissolve_wins() {
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            Neuron {
                dissolve_state: NOTDISSOLVING_MAX_DISSOLVE_DELAY,
                cached_neuron_stake_e8s: 1,
                ..Neuron::default()
            },
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..Neuron::default()
            },
        ],
        "P-",
        ProposalStatus::Executed,
        ProposalStatus::Executed,
    );
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            Neuron {
                dissolve_state: NOTDISSOLVING_MAX_DISSOLVE_DELAY,
                cached_neuron_stake_e8s: 21,
                ..Neuron::default()
            },
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..Neuron::default()
            },
        ],
        "nP",
        ProposalStatus::Rejected,
        ProposalStatus::Rejected,
    );
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            Neuron {
                dissolve_state: NOTDISSOLVING_MAX_DISSOLVE_DELAY,
                cached_neuron_stake_e8s: 21,
                ..Neuron::default()
            },
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..Neuron::default()
            },
        ],
        "-P",
        ProposalStatus::Open,
        ProposalStatus::Rejected,
    );
}

/// Here 2 neurons with same stake and same dissolve delay disagree. The oldest
/// one should win, unless both are older than the age giving the max age bonus.
#[test]
fn test_two_neuron_disagree_identical_stake_older_wins() {
    // The age bonus is 25% at most -- to make it detectable with integer voting
    // powers, stakes need to be at least 4 e8s.
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 4,
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS
                    - MAX_NEURON_AGE_FOR_AGE_BONUS,
                ..Neuron::default()
            },
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 4,
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS,
                ..Neuron::default()
            },
        ],
        "P-",
        ProposalStatus::Executed,
        ProposalStatus::Executed,
    );
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 200,
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS
                    - MAX_NEURON_AGE_FOR_AGE_BONUS,
                ..Neuron::default()
            },
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 4,
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS,
                ..Neuron::default()
            },
        ],
        "nP",
        ProposalStatus::Rejected,
        ProposalStatus::Rejected,
    );
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 200,
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS
                    - MAX_NEURON_AGE_FOR_AGE_BONUS,
                ..Neuron::default()
            },
            Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 4,
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS,
                ..Neuron::default()
            },
        ],
        "-P",
        ProposalStatus::Open,
        ProposalStatus::Rejected,
    );
}

/// *Test fixture for following*
///
/// - There are nine neurons: 1-9.
///
/// - Every neuron has the same stake of 10 ICP and (non-dissolving) dissolution
///   period of 1 year, so the same voting power. Thus, 5 out of 9 need to vote
///   to reach a verdict.
///
/// - Neuron 2 follows 1, 3, 4 on topic Governance and neuron 3 follows 5, 6, 7
///   on topic Unknown = all topics without specific override
///
/// - Neurons 1, 5, 6 have a controller set and can vote.
#[cfg(feature = "test")]
fn fixture_for_following_new() -> NNS {
    NNSBuilder::new()
        .set_economics(NetworkEconomics::with_default_values())
        .add_neuron(NeuronBuilder::new(1, 1_000_000_000, principal(1)).set_dissolve_delay(31557600))
        .add_neuron(
            NeuronBuilder::new_without_owner(2, 1_000_000_000)
                .set_dissolve_delay(31557600)
                .add_followees(
                    Topic::NetworkEconomics as i32,
                    neuron::Followees {
                        followees: [NeuronId { id: 1 }, NeuronId { id: 3 }, NeuronId { id: 4 }]
                            .to_vec(),
                    },
                ),
        )
        .add_neuron(
            NeuronBuilder::new_without_owner(3, 1_000_000_000)
                .set_dissolve_delay(31557600)
                .add_followees(
                    Topic::Unspecified as i32,
                    neuron::Followees {
                        followees: [NeuronId { id: 5 }, NeuronId { id: 6 }, NeuronId { id: 7 }]
                            .to_vec(),
                    },
                ),
        )
        .add_neuron(NeuronBuilder::new_without_owner(4, 1_000_000_000).set_dissolve_delay(31557600))
        .add_neuron(NeuronBuilder::new(5, 1_000_000_000, principal(5)).set_dissolve_delay(31557600))
        .add_neuron(NeuronBuilder::new(6, 1_000_000_000, principal(6)).set_dissolve_delay(31557600))
        .add_neuron(NeuronBuilder::new_without_owner(7, 1_000_000_000).set_dissolve_delay(31557600))
        .add_neuron(NeuronBuilder::new_without_owner(8, 1_000_000_000).set_dissolve_delay(31557600))
        .add_neuron(NeuronBuilder::new_without_owner(9, 1_000_000_000).set_dissolve_delay(31557600))
        .create()
}

/// *Test scenario*
///
/// - Neuron 1 makes a proposal (on topic NetworkEconomics) and implicitly votes
///   yes.
///
/// - Neurons 5 and 6 vote yes.
///
/// - The proposal is accepted and executed as five neurons (1, 2, 3, 5, 6) have
///   voted 'yes'.
///
/// This tests several things:
///
/// - That following is generally working.
///
/// - That the proposer votes implicitly.
///
/// - That following works both for the topic of the proposal and for the
///   fallback case.
///
/// - As neuron 3 follows neurons 5 and 6 on the unknown topic, 3 should vote
///   yes.
///
/// - As neuron 2 follows neurons 1 and 3 on the NetworkEconomics topic, 2 should vote
///   yes as 1 votes implicitly by proposing and 3 votes by following 5 and 6.
#[cfg(feature = "test")]
#[test]
fn test_cascade_following_new() {
    let mut nns = fixture_for_following_new();
    let id = NeuronId { id: 1 };

    nns.governance
        .make_proposal(
            &id,
            // Must match neuron 1's serialized_id.
            &principal(1),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "test".to_string(),
                action: Some(proposal::Action::ManageNetworkEconomics(NetworkEconomics {
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .unwrap();

    // The fee should now be 1 ICPT since the fees are charged upfront.
    assert_eq!(nns.get_neuron(&id).neuron_fees_e8s, 100_000_000);

    // Once the proposal passes
    // Check that the vote is registered in the proposing neuron.
    assert_eq!(
        &BallotInfo {
            proposal_id: Some(ProposalId { id: 1 }),
            vote: Vote::Yes as i32
        },
        nns.get_neuron(&id).recent_ballots.get(0).unwrap()
    );
    // Check that the vote is registered in the proposal
    assert_eq!(
        (Vote::Yes as i32),
        nns.governance
            .get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .ballots
            .get(&1)
            .unwrap()
            .vote
    );

    assert_changes!(
        nns,
        Changed::Changed(vec![NNSStateChange::GovernanceProto(vec![
            GovernanceChange::Neurons(vec![MapChange::Changed(
                1,
                vec![
                    NeuronChange::NeuronFeesE8S(U64Change(0, 100000000)),
                    NeuronChange::RecentBallots(vec![VecChange::Added(
                        0,
                        vec![
                            BallotInfoChange::ProposalId(OptionChange::Different(
                                None,
                                Some(ProposalId { id: 1 }),
                            )),
                            BallotInfoChange::Vote(I32Change(0, 1)),
                        ],
                    )]),
                ],
            )]),
            GovernanceChange::Proposals(vec![MapChange::Added(
                1,
                vec![
                    ProposalDataChange::Id(OptionChange::Different(
                        None,
                        Some(ProposalId { id: 1 }),
                    )),
                    ProposalDataChange::Proposer(OptionChange::Different(
                        None,
                        Some(NeuronId { id: 1 }),
                    )),
                    ProposalDataChange::RejectCostE8S(U64Change(0, 100000000)),
                    ProposalDataChange::Proposal(OptionChange::Different(
                        None,
                        Some(vec![
                            ProposalChange::Title(OptionChange::Different(
                                None,
                                Some("A Reasonable Title".to_string()),
                            )),
                            ProposalChange::Summary(StringChange(
                                "".to_string(),
                                "test".to_string(),
                            )),
                            ProposalChange::Action(OptionChange::Different(
                                None,
                                Some(ActionDesc::ManageNetworkEconomics(NetworkEconomics {
                                    ..Default::default()
                                })),
                            )),
                        ]),
                    )),
                    ProposalDataChange::ProposalTimestampSeconds(U64Change(0, 999111000)),
                    ProposalDataChange::Ballots(vec![
                        MapChange::Added(
                            1,
                            Ballot {
                                vote: Vote::Yes as i32,
                                voting_power: 1125000000,
                            },
                        ),
                        MapChange::Added(
                            2,
                            Ballot {
                                vote: Vote::Unspecified as i32,
                                voting_power: 1125000000,
                            },
                        ),
                        MapChange::Added(
                            3,
                            Ballot {
                                vote: Vote::Unspecified as i32,
                                voting_power: 1125000000,
                            },
                        ),
                        MapChange::Added(
                            4,
                            Ballot {
                                vote: Vote::Unspecified as i32,
                                voting_power: 1125000000,
                            },
                        ),
                        MapChange::Added(
                            5,
                            Ballot {
                                vote: Vote::Unspecified as i32,
                                voting_power: 1125000000,
                            },
                        ),
                        MapChange::Added(
                            6,
                            Ballot {
                                vote: Vote::Unspecified as i32,
                                voting_power: 1125000000,
                            },
                        ),
                        MapChange::Added(
                            7,
                            Ballot {
                                vote: Vote::Unspecified as i32,
                                voting_power: 1125000000,
                            },
                        ),
                        MapChange::Added(
                            8,
                            Ballot {
                                vote: Vote::Unspecified as i32,
                                voting_power: 1125000000,
                            },
                        ),
                        MapChange::Added(
                            9,
                            Ballot {
                                vote: Vote::Unspecified as i32,
                                voting_power: 1125000000,
                            },
                        ),
                    ]),
                    ProposalDataChange::LatestTally(OptionChange::Different(
                        None,
                        Some(Tally {
                            timestamp_seconds: 999111000,
                            yes: 1125000000,
                            no: 0,
                            total: 10125000000,
                        }),
                    )),
                    ProposalDataChange::WaitForQuietState(OptionChange::Different(
                        None,
                        Some(WaitForQuietStateDesc {
                            current_deadline_timestamp_seconds: 999111001,
                        }),
                    )),
                ],
            )]),
        ],)])
    );

    // Now vote yes for neurons 5 and 6.
    nns.register_vote_assert_success(
        principal(5),
        NeuronId { id: 5 },
        ProposalId { id: 1 },
        Vote::Yes,
    );

    assert_changes!(
        nns,
        Changed::Changed(vec![NNSStateChange::GovernanceProto(vec![
            GovernanceChange::Neurons(vec![MapChange::Changed(
                5,
                vec![NeuronChange::RecentBallots(vec![VecChange::Added(
                    0,
                    vec![
                        BallotInfoChange::ProposalId(OptionChange::Different(
                            None,
                            Some(ProposalId { id: 1 }),
                        )),
                        BallotInfoChange::Vote(I32Change(0, 1)),
                    ],
                )])],
            )]),
            GovernanceChange::Proposals(vec![MapChange::Changed(
                1,
                vec![
                    ProposalDataChange::Ballots(vec![MapChange::Changed(
                        5,
                        vec![BallotChange::Vote(I32Change(0, 1))],
                    )]),
                    ProposalDataChange::LatestTally(OptionChange::BothSome(vec![
                        TallyChange::Yes(U64Change(1125000000, 2250000000)),
                    ])),
                ],
            )]),
        ],)])
    );

    nns.register_vote_assert_success(
        principal(6),
        NeuronId { id: 6 },
        ProposalId { id: 1 },
        Vote::Yes,
    );

    // Check that the vote for neuron 2 is registered in the proposal
    assert_eq!(
        (Vote::Yes as i32),
        nns.governance
            .get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .ballots
            .get(&2)
            .unwrap()
            .vote
    );
    // Check that neuron's vote is registered in the neuron
    assert_eq!(
        &BallotInfo {
            proposal_id: Some(ProposalId { id: 1 }),
            vote: Vote::Yes as i32
        },
        nns.get_neuron(&NeuronId { id: 2 })
            .recent_ballots
            .get(0)
            .unwrap()
    );
    // The proposal should now be accepted and executed.
    assert_eq!(
        ProposalStatus::Executed,
        nns.governance
            .get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );

    // After the proposal is accepted the Neuron 1 should have 0 fees again
    assert_eq!(nns.get_neuron(&id).neuron_fees_e8s, 0);

    assert_changes!(
        nns,
        Changed::Changed(vec![NNSStateChange::GovernanceProto(vec![
            GovernanceChange::Neurons(vec![
                MapChange::Changed(
                    1,
                    vec![NeuronChange::NeuronFeesE8S(U64Change(100000000, 0))],
                ),
                MapChange::Changed(
                    2,
                    vec![NeuronChange::RecentBallots(vec![VecChange::Added(
                        0,
                        vec![
                            BallotInfoChange::ProposalId(OptionChange::Different(
                                None,
                                Some(ProposalId { id: 1 }),
                            )),
                            BallotInfoChange::Vote(I32Change(0, 1)),
                        ],
                    )])],
                ),
                MapChange::Changed(
                    3,
                    vec![NeuronChange::RecentBallots(vec![VecChange::Added(
                        0,
                        vec![
                            BallotInfoChange::ProposalId(OptionChange::Different(
                                None,
                                Some(ProposalId { id: 1 }),
                            )),
                            BallotInfoChange::Vote(I32Change(0, 1)),
                        ],
                    )])],
                ),
                MapChange::Changed(
                    6,
                    vec![NeuronChange::RecentBallots(vec![VecChange::Added(
                        0,
                        vec![
                            BallotInfoChange::ProposalId(OptionChange::Different(
                                None,
                                Some(ProposalId { id: 1 }),
                            )),
                            BallotInfoChange::Vote(I32Change(0, 1)),
                        ],
                    )])],
                ),
            ]),
            GovernanceChange::Proposals(vec![MapChange::Changed(
                1,
                vec![
                    ProposalDataChange::Ballots(vec![
                        MapChange::Changed(2, vec![BallotChange::Vote(I32Change(0, 1))]),
                        MapChange::Changed(3, vec![BallotChange::Vote(I32Change(0, 1))]),
                        MapChange::Changed(6, vec![BallotChange::Vote(I32Change(0, 1))]),
                    ]),
                    ProposalDataChange::LatestTally(OptionChange::BothSome(vec![
                        TallyChange::Yes(U64Change(2250000000, 5625000000)),
                    ])),
                    ProposalDataChange::DecidedTimestampSeconds(U64Change(0, 999111000)),
                    ProposalDataChange::ExecutedTimestampSeconds(U64Change(0, 999111000)),
                ],
            )]),
        ],)])
    );
}

/// *Test fixture for following*
///
/// - There are nine neurons: 1-9.
///
/// - Every neuron has the same stake of 10 ICP and (non-dissolving) dissolution
///   period of 1 year, so the same voting power. Thus, 5 out of 9 need to vote
///   to reach a verdict.
///
/// - Neuron 2 follows 1, 3, 4 on topic NetworkEconomics and neuron 3 follows 5,
///   6, 7 on topic Unknown = all topics (except governance) without specific
///   override
///
/// - Neurons 1, 5, 6, 7, and 8 have a controller set and can vote.
fn fixture_for_following() -> GovernanceProto {
    let mut driver = fake::FakeDriver::default();
    // A 'default' neuron, extended with additional fields below.
    let mut neuron = move |id| Neuron {
        id: Some(NeuronId { id }),
        cached_neuron_stake_e8s: 1_000_000_000, // 10 ICP
        // One year
        dissolve_state: Some(neuron::DissolveState::DissolveDelaySeconds(31557600)),
        account: driver.random_byte_array().to_vec(),
        ..Default::default()
    };
    GovernanceProto {
        economics: Some(NetworkEconomics::with_default_values()),
        wait_for_quiet_threshold_seconds: 1,
        neurons: [
            (
                1,
                Neuron {
                    // Needs controller to vote.
                    controller: Some(principal(1)),
                    ..neuron(1)
                },
            ),
            (
                2,
                Neuron {
                    followees: [(
                        Topic::NetworkEconomics as i32,
                        neuron::Followees {
                            followees: [NeuronId { id: 1 }, NeuronId { id: 3 }, NeuronId { id: 4 }]
                                .to_vec(),
                        },
                    )]
                    .to_vec()
                    .into_iter()
                    .collect(),
                    ..neuron(2)
                },
            ),
            (
                3,
                Neuron {
                    followees: [(
                        Topic::Unspecified as i32,
                        neuron::Followees {
                            followees: [NeuronId { id: 5 }, NeuronId { id: 6 }, NeuronId { id: 7 }]
                                .to_vec(),
                        },
                    )]
                    .to_vec()
                    .into_iter()
                    .collect(),
                    ..neuron(3)
                },
            ),
            (4, neuron(4)),
            (
                5,
                Neuron {
                    controller: Some(principal(5)),
                    ..neuron(5)
                },
            ),
            (
                6,
                Neuron {
                    controller: Some(principal(6)),
                    ..neuron(6)
                },
            ),
            (
                7,
                Neuron {
                    controller: Some(principal(7)),
                    ..neuron(7)
                },
            ),
            (
                8,
                Neuron {
                    controller: Some(principal(8)),
                    ..neuron(8)
                },
            ),
            (9, neuron(9)),
        ]
        .to_vec()
        .into_iter()
        .collect(),
        ..Default::default()
    }
}

/// *Test scenario*
///
/// - Neuron 1 makes a proposal (Motion of topic Governance) and implicitly
///   votes yes.
///
/// - Neurons 5 and 6 vote yes.
///
/// - The proposal is accepted and executed as five neurons (1, 2, 3, 5, 6) have
///   voted 'yes'.
///
/// This tests several things:
///
/// - That following is generally working.
///
/// - That the proposer votes implicitly.
///
/// - That following works both for the topic of the proposal and for the
///   fallback case.
///
/// - As neuron 3 follows neurons 5 and 6 on the unknown topic, 3 should vote
///   yes.
///
/// - As neuron 2 follows neurons 1 and 3 on the NetworkEconomics topic, 2
///   should vote yes as 1 votes implicitly by proposing and 3 votes by
///   following 5 and 6.
#[test]
fn test_cascade_following() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "test".to_string(),
            action: Some(proposal::Action::ManageNetworkEconomics(NetworkEconomics {
                ..Default::default()
            })),
            ..Default::default()
        },
    )
    .unwrap();

    // The fee should now be 1 ICPT since the fees are charged upfront.
    assert_eq!(
        gov.proto.neurons.get(&1).unwrap().neuron_fees_e8s,
        100_000_000
    );

    // Once the proposal passes
    // Check that the vote is registered in the proposing neuron.
    assert_eq!(
        &BallotInfo {
            proposal_id: Some(ProposalId { id: 1 }),
            vote: Vote::Yes as i32
        },
        gov.proto
            .neurons
            .get(&1)
            .unwrap()
            .recent_ballots
            .get(0)
            .unwrap()
    );
    // Check that the vote is registered in the proposal
    assert_eq!(
        (Vote::Yes as i32),
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .ballots
            .get(&1)
            .unwrap()
            .vote
    );
    // Now vote yes for neurons 5 and 6.
    fake::register_vote_assert_success(
        &mut gov,
        principal(5),
        NeuronId { id: 5 },
        ProposalId { id: 1 },
        Vote::Yes,
    );
    fake::register_vote_assert_success(
        &mut gov,
        principal(6),
        NeuronId { id: 6 },
        ProposalId { id: 1 },
        Vote::Yes,
    );

    // Check that the vote for neuron 2 is registered in the proposal
    assert_eq!(
        (Vote::Yes as i32),
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .ballots
            .get(&2)
            .unwrap()
            .vote
    );
    // Check that neuron's vote is registered in the neuron
    assert_eq!(
        &BallotInfo {
            proposal_id: Some(ProposalId { id: 1 }),
            vote: Vote::Yes as i32
        },
        gov.proto
            .neurons
            .get(&2)
            .unwrap()
            .recent_ballots
            .get(0)
            .unwrap()
    );
    // The proposal should now be accepted and executed.
    assert_eq!(
        ProposalStatus::Executed,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );

    // After the proposal is accepted the Neuron 1 should have 0 fees again
    assert_eq!(gov.proto.neurons.get(&1).unwrap().neuron_fees_e8s, 0);
}

/// In this scenario, we simply test that you cannot make a proposal
/// to set the conversion rate below the minimum allowable rate.
#[test]
fn test_minimum_icp_xdr_conversion_rate() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    // Set minimum conversion rate.
    gov.proto.economics.as_mut().unwrap().minimum_icp_xdr_rate = 100_000;
    // This should fail.
    assert_eq!(
        ErrorType::InvalidProposal as i32,
        gov.make_proposal(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &PrincipalId::try_from(b"SID1".to_vec()).unwrap(),
            &Proposal {
                summary: "test".to_string(),
                action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
                    nns_function: NnsFunction::IcpXdrConversionRate as i32,
                    payload: Encode!(&UpdateIcpXdrConversionRatePayload {
                        xdr_permyriad_per_icp: 0,
                        data_source: "".to_string(),
                        timestamp_seconds: 0,
                    })
                    .unwrap(),
                })),
                ..Default::default()
            },
        )
        .unwrap_err()
        .error_type
    );
    // This should succeed
    gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &PrincipalId::try_from(b"SID1".to_vec()).unwrap(),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "test".to_string(),
            action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
                nns_function: NnsFunction::IcpXdrConversionRate as i32,
                payload: Encode!(&UpdateIcpXdrConversionRatePayload {
                    xdr_permyriad_per_icp: 100_000_000,
                    data_source: "".to_string(),
                    timestamp_seconds: 0,
                })
                .unwrap(),
            })),
            ..Default::default()
        },
    )
    .unwrap();
}

#[test]
fn test_node_provider_must_be_registered() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    let node_provider = NodeProvider {
        id: Some(PrincipalId::try_from(b"SID2".to_vec()).unwrap()),
        reward_account: None,
    };
    // Register a single node provider
    gov.proto.node_providers.push(node_provider);
    // This should fail.
    assert_eq!(
        ErrorType::InvalidProposal as i32,
        gov.make_proposal(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &PrincipalId::try_from(b"SID1".to_vec()).unwrap(),
            &Proposal {
                summary: "test".to_string(),
                action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
                    nns_function: NnsFunction::AssignNoid as i32,
                    payload: Encode!(&AddNodeOperatorPayload {
                        node_provider_principal_id: PrincipalId::try_from(b"SID3".to_vec()).ok(),
                        ..Default::default()
                    })
                    .unwrap(),
                })),
                ..Default::default()
            },
        )
        .unwrap_err()
        .error_type
    );
    // This should succeed
    gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &PrincipalId::try_from(b"SID1".to_vec()).unwrap(),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "test".to_string(),
            action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
                nns_function: NnsFunction::AssignNoid as i32,
                payload: Encode!(&AddNodeOperatorPayload {
                    node_provider_principal_id: PrincipalId::try_from(b"SID2".to_vec()).ok(),
                    ..Default::default()
                })
                .unwrap(),
            })),
            ..Default::default()
        },
    )
    .unwrap();
}

/// In this scenario, we simply test that you cannot make a proposal
/// if you have insufficient stake (less than the reject fee).
#[test]
fn test_sufficient_stake() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    // Set stake to 0.5 ICP.
    gov.proto
        .neurons
        .get_mut(&1)
        .unwrap()
        .cached_neuron_stake_e8s = 50_000_000;
    // This should fail because the reject_cost_e8s is 1 ICP.
    assert_eq!(
        ErrorType::PreconditionFailed as i32,
        gov.make_proposal(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &principal(1),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "test".to_string(),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "dummy text".to_string(),
                })),
                ..Default::default()
            },
        )
        .unwrap_err()
        .error_type
    );
    // Set stake to 1 ICP.
    gov.proto
        .neurons
        .get_mut(&1)
        .unwrap()
        .cached_neuron_stake_e8s = 100_000_000;
    // This should succeed because the reject_cost_e8s is 1 ICP (same as stake).
    gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "test".to_string(),
            action: Some(proposal::Action::ManageNetworkEconomics(NetworkEconomics {
                ..Default::default()
            })),
            ..Default::default()
        },
    )
    .unwrap();
}

/// In this scenario, we configure neurons 5 and 6 to follow neuron 1.
/// When neuron 1 now votes, this should result in the propsal being
/// immediately acceptable.
#[test]
fn test_all_follow_proposer() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    // Add following for 5 and 6 for 1.
    gov.manage_neuron(
        // Must match neuron 5's serialized_id.
        &principal(5),
        &ManageNeuron {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 5 })),
            command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                topic: Topic::Unspecified as i32,
                followees: [NeuronId { id: 1 }].to_vec(),
            })),
        },
    )
    .now_or_never()
    .unwrap()
    .expect("Manage neuron failed");

    gov.manage_neuron(
        // Must match neuron 6's serialized_id.
        &principal(6),
        &ManageNeuron {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 6 })),
            command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                topic: Topic::Unspecified as i32,
                followees: [NeuronId { id: 1 }].to_vec(),
            })),
        },
    )
    .now_or_never()
    .unwrap()
    .expect("Manage neuron failed");

    gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "test".to_string(),
            action: Some(proposal::Action::ManageNetworkEconomics(NetworkEconomics {
                ..Default::default()
            })),
            ..Default::default()
        },
    )
    .unwrap();
    // The proposal should now be accepted and executed.
    assert_eq!(
        ProposalStatus::Executed,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );
}

/// Here we configure the nodes so that to vote no to the proposal.
///
/// Neuron 1 still makes the proposal.
///
/// Neuron 3 follows {5, 6, 7} and neuron 2 follows {1, 3, 4} in the
/// fixture.
///
/// We make neurons 4, 5, and 6 vote 'no'. Neuron 3 follows {5, 6} and
/// neuron 2 follows {3, 4} and we now have a quorum for 'no', viz., 2
/// to 6.
#[test]
fn test_follow_negative() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "test".to_string(),
            action: Some(proposal::Action::ManageNetworkEconomics(NetworkEconomics {
                ..Default::default()
            })),
            ..Default::default()
        },
    )
    .unwrap();
    // No controller for 4 yet.
    let result = fake::register_vote(
        &mut gov,
        // Must match neuron 4's serialized_id.
        principal(4),
        NeuronId { id: 4 },
        ProposalId { id: 1 },
        Vote::No,
    );
    assert_matches!(
        result.command,
        Some(manage_neuron_response::Command::Error(err))
            if err.error_type == ErrorType::NotAuthorized as i32
    );
    gov.proto.neurons.get_mut(&4).unwrap().controller = Some(principal(4));
    fake::register_vote_assert_success(
        &mut gov,
        principal(4),
        NeuronId { id: 4 },
        ProposalId { id: 1 },
        Vote::No,
    );
    fake::register_vote_assert_success(
        &mut gov,
        principal(5),
        NeuronId { id: 5 },
        ProposalId { id: 1 },
        Vote::No,
    );
    fake::register_vote_assert_success(
        &mut gov,
        principal(6),
        NeuronId { id: 6 },
        ProposalId { id: 1 },
        Vote::No,
    );

    // Now proccess the proposals: neurons 2, 3, 4, 5, 6 have voted no (5/9)
    gov.run_periodic_tasks().now_or_never();
    // The proposal should now be rejected.
    assert_eq!(
        ProposalStatus::Rejected,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );
    // Make sure that the neuron has been changed the reject fee.
    assert_eq!(
        gov.proto.neurons.get(&1).unwrap().neuron_fees_e8s,
        gov.proto.economics.unwrap().reject_cost_e8s
    );
}

/// Here we test that following doesn't apply to the Governance topic.
///
/// Neuron 1 makes a proposal.
///
/// Neurons 5, 6, 7, 8 vote yes.
///
/// As no following applies, the proposal should not be adopted until
/// neuron 8 votes yes as default following is disabled for governance
/// proposals.
#[test]
fn test_no_default_follow_for_governance() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("dummy title".to_string()),
            summary: "test".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "dummy text".to_string(),
            })),
            ..Default::default()
        },
    )
    .unwrap();
    // Now vote yes for neurons 5-7.
    for i in 5..=7 {
        fake::register_vote_assert_success(
            &mut gov,
            principal(i),
            NeuronId { id: i },
            ProposalId { id: 1 },
            Vote::Yes,
        );
        // The proposal should still be open
        assert_eq!(
            ProposalStatus::Open,
            gov.get_proposal_data(ProposalId { id: 1 })
                .unwrap()
                .status()
        );
    }
    // When neuron 8 votes, the proposal should be adopted and
    // executed.
    fake::register_vote_assert_success(
        &mut gov,
        principal(8),
        NeuronId { id: 8 },
        ProposalId { id: 1 },
        Vote::Yes,
    );
    // The proposal should now be executed.
    assert_eq!(
        ProposalStatus::Executed,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );
}

/// *Test fixture for manage neuron*
///
/// - There are six neurons: 1-6.
///
/// - Every neuron has the same stake of 10 ICP, but no dissolution
/// period specified.
//
///
/// - Neuron 1 follows 2, 3, and 4 on topic `ManageNeuron`.
///
/// - Neurons 2, 3, 4, and 5 have a controller so they can vote.
fn fixture_for_manage_neuron() -> GovernanceProto {
    let mut driver = fake::FakeDriver::default();
    // A 'default' neuron, extended with additional fields below.
    let mut neuron = move |id| Neuron {
        id: Some(NeuronId { id }),
        cached_neuron_stake_e8s: 1_000_000_000, // 10 ICP
        account: driver.random_byte_array().to_vec(),
        ..Default::default()
    };
    GovernanceProto {
        economics: Some(NetworkEconomics::with_default_values()),
        short_voting_period_seconds: 1,
        neurons: [
            (
                1,
                Neuron {
                    created_timestamp_seconds: 1066,
                    controller: Some(principal(1)),
                    hot_keys: vec![PrincipalId::try_from(b"HOT_SID1".to_vec()).unwrap()],
                    followees: [(
                        Topic::NeuronManagement as i32,
                        neuron::Followees {
                            followees: [NeuronId { id: 2 }, NeuronId { id: 3 }, NeuronId { id: 4 }]
                                .to_vec(),
                        },
                    )]
                    .to_vec()
                    .into_iter()
                    .collect(),
                    ..neuron(1)
                },
            ),
            (
                2,
                Neuron {
                    controller: Some(principal(2)),
                    hot_keys: vec![PrincipalId::try_from(b"HOT_SID2".to_vec()).unwrap()],
                    ..neuron(2)
                },
            ),
            (
                3,
                Neuron {
                    controller: Some(principal(3)),
                    ..neuron(3)
                },
            ),
            (
                4,
                Neuron {
                    controller: Some(principal(4)),
                    ..neuron(4)
                },
            ),
            (
                5,
                Neuron {
                    controller: Some(principal(5)),
                    ..neuron(5)
                },
            ),
            (6, neuron(6)),
        ]
        .to_vec()
        .into_iter()
        .collect(),
        ..Default::default()
    }
}

/// Test authorization for calls to `get_neuron_info` and
/// `get_full_neuron`.
#[test]
fn test_query_for_manage_neuron() {
    let driver = fake::FakeDriver::default();
    let gov = Governance::new(
        fixture_for_manage_neuron(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    // Test that anybody can call `get_neuron_info` as long as the
    // neuron exists.
    let neuron_info = gov.get_neuron_info(&NeuronId { id: 1 }).unwrap();
    assert_eq!(1066, neuron_info.created_timestamp_seconds);
    assert_eq!(1_000_000_000, neuron_info.stake_e8s,);
    // But not if it doesn't exist.
    assert_eq!(
        ErrorType::NotFound as i32,
        gov.get_neuron_info(&NeuronId { id: 100 })
            .unwrap_err()
            .error_type
    );
    // Test that the neuron info can be found by subaccount.
    let neuron_1_subaccount = Subaccount(
        gov.get_neuron(&NeuronId { id: 1 }).unwrap().account[..]
            .try_into()
            .unwrap(),
    );
    assert_eq!(
        1066,
        gov.get_neuron_info_by_id_or_subaccount(&NeuronIdOrSubaccount::Subaccount(
            neuron_1_subaccount.to_vec()
        ))
        .unwrap()
        .created_timestamp_seconds
    );
    assert_eq!(
        1066,
        gov.get_full_neuron_by_id_or_subaccount(
            &NeuronIdOrSubaccount::Subaccount(neuron_1_subaccount.to_vec()),
            &principal(1)
        )
        .unwrap()
        .created_timestamp_seconds
    );
    // But not if it doesn't exist.
    assert_eq!(
        ErrorType::NotFound as i32,
        gov.get_neuron_info_by_id_or_subaccount(&NeuronIdOrSubaccount::Subaccount(
            [0u8; 32].to_vec()
        ))
        .unwrap_err()
        .error_type
    );
    assert_eq!(
        ErrorType::NotFound as i32,
        gov.get_full_neuron_by_id_or_subaccount(
            &NeuronIdOrSubaccount::Subaccount([0u8; 32].to_vec()),
            &principal(1)
        )
        .unwrap_err()
        .error_type
    );

    // Test that the controller can get the full neuron
    assert_eq!(
        1066,
        gov.get_full_neuron(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &principal(1)
        )
        .unwrap()
        .created_timestamp_seconds
    );
    // Test that hot keys can get the full neuron.
    assert_eq!(
        1066,
        gov.get_full_neuron(
            &NeuronId { id: 1 },
            // Must match neuron 1's hot key.
            &PrincipalId::try_from(b"HOT_SID1".to_vec()).unwrap()
        )
        .unwrap()
        .created_timestamp_seconds
    );
    // Neuron 1 is 'managed' by neuron 2: test that the controller of
    // neuron 2 can get the full neuron 1.
    assert_eq!(
        1066,
        gov.get_full_neuron(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &principal(2)
        )
        .unwrap()
        .created_timestamp_seconds
    );
    // Neuron 1 is 'managed' by neuron 2: test that the hot key of
    // neuron 2 can get the full neuron 1.
    assert_eq!(
        1066,
        gov.get_full_neuron(
            &NeuronId { id: 1 },
            // Must match neuron 1's hot key.
            &PrincipalId::try_from(b"HOT_SID2".to_vec()).unwrap()
        )
        .unwrap()
        .created_timestamp_seconds
    );
    // Neuron 1 is not 'managed' by neuron 5...
    assert_eq!(
        ErrorType::NotAuthorized as i32,
        gov.get_full_neuron(
            &NeuronId { id: 1 },
            // Must match neuron 1's hot key.
            &principal(5)
        )
        .unwrap_err()
        .error_type
    );
}

///
/// - Neuron 2 makes a manage neuron proposal.
///
/// - Neuron 5 attempts to vote.
///
/// - Neuron 3 votes yes.
///
/// Now the proposal ought to be accepted and executed and neuron 1 modified.
///
/// The proposal itself is to make neuron 2 the sole manager of
/// canister 1.
///
/// As a next step, neuron 2 submits a proposal and this ought to be
/// executed immediately as 2 is now the sole manager of canister 1.
#[test]
fn test_manage_neuron() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_manage_neuron(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    // Make a proposal to replace the list of followees (2-4) with just 2.
    gov.make_proposal(
        &NeuronId { id: 2 },
        // Must match neuron 1's serialized_id.
        &principal(2),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 1 })),
                id: None,
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::NeuronManagement as i32,
                    followees: [NeuronId { id: 2 }].to_vec(),
                })),
            }))),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        ProposalStatus::Open,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );
    // Check that neuron 5 cannot vote...
    let result = fake::register_vote(
        &mut gov,
        // Must match neuron 4's serialized_id.
        principal(5),
        NeuronId { id: 5 },
        ProposalId { id: 1 },
        Vote::No,
    );
    assert_matches!(
        result.command,
        Some(manage_neuron_response::Command::Error(err))
            if err.error_type == ErrorType::NotAuthorized as i32
    );
    fake::register_vote_assert_success(
        &mut gov,
        principal(3),
        NeuronId { id: 3 },
        ProposalId { id: 1 },
        Vote::Yes,
    );

    assert_eq!(
        ProposalStatus::Executed,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );
    // Make sure that the neuron has been changed the fee for manage
    // neuron proposals.
    assert_eq!(
        gov.proto.neurons.get(&2).unwrap().neuron_fees_e8s,
        gov.proto
            .economics
            .as_ref()
            .unwrap()
            .neuron_management_fee_per_proposal_e8s
    );
    // Now there should be a single followee...
    assert_eq!(
        1,
        gov.proto
            .neurons
            .get_mut(&1)
            .unwrap()
            .followees
            .get(&(Topic::NeuronManagement as i32))
            .unwrap()
            .followees
            .len()
    );
    // ... viz., neuron 2.
    assert_eq!(
        2,
        gov.proto
            .neurons
            .get_mut(&1)
            .unwrap()
            .followees
            .get(&(Topic::NeuronManagement as i32))
            .unwrap()
            .followees
            .get(0)
            .unwrap()
            .id
    );
    // Make a proposal to change this list of followees back.
    gov.make_proposal(
        &NeuronId { id: 2 },
        // Must match neuron 1's serialized_id.
        &principal(2),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 1 })),
                id: None,
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::NeuronManagement as i32,
                    followees: [NeuronId { id: 2 }, NeuronId { id: 3 }, NeuronId { id: 4 }]
                        .to_vec(),
                })),
            }))),
            ..Default::default()
        },
    )
    .unwrap();
    // Now proccess the proposals: proposal should be executed as
    // neuron 2 is the sole followee of neuron 1 on the manage neuron
    // topic.
    gov.run_periodic_tasks().now_or_never();
    assert_eq!(
        ProposalStatus::Executed,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );
    // Now there should be three followees again.
    assert_eq!(
        3,
        gov.proto
            .neurons
            .get_mut(&1)
            .unwrap()
            .followees
            .get(&(Topic::NeuronManagement as i32))
            .unwrap()
            .followees
            .len()
    );
    // Make sure that the neuron has been changed an additional fee
    // for manage neuron proposals.
    assert_eq!(
        gov.proto.neurons.get(&2).unwrap().neuron_fees_e8s,
        2 * gov
            .proto
            .economics
            .as_ref()
            .unwrap()
            .neuron_management_fee_per_proposal_e8s
    );
}

/// In this scenario, we test that you cannot make a manage neuron
/// proposal if you have insufficient stake (less than the manage neuron fee).
#[test]
fn test_sufficient_stake_for_manage_neuron() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_manage_neuron(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    // Set stake to less than 0.01 ICP (same as
    // neuron_management_fee_per_proposal_e8s).
    gov.proto
        .neurons
        .get_mut(&2)
        .unwrap()
        .cached_neuron_stake_e8s = 999_999;
    // Try to make a proposal... This should fail because the
    // neuron_management_fee_per_proposal_e8s is 0.01 ICP.
    assert_eq!(
        ErrorType::InsufficientFunds as i32,
        gov.make_proposal(
            &NeuronId { id: 2 },
            // Must match neuron 1's serialized_id.
            &principal(2),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: 1
                    })),
                    id: None,
                    command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                        topic: Topic::NeuronManagement as i32,
                        followees: [NeuronId { id: 2 }].to_vec(),
                    })),
                }))),
                ..Default::default()
            },
        )
        .unwrap_err()
        .error_type
    );
    // Set stake to 2 ICP.
    gov.proto
        .neurons
        .get_mut(&2)
        .unwrap()
        .cached_neuron_stake_e8s = 200_000_000;
    // This should now succeed.
    gov.make_proposal(
        &NeuronId { id: 2 },
        // Must match neuron 1's serialized_id.
        &principal(2),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 1 })),
                id: None,
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::NeuronManagement as i32,
                    followees: [NeuronId { id: 2 }].to_vec(),
                })),
            }))),
            ..Default::default()
        },
    )
    .unwrap();
}

/// Constructs a fixture with 2 neurons of different stakes and no
/// following. Neuron 2 has a greater stake.
fn fixture_two_neurons_second_is_bigger() -> GovernanceProto {
    let mut driver = fake::FakeDriver::default();
    GovernanceProto {
        economics: Some(NetworkEconomics::default()),
        neurons: hashmap! {
             1 =>
                Neuron {
                    id: Some(NeuronId {id: 1}),
                 controller: Some(principal(1)),
                    cached_neuron_stake_e8s: 23,
                    account: driver.random_byte_array().to_vec(),
                 // One year
                 dissolve_state: Some(neuron::DissolveState::DissolveDelaySeconds(31557600)),
                 ..Default::default()
             },
         2 =>
                Neuron {
                    id: Some(NeuronId {id: 1}),
                 controller: Some(principal(2)),
                    cached_neuron_stake_e8s: 951,
                    account: driver.random_byte_array().to_vec(),
                 // One year
                 dissolve_state: Some(neuron::DissolveState::DissolveDelaySeconds(31557600)),
                 ..Default::default()
             },
        },
        ..Default::default()
    }
}

#[test]
#[should_panic]
fn test_invalid_proposals_fail() {
    let fake_driver = fake::FakeDriver::default();
    let fixture = fixture_two_neurons_second_is_bigger();
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );

    let long_string = (0..(PROPOSAL_MOTION_TEXT_BYTES_MAX + 1))
        .map(|_| "X")
        .collect::<String>();
    // Now let's send a proposal
    gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "proposal 1".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: long_string,
            })),
            ..Default::default()
        },
    )
    .unwrap();
}

/// In this scenario, the wait-for-quiet policy make that proposals last though
/// several reward periods.
///
/// We check that the reward event for a proposal happens at the expected time.
#[test]
fn test_reward_event_proposals_last_longer_than_reward_period() {
    let mut fake_driver = fake::FakeDriver::default()
        .at(56)
        // To make assertion easy to sanity-check, the total supply of ICPs is chosen
        // so that the reward supply for the first day is 100 (365_250 * 10% / 365.25 = 100).
        // On next days it will be a bit less, but it is still easy to verify by eye
        // the order of magnitude.
        .with_supply(Tokens::from_e8s(365_250));
    let mut fixture = fixture_two_neurons_second_is_bigger();
    // Proposals last longer than the reward period
    let wait_for_quiet_threshold_seconds = 5 * REWARD_DISTRIBUTION_PERIOD_SECONDS;
    fixture.wait_for_quiet_threshold_seconds = wait_for_quiet_threshold_seconds;
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );
    let expected_initial_event = RewardEvent {
        day_after_genesis: 0,
        actual_timestamp_seconds: 56,
        settled_proposals: vec![],
        distributed_e8s_equivalent: 0,
    };

    assert_eq!(*gov.latest_reward_event(), expected_initial_event);
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS / 2);
    gov.run_periodic_tasks().now_or_never();

    // Too early: nothing should have changed
    assert_eq!(*gov.latest_reward_event(), expected_initial_event);
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    gov.run_periodic_tasks().now_or_never();
    // A reward event should have happened, albeit an empty one.
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 1,
            actual_timestamp_seconds: 56 + 3 * REWARD_DISTRIBUTION_PERIOD_SECONDS / 2,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
        }
    );
    // Now let's send a proposal
    gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "proposal 1".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "Thou shall not do bad things with the IC".to_string(),
            })),
            ..Default::default()
        },
    )
    .unwrap();
    let pid = ProposalId { id: 1 };
    // Let's advance time by several reward periods, but less than the
    // wait-for-quiet. The proposal should not be considered for reward.
    fake_driver.advance_time_by(2 * REWARD_DISTRIBUTION_PERIOD_SECONDS);
    gov.run_periodic_tasks().now_or_never();
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 3,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
        }
    );
    // let's advance further in time, just before expiration
    fake_driver.advance_time_by(3 * REWARD_DISTRIBUTION_PERIOD_SECONDS - 5);
    gov.run_periodic_tasks().now_or_never();
    // This should have triggered an empty reward event
    assert_eq!(gov.latest_reward_event().day_after_genesis, 6);
    // let's advance further in time, but not far enough to trigger a reward event
    fake_driver.advance_time_by(10);
    gov.run_periodic_tasks().now_or_never();
    assert_eq!(gov.latest_reward_event().day_after_genesis, 6);
    // let's advance far enough to trigger a reward event
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    gov.run_periodic_tasks().now_or_never();
    // distributed_e8s_equivalent should be roughly 365_250 / 365.25 * 10 % = 100,
    // but a bit less since this is 7 days after genesis.
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 7,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![pid],
            // Just copy the distributed_e8s_equivalent from the actual here, we'll
            // assert value just below
            distributed_e8s_equivalent: 99
        }
    );
    // There was only one voter (the proposer), which should get all of the reward.
    assert_eq!(
        gov.get_neuron(&NeuronId { id: 1 })
            .unwrap()
            .maturity_e8s_equivalent,
        99
    );
    // The ballots should have been cleared
    let p = gov.get_proposal_data(pid).unwrap();
    assert!(p.ballots.is_empty(), "Proposal Info: {:?}", p);

    // Now let's advance again -- a new empty reward event should happen
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    gov.run_periodic_tasks().now_or_never();
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 8,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
        }
    );
    // Neuron maturity should not have changed
    assert_eq!(
        gov.get_neuron(&NeuronId { id: 1 })
            .unwrap()
            .maturity_e8s_equivalent,
        99
    );
}

/// Restricted proposals, those where the eligible voters depend on the
/// proposal's content, should never be taken into account for voting rewards.
#[test]
fn test_restricted_proposals_are_not_eligible_for_voting_rewards() {
    let mut fake_driver = fake::FakeDriver::default()
        .at(3)
        // We need a positive supply to ensure that there can be voting rewards
        .with_supply(Tokens::from_e8s(1_234_567_890));
    let mut fixture = fixture_for_manage_neuron();
    // Proposals last one second
    let proposal_expiration_seconds = 1;
    let wait_for_quiet_threshold_seconds = proposal_expiration_seconds;
    fixture.wait_for_quiet_threshold_seconds = wait_for_quiet_threshold_seconds;
    fixture.short_voting_period_seconds = wait_for_quiet_threshold_seconds;
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );
    gov.run_periodic_tasks().now_or_never();
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 0,
            actual_timestamp_seconds: 3,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
        }
    );

    // Now let's send a private proposal
    // Make a proposal to replace the list of followees (2-4) with just 3.
    gov.make_proposal(
        &NeuronId { id: 2 },
        // Must match neuron 1's serialized_id.
        &principal(2),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 1 })),
                id: None,
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::NeuronManagement as i32,
                    followees: [NeuronId { id: 3 }].to_vec(),
                })),
            }))),
            ..Default::default()
        },
    )
    .unwrap();

    {
        let info = gov.get_proposal_data(ProposalId { id: 1 }).unwrap();
        assert_eq!(info.status(), ProposalStatus::Open);
        assert_eq!(
            info.reward_status(fake_driver.now(), proposal_expiration_seconds),
            ProposalRewardStatus::Ineligible
        );
    }

    // Let's advance time one reward periods. The proposal should not be considered
    // for the reward event.
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    gov.run_periodic_tasks().now_or_never();
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 1,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
        }
    );

    {
        gov.run_periodic_tasks().now_or_never();
        let info = gov.get_proposal_data(ProposalId { id: 1 }).unwrap();
        assert_eq!(info.status(), ProposalStatus::Rejected);
        assert_eq!(
            info.reward_status(fake_driver.now(), proposal_expiration_seconds),
            ProposalRewardStatus::Ineligible
        );
    }
}

#[test]
fn test_reward_distribution_skips_deleted_neurons() {
    let mut fixture = fixture_two_neurons_second_is_bigger();
    fixture.proposals.insert(
        1_u64,
        ProposalData {
            id: Some(ProposalId { id: 1 }),
            proposer: Some(NeuronId { id: 2 }),
            reject_cost_e8s: 0,
            proposal: Some(Proposal {
                title: Some("Test motion proposal".to_string()),
                summary: "A proposal voted on by a now-gone neuron".to_string(),
                url: "https://oops".to_string(),
                action: Some(Action::Motion(Motion {
                    motion_text: "a motion".to_string(),
                })),
            }),
            proposal_timestamp_seconds: 2530,
            ballots: [
                (
                    // This is a ballot by neuron 2, which still exists
                    2,
                    Ballot {
                        vote: Vote::Yes as i32,
                        voting_power: 250,
                    },
                ),
                (
                    // This is a ballot by neuron 999, which is not present in the neuron map.
                    999,
                    Ballot {
                        vote: Vote::Yes as i32,
                        voting_power: 750,
                    },
                ),
            ]
            .iter()
            .cloned()
            .collect(),
            ..Default::default()
        },
    );
    let mut fake_driver = fake::FakeDriver::default()
        .at(2500) // Just a little before the proposal happened.
        // To make assertion easy to sanity-check, the total supply of ICPs is chosen
        // so that the reward supply for the first day is 100 (365_250 * 10% / 365.25 = 100).
        .with_supply(Tokens::from_e8s(365_250));
    fixture.wait_for_quiet_threshold_seconds = 5;
    // Let's set genesis
    let genesis_timestamp_seconds = fake_driver.now();
    fixture.genesis_timestamp_seconds = genesis_timestamp_seconds;
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );

    // Make sure that the fixture function indeed did not create a neuron 999.
    assert_matches!(gov.get_neuron(&NeuronId { id: 999 }), Err(e) if e.error_type == NotFound as i32);

    // The proposal at genesis time is not ready to be settled
    gov.run_periodic_tasks().now_or_never();
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 0,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
        }
    );

    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    gov.run_periodic_tasks().now_or_never();
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 1,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![ProposalId { id: 1 }],
            // We should have distrubuted 100 e8 equivalent if all voters still existed.
            // Since neuron 999 is gone and had a voting power 3x that of neuron 2,
            // only 1/4 is actually distributed.
            distributed_e8s_equivalent: 25,
        }
    );
    assert_eq!(
        25,
        gov.get_full_neuron(&NeuronId { id: 2 }, &principal(2))
            .unwrap()
            .maturity_e8s_equivalent
    );
}

/// In this test, genesis is set to happen 1.5 reward period later than when the
/// governance canister is created.
///
/// Proposals that are ready-to-settle before the end of the first period should
/// all be considered in the first reward event.
///
/// Short proposals are set to last a few seconds (much shorter than a reward
/// period), and long proposals are set to last 2 reward periods -- so that a
/// long proposal created before genesis should only be considered in the second
/// reward event after genesis, not the first.
#[test]
fn test_genesis_in_the_future_in_supported() {
    let mut fake_driver = fake::FakeDriver::default()
        .at(78)
        // To make assertion easy to sanity-check, the total supply of ICPs is chosen
        // so that the reward supply for the first day is 100 (365_250 * 10% / 365.25 = 100).
        .with_supply(Tokens::from_e8s(365_250));
    let mut fixture = fixture_two_neurons_second_is_bigger();
    fixture.wait_for_quiet_threshold_seconds = 2 * REWARD_DISTRIBUTION_PERIOD_SECONDS;
    fixture.short_voting_period_seconds = 13;
    // Let's set genesis
    let genesis_timestamp_seconds = fake_driver.now() + 3 * REWARD_DISTRIBUTION_PERIOD_SECONDS / 2;
    fixture.genesis_timestamp_seconds = genesis_timestamp_seconds;
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );
    gov.run_periodic_tasks().now_or_never();
    // At genesis, we should create an empty reward event
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 0,
            actual_timestamp_seconds: 78,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
        }
    );

    // Submit a short (rate update) and a long proposal
    let long_early_proposal_pid = gov
        .make_proposal(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &principal(1),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "proposal 1 (long)".to_string(),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "a".to_string(),
                })),
                ..Default::default()
            },
        )
        .unwrap();
    let short_proposal_pid = gov
        .make_proposal(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &principal(1),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "proposal 2 (short)".to_string(),
                action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
                    nns_function: NnsFunction::IcpXdrConversionRate as i32,
                    payload: Encode!(&UpdateIcpXdrConversionRatePayload {
                        xdr_permyriad_per_icp: 9256,
                        data_source: "the data source".to_string(),
                        timestamp_seconds: 111_222_333,
                    })
                    .unwrap(),
                })),
                ..Default::default()
            },
        )
        .unwrap();

    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    gov.run_periodic_tasks().now_or_never();
    // We're still pre-genesis at that point
    assert!(fake_driver.now() < genesis_timestamp_seconds);
    // No new reward event should have been created...
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 0,
            actual_timestamp_seconds: 78,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
        }
    );
    // ... even though the short proposal is ready to settle
    let short_info = gov
        .get_proposal_info(&PrincipalId::new_anonymous(), short_proposal_pid)
        .unwrap();
    assert_eq!(
        short_info.reward_status, ReadyToSettle as i32,
        "Proposal info for the 'short' proposal: {:#?}",
        short_info
    );
    assert_eq!(
        short_info.reward_event_round, 0,
        "Proposal info for the 'short' proposal: {:#?}",
        short_info
    );

    // The long proposal, however, is still open for voting
    let long_early_info = gov
        .get_proposal_info(&PrincipalId::new_anonymous(), long_early_proposal_pid)
        .unwrap();
    assert_eq!(
        long_early_info.reward_status, AcceptVotes as i32,
        "Proposal info for the 'long' proposal: {:#?}",
        long_early_info
    );
    assert_eq!(
        long_early_info.reward_event_round, 0,
        "Proposal info for the 'long' proposal: {:#?}",
        long_early_info
    );

    // Submits another long proposal, this time that should not be ready to settle
    // before the first reward distribution.
    let pre_genesis_proposal_that_should_settle_in_period_2_pid = gov
        .make_proposal(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &principal(1),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "pre_genesis_proposal_that_should_settle_in_period_2".to_string(),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "b".to_string(),
                })),
                ..Default::default()
            },
        )
        .unwrap();

    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    gov.run_periodic_tasks().now_or_never();
    // Now we're 0.5 reward period after genesis. Still no new reward event
    // expected.
    assert_eq!(
        fake_driver.now(),
        genesis_timestamp_seconds + REWARD_DISTRIBUTION_PERIOD_SECONDS / 2
    );
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 0,
            actual_timestamp_seconds: 78,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
        }
    );
    // The long early proposal should now be ready to settle
    // The long proposal, however, is still open for voting
    let long_early_info = gov
        .get_proposal_info(&PrincipalId::new_anonymous(), long_early_proposal_pid)
        .unwrap();
    assert_eq!(
        long_early_info.reward_status, ReadyToSettle as i32,
        "Proposal info for the 'long' proposal: {:#?}",
        long_early_info
    );

    // Let's go just at the time we should create the first reward event
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS / 2);
    gov.run_periodic_tasks().now_or_never();
    assert_eq!(
        fake_driver.now(),
        genesis_timestamp_seconds + REWARD_DISTRIBUTION_PERIOD_SECONDS
    );
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 1,
            actual_timestamp_seconds: fake_driver.now(),
            // Settled proposals are sorted
            settled_proposals: vec![long_early_proposal_pid, short_proposal_pid],
            distributed_e8s_equivalent: 100,
        }
    );

    // Let's go just at the time we should create the first reward event
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    gov.run_periodic_tasks().now_or_never();
    // This time, the other long proposal submitted before genesis shoud be
    // considered
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 2,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![pre_genesis_proposal_that_should_settle_in_period_2_pid],
            distributed_e8s_equivalent: gov.latest_reward_event().distributed_e8s_equivalent,
        }
    );

    // At this point, all proposals have been rewarded
    assert_eq!(
        gov.get_proposal_info(&PrincipalId::new_anonymous(), long_early_proposal_pid)
            .unwrap()
            .reward_event_round,
        1
    );
    assert_eq!(
        gov.get_proposal_info(&PrincipalId::new_anonymous(), short_proposal_pid)
            .unwrap()
            .reward_event_round,
        1
    );
    assert_eq!(
        gov.get_proposal_info(
            &PrincipalId::new_anonymous(),
            pre_genesis_proposal_that_should_settle_in_period_2_pid
        )
        .unwrap()
        .reward_event_round,
        2
    );
}

/// Test helper where several proposals are created and voted on by
/// various neurons. 100 e8s of voting rewards are distributed and the
/// final maturities are returned, truncated to the nearest integer
/// (so they don't have to add up to 100).
///
/// In this test, all proposals last 1 second, which is smaller than the reward
/// period. This allows to have tests where everything interesting happens in
/// the first reward period.
fn compute_maturities(
    stakes_e8s: Vec<u64>,
    proposals: Vec<impl Into<fake::ProposalNeuronBehavior>>,
) -> Vec<u64> {
    let proposals: Vec<fake::ProposalNeuronBehavior> =
        proposals.into_iter().map(|x| x.into()).collect();

    let mut fake_driver = fake::FakeDriver::default()
        // To make assertion easy to sanity-check, the total supply of ICPs is chosen
        // so that the reward supply for the first day is 100 (365_250 * 10% / 365.25 = 100).
        .with_supply(Tokens::from_e8s(365_250));

    let fixture = GovernanceProto {
        neurons: stakes_e8s
            .iter()
            .enumerate()
            .map(|(i, stake_e8s)| {
                (
                    i as u64,
                    Neuron {
                        id: Some(NeuronId { id: i as u64 }),
                        controller: Some(principal(i as u64)),
                        cached_neuron_stake_e8s: *stake_e8s,
                        dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                        account: fake_driver.get_fake_env().random_byte_array().to_vec(),
                        ..Default::default()
                    },
                )
            })
            .collect(),
        wait_for_quiet_threshold_seconds: 10,
        economics: Some(NetworkEconomics::default()),
        ..Default::default()
    };

    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );

    let expected_initial_event = RewardEvent {
        day_after_genesis: 0,
        actual_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS,
        settled_proposals: vec![],
        distributed_e8s_equivalent: 0,
    };

    assert_eq!(*gov.latest_reward_event(), expected_initial_event);

    for (i, behavior) in (1_u64..).zip(proposals.iter()) {
        behavior.propose_and_vote(&mut gov, format!("proposal {}", i));
    }

    // Let's advance time by one reward periods. All proposals should be considered
    // for reward.
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    gov.run_periodic_tasks().now_or_never();
    let actual_reward_event = gov.latest_reward_event();
    assert_eq!(
        *actual_reward_event,
        RewardEvent {
            day_after_genesis: 1,
            actual_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS
                + REWARD_DISTRIBUTION_PERIOD_SECONDS,
            settled_proposals: (1_u64..1 + proposals.len() as u64)
                .map(|id| ProposalId { id })
                .collect(),
            // Don't assert on distributed_e8s_equivalent here -- the assertions
            // is the job of the caller
            distributed_e8s_equivalent: actual_reward_event.distributed_e8s_equivalent,
        }
    );

    (0_u64..stakes_e8s.len() as u64)
        .map(|id| {
            gov.get_neuron(&NeuronId { id })
                .unwrap()
                .maturity_e8s_equivalent
        })
        .collect()
}

proptest! {

/// Check that voting a Governance proposal yields 20x more maturity
/// than voting on a network economics proposal.
#[cfg(feature = "test")]
#[test]
fn test_topic_weights(stake in 1u64..1_000_000_000) {
    // Neuron 0 proposes and votes on a governance proposal. Neuron 1
    // proposes and votes on five network economics proposals. Neuron
    // 0 gets 20 times the voting power and neuron 1 gets 5 tives the
    // voting power. Thus, their ratio of voting rewards ought to be
    // 20:5 or 4:1 or 80:20 regardless of the stakes.
    //
    // Note that compute_maturities returns the resulting maturities
    // when 100 e8s of voting rewards are distributed.
    assert_eq!(
        compute_maturities(vec![stake, stake], vec!["P-G", "-PN", "-PN", "-PN", "-PN", "-PN"]),
        vec![80, 20]
    );
    // Make sure that, when voting on proposals of the same type in
    // the ratio 1:5, they get voting rewards in the ratio 1:5
    // instead. Note that the maturities are truncated: 16.(6) to 16
    // and 83.(3) to 83.
    assert_eq!(
        compute_maturities(vec![stake, stake], vec!["P-N", "-P", "-P", "-P", "-P", "-P"]),
        vec![16, 83]
    );
    assert_eq!(
        compute_maturities(vec![stake, stake], vec!["P-G", "-PG", "-PG", "-PG", "-PG", "-PG"]),
        vec![16, 83]
    );
    assert_eq!(
        compute_maturities(vec![stake, stake], vec!["P-E", "-PE", "-PE", "-PE", "-PE", "-PE"]),
        vec![16, 83]
    );
    // Ensure that voting on an exchange rate proposal gives 1% of the
    // voting rewards. Note that the maturities are truncated:
    // 99.(0099) to 99 and 0.(0099) to 0.
    assert_eq!(
        compute_maturities(vec![stake, stake], vec!["P-N", "-PE"]),
        vec![99, 0]
    );
}

}

/// Check that, if all stakes are scaled uniformly, the maturities are
/// unchanged.
#[test]
fn test_maturities_are_invariant_by_stake_scaling() {
    assert_eq!(compute_maturities(vec![1], vec!["P"]), vec![100]);
    assert_eq!(compute_maturities(vec![2], vec!["P"],), vec![100]);
    assert_eq!(compute_maturities(vec![43_330], vec!["P"]), vec![100]);
}

/// Check that, if there is no proposal in the reward period, maturities do not
/// increase.
#[test]
fn test_no_maturity_increase_if_no_proposal() {
    // Single neuron
    assert_eq!(compute_maturities(vec![1], Vec::<&str>::new()), vec![0]);
    // Two neurons
    assert_eq!(
        compute_maturities(vec![1, 5], Vec::<&str>::new()),
        vec![0, 0]
    );
}

/// In this test, one neuron does nothing. It should get no maturity.
#[test]
fn test_passive_neurons_dont_get_mature() {
    assert_eq!(compute_maturities(vec![1, 1], vec!["P-"]), vec![100, 0]);
    assert_eq!(compute_maturities(vec![1, 1], vec!["-P"]), vec![0, 100]);
}

/// Tests that proposing, voting yes, and voting no all result in the same
/// maturity increase
#[test]
fn test_proposing_voting_yes_voting_no_are_equivalent_for_rewards() {
    assert_eq!(compute_maturities(vec![1, 1], vec!["Py"]), vec![50, 50]);
    assert_eq!(compute_maturities(vec![1, 1], vec!["Pn"]), vec![50, 50]);
    assert_eq!(compute_maturities(vec![1, 1], vec!["yP"]), vec![50, 50]);
    assert_eq!(compute_maturities(vec![1, 1], vec!["nP"]), vec![50, 50]);
}

/// In this test, there are 4 neurons, which are not always active: they
/// participate actively (as proposer or voter) on 3/4 of the proposals. Since
/// they are all behaving similarly, they all get an identical maturity.
#[test]
fn test_neuron_sometimes_active_sometimes_passive_which_proposal_does_not_matter() {
    assert_eq!(
        compute_maturities(vec![1, 1, 1, 1], vec!["-Pyn", "P-yn", "Py-n", "Pyn-"]),
        vec![25, 25, 25, 25]
    );
}

/// In this test, one neuron is always active, but the other not always. The
/// more active neuron should get more maturity.
#[test]
fn test_active_neuron_gets_more_mature_than_less_active_one() {
    assert_eq!(
        compute_maturities(vec![1, 1], vec!["P-", "P-", "yP"]),
        vec![75, 25] // first neuron voted 3 times, second 1 time
    );
    assert_eq!(
        compute_maturities(
            vec![2, 1, 1], // First neuron has more stake not to trigger wait for quiet.
            vec!["P--", "P--", "Py-", "P-y", "Pn-", "P-n", "Pyn"]
        ),
        vec![70, 15, 15] /* first neuron votes 7 times with double the stake, second 3 times,
                          * third 3 times. */
    );
}

#[test]
fn test_more_stakes_gets_more_maturity() {
    assert_eq!(compute_maturities(vec![3, 1], vec!["Py"]), vec![75, 25]);
    assert_eq!(compute_maturities(vec![3, 1], vec!["yP"]), vec![75, 25]);
}

/// This test combines differences in activity and differences in stakes to
/// compute rewards.
#[test]
fn test_reward_complex_scenario() {
    assert_eq!(
        compute_maturities(vec![3, 1, 1], vec!["-P-", "--P", "y-P", "P-n"]),
        // First neuron voted twice, 2 * 3 = 6 used voting rights
        // Second neuron voted once, 1 * 1 = 1 used voting rights
        // Third neuron voted 3 times, 3 * 1 = 3 used voting rights
        // Total 10 used voting rights
        vec![60, 10, 30]
    );
}

fn fixture_for_approve_kyc() -> GovernanceProto {
    let mut driver = fake::FakeDriver::default();
    let principal1 = PrincipalId::new_self_authenticating(b"SID1");
    let principal2 = PrincipalId::new_self_authenticating(b"SID2");
    let principal3 = PrincipalId::new_self_authenticating(b"SID3");
    GovernanceProto {
        economics: Some(NetworkEconomics::with_default_values()),
        neurons: [
            (
                1,
                Neuron {
                    id: Some(NeuronId { id: 1 }),
                    controller: Some(principal1),
                    cached_neuron_stake_e8s: 10 * 100_000_000,
                    account: driver.random_byte_array().to_vec(),
                    kyc_verified: false,
                    ..Default::default()
                },
            ),
            (
                2,
                Neuron {
                    id: Some(NeuronId { id: 2 }),
                    controller: Some(principal2),
                    cached_neuron_stake_e8s: 10 * 100_000_000,
                    account: driver.random_byte_array().to_vec(),
                    kyc_verified: false,
                    ..Default::default()
                },
            ),
            (
                3,
                Neuron {
                    id: Some(NeuronId { id: 3 }),
                    controller: Some(principal2),
                    cached_neuron_stake_e8s: 10 * 100_000_000,
                    account: driver.random_byte_array().to_vec(),
                    kyc_verified: false,
                    ..Default::default()
                },
            ),
            (
                4,
                Neuron {
                    id: Some(NeuronId { id: 4 }),
                    controller: Some(principal3),
                    cached_neuron_stake_e8s: 10 * 100_000_000,
                    account: driver.random_byte_array().to_vec(),
                    kyc_verified: false,
                    ..Default::default()
                },
            ),
        ]
        .to_vec()
        .into_iter()
        .collect(),
        ..Default::default()
    }
}

/// Given that:
///
/// - Principal 1 owns neuron A
/// - Principal 2 owns neurons B and C
/// - Principal 3 owns neuron D
///
/// If we approve KYC for Principals 1 and 2, neurons A, B and C should have
/// `kyc_verified=true`, while neuron D still has `kyc_verified=false`
#[test]
fn test_approve_kyc() {
    let fixture = fixture_for_approve_kyc();
    let driver = fake::FakeDriver::default()
        .with_ledger_from_neurons(
            &fixture
                .neurons
                .iter()
                .map(|(_, y)| y)
                .cloned()
                .collect::<Vec<Neuron>>(),
        )
        .with_supply(Tokens::from_tokens(1_000_000).unwrap());
    let mut gov = Governance::new(fixture, driver.get_fake_env(), driver.get_fake_ledger());
    let neuron_a = gov.proto.neurons.get(&1).unwrap().clone();
    let neuron_b = gov.proto.neurons.get(&2).unwrap().clone();

    let principal1 = *neuron_a.controller.as_ref().unwrap();
    let principal2 = *neuron_b.controller.as_ref().unwrap();

    // Test that non kyc'd neurons can't be disbursed to accounts.
    let result = gov
        .disburse_neuron(
            neuron_a.id.as_ref().unwrap(),
            &principal1,
            &Disburse {
                amount: None,
                to_account: Some(AccountIdentifier::new(principal1, None).into()),
            },
        )
        .now_or_never()
        .unwrap();

    assert_matches!(result, Err(msg) if msg.error_message.to_lowercase().contains("kyc verified"));

    // Test that non kyc'd neurons can't be disbursed to another neuron.
    let result = gov
        .disburse_to_neuron(
            neuron_b.id.as_ref().unwrap(),
            &principal2,
            &DisburseToNeuron {
                new_controller: Some(principal2),
                amount_e8s: 5 * 100_000_000,
                dissolve_delay_seconds: 0,
                kyc_verified: true,
                nonce: 1234,
            },
        )
        .now_or_never()
        .unwrap();

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().error_message,
        "Neuron is not kyc verified: 2"
    );

    assert!(!gov.proto.neurons.get(&1).unwrap().kyc_verified);
    assert!(!gov.proto.neurons.get(&2).unwrap().kyc_verified);
    assert!(!gov.proto.neurons.get(&3).unwrap().kyc_verified);
    assert!(!gov.proto.neurons.get(&4).unwrap().kyc_verified);

    gov.approve_genesis_kyc(&[principal1, principal2]);

    assert!(gov.proto.neurons.get(&1).unwrap().kyc_verified);
    assert!(gov.proto.neurons.get(&2).unwrap().kyc_verified);
    assert!(gov.proto.neurons.get(&3).unwrap().kyc_verified);
    assert!(!gov.proto.neurons.get(&4).unwrap().kyc_verified);

    // Disbursing should now work.
    let _ = gov
        .disburse_neuron(
            neuron_a.id.as_ref().unwrap(),
            &principal1,
            &Disburse {
                amount: None,
                to_account: Some(AccountIdentifier::new(principal1, None).into()),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Error disbursing neuron.");

    // ...as should disburse-to-neuron.
    let _ = gov
        .disburse_to_neuron(
            neuron_b.id.as_ref().unwrap(),
            &principal2,
            &DisburseToNeuron {
                new_controller: Some(principal2),
                amount_e8s: 5 * 100_000_000,
                dissolve_delay_seconds: 0,
                kyc_verified: true,
                nonce: 1234,
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Error disbursing to neuron.");
}

/// Create and store some Neurons in a `Governance` object, and assert that
/// their IDs can be fetched as expected by calling
/// `get_neuron_ids_by_principal`
#[test]
fn test_get_neuron_ids_by_principal() {
    let principal1 = principal(1);
    let principal2 = principal(2);
    let principal3 = principal(3);
    let principal4 = principal(4);
    let mut driver = fake::FakeDriver::default();

    let neuron_a = Neuron {
        id: Some(NeuronId { id: 1 }),
        controller: Some(principal1),
        account: driver.random_byte_array().to_vec(),
        ..Default::default()
    };
    let neuron_b = Neuron {
        id: Some(NeuronId { id: 2 }),
        controller: Some(principal2),
        account: driver.random_byte_array().to_vec(),
        ..Default::default()
    };
    let neuron_c = Neuron {
        id: Some(NeuronId { id: 3 }),
        controller: Some(principal2),
        account: driver.random_byte_array().to_vec(),
        ..Default::default()
    };
    let neuron_d = Neuron {
        id: Some(NeuronId { id: 4 }),
        controller: Some(principal2),
        hot_keys: vec![principal4],
        account: driver.random_byte_array().to_vec(),
        ..Default::default()
    };

    let mut gov_proto = empty_fixture();
    gov_proto.neurons = vec![(1, neuron_a), (2, neuron_b), (3, neuron_c), (4, neuron_d)]
        .into_iter()
        .collect();

    let driver = fake::FakeDriver::default();
    let gov = Governance::new(gov_proto, driver.get_fake_env(), driver.get_fake_ledger());

    let mut principal2_neuron_ids = gov.get_neuron_ids_by_principal(&principal2);
    principal2_neuron_ids.sort_unstable();

    assert_eq!(gov.get_neuron_ids_by_principal(&principal1), vec![1]);
    assert_eq!(principal2_neuron_ids, vec![2, 3, 4]);
    assert_eq!(
        gov.get_neuron_ids_by_principal(&principal3),
        Vec::<u64>::new()
    );
    assert_eq!(gov.get_neuron_ids_by_principal(&principal4), vec![4]);
}

/// *Test fixture for general tests*
fn empty_fixture() -> GovernanceProto {
    GovernanceProto {
        economics: Some(NetworkEconomics::with_default_values()),
        ..Default::default()
    }
}

fn claim_or_refresh_neuron_by_memo(
    gov: &mut Governance,
    caller: &PrincipalId,
    controller: Option<PrincipalId>,
    _subaccount: Subaccount,
    memo: Memo,
    neuron_id_or_subaccount: Option<NeuronIdOrSubaccount>,
) -> Result<NeuronId, GovernanceError> {
    let manage_neuron_response = gov
        .manage_neuron(
            caller,
            &ManageNeuron {
                id: None,
                command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                    by: Some(By::MemoAndController(MemoAndController {
                        memo: memo.0,
                        controller,
                    })),
                })),
                neuron_id_or_subaccount,
            },
        )
        .now_or_never()
        .unwrap();
    match manage_neuron_response.command.unwrap() {
        CommandResponse::Error(error) => Err(error),
        CommandResponse::ClaimOrRefresh(claim_or_refresh_response) => {
            Ok(claim_or_refresh_response.refreshed_neuron_id.unwrap())
        }
        _ => panic!("Unexpected command response."),
    }
}

fn governance_with_staked_neuron(
    dissolve_delay_seconds: u64,
    neuron_stake_e8s: u64,
    _block_height: u64,
    from: PrincipalId,
    nonce: u64,
) -> (fake::FakeDriver, Governance, NeuronId, Subaccount) {
    let to_subaccount = Subaccount({
        let mut sha = Sha256::new();
        sha.write(&[0x0c]);
        sha.write(b"neuron-stake");
        sha.write(from.as_slice());
        sha.write(&nonce.to_be_bytes());
        sha.finish()
    });

    let driver = fake::FakeDriver::default()
        .at(56)
        .with_ledger_accounts(vec![fake::FakeAccount {
            id: AccountIdentifier::new(
                ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
                Some(to_subaccount),
            ),
            amount_e8s: neuron_stake_e8s,
        }])
        .with_supply(Tokens::from_tokens(400_000_000).unwrap());
    let mut gov = Governance::new(
        empty_fixture(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );

    // Add a stake transfer for this neuron, emulating a ledger call.
    let nid =
        claim_or_refresh_neuron_by_memo(&mut gov, &from, None, to_subaccount, Memo(nonce), None)
            .unwrap();

    assert_eq!(gov.proto.neurons.len(), 1);

    let neuron = gov.proto.neurons.get_mut(&nid.id).unwrap();
    neuron
        .configure(
            &from,
            driver.now(),
            &Configure {
                operation: Some(Operation::IncreaseDissolveDelay(IncreaseDissolveDelay {
                    additional_dissolve_delay_seconds: dissolve_delay_seconds as u32,
                })),
            },
        )
        .unwrap();

    (driver, gov, nid, to_subaccount)
}

/// Creates a neuron that has accumulated some maturity.
///
/// If `dissolved` is true, the returned neuron is in the "dissolved" state,
/// otherwise the returned neuron is in the "not-dissolving" state.
fn create_mature_neuron(dissolved: bool) -> (fake::FakeDriver, Governance, Neuron) {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds = MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS;
    let neuron_stake_e8s = 100_000_000;

    let (mut driver, mut gov, id, to_subaccount) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    // Make sure the neuron was created with the right details.
    assert_eq!(
        gov.proto.neurons.get(&id.id).unwrap(),
        &Neuron {
            id: Some(id.clone()),
            account: to_subaccount.to_vec(),
            controller: Some(from),
            cached_neuron_stake_e8s: neuron_stake_e8s,
            created_timestamp_seconds: driver.now(),
            aging_since_timestamp_seconds: driver.now(),
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)),
            kyc_verified: true,
            ..Default::default()
        }
    );
    assert_eq!(gov.get_neuron_ids_by_principal(&from), vec![id.id]);

    let neuron = gov.proto.neurons.get_mut(&id.id).unwrap();

    // Dissolve the neuron if `dissolved` is true
    if dissolved {
        neuron
            .configure(
                &from,
                driver.now(),
                &Configure {
                    operation: Some(Operation::StartDissolving(StartDissolving {})),
                },
            )
            .unwrap();
        // Advance the time in the env
        driver.advance_time_by(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS + 1);

        // The neuron state should now be "Dissolved", meaning we can
        // now disburse the neuron.
        assert_eq!(
            neuron.get_neuron_info(driver.now()).state(),
            NeuronState::Dissolved
        );
    } else {
        driver.advance_time_by(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS + 1);
    }

    let neuron_fees_e8s = 50_000_000; // 0.5 ICPT
    let neuron_maturity = 25_000_000;
    // Pretend the neuron has some rewards and fees to pay.
    neuron.neuron_fees_e8s = neuron_fees_e8s;
    // .. and some maturity to collect.
    neuron.maturity_e8s_equivalent = neuron_maturity;

    let n = neuron.clone();

    (driver, gov, n)
}

#[test]
fn test_neuron_lifecycle() {
    let (driver, mut gov, neuron) = create_mature_neuron(true);

    let id = neuron.id.unwrap();
    let from = neuron.controller.unwrap();
    let neuron_stake_e8s = neuron.cached_neuron_stake_e8s;
    let neuron_fees_e8s = neuron.neuron_fees_e8s;
    let neuron_maturity = neuron.maturity_e8s_equivalent;

    gov.disburse_neuron(
        &id,
        &from,
        &Disburse {
            amount: None,
            to_account: Some(AccountIdentifier::new(from, None).into()),
        },
    )
    .now_or_never()
    .unwrap()
    .unwrap();

    // The user's account should now have the amount
    driver.assert_account_contains(
        &AccountIdentifier::new(from, None),
        // In the end, the user's account should have the stake + rewards - fees
        // - transaction fees.
        neuron_stake_e8s - neuron_fees_e8s + neuron_maturity
            - gov.proto.economics.as_ref().unwrap().transaction_fee_e8s,
    );
}

#[test]
fn test_disburse_to_subaccount() {
    let (driver, mut gov, neuron) = create_mature_neuron(true);

    let id = neuron.id.unwrap();
    let from = neuron.controller.unwrap();
    let neuron_stake_e8s = neuron.cached_neuron_stake_e8s;
    let neuron_fees_e8s = neuron.neuron_fees_e8s;
    let neuron_maturity = neuron.maturity_e8s_equivalent;

    let to_subaccount = Subaccount({
        let mut sha = Sha256::new();
        sha.write(b"my_account");
        sha.finish()
    });

    gov.disburse_neuron(
        &id,
        &from,
        &Disburse {
            amount: None,
            to_account: Some(AccountIdentifier::new(from, Some(to_subaccount)).into()),
        },
    )
    .now_or_never()
    .unwrap()
    .unwrap();

    // The user's account should now have the amount
    driver.assert_account_contains(
        &AccountIdentifier::new(from, Some(to_subaccount)),
        // In the end, the user's account should have the stake + rewards - fees
        // - transaction fees.
        neuron_stake_e8s - neuron_fees_e8s + neuron_maturity
            - gov.proto.economics.as_ref().unwrap().transaction_fee_e8s,
    );
}

#[test]
fn test_nns1_520() {
    let (driver, mut gov, neuron) = create_mature_neuron(true);

    let id = neuron.id.unwrap();
    let from = neuron.controller.unwrap();
    let neuron_stake_e8s = neuron.cached_neuron_stake_e8s;
    let neuron_fees_e8s = neuron.neuron_fees_e8s;
    let neuron_maturity = neuron.maturity_e8s_equivalent;

    let to_subaccount = Subaccount({
        let mut sha = Sha256::new();
        sha.write(b"my_account");
        sha.finish()
    });

    gov.disburse_neuron(
        &id,
        &from,
        &Disburse {
            amount: Some(Amount { e8s: 100000000 }),
            to_account: Some(AccountIdentifier::new(from, Some(to_subaccount)).into()),
        },
    )
    .now_or_never()
    .unwrap()
    .unwrap();

    // The user's account should now have the amount
    driver.assert_account_contains(
        &AccountIdentifier::new(from, Some(to_subaccount)),
        // In the end, the user's account should have the stake + rewards - fees
        // - transaction fees.
        neuron_stake_e8s - neuron_fees_e8s + neuron_maturity
            - gov.proto.economics.as_ref().unwrap().transaction_fee_e8s,
    );

    assert_eq!(
        gov.proto
            .neurons
            .get(&id.id)
            .unwrap()
            .cached_neuron_stake_e8s,
        0
    );
}

#[test]
fn test_disburse_to_main_acccount() {
    let (driver, mut gov, neuron) = create_mature_neuron(true);

    let id = neuron.id.unwrap();
    let from = neuron.controller.unwrap();
    let neuron_stake_e8s = neuron.cached_neuron_stake_e8s;
    let neuron_fees_e8s = neuron.neuron_fees_e8s;
    let neuron_maturity = neuron.maturity_e8s_equivalent;

    gov.disburse_neuron(
        &id,
        &from,
        &Disburse {
            amount: None,
            to_account: None,
        },
    )
    .now_or_never()
    .unwrap()
    .unwrap();

    // The user's account should now have the amount
    driver.assert_account_contains(
        &AccountIdentifier::new(from, None),
        // In the end, the user's account should have the stake + rewards - fees
        // - transaction fees.
        neuron_stake_e8s - neuron_fees_e8s + neuron_maturity
            - gov.proto.economics.as_ref().unwrap().transaction_fee_e8s,
    );
}

// Test cases for claim and refresh
// - Claim with memo
//   - Controller
//   - Someone else for the controller
//   - It's not possible for someone else to claim for themselves
// - Refresh with memo
//   - Anyone can do it
// - Refresh with subaccount
//   - Anyone can do it

// Builds governance with a staked, but unclaimed, neuron.
fn governance_with_staked_unclaimed_neuron(
    from: &PrincipalId,
    nonce: u64,
    stake: Tokens,
) -> (fake::FakeDriver, Governance, Subaccount) {
    let to_subaccount = Subaccount({
        let mut sha = Sha256::new();
        sha.write(&[0x0c]);
        sha.write(b"neuron-stake");
        sha.write(from.as_slice());
        sha.write(&nonce.to_be_bytes());
        sha.finish()
    });

    let driver = fake::FakeDriver::default()
        .at(56)
        .with_ledger_accounts(vec![fake::FakeAccount {
            id: AccountIdentifier::new(
                ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
                Some(to_subaccount),
            ),
            amount_e8s: stake.get_e8s(),
        }])
        .with_supply(Tokens::from_tokens(400_000_000).unwrap());

    let gov = Governance::new(
        empty_fixture(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );

    (driver, gov, to_subaccount)
}

/// Tests that the controller of a neuron (the principal whose hash was used
/// to build the subaccount) can claim a neuron just with the memo.
#[test]
fn test_claim_neuron_by_memo_only() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let memo = 1234u64;
    let stake = Tokens::from_tokens(10u64).unwrap();
    let (_, mut gov, _) = governance_with_staked_unclaimed_neuron(&owner, memo, stake);

    let manage_neuron_response = gov
        .manage_neuron(
            &owner,
            &ManageNeuron {
                neuron_id_or_subaccount: None,
                id: None,
                command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                    by: Some(By::MemoAndController(MemoAndController {
                        memo,
                        controller: None,
                    })),
                })),
            },
        )
        .now_or_never()
        .unwrap();

    let nid = match manage_neuron_response.command.unwrap() {
        CommandResponse::ClaimOrRefresh(response) => response.refreshed_neuron_id,
        CommandResponse::Error(error) => panic!("Error claiming neuron: {:?}", error),
        _ => panic!("Invalid response."),
    };

    assert!(nid.is_some());
    let nid = nid.unwrap();
    let neuron = gov.get_neuron(&nid).unwrap();
    assert_eq!(neuron.controller.unwrap(), owner);
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());
}

#[test]
fn test_claim_neuron_without_minimum_stake_fails() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let memo = 1234u64;
    let stake = Tokens::from_e8s(50000000u64);
    let (_, mut gov, _) = governance_with_staked_unclaimed_neuron(&owner, memo, stake);

    let manage_neuron_response = gov
        .manage_neuron(
            &owner,
            &ManageNeuron {
                neuron_id_or_subaccount: None,
                id: None,
                command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                    by: Some(By::MemoAndController(MemoAndController {
                        memo,
                        controller: None,
                    })),
                })),
            },
        )
        .now_or_never()
        .unwrap();

    match manage_neuron_response.command.unwrap() {
        CommandResponse::Error(error) => {
            assert_eq!(
                ErrorType::from_i32(error.error_type).unwrap(),
                ErrorType::InsufficientFunds
            );
        }
        _ => panic!("Invalid response."),
    };
}

fn claim_neuron_by_memo_and_controller(owner: PrincipalId, caller: PrincipalId) {
    let memo = 1234u64;
    let stake = Tokens::from_tokens(10u64).unwrap();
    let (_, mut gov, _) =
        governance_with_staked_unclaimed_neuron(&owner, memo, Tokens::from_tokens(10u64).unwrap());

    let manage_neuron_response = gov
        .manage_neuron(
            &caller,
            &ManageNeuron {
                neuron_id_or_subaccount: None,
                id: None,
                command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                    by: Some(By::MemoAndController(MemoAndController {
                        memo,
                        controller: Some(owner),
                    })),
                })),
            },
        )
        .now_or_never()
        .unwrap();

    let nid = match manage_neuron_response.command.unwrap() {
        CommandResponse::ClaimOrRefresh(response) => response.refreshed_neuron_id,
        CommandResponse::Error(error) => panic!("Error claiming neuron: {:?}", error),
        _ => panic!("Invalid response."),
    };

    assert!(nid.is_some());
    let nid = nid.unwrap();
    let neuron = gov.get_neuron(&nid).unwrap();
    assert_eq!(neuron.controller.unwrap(), owner);
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());
}

/// Like the above, but explicitely sets the controller in the MemoAndController
/// struct.
#[test]
fn test_claim_neuron_memo_and_controller_by_controller() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    claim_neuron_by_memo_and_controller(owner, owner);
}

/// Tests that a non-controller can claim a neuron for the controller (the
/// principal whose id was used to build the subaccount).
#[test]
fn test_claim_neuron_memo_and_controller_by_proxy() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let caller = *TEST_NEURON_2_OWNER_PRINCIPAL;
    claim_neuron_by_memo_and_controller(owner, caller);
}

/// Tests that a non-controller can't claim a neuron for themselves.
#[test]
fn test_non_controller_cant_claim_neuron_for_themselves() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let claimer = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let memo = 1234u64;
    let (_, mut gov, _) =
        governance_with_staked_unclaimed_neuron(&owner, memo, Tokens::from_tokens(10u64).unwrap());

    let manage_neuron_response = gov
        .manage_neuron(
            &claimer,
            &ManageNeuron {
                neuron_id_or_subaccount: None,
                id: None,
                command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                    by: Some(By::MemoAndController(MemoAndController {
                        memo,
                        controller: Some(claimer),
                    })),
                })),
            },
        )
        .now_or_never()
        .unwrap();

    match manage_neuron_response.command.unwrap() {
        CommandResponse::Error(_) => (),
        _ => panic!("Claim should have failed."),
    };
}

fn refresh_neuron_by_memo(owner: PrincipalId, caller: PrincipalId) {
    let stake = Tokens::from_tokens(10u64).unwrap();
    let memo = Memo(1234u64);
    let (mut driver, mut gov, nid, subaccount) =
        governance_with_staked_neuron(1, stake.get_e8s(), 0, owner, memo.0);

    let neuron = gov.get_neuron(&nid).unwrap();
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());

    driver.add_funds_to_account(
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(subaccount)),
        stake.get_e8s(),
    );

    // stake shouldn't have changed.
    let neuron = gov.get_neuron(&nid).unwrap();
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());

    let manage_neuron_response = gov
        .manage_neuron(
            &caller,
            &ManageNeuron {
                neuron_id_or_subaccount: None,
                id: None,
                command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                    by: Some(By::MemoAndController(MemoAndController {
                        memo: memo.0,
                        controller: Some(owner),
                    })),
                })),
            },
        )
        .now_or_never()
        .unwrap();

    let nid = match manage_neuron_response.command.unwrap() {
        CommandResponse::ClaimOrRefresh(response) => response.refreshed_neuron_id,
        CommandResponse::Error(error) => panic!("Error claiming neuron: {:?}", error),
        _ => panic!("Invalid response."),
    };

    assert!(nid.is_some());
    let nid = nid.unwrap();
    let neuron = gov.get_neuron(&nid).unwrap();
    assert_eq!(neuron.controller.unwrap(), owner);
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s() * 2);
}

/// Tests that a neuron can be refreshed by memo by it's controller.
#[test]
fn test_refresh_neuron_by_memo_by_controller() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    refresh_neuron_by_memo(owner, owner);
}

/// Tests that a neuron can be refreshed by memo by proxy.
#[test]
fn test_refresh_neuron_by_memo_by_proxy() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let caller = *TEST_NEURON_2_OWNER_PRINCIPAL;
    refresh_neuron_by_memo(owner, caller);
}

enum RefreshBy {
    NeuronId,
    Subaccount,
}

fn refresh_neuron_by_id_or_subaccount(
    owner: PrincipalId,
    caller: PrincipalId,
    refresh_by: RefreshBy,
) {
    let stake = Tokens::from_tokens(10u64).unwrap();
    let memo = Memo(1234u64);
    let (mut driver, mut gov, nid, subaccount) =
        governance_with_staked_neuron(1, stake.get_e8s(), 0, owner, memo.0);

    let neuron = gov.get_neuron(&nid).unwrap();
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());

    driver.add_funds_to_account(
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(subaccount)),
        stake.get_e8s(),
    );

    // stake shouldn't have changed.
    let neuron = gov.get_neuron(&nid).unwrap().clone();
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());

    let neuron_id_or_subaccount = match refresh_by {
        RefreshBy::NeuronId => NeuronIdOrSubaccount::NeuronId(neuron.id.as_ref().unwrap().clone()),
        RefreshBy::Subaccount => NeuronIdOrSubaccount::Subaccount(subaccount.into()),
    };

    let manage_neuron_response = gov
        .manage_neuron(
            &caller,
            &ManageNeuron {
                neuron_id_or_subaccount: Some(neuron_id_or_subaccount),
                id: None,
                command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                    by: Some(By::NeuronIdOrSubaccount(Empty {})),
                })),
            },
        )
        .now_or_never()
        .unwrap();

    let nid = match manage_neuron_response.command.unwrap() {
        CommandResponse::ClaimOrRefresh(response) => response.refreshed_neuron_id,
        CommandResponse::Error(error) => panic!("Error claiming neuron: {:?}", error),
        _ => panic!("Invalid response."),
    };

    assert!(nid.is_some());
    let nid = nid.unwrap();
    let neuron = gov.get_neuron(&nid).unwrap();
    assert_eq!(neuron.controller.unwrap(), owner);
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s() * 2);
}

#[test]
fn test_refresh_neuron_by_id_by_controller() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    refresh_neuron_by_id_or_subaccount(owner, owner, RefreshBy::NeuronId);
}

#[test]
fn test_refresh_neuron_by_id_by_proxy() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    refresh_neuron_by_id_or_subaccount(owner, caller, RefreshBy::NeuronId);
}

/// Tests that a neuron can be refreshed by subaccount, and that anyone can do
/// it.
#[test]
fn test_refresh_neuron_by_subaccount_by_controller() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    refresh_neuron_by_id_or_subaccount(owner, owner, RefreshBy::Subaccount);
}

#[test]
fn test_refresh_neuron_by_subaccount_by_proxy() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    refresh_neuron_by_id_or_subaccount(owner, caller, RefreshBy::Subaccount);
}

#[test]
fn test_claim_or_refresh_neuron_does_not_overflow() {
    let (mut driver, mut gov, neuron) = create_mature_neuron(true);
    let nid = neuron.id.unwrap();
    let neuron = gov.get_neuron_mut(&nid).unwrap();
    let _account = neuron.account.clone();
    let subaccount = subaccount_from_slice(&neuron.account).unwrap().unwrap();

    // Increase the dissolve delay, this will make the neuron start aging from
    // 'now'.
    neuron
        .configure(
            &*TEST_NEURON_1_OWNER_PRINCIPAL,
            driver.now(),
            &Configure {
                operation: Some(Operation::IncreaseDissolveDelay(IncreaseDissolveDelay {
                    additional_dissolve_delay_seconds: 6
                        * ic_nns_governance::governance::ONE_MONTH_SECONDS as u32,
                })),
            },
        )
        .unwrap();

    // Advance the current time, so that the neuron has accumulated
    // some age.
    driver.advance_time_by(12 * ic_nns_governance::governance::ONE_MONTH_SECONDS);

    assert_eq!(
        neuron.aging_since_timestamp_seconds,
        driver.now() - 12 * ic_nns_governance::governance::ONE_MONTH_SECONDS - 1,
    );

    let _block_height = 543212234;
    // Note that the nonce must match the nonce chosen in the original
    // transfer.
    let _nonce = 1234u64;

    driver.add_funds_to_account(
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(subaccount)),
        100_000_000_000_000,
    );

    // Note that the nonce must match the nonce chosen in the original
    // transfer.
    let nonce = 1234u64;
    let nid_result = claim_or_refresh_neuron_by_memo(
        &mut gov,
        &TEST_NEURON_1_OWNER_PRINCIPAL,
        None,
        subaccount,
        Memo(nonce),
        None,
    )
    .unwrap();

    assert_eq!(nid_result, nid);
    let neuron = gov.get_neuron_mut(&nid).unwrap();
    assert_eq!(neuron.cached_neuron_stake_e8s, 100_000_100_000_000);
}

#[test]
fn test_set_dissolve_delay() {
    let (mut driver, _, mut neuron) = create_mature_neuron(true);

    // Neuron should be dissolved
    assert_eq!(neuron.state(driver.now()), NeuronState::Dissolved);

    // Try to set the dissolve delay to a value before the current time, should
    // fail.
    assert!(neuron
        .configure(
            &*TEST_NEURON_1_OWNER_PRINCIPAL,
            driver.now(),
            &Configure {
                operation: Some(Operation::SetDissolveTimestamp(SetDissolveTimestamp {
                    dissolve_timestamp_seconds: driver.now() - 1,
                })),
            },
        )
        .is_err());

    // Try to set the dissolve delay to a value in the future, should succeed.
    neuron
        .configure(
            &*TEST_NEURON_1_OWNER_PRINCIPAL,
            driver.now(),
            &Configure {
                operation: Some(Operation::SetDissolveTimestamp(SetDissolveTimestamp {
                    dissolve_timestamp_seconds: driver.now()
                        + 3 * ic_nns_governance::governance::ONE_MONTH_SECONDS,
                })),
            },
        )
        .unwrap();

    // Since we set the dissolve delay, neuron should be non-dissolving.
    assert_eq!(neuron.state(driver.now()), NeuronState::NotDissolving);

    // Try to set the dissolve delay to a value that is smaller than the
    // current one, should fail.
    assert!(neuron
        .configure(
            &*TEST_NEURON_1_OWNER_PRINCIPAL,
            driver.now(),
            &Configure {
                operation: Some(Operation::SetDissolveTimestamp(SetDissolveTimestamp {
                    dissolve_timestamp_seconds: driver.now()
                        + 2 * ic_nns_governance::governance::ONE_MONTH_SECONDS,
                })),
            },
        )
        .is_err());

    // Try to set the dissolve dealy to a value that is bigger that the max u32,
    // should fail.
    assert!(neuron
        .configure(
            &*TEST_NEURON_1_OWNER_PRINCIPAL,
            driver.now(),
            &Configure {
                operation: Some(Operation::SetDissolveTimestamp(SetDissolveTimestamp {
                    dissolve_timestamp_seconds: driver.now()
                        + 3 * ic_nns_governance::governance::ONE_MONTH_SECONDS
                        + u32::MAX as u64
                        + 1,
                })),
            },
        )
        .is_err());

    // Try to increase the dissolve delay to a value that is bigger than 8 years,
    // should cap the value to 8y, but succeed.
    neuron
        .configure(
            &*TEST_NEURON_1_OWNER_PRINCIPAL,
            driver.now(),
            &Configure {
                operation: Some(Operation::SetDissolveTimestamp(SetDissolveTimestamp {
                    dissolve_timestamp_seconds: driver.now()
                        + 3 * ic_nns_governance::governance::ONE_MONTH_SECONDS
                        + u32::MAX as u64,
                })),
            },
        )
        .unwrap();

    // Since we increased the dissolve delay, neuron should remain non-dissolving.
    assert_eq!(neuron.state(driver.now()), NeuronState::NotDissolving);

    // Set the neuron to dissolve
    neuron
        .configure(
            &*TEST_NEURON_1_OWNER_PRINCIPAL,
            driver.now(),
            &Configure {
                operation: Some(Operation::StartDissolving(StartDissolving {})),
            },
        )
        .unwrap();

    assert_eq!(neuron.state(driver.now()), NeuronState::Dissolving);

    // Advance the time by almost the amount we set
    driver.advance_time_by(8 * 12 * ic_nns_governance::governance::ONE_MONTH_SECONDS - 1);

    // Neuron should still be dissolving.
    assert_eq!(neuron.state(driver.now()), NeuronState::Dissolving);

    // Advance the time by the last remaining second.
    driver.advance_time_by(1);
    // Now the neuron should be dissolved.
    assert_eq!(neuron.state(driver.now()), NeuronState::Dissolved);
}

#[test]
fn test_cant_disburse_without_paying_fees() {
    let (driver, mut gov, neuron) = create_mature_neuron(true);

    let id = neuron.id.clone().unwrap();
    let from = neuron.controller.unwrap();
    let neuron_stake_e8s = neuron.cached_neuron_stake_e8s;
    let neuron_fees_e8s = neuron.neuron_fees_e8s;
    let neuron_maturity = neuron.maturity_e8s_equivalent;

    // Try to disburse more than the stake amount, this should fail.
    // and cause the neuron to be unchanged.
    let result = gov
        .disburse_neuron(
            &id,
            &from,
            &Disburse {
                amount: Some(manage_neuron::disburse::Amount {
                    e8s: 1000 * 100_000_000,
                }),
                to_account: Some(AccountIdentifier::new(from, None).into()),
            },
        )
        .now_or_never()
        .unwrap();

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().error_type(), ErrorType::External);

    assert_eq!(0, gov.proto.neurons.get(&id.id).unwrap().neuron_fees_e8s);
    driver.assert_account_contains(
        &AccountIdentifier::new(
            GOVERNANCE_CANISTER_ID.get(),
            Some(Subaccount::try_from(&neuron.account[..]).unwrap()),
        ),
        neuron_stake_e8s - neuron_fees_e8s,
    );

    // Now try to disburse exactly the cached  amount, this should fail
    // since the fees were burned above.
    let result = gov
        .disburse_neuron(
            &id,
            &from,
            &Disburse {
                amount: Some(manage_neuron::disburse::Amount {
                    e8s: neuron_stake_e8s,
                }),
                to_account: Some(AccountIdentifier::new(from, None).into()),
            },
        )
        .now_or_never()
        .unwrap();

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().error_type(), ErrorType::External);

    // Finally try to disburse only the current stake (the initial
    // stake - the fees);
    gov.disburse_neuron(
        &id,
        &from,
        &Disburse {
            amount: Some(manage_neuron::disburse::Amount {
                e8s: neuron_stake_e8s - neuron_fees_e8s,
            }),
            to_account: Some(AccountIdentifier::new(from, None).into()),
        },
    )
    .now_or_never()
    .unwrap()
    .unwrap();

    // The user's account should now have the amount
    driver.assert_account_contains(
        &AccountIdentifier::new(from, None),
        // In the end, the user's account should have the stake + rewards - fees
        // - transaction fees.
        neuron_stake_e8s - neuron_fees_e8s + neuron_maturity
            - gov.proto.economics.as_ref().unwrap().transaction_fee_e8s,
    );
}

/// Checks that split_neuron fails if the preconditions are not met. In
/// particular, an attempt to split a neuron fails if:
/// * 1. the neuron does not exist.
/// * 2. the caller is not the neuron's controller.
/// * 3. the parent neuron would be left with less than the minimum stake.
/// * 4. the child neuron would have less than the minimum stake.
/// In all these cases it must thus hold that:
/// * the correct error is returned
/// * the parent neuron is unchanged
/// * the list of all neurons remained unchanged
/// * the list of accounts is unchanged
#[test]
fn test_neuron_split_fails() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds = MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;

    let (driver, mut gov, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    let neuron = gov.proto.neurons.get_mut(&id.id).unwrap();
    let transaction_fee = gov.proto.economics.as_ref().unwrap().transaction_fee_e8s;
    let min_neuron_stake = gov
        .proto
        .economics
        .as_ref()
        .unwrap()
        .neuron_minimum_stake_e8s;

    assert_eq!(
        neuron.get_neuron_info(driver.now()).state(),
        NeuronState::NotDissolving
    );

    let neuron_before = neuron.clone();

    // 1. Attempt to split a neuron that does not exist

    // make a nonexisting_neuron_id
    let nonexisting_neuron_id = NeuronId { id: 12345 };
    let split_res_1 = gov
        .split_neuron(
            &nonexisting_neuron_id,
            &from,
            &Split {
                amount_e8s: 1_000_000,
            },
        )
        .now_or_never()
        .unwrap();
    assert_matches!(
        split_res_1,
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == NotFound as i32 && msg.to_lowercase().contains("neuron not found"));

    // 2. Attempt to split a neuron as someone who is not the neuron's controller
    let unauthorized_caller = *TEST_NEURON_2_OWNER_PRINCIPAL;
    let split_res_2 = gov
        .split_neuron(
            &id,
            &unauthorized_caller,
            &Split {
                amount_e8s: 1_000_000,
            },
        )
        .now_or_never()
        .unwrap();
    assert_matches!(
        split_res_2,
        Err(GovernanceError{error_type: code, error_message: _msg})
            if code == NotAuthorized as i32);

    // 3. Attempt to split an amount that leaves the parent with less than min_stake
    let split_res_3 = gov
        .split_neuron(
            &id,
            &from,
            &Split {
                amount_e8s: 1_000_000_000 - min_neuron_stake + 1,
            },
        )
        .now_or_never()
        .unwrap();
    assert_matches!(
        split_res_3,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == InsufficientFunds as i32 && msg.to_lowercase().contains("the parent has stake"));

    // 4. Attempt to split an amount that results in a child neuron with less than
    // min_stake
    let split_res_4 = gov
        .split_neuron(
            &id,
            &from,
            &Split {
                amount_e8s: min_neuron_stake - 1 + transaction_fee,
            },
        )
        .now_or_never()
        .unwrap();
    assert_matches!(
       split_res_4,
       Err(GovernanceError{error_type: code, error_message: msg})
           if code == InsufficientFunds as i32 && msg.to_lowercase().contains("at the minimum, one needs the minimum neuron stake"));

    // Parent neuron did not change
    assert_eq!(*gov.get_neuron(&id).unwrap(), neuron_before);
    // There is still only one neuron
    assert_eq!(gov.proto.neurons.len(), 1);
    //  There is still only one ledger account.
    driver.assert_num_neuron_accounts_exist(1);
}

#[test]
fn test_neuron_split() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds = MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;

    let (driver, mut gov, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    let neuron = gov.proto.neurons.get_mut(&id.id).unwrap();
    let transaction_fee = gov.proto.economics.as_ref().unwrap().transaction_fee_e8s;

    assert_eq!(
        neuron.get_neuron_info(driver.now()).state(),
        NeuronState::NotDissolving
    );

    let child_nid = gov
        .split_neuron(
            &id,
            &from,
            &Split {
                amount_e8s: 100_000_000 + transaction_fee,
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    // We should now have 2 neurons.
    assert_eq!(gov.proto.neurons.len(), 2);
    // And we should have two ledger accounts.
    driver.assert_num_neuron_accounts_exist(2);

    let child_neuron = gov
        .get_neuron(&child_nid)
        .expect("The child neuron is missing");
    let parent_neuron = gov.get_neuron(&id).expect("The parent neuron is missing");
    let child_subaccount = child_neuron.account.clone();

    assert_eq!(
        parent_neuron.cached_neuron_stake_e8s,
        neuron_stake_e8s - 100_000_000 - transaction_fee
    );

    assert_eq!(
        child_neuron,
        &Neuron {
            id: Some(child_nid.clone()),
            account: child_subaccount,
            controller: parent_neuron.controller,
            cached_neuron_stake_e8s: 100_000_000,
            created_timestamp_seconds: parent_neuron.created_timestamp_seconds,
            aging_since_timestamp_seconds: parent_neuron.aging_since_timestamp_seconds,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                parent_neuron.dissolve_delay_seconds(driver.get_fake_env().now())
            )),
            kyc_verified: true,
            ..Default::default()
        }
    );

    let mut neuron_ids = gov.get_neuron_ids_by_principal(&from);
    neuron_ids.sort_unstable();
    let mut expected_neuron_ids = vec![id.id, child_nid.id];
    expected_neuron_ids.sort_unstable();
    assert_eq!(neuron_ids, expected_neuron_ids);
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
    fn icp(amount: u64) -> u64 {
        amount * 100_000_000
    }

    let mut nns = NNSBuilder::new()
        .set_economics(NetworkEconomics::with_default_values())
        .add_account_for(principal(1), icp(1))
        .add_account_for(principal(11), icp(100)) // in order to propose
        .add_neuron(
            NeuronBuilder::new(1, icp(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS)
                .set_maturity(icp(123))
                .set_aging_since_timestamp(0)
                .set_creation_timestamp(10)
                .set_kyc_verified(true)
                .set_not_for_profit(true),
        )
        .add_neuron(
            NeuronBuilder::new(2, icp(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp(456))
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .set_kyc_verified(false)
                .set_not_for_profit(false),
        )
        .add_neuron(
            NeuronBuilder::new(3, icp(4_560), principal(2))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp(456))
                .set_aging_since_timestamp(10),
        )
        .add_neuron(
            NeuronBuilder::new(4, icp(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp(456))
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .set_kyc_verified(true)
                .set_not_for_profit(false),
        )
        .add_neuron(
            NeuronBuilder::new(5, icp(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp(456))
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .set_kyc_verified(true)
                .set_not_for_profit(true)
                .set_joined_community_fund(10),
        )
        .add_neuron(
            NeuronBuilder::new(6, icp(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS)
                .set_maturity(icp(123))
                .set_aging_since_timestamp(0)
                .set_creation_timestamp(10)
                .do_not_create_subaccount()
                .set_kyc_verified(true)
                .set_not_for_profit(true),
        )
        .add_neuron(
            NeuronBuilder::new(7, icp(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp(456))
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .do_not_create_subaccount()
                .set_kyc_verified(true)
                .set_not_for_profit(true),
        )
        .add_neuron(
            NeuronBuilder::new(8, icp(1), principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp(456))
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .set_kyc_verified(true)
                .set_not_for_profit(true),
        )
        .add_neuron(
            NeuronBuilder::new(9, 1, principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp(456))
                .set_aging_since_timestamp(10)
                .set_creation_timestamp(20)
                .set_kyc_verified(true)
                .set_not_for_profit(true),
        )
        .add_neuron(
            NeuronBuilder::new(10, icp(4_560), principal(11))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp(456))
                .set_aging_since_timestamp(10),
        )
        .add_neuron(
            NeuronBuilder::new(11, icp(4_560), principal(11))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp(456))
                .set_aging_since_timestamp(50),
        )
        .add_neuron(
            NeuronBuilder::new(12, icp(4_560), principal(11))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp(456))
                .set_aging_since_timestamp(10),
        )
        .add_neuron(
            NeuronBuilder::new(13, icp(4_560), principal(11))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_maturity(icp(456))
                .set_aging_since_timestamp(10),
        )
        .add_neuron(
            NeuronBuilder::new(14, icp(3_456), principal(123))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4),
        )
        .add_neuron(
            NeuronBuilder::new(15, icp(3_456), principal(123))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4),
        )
        .add_neuron(
            NeuronBuilder::new(16, icp(1_234), principal(123))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_managers(Followees {
                    followees: vec![NeuronId { id: 14 }],
                }),
        )
        .add_neuron(
            NeuronBuilder::new(17, icp(2_345), principal(123))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_managers(Followees {
                    followees: vec![NeuronId { id: 15 }],
                }),
        )
        .add_neuron(
            NeuronBuilder::new(18, icp(3_456), principal(123))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4),
        )
        .create();

    // 1. Source id and target id cannot be the same
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 1 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == InvalidCommand as i32 &&
           msg == "Cannot merge a neuron into itself");

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

    // 4. Source neuron's kyc_verified field must match target
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 2 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "Source neuron's kyc_verified field does not match target");

    // 5. Source neuron's not_for_profit field must match target
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 4 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "Source neuron's not_for_profit field does not match target");

    // 6. Cannot merge neurons that have been dedicated to the community fund
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 5 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "Cannot merge neurons that have been dedicated to the community fund");

    // 7. Subaccount of source neuron to be merged must be present
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 7 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == External as i32 &&
           msg == "Source account doesn't exist");

    // 8. Subaccount of target neuron to be merged must be present
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 6 },
            &principal(1),
            &NeuronId { id: 8 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == External as i32 &&
           msg == "Target account doesn't exist");

    // 9. Neither neuron can be the proposer of an open proposal
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

    // 10. Neither neuron can be the subject of a MergeNeuron proposal
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

    // 11. Source neuron must exist
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 6 },
            &principal(1),
            &NeuronId { id: 100 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == NotFound as i32 &&
           msg == "Neuron not found: NeuronId { id: 100 }");

    // 12. Target neuron must exist
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 100 },
            &principal(1),
            &NeuronId { id: 8 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == NotFound as i32 &&
           msg == "Neuron not found: NeuronId { id: 100 }");

    // 13. Stake of the source neuron of a merge must be greater than the fee
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 1 },
            &principal(1),
            &NeuronId { id: 9 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == InvalidCommand as i32 &&
           msg == "Stake of the source neuron of a merge must be greater than the fee");

    // 14. Neurons with different ManageNeuron lists cannot be merged
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 16 },
            &principal(123),
            &NeuronId { id: 17 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "ManageNeuron following of source and target does not match");

    // 15. Neurons with resp. without ManageNeuron cannot be merged
    assert_matches!(
        nns.merge_neurons(
            &NeuronId { id: 16 },
            &principal(123),
            &NeuronId { id: 18 },
        ),
        Err(GovernanceError{error_type: code, error_message: msg})
        if code == PreconditionFailed as i32 &&
           msg == "ManageNeuron following of source and target does not match");
}

proptest! {

#[allow(clippy::vec_init_then_push)]
#[test]
fn test_merge_neurons(
    n1_stake in 100_000_000u64..500_000_000_000,
    n1_maturity in 0u64..500_000_000_000,
    n1_fees in 0u64..99_000_000,
    n1_dissolve in 0u64..MAX_DISSOLVE_DELAY_SECONDS,
    n1_age in 0u64..315_360_000,
    n2_stake in 100_000_000u64..500_000_000_000,
    n2_maturity in 0u64..500_000_000_000,
    n2_fees in 0u64..99_000_000,
    n2_dissolve in 0u64..MAX_DISSOLVE_DELAY_SECONDS,
    n2_age in 0u64..315_360_000
) {
    // Start the NNS 20 years after genesis, to give lots of time for aging.
    let epoch = DEFAULT_TEST_START_TIMESTAMP_SECONDS + (20 * ONE_YEAR_SECONDS);

    let mut nns = NNSBuilder::new()
        .set_start_time(epoch)
        .set_economics(NetworkEconomics::with_default_values())
        .with_supply(0) // causes minting account to be created
        .add_account_for(principal(1), 0)
        // the source
        .add_neuron(
            NeuronBuilder::new(1, n1_stake, principal(1))
                .set_dissolve_delay(n1_dissolve)
                .set_maturity(n1_maturity)
                .set_neuron_fees(n1_fees)
                .set_aging_since_timestamp(epoch.saturating_sub(n1_age)),
        )
        // the target
        .add_neuron(
            NeuronBuilder::new(2, n2_stake, principal(1))
                .set_dissolve_delay(n2_dissolve)
                .set_maturity(n2_maturity)
                .set_neuron_fees(n2_fees)
                .set_aging_since_timestamp(epoch.saturating_sub(n2_age)),
        )
        .create();

    // advance by a year, just to spice things up
    nns.advance_time_by(ONE_YEAR_SECONDS);

    nns.governance
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

    #[cfg(feature = "test")]
    let fee = nns
        .governance
        .proto
        .economics
        .as_ref()
        .unwrap()
        .transaction_fee_e8s;

    #[cfg(feature = "test")]
    prop_assert_changes!(
        nns,
        Changed::Changed(vec![
            NNSStateChange::Now(U64Change(epoch, epoch + ONE_YEAR_SECONDS)),
            NNSStateChange::Accounts({
                let account1 = MapChange::Changed(
                    nns.get_neuron_account_id(2),
                    U64Change(n2_stake, n2_stake + (n1_stake - n1_fees) - fee),
                );
                let account2 = MapChange::Changed(
                    nns.get_neuron_account_id(1),
                    U64Change(n1_stake, if n1_fees > fee { 0 } else { n1_fees }),
                );
                let minting =
                    MapChange::Changed(governance_minting_account(), U64Change(0, n1_fees));
                let mut changes = Vec::new();
                changes.push(account1);
                if n1_fees > fee {
                    changes.push(minting);
                }
                changes.push(account2);
                changes
            }),
            NNSStateChange::GovernanceProto(vec![GovernanceChange::Neurons(vec![
                MapChange::Changed(1, {
                    let stake = NeuronChange::CachedNeuronStakeE8S(U64Change(n1_stake, 0));
                    let fees = NeuronChange::NeuronFeesE8S(U64Change(n1_fees, 0));
                    let aging = NeuronChange::AgingSinceTimestampSeconds(U64Change(
                        epoch.saturating_sub(n1_age),
                        nns.now(),
                    ));
                    let maturity = NeuronChange::MaturityE8SEquivalent(U64Change(n1_maturity, 0));
                    let mut changes = Vec::new();
                    changes.push(stake);
                    if n1_fees > 0 {
                        changes.push(fees);
                    }
                    changes.push(aging);
                    if n1_maturity > 0 {
                        changes.push(maturity);
                    }
                    changes
                }),
                MapChange::Changed(2, {
                    let stake = NeuronChange::CachedNeuronStakeE8S(U64Change(
                        n2_stake,
                        n2_stake + (n1_stake - n1_fees) - fee,
                    ));
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
                        let (_new_stake, new_age_seconds) =
                            ic_nns_governance::governance::combine_aged_stakes(
                                n2_stake,
                                n2_age_seconds,
                                (n1_stake - n1_fees) - fee,
                                n1_age_seconds,
                            );
                        nns.now().saturating_sub(new_age_seconds)
                    };
                    let aging =
                        NeuronChange::AgingSinceTimestampSeconds(U64Change(old_age, new_age));
                    let maturity = NeuronChange::MaturityE8SEquivalent(U64Change(
                        n2_maturity,
                        n2_maturity + n1_maturity,
                    ));
                    let dissolve = NeuronChange::DissolveState(OptionChange::BothSome(
                        DissolveStateChange::BothDissolveDelaySeconds(U64Change(
                            n2_dissolve,
                            n1_dissolve,
                        )),
                    ));
                    let mut changes = Vec::new();
                    changes.push(stake);
                    if old_age != new_age {
                        changes.push(aging);
                    }
                    if n1_maturity > 0 {
                        changes.push(maturity);
                    }
                    if n1_dissolve > n2_dissolve {
                        changes.push(dissolve);
                    }
                    changes
                })
            ])]),
        ])
    );
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
                .set_managers(Followees {
                    followees: vec![NeuronId { id: 1 }],
                }),
        )
        // the target
        .add_neuron(
            NeuronBuilder::new(3, n3_stake, principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS * 4)
                .set_aging_since_timestamp(DEFAULT_TEST_START_TIMESTAMP_SECONDS)
                .set_managers(Followees {
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
        .proto
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
                    U64Change(n3_stake, n3_stake + n2_stake - fee),
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
                        n3_stake + n2_stake - fee,
                    )),],
                ),
            ])]),
        ])
    );
}

/// Checks that:
/// * An attempt to spawn a neuron does nothing if the parent has too little
///   maturity.
/// * when the parent neuron has sufficient maturity, a new neuron may be spawn.
#[test]
fn test_neuron_spawn() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds = MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;

    let (mut driver, mut gov, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    let neuron = gov.get_neuron_mut(&id).expect("Neuron did not exist");

    assert_eq!(
        neuron.get_neuron_info(driver.now()).state(),
        NeuronState::NotDissolving
    );

    // Starts with too little maturity
    neuron.maturity_e8s_equivalent = 187;
    assert!(
        neuron.maturity_e8s_equivalent
            < NetworkEconomics::with_default_values().neuron_minimum_stake_e8s
    );
    let child_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;

    // An attempt to spawn a neuron should simply return an error and
    // change nothing.
    let neuron_before = neuron.clone();
    let spawn_res = gov
        .spawn_neuron(
            &id,
            &from,
            &Spawn {
                new_controller: Some(child_controller),
                nonce: None,
                percentage_to_spawn: None,
            },
        )
        .now_or_never()
        .unwrap();
    assert_matches!(
        spawn_res,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == InsufficientFunds as i32 && msg.to_lowercase().contains("maturity"));
    assert_eq!(*gov.get_neuron(&id).unwrap(), neuron_before);

    // Artificially set the neuron's maturity to sufficient value
    let neuron = gov.get_neuron_mut(&id).expect("Neuron did not exist");
    let parent_maturity_e8s_equivalent: u64 = 123_456_789;
    assert!(
        parent_maturity_e8s_equivalent
            > NetworkEconomics::with_default_values().neuron_minimum_stake_e8s
    );
    neuron.maturity_e8s_equivalent = parent_maturity_e8s_equivalent;

    // Advance the time so that we can check that the spawned neuron has the age
    // and the right creation timestamp
    driver.advance_time_by(1);

    let child_nid = gov
        .spawn_neuron(
            &id,
            &from,
            &Spawn {
                new_controller: Some(child_controller),
                nonce: None,
                percentage_to_spawn: None,
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    // We should now have 2 neurons.
    assert_eq!(gov.proto.neurons.len(), 2);
    // And we should have two ledger accounts.
    driver.assert_num_neuron_accounts_exist(2);

    let child_neuron = gov
        .get_neuron(&child_nid)
        .expect("The child neuron is missing");
    let parent_neuron = gov.get_neuron(&id).expect("The parent neuron is missing");
    let child_subaccount = child_neuron.account.clone();

    // Maturity on the parent neuron should be reset.
    assert_eq!(parent_neuron.maturity_e8s_equivalent, 0);

    assert_eq!(
        child_neuron,
        &Neuron {
            id: Some(child_nid.clone()),
            account: child_subaccount,
            controller: Some(child_controller),
            cached_neuron_stake_e8s: parent_maturity_e8s_equivalent,
            created_timestamp_seconds: driver.now(),
            aging_since_timestamp_seconds: driver.now(),
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                gov.proto
                    .economics
                    .as_ref()
                    .unwrap()
                    .neuron_spawn_dissolve_delay_seconds
            )),
            kyc_verified: true,
            ..Default::default()
        }
    );
}

#[test]
fn test_neuron_spawn_with_subaccount() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds = MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;

    let (mut driver, mut gov, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    let neuron = gov.get_neuron_mut(&id).expect("Neuron did not exist");

    assert_eq!(
        neuron.get_neuron_info(driver.now()).state(),
        NeuronState::NotDissolving
    );

    // Starts with too little maturity
    neuron.maturity_e8s_equivalent = 187;
    assert!(
        neuron.maturity_e8s_equivalent
            < NetworkEconomics::with_default_values().neuron_minimum_stake_e8s
    );
    let child_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;

    // An attempt to spawn a neuron should simply return an error and
    // change nothing.
    let neuron_before = neuron.clone();
    let spawn_res = gov
        .spawn_neuron(
            &id,
            &from,
            &Spawn {
                new_controller: Some(child_controller),
                nonce: None,
                percentage_to_spawn: None,
            },
        )
        .now_or_never()
        .unwrap();
    assert_matches!(
        spawn_res,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == InsufficientFunds as i32 && msg.to_lowercase().contains("maturity"));
    assert_eq!(*gov.get_neuron(&id).unwrap(), neuron_before);

    // Artificially set the neuron's maturity to sufficient value
    let neuron = gov.get_neuron_mut(&id).expect("Neuron did not exist");
    let parent_maturity_e8s_equivalent: u64 = 123_456_789;
    assert!(
        parent_maturity_e8s_equivalent
            > NetworkEconomics::with_default_values().neuron_minimum_stake_e8s
    );
    neuron.maturity_e8s_equivalent = parent_maturity_e8s_equivalent;

    // Advance the time so that we can check that the spawned neuron has the age
    // and the right creation timestamp
    driver.advance_time_by(1);

    // Nonce used for spawn (given as input).
    let nonce_spawn = driver.random_u64();

    let child_nid = gov
        .spawn_neuron(
            &id,
            &from,
            &Spawn {
                new_controller: Some(child_controller),
                nonce: Some(nonce_spawn),
                percentage_to_spawn: None,
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    // We should now have 2 neurons.
    assert_eq!(gov.proto.neurons.len(), 2);
    // And we should have two ledger accounts.
    driver.assert_num_neuron_accounts_exist(2);

    let child_neuron = gov
        .get_neuron(&child_nid)
        .expect("The child neuron is missing");
    let parent_neuron = gov.get_neuron(&id).expect("The parent neuron is missing");
    let child_subaccount = child_neuron.account.clone();

    // Verify that the sub-account was created according to spawn input.
    let expected_subaccount = {
        let mut state = Sha256::new();
        state.write(&[0x0c]);
        state.write(b"neuron-stake");
        state.write(child_controller.as_slice());
        state.write(&nonce_spawn.to_be_bytes());
        state.finish()
    };

    assert_eq!(
        child_subaccount, expected_subaccount,
        "Sub-account doesn't match expected sub-account (with nonce)."
    );

    // Maturity on the parent neuron should be reset.
    assert_eq!(parent_neuron.maturity_e8s_equivalent, 0);

    assert_eq!(
        child_neuron,
        &Neuron {
            id: Some(child_nid.clone()),
            account: child_subaccount,
            controller: Some(child_controller),
            cached_neuron_stake_e8s: parent_maturity_e8s_equivalent,
            created_timestamp_seconds: driver.now(),
            aging_since_timestamp_seconds: driver.now(),
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                gov.proto
                    .economics
                    .as_ref()
                    .unwrap()
                    .neuron_spawn_dissolve_delay_seconds
            )),
            kyc_verified: true,
            ..Default::default()
        }
    );
}

/// Checks that:
/// * Specifying a percentage_to_spawn different from 100 lead to the proper fractional maturity
/// to be spawned.
#[test]
fn test_neuron_spawn_partial_exact() {
    assert_neuron_spawn_partial(240_000_000, 60, 144_000_000, 96_000_000);
}

#[test]
fn test_neuron_spawn_partial_rounding() {
    assert_neuron_spawn_partial(240_000_013, 51, 122_400_006, 117_600_007);
}

fn assert_neuron_spawn_partial(
    parent_maturity: u64,
    percentage: u32,
    expected_spawned_maturity: u64,
    expected_remaining_maturity: u64,
) {
    assert_eq!(
        parent_maturity,
        expected_spawned_maturity + expected_remaining_maturity,
        "Invalid test, spawned+remaining maturity should match parent maturity."
    );

    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds = MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;

    let (mut driver, mut gov, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    let neuron = gov.get_neuron_mut(&id).expect("Neuron did not exist");
    assert_eq!(
        neuron.get_neuron_info(driver.now()).state(),
        NeuronState::NotDissolving
    );

    let child_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;

    // An attempt to spawn a neuron should simply return an error and
    // change nothing.
    let neuron_before = neuron.clone();
    assert_eq!(*gov.get_neuron(&id).unwrap(), neuron_before);

    // Artificially set the neuron's maturity to sufficient value
    let neuron = gov.get_neuron_mut(&id).expect("Neuron did not exist");
    let parent_maturity_e8s_equivalent: u64 = parent_maturity;
    assert!(
        parent_maturity_e8s_equivalent
            > NetworkEconomics::with_default_values().neuron_minimum_stake_e8s
    );
    neuron.maturity_e8s_equivalent = parent_maturity_e8s_equivalent;

    // Advance the time so that we can check that the spawned neuron has the age
    // and the right creation timestamp
    driver.advance_time_by(1);

    // Spawn 60 percent of maturity.
    let child_nid = gov
        .spawn_neuron(
            &id,
            &from,
            &Spawn {
                new_controller: Some(child_controller),
                nonce: None,
                percentage_to_spawn: Some(percentage),
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    // We should now have 2 neurons.
    assert_eq!(gov.proto.neurons.len(), 2);
    // And we should have two ledger accounts.
    driver.assert_num_neuron_accounts_exist(2);

    let child_neuron = gov
        .get_neuron(&child_nid)
        .expect("The child neuron is missing");
    let parent_neuron = gov.get_neuron(&id).expect("The parent neuron is missing");
    let child_subaccount = child_neuron.account.clone();

    // Some maturity should be remaining on the parent neuron.
    assert_eq!(
        parent_neuron.maturity_e8s_equivalent,
        expected_remaining_maturity
    );

    assert_eq!(
        child_neuron,
        &Neuron {
            id: Some(child_nid.clone()),
            account: child_subaccount,
            controller: Some(child_controller),
            cached_neuron_stake_e8s: expected_spawned_maturity,
            created_timestamp_seconds: driver.now(),
            aging_since_timestamp_seconds: driver.now(),
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                gov.proto
                    .economics
                    .as_ref()
                    .unwrap()
                    .neuron_spawn_dissolve_delay_seconds
            )),
            kyc_verified: true,
            ..Default::default()
        }
    );
}

/// Assert that a neuron cannot be created with a non self-authenticating
/// controller `PrincipalId` (via a call to `spawn_neuron`).
#[test]
fn test_neuron_with_non_self_authenticating_controller_cannot_be_spawned() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds = MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;

    let (_, mut gov, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    let neuron = gov.get_neuron_mut(&id).expect("Neuron did not exist");
    neuron.maturity_e8s_equivalent = 123_456_789;

    let non_self_authenticating_principal_id = PrincipalId::new_user_test_id(144);

    let result: Result<NeuronId, GovernanceError> = gov
        .spawn_neuron(
            &id,
            &from,
            &Spawn {
                new_controller: Some(non_self_authenticating_principal_id),
                nonce: None,
                percentage_to_spawn: None,
            },
        )
        .now_or_never()
        .unwrap();

    assert_matches!(
        result,
        Err(GovernanceError{ error_type: code, error_message: msg })
            if code == PreconditionFailed as i32 && msg.contains("must be self-authenticating"));
}

#[test]
fn test_disburse_to_neuron() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds = MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS;
    let neuron_stake_e8s = 10 * 100_000_000; // 10 ICPT

    let (mut driver, mut gov, id, _to_subaccount) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    let parent_neuron = gov.proto.neurons.get_mut(&id.id).unwrap();
    let transaction_fee = gov.proto.economics.as_ref().unwrap().transaction_fee_e8s;

    // Now Set the neuron to start dissolving
    parent_neuron
        .configure(
            &from,
            driver.now(),
            &Configure {
                operation: Some(Operation::StartDissolving(StartDissolving {})),
            },
        )
        .unwrap();

    // Advance the time in the env
    driver.advance_time_by(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS + 1);

    // The neuron state should now be "Dissolved", meaning we can
    // now disburse the neuron.
    assert_eq!(
        parent_neuron.get_neuron_info(driver.now()).state(),
        NeuronState::Dissolved
    );

    let child_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;

    let child_nid = gov
        .disburse_to_neuron(
            &id,
            &from,
            &DisburseToNeuron {
                new_controller: Some(child_controller),
                amount_e8s: 2 * 100_000_000 + transaction_fee, // 2 ICPT + transaction_fee
                dissolve_delay_seconds: 24 * 60 * 60,          // 1 day.
                kyc_verified: true,
                nonce,
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    // We should now have 2 neurons.
    assert_eq!(gov.proto.neurons.len(), 2);
    // And we should have two ledger accounts.
    driver.assert_num_neuron_accounts_exist(2);

    let child_neuron = gov
        .get_neuron(&child_nid)
        .expect("The child neuron is missing");
    let parent_neuron = gov.get_neuron(&id).expect("The parent neuron is missing");
    let child_subaccount = child_neuron.account.clone();

    assert_eq!(
        parent_neuron.cached_neuron_stake_e8s,
        neuron_stake_e8s - 2 * 100_000_000 - transaction_fee
    );

    assert_eq!(
        child_neuron,
        &Neuron {
            id: Some(child_nid.clone()),
            account: child_subaccount,
            controller: Some(child_controller),
            cached_neuron_stake_e8s: 2 * 100_000_000,
            created_timestamp_seconds: driver.now(),
            aging_since_timestamp_seconds: driver.now(),
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(24 * 60 * 60)),
            kyc_verified: true,
            ..Default::default()
        }
    );

    let to_subaccount = {
        let mut state = Sha256::new();
        state.write(&[0x0c]);
        state.write(b"neuron-split");
        state.write(child_controller.as_slice());
        state.write(&nonce.to_be_bytes());
        state.finish()
    };

    assert_eq!(child_neuron.account, to_subaccount);
}

fn governance_with_neurons(neurons: &[Neuron]) -> (fake::FakeDriver, Governance) {
    let accounts: Vec<fake::FakeAccount> = neurons
        .iter()
        .map(|n| fake::FakeAccount {
            id: AccountIdentifier::new(
                GOVERNANCE_CANISTER_ID.get(),
                Some(Subaccount(n.account.as_slice().try_into().unwrap())),
            ),
            amount_e8s: n.cached_neuron_stake_e8s,
        })
        .collect();
    let driver = fake::FakeDriver::default()
        .at(56)
        .with_ledger_accounts(accounts)
        .with_supply(Tokens::from_tokens(100_000_000_000).unwrap());

    let mut proto = empty_fixture();
    proto.neurons.extend(
        neurons
            .iter()
            .map(|n| (n.id.as_ref().unwrap().id, n.clone())),
    );

    let gov = Governance::new(proto, driver.get_fake_env(), driver.get_fake_ledger());
    assert_eq!(gov.proto.neurons.len(), 3);
    (driver, gov)
}

#[test]
fn test_not_for_profit_neurons() {
    let p: PathBuf = ["tests", "neurons.csv"].iter().collect();
    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let normal_neuron = init_neurons[&42].clone();

    // Add the normal neuron as a followee of the not-for-profit neuron.
    init_neurons.get_mut(&25).unwrap().followees.insert(
        Topic::NeuronManagement as i32,
        Followees {
            followees: vec![normal_neuron.id.as_ref().unwrap().clone()],
        },
    );

    let (_, mut gov) =
        governance_with_neurons(&init_neurons.values().cloned().collect::<Vec<Neuron>>());

    let not_for_profit_neuron = init_neurons[&25].clone();

    // A normal neuron can't issue a manage neuron proposal to disburse,
    // split or disburse-to-neuron.
    let result = gov.make_proposal(
        normal_neuron.id.as_ref().unwrap(),
        normal_neuron.controller.as_ref().unwrap(),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    normal_neuron.id.as_ref().unwrap().clone(),
                )),
                id: None,
                command: Some(manage_neuron::Command::Disburse(manage_neuron::Disburse {
                    amount: None,
                    to_account: None,
                })),
            }))),
            summary: "".to_string(),
            url: "".to_string(),
        },
    );
    assert!(result.is_err());
    assert_eq!(result.err().unwrap().error_type(), ErrorType::NotAuthorized);

    // A not for profit neuron, on the other hand, can.
    // The followee of the managed neuron must make the proposal, in this case.
    let result = gov.make_proposal(
        normal_neuron.id.as_ref().unwrap(),
        normal_neuron.controller.as_ref().unwrap(),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    not_for_profit_neuron.id.as_ref().unwrap().clone(),
                )),
                id: None,
                command: Some(manage_neuron::Command::Disburse(manage_neuron::Disburse {
                    amount: None,
                    to_account: None,
                })),
            }))),
            summary: "".to_string(),
            url: "".to_string(),
        },
    );

    result.expect("Failed.");
}

#[test]
fn test_hot_keys_cant_change_followees_of_manage_neuron_topic() {
    let p: PathBuf = ["tests", "neurons.csv"].iter().collect();
    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let second_neuron = init_neurons[&42].clone();

    // Add the controller of the second neuron as a hot key of the first one.
    init_neurons
        .get_mut(&25)
        .unwrap()
        .hot_keys
        .push(*second_neuron.controller.as_ref().unwrap());

    let (_, mut gov) =
        governance_with_neurons(&init_neurons.values().cloned().collect::<Vec<Neuron>>());

    let first_neuron = init_neurons[&25].clone();

    // The controller of the second neuron should now be able
    // change the followees of most topics.
    let result = gov
        .manage_neuron(
            second_neuron.controller.as_ref().unwrap(),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    first_neuron.id.as_ref().unwrap().clone(),
                )),
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::NetworkEconomics as i32,
                    followees: vec![second_neuron.id.as_ref().unwrap().clone()],
                })),
            },
        )
        .now_or_never()
        .unwrap();

    assert!(result.is_ok());

    // .. but it shouldn't be able to change the followees of the manage neuron
    // topic.
    let result = gov
        .manage_neuron(
            second_neuron.controller.as_ref().unwrap(),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    first_neuron.id.as_ref().unwrap().clone(),
                )),
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::NeuronManagement as i32,
                    followees: vec![second_neuron.id.as_ref().unwrap().clone()],
                })),
            },
        )
        .now_or_never()
        .unwrap();

    assert!(result.is_err());
    assert_eq!(
        result.clone().err().unwrap().error_type(),
        ErrorType::NotAuthorized
    );
    assert_eq!(
        result.err().unwrap().error_message,
        "Caller is not authorized to manage following of neuron for the ManageNeuron topic."
    );
}

#[test]
fn test_add_and_remove_hot_key() {
    let p: PathBuf = ["tests", "neurons.csv"].iter().collect();
    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let (_, mut gov) =
        governance_with_neurons(&init_neurons.values().cloned().collect::<Vec<Neuron>>());

    let neuron = init_neurons[&25].clone();
    let new_controller = init_neurons[&42].controller.unwrap();

    assert!(!gov
        .principal_to_neuron_ids_index
        .get(&new_controller)
        .unwrap()
        .contains(&neuron.id.as_ref().unwrap().id));
    // Add a hot key to the neuron and make sure that gets reflected in the
    // principal to neuron ids index.
    let result = gov
        .manage_neuron(
            neuron.controller.as_ref().unwrap(),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    neuron.id.as_ref().unwrap().clone(),
                )),
                command: Some(manage_neuron::Command::Configure(
                    manage_neuron::Configure {
                        operation: Some(manage_neuron::configure::Operation::AddHotKey(
                            manage_neuron::AddHotKey {
                                new_hot_key: Some(new_controller),
                            },
                        )),
                    },
                )),
            },
        )
        .now_or_never()
        .unwrap();

    assert!(result.is_ok());
    assert!(gov
        .principal_to_neuron_ids_index
        .get(&new_controller)
        .unwrap()
        .contains(&neuron.id.as_ref().unwrap().id));

    // Remove a hot key from that neuron and make sure that gets reflected in
    // the principal to neuron ids index.
    let result = gov
        .manage_neuron(
            neuron.controller.as_ref().unwrap(),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    neuron.id.as_ref().unwrap().clone(),
                )),
                command: Some(manage_neuron::Command::Configure(
                    manage_neuron::Configure {
                        operation: Some(manage_neuron::configure::Operation::RemoveHotKey(
                            manage_neuron::RemoveHotKey {
                                hot_key_to_remove: Some(new_controller),
                            },
                        )),
                    },
                )),
            },
        )
        .now_or_never()
        .unwrap();

    assert!(result.is_ok());
    assert!(!gov
        .principal_to_neuron_ids_index
        .get(&new_controller)
        .unwrap()
        .contains(&neuron.id.as_ref().unwrap().id));
}

#[test]
fn test_manage_and_reward_node_providers() {
    let p: PathBuf = ["tests", "neurons.csv"].iter().collect();
    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let voter_pid = *init_neurons[&42].controller.as_ref().unwrap();

    let voter_neuron = init_neurons[&42].id.as_ref().unwrap().clone();
    init_neurons.get_mut(&42).unwrap().dissolve_state = Some(DissolveState::DissolveDelaySeconds(
        MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
    ));
    let np_pid = PrincipalId::new_self_authenticating(&[14]);

    let (driver, mut gov) =
        governance_with_neurons(&init_neurons.values().cloned().collect::<Vec<Neuron>>());

    println!(
        "Ledger {:?}\n",
        driver.state.as_ref().try_lock().unwrap().accounts,
    );

    // Submit a proposal to reward a node provider which doesn't exist.
    // The submitter neuron votes automatically and that should be enough
    // to have it accepted.
    let pid = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron.clone())),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("NP reward proposal".to_string()),
                    summary: "Reward this NP...".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::RewardNodeProvider(RewardNodeProvider {
                        node_provider: Some(NodeProvider {
                            id: Some(np_pid),
                            reward_account: None,
                        }),
                        amount_e8s: 10 * 100_000_000,
                        reward_mode: Some(RewardMode::RewardToAccount(RewardToAccount {
                            to_account: None,
                        })),
                    })),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // The proposal should have failed as the node provider doesn't exist.
    let info = gov
        .get_proposal_info(&PrincipalId::new_anonymous(), pid)
        .unwrap();
    assert_eq!(info.status(), ProposalStatus::Failed, "info: {:?}", info);
    assert_eq!(
        info.failure_reason.as_ref().unwrap().error_type,
        ErrorType::NotFound as i32,
        "info: {:?}",
        info
    );

    // Now make a proposal to add the node provider.
    let pid = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron.clone())),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("NP reward proposal".to_string()),
                    summary: "Just want to add this NP.".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::AddOrRemoveNodeProvider(
                        AddOrRemoveNodeProvider {
                            change: Some(Change::ToAdd(NodeProvider {
                                id: Some(np_pid),
                                reward_account: None,
                            })),
                        },
                    )),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // The proposal should have been executed
    assert_eq!(
        gov.get_proposal_data(pid).unwrap().status(),
        ProposalStatus::Executed
    );

    assert_eq!(gov.get_node_providers().len(), 1);

    assert_eq!(
        gov.get_node_providers()[0],
        NodeProvider {
            id: Some(np_pid),
            reward_account: None
        }
    );

    // Adding the same node provider again should fail.
    let pid = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron.clone())),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("NP reward proposal".to_string()),
                    summary: "Just want to add this NP.".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::AddOrRemoveNodeProvider(
                        AddOrRemoveNodeProvider {
                            change: Some(Change::ToAdd(NodeProvider {
                                id: Some(np_pid),
                                reward_account: None,
                            })),
                        },
                    )),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    assert_eq!(
        gov.get_proposal_data(pid).unwrap().status(),
        ProposalStatus::Failed
    );

    // Rewarding the node provider to the default account should now work.
    let pid = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron.clone())),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("NP reward proposal".to_string()),
                    summary: "Reward this NP...".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::RewardNodeProvider(RewardNodeProvider {
                        node_provider: Some(NodeProvider {
                            id: Some(np_pid),
                            reward_account: None,
                        }),
                        amount_e8s: 10 * 100_000_000,
                        reward_mode: Some(RewardMode::RewardToAccount(RewardToAccount {
                            to_account: None,
                        })),
                    })),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // The proposal should have been executed
    assert_eq!(
        gov.get_proposal_data(pid).unwrap().status(),
        ProposalStatus::Executed
    );

    driver.assert_account_contains(&AccountIdentifier::new(np_pid, None), 10 * 100_000_000);

    let to_subaccount = Subaccount({
        let mut sha = Sha256::new();
        sha.write(b"my_account");
        sha.finish()
    });

    // Rewarding the node provider to a specified account should also work.
    let pid = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron.clone())),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("NP reward proposal".to_string()),
                    summary: "Reward this NP...".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::RewardNodeProvider(RewardNodeProvider {
                        node_provider: Some(NodeProvider {
                            id: Some(np_pid),
                            reward_account: None,
                        }),
                        amount_e8s: 10 * 100_000_000,
                        reward_mode: Some(RewardMode::RewardToAccount(RewardToAccount {
                            to_account: Some(
                                AccountIdentifier::new(np_pid, Some(to_subaccount)).into(),
                            ),
                        })),
                    })),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // The proposal should have been executed
    assert_eq!(
        gov.get_proposal_data(pid).unwrap().status(),
        ProposalStatus::Executed
    );

    driver.assert_account_contains(
        &AccountIdentifier::new(np_pid, Some(to_subaccount)),
        10 * 100_000_000,
    );

    // Reward the node provider with a neuron instead of liquid ICP.
    let pid = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron.clone())),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("NP reward proposal".to_string()),
                    summary: "Reward this NP...".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::RewardNodeProvider(RewardNodeProvider {
                        node_provider: Some(NodeProvider {
                            id: Some(np_pid),
                            reward_account: None,
                        }),
                        amount_e8s: 99_999_999,
                        reward_mode: Some(RewardMode::RewardToNeuron(RewardToNeuron {
                            dissolve_delay_seconds: 10,
                        })),
                    })),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };
    // The proposal should have been executed
    assert_eq!(
        gov.get_proposal_data(pid).unwrap().status(),
        ProposalStatus::Executed
    );
    // Find the neuron...
    let (_, neuron) = gov
        .proto
        .neurons
        .iter()
        .find(|(_, x)| x.controller == Some(np_pid))
        .unwrap();
    assert_eq!(neuron.stake_e8s(), 99_999_999);
    // Find the transaction in the ledger...
    driver.assert_account_contains(
        &AccountIdentifier::new(
            GOVERNANCE_CANISTER_ID.get(),
            Some(Subaccount::try_from(&neuron.account[..]).unwrap()),
        ),
        99_999_999,
    );
    // Now make a proposal to remove the NodeProvider
    let pid = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("NP reward proposal".to_string()),
                    summary: "Just want to remove this NP.".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::AddOrRemoveNodeProvider(
                        AddOrRemoveNodeProvider {
                            change: Some(Change::ToRemove(NodeProvider {
                                id: Some(np_pid),
                                reward_account: None,
                            })),
                        },
                    )),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // The proposal should have been executed
    assert_eq!(
        gov.get_proposal_data(pid).unwrap().status(),
        ProposalStatus::Executed
    );

    // There should no longer be a noder provider.
    assert_eq!(gov.get_node_providers().len(), 0);
}

#[test]
fn test_manage_and_reward_multiple_node_providers() {
    let p: PathBuf = ["tests", "neurons.csv"].iter().collect();
    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let voter_pid = *init_neurons[&42].controller.as_ref().unwrap();

    let voter_neuron = init_neurons[&42].id.as_ref().unwrap().clone();
    init_neurons.get_mut(&42).unwrap().dissolve_state = Some(DissolveState::DissolveDelaySeconds(
        MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
    ));
    let np_pid_0 = PrincipalId::new_self_authenticating(&[14]);
    let np_pid_1 = PrincipalId::new_self_authenticating(&[15]);
    let np_pid_2 = PrincipalId::new_self_authenticating(&[16]);

    let (driver, mut gov) =
        governance_with_neurons(&init_neurons.values().cloned().collect::<Vec<Neuron>>());

    println!(
        "Ledger {:?}\n",
        driver.state.as_ref().try_lock().unwrap().accounts,
    );

    // Submit a proposal to reward a node provider which doesn't exist.
    // The submitter neuron votes automatically and that should be enough
    // to have it accepted
    let pid = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron.clone())),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("NP reward proposal".to_string()),
                    summary: "Reward this NP...".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::RewardNodeProvider(RewardNodeProvider {
                        node_provider: Some(NodeProvider {
                            id: Some(np_pid_1),
                            reward_account: None,
                        }),
                        amount_e8s: 10 * 100_000_000,
                        reward_mode: Some(RewardMode::RewardToAccount(RewardToAccount {
                            to_account: None,
                        })),
                    })),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // The proposal should have failed as the node provider doesn't exist
    let info = gov
        .get_proposal_info(&PrincipalId::new_anonymous(), pid)
        .unwrap();
    assert_eq!(info.status(), ProposalStatus::Failed, "info: {:?}", info);
    assert_eq!(
        info.failure_reason.as_ref().unwrap().error_type,
        ErrorType::NotFound as i32,
        "info: {:?}",
        info
    );

    let np_pid_vec = vec![np_pid_0, np_pid_1, np_pid_2];

    // Now make proposals to add the real node providers
    for np_pid in np_pid_vec.clone() {
        let prop_id = match gov
            .manage_neuron(
                &voter_pid,
                &ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        voter_neuron.clone(),
                    )),
                    command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                        title: Some("NP reward proposal".to_string()),
                        summary: "Just want to add this other NP.".to_string(),
                        url: "".to_string(),
                        action: Some(proposal::Action::AddOrRemoveNodeProvider(
                            AddOrRemoveNodeProvider {
                                change: Some(Change::ToAdd(NodeProvider {
                                    id: Some(np_pid),
                                    reward_account: None,
                                })),
                            },
                        )),
                    }))),
                },
            )
            .now_or_never()
            .unwrap()
            .expect("Couldn't submit proposal.")
            .command
            .unwrap()
        {
            manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
            _ => panic!("Invalid response"),
        };

        // The proposal should have been executed
        assert_eq!(
            gov.get_proposal_data(prop_id).unwrap().status(),
            ProposalStatus::Executed
        );

        assert_eq!(
            gov.get_node_providers()[0],
            NodeProvider {
                id: Some(np_pid_0),
                reward_account: None
            }
        );
    }

    assert_eq!(gov.get_node_providers().len(), 3);

    // Adding any of the same node providers again should fail
    for np_pid in np_pid_vec {
        let prop_id = match gov
            .manage_neuron(
                &voter_pid,
                &ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        voter_neuron.clone(),
                    )),
                    command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                        title: Some("Add NP".to_string()),
                        summary: "Just want to add this other NP.".to_string(),
                        url: "".to_string(),
                        action: Some(proposal::Action::AddOrRemoveNodeProvider(
                            AddOrRemoveNodeProvider {
                                change: Some(Change::ToAdd(NodeProvider {
                                    id: Some(np_pid),
                                    reward_account: None,
                                })),
                            },
                        )),
                    }))),
                },
            )
            .now_or_never()
            .unwrap()
            .expect("Couldn't submit proposal.")
            .command
            .unwrap()
        {
            manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
            _ => panic!("Invalid response"),
        };

        // The proposal should have failed
        assert_eq!(
            gov.get_proposal_data(prop_id).unwrap().status(),
            ProposalStatus::Failed
        );
    }

    let to_subaccount = Subaccount({
        let mut sha = Sha256::new();
        sha.write(b"my_account");
        sha.finish()
    });

    let manage_neuron_cmd = ManageNeuron {
        id: None,
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron.clone())),
        command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
            title: Some("Reward NP".to_string()),
            summary: "Reward these NPs...".to_string(),
            url: "".to_string(),
            action: Some(proposal::Action::RewardNodeProviders(RewardNodeProviders {
                rewards: vec![
                    RewardNodeProvider {
                        node_provider: Some(NodeProvider {
                            id: Some(np_pid_0),
                            reward_account: None,
                        }),
                        amount_e8s: 10 * 100_000_000,
                        reward_mode: Some(RewardMode::RewardToAccount(RewardToAccount {
                            to_account: Some(AccountIdentifier::new(np_pid_0, None).into()),
                        })),
                    },
                    RewardNodeProvider {
                        node_provider: Some(NodeProvider {
                            id: Some(np_pid_1),
                            reward_account: None,
                        }),
                        amount_e8s: 10 * 100_000_000,
                        reward_mode: Some(RewardMode::RewardToAccount(RewardToAccount {
                            to_account: Some(
                                AccountIdentifier::new(np_pid_1, Some(to_subaccount)).into(),
                            ),
                        })),
                    },
                    RewardNodeProvider {
                        node_provider: Some(NodeProvider {
                            id: Some(np_pid_2),
                            reward_account: None,
                        }),
                        amount_e8s: 99_999_999,
                        reward_mode: Some(RewardMode::RewardToNeuron(RewardToNeuron {
                            dissolve_delay_seconds: 10,
                        })),
                    },
                ],
                use_registry_derived_rewards: Some(false),
            })),
        }))),
    };

    // Repeat the above steps with two new NPs:
    // * Reward np_pid_1 with 10 * 100_000_000 to their default account
    // * Reward np_pid_2 with 10 * 100_000_000 to a specific sub-account
    // * Reward np_pid_3 with 99_999_999 to a neuron instead of liquid ICP
    let prop_id = match gov
        .manage_neuron(&voter_pid, &manage_neuron_cmd)
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // The proposal should have been executed
    assert_eq!(
        gov.get_proposal_data(prop_id).unwrap().status(),
        ProposalStatus::Executed
    );

    // Check first reward
    driver.assert_account_contains(&AccountIdentifier::new(np_pid_0, None), 10 * 100_000_000);

    // Check second reward
    driver.assert_account_contains(
        &AccountIdentifier::new(np_pid_1, Some(to_subaccount)),
        10 * 100_000_000,
    );

    // Check third reward
    // Find the neuron...
    let (_, neuron) = gov
        .proto
        .neurons
        .iter()
        .find(|(_, x)| x.controller == Some(np_pid_2))
        .unwrap();
    assert_eq!(neuron.stake_e8s(), 99_999_999);
    // Find the transaction in the ledger...
    driver.assert_account_contains(
        &AccountIdentifier::new(
            GOVERNANCE_CANISTER_ID.get(),
            Some(Subaccount::try_from(&neuron.account[..]).unwrap()),
        ),
        99_999_999,
    );

    // Remove the first and third NPs
    let prop_id = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron.clone())),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("Remove NP".to_string()),
                    summary: "Just want to remove this NP.".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::AddOrRemoveNodeProvider(
                        AddOrRemoveNodeProvider {
                            change: Some(Change::ToRemove(NodeProvider {
                                id: Some(np_pid_0),
                                reward_account: None,
                            })),
                        },
                    )),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // The proposal should have been executed
    assert_eq!(
        gov.get_proposal_data(prop_id).unwrap().status(),
        ProposalStatus::Executed
    );

    let prop_id = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("Remove NP".to_string()),
                    summary: "Just want to remove this NP.".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::AddOrRemoveNodeProvider(
                        AddOrRemoveNodeProvider {
                            change: Some(Change::ToRemove(NodeProvider {
                                id: Some(np_pid_2),
                                reward_account: None,
                            })),
                        },
                    )),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // The proposal should have been executed
    assert_eq!(
        gov.get_proposal_data(prop_id).unwrap().status(),
        ProposalStatus::Executed
    );

    // There should only be one node provider left
    assert_eq!(gov.get_node_providers().len(), 1);

    // Send the same command as before, target all three NPs (two do not exist
    // anymore)
    let prop_id = match gov
        .manage_neuron(&voter_pid, &manage_neuron_cmd)
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // The proposal should have been executed
    assert_eq!(
        gov.get_proposal_data(prop_id).unwrap().status(),
        ProposalStatus::Executed
    );

    // Check reward
    driver.assert_account_contains(
        &AccountIdentifier::new(np_pid_1, Some(to_subaccount)),
        10 * 200_000_000,
    );
}

#[test]
fn test_network_economics_proposal() {
    let p: PathBuf = ["tests", "neurons.csv"].iter().collect();
    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let voter_pid = *init_neurons[&42].controller.as_ref().unwrap();
    let voter_neuron = init_neurons[&42].id.as_ref().unwrap().clone();
    init_neurons.get_mut(&42).unwrap().dissolve_state = Some(DissolveState::DissolveDelaySeconds(
        MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
    ));
    let (_, mut gov) =
        governance_with_neurons(&init_neurons.values().cloned().collect::<Vec<Neuron>>());

    gov.proto.economics.as_mut().unwrap().reject_cost_e8s = 1234;
    gov.proto
        .economics
        .as_mut()
        .unwrap()
        .neuron_minimum_stake_e8s = 1234;

    // Making a proposal to change 'reject_cost_e8s' should only change
    // that value.
    let pid = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("Network Economics change".to_string()),
                    summary: "Just want to change this param.".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::ManageNetworkEconomics(NetworkEconomics {
                        reject_cost_e8s: 56789,
                        ..Default::default()
                    })),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // The proposal should have been executed
    assert_eq!(
        gov.get_proposal_data(pid).unwrap().status(),
        ProposalStatus::Executed
    );

    // Make sure only that value changed.
    assert_eq!(gov.proto.economics.as_ref().unwrap().reject_cost_e8s, 56789);
    assert_eq!(
        gov.proto
            .economics
            .as_ref()
            .unwrap()
            .neuron_minimum_stake_e8s,
        1234
    );
}

#[test]
fn test_default_followees() {
    let p: PathBuf = ["tests", "neurons.csv"].iter().collect();
    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let voter_pid = *init_neurons[&42].controller.as_ref().unwrap();
    let voter_neuron = init_neurons[&42].id.as_ref().unwrap().clone();
    init_neurons.get_mut(&42).unwrap().dissolve_state = Some(DissolveState::DissolveDelaySeconds(
        MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
    ));
    let (mut driver, mut gov) =
        governance_with_neurons(&init_neurons.values().cloned().collect::<Vec<Neuron>>());

    let default_followees = hashmap![
        Topic::ExchangeRate as i32 => Followees { followees: vec![voter_neuron.clone()]},
        Topic::NetworkEconomics as i32 => Followees { followees: vec![voter_neuron.clone()]},
        Topic::Governance as i32 => Followees { followees: vec![voter_neuron.clone()]},
        Topic::NodeAdmin as i32 => Followees { followees: vec![voter_neuron.clone()]},
        Topic::ParticipantManagement as i32 => Followees { followees: vec![voter_neuron.clone()]},
        Topic::SubnetManagement as i32 => Followees { followees: vec![voter_neuron.clone()]},
        Topic::NetworkCanisterManagement as i32 => Followees { followees: vec![voter_neuron.clone()]},
        Topic::Kyc as i32 => Followees { followees: vec![voter_neuron.clone()]},
    ];

    gov.proto.default_followees = default_followees.clone();
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let neuron_stake_e8s = 100 * 100_000_000;
    let nonce = 1234u64;

    let to_subaccount = Subaccount({
        let mut sha = Sha256::new();
        sha.write(&[0x0c]);
        sha.write(b"neuron-stake");
        sha.write(from.as_slice());
        sha.write(&nonce.to_be_bytes());
        sha.finish()
    });

    driver.create_account_with_funds(
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(to_subaccount)),
        neuron_stake_e8s,
    );

    let id =
        claim_or_refresh_neuron_by_memo(&mut gov, &from, None, to_subaccount, Memo(nonce), None)
            .unwrap();

    assert_eq!(gov.get_neuron(&id).unwrap().followees, default_followees);

    let default_followees2 = hashmap![
        Topic::ExchangeRate as i32 => Followees { followees: vec![]},
        Topic::NetworkEconomics as i32 => Followees { followees: vec![voter_neuron.clone()]},
        Topic::Governance as i32 => Followees { followees: vec![]},
        Topic::NodeAdmin as i32 => Followees { followees: vec![voter_neuron.clone()]},
        Topic::ParticipantManagement as i32 => Followees { followees: vec![]},
        Topic::SubnetManagement as i32 => Followees { followees: vec![voter_neuron.clone()]},
        Topic::NetworkCanisterManagement as i32 => Followees { followees: vec![voter_neuron.clone()]},
        Topic::Kyc as i32 => Followees { followees: vec![]},
    ];

    // Make a proposal to chante the deafult followees.
    let pid = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("Change Network Economics".to_string()),
                    summary: "Just want to change this param.".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::SetDefaultFollowees(SetDefaultFollowees {
                        default_followees: default_followees2.clone(),
                    })),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    assert_eq!(
        gov.get_proposal_data(pid).unwrap().status(),
        ProposalStatus::Executed
    );

    let nonce = 2345u64;
    let to_subaccount = Subaccount({
        let mut sha = Sha256::new();
        sha.write(&[0x0c]);
        sha.write(b"neuron-stake");
        sha.write(from.as_slice());
        sha.write(&nonce.to_be_bytes());
        sha.finish()
    });

    driver.create_account_with_funds(
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(to_subaccount)),
        neuron_stake_e8s,
    );

    let id2 =
        claim_or_refresh_neuron_by_memo(&mut gov, &from, None, to_subaccount, Memo(nonce), None)
            .unwrap();

    // The second neuron should have the default followees we set with the proposal.
    assert!(id != id2);
    assert_eq!(gov.get_neuron(&id2).unwrap().followees, default_followees2);
}

#[test]
fn test_recompute_tally() {
    let ballot = |v: Vote| -> Ballot {
        Ballot {
            vote: v as i32,
            voting_power: 10,
        }
    };
    let mut pinfo = ProposalData {
        ballots: [
            (1, ballot(Vote::Yes)),
            (2, ballot(Vote::Yes)),
            (3, ballot(Vote::Yes)),
            (4, ballot(Vote::No)),
            (5, ballot(Vote::Unspecified)),
        ]
        .to_vec()
        .into_iter()
        .collect(),
        ..Default::default()
    };
    pinfo.recompute_tally(10, ONE_DAY_SECONDS);
    assert_eq!(
        Some(Tally {
            timestamp_seconds: 10,
            yes: 30,
            no: 10,
            total: 50,
        }),
        pinfo.latest_tally
    );
}

// Creates a Governance store with one dummy ExecuteNnsFunction proposal
fn fixture_for_proposals(proposal_id: ProposalId, payload: Vec<u8>) -> GovernanceProto {
    let execute_nns_function = ExecuteNnsFunction {
        nns_function: NnsFunction::ClearProvisionalWhitelist as i32,
        payload,
    };
    let proposal = Proposal {
        title: Some("A Reasonable Title".to_string()),
        action: Some(proposal::Action::ExecuteNnsFunction(execute_nns_function)),
        ..Default::default()
    };
    let proposal_data = ProposalData {
        id: Some(proposal_id),
        proposal: Some(proposal),
        ..Default::default()
    };
    GovernanceProto {
        economics: Some(NetworkEconomics::with_default_values()),
        proposals: once((proposal_id.id, proposal_data)).collect(),
        ..Default::default()
    }
}

// Test that the response has the expected topic and that it still has the
// payload!
#[test]
fn test_get_proposal_info() {
    // ARRANGE
    let proposal_id = ProposalId { id: 2 };
    let driver = fake::FakeDriver::default();
    let gov = Governance::new(
        fixture_for_proposals(proposal_id, vec![1, 2, 3]),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    let caller = &principal(1);

    // ACT
    let result = gov.get_proposal_info(caller, proposal_id).unwrap();

    // ASSERT
    assert_eq!(Topic::NetworkEconomics as i32, result.topic);
    let action = result.proposal.unwrap().action.unwrap();
    assert_matches!(
        action,
        proposal::Action::ExecuteNnsFunction(eu) if eu.payload == [1, 2, 3]
    );
}

#[test]
fn test_list_proposals_removes_execute_nns_function_payload() {
    // ARRANGE
    let proposal_id = ProposalId { id: 2 };
    let payload = iter::repeat(42)
        .take(EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX + 1)
        .collect();
    let driver = fake::FakeDriver::default();
    let gov = Governance::new(
        fixture_for_proposals(proposal_id, payload),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    let caller = &principal(1);

    // ACT
    let results = gov.list_proposals(
        caller,
        &ListProposalInfo {
            ..Default::default()
        },
    );

    // ASSERT
    let action = results.proposal_info[0]
        .proposal
        .as_ref()
        .unwrap()
        .action
        .as_ref()
        .unwrap();
    assert_matches!(
        action,
        proposal::Action::ExecuteNnsFunction(eu) if eu.payload.is_empty()
    );
}

#[test]
fn test_list_proposals_retains_execute_nns_function_payload() {
    // ARRANGE
    let proposal_id = ProposalId { id: 2 };
    let payload = iter::repeat(42)
        .take(EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX)
        .collect();
    let driver = fake::FakeDriver::default();
    let gov = Governance::new(
        fixture_for_proposals(proposal_id, payload),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    let caller = &principal(1);

    // ACT
    let results = gov.list_proposals(
        caller,
        &ListProposalInfo {
            ..Default::default()
        },
    );

    // ASSERT
    let action = results.proposal_info[0]
        .proposal
        .as_ref()
        .unwrap()
        .action
        .as_ref()
        .unwrap();
    assert_matches!(
        action,
        proposal::Action::ExecuteNnsFunction(eu)
        if eu.payload.len() ==
            EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX
    );
}

#[test]
fn test_get_pending_proposals_removes_execute_nns_function_payload() {
    // ARRANGE
    let proposal_id = ProposalId { id: 2 };
    let payload = iter::repeat(42)
        .take(EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX + 1)
        .collect();
    let driver = fake::FakeDriver::default();
    let gov = Governance::new(
        fixture_for_proposals(proposal_id, payload),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    let caller = &principal(1);

    // ACT
    let results = gov.get_pending_proposals(caller);

    // ASSERT
    let action = results[0]
        .proposal
        .as_ref()
        .unwrap()
        .action
        .as_ref()
        .unwrap();
    assert_matches!(
        action,
        proposal::Action::ExecuteNnsFunction(eu) if eu.payload.is_empty()
    );
}

/// There are 99 proposals [2, 3, ..., 100] in this test which only
/// tests that paging works as expected.
#[test]
fn test_list_proposals() {
    let proto = GovernanceProto {
        economics: Some(NetworkEconomics::with_default_values()),
        proposals: (2..=100)
            .collect::<Vec<u64>>()
            .iter()
            .map(|x| {
                (
                    *x,
                    ProposalData {
                        id: Some(ProposalId { id: *x }),
                        ..Default::default()
                    },
                )
            })
            .collect::<BTreeMap<u64, ProposalData>>(),
        ..Default::default()
    };
    let driver = fake::FakeDriver::default();
    let gov = Governance::new(proto, driver.get_fake_env(), driver.get_fake_ledger());
    let caller = &principal(1);
    {
        let lst = gov
            .list_proposals(
                caller,
                &ListProposalInfo {
                    ..Default::default()
                },
            )
            .proposal_info;
        assert_eq!(
            (2..=100).rev().collect::<Vec<u64>>(),
            lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
        );
    }
    let mut lst = gov
        .list_proposals(
            caller,
            &ListProposalInfo {
                limit: 50,
                ..Default::default()
            },
        )
        .proposal_info;
    assert_eq!(
        (51..=100).rev().collect::<Vec<u64>>(),
        lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
    );
    lst = gov
        .list_proposals(
            caller,
            &ListProposalInfo {
                limit: 50,
                before_proposal: lst.last().and_then(|x| x.id),
                ..Default::default()
            },
        )
        .proposal_info;
    assert_eq!(
        (2..=50).rev().collect::<Vec<u64>>(),
        lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
    );
    lst = gov
        .list_proposals(
            caller,
            &ListProposalInfo {
                limit: 50,
                before_proposal: lst.last().and_then(|x| x.id),
                ..Default::default()
            },
        )
        .proposal_info;
    assert_eq!(0, lst.len());
}

// Tests the following:
//
// 1. A proposal with resticted voting is included only if the caller
//    is allowed to vote on the proposal.
//
// 2. That the include filter for status is respected.
//
// 3. That the include filter for reward status is respected.
//
// 4. Only shows votes from neurons that the caller either controlls
//    or is a registered hot key for.
//
// 5. The exclude topic list is honoured.
#[test]
fn test_filter_proposals() {
    let principal12 = principal(12);
    let principal3 = principal(3);
    let principal4 = principal(4);
    let principal_hot = PrincipalId::try_from(b"SID-hot".to_vec()).unwrap();
    let mut driver = fake::FakeDriver::default();
    let proto = GovernanceProto {
        wait_for_quiet_threshold_seconds: 100,
        economics: Some(NetworkEconomics::with_default_values()),
        neurons: [
            (
                1,
                Neuron {
                    id: Some(NeuronId { id: 1 }),
                    controller: Some(principal12),
                    cached_neuron_stake_e8s: 10 * 100_000_000,
                    account: driver.random_byte_array().to_vec(),
                    ..Default::default()
                },
            ),
            (
                2,
                Neuron {
                    id: Some(NeuronId { id: 2 }),
                    controller: Some(principal12),
                    cached_neuron_stake_e8s: 10 * 100_000_000,
                    account: driver.random_byte_array().to_vec(),
                    ..Default::default()
                },
            ),
            (
                3,
                Neuron {
                    id: Some(NeuronId { id: 3 }),
                    controller: Some(principal3),
                    hot_keys: vec![principal_hot],
                    cached_neuron_stake_e8s: 10 * 100_000_000,
                    account: driver.random_byte_array().to_vec(),
                    ..Default::default()
                },
            ),
            (
                4,
                Neuron {
                    id: Some(NeuronId { id: 4 }),
                    controller: Some(principal4),
                    hot_keys: vec![principal_hot],
                    cached_neuron_stake_e8s: 10 * 100_000_000,
                    account: driver.random_byte_array().to_vec(),
                    ..Default::default()
                },
            ),
            (
                5,
                Neuron {
                    id: Some(NeuronId { id: 5 }),
                    cached_neuron_stake_e8s: 10 * 100_000_000,
                    account: driver.random_byte_array().to_vec(),
                    followees: [(
                        Topic::NeuronManagement as i32,
                        neuron::Followees {
                            followees: [NeuronId { id: 3 }, NeuronId { id: 4 }].to_vec(),
                        },
                    )]
                    .to_vec()
                    .into_iter()
                    .collect(),
                    ..Default::default()
                },
            ),
        ]
        .to_vec()
        .into_iter()
        .collect(),
        proposals: [
            (
                1,
                // status: EXECUTED
                // restricted: false
                // reward_status: SETTLED
                // topic: GOVERNANCE
                ProposalData {
                    id: Some(ProposalId { id: 1 }),
                    proposer: Some(NeuronId { id: 1 }),
                    proposal: Some(Proposal {
                        title: Some("A Reasonable Title".to_string()),
                        summary: "summary".to_string(),
                        action: Some(proposal::Action::Motion(Motion {
                            motion_text: "me like proposals".to_string(),
                        })),
                        ..Default::default()
                    }),
                    latest_tally: Some(Tally {
                        timestamp_seconds: 10,
                        yes: 2,
                        no: 0,
                        total: 3,
                    }),
                    decided_timestamp_seconds: 1,
                    executed_timestamp_seconds: 1,
                    reward_event_round: 1,
                    ..Default::default()
                },
            ),
            (
                2,
                // status: OPEN
                // restricted: true
                // reward_status: INELIGIBLE
                // topic: MANAGE_NEURON
                ProposalData {
                    id: Some(ProposalId { id: 2 }),
                    proposer: Some(NeuronId { id: 4 }),
                    proposal: Some(Proposal {
                        title: Some("A Reasonable Title".to_string()),
                        summary: "summary".to_string(),
                        action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                                NeuronId { id: 5 },
                            )),
                            id: None,
                            command: Some(manage_neuron::Command::Disburse(
                                manage_neuron::Disburse {
                                    amount: None,
                                    to_account: None,
                                },
                            )),
                        }))),
                        ..Default::default()
                    }),
                    latest_tally: Some(Tally {
                        timestamp_seconds: 10,
                        yes: 2,
                        no: 0,
                        total: 3,
                    }),
                    ..Default::default()
                },
            ),
            (
                3,
                // status: OPEN
                // restricted: false
                // reward_status: ACCEPT_VOTES or READY_TO_SETTLE
                // topic: GOVERNANCE
                ProposalData {
                    id: Some(ProposalId { id: 3 }),
                    proposer: Some(NeuronId { id: 1 }),
                    proposal: Some(Proposal {
                        title: Some("A Reasonable Title".to_string()),
                        summary: "summary".to_string(),
                        action: Some(proposal::Action::Motion(Motion {
                            motion_text: "me like proposals".to_string(),
                        })),
                        ..Default::default()
                    }),
                    ballots: [
                        (
                            1,
                            Ballot {
                                vote: Vote::Yes as i32,
                                voting_power: 1,
                            },
                        ),
                        (
                            2,
                            Ballot {
                                vote: Vote::Yes as i32,
                                voting_power: 1,
                            },
                        ),
                        (
                            3,
                            Ballot {
                                vote: Vote::Yes as i32,
                                voting_power: 1,
                            },
                        ),
                        (
                            4,
                            Ballot {
                                vote: Vote::No as i32,
                                voting_power: 1,
                            },
                        ),
                        (
                            5,
                            Ballot {
                                vote: Vote::Unspecified as i32,
                                voting_power: 1,
                            },
                        ),
                    ]
                    .to_vec()
                    .into_iter()
                    .collect(),
                    latest_tally: Some(Tally {
                        timestamp_seconds: 10,
                        yes: 3,
                        no: 1,
                        total: 5,
                    }),
                    ..Default::default()
                },
            ),
            (
                4,
                // status: FAILED
                // restricted: false
                // reward_status: SETTLED
                // topic: GOVERNANCE
                ProposalData {
                    id: Some(ProposalId { id: 4 }),
                    proposer: Some(NeuronId { id: 1 }),
                    proposal: Some(Proposal {
                        title: Some("A Reasonable Title".to_string()),
                        summary: "summary".to_string(),
                        action: Some(proposal::Action::Motion(Motion {
                            motion_text: "me like proposals".to_string(),
                        })),
                        ..Default::default()
                    }),
                    latest_tally: Some(Tally {
                        timestamp_seconds: 10,
                        yes: 2,
                        no: 0,
                        total: 3,
                    }),
                    decided_timestamp_seconds: 1,
                    failed_timestamp_seconds: 1,
                    reward_event_round: 1,
                    ..Default::default()
                },
            ),
        ]
        .to_vec()
        .into_iter()
        .collect::<BTreeMap<u64, ProposalData>>(),
        ..Default::default()
    };
    let mut driver = fake::FakeDriver::default().at(20);
    let gov = Governance::new(proto, driver.get_fake_env(), driver.get_fake_ledger());
    // Test 1: a proposal with resticted voting is included only if
    // the caller is allowed to vote on the proposal.
    {
        // Try listing all proposals as principal4.
        let lst = gov
            .list_proposals(
                &principal4,
                &ListProposalInfo {
                    ..Default::default()
                },
            )
            .proposal_info;
        for p in lst.iter() {
            println!(
                "Proposal {:?} {:?} {:?} {:?}",
                p.id, p.status, p.reward_status, p
            );
        }
        // Principal 4 is a manager of the neuron 5 which is managed
        // by proposal 2.
        assert_eq!(
            vec![4, 3, 2, 1],
            lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
        );
    }
    {
        // Try listing all proposals as the hot key.
        let lst = gov
            .list_proposals(
                &principal_hot,
                &ListProposalInfo {
                    ..Default::default()
                },
            )
            .proposal_info;
        // The hot key is also a manager of the neuron 5 which is
        // managed by proposal 2.
        assert_eq!(
            vec![4, 3, 2, 1],
            lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
        );
    }
    {
        // Try listing all proposals as principal12.
        let lst = gov
            .list_proposals(
                &principal12,
                &ListProposalInfo {
                    ..Default::default()
                },
            )
            .proposal_info;
        // Principal 1/2 is not a manager of neuron 5 which is managed
        // by proposal 2.
        assert_eq!(
            vec![4, 3, 1],
            lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
        );
    }
    // Test 2: the include filter for status is respected.
    {
        let lst = gov
            .list_proposals(
                &principal4,
                &ListProposalInfo {
                    include_status: vec![ProposalStatus::Open as i32],
                    ..Default::default()
                },
            )
            .proposal_info;
        assert_eq!(
            vec![3, 2],
            lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
        );
        let lst = gov
            .list_proposals(
                &principal4,
                &ListProposalInfo {
                    include_status: vec![
                        ProposalStatus::Executed as i32,
                        ProposalStatus::Failed as i32,
                    ],
                    ..Default::default()
                },
            )
            .proposal_info;
        assert_eq!(
            vec![4, 1],
            lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
        );
    }
    // Test 3: the include filter for reward status is respected.
    {
        let lst = gov
            .list_proposals(
                &principal4,
                &ListProposalInfo {
                    include_reward_status: vec![ProposalRewardStatus::Settled as i32],
                    ..Default::default()
                },
            )
            .proposal_info;
        assert_eq!(
            vec![4, 1],
            lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
        );
        let lst = gov
            .list_proposals(
                &principal4,
                &ListProposalInfo {
                    include_reward_status: vec![ProposalRewardStatus::AcceptVotes as i32],
                    ..Default::default()
                },
            )
            .proposal_info;
        assert_eq!(driver.now(), 20);
        assert_eq!(
            vec![3],
            lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
        );
        // Advance time.
        driver.advance_time_by(100);
        assert_eq!(driver.now(), 120);
        // Now proposal 3 should no longer 'accept votes'.
        let lst = gov
            .list_proposals(
                &principal4,
                &ListProposalInfo {
                    include_reward_status: vec![ProposalRewardStatus::AcceptVotes as i32],
                    ..Default::default()
                },
            )
            .proposal_info;
        assert!(lst.iter().map(|x| x.id.unwrap().id).next().is_none());
    }
    // Instead, proposal 3 should now be 'ready to settle'.
    let lst = gov
        .list_proposals(
            &principal12,
            &ListProposalInfo {
                include_reward_status: vec![ProposalRewardStatus::ReadyToSettle as i32],
                ..Default::default()
            },
        )
        .proposal_info;
    assert_eq!(
        vec![3],
        lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
    );
    // Test 4: only show votes from neurons that the caller (in this
    // case principal 1/2) either controlls or is a registered hot key
    // for.
    assert_eq!(
        [
            (
                1,
                Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: 1
                }
            ),
            (
                2,
                Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: 1
                }
            ),
        ]
        .to_vec()
        .into_iter()
        .collect::<HashMap<u64, Ballot>>(),
        lst[0].ballots
    );
    // Similar, but with the hot key.
    let lst = gov
        .list_proposals(
            &principal_hot,
            &ListProposalInfo {
                include_reward_status: vec![ProposalRewardStatus::ReadyToSettle as i32],
                include_status: vec![ProposalStatus::Open as i32],
                ..Default::default()
            },
        )
        .proposal_info;
    assert_eq!(
        vec![3],
        lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
    );
    assert_eq!(
        [
            (
                3,
                Ballot {
                    vote: Vote::Yes as i32,
                    voting_power: 1
                }
            ),
            (
                4,
                Ballot {
                    vote: Vote::No as i32,
                    voting_power: 1
                }
            ),
        ]
        .to_vec()
        .into_iter()
        .collect::<HashMap<u64, Ballot>>(),
        lst[0].ballots
    );
    // Test 5: make sure that the `exclude_topic` list is honoured.
    {
        // Try listing all proposals as the hot key.
        let lst = gov
            .list_proposals(
                &principal_hot,
                &ListProposalInfo {
                    exclude_topic: vec![Topic::Governance as i32],
                    ..Default::default()
                },
            )
            .proposal_info;
        assert_eq!(
            vec![2],
            lst.iter().map(|x| x.id.unwrap().id).collect::<Vec<u64>>()
        );
    }
}

// Test that listing of neurons satisfies the following properties:
//
// 1. That the neurons with the caller as controller or hot keys are
// included in the result if `include_neurons_readable_by_caller` is true.
//
// 2. That the full neuron information is retrieved for a neuron
// listed in `neuron_ids` if and only if the caller is authorized to
// view it.
#[test]
fn test_list_neurons() {
    // Create 100 neurons with IDs 1-100.
    let mut proto = GovernanceProto {
        neurons: (1..100)
            .collect::<Vec<u64>>()
            .iter()
            .map(|x| {
                (
                    *x,
                    Neuron {
                        id: Some(NeuronId { id: *x }),
                        ..Default::default()
                    },
                )
            })
            .collect::<HashMap<u64, Neuron>>(),
        ..Default::default()
    };
    let p1 = principal(1);
    let p2 = principal(2);
    let p3 = principal(3);
    let p4 = principal(4);
    let p5 = principal(5);
    // Set controllers.
    proto.neurons.get_mut(&1).unwrap().controller = Some(p1);
    proto.neurons.get_mut(&2).unwrap().controller = Some(p2);
    proto.neurons.get_mut(&3).unwrap().controller = Some(p3);
    proto.neurons.get_mut(&4).unwrap().controller = Some(p4);
    // Set hot keys.
    proto.neurons.get_mut(&12).unwrap().hot_keys = vec![p1, p2];
    proto.neurons.get_mut(&21).unwrap().hot_keys = vec![p1, p2];
    proto.neurons.get_mut(&13).unwrap().hot_keys = vec![p1, p3];
    proto.neurons.get_mut(&31).unwrap().hot_keys = vec![p1, p3];
    // Set manage neuron followees
    proto.neurons.get_mut(&42).unwrap().followees = [(
        Topic::NeuronManagement as i32,
        neuron::Followees {
            followees: [NeuronId { id: 2 }, NeuronId { id: 4 }].to_vec(),
        },
    )]
    .to_vec()
    .into_iter()
    .collect();
    let driver = fake::FakeDriver::default();
    let gov = Governance::new(proto, driver.get_fake_env(), driver.get_fake_ledger());
    assert_eq!(
        ListNeuronsResponse {
            ..Default::default()
        },
        gov.list_neurons_by_principal(
            &ListNeurons {
                ..Default::default()
            },
            &p1
        )
    );
    // Principal p1 has access to n1 (controller) and n12, n21, n13, n31, as hot
    // key.
    let p1_listing = gov.list_neurons_by_principal(
        &ListNeurons {
            include_neurons_readable_by_caller: true,
            neuron_ids: vec![],
        },
        &p1,
    );
    let p1_access = vec![1, 12, 13, 21, 31]
        .into_iter()
        .collect::<HashSet<u64>>();
    assert_eq!(
        p1_access,
        p1_listing.neuron_infos.iter().map(|(x, _)| *x).collect()
    );
    assert_eq!(
        p1_access,
        p1_listing
            .full_neurons
            .iter()
            .map(|x| x.id.as_ref().unwrap().id)
            .collect::<HashSet<u64>>()
    );
    // Principal p5 has no access
    let p5_listing = gov.list_neurons_by_principal(
        &ListNeurons {
            include_neurons_readable_by_caller: true,
            neuron_ids: vec![200],
        },
        &p5,
    );
    let p5_access = vec![].into_iter().collect::<HashSet<u64>>();
    assert_eq!(
        p5_access,
        p5_listing
            .neuron_infos
            .iter()
            .map(|(x, _)| *x)
            .collect::<HashSet<u64>>()
    );
    assert_eq!(
        p5_access,
        p5_listing
            .full_neurons
            .iter()
            .map(|x| x.id.as_ref().unwrap().id)
            .collect::<HashSet<u64>>()
    );
    // Principal p4 has access only to n4 (controller). But it can
    // also view 42 as followee on the manage neuron topic.
    let p4_listing = gov.list_neurons_by_principal(
        &ListNeurons {
            include_neurons_readable_by_caller: true,
            neuron_ids: vec![42, 99],
        },
        &p4,
    );
    assert_eq!(
        vec![4, 42, 99].into_iter().collect::<HashSet<u64>>(),
        p4_listing
            .neuron_infos
            .iter()
            .map(|(x, _)| *x)
            .collect::<HashSet<u64>>()
    );
    assert_eq!(
        vec![4, 42].into_iter().collect::<HashSet<u64>>(),
        p4_listing
            .full_neurons
            .iter()
            .map(|x| x.id.as_ref().unwrap().id)
            .collect::<HashSet<u64>>()
    );
}

#[test]
fn test_max_number_of_proposals_with_ballots() {
    let mut fake_driver = fake::FakeDriver::default();
    let proto = GovernanceProto {
        wait_for_quiet_threshold_seconds: 5,
        ..fixture_two_neurons_second_is_bigger()
    };
    let mut gov = Governance::new(
        proto,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );
    // Vote with neuron 1. It is smaller, so proposals are not auto-accepted.
    for i in 0..MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS {
        gov.make_proposal(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &principal(1),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: format!("proposal {} summary", i),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "dummy text".to_string(),
                })),
                ..Default::default()
            },
        )
        .unwrap();
    }
    assert_eq!(
        MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS,
        gov.get_pending_proposals_data().count()
    );
    // Let's try one more. It should be rejected.
    assert_matches!(gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "this one should not make it though...".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "so many proposals!".to_string(),
            })),
            ..Default::default()
        },
    ), Err(GovernanceError{error_type, error_message: _}) if error_type==ResourceExhausted as i32);
    // Let's try a NnsCanisterUpgrade. This proposal type is whitelisted, so it can
    // be submitted even though the max is reached.
    assert_matches!(
        gov.make_proposal(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &principal(1),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "NnsCanisterUpgrade should go through despite the limit".to_string(),
                action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
                    nns_function: NnsFunction::NnsCanisterUpgrade as i32,
                    payload: Vec::new(),
                })),
                ..Default::default()
            },
        ),
        Ok(_)
    );

    fake_driver.advance_time_by(10);
    gov.run_periodic_tasks().now_or_never();

    // Now all proposals should have been rejected.
    for i in 1_u64..MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS as u64 + 2 {
        assert_eq!(
            gov.get_proposal_data(ProposalId { id: i })
                .unwrap()
                .status(),
            Rejected
        );
    }

    // But we still can't submit new proposals.
    // Let's try one more. It should be rejected.
    assert_matches!(gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "this one should not make it though...".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "so many proposals!".to_string(),
            })),
            ..Default::default()
        },
    ), Err(GovernanceError{error_type, error_message: _}) if error_type==ResourceExhausted as i32);

    // Let's make a reward event happen
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    gov.run_periodic_tasks().now_or_never();

    // Now it should be allowed to submit a new one
    gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "Now it should work!".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "did it?".to_string(),
            })),
            ..Default::default()
        },
    )
    .unwrap();
}

#[test]
fn test_proposal_gc() {
    let props = (1..1000)
        .collect::<Vec<u64>>()
        .iter()
        .map(|x| {
            (
                *x,
                ProposalData {
                    id: Some(ProposalId { id: *x }),
                    decided_timestamp_seconds: 60,
                    reward_event_round: 1,
                    proposal: Some(Proposal {
                        title: Some("A Reasonable Title".to_string()),
                        action: Some(if x % 2 == 0 {
                            proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                                ..Default::default()
                            }))
                        } else {
                            proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
                                ..Default::default()
                            })
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
        })
        .collect::<BTreeMap<u64, ProposalData>>();
    let proto = GovernanceProto {
        economics: Some(NetworkEconomics::with_default_values()),
        proposals: props.clone(),
        ..Default::default()
    };
    // Set timestamp to 30 days
    let mut driver = fake::FakeDriver::default().at(60 * 60 * 24 * 30);
    let mut gov = Governance::new(proto, driver.get_fake_env(), driver.get_fake_ledger());
    assert_eq!(999, gov.proto.proposals.len());
    // First check GC does not take place if
    // latest_gc_{timestamp_seconds|num_proposals} are both close to
    // their current values.
    gov.latest_gc_timestamp_seconds = driver.now() - 60;
    gov.latest_gc_num_proposals = gov.proto.proposals.len() - 10;
    assert!(!gov.maybe_gc());
    // Now, assume that 500 proposals has been added since the last run...
    gov.latest_gc_num_proposals = gov.proto.proposals.len() - 500;
    assert!(gov.maybe_gc());
    // We keep max 100 proposals per topic and only two topics are
    // present in the list of proposals.
    assert!(gov.proto.proposals.len() <= 200);
    // Check that the proposals with high IDs have been kept and the
    // proposals with low IDs have been purged.
    for i in 1..500 {
        assert!(gov.proto.proposals.get(&i).is_none());
    }
    for i in 900..1000 {
        assert!(gov.proto.proposals.get(&i).is_some());
    }
    // Running again, nothing should change...
    assert!(!gov.maybe_gc());
    // Reset all proposals.
    gov.proto.proposals = props;
    gov.latest_gc_timestamp_seconds = driver.now() - 60;
    gov.latest_gc_num_proposals = gov.proto.proposals.len() - 10;
    assert!(!gov.maybe_gc());
    // Advance time by two days...
    driver.advance_time_by(60 * 60 * 24 * 2);
    // This ought to induce GC.
    assert!(gov.maybe_gc());
    assert!(gov.proto.proposals.len() <= 200);
    // Advance time by a little.
    driver.advance_time_by(60);
    // No GC should be induced.
    assert!(!gov.maybe_gc());
}

#[test]
fn test_id_v1_works() {
    let driver = fake::FakeDriver::default();

    let mut gov = Governance::new(
        fixture_for_manage_neuron(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    // Make a proposal to replace the list of followees (2-4) with just 2.
    gov.make_proposal(
        &NeuronId { id: 2 },
        // Must match neuron 1's serialized_id.
        &principal(2),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: None,
                id: Some(NeuronId { id: 1 }),
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::NeuronManagement as i32,
                    followees: [NeuronId { id: 2 }].to_vec(),
                })),
            }))),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        ProposalStatus::Open,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );
}

#[test]
fn test_can_follow_by_subaccount_and_neuron_id() {
    fn test_can_follow_by(make_neuron_id: fn(&Neuron) -> NeuronIdOrSubaccount) {
        let driver = fake::FakeDriver::default();
        let mut gov = Governance::new(
            fixture_for_manage_neuron(),
            driver.get_fake_env(),
            driver.get_fake_ledger(),
        );

        let nid = NeuronId { id: 2 };
        let folowee = NeuronId { id: 1 };

        // Check that the neuron isn't following anyone beforehand
        let neuron = gov.get_neuron(&nid).expect("Failed to get neuron");
        let f = neuron.followees.get(&(Topic::Unspecified as i32));
        assert_eq!(f, None);
        let neuron_id_or_subaccount = make_neuron_id(neuron);

        // Start following
        gov.manage_neuron(
            // Must match neuron 5's serialized_id.
            &principal(2),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(neuron_id_or_subaccount.clone()),
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::Unspecified as i32,
                    followees: [folowee.clone()].to_vec(),
                })),
            },
        )
        .now_or_never()
        .unwrap()
        .expect("Manage neuron failed");

        // Check that you're actually following
        let neuron = gov.get_neuron(&nid).unwrap();

        let f = neuron
            .followees
            .get(&(Topic::Unspecified as i32))
            .unwrap()
            .followees
            .clone();
        assert_eq!(
            f,
            vec![folowee.clone()],
            "failed to start following neuron {:?} by {:?}",
            folowee,
            neuron_id_or_subaccount
        );
    }

    test_can_follow_by(|n| NeuronIdOrSubaccount::NeuronId(n.id.as_ref().unwrap().clone()));
    test_can_follow_by(|n| NeuronIdOrSubaccount::Subaccount(n.account.to_vec()));
}

#[cfg(feature = "test")]
fn assert_merge_maturity_executes_as_expected_new(
    nns: &mut NNS,
    id: &NeuronId,
    controller: &PrincipalId,
    percentage_to_merge: u32,
    expected_merged_maturity: u64,
) {
    let neuron = nns.get_neuron(id).clone();
    let response = nns
        .merge_maturity(id, controller, percentage_to_merge)
        .unwrap();
    let merged_maturity = response.merged_maturity_e8s;

    assert_eq!(merged_maturity, expected_merged_maturity);

    let expected_resulting_maturity = neuron.maturity_e8s_equivalent - merged_maturity;
    let expected_resulting_stake = neuron.cached_neuron_stake_e8s + merged_maturity;
    let post_merge_account_balance = nns.get_neuron_stake(&neuron);
    let merged_neuron = nns.get_neuron(id);

    assert_eq!(
        merged_neuron.maturity_e8s_equivalent,
        expected_resulting_maturity
    );
    assert_eq!(
        merged_neuron.cached_neuron_stake_e8s,
        expected_resulting_stake
    );
    assert_eq!(
        merged_neuron.cached_neuron_stake_e8s,
        post_merge_account_balance
    );

    assert!(neuron.aging_since_timestamp_seconds < merged_neuron.aging_since_timestamp_seconds);
}

proptest! {

#[cfg(feature = "test")]
#[test]
fn test_merge_maturity_of_neuron_new(start in 56u64..56_000_000,
                                     supply in 100_000_000u64..400_000_000,
                                     stake in 100_000_000u64..5_000_000_000_000_000,
                                     fees in 100_000_000u64..100_000_000_000,
                                     // maturity must be <= stake
                                     maturity in 25_000_000u64..100_000_000) {
    let mut nns = NNSBuilder::new()
        .set_block_height(543212234)
        .set_start_time(start)
        .with_supply(supply)
        .add_account_for(principal(1), 100_000_000)
        .add_neuron(
            NeuronBuilder::new(100, stake, principal(1))
                .set_dissolve_delay(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS)
                .set_neuron_fees(fees)
                .set_maturity(maturity),
        )
        .set_economics(NetworkEconomics {
            neuron_minimum_stake_e8s: 100_000_000,
            ..Default::default()
        })
        .create();

    nns.advance_time_by(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS + 1);

    let id = NeuronId { id: 100 };
    let neuron = nns.get_neuron(&id);
    let neuron_stake_e8s: u64 = neuron.cached_neuron_stake_e8s;
    let account_id = LedgerBuilder::neuron_account_id(neuron);
    let account_balance = nns.get_account_balance(account_id);
    assert_eq!(neuron_stake_e8s, account_balance);

    let controller = *neuron.controller.as_ref().unwrap();

    // Assert that maturity can't be merged by someone who doesn't control the
    // neuron
    assert!(nns
        .merge_maturity(&id, &*TEST_NEURON_2_OWNER_PRINCIPAL, 10)
        .is_err());

    // Assert percents outside of (0, 100] are rejected
    assert!(nns.merge_maturity(&id, &controller, 0).is_err());
    assert!(nns.merge_maturity(&id, &controller, 250).is_err());

    // Now we merge the maturity in gradually, first 10%, then 50% of what
    // remains, then all of the remainder. In this way, all of the maturity is
    // merged, just in three steps so that we can check the progress.

    // Assert that 10% of a neuron's maturity can be merged successfully
    let mut current_stake = stake;
    let mut maturity_left = maturity;
    let mut aging_since = start;
    assert_merge_maturity_executes_as_expected_new(&mut nns, &id, &controller, 10, maturity_left / 10);
    aging_since = prorated_neuron_age(aging_since, current_stake, current_stake + (maturity_left / 10), nns.now());
    current_stake += maturity_left / 10;
    maturity_left -= maturity_left / 10;

    // Assert that 50% of a neuron's maturity can be merged successfully
    assert_merge_maturity_executes_as_expected_new(&mut nns, &id, &controller, 50, maturity_left / 2);
    aging_since = prorated_neuron_age(aging_since, current_stake, current_stake + (maturity_left / 2), nns.now());
    current_stake += maturity_left / 2;
    maturity_left -= maturity_left / 2;

    // Assert that 100% of a neuron's maturity can be merged successfully
    assert_merge_maturity_executes_as_expected_new(&mut nns, &id, &controller, 100, maturity_left);
    aging_since = prorated_neuron_age(aging_since, current_stake, current_stake + maturity_left, nns.now());
    current_stake += maturity_left;
    maturity_left -= maturity_left;

    assert_eq!(current_stake, stake + maturity);
    assert_eq!(maturity_left, 0);

    // Assert that merging a neuron with no maturity fails
    assert!(nns.merge_maturity(&id, &controller, 10).is_err());

    prop_assert_changes!(nns, Changed::Changed(vec![
        NNSStateChange::Now(U64Change(
            start,
            start + MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS + 1,
        )),
        NNSStateChange::Accounts(vec![
            MapChange::Changed(
                nns.get_neuron_account_id(100),
                U64Change(stake, stake + maturity)
            ),
            MapChange::Changed(
                LedgerBuilder::minting_account(),
                U64Change(supply, supply - maturity),
            ),
        ]),
        NNSStateChange::GovernanceProto(vec![GovernanceChange::Neurons(vec![MapChange::Changed(
            100,
            vec![
                NeuronChange::CachedNeuronStakeE8S(U64Change(stake, current_stake)),
                NeuronChange::AgingSinceTimestampSeconds(U64Change(start, aging_since)),
                NeuronChange::MaturityE8SEquivalent(U64Change(maturity, maturity_left)),
            ],
        )])]),
    ]));
}

}

#[test]
fn test_merge_maturity_of_neuron() {
    let (driver, mut gov, neuron) = create_mature_neuron(false);

    let id = neuron.id.clone().unwrap();
    let controller = neuron.controller.unwrap();
    let neuron_stake_e8s = neuron.cached_neuron_stake_e8s;
    let account = AccountIdentifier::new(
        ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
        Some(Subaccount::try_from(neuron.account.as_slice()).unwrap()),
    );
    let account_balance = driver
        .account_balance(account)
        .now_or_never()
        .unwrap()
        .unwrap()
        .get_e8s();
    assert_eq!(neuron_stake_e8s, account_balance);

    {
        let maturity = 25_000_000;
        let neuron = gov.get_neuron_mut(&id).unwrap();
        neuron.maturity_e8s_equivalent = maturity;
    }

    // Assert that maturity can't be merged by someone who doesn't control the
    // neuron
    assert!(merge_maturity(&mut gov, id.clone(), &*TEST_NEURON_2_OWNER_PRINCIPAL, 10).is_err());

    // Assert percents outside of (0, 100] are rejected
    assert!(merge_maturity(&mut gov, id.clone(), &controller, 0).is_err());
    assert!(merge_maturity(&mut gov, id.clone(), &controller, 250).is_err());

    // Assert that 10% of a neuron's maturity can be merged successfully
    assert_merge_maturity_executes_as_expected(
        &mut gov,
        id.clone(),
        &controller,
        10,
        2_500_000,
        &driver,
    );

    // Assert that 50% of a neuron's maturity can be merged successfully
    assert_merge_maturity_executes_as_expected(
        &mut gov,
        id.clone(),
        &controller,
        50,
        11_250_000,
        &driver,
    );

    // Assert that 100% of a neuron's maturity can be merged successfully
    assert_merge_maturity_executes_as_expected(
        &mut gov,
        id.clone(),
        &controller,
        100,
        11_250_000,
        &driver,
    );

    // Assert that merging a neuron with no maturity fails
    assert!(merge_maturity(&mut gov, id, &controller, 10).is_err());
}

/// Merge the maturity for a given neuron and assert that the neuron's stake,
/// maturity and account balance were correctly modified
fn assert_merge_maturity_executes_as_expected(
    gov: &mut Governance,
    id: NeuronId,
    controller: &PrincipalId,
    percentage_to_merge: u32,
    expected_merged_maturity: u64,
    driver: &fake::FakeDriver,
) {
    let neuron = gov.get_neuron(&id).unwrap().clone();
    let account = AccountIdentifier::new(
        ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
        Some(Subaccount::try_from(neuron.account.as_slice()).unwrap()),
    );
    let response = merge_maturity(gov, id.clone(), controller, percentage_to_merge).unwrap();
    let merged_maturity = response.merged_maturity_e8s;
    assert_eq!(merged_maturity, expected_merged_maturity);
    let expected_resulting_maturity = neuron.maturity_e8s_equivalent - merged_maturity;
    let expected_resulting_stake = neuron.cached_neuron_stake_e8s + merged_maturity;
    let post_merge_account_balance = driver
        .account_balance(account)
        .now_or_never()
        .unwrap()
        .unwrap()
        .get_e8s();
    let merged_neuron = gov.get_neuron(&id).unwrap();
    assert_eq!(
        merged_neuron.maturity_e8s_equivalent,
        expected_resulting_maturity
    );
    assert_eq!(
        merged_neuron.cached_neuron_stake_e8s,
        expected_resulting_stake
    );
    assert_eq!(
        merged_neuron.cached_neuron_stake_e8s,
        post_merge_account_balance
    );

    assert!(neuron.aging_since_timestamp_seconds < merged_neuron.aging_since_timestamp_seconds);
}

/// A helper to merge the maturity of a neuron
fn merge_maturity(
    gov: &mut Governance,
    id: NeuronId,
    controller: &PrincipalId,
    percentage_to_merge: u32,
) -> Result<MergeMaturityResponse, GovernanceError> {
    let result = gov
        .manage_neuron(
            controller,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(id)),
                command: Some(Command::MergeMaturity(MergeMaturity {
                    percentage_to_merge,
                })),
            },
        )
        .now_or_never()
        .unwrap()
        .command
        .unwrap();

    match result {
        manage_neuron_response::Command::Error(e) => Err(e),
        manage_neuron_response::Command::MergeMaturity(response) => Ok(response),
        _ => panic!("Merge maturity command returned unexpected response"),
    }
}

#[test]
fn test_update_stake() {
    // Assert that doubling a neuron's stake halves its age
    let mut neuron = Neuron::default();
    let now = 10;
    neuron.cached_neuron_stake_e8s = Tokens::new(5, 0).unwrap().get_e8s();
    neuron.aging_since_timestamp_seconds = 0;
    neuron.update_stake(Tokens::new(10, 0).unwrap().get_e8s(), now);
    assert_eq!(neuron.aging_since_timestamp_seconds, 5);
    assert_eq!(
        neuron.cached_neuron_stake_e8s,
        Tokens::new(10, 0).unwrap().get_e8s()
    );

    // Increase the stake by a random amount
    let mut neuron = Neuron::default();
    let now = 10000;
    neuron.cached_neuron_stake_e8s = Tokens::new(50, 0).unwrap().get_e8s();
    neuron.aging_since_timestamp_seconds = 0;
    neuron.update_stake(Tokens::new(58, 0).unwrap().get_e8s(), now);
    let expected_aging_since_timestamp_seconds = 1380;
    assert_eq!(
        neuron.aging_since_timestamp_seconds,
        expected_aging_since_timestamp_seconds
    );
    assert_eq!(
        neuron.cached_neuron_stake_e8s,
        Tokens::new(58, 0).unwrap().get_e8s()
    );
}

#[test]
fn test_compute_cached_metrics() {
    let now = 100;
    let mut neurons = HashMap::<u64, Neuron>::new();

    // Not Dissolving neurons
    neurons.insert(
        1,
        Neuron {
            cached_neuron_stake_e8s: 100_000_000,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(1)),
            ..Default::default()
        },
    );

    neurons.insert(
        2,
        Neuron {
            cached_neuron_stake_e8s: 234_000_000,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(ONE_YEAR_SECONDS)),
            joined_community_fund_timestamp_seconds: Some(1),
            ..Default::default()
        },
    );

    neurons.insert(
        3,
        Neuron {
            cached_neuron_stake_e8s: 568_000_000,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(ONE_YEAR_SECONDS * 4)),
            ..Default::default()
        },
    );

    neurons.insert(
        4,
        Neuron {
            cached_neuron_stake_e8s: 1_123_000_000,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(ONE_YEAR_SECONDS * 4)),
            ..Default::default()
        },
    );

    neurons.insert(
        5,
        Neuron {
            cached_neuron_stake_e8s: 6_087_000_000,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(ONE_YEAR_SECONDS * 8)),
            ..Default::default()
        },
    );

    // Zero stake
    neurons.insert(
        6,
        Neuron {
            cached_neuron_stake_e8s: 0,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(5)),
            ..Default::default()
        },
    );

    // Less than minimum stake
    neurons.insert(
        7,
        Neuron {
            cached_neuron_stake_e8s: 100,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(5)),
            ..Default::default()
        },
    );

    // Dissolving neurons
    neurons.insert(
        8,
        Neuron {
            cached_neuron_stake_e8s: 234_000_000,
            dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                now + ONE_YEAR_SECONDS,
            )),
            ..Default::default()
        },
    );

    neurons.insert(
        9,
        Neuron {
            cached_neuron_stake_e8s: 568_000_000,
            dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                now + ONE_YEAR_SECONDS * 3,
            )),
            ..Default::default()
        },
    );

    neurons.insert(
        10,
        Neuron {
            cached_neuron_stake_e8s: 1_123_000_000,
            dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                now + ONE_YEAR_SECONDS * 5,
            )),
            ..Default::default()
        },
    );

    neurons.insert(
        11,
        Neuron {
            cached_neuron_stake_e8s: 6_087_000_000,
            dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                now + ONE_YEAR_SECONDS * 5,
            )),
            ..Default::default()
        },
    );

    neurons.insert(
        12,
        Neuron {
            cached_neuron_stake_e8s: 18_000_000_000,
            dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                now + ONE_YEAR_SECONDS * 7,
            )),
            ..Default::default()
        },
    );

    // Dissolved neurons
    neurons.insert(
        13,
        Neuron {
            cached_neuron_stake_e8s: 4_450_000_000,
            ..Default::default()
        },
    );

    neurons.insert(
        14,
        Neuron {
            cached_neuron_stake_e8s: 1_220_000_000,
            ..Default::default()
        },
    );

    neurons.insert(
        15,
        Neuron {
            cached_neuron_stake_e8s: 100_000_000,
            dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(1)),
            ..Default::default()
        },
    );

    let economics = NetworkEconomics {
        neuron_minimum_stake_e8s: 100_000_000,
        ..Default::default()
    };

    let gov = GovernanceProto {
        economics: Some(economics),
        neurons,
        ..Default::default()
    };

    let actual_metrics = gov.compute_cached_metrics(now, Tokens::new(147, 0).unwrap());

    let expected_metrics = GovernanceCachedMetrics {
        timestamp_seconds: 100,
        total_supply_icp: 147,
        dissolving_neurons_count: 5,
        dissolving_neurons_e8s_buckets: [
            (3, 568000000.0),
            (5, 7210000000.0),
            (1, 234000000.0),
            (7, 18000000000.0),
        ]
        .iter()
        .cloned()
        .collect(),
        dissolving_neurons_count_buckets: [(5, 2), (3, 1), (7, 1), (1, 1)]
            .iter()
            .cloned()
            .collect(),
        not_dissolving_neurons_count: 7,
        not_dissolving_neurons_e8s_buckets: [
            (8, 6087000000.0),
            (4, 1691000000.0),
            (1, 234000000.0),
            (0, 100000100.0),
        ]
        .iter()
        .cloned()
        .collect(),
        not_dissolving_neurons_count_buckets: [(0, 3), (1, 1), (4, 2), (8, 1)]
            .iter()
            .cloned()
            .collect(),
        dissolved_neurons_count: 3,
        dissolved_neurons_e8s: 5770000000,
        garbage_collectable_neurons_count: 2,
        neurons_with_invalid_stake_count: 1,
        total_staked_e8s: 39_894_000_100,
        neurons_with_less_than_6_months_dissolve_delay_count: 6,
        neurons_with_less_than_6_months_dissolve_delay_e8s: 5870000100,
        community_fund_total_staked_e8s: 234_000_000,
    };

    assert_eq!(expected_metrics, actual_metrics);
}

/// Creates a fixture with one neuron, aging since the test start timestamp, in
/// a given dissolve_state.
fn fixture_for_dissolving_neuron_tests(id: u64, dissolve_state: DissolveState) -> GovernanceProto {
    GovernanceProto {
        economics: Some(NetworkEconomics::default()),
        neurons: [(
            1,
            Neuron {
                id: Some(NeuronId { id }),
                controller: Some(principal(id)),
                dissolve_state: Some(dissolve_state),
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS,
                ..Neuron::default()
            },
        )]
        .to_vec()
        .into_iter()
        .collect(),
        ..Default::default()
    }
}

/// Tests that a neuron in a non-dissolving state changes to a dissolving state
/// when a "start_dissolving" command is issued. Also tests that the neuron ages
/// appropriately in both states.
#[test]
fn test_start_dissolving() {
    let fake_driver = fake::FakeDriver::default();
    let id: u64 = 1;
    let fixture: GovernanceProto = fixture_for_dissolving_neuron_tests(
        id,
        DissolveState::DissolveDelaySeconds(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS),
    );
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );
    assert_eq!(
        gov.get_neuron(&NeuronId { id }).unwrap().dissolve_state,
        Some(DissolveState::DissolveDelaySeconds(
            MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS
        ),)
    );
    // Assert that in one second the age of the neuron will be one second.
    assert_eq!(
        gov.get_neuron(&NeuronId { id })
            .unwrap()
            .age_seconds(DEFAULT_TEST_START_TIMESTAMP_SECONDS + 1),
        1
    );
    gov.manage_neuron(
        &principal(id),
        &ManageNeuron {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id })),
            command: Some(manage_neuron::Command::Configure(
                manage_neuron::Configure {
                    operation: Some(manage_neuron::configure::Operation::StartDissolving(
                        manage_neuron::StartDissolving {},
                    )),
                },
            )),
        },
    )
    .now_or_never()
    .unwrap()
    .expect("Manage neuron failed");
    assert_eq!(
        gov.get_neuron(&NeuronId { id }).unwrap().dissolve_state,
        Some(DissolveState::WhenDissolvedTimestampSeconds(
            DEFAULT_TEST_START_TIMESTAMP_SECONDS + MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS
        ),)
    );
    // Assert that in one second the age of the neuron will be zero.
    assert_eq!(
        gov.get_neuron(&NeuronId { id })
            .unwrap()
            .age_seconds(DEFAULT_TEST_START_TIMESTAMP_SECONDS + 1),
        0
    );
}

/// Tests that a neuron in a dissolving state will panic if a "start_dissolving"
/// command is issued.
#[test]
#[should_panic]
fn test_start_dissolving_panics() {
    let fake_driver = fake::FakeDriver::default();
    let id: u64 = 1;
    let fixture: GovernanceProto = fixture_for_dissolving_neuron_tests(
        id,
        DissolveState::WhenDissolvedTimestampSeconds(DEFAULT_TEST_START_TIMESTAMP_SECONDS),
    );
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );
    assert_eq!(
        gov.get_neuron(&NeuronId { id }).unwrap().dissolve_state,
        Some(DissolveState::DissolveDelaySeconds(
            MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS
        ))
    );
    gov.manage_neuron(
        &principal(id),
        &ManageNeuron {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id })),
            command: Some(manage_neuron::Command::Configure(
                manage_neuron::Configure {
                    operation: Some(manage_neuron::configure::Operation::StartDissolving(
                        manage_neuron::StartDissolving {},
                    )),
                },
            )),
        },
    )
    .now_or_never()
    .unwrap()
    .expect("Manage neuron failed");
}

/// Tests that a neuron in a dissolving state will stop dissolving if a
/// "stop_dissolving" command is issued, and that the neuron will age when not
/// dissolving.
#[test]
fn test_stop_dissolving() {
    let fake_driver = fake::FakeDriver::default();
    let id: u64 = 1;
    let fixture: GovernanceProto = fixture_for_dissolving_neuron_tests(
        id,
        DissolveState::WhenDissolvedTimestampSeconds(
            DEFAULT_TEST_START_TIMESTAMP_SECONDS + MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
        ),
    );
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );
    assert_eq!(
        gov.get_neuron(&NeuronId { id }).unwrap().dissolve_state,
        Some(DissolveState::WhenDissolvedTimestampSeconds(
            DEFAULT_TEST_START_TIMESTAMP_SECONDS + MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS
        ),)
    );
    gov.manage_neuron(
        &principal(id),
        &ManageNeuron {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id })),
            command: Some(manage_neuron::Command::Configure(
                manage_neuron::Configure {
                    operation: Some(manage_neuron::configure::Operation::StopDissolving(
                        manage_neuron::StopDissolving {},
                    )),
                },
            )),
        },
    )
    .now_or_never()
    .unwrap()
    .expect("Manage neuron failed");
    assert_eq!(
        gov.get_neuron(&NeuronId { id }).unwrap().dissolve_state,
        Some(DissolveState::DissolveDelaySeconds(
            MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS
        ),)
    );
    // Assert that in one second the age of the neuron will be one second.
    assert_eq!(
        gov.get_neuron(&NeuronId { id })
            .unwrap()
            .age_seconds(DEFAULT_TEST_START_TIMESTAMP_SECONDS + 1),
        1
    );
}

/// Tests that a neuron in a non-dissolving state will panic if a
/// "stop_dissolving" command is issued.
#[test]
#[should_panic]
fn test_stop_dissolving_panics() {
    let fake_driver = fake::FakeDriver::default();
    let id: u64 = 1;
    let fixture: GovernanceProto = fixture_for_dissolving_neuron_tests(
        id,
        DissolveState::DissolveDelaySeconds(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS),
    );
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );
    assert_eq!(
        gov.get_neuron(&NeuronId { id }).unwrap().dissolve_state,
        Some(DissolveState::DissolveDelaySeconds(
            MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS
        ))
    );
    gov.manage_neuron(
        &principal(id),
        &ManageNeuron {
            id: None,
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id })),
            command: Some(manage_neuron::Command::Configure(
                manage_neuron::Configure {
                    operation: Some(manage_neuron::configure::Operation::StopDissolving(
                        manage_neuron::StopDissolving {},
                    )),
                },
            )),
        },
    )
    .now_or_never()
    .unwrap()
    .expect("Manage neuron failed");
}

#[test]
fn test_update_node_provider() {
    let (_, mut gov, neuron) = create_mature_neuron(false);
    let id = neuron.id.unwrap();
    let neuron = gov.get_neuron(&id).unwrap().clone();
    let controller = neuron.controller.unwrap();
    let account = AccountIdentifier::new(
        ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
        Some(Subaccount::try_from(neuron.account.as_slice()).unwrap()),
    );

    let update_np = UpdateNodeProvider {
        reward_account: None,
    };

    // Attempting to update a Node Provider when none exist should fail
    let err = gov
        .update_node_provider(&controller, update_np)
        .unwrap_err();
    assert_eq!(err.error_type, ErrorType::NotFound as i32);

    let np = NodeProvider {
        id: Some(controller),
        reward_account: Some(account.into_proto()),
    };

    gov.proto.node_providers.push(np);

    let hex = "b6a3539e69c6b75fe3c87b1ff82b1fc7f189a6113b77ba653b2e5eed67c95632";
    let new_reward_account = AccountIdentifier::from_hex(hex).unwrap().into_proto();
    let update_np = UpdateNodeProvider {
        reward_account: Some(new_reward_account.clone()),
    };

    // Updating an existing Node Provider with a valid reward account should succeed
    assert!(gov
        .update_node_provider(&controller, update_np.clone())
        .is_ok());
    assert_eq!(
        gov.proto
            .node_providers
            .get(0)
            .unwrap()
            .reward_account
            .as_ref()
            .unwrap(),
        &new_reward_account
    );

    // Updating an existing Node Provider without specifying a reward account should
    // fail
    let err = gov
        .update_node_provider(&controller, UpdateNodeProvider::default())
        .unwrap_err();
    assert_eq!(err.error_type, ErrorType::PreconditionFailed as i32);

    // Attempting to update a non-existant Node Provider with a valid reward account
    // should fail
    let err = gov
        .update_node_provider(&PrincipalId::new_anonymous(), update_np)
        .unwrap_err();
    assert_eq!(err.error_type, ErrorType::NotFound as i32);
}

/// Helper function to increase a given neuron dissolve_delay.
fn increase_dissolve_delay(
    gov: &mut Governance,
    principal_id: u64,
    neuron_id: u64,
    delay_increase: u32,
) {
    increase_dissolve_delay_raw(
        gov,
        &principal(principal_id),
        NeuronId { id: neuron_id },
        delay_increase,
    )
    .now_or_never()
    .unwrap()
    .expect("Manage neuron failed");
}

/// Tests the command to increase dissolve delay of a given neuron. Tests five
/// scenarios:
/// * A non dissolving neuron and an increment lower than the maximum one.
/// * A non dissolving neuron and an increment higher than the maximum one.
/// * A dissolving neuron and an increment lower than the maximum one.
/// * A dissolving neuron and an increment higher than the maximun one.
/// * A dissolved neuron.
#[test]
fn test_increase_dissolve_delay() {
    let principal_id = 1;
    let fake_driver = fake::FakeDriver::default();
    let fixture: GovernanceProto = GovernanceProto {
        economics: Some(NetworkEconomics::default()),
        neurons: [
            (
                1,
                Neuron {
                    id: Some(NeuronId { id: 1 }),
                    controller: Some(principal(principal_id)),
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
                    )),
                    ..Neuron::default()
                },
            ),
            (
                2,
                Neuron {
                    id: Some(NeuronId { id: 2 }),
                    controller: Some(principal(principal_id)),
                    dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                        DEFAULT_TEST_START_TIMESTAMP_SECONDS
                            + MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS,
                    )),
                    ..Neuron::default()
                },
            ),
            (
                3,
                Neuron {
                    id: Some(NeuronId { id: 3 }),
                    controller: Some(principal(principal_id)),
                    dissolve_state: Some(DissolveState::WhenDissolvedTimestampSeconds(
                        DEFAULT_TEST_START_TIMESTAMP_SECONDS - 1,
                    )),
                    ..Neuron::default()
                },
            ),
        ]
        .to_vec()
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );
    // Tests for neuron 1. Non-dissolving.
    increase_dissolve_delay(&mut gov, principal_id, 1, 1);
    assert_eq!(
        gov.get_neuron(&NeuronId { id: 1 }).unwrap().dissolve_state,
        Some(DissolveState::DissolveDelaySeconds(
            MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS + 1
        ),)
    );
    increase_dissolve_delay(
        &mut gov,
        principal_id,
        1,
        u32::try_from(MAX_DISSOLVE_DELAY_SECONDS + 1)
            .expect("MAX_DISSOLVE_DELAY_SECONDS larger than u32"),
    );
    assert_eq!(
        gov.get_neuron(&NeuronId { id: 1 }).unwrap().dissolve_state,
        Some(DissolveState::DissolveDelaySeconds(
            MAX_DISSOLVE_DELAY_SECONDS
        ),)
    );
    // Tests for neuron 2. Dissolving.
    increase_dissolve_delay(&mut gov, principal_id, 2, 1);
    assert_eq!(
        gov.get_neuron(&NeuronId { id: 2 }).unwrap().dissolve_state,
        Some(DissolveState::WhenDissolvedTimestampSeconds(
            DEFAULT_TEST_START_TIMESTAMP_SECONDS
                + MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS
                + 1,
        ))
    );
    increase_dissolve_delay(
        &mut gov,
        principal_id,
        2,
        u32::try_from(MAX_DISSOLVE_DELAY_SECONDS + 1)
            .expect("MAX_DISSOLVE_DELAY_SECONDS larger than u32"),
    );
    assert_eq!(
        gov.get_neuron(&NeuronId { id: 2 }).unwrap().dissolve_state,
        Some(DissolveState::WhenDissolvedTimestampSeconds(
            DEFAULT_TEST_START_TIMESTAMP_SECONDS + MAX_DISSOLVE_DELAY_SECONDS,
        ))
    );
    // Tests for neuron 3. Dissolved.
    increase_dissolve_delay(
        &mut gov,
        principal_id,
        3,
        u32::try_from(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS)
            .expect("MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS larger than u32"),
    );
    assert_eq!(
        gov.get_neuron(&NeuronId { id: 3 }).unwrap().dissolve_state,
        Some(DissolveState::DissolveDelaySeconds(
            MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS
        ),)
    );
}

// Test scenario. There are three neurons 1, 2, and 3 with stakes 10,
// 20, and 100 ICP. The first neuron is controlled by principal A and
// the second and third by principal B.
//
// At first none of the neurons have joined the community fund. The
// global metric of total ICP in the community fund should be zero and
// the total ICP in neurons should be 130.
//
// Principal A tries to join the community fund for neuron 3. This
// should fail as A is not the controller.
//
// Principal B now tries to join the community fund for neuron 3. This
// should succeed and the global metric should now show that 100 ICP
// are in the community fund.
//
// Principal A tries to join the community fund for neuron 1. This
// should succeed and the global metric should now show 110 ICP in the
// community fund.
//
// The time advances.
//
// Principal B tries to join the community fund for neuron 3
// (again). This should fail as this neuron is already in the
// community fund.
//
// At the end of all this, 110 ICP should be reported as being in the
// community fund and 130 ICP reported as the total ICP in neurons.
#[test]
fn test_join_community_fund() {
    let now = 778899;
    let principal_a = 42;
    let principal_b = 128;
    let fixture: GovernanceProto = GovernanceProto {
        economics: Some(NetworkEconomics::default()),
        neurons: [
            (
                1,
                Neuron {
                    id: Some(NeuronId { id: 1 }),
                    cached_neuron_stake_e8s: 10 * 100_000_000,
                    controller: Some(principal(principal_a)),
                    ..Neuron::default()
                },
            ),
            (
                2,
                Neuron {
                    id: Some(NeuronId { id: 2 }),
                    cached_neuron_stake_e8s: 20 * 100_000_000,
                    controller: Some(principal(principal_b)),
                    ..Neuron::default()
                },
            ),
            (
                3,
                Neuron {
                    id: Some(NeuronId { id: 3 }),
                    cached_neuron_stake_e8s: 100 * 100_000_000,
                    controller: Some(principal(principal_b)),
                    ..Neuron::default()
                },
            ),
        ]
        .to_vec()
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let total_icp_suppply = Tokens::new(200, 0).unwrap();
    let mut driver = fake::FakeDriver::default()
        .at(60 * 60 * 24 * 30)
        .with_supply(total_icp_suppply);
    let mut gov = Governance::new(fixture, driver.get_fake_env(), driver.get_fake_ledger());
    {
        let actual_metrics = gov.proto.compute_cached_metrics(now, total_icp_suppply);
        assert_eq!(200, actual_metrics.total_supply_icp);
        assert_eq!(130 * 100_000_000, actual_metrics.total_staked_e8s);
        assert_eq!(0, actual_metrics.community_fund_total_staked_e8s);
    }
    // Try to join community fund with the wrong controller (A instead of B).
    {
        let result = gov
            .manage_neuron(
                &principal(principal_a),
                &ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: 3,
                    })),
                    command: Some(manage_neuron::Command::Configure(
                        manage_neuron::Configure {
                            operation: Some(Operation::JoinCommunityFund(JoinCommunityFund {})),
                        },
                    )),
                },
            )
            .now_or_never()
            .unwrap();
        assert_eq!(ErrorType::NotAuthorized, result.err().unwrap().error_type());
    }
    // Join the community fund for neuron 3.
    {
        let result = gov
            .manage_neuron(
                &principal(principal_b),
                &ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: 3,
                    })),
                    command: Some(manage_neuron::Command::Configure(
                        manage_neuron::Configure {
                            operation: Some(Operation::JoinCommunityFund(JoinCommunityFund {})),
                        },
                    )),
                },
            )
            .now_or_never()
            .unwrap();
        assert!(result.is_ok());
        let actual_metrics = gov.proto.compute_cached_metrics(now, total_icp_suppply);
        assert_eq!(200, actual_metrics.total_supply_icp);
        assert_eq!(130 * 100_000_000, actual_metrics.total_staked_e8s);
        assert_eq!(
            100 * 100_000_000,
            actual_metrics.community_fund_total_staked_e8s
        );
        // 30 days in now
        assert_eq!(
            60 * 60 * 24 * 30,
            gov.proto
                .neurons
                .get(&3)
                .unwrap()
                .joined_community_fund_timestamp_seconds
                .unwrap_or(0)
        );
        // Check that neuron info displays the same information.
        let neuron_info = gov.get_neuron_info(&NeuronId { id: 3 }).unwrap();
        assert_eq!(
            60 * 60 * 24 * 30,
            neuron_info
                .joined_community_fund_timestamp_seconds
                .unwrap_or(0)
        );
    }
    // Advance time by two days...
    driver.advance_time_by(60 * 60 * 24 * 2);
    // Join the community fund for neuron 1.
    {
        let result = gov
            .manage_neuron(
                &principal(principal_a),
                &ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: 1,
                    })),
                    command: Some(manage_neuron::Command::Configure(
                        manage_neuron::Configure {
                            operation: Some(Operation::JoinCommunityFund(JoinCommunityFund {})),
                        },
                    )),
                },
            )
            .now_or_never()
            .unwrap();
        assert!(result.is_ok());
        let actual_metrics = gov.proto.compute_cached_metrics(now, total_icp_suppply);
        assert_eq!(200, actual_metrics.total_supply_icp);
        assert_eq!(130 * 100_000_000, actual_metrics.total_staked_e8s);
        assert_eq!(
            110 * 100_000_000,
            actual_metrics.community_fund_total_staked_e8s
        );
        // 32 days in now
        assert_eq!(
            60 * 60 * 24 * 32,
            gov.proto
                .neurons
                .get(&1)
                .unwrap()
                .joined_community_fund_timestamp_seconds
                .unwrap_or(0)
        );
    }
    // Principal B tries to join the community fund for neuron 3
    // (again). This should fail as this neuron is already in the
    // community fund.
    {
        let result = gov
            .manage_neuron(
                &principal(principal_b),
                &ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: 3,
                    })),
                    command: Some(manage_neuron::Command::Configure(
                        manage_neuron::Configure {
                            operation: Some(Operation::JoinCommunityFund(JoinCommunityFund {})),
                        },
                    )),
                },
            )
            .now_or_never()
            .unwrap();
        assert_eq!(
            ErrorType::AlreadyJoinedCommunityFund,
            result.err().unwrap().error_type()
        );
    }
    // Run periodic tasks to populate metrics. Need to call it twice
    // as the first call will just distribute rewards.
    gov.run_periodic_tasks().now_or_never();
    gov.run_periodic_tasks().now_or_never();
    let actual_metrics = gov.proto.metrics.unwrap();
    assert_eq!(200, actual_metrics.total_supply_icp);
    assert_eq!(130 * 100_000_000, actual_metrics.total_staked_e8s);
    assert_eq!(
        110 * 100_000_000,
        actual_metrics.community_fund_total_staked_e8s
    );
    // Neuron 2 is not in the fund.
    assert_eq!(
        0,
        gov.proto
            .neurons
            .get(&2)
            .unwrap()
            .joined_community_fund_timestamp_seconds
            .unwrap_or(0)
    );
}

/// Struct to help with the wait for quiet tests.
struct NeuronVote {
    vote_and_time: Option<(Vote, u64)>,
    stake: u64,
}

/// Helper function for testing wait for quiet.
/// The idea is to simplify testing different voting dynamics.
///
/// Takes as inputs:
/// - The initial duration of the voting period
/// - A vector of neuron votes, representing what neurons are in the system, and
///   when and how they vote.
///
/// Returns the governance mock and the proposal id.
fn wait_for_quiet_test_helper(
    initial_expiration_seconds: u64,
    in_neuron_votes: &mut Vec<NeuronVote>,
) -> (Governance, ProposalId, u64) {
    let mut neuron_votes = vec![NeuronVote {
        vote_and_time: Some((Vote::Yes, 0)),
        stake: 1,
    }];
    neuron_votes.append(in_neuron_votes);
    neuron_votes.sort_by(|a, b| match (a.vote_and_time, b.vote_and_time) {
        (Some((_, a_time)), Some((_, b_time))) => a_time.cmp(&b_time),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        _ => Ordering::Equal,
    });
    let mut fake_driver = fake::FakeDriver::default();
    let fixture = GovernanceProto {
        economics: Some(NetworkEconomics::default()),
        neurons: neuron_votes
            .iter()
            .enumerate()
            .map(|(i, neuron_vote)| {
                (
                    i as u64,
                    Neuron {
                        id: Some(NeuronId { id: i as u64 }),
                        dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                        controller: Some(principal(i as u64)),
                        cached_neuron_stake_e8s: neuron_vote.stake,
                        ..Neuron::default()
                    },
                )
            })
            .collect::<HashMap<u64, Neuron>>(),
        wait_for_quiet_threshold_seconds: initial_expiration_seconds,
        ..Default::default()
    };

    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
    );
    let pid = gov
        .make_proposal(
            &NeuronId { id: 0 },
            // Must match neuron 1's serialized_id.
            &principal(0),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "Summary".to_string(),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "Some proposal".to_string(),
                })),
                ..Default::default()
            },
        )
        .unwrap();
    let expected_initial_deadline_seconds =
        DEFAULT_TEST_START_TIMESTAMP_SECONDS + initial_expiration_seconds;
    let initial_deadline_seconds = gov
        .get_proposal_data(ProposalId { id: 1 })
        .unwrap()
        .wait_for_quiet_state
        .as_ref()
        .unwrap()
        .current_deadline_timestamp_seconds;
    assert_eq!(expected_initial_deadline_seconds, initial_deadline_seconds);
    let mut time_since_proposal_seconds = 0;
    for (i, neuron_vote) in neuron_votes.iter().enumerate().skip(1) {
        if let Some(vote_and_time) = neuron_vote.vote_and_time {
            fake_driver.advance_time_by(vote_and_time.1 - time_since_proposal_seconds);
            time_since_proposal_seconds = vote_and_time.1;
            fake::register_vote_assert_success(
                &mut gov,
                principal(i as u64),
                NeuronId { id: i as u64 },
                pid,
                vote_and_time.0,
            );
        } else {
            break;
        }
    }
    (gov, pid, initial_deadline_seconds)
}

/// Simulates the situation in which there is a big voter close to the deadline
/// that votes against the trend. Asserts the deadline has moved by at least
/// half of the possible delay, but not more than the maximum.
#[test]
fn test_wfq_big_late_voter_delay() {
    let initial_expiration_seconds = 1000;
    let mut neuron_votes = vec![
        NeuronVote {
            vote_and_time: Some((Vote::Yes, 1)),
            stake: 100_000_000,
        },
        NeuronVote {
            vote_and_time: Some((Vote::No, 900)),
            stake: 100_000_002,
        },
        NeuronVote {
            vote_and_time: None,
            stake: 10_000_000,
        },
    ];
    let (gov, pid, initial_deadline_seconds) =
        wait_for_quiet_test_helper(initial_expiration_seconds, &mut neuron_votes);
    let deadline_after_test = gov
        .get_proposal_data(pid)
        .unwrap()
        .wait_for_quiet_state
        .as_ref()
        .unwrap()
        .current_deadline_timestamp_seconds;
    assert!(
        deadline_after_test
            > initial_deadline_seconds + WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS / 2
    );
    assert!(
        deadline_after_test < initial_deadline_seconds + WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS
    );
}

/// Simulates a similar situation to the previous test, with the difference that
/// the big voter reaches a majority, so there is no point in extending the
/// deadline.
#[test]
fn test_wfq_majority_reached_no_delay() {
    let initial_expiration_seconds = 1000;
    let mut neuron_votes = vec![
        NeuronVote {
            vote_and_time: Some((Vote::Yes, 1)),
            stake: 100_000_000,
        },
        NeuronVote {
            vote_and_time: Some((Vote::No, 900)),
            stake: 200_000_000,
        },
    ];
    let (gov, pid, initial_deadline_seconds) =
        wait_for_quiet_test_helper(initial_expiration_seconds, &mut neuron_votes);
    let deadline_after_test = gov
        .get_proposal_data(pid)
        .unwrap()
        .wait_for_quiet_state
        .as_ref()
        .unwrap()
        .current_deadline_timestamp_seconds;
    assert!(
        deadline_after_test
            < initial_deadline_seconds + WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS / 20
    );
}

/// Simulates a situation in wich most of the voting is done at the beginning of
/// the interval and there is no controversy. In such situation there should be
/// no effect on the deadline.
#[test]
fn test_wfq_low_noise() {
    let initial_expiration_seconds = 1000;
    let mut neuron_votes = vec![
        NeuronVote {
            vote_and_time: Some((Vote::Yes, 10)),
            stake: 100_000_000,
        },
        NeuronVote {
            vote_and_time: Some((Vote::Yes, 100)),
            stake: 100_000_000,
        },
        NeuronVote {
            vote_and_time: Some((Vote::Yes, 250)),
            stake: 100_000_000,
        },
        NeuronVote {
            vote_and_time: None,
            stake: 500_000_000,
        },
    ];
    let (gov, pid, initial_deadline_seconds) =
        wait_for_quiet_test_helper(initial_expiration_seconds, &mut neuron_votes);
    let deadline_after_test = gov
        .get_proposal_data(pid)
        .unwrap()
        .wait_for_quiet_state
        .as_ref()
        .unwrap()
        .current_deadline_timestamp_seconds;
    assert_eq!(deadline_after_test, initial_deadline_seconds);
}

/// simulates a situation in which there are multiple swings close to the
/// deadline, extending it several times. Checks that the deadline has been
/// extended more than the maximum (thus has been extended several times).
#[test]
fn test_wfq_multiple_delays() {
    let initial_expiration_seconds = 1000;
    let mut neuron_votes = vec![
        NeuronVote {
            vote_and_time: Some((Vote::No, 10)),
            stake: 100_000_000,
        },
        NeuronVote {
            vote_and_time: Some((Vote::Yes, 900)),
            stake: 100_000_000,
        },
        NeuronVote {
            vote_and_time: Some((Vote::No, 32200)),
            stake: 100_000_000,
        },
        NeuronVote {
            vote_and_time: Some((Vote::Yes, 51000)),
            stake: 100_000_000,
        },
        NeuronVote {
            vote_and_time: None,
            stake: 1_000_000,
        },
    ];
    let (gov, pid, initial_deadline_seconds) =
        wait_for_quiet_test_helper(initial_expiration_seconds, &mut neuron_votes);
    let deadline_after_test = gov
        .get_proposal_data(pid)
        .unwrap()
        .wait_for_quiet_state
        .as_ref()
        .unwrap()
        .current_deadline_timestamp_seconds;
    assert!(
        deadline_after_test > initial_deadline_seconds + WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS
    );
}

/// Real voting data
#[test]
fn test_wfq_real_data() {
    let initial_expiration_seconds = ONE_DAY_SECONDS;
    let mut neuron_votes = {
        vec![
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 0)),
                stake: 353515574,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 234)),
                stake: 97193797941,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 745)),
                stake: 2042085059,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 1416)),
                stake: 6142394930,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 1590)),
                stake: 43161041120,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 2340)),
                stake: 205898650248,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 2636)),
                stake: 25698159726,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 3016)),
                stake: 2466839372,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 3744)),
                stake: 57217848385,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 3777)),
                stake: 10707432666,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 4000)),
                stake: 1281383126386,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 4056)),
                stake: 7445855878,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 4453)),
                stake: 129231509,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 5043)),
                stake: 797768017,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 5696)),
                stake: 206694565,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 5708)),
                stake: 313220629653,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 6857)),
                stake: 11928697907,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 7897)),
                stake: 4363900439,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 8867)),
                stake: 93273975020,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 9318)),
                stake: 769701244,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 9640)),
                stake: 2330877624,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 12482)),
                stake: 10066532378,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 13796)),
                stake: 41257526769,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 14671)),
                stake: 201314526,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 14806)),
                stake: 2765532993,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 15659)),
                stake: 215871429,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 16716)),
                stake: 2954208069,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 16889)),
                stake: 175619576694,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 17201)),
                stake: 2983554526,
            },
            NeuronVote {
                vote_and_time: Some((Vote::No, 17220)),
                stake: 28132394322,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 18049)),
                stake: 6965879980,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 19845)),
                stake: 34841385360,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 19953)),
                stake: 10447089553,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 20223)),
                stake: 61615796398,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 20363)),
                stake: 569604644,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 21112)),
                stake: 3661210208,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 21586)),
                stake: 845886788,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 21884)),
                stake: 1015526376,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 22921)),
                stake: 9073764808,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 22985)),
                stake: 5149255219,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 24260)),
                stake: 100427188890,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 24407)),
                stake: 762337331757,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 24580)),
                stake: 562111058,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 24597)),
                stake: 1218235448,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 25344)),
                stake: 1138636112,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 25356)),
                stake: 845812914,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 26174)),
                stake: 1852836133,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 26532)),
                stake: 2802337531,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 28178)),
                stake: 20243100661,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 28254)),
                stake: 58313880182,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 28940)),
                stake: 2980472480,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 29380)),
                stake: 223138436,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 29428)),
                stake: 2364063637,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 29484)),
                stake: 108447910,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 29910)),
                stake: 18929068975,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 30300)),
                stake: 225405974033,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 30733)),
                stake: 737832810,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 30953)),
                stake: 1083769179347,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 31433)),
                stake: 1387194081,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 32962)),
                stake: 4012112347,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 33052)),
                stake: 1677393462,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 33657)),
                stake: 1915715598,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 34483)),
                stake: 1843348693,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 36320)),
                stake: 111612460,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 36640)),
                stake: 5029065765,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 37785)),
                stake: 12271928291,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 38974)),
                stake: 228832259,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 40059)),
                stake: 36253363346,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 40113)),
                stake: 3194934230,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 41400)),
                stake: 36178052230,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 41637)),
                stake: 3035352446,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 43810)),
                stake: 7649273646,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 44108)),
                stake: 1010202599,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 44171)),
                stake: 5631956256142,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 44776)),
                stake: 22527023403,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 47001)),
                stake: 37765872796,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 47973)),
                stake: 3041822169,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 49349)),
                stake: 2665743133,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 49403)),
                stake: 509910798,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 49704)),
                stake: 5199038411,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 50691)),
                stake: 4516531632,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 53254)),
                stake: 832702964,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 53943)),
                stake: 4104424750,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 56791)),
                stake: 998839134,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 57849)),
                stake: 20157812743,
            },
            NeuronVote {
                vote_and_time: Some((Vote::No, 58321)),
                stake: 6035055556,
            },
            NeuronVote {
                vote_and_time: Some((Vote::No, 58383)),
                stake: 30705095819,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 58803)),
                stake: 529001961,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 59307)),
                stake: 43955612349,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 59897)),
                stake: 3267094884,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 60101)),
                stake: 154689073,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 60913)),
                stake: 13572846359,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 62780)),
                stake: 32588091077,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 62879)),
                stake: 150145019,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 66011)),
                stake: 1543084015,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 67048)),
                stake: 1081324123442,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 67100)),
                stake: 32884140137,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 67743)),
                stake: 63393687969,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 70078)),
                stake: 401310940,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 70944)),
                stake: 444573411,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 71604)),
                stake: 4692964656,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 76507)),
                stake: 10639628606,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 77615)),
                stake: 1820002001,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 78719)),
                stake: 533205724612,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 82884)),
                stake: 4029578423,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 87128)),
                stake: 2914734043,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 87826)),
                stake: 1680165373,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 87902)),
                stake: 401670146,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 92758)),
                stake: 4006259449,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 93841)),
                stake: 52060043788,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 96009)),
                stake: 6362738860,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 99285)),
                stake: 360839700,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 100107)),
                stake: 5516219444,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 100378)),
                stake: 38680923792,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 102312)),
                stake: 5729420131,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 105941)),
                stake: 4637595636,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 110022)),
                stake: 3099824893,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 110550)),
                stake: 127837960,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 111492)),
                stake: 7804039761,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 115478)),
                stake: 804053523,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 117338)),
                stake: 11046054044,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 117627)),
                stake: 4167123167,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 119873)),
                stake: 10679212233,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 123023)),
                stake: 7067247894,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 124423)),
                stake: 25205259292,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 124759)),
                stake: 20193617638,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 128298)),
                stake: 37509111570,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 134194)),
                stake: 938369667,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 138752)),
                stake: 1792599974,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 141300)),
                stake: 470598467,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 141628)),
                stake: 1228253327444,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 144399)),
                stake: 1972124675,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 146500)),
                stake: 221626989,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 149343)),
                stake: 4368358092,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 150521)),
                stake: 60091650988,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 150535)),
                stake: 277604120,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 150826)),
                stake: 1118685913,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 151448)),
                stake: 3462015793628,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 151507)),
                stake: 1852741327,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 152801)),
                stake: 3441305840,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 153089)),
                stake: 2000530886,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 153902)),
                stake: 12644131151,
            },
            NeuronVote {
                vote_and_time: Some((Vote::Yes, 154197)),
                stake: 3123690897615595,
            },
        ]
    };
    let (gov, pid, initial_deadline_seconds) =
        wait_for_quiet_test_helper(initial_expiration_seconds, &mut neuron_votes);
    let deadline_after_test = gov
        .get_proposal_data(pid)
        .unwrap()
        .wait_for_quiet_state
        .as_ref()
        .unwrap()
        .current_deadline_timestamp_seconds;
    //TODO(alejandro): How much should the deadline be extended in this case?
    assert!(
        deadline_after_test < initial_deadline_seconds + WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS
    );
}

/// Tests a situation in which the majority changes with every vote, with a vote
/// every 20s.
#[test]
fn test_wfq_constant_flipping() {
    let initial_expiration_seconds = 4 * ONE_DAY_SECONDS;
    let mut neuron_votes: Vec<NeuronVote> = vec![NeuronVote {
        vote_and_time: Some((Vote::Yes, 1)),
        stake: 10,
    }];

    for i in 1..ONE_DAY_SECONDS / 10 {
        let vote: Vote;
        if i % 2 == 0 {
            vote = Vote::Yes;
        } else {
            vote = Vote::No;
        }
        neuron_votes.push(NeuronVote {
            vote_and_time: Some((vote, 80 * i as u64)),
            stake: 20,
        })
    }
    let (gov, pid, initial_deadline_seconds) =
        wait_for_quiet_test_helper(initial_expiration_seconds, &mut neuron_votes);
    let deadline_after_test = gov
        .get_proposal_data(pid)
        .unwrap()
        .wait_for_quiet_state
        .as_ref()
        .unwrap()
        .current_deadline_timestamp_seconds;

    assert!(deadline_after_test <= initial_deadline_seconds + 4 * ONE_DAY_SECONDS);
    // Assert that the deadline is moved by 96 hours.
    assert!(deadline_after_test <= DEFAULT_TEST_START_TIMESTAMP_SECONDS + 8 * ONE_DAY_SECONDS);
    assert!(
        deadline_after_test >= DEFAULT_TEST_START_TIMESTAMP_SECONDS + 8 * ONE_DAY_SECONDS - 600
    );
}

/// Test for the known neuron functionality.
///
/// The test does the following:
/// - Start with 3 neurons, none of them "known".
/// - Register a name for two of them.
/// - Assert than when querying the known neurons by id the result is the
///   expected one.
/// - Assert than when querying all known neurons the result is the expected
///   one.
/// - Try Updating one Neuron with the name of the other, this should not succeed.
/// - Verify that nothing is changed, the previous proposal did not succeed.
/// - Update the name of one of the neurons, with a new name.
/// - Assert than when querying the neuron the updated name is correct.
#[test]
fn test_known_neurons() {
    let driver = fake::FakeDriver::default();
    let neurons = [
        (
            1,
            Neuron {
                id: Some(NeuronId { id: 1 }),
                controller: Some(principal(1)),
                cached_neuron_stake_e8s: 100_000_000,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                    MAX_DISSOLVE_DELAY_SECONDS,
                )),
                ..Default::default()
            },
        ),
        (
            2,
            Neuron {
                id: Some(NeuronId { id: 2 }),
                controller: Some(principal(2)),
                cached_neuron_stake_e8s: 100_000_000,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                    MAX_DISSOLVE_DELAY_SECONDS,
                )),
                ..Default::default()
            },
        ),
        (
            3,
            Neuron {
                id: Some(NeuronId { id: 3 }),
                controller: Some(principal(3)),
                cached_neuron_stake_e8s: 100_000_000_000,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                    MAX_DISSOLVE_DELAY_SECONDS,
                )),
                ..Default::default()
            },
        ),
    ]
    .to_vec()
    .into_iter()
    .collect();
    let governance_proto = GovernanceProto {
        economics: Some(NetworkEconomics::with_default_values()),
        neurons,
        ..Default::default()
    };
    let mut gov = Governance::new(
        governance_proto,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );

    gov.make_proposal(
        &NeuronId { id: 3 },
        &principal(3),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "proposal 1 summary".to_string(),
            action: Some(proposal::Action::RegisterKnownNeuron(KnownNeuron {
                id: Some(NeuronId { id: 1 }),
                known_neuron_data: Some(KnownNeuronData {
                    name: "One".to_string(),
                    description: None,
                }),
            })),
            ..Default::default()
        },
    )
    .unwrap();

    gov.make_proposal(
        &NeuronId { id: 3 },
        &principal(3),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "proposal 2 summary".to_string(),
            action: Some(proposal::Action::RegisterKnownNeuron(KnownNeuron {
                id: Some(NeuronId { id: 2 }),
                known_neuron_data: Some(KnownNeuronData {
                    name: "Two".to_string(),
                    description: None,
                }),
            })),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        gov.get_neuron_info(&NeuronId { id: 1 })
            .unwrap()
            .known_neuron_data
            .unwrap()
            .name,
        "One".to_string()
    );
    let expected_known_neurons = vec![
        KnownNeuron {
            id: Some(NeuronId { id: 1 }),
            known_neuron_data: Some(KnownNeuronData {
                name: "One".to_string(),
                description: None,
            }),
        },
        KnownNeuron {
            id: Some(NeuronId { id: 2 }),
            known_neuron_data: Some(KnownNeuronData {
                name: "Two".to_string(),
                description: None,
            }),
        },
    ];
    let mut sorted_response_known_neurons = gov.list_known_neurons().known_neurons;
    sorted_response_known_neurons
        .sort_by(|a, b| a.id.as_ref().unwrap().id.cmp(&b.id.as_ref().unwrap().id));
    assert_eq!(sorted_response_known_neurons, expected_known_neurons);

    // This proposal tries to name neuron 1 with the already existing name "Two", the change should not be executed.
    let failed_proposal_id = gov
        .make_proposal(
            &NeuronId { id: 3 },
            &principal(3),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "proposal 3 summary".to_string(),
                action: Some(proposal::Action::RegisterKnownNeuron(KnownNeuron {
                    id: Some(NeuronId { id: 1 }),
                    known_neuron_data: Some(KnownNeuronData {
                        name: "Two".to_string(),
                        description: None,
                    }),
                })),
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(
        gov.get_proposal_info(&principal(3), failed_proposal_id)
            .unwrap()
            .status(),
        ProposalStatus::Failed
    );

    // Check that the state is the same as before the last proposal.
    let mut sorted_response_known_neurons = gov.list_known_neurons().known_neurons;
    sorted_response_known_neurons
        .sort_by(|a, b| a.id.as_ref().unwrap().id.cmp(&b.id.as_ref().unwrap().id));
    assert_eq!(sorted_response_known_neurons, expected_known_neurons);

    // Update the name of neuron 2.
    gov.make_proposal(
        &NeuronId { id: 3 },
        &principal(3),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "proposal 4 summary".to_string(),
            action: Some(proposal::Action::RegisterKnownNeuron(KnownNeuron {
                id: Some(NeuronId { id: 2 }),
                known_neuron_data: Some(KnownNeuronData {
                    name: "Zwei".to_string(),
                    description: None,
                }),
            })),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        gov.get_neuron_info(&NeuronId { id: 2 })
            .unwrap()
            .known_neuron_data
            .unwrap()
            .name,
        "Zwei".to_string()
    );

    let expected_known_neuron_name_set: HashSet<String> = ["One".to_string(), "Zwei".to_string()]
        .iter()
        .cloned()
        .collect();
    assert_eq!(expected_known_neuron_name_set, gov.known_neuron_name_set);
}

#[test]
fn test_no_proposal_title_is_invalid() {
    let result = validate_proposal_title(&None);
    assert!(!result.is_ok());
}

#[test]
fn test_short_proposal_title_is_invalid() {
    let result = validate_proposal_title(&Some("hi".to_string()));
    assert!(!result.is_ok());
}

#[test]
fn test_long_proposal_title_is_invalid() {
    let mut long_title = String::new();
    for _ in 0..300 {
        long_title.push('Z');
    }

    let result = validate_proposal_title(&Some(long_title));
    assert!(!result.is_ok());
}

#[test]
fn test_accept_reasonable_proposal_title() {
    let result = validate_proposal_title(&Some("When In The Course of Human Events".to_string()));
    assert!(result.is_ok());
}
