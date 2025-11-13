//! The unit tests for `Governance` use *test fixtures*. The fixtures
//! are defi data_source: (), timestamp_seconds: ()ned as small but
//! complex/weird configurations of neurons and proposals against which several
//! tests are run.
use crate::fake::{
    DAPP_CANISTER_ID, DEVELOPER_PRINCIPAL_ID, NODE_PROVIDER_REWARD, SNS_GOVERNANCE_CANISTER_ID,
    SNS_LEDGER_ARCHIVE_CANISTER_ID, SNS_LEDGER_CANISTER_ID, SNS_LEDGER_INDEX_CANISTER_ID,
    SNS_ROOT_CANISTER_ID, TARGET_SWAP_CANISTER_ID,
};
use assert_matches::assert_matches;
use async_trait::async_trait;
use candid::{Decode, Encode};
use common::increase_dissolve_delay_raw;
use fixtures::{NNSBuilder, NeuronBuilder, account, new_motion_proposal, principal};
use futures::future::FutureExt;
use ic_base_types::{CanisterId, NumBytes, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_nervous_system_clients::canister_status::{
    CanisterStatusResultV2, CanisterStatusType, MemoryMetricsFromManagementCanister,
};
use ic_nervous_system_common::{
    E8, NervousSystemError, ONE_DAY_SECONDS, ONE_MONTH_SECONDS, ONE_YEAR_SECONDS, ledger,
    ledger::compute_neuron_staking_subaccount_bytes,
};
use ic_nervous_system_common_test_keys::{
    TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
};
use ic_nervous_system_common_test_utils::{LedgerReply, SpyLedger};
use ic_nervous_system_proto::pb::v1::{Decimal, Duration, GlobalTimeOfDay, Percentage};
use ic_nervous_system_timers::test::{
    run_pending_timers, run_pending_timers_every_interval_for_count,
};
use ic_neurons_fund::{
    NeuronsFundParticipationLimits, PolynomialMatchingFunction, SerializableFunction,
};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance::governance::MINIMUM_SECONDS_BETWEEN_ALLOWANCE_INCREASE;
#[cfg(feature = "tla")]
use ic_nns_governance::governance::tla::{TLA_TRACES_LKEY, check_traces as tla_check_traces};
use ic_nns_governance::storage::reset_stable_memory;
use ic_nns_governance::timer_tasks::schedule_tasks;
use ic_nns_governance::{
    DEFAULT_VOTING_POWER_REFRESHED_TIMESTAMP_SECONDS,
    governance::{
        Environment, Governance, HeapGrowthPotential, INITIAL_NEURON_DISSOLVE_DELAY,
        MAX_DISSOLVE_DELAY_SECONDS, MAX_NEURON_AGE_FOR_AGE_BONUS, MAX_NEURON_CREATION_SPIKE,
        MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS, PROPOSAL_MOTION_TEXT_BYTES_MAX,
        REWARD_DISTRIBUTION_PERIOD_SECONDS, WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS,
        get_node_provider_reward,
        test_data::{
            CREATE_SERVICE_NERVOUS_SYSTEM, CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING,
        },
    },
    governance_proto_builder::GovernanceProtoBuilder,
    pb::v1::{
        AddOrRemoveNodeProvider, Ballot, BallotInfo, CreateServiceNervousSystem, Empty,
        ExecuteNnsFunction, Followees, GovernanceError, IdealMatchedParticipationFunction,
        InstallCode, KnownNeuron, KnownNeuronData, ManageNeuron, MonthlyNodeProviderRewards,
        Motion, NetworkEconomics, NeuronType, NeuronsFundData, NeuronsFundEconomics,
        NeuronsFundMatchedFundingCurveCoefficients, NeuronsFundParticipation, NeuronsFundSnapshot,
        NnsFunction, NodeProvider, Proposal, ProposalData,
        ProposalRewardStatus::{self, AcceptVotes, ReadyToSettle},
        ProposalStatus::{self, Rejected},
        RewardEvent, RewardNodeProvider, RewardNodeProviders,
        SettleNeuronsFundParticipationRequest, SwapBackgroundInformation, SwapParticipationLimits,
        Tally, Topic, UpdateNodeProvider, Visibility, Vote, VotingPowerEconomics,
        WaitForQuietState,
        add_or_remove_node_provider::Change,
        governance::GovernanceCachedMetrics,
        governance_error::ErrorType::{
            self, InsufficientFunds, NotAuthorized, NotFound, ResourceExhausted,
        },
        install_code::CanisterInstallMode,
        manage_neuron::{
            self, ChangeAutoStakeMaturity, ClaimOrRefresh, Command, Configure, Disburse,
            DisburseToNeuron, IncreaseDissolveDelay, JoinCommunityFund, LeaveCommunityFund,
            MergeMaturity, NeuronIdOrSubaccount, RefreshVotingPower, SetVisibility, Spawn, Split,
            StartDissolving,
            claim_or_refresh::{By, MemoAndController},
            configure::Operation,
            disburse::Amount,
        },
        neurons_fund_snapshot::NeuronsFundNeuronPortion,
        proposal::{self, Action},
        reward_node_provider::{RewardMode, RewardToAccount, RewardToNeuron},
        settle_neurons_fund_participation_request, swap_background_information,
    },
};
use ic_nns_governance::{
    canister_state::{governance_mut, set_governance_for_tests},
    pb::v1::{Account, Subaccount as GovernanceSubaccount, manage_neuron::DisburseMaturity},
};
use ic_nns_governance::{governance::RandomnessGenerator, pb::v1::manage_neuron::Follow};
use ic_nns_governance_api::{
    self as api, CreateServiceNervousSystem as ApiCreateServiceNervousSystem, ListNeurons,
    ListNeuronsResponse, ManageNeuronResponse, NeuronInfo, NeuronState,
    manage_neuron_response::{self, Command as CommandResponse, ConfigureResponse},
    proposal::Action as ApiAction,
    proposal_validation::validate_proposal_title,
};
use ic_nns_governance_init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_root::{GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse};
use ic_sns_swap::pb::v1::{
    self as sns_swap_pb,
    IdealMatchedParticipationFunction as IdealMatchedParticipationFunctionSwapPb, Lifecycle,
    LinearScalingCoefficient, NeuronsFundParticipationConstraints,
};
use ic_sns_wasm::pb::v1::{
    DeployNewSnsRequest, DeployNewSnsResponse, DeployedSns, ListDeployedSnsesRequest,
    ListDeployedSnsesResponse, SnsWasmError,
};
use icp_ledger::{
    AccountIdentifier, Memo, Subaccount, Tokens,
    protobuf::AccountIdentifier as AccountIdentifierProto,
};
use lazy_static::lazy_static;
use maplit::{btreemap, btreeset, hashmap};
use pretty_assertions::{assert_eq, assert_ne};
use proptest::prelude::{ProptestConfig, proptest};
use rand::{Rng, SeedableRng, prelude::IteratorRandom, rngs::StdRng};
use registry_canister::mutations::do_add_node_operator::AddNodeOperatorPayload;
use rust_decimal_macros::dec;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    convert::{TryFrom, TryInto},
    iter::once,
    path::PathBuf,
    sync::{Arc, Mutex},
};
#[cfg(feature = "tla")]
use tla_instrumentation_proc_macros::with_tla_trace_check;

/// The 'fake' module is the old scheme for providing NNS test fixtures, aka
/// the FakeDriver. It is being used here until the older tests have been
/// ported to the new 'fixtures' module.
mod fake;

// Using a `pub mod` works around spurious dead code warnings; see
// https://github.com/rust-lang/rust/issues/46379
pub mod fixtures;

// Using a `pub mod` works around spurious dead code warnings; see
// https://github.com/rust-lang/rust/issues/46379
pub mod common;

// Some time in Oct, 2024. There is nothing magical about this value. The only
// thing special about it is that it is "realistic". This was chosen by simply
// looking at the clock.
const START_TIMESTAMP_SECONDS: u64 = 1730132754;

lazy_static! {
    static ref RANDOM_PRINCIPAL_ID: PrincipalId = PrincipalId::new_user_test_id(0xDEAD_BEEF);
}

const DEFAULT_TEST_START_TIMESTAMP_SECONDS: u64 = 999_111_000_u64;

const RANDOM_U64: u64 = 0_u64;

const USUAL_REWARD_POT_E8S: u64 = 100;

const NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE: Option<api::neuron::DissolveState> =
    Some(api::neuron::DissolveState::DissolveDelaySeconds(
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
    ));

const NOTDISSOLVING_MAX_DISSOLVE_DELAY: Option<api::neuron::DissolveState> = Some(
    api::neuron::DissolveState::DissolveDelaySeconds(MAX_DISSOLVE_DELAY_SECONDS),
);

const MANAGER_ID: u64 = 1000;
const NEURON_1_CONTROLLER: u64 = 100;
const NEURON_2_CONTROLLER: u64 = 100;
const NEURON_3_CONTROLLER: u64 = 200;

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

/// Submits a proposal, votes on it as instructed, and then verifies:
/// - that the proposal status, immediately after voting, is as expected
/// - that the proposal status, after proposal expiration, is as expected
///
/// To simplify test setup:
/// - The rejection fee is set to zero
/// - all votes happen at proposal creation time.
/// - uses an arbitrary duration for proposal expiration time.
fn check_proposal_status_after_voting_and_after_expiration(
    neurons: impl IntoIterator<Item = api::Neuron>,
    behavior: impl Into<fake::ProposalNeuronBehavior>,
    expected_after_voting: ProposalStatus,
    expected_after_expiration: ProposalStatus,
) {
    reset_stable_memory();
    let expiration_seconds = 17; // Arbitrary duration
    let network_economics = api::NetworkEconomics {
        reject_cost_e8s: 0,          // It's the default, but specify for emphasis
        neuron_minimum_stake_e8s: 0, // It's the default, but specify for emphasis
        ..api::NetworkEconomics::with_default_values()
    };
    let mut fake_driver = fake::FakeDriver::default();

    let neurons = neurons
        .into_iter()
        .zip(0_u64..)
        .map(|(neuron, i)| api::Neuron {
            id: Some(NeuronId { id: i }),
            controller: Some(principal(i)),
            account: fake_driver
                .random_byte_array()
                .expect("Could not get random byte array")
                .to_vec(),
            ..neuron
        })
        .collect();

    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(network_economics)
        .with_neurons(neurons)
        .with_wait_for_quiet_threshold(expiration_seconds)
        .build();

    let mut gov = Governance::new(
        governance_proto,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
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
        vec![api::Neuron {
            dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
            cached_neuron_stake_e8s: 1,
            ..api::Neuron::default()
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
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..api::Neuron::default()
            },
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..api::Neuron::default()
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
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..api::Neuron::default()
            },
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..api::Neuron::default()
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
fn test_two_neuron_disagree_identical_voting_power_one_does_not_vote_proposal_should_rejected_at_expiration()
 {
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..api::Neuron::default()
            },
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 40,
                ..api::Neuron::default()
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
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 8,
                ..api::Neuron::default()
            },
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 7,
                ..api::Neuron::default()
            },
        ],
        "P-",
        ProposalStatus::Executed,
        ProposalStatus::Executed,
    );
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 400,
                ..api::Neuron::default()
            },
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 7,
                ..api::Neuron::default()
            },
        ],
        "nP",
        ProposalStatus::Rejected,
        ProposalStatus::Rejected,
    );
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 400,
                ..api::Neuron::default()
            },
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 7,
                ..api::Neuron::default()
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
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MAX_DISSOLVE_DELAY,
                cached_neuron_stake_e8s: 1,
                ..api::Neuron::default()
            },
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..api::Neuron::default()
            },
        ],
        "P-",
        ProposalStatus::Executed,
        ProposalStatus::Executed,
    );
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MAX_DISSOLVE_DELAY,
                cached_neuron_stake_e8s: 21,
                ..api::Neuron::default()
            },
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..api::Neuron::default()
            },
        ],
        "nP",
        ProposalStatus::Rejected,
        ProposalStatus::Rejected,
    );
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MAX_DISSOLVE_DELAY,
                cached_neuron_stake_e8s: 21,
                ..api::Neuron::default()
            },
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 1,
                ..api::Neuron::default()
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
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 4,
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS
                    - MAX_NEURON_AGE_FOR_AGE_BONUS,
                ..api::Neuron::default()
            },
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 4,
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS,
                ..api::Neuron::default()
            },
        ],
        "P-",
        ProposalStatus::Executed,
        ProposalStatus::Executed,
    );
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 200,
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS
                    - MAX_NEURON_AGE_FOR_AGE_BONUS,
                ..api::Neuron::default()
            },
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 4,
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS,
                ..api::Neuron::default()
            },
        ],
        "nP",
        ProposalStatus::Rejected,
        ProposalStatus::Rejected,
    );
    check_proposal_status_after_voting_and_after_expiration(
        vec![
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 200,
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS
                    - MAX_NEURON_AGE_FOR_AGE_BONUS,
                ..api::Neuron::default()
            },
            api::Neuron {
                dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
                cached_neuron_stake_e8s: 4,
                aging_since_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS,
                ..api::Neuron::default()
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
/// - Neuron 2 follows 1, 3, 4 on topic NetworkEconomics and neuron 3 follows 5,
///   6, 7 on topic Unknown = all topics (except governance) without specific
///   override
///
/// - Neurons 1, 5, 6, 7, and 8 have a controller set and can vote.
fn fixture_for_following() -> api::Governance {
    let mut driver = fake::FakeDriver::default();
    // A 'default' neuron, extended with additional fields below.
    let mut neuron = move |id| api::Neuron {
        id: Some(NeuronId { id }),
        controller: Some(principal(id)),
        cached_neuron_stake_e8s: 1_000_000_000, // 10 ICP
        // One year
        dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(31557600)),
        account: driver
            .random_byte_array()
            .expect("Could not get random byte array")
            .to_vec(),
        visibility: Some(Visibility::Public as i32),
        ..Default::default()
    };
    api::Governance {
        economics: Some(api::NetworkEconomics::with_default_values()),
        wait_for_quiet_threshold_seconds: 1,
        neurons: btreemap! {
            1 => neuron(1),
            2 => api::Neuron {
                followees: hashmap! {
                    Topic::NetworkEconomics as i32 => api::neuron::Followees {
                        followees: [NeuronId { id: 1 }, NeuronId { id: 3 }, NeuronId { id: 4 }].to_vec(),
                    },
                },
                ..neuron(2)
            },
            3 => api::Neuron {
                followees: hashmap! {
                    Topic::Unspecified as i32 => api::neuron::Followees {
                        followees: [NeuronId { id: 5 }, NeuronId { id: 6 }, NeuronId { id: 7 }].to_vec(),
                    },
                },
                ..neuron(3)
            },
            4 => neuron(4),
            5 => neuron(5),
            6 => neuron(6),
            7 => neuron(7),
            8 => neuron(8),
            9 => neuron(9),
        },
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
#[tokio::test]
async fn test_cascade_following() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
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
    .await
    .unwrap();

    // The fee should now be 1 ICP since the fees are charged upfront.
    assert_eq!(
        gov.get_full_neuron(&NeuronId { id: 1 }, &principal(1))
            .unwrap()
            .neuron_fees_e8s,
        100_000_000
    );

    // Once the proposal passes
    // Check that the vote is registered in the proposing neuron.
    assert_eq!(
        &api::BallotInfo {
            proposal_id: Some(ProposalId { id: 1 }),
            vote: Vote::Yes as i32
        },
        gov.get_full_neuron(&NeuronId { id: 1 }, &principal(1))
            .unwrap()
            .recent_ballots
            .first()
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

    // Recent ballots are not immediately recorded in every case (such as when there are
    // many votes in the cascading, it is done later through timer tasks)
    gov.process_voting_state_machines().await;

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
        vec![BallotInfo {
            proposal_id: Some(ProposalId { id: 1 }),
            vote: Vote::Yes as i32
        }],
        gov.neuron_store
            .with_neuron(&NeuronId::from_u64(2), |n| n.recent_ballots.clone())
            .expect("Neuron not found")
    );
    // The proposal should now be accepted and executed.
    assert_eq!(
        ProposalStatus::Executed,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );

    // After the proposal is accepted the Neuron 1 should have 0 fees again
    assert_eq!(
        gov.neuron_store
            .with_neuron(&NeuronId::from_u64(1), |n| n.neuron_fees_e8s)
            .expect("Neuron not found"),
        0
    );
}

#[tokio::test]
async fn test_minimum_icp_xdr_conversion_rate_limits_monthly_node_provider_rewards() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    // Set minimum conversion rate.
    let minimum_icp_xdr_rate = 100;
    gov.heap_data
        .economics
        .as_mut()
        .unwrap()
        .minimum_icp_xdr_rate = minimum_icp_xdr_rate;

    let node_provider_pid = PrincipalId::new_user_test_id(1);
    let node_provider = NodeProvider {
        id: Some(node_provider_pid),
        reward_account: None,
    };

    gov.heap_data.node_providers = vec![node_provider.clone()];

    let monthly_node_provider_rewards = gov.get_monthly_node_provider_rewards().await.unwrap();
    let actual_node_provider_reward = monthly_node_provider_rewards
        .rewards
        .iter()
        .find(|reward| reward.node_provider.as_ref().unwrap().id == Some(node_provider_pid))
        .unwrap()
        .clone();

    let expected_node_provider_reward = get_node_provider_reward(
        &node_provider,
        NODE_PROVIDER_REWARD,
        minimum_icp_xdr_rate * NetworkEconomics::ICP_XDR_RATE_TO_BASIS_POINT_MULTIPLIER,
    )
    .unwrap();
    assert_eq!(actual_node_provider_reward, expected_node_provider_reward);
}

#[tokio::test]
async fn test_manage_network_economics_change_one_deep_subfield() {
    // Step 1: Prepare the world. All we need is a Governance with one neuron.
    // The neuron will be used to make a ManageNetworkEconomics proposal.

    let controller = PrincipalId::new_user_test_id(519_572_717);
    let neuron = api::Neuron {
        id: Some(NeuronId { id: 1 }),
        controller: Some(controller),
        account: vec![42_u8; 32],
        dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
        cached_neuron_stake_e8s: 100 * E8,
        ..Default::default()
    };

    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        api::Governance {
            economics: Some(api::NetworkEconomics::with_default_values()),
            neurons: btreemap! { 1 => neuron },
            ..Default::default()
        },
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Call the code under test. Make a ManageNetworkEconomics proposal.
    // It gets executed immediately, since there is only one neuron.

    let neurons_fund_economics = Some(NeuronsFundEconomics {
        neurons_fund_matched_funding_curve_coefficients: Some(
            NeuronsFundMatchedFundingCurveCoefficients {
                // This is the ONLY field that should be touched.
                contribution_threshold_xdr: Some(Decimal {
                    human_readable: Some("123456789".to_string()),
                }),

                // Do not touch other fields.
                one_third_participation_milestone_xdr: None,
                ..Default::default()
            },
        ),

        // Do not touch other fields.
        minimum_icp_xdr_rate: None,
        ..Default::default()
    });

    // Assert that the proposal contains a different value for contribution_threshold_xdr.
    {
        let prior_contribution_threshold_xdr = gov
            .heap_data
            .economics
            .as_ref()
            .unwrap()
            .neurons_fund_economics
            .as_ref()
            .unwrap()
            .neurons_fund_matched_funding_curve_coefficients
            .as_ref()
            .unwrap()
            .contribution_threshold_xdr
            .as_ref()
            .unwrap()
            .human_readable
            .as_deref()
            .unwrap();
        let prior_contribution_threshold_xdr =
            rust_decimal::Decimal::try_from(prior_contribution_threshold_xdr).unwrap();

        let proposal_contribution_threshold_xdr = rust_decimal::Decimal::from(123_456_789);

        assert_ne!(
            prior_contribution_threshold_xdr,
            proposal_contribution_threshold_xdr
        );
    }
    gov.make_proposal(
        &NeuronId { id: 1 },
        &controller,
        &Proposal {
            title: Some("Change start_reducing_voting_power_after_seconds to 42.".to_string()),
            summary: "Best proposal of all time. Of all time.".to_string(),
            url: "https://forum.dfinity.org".to_string(),
            action: Some(proposal::Action::ManageNetworkEconomics(NetworkEconomics {
                neurons_fund_economics,

                // Do not touch other fields.
                reject_cost_e8s: 0,
                ..Default::default()
            })),
        },
    )
    .await
    .unwrap();

    // Step 3: Verify results.

    let mut expected_network_economics = NetworkEconomics::with_default_values();
    expected_network_economics
        .neurons_fund_economics
        .as_mut()
        .unwrap()
        .neurons_fund_matched_funding_curve_coefficients
        .as_mut()
        .unwrap()
        .contribution_threshold_xdr = Some(Decimal {
        human_readable: Some("123456789".to_string()),
    });

    assert_eq!(gov.heap_data.economics, Some(expected_network_economics));
}

#[tokio::test]
async fn test_manage_network_economics_reject_invalid() {
    // Step 1: Prepare the world. We only really need a super basic Governance.

    let controller = PrincipalId::new_user_test_id(519_572_717);
    let neuron = api::Neuron {
        id: Some(NeuronId { id: 1 }),
        controller: Some(controller),
        account: vec![42_u8; 32],
        dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
        cached_neuron_stake_e8s: 100 * E8,
        ..Default::default()
    };

    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        api::Governance {
            economics: Some(api::NetworkEconomics::with_default_values()),
            neurons: btreemap! { 1 => neuron },
            ..Default::default()
        },
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Call the code under test. Make a ManageNetworkEconomics proposal.
    // It gets executed immediately, since there is only one neuron.

    let too_small_for_full_participation_milestone_xdr = 7_u64;
    // Assert that too_small_for_full_participation_milestone_xdr is a
    // problemmatic value if it were to be used a proposal (this is
    // foreshadowing, in case you didn't notice).
    {
        let one_third_participation_milestone_xdr = NetworkEconomics::with_default_values()
            .neurons_fund_economics
            .unwrap()
            .neurons_fund_matched_funding_curve_coefficients
            .unwrap()
            .one_third_participation_milestone_xdr
            .unwrap()
            .human_readable;
        let one_third_participation_milestone_xdr = rust_decimal::Decimal::try_from(
            one_third_participation_milestone_xdr.as_deref().unwrap(),
        )
        .unwrap();
        assert!(
            rust_decimal::Decimal::from(too_small_for_full_participation_milestone_xdr)
                < one_third_participation_milestone_xdr,
            "{too_small_for_full_participation_milestone_xdr} vs. {one_third_participation_milestone_xdr}"
        );
    }

    let neurons_fund_economics = Some(NeuronsFundEconomics {
        neurons_fund_matched_funding_curve_coefficients: Some(
            NeuronsFundMatchedFundingCurveCoefficients {
                full_participation_milestone_xdr: Some(Decimal {
                    human_readable: Some(format!(
                        "{too_small_for_full_participation_milestone_xdr}"
                    )),
                }),
                ..Default::default()
            },
        ),
        ..Default::default()
    });

    let result = gov
        .make_proposal(
            &NeuronId { id: 1 },
            &controller,
            &Proposal {
                title: Some("Change start_reducing_voting_power_after_seconds to 42.".to_string()),
                summary: "Best proposal of all time. Of all time.".to_string(),
                url: "https://forum.dfinity.org".to_string(),
                action: Some(proposal::Action::ManageNetworkEconomics(NetworkEconomics {
                    neurons_fund_economics,

                    // The proposal will not touch other fields, regardless of
                    // whether we mention them explicitly or not.
                    reject_cost_e8s: 0,
                    ..Default::default()
                })),
            },
        )
        .await;

    // Step 3: Verify results.

    // Step 3.1: Proposal creation failed.
    {
        let err = result.unwrap_err();
        assert_eq!(
            ErrorType::try_from(err.error_type),
            Ok(ErrorType::InvalidProposal)
        );
        let message = err.error_message.to_lowercase();
        for key_word in ["one_third", "full_participation"] {
            assert!(message.contains(key_word), "{key_word} not in {err:#?}");
        }
    }

    // Step 3.2: No change.
    assert_eq!(
        gov.heap_data.economics,
        Some(NetworkEconomics::with_default_values())
    );
}

// These values are individually compatible with
// NetworkEconomics::with_default_values, but they are not compatible with
// each other. This means that separate proposals can be made to set these
// values, but when the second one is executed, it fails.
const NEW_MINIMUM_ICP_XDR_RATE: u64 = 500_000;
const NEW_MAXIMUM_ICP_XDR_RATE: u64 = 499_000;

#[tokio::test]
async fn test_manage_network_economics_revalidate_at_execution_time_set_minimum_icp_xdr_rate_first()
{
    let new_network_economics = test_manage_network_economics_revalidate_at_execution_time(
        |set_minimum_icp_xdr_rate_proposal_id, set_maximum_icp_xdr_rate_proposal_id| {
            (
                set_minimum_icp_xdr_rate_proposal_id,
                set_maximum_icp_xdr_rate_proposal_id,
            )
        },
    )
    .await;

    let mut expected_network_economics = NetworkEconomics::with_default_values();
    expected_network_economics
        .neurons_fund_economics
        .as_mut()
        .unwrap()
        .minimum_icp_xdr_rate = Some(Percentage {
        basis_points: Some(NEW_MINIMUM_ICP_XDR_RATE),
    });

    assert_eq!(new_network_economics, expected_network_economics);

    let maximum_icp_xdr_rate = new_network_economics
        .neurons_fund_economics
        .as_ref()
        .unwrap()
        .maximum_icp_xdr_rate
        .as_ref()
        .unwrap()
        .basis_points
        .unwrap();
    assert_ne!(maximum_icp_xdr_rate, NEW_MAXIMUM_ICP_XDR_RATE);
}

#[tokio::test]
async fn test_manage_network_economics_revalidate_at_execution_time_set_maximum_icp_xdr_rate_first()
{
    let new_network_economics = test_manage_network_economics_revalidate_at_execution_time(
        |set_minimum_icp_xdr_rate_proposal_id, set_maximum_icp_xdr_rate_proposal_id| {
            (
                set_maximum_icp_xdr_rate_proposal_id,
                set_minimum_icp_xdr_rate_proposal_id,
            )
        },
    )
    .await;

    let mut expected_network_economics = NetworkEconomics::with_default_values();
    expected_network_economics
        .neurons_fund_economics
        .as_mut()
        .unwrap()
        .maximum_icp_xdr_rate = Some(Percentage {
        basis_points: Some(NEW_MAXIMUM_ICP_XDR_RATE),
    });

    assert_eq!(new_network_economics, expected_network_economics);

    let minimum_icp_xdr_rate = new_network_economics
        .neurons_fund_economics
        .as_ref()
        .unwrap()
        .minimum_icp_xdr_rate
        .as_ref()
        .unwrap()
        .basis_points
        .unwrap();
    assert_ne!(minimum_icp_xdr_rate, NEW_MINIMUM_ICP_XDR_RATE);
}

/// Two proposals are created:
///
///     1. Sets minimum_icp_xdr_rate to NEW_MINIMUM_ICP_XDR_RATE.
///
///     2. Sets maximum_icp_xdr_rate to NEW_MAXIMUM_ICP_XDR_RATE.
///
/// Unlike many tests, these proposals do NOT get decided immediately. This
/// shows that they can EXIST (and be voted on) concurrently.
///
/// order_of_execution controls which gets voted in first.
///
/// Asserts that
///
///     1. The first proposal is marked as successfully executed.
///
///     2. The second proposal is marked as attempted to execute, but was
///        unsuccessful.
///
/// Returns the resulting NetworkEconomics.
async fn test_manage_network_economics_revalidate_at_execution_time(
    order_of_execution: impl Fn(
        /* set_min_proposal_id */ ProposalId,
        /* set_max_proposal_id */ ProposalId,
    ) -> (ProposalId, ProposalId),
) -> NetworkEconomics {
    // Step 1: Prepare the world.

    // Step 1.1: Create a governance with two neurons:
    //
    //     1. proposer - Has little voting power. This is used to MAKE a couple
    //        of proposals without them being decided immediately.
    //
    //     2. decider - Hot lots of VP. This does NOT vote until AFTER BOTH
    //        proposals have been created. This votes in favor of both
    //        proposals. This causes the proposals to attempt execution.
    //        However, only the first one is executed SUCCESSFULLY. The second
    //        one fails, because the proposals are not compatible with one
    //        another (despite being able to EXIST and be voted on
    //        concurrently).

    let controller = PrincipalId::new_user_test_id(519_572_717);
    let proposer_neuron = api::Neuron {
        id: Some(NeuronId { id: 1 }),
        controller: Some(controller),
        account: vec![42_u8; 32],
        dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
        cached_neuron_stake_e8s: 100 * E8,
        ..Default::default()
    };
    let decider_neuron = api::Neuron {
        id: Some(NeuronId { id: 2 }),
        account: vec![57_u8; 32],
        cached_neuron_stake_e8s: E8 * E8, // Powerful!
        ..proposer_neuron.clone()
    };

    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        api::Governance {
            economics: Some(api::NetworkEconomics::with_default_values()),
            neurons: btreemap! {
                1 => proposer_neuron,
                2 => decider_neuron,
            },
            wait_for_quiet_threshold_seconds: 1,
            ..Default::default()
        },
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 1.2: Make a couple of proposals.

    let set_min_proposal_id = gov
        .make_proposal(
            &NeuronId { id: 1 },
            &controller,
            &Proposal {
                title: Some("Change start_reducing_voting_power_after_seconds to 42.".to_string()),
                summary: "Best proposal of all time. Of all time.".to_string(),
                url: "https://forum.dfinity.org".to_string(),
                action: Some(proposal::Action::ManageNetworkEconomics(NetworkEconomics {
                    neurons_fund_economics: Some(NeuronsFundEconomics {
                        minimum_icp_xdr_rate: Some(Percentage {
                            basis_points: Some(NEW_MINIMUM_ICP_XDR_RATE),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            },
        )
        .await
        .unwrap();

    let set_max_proposal_id = gov
        .make_proposal(
            &NeuronId { id: 1 },
            &controller,
            &Proposal {
                title: Some("Change start_reducing_voting_power_after_seconds to 42.".to_string()),
                summary: "Best proposal of all time. Of all time.".to_string(),
                url: "https://forum.dfinity.org".to_string(),
                action: Some(proposal::Action::ManageNetworkEconomics(NetworkEconomics {
                    neurons_fund_economics: Some(NeuronsFundEconomics {
                        maximum_icp_xdr_rate: Some(Percentage {
                            basis_points: Some(NEW_MAXIMUM_ICP_XDR_RATE),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
            },
        )
        .await
        .unwrap();

    // Step 2: Call the code under test. Vote in the proposals.

    let (first_proposal_id, second_proposal_id) =
        order_of_execution(set_min_proposal_id, set_max_proposal_id);
    for proposal_id in [first_proposal_id, second_proposal_id] {
        let result = gov
            .manage_neuron(
                &controller,
                &ManageNeuron {
                    command: Some(manage_neuron::Command::RegisterVote(
                        manage_neuron::RegisterVote {
                            proposal: Some(proposal_id),
                            vote: Vote::Yes as i32,
                        },
                    )),
                    neuron_id_or_subaccount: Some(manage_neuron::NeuronIdOrSubaccount::NeuronId(
                        NeuronId { id: 2 },
                    )),
                    id: None,
                },
            )
            .await;
        // Assert vote successful.
        match result.command {
            Some(manage_neuron_response::Command::RegisterVote(_)) => (),
            _ => panic!("{result:#?}"),
        }
    }

    // Step 3: Verify results.

    // Step 3.1: Only the frist proposal executed successfully.

    let first_proposal = gov
        .get_proposal_info(&controller, first_proposal_id)
        .unwrap();
    assert_ne!(
        first_proposal.decided_timestamp_seconds, 0,
        "{:#?}",
        first_proposal,
    );
    assert_ne!(
        first_proposal.executed_timestamp_seconds, 0,
        "{:#?}",
        first_proposal,
    );
    assert_eq!(first_proposal.failure_reason, None, "{:#?}", first_proposal,);

    let second_proposal = gov
        .get_proposal_info(&controller, second_proposal_id)
        .unwrap();
    // Yes, it was decided, like the other proposal.
    assert_ne!(
        second_proposal.decided_timestamp_seconds, 0,
        "{:#?}",
        second_proposal,
    );
    // Sadly, though, it failed, unlike the other proposal.
    assert_ne!(
        second_proposal.failed_timestamp_seconds, 0,
        "{:#?}",
        second_proposal,
    );
    // And the reason it failed was...
    let failure_reason = second_proposal.failure_reason.clone().unwrap();
    assert_eq!(
        ErrorType::try_from(failure_reason.error_type),
        Ok(ErrorType::InvalidProposal),
        "{:#?}",
        second_proposal,
    );
    let message = failure_reason.error_message.to_lowercase();
    for key_word in [
        "resulting",
        "economics",
        "valid",
        "reason",
        "maximum_icp_xdr_rate",
        "greater",
        "minimum_icp_xdr_rate",
    ] {
        assert!(message.contains(key_word), "{second_proposal:#?}");
    }

    // Step 3.2: Let the caller inspect the resulting NetworkEconomics.
    gov.heap_data.economics.unwrap()
}

#[tokio::test]
async fn test_mint_monthly_node_provider_rewards() {
    // Step 1: prepare the canister state and the Governance minting account.
    let mut driver = fake::FakeDriver::default();
    let node_provider = NodeProvider {
        id: Some(PrincipalId::new_user_test_id(1)),
        reward_account: None,
    };
    driver.create_account_with_funds(
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), None),
        1_000_000_000,
    );
    let default_economics = NetworkEconomics::with_default_values();
    let mut gov = Governance::new(
        api::Governance {
            most_recent_monthly_node_provider_rewards: Some(api::MonthlyNodeProviderRewards {
                timestamp: 0,
                rewards: vec![],
                xdr_conversion_rate: None,
                minimum_xdr_permyriad_per_icp: None,
                maximum_node_provider_rewards_e8s: None,
                registry_version: None,
                node_providers: vec![],
                start_date: None,
                end_date: None,
            }),
            ..Default::default()
        },
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    gov.heap_data.economics = Some(default_economics.clone());
    gov.heap_data.node_providers = vec![node_provider.clone()];

    // Step 2: Run twice heartbeat so that minting rewards is reached.
    gov.run_periodic_tasks().now_or_never();
    gov.run_periodic_tasks().now_or_never();

    // Step 3: Verify that node provider rewards are minted.
    let most_recent_monthly_node_provider_rewards = gov
        .heap_data
        .most_recent_monthly_node_provider_rewards
        .unwrap();
    assert!(most_recent_monthly_node_provider_rewards.timestamp > 0);
    assert_eq!(most_recent_monthly_node_provider_rewards.rewards.len(), 1);
    let MonthlyNodeProviderRewards {
        timestamp: _,
        start_date: _,
        end_date: _,
        rewards,
        xdr_conversion_rate,
        minimum_xdr_permyriad_per_icp,
        maximum_node_provider_rewards_e8s,
        registry_version,
        node_providers,
    } = most_recent_monthly_node_provider_rewards;
    let reward = rewards[0].clone();
    assert_eq!(reward.node_provider.unwrap(), node_provider);
    let xdr_conversion_rate = xdr_conversion_rate.unwrap();
    assert_eq!(xdr_conversion_rate.xdr_permyriad_per_icp.unwrap(), 1);
    assert!(xdr_conversion_rate.timestamp_seconds.unwrap() > 0);
    // Default value (100) * conversion to permyriad
    assert_eq!(minimum_xdr_permyriad_per_icp, Some(10_000));
    assert_eq!(
        maximum_node_provider_rewards_e8s,
        Some(default_economics.maximum_node_provider_rewards_e8s)
    );
    // It happens to be 5, we just want to ensure it is set.
    assert_eq!(registry_version, Some(5));
    assert_eq!(node_providers.len(), 1);
}

#[tokio::test]
async fn test_node_provider_must_be_registered() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    let node_provider = NodeProvider {
        id: Some(PrincipalId::try_from(b"SID2".to_vec()).unwrap()),
        reward_account: None,
    };
    // Register a single node provider
    gov.heap_data.node_providers.push(node_provider);
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
        .await
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
    .await
    .unwrap();
}

/// In this scenario, we simply test that you cannot make a proposal
/// if you have insufficient stake (less than the reject fee).
#[tokio::test]
async fn test_sufficient_stake() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    // Set stake to 0.5 ICP.
    gov.neuron_store
        .with_neuron_mut(&NeuronId { id: 1 }, |n| {
            n.cached_neuron_stake_e8s = 50_000_000;
        })
        .expect("Neuron not found");
    // This should fail because the reject_cost_e8s is 1 ICP.
    assert_eq!(
        ErrorType::InsufficientFunds as i32,
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
        .await
        .unwrap_err()
        .error_type
    );
    // Set stake to 1 ICP.
    gov.neuron_store
        .with_neuron_mut(&NeuronId { id: 1 }, |n| {
            n.cached_neuron_stake_e8s = 100_000_000;
        })
        .expect("Neuron not found.");
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
    .await
    .unwrap();
}

/// In this scenario, we configure neurons 5 and 6 to follow neuron 1.
/// When neuron 1 now votes, this should result in the proposal being
/// immediately acceptable.
#[tokio::test]
async fn test_all_follow_proposer() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Later, we'll inspect the same field again to verify that voting power
    // refresh actually took place. This is just to make sure that the later
    // value is different from this earlier one.
    assert_eq!(
        gov.with_neuron(&NeuronId { id: 5 }, |neuron| {
            neuron.voting_power_refreshed_timestamp_seconds()
        })
        .unwrap(),
        DEFAULT_VOTING_POWER_REFRESHED_TIMESTAMP_SECONDS,
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
    .await
    .panic_if_error("Manage neuron failed");

    // Assert that neuron 5's voting power was refreshed. More concretely,
    // verifying that neuron 5's voting_power_refreshed_timestamp_seconds
    // changed from before. (Earlier, we saw that this field had a different
    // value, to wit, DEFAULT_VOTING_POWER_REFRESHED_TIMESTAMP_SECONDS)
    assert_ne!(
        DEFAULT_TEST_START_TIMESTAMP_SECONDS,
        DEFAULT_VOTING_POWER_REFRESHED_TIMESTAMP_SECONDS,
    );
    assert_eq!(
        gov.with_neuron(&NeuronId { id: 5 }, |neuron| {
            neuron.voting_power_refreshed_timestamp_seconds()
        })
        .unwrap(),
        DEFAULT_TEST_START_TIMESTAMP_SECONDS,
    );

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
    .await
    .panic_if_error("Manage neuron failed");

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
    .await
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
#[tokio::test]
async fn test_follow_negative() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
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
    .await
    .unwrap();
    // Vote for 4 with a wrong controller.
    let result = fake::register_vote(
        &mut gov,
        // Must match neuron 4's serialized_id.
        principal(101),
        NeuronId { id: 4 },
        ProposalId { id: 1 },
        Vote::No,
    );
    assert_matches!(
        result.command,
        Some(manage_neuron_response::Command::Error(err))
            if err.error_type == ErrorType::NotAuthorized as i32
    );
    // Now vote no for neurons 4 (with the right controller), 5, and 6.
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

    // Now process the proposals: neurons 2, 3, 4, 5, 6 have voted no (5/9)
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
        gov.neuron_store
            .with_neuron(&NeuronId::from_u64(1), |n| n.neuron_fees_e8s)
            .expect("Neuron not found"),
        gov.heap_data.economics.unwrap().reject_cost_e8s
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
#[tokio::test]
async fn test_no_default_follow_for_governance() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
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
    .await
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

/// Here we test that following doesn't apply to the Governance topic.
///
/// Neuron 1 makes a proposal.
///
/// Neurons 5, 6, 7, 8 vote yes.
///
/// As no following applies, the proposal should not be adopted until
/// neuron 8 votes yes as default following is disabled for governance
/// proposals.
#[tokio::test]
async fn test_no_voting_after_deadline() {
    let mut driver = fake::FakeDriver::default();
    // current time is assumed to be DEFAULT_TEST_START_TIMESTAMP_SECONDS
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    let proposal_id = gov
        .make_proposal(
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
        .await
        .unwrap();
    let proposal_data = gov.get_proposal_data(proposal_id).unwrap();
    let deadline_seconds = proposal_data
        .wait_for_quiet_state
        .as_ref()
        .unwrap()
        .current_deadline_timestamp_seconds;
    driver.advance_time_by(deadline_seconds + 1 - DEFAULT_TEST_START_TIMESTAMP_SECONDS);

    // 2. Cast vote
    let result = fake::register_vote(
        &mut gov,
        principal(5),
        NeuronId { id: 5 },
        ProposalId { id: 1 },
        Vote::Yes,
    );

    // 3. Inspect results
    assert_eq!(
        result,
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::Error(
                api::GovernanceError::new_with_message(
                    api::governance_error::ErrorType::PreconditionFailed,
                    "Proposal deadline has passed.",
                )
            ))
        }
    );
}

/// *Test fixture for manage neuron*
///
/// - There are six neurons: 1-6.
///
/// - Every neuron has the same stake of 10 ICP, but no dissolution
///   period specified.
//
///
/// - Neuron 1 follows 2, 3, and 4 on topic `ManageNeuron`.
///
/// - Neurons 2, 3, 4, and 5 have a controller so they can vote.
fn fixture_for_manage_neuron() -> api::Governance {
    let mut driver = fake::FakeDriver::default();

    // A 'default' neuron, extended with additional fields below.
    let mut neuron = move |id| api::Neuron {
        id: Some(NeuronId { id }),
        controller: Some(principal(id)),
        cached_neuron_stake_e8s: 1_000_000_000, // 10 ICP
        account: driver
            .random_byte_array()
            .expect("Could not get random byte array")
            .to_vec(),
        dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
        aging_since_timestamp_seconds: u64::MAX,
        visibility: Some(Visibility::Public as i32),
        ..Default::default()
    };

    let neurons = vec![
        api::Neuron {
            created_timestamp_seconds: 1066,
            hot_keys: vec![PrincipalId::try_from(b"HOT_SID1".to_vec()).unwrap()],
            followees: hashmap! {
                Topic::NeuronManagement as i32 => api::neuron::Followees {
                    followees: [NeuronId { id: 2 }, NeuronId { id: 3 }, NeuronId { id: 4 }]
                        .to_vec(),
                },
            },
            ..neuron(1)
        },
        api::Neuron {
            hot_keys: vec![PrincipalId::try_from(b"HOT_SID2".to_vec()).unwrap()],
            ..neuron(2)
        },
        neuron(3),
        neuron(4),
        neuron(5),
        neuron(6),
    ];

    GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(api::NetworkEconomics::with_default_values())
        .with_neurons(neurons)
        .with_short_voting_period(1)
        .with_neuron_management_voting_period(1)
        .with_wait_for_quiet_threshold(10)
        .build()
}

#[test]
fn test_enforce_public_neuron() {
    // Step 1: Prepare the world.

    let driver = fake::FakeDriver::default();
    let governance = Governance::new(
        fixture_for_manage_neuron(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Call code under test.
    let neuron_id = NeuronId { id: 1 };
    let key = NeuronIdOrSubaccount::NeuronId(neuron_id);
    let controller = principal(1);

    let neuron_info = governance
        .get_neuron_info_by_id_or_subaccount(&key, *RANDOM_PRINCIPAL_ID)
        .unwrap();

    let full_neuron = governance
        .get_full_neuron_by_id_or_subaccount(
            &NeuronIdOrSubaccount::NeuronId(neuron_id),
            &controller,
        )
        .unwrap();

    let list_neurons_response = governance.list_neurons(
        &ListNeurons {
            neuron_ids: vec![1],
            ..Default::default()
        },
        controller,
    );

    // Step 3: Inspect results.
    // TODO(NNS1-4230):
    // Here, we just want to assert that for a random principal ID
    // full_neuron is not in the result.
    assert_eq!(neuron_info.visibility, Some(Visibility::Public as i32));
    assert_eq!(full_neuron.visibility, Some(Visibility::Public as i32));

    assert_eq!(
        list_neurons_response,
        ListNeuronsResponse {
            neuron_infos: hashmap! {
                1 => neuron_info,
            },
            full_neurons: vec![full_neuron],
            total_pages_available: Some(1),
        }
    );
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
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    // Test that anybody can call `get_neuron_info` as long as the
    // neuron exists.
    let neuron_info = gov
        .get_neuron_info(&NeuronId { id: 1 }, *RANDOM_PRINCIPAL_ID)
        .unwrap();
    assert_eq!(1066, neuron_info.created_timestamp_seconds);
    assert_eq!(1_000_000_000, neuron_info.stake_e8s,);
    // But not if it doesn't exist.
    assert_eq!(
        ErrorType::NotFound as i32,
        gov.get_neuron_info(&NeuronId { id: 100 }, *RANDOM_PRINCIPAL_ID)
            .unwrap_err()
            .error_type
    );
    // Test that the neuron info can be found by subaccount.
    let neuron_1_subaccount = gov
        .neuron_store
        .with_neuron(&NeuronId { id: 1 }, |n| n.subaccount())
        .unwrap();
    assert_eq!(
        1066,
        gov.get_neuron_info_by_id_or_subaccount(
            &NeuronIdOrSubaccount::Subaccount(neuron_1_subaccount.to_vec()),
            *RANDOM_PRINCIPAL_ID,
        )
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
        gov.get_neuron_info_by_id_or_subaccount(
            &NeuronIdOrSubaccount::Subaccount([0u8; 32].to_vec()),
            *RANDOM_PRINCIPAL_ID,
        )
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
#[tokio::test]
async fn test_manage_neuron() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_manage_neuron(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
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
    .await
    .unwrap();
    assert_eq!(
        ProposalStatus::Open,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );
    assert_eq!(
        gov.get_neuron_info(&NeuronId { id: 2 }, principal(2))
            .unwrap()
            .recent_ballots,
        vec![api::BallotInfo {
            proposal_id: Some(ProposalId { id: 1 },),
            vote: Vote::Yes as i32,
        }]
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
    assert_eq!(
        gov.get_neuron_info(&NeuronId { id: 3 }, principal(3),)
            .unwrap()
            .recent_ballots,
        vec![api::BallotInfo {
            proposal_id: Some(ProposalId { id: 1 },),
            vote: Vote::Yes as i32,
        }]
    );
    // Make sure that the neuron has been changed the fee for manage
    // neuron proposals.
    assert_eq!(
        gov.neuron_store
            .with_neuron(&NeuronId::from_u64(2), |n| n.neuron_fees_e8s)
            .expect("Neuron not found"),
        gov.heap_data
            .economics
            .as_ref()
            .unwrap()
            .neuron_management_fee_per_proposal_e8s
    );
    // Now there should be a single followee...
    assert_eq!(
        1,
        gov.neuron_store
            .with_neuron(&NeuronId { id: 1 }, |n| {
                n.followees
                    .get(&(Topic::NeuronManagement as i32))
                    .unwrap()
                    .followees
                    .len()
            })
            .expect("Neuron not found.")
    );
    // ... viz., neuron 2.
    assert_eq!(
        2,
        gov.neuron_store
            .with_neuron(&NeuronId { id: 1 }, |n| {
                n.followees
                    .get(&(Topic::NeuronManagement as i32))
                    .unwrap()
                    .followees
                    .first()
                    .unwrap()
                    .id
            })
            .expect("Neuron not found.")
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
    .await
    .unwrap();
    // Now process the proposals: proposal should be executed as
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
        gov.neuron_store
            .with_neuron(&NeuronId { id: 1 }, |n| {
                n.followees
                    .get(&(Topic::NeuronManagement as i32))
                    .unwrap()
                    .followees
                    .len()
            })
            .expect("Neuron not found")
    );
    // Make sure that the neuron has been changed an additional fee
    // for manage neuron proposals.
    assert_eq!(
        gov.neuron_store
            .with_neuron(&NeuronId { id: 2 }, |n| n.neuron_fees_e8s)
            .expect("Neuron not found"),
        2 * gov
            .heap_data
            .economics
            .as_ref()
            .unwrap()
            .neuron_management_fee_per_proposal_e8s
    );
}

/// In this scenario, we test that you cannot make a manage neuron
/// proposal if you have insufficient stake (less than the manage neuron fee).
#[tokio::test]
async fn test_sufficient_stake_for_manage_neuron() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_manage_neuron(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    // Set stake to less than 0.01 ICP (same as
    // neuron_management_fee_per_proposal_e8s).
    gov.neuron_store
        .with_neuron_mut(&NeuronId { id: 2 }, |n| {
            n.cached_neuron_stake_e8s = 999_999;
        })
        .expect("Neuron not found.");
    // Try to make a proposal... This should fail because the
    // neuron_management_fee_per_proposal_e8s is 0.01 ICP.
    let err = gov
        .make_proposal(
            &NeuronId { id: 2 },
            // Must match neuron 1's serialized_id.
            &principal(2),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: 1,
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
        .await
        .unwrap_err();
    assert_eq!(
        ErrorType::InsufficientFunds,
        ErrorType::try_from(err.error_type).unwrap(),
        "actual error: {:?}",
        err
    );
    // Set stake to 2 ICP.
    gov.neuron_store
        .with_neuron_mut(&NeuronId { id: 2 }, |n| {
            n.cached_neuron_stake_e8s = 200_000_000;
        })
        .expect("Neuron not found.");
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
    .await
    .unwrap();
}

/// Constructs a fixture with 2 neurons of different stakes and no
/// following. Neuron 2 has a greater stake.
fn fixture_two_neurons_second_is_bigger() -> api::Governance {
    let mut driver = fake::FakeDriver::default();

    let neurons = vec![
        api::Neuron {
            id: Some(NeuronId { id: 1 }),
            controller: Some(principal(1)),
            cached_neuron_stake_e8s: 23,
            account: driver
                .random_byte_array()
                .expect("Could not get random byte array")
                .to_vec(),
            // One year
            dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(31557600)),
            ..Default::default()
        },
        api::Neuron {
            id: Some(NeuronId { id: 2 }),
            controller: Some(principal(2)),
            cached_neuron_stake_e8s: 951,
            account: driver
                .random_byte_array()
                .expect("Could not get random byte array")
                .to_vec(),
            // One year
            dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(31557600)),
            ..Default::default()
        },
    ];

    let mut result = GovernanceProtoBuilder::new().with_neurons(neurons).build();

    // Make NetworkEconomics slightly less invalid.
    // (This is a rework of an old test.)
    result
        .economics
        .as_mut()
        .unwrap()
        .max_proposals_to_keep_per_topic = 100;

    result
}

#[tokio::test]
#[should_panic]
async fn test_invalid_proposals_fail() {
    let fake_driver = fake::FakeDriver::default();
    let governance_proto = fixture_two_neurons_second_is_bigger();
    let mut gov = Governance::new(
        governance_proto,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
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
    .await
    .unwrap();
}

fn deciding_voting_power(gov: &Governance, neuron_id: u64, now: u64) -> u64 {
    gov.neuron_store
        .with_neuron(&NeuronId { id: neuron_id }, |n| n.clone())
        .unwrap()
        .deciding_voting_power(&VotingPowerEconomics::DEFAULT, now)
}

#[tokio::test]
async fn test_compute_tally_while_open() {
    // Prepare the test with 2 neurons
    let fake_driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        api::Governance {
            wait_for_quiet_threshold_seconds: 5,
            ..fixture_two_neurons_second_is_bigger()
        },
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );

    // Make the proposal from the smaller neuron.
    let pid = gov
        .make_proposal(
            &NeuronId { id: 1 },
            &principal(1),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "proposal 1".to_string(),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "".to_string(),
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Tally should have the smaller neuron voting yes.
    assert_eq!(
        gov.get_proposal_data(pid).unwrap().latest_tally,
        Some(Tally {
            timestamp_seconds: fake_driver.now(),
            no: 0,
            yes: deciding_voting_power(&gov, 1, fake_driver.now()),
            total: deciding_voting_power(&gov, 1, fake_driver.now())
                + deciding_voting_power(&gov, 2, fake_driver.now())
        })
    );
}

#[tokio::test]
async fn test_compute_tally_after_decided() {
    // Prepare the test with 2 neurons
    let fake_driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        api::Governance {
            wait_for_quiet_threshold_seconds: 5,
            ..fixture_two_neurons_second_is_bigger()
        },
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );

    // Make the proposal from the larger neuron.
    let pid = gov
        .make_proposal(
            &NeuronId { id: 2 },
            &principal(2),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "proposal 1".to_string(),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "".to_string(),
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Tally should have the larger neuron voting yes, and the proposal is decided.
    assert_eq!(
        gov.get_proposal_data(pid).unwrap().latest_tally,
        Some(Tally {
            timestamp_seconds: fake_driver.now(),
            no: 0,
            yes: deciding_voting_power(&gov, 2, fake_driver.now()),
            total: deciding_voting_power(&gov, 1, fake_driver.now())
                + deciding_voting_power(&gov, 2, fake_driver.now())
        })
    );

    // Let the smaller neuron vote no.
    fake::register_vote_assert_success(
        &mut gov,
        principal(1),
        NeuronId { id: 1 },
        ProposalId { id: 1 },
        Vote::No,
    );

    // The tally should still be recomputed.
    assert_eq!(
        gov.get_proposal_data(pid).unwrap().latest_tally,
        Some(Tally {
            timestamp_seconds: fake_driver.now(),
            no: deciding_voting_power(&gov, 1, fake_driver.now()),
            yes: deciding_voting_power(&gov, 2, fake_driver.now()),
            total: deciding_voting_power(&gov, 1, fake_driver.now())
                + deciding_voting_power(&gov, 2, fake_driver.now())
        })
    );
}

#[tokio::test]
async fn test_no_compute_tally_after_deadline() {
    // Prepare the test with 2 neurons
    let mut fake_driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        api::Governance {
            wait_for_quiet_threshold_seconds: 5,
            ..fixture_two_neurons_second_is_bigger()
        },
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );

    // Make the proposal from the larger neuron and let the smaller neuron vote no.
    let pid = gov
        .make_proposal(
            &NeuronId { id: 2 },
            &principal(2),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "proposal 1".to_string(),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "".to_string(),
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Advance time past the deadline.
    let previous_time = fake_driver.now();
    fake_driver.advance_time_by(6);

    // Attempt to cast another vote after deadline which should fail.
    assert_matches!(
        fake::register_vote(
            &mut gov,
            principal(1),
            NeuronId { id: 1 },
            ProposalId { id: 1 },
            Vote::No,
        ).command,
        Some(manage_neuron_response::Command::Error(err))
            if err.error_type == ErrorType::PreconditionFailed as i32
    );

    // Simulate a heartbeat.
    gov.run_periodic_tasks().now_or_never();

    // The tally should not be recomputed after deadline because of heartbeat.
    // This is important since computing the tally is expensive.
    assert_eq!(
        gov.get_proposal_data(pid)
            .unwrap()
            .latest_tally
            .as_ref()
            .unwrap()
            .timestamp_seconds,
        previous_time
    );
}
/// In this scenario, the wait-for-quiet policy make that proposals last though
/// several reward periods.
///
/// We check that the reward event for a proposal happens at the expected time.
#[tokio::test]
async fn test_reward_event_proposals_last_longer_than_reward_period() {
    let genesis_timestamp_seconds = 56;
    let mut fake_driver = fake::FakeDriver::default()
        .at(genesis_timestamp_seconds)
        // To make assertion easy to sanity-check, the total supply of ICPs is chosen
        // so that the reward supply for the first day is 100 (365_250 * 10% / 365.25 = 100).
        // On next days it will be a bit less, but it is still easy to verify by eye
        // the order of magnitude.
        .with_supply(Tokens::from_e8s(365_250));
    const INITIAL_REWARD_POT_PER_ROUND_E8S: u64 = 100;
    let mut fixture = fixture_two_neurons_second_is_bigger();
    // Proposals last longer than the reward period
    let wait_for_quiet_threshold_seconds = 5 * REWARD_DISTRIBUTION_PERIOD_SECONDS;
    fixture.wait_for_quiet_threshold_seconds = wait_for_quiet_threshold_seconds;
    let gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );
    set_governance_for_tests(gov);
    let gov = governance_mut();
    schedule_tasks();

    let expected_initial_event = RewardEvent {
        day_after_genesis: 0,
        actual_timestamp_seconds: genesis_timestamp_seconds,
        settled_proposals: vec![],
        distributed_e8s_equivalent: 0,
        total_available_e8s_equivalent: 0,
        rounds_since_last_distribution: Some(0),
        latest_round_available_e8s_equivalent: Some(0),
    };

    assert_eq!(*gov.latest_reward_event(), expected_initial_event);
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS / 2);
    run_pending_timers();
    gov.run_periodic_tasks().now_or_never();

    // Too early: nothing should have changed
    assert_eq!(*gov.latest_reward_event(), expected_initial_event);
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    // We are now 1.5 reward periods (1.5 days) past genesis.1
    run_pending_timers();
    gov.run_periodic_tasks().now_or_never();
    // A reward event should have happened, albeit an empty one, i.e.,
    // given that no voting took place, no rewards were distributed.
    // Total available rewards in the first reward period is 100.
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 1,
            actual_timestamp_seconds: 56 + 3 * REWARD_DISTRIBUTION_PERIOD_SECONDS / 2,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
            total_available_e8s_equivalent: 100,
            rounds_since_last_distribution: Some(1),
            latest_round_available_e8s_equivalent: Some(100),
        }
    );

    // Make a proposal.
    let proposal_id = gov
        .make_proposal(
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
        .await
        .unwrap();

    // Let's advance time by two reward periods, but less than the
    // wait-for-quiet. The proposal should not be considered for rewards.
    // Given that two reward periods passed since the last reward event
    // and given that each reward period gives slightly less than 100 maturity
    // total_available_e8s_equivalent is equal to 199 maturity.
    fake_driver.advance_time_by(2 * REWARD_DISTRIBUTION_PERIOD_SECONDS);
    // We are now at +3.5 reward periods.
    run_pending_timers();
    gov.run_periodic_tasks().now_or_never();
    {
        let fully_elapsed_reward_rounds = 3;
        let total_available_e8s_equivalent = fully_elapsed_reward_rounds
            * INITIAL_REWARD_POT_PER_ROUND_E8S
            // We need to subtract a little bit, because the reward rate
            // gradually decreases.
            - 1;
        assert_eq!(
            *gov.latest_reward_event(),
            RewardEvent {
                day_after_genesis: fully_elapsed_reward_rounds,
                actual_timestamp_seconds: fake_driver.now(),
                settled_proposals: vec![],
                distributed_e8s_equivalent: 0,
                total_available_e8s_equivalent,
                rounds_since_last_distribution: Some(3), // 2 reward periods elapsed + 1 rollover round
                latest_round_available_e8s_equivalent: Some(INITIAL_REWARD_POT_PER_ROUND_E8S - 1)
            }
        );
    }
    // let's advance further in time, just before expiration
    fake_driver.advance_time_by(3 * REWARD_DISTRIBUTION_PERIOD_SECONDS - 5);
    // We are now at +6.5 - epsilon reward periods. Notice that at 6.5 reward
    // periods, the proposal become rewardable.
    run_pending_timers();
    gov.run_periodic_tasks().now_or_never();
    // This should have triggered an empty reward event
    assert_eq!(gov.latest_reward_event().day_after_genesis, 6);
    // let's advance further in time, but not far enough to trigger a reward event
    fake_driver.advance_time_by(10);
    // We are now at +6.5 + epsilon reward periods.

    // This should generate a RewardEvent, because we now have a rewardable
    // proposal (i.e. the proposal has reward_status ReadyToSettle).
    run_pending_timers();
    gov.run_periodic_tasks().now_or_never();
    assert_eq!(gov.latest_reward_event().day_after_genesis, 6);
    // let's advance far enough to trigger a reward event
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS + 1);
    run_pending_timers_every_interval_for_count(std::time::Duration::from_secs(3), 3);

    // Inspect latest_reward_event.
    let fully_elapsed_reward_rounds = 7;
    let expected_available_e8s_equivalent =
        fully_elapsed_reward_rounds * INITIAL_REWARD_POT_PER_ROUND_E8S - 3;
    let neuron_share = gov
        .neuron_store
        .with_neuron(&NeuronId::from_u64(1), |n| {
            n.deciding_voting_power(&VotingPowerEconomics::DEFAULT, fake_driver.now()) as f64
        })
        .expect("Neuron not found")
        / gov.neuron_store.with_active_neurons_iter(|iter| {
            iter.map(|neuron| {
                neuron.deciding_voting_power(&VotingPowerEconomics::DEFAULT, fake_driver.now())
            })
            .sum::<u64>() as f64
        });
    let expected_distributed_e8s_equivalent =
        (expected_available_e8s_equivalent as f64 * neuron_share) as u64;
    assert_eq!(expected_distributed_e8s_equivalent, 15);
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: fully_elapsed_reward_rounds,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![proposal_id],
            distributed_e8s_equivalent: expected_distributed_e8s_equivalent,
            total_available_e8s_equivalent: expected_available_e8s_equivalent,
            rounds_since_last_distribution: Some(fully_elapsed_reward_rounds),
            latest_round_available_e8s_equivalent: Some(INITIAL_REWARD_POT_PER_ROUND_E8S - 1)
        }
    );

    // Inspect neuron maturities.
    assert_eq!(
        gov.neuron_store
            .with_neuron(&NeuronId { id: 1 }, |n| n.clone())
            .unwrap()
            .maturity_e8s_equivalent,
        expected_distributed_e8s_equivalent,
    );
    gov.neuron_store.with_active_neurons_iter(|iter| {
        for neuron in iter {
            if neuron.id().id == 1 {
                continue;
            }

            assert_eq!(neuron.maturity_e8s_equivalent, 0, "{:#?}", neuron);
        }
    });

    // The ballots should have been cleared
    let proposal = gov.get_proposal_data(proposal_id).unwrap();
    assert!(proposal.ballots.is_empty(), "Proposal Info: {proposal:?}");

    // Now let's advance again -- a new empty reward event should happen
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    run_pending_timers();

    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 8,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
            total_available_e8s_equivalent: 99,
            rounds_since_last_distribution: Some(1),
            latest_round_available_e8s_equivalent: Some(99)
        }
    );

    // Neuron maturity should not have changed
    assert_eq!(
        gov.neuron_store
            .with_neuron(&NeuronId { id: 1 }, |n| n.clone())
            .unwrap()
            .maturity_e8s_equivalent,
        expected_distributed_e8s_equivalent,
    );
}

/// Restricted proposals, those where the eligible voters depend on the
/// proposal's content, should never be taken into account for voting rewards.
#[tokio::test]
async fn test_restricted_proposals_are_not_eligible_for_voting_rewards() {
    let genesis_timestamp_seconds = 3;

    let mut fake_driver = fake::FakeDriver::default()
        .at(genesis_timestamp_seconds)
        // We need a positive supply to ensure that there can be voting rewards
        .with_supply(Tokens::from_e8s(1_234_567_890));

    let mut fixture = fixture_for_manage_neuron();
    // Proposals last one second
    let proposal_expiration_seconds = 1;
    let wait_for_quiet_threshold_seconds = proposal_expiration_seconds;
    fixture.wait_for_quiet_threshold_seconds = wait_for_quiet_threshold_seconds;
    fixture.short_voting_period_seconds = wait_for_quiet_threshold_seconds;
    fixture.neuron_management_voting_period_seconds = Some(wait_for_quiet_threshold_seconds);
    let gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );
    set_governance_for_tests(gov);
    let gov = governance_mut();
    schedule_tasks();

    run_pending_timers();
    // Initial reward event
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 0,
            actual_timestamp_seconds: genesis_timestamp_seconds,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
            total_available_e8s_equivalent: 0,
            rounds_since_last_distribution: Some(0),
            latest_round_available_e8s_equivalent: Some(0)
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
    .await
    .unwrap();

    {
        let info = gov.get_proposal_data(ProposalId { id: 1 }).unwrap();
        assert_eq!(info.status(), ProposalStatus::Open, "{:#?}", info);
        assert_eq!(
            info.reward_status(fake_driver.now(), proposal_expiration_seconds),
            ProposalRewardStatus::Ineligible
        );
    }

    // Let's advance time one reward periods. The proposal should not be considered
    // for the reward event.
    // total_available_e8s_equivalent is equal to reward function * total supply / 365.25,
    // which is 10% * 1234567890/365.25 = 338006
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS + 1);
    run_pending_timers();

    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 1,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
            total_available_e8s_equivalent: 338006,
            rounds_since_last_distribution: Some(1),
            latest_round_available_e8s_equivalent: Some(338006)
        }
    );

    {
        gov.run_periodic_tasks().now_or_never();
        run_pending_timers();
        let info = gov.get_proposal_data(ProposalId { id: 1 }).unwrap();
        assert_eq!(info.status(), ProposalStatus::Rejected);
        assert_eq!(
            info.reward_status(fake_driver.now(), proposal_expiration_seconds),
            ProposalRewardStatus::Ineligible
        );
    }
}

#[tokio::test]
async fn test_disallow_large_manage_neuron_proposals() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_manage_neuron(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    let result = gov
        .make_proposal(
            &NeuronId { id: 2 },
            // Must match neuron 2's serialized_id.
            &principal(2),
            &Proposal {
                title: Some("A Manage Neuron Proposal".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: 1,
                    })),
                    id: None,
                    command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                        title: Some("An Install Code Proposal".to_string()),
                        summary: "proposal 1".to_string(),
                        action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
                            nns_function: 42,
                            payload: vec![1u8; 1_000_000],
                        })),
                        ..Default::default()
                    }))),
                }))),
                ..Default::default()
            },
        )
        .await;
    assert_matches!(
        result,
        Err(GovernanceError { error_type, .. })
        if error_type == ErrorType::PreconditionFailed as i32
    );

    // Sanity check: disburse maturity should be allowed.
    gov.make_proposal(
        &NeuronId { id: 2 },
        // Must match neuron 2's serialized_id.
        &principal(2),
        &Proposal {
            title: Some("A Manage Neuron Proposal".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 1 })),
                id: None,
                command: Some(Command::DisburseMaturity(DisburseMaturity {
                    percentage_to_disburse: 100,
                    to_account: None,
                    to_account_identifier: None,
                })),
            }))),
            ..Default::default()
        },
    )
    .now_or_never()
    .unwrap()
    .unwrap();
    // Disburse maturity with invalid to_account should not be allowed.
    let result = gov
        .make_proposal(
            &NeuronId { id: 2 },
            // Must match neuron 2's serialized_id.
            &principal(2),
            &Proposal {
                title: Some("A Manage Neuron Proposal".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: 1,
                    })),
                    id: None,
                    command: Some(Command::DisburseMaturity(DisburseMaturity {
                        percentage_to_disburse: 100,
                        to_account: Some(Account {
                            owner: None,
                            subaccount: Some(GovernanceSubaccount {
                                subaccount: vec![1u8; 1_000_000],
                            }),
                        }),
                        to_account_identifier: None,
                    })),
                }))),
                ..Default::default()
            },
        )
        .now_or_never()
        .unwrap();
    assert_matches!(
        result,
        Err(GovernanceError { error_type, .. })
        if error_type == ErrorType::InvalidCommand as i32
    );
    // Disburse maturity with invalid to_account_identifier should not be allowed.
    let result = gov
        .make_proposal(
            &NeuronId { id: 2 },
            // Must match neuron 2's serialized_id.
            &principal(2),
            &Proposal {
                title: Some("A Manage Neuron Proposal".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: 1,
                    })),
                    id: None,
                    command: Some(Command::DisburseMaturity(DisburseMaturity {
                        percentage_to_disburse: 100,
                        to_account: None,
                        to_account_identifier: Some(AccountIdentifierProto {
                            hash: vec![1u8; 1_000_000],
                        }),
                    })),
                }))),
                ..Default::default()
            },
        )
        .now_or_never()
        .unwrap();
    assert_matches!(
        result,
        Err(GovernanceError { error_type, .. })
        if error_type == ErrorType::InvalidCommand as i32
    );

    // Disburse with invalid to_account should not be allowed.
    let result = gov
        .make_proposal(
            &NeuronId { id: 2 },
            // Must match neuron 2's serialized_id.
            &principal(2),
            &Proposal {
                title: Some("A Manage Neuron Proposal".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: 1,
                    })),
                    id: None,
                    command: Some(Command::Disburse(Disburse {
                        amount: Some(Amount { e8s: 1_000_000_000 }),
                        to_account: Some(AccountIdentifierProto {
                            hash: vec![1u8; 1_000_000],
                        }),
                    })),
                }))),
                ..Default::default()
            },
        )
        .now_or_never()
        .unwrap();
    assert_matches!(
        result,
        Err(GovernanceError { error_type, .. })
        if error_type == ErrorType::InvalidCommand as i32
    );

    // Sanity check: follow should be allowed.
    gov.make_proposal(
        &NeuronId { id: 2 },
        // Must match neuron 2's serialized_id.
        &principal(2),
        &Proposal {
            title: Some("A Manage Neuron Proposal".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 1 })),
                id: None,
                command: Some(Command::Follow(Follow {
                    topic: Topic::Governance as i32,
                    followees: vec![NeuronId { id: 1 }],
                })),
            }))),
            ..Default::default()
        },
    )
    .now_or_never()
    .unwrap()
    .unwrap();
    // Follow with too many followees should not be allowed.
    let result = gov
        .make_proposal(
            &NeuronId { id: 2 },
            // Must match neuron 2's serialized_id.
            &principal(2),
            &Proposal {
                title: Some("A Manage Neuron Proposal".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: 1,
                    })),
                    id: None,
                    command: Some(Command::Follow(Follow {
                        topic: Topic::Governance as i32,
                        followees: vec![NeuronId { id: 1 }; 1000],
                    })),
                }))),
                ..Default::default()
            },
        )
        .now_or_never()
        .unwrap();
    assert_matches!(
        result,
        Err(GovernanceError { error_type, error_message })
        if error_type == ErrorType::InvalidCommand as i32
            && error_message.contains("Too many followees")
    );
}

#[test]
fn test_reward_distribution_skips_deleted_neurons() {
    let mut fixture = fixture_two_neurons_second_is_bigger();
    fixture.proposals.insert(
        1_u64,
        api::ProposalData {
            id: Some(ProposalId { id: 1 }),
            proposer: Some(NeuronId { id: 2 }),
            reject_cost_e8s: 0,
            proposal: Some(api::Proposal {
                title: Some("Test motion proposal".to_string()),
                summary: "A proposal voted on by a now-gone neuron".to_string(),
                url: "https://oops".to_string(),
                action: Some(api::proposal::Action::Motion(api::Motion {
                    motion_text: "a motion".to_string(),
                })),
            }),
            proposal_timestamp_seconds: 2530,
            ballots: [
                (
                    // This is a ballot by neuron 2, which still exists
                    2,
                    api::Ballot {
                        vote: Vote::Yes as i32,
                        voting_power: 250,
                    },
                ),
                (
                    // This is a ballot by neuron 999, which is not present in the neuron map.
                    999,
                    api::Ballot {
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
    let gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );

    set_governance_for_tests(gov);
    let gov = governance_mut();
    schedule_tasks();

    // Make sure that the fixture function indeed did not create a neuron 999.
    assert_matches!(gov.neuron_store.with_neuron(&NeuronId { id: 999 }, |n| n.clone()).map_err(|e| {
        let gov_error: GovernanceError = e.into();
        gov_error
    }), Err(e) if e.error_type == NotFound as i32);

    // The proposal at genesis time is not ready to be settled
    run_pending_timers();
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 0,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
            total_available_e8s_equivalent: 0,
            rounds_since_last_distribution: Some(0),
            latest_round_available_e8s_equivalent: Some(0)
        }
    );

    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS + 1);
    run_pending_timers();

    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 1,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![ProposalId { id: 1 }],
            // We should have distributed 100 e8 equivalent if all voters still existed.
            // Since neuron 999 is gone and had a voting power 3x that of neuron 2,
            // only 1/4 is actually distributed.
            distributed_e8s_equivalent: 25,
            total_available_e8s_equivalent: 100,
            rounds_since_last_distribution: Some(1),
            latest_round_available_e8s_equivalent: Some(100)
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
#[tokio::test]
async fn test_genesis_in_the_future_in_supported() {
    let mut fake_driver = fake::FakeDriver::default()
        .at(78)
        // To make assertion easy to sanity-check, the total supply of ICPs is chosen
        // so that the reward supply for the first day is 100 (365_250 * 10% / 365.25 = 100).
        .with_supply(Tokens::from_e8s(365_250));
    let mut fixture = fixture_two_neurons_second_is_bigger();
    fixture.wait_for_quiet_threshold_seconds = 2 * REWARD_DISTRIBUTION_PERIOD_SECONDS;
    fixture.short_voting_period_seconds = 13;
    fixture.neuron_management_voting_period_seconds = Some(13);
    // Let's set genesis
    let genesis_timestamp_seconds = fake_driver.now() + 3 * REWARD_DISTRIBUTION_PERIOD_SECONDS / 2;
    fixture.genesis_timestamp_seconds = genesis_timestamp_seconds;
    let gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );
    set_governance_for_tests(gov);
    let gov = governance_mut();
    schedule_tasks();

    gov.run_periodic_tasks().now_or_never();
    // At genesis, we should create an empty reward event
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 0,
            actual_timestamp_seconds: 78,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
            total_available_e8s_equivalent: 0,
            rounds_since_last_distribution: Some(0),
            latest_round_available_e8s_equivalent: Some(0)
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
        .await
        .unwrap();

    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    run_pending_timers();
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
            total_available_e8s_equivalent: 0,
            rounds_since_last_distribution: Some(0),
            latest_round_available_e8s_equivalent: Some(0)
        }
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
        .await
        .unwrap();

    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    run_pending_timers();
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
            total_available_e8s_equivalent: 0,
            rounds_since_last_distribution: Some(0),
            latest_round_available_e8s_equivalent: Some(0)
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
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS / 2 + 1);
    run_pending_timers();
    assert_eq!(
        fake_driver.now(),
        genesis_timestamp_seconds + REWARD_DISTRIBUTION_PERIOD_SECONDS + 1
    );
    // Given that the second neuron is much bigger (stake 953) compared to the
    // the first neuron (stake 23) and only the first neuron voted,
    // distributed_e8s_equivalent is 2% (=23/(23+953)) of
    // total_available_e8s_equivalent (=100) and thus equal to 2.
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 1,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![long_early_proposal_pid],
            distributed_e8s_equivalent: 2,
            total_available_e8s_equivalent: 100,
            rounds_since_last_distribution: Some(1),
            latest_round_available_e8s_equivalent: Some(100)
        }
    );

    // Let's go just at the time we should create the first reward event
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    run_pending_timers();
    // This time, the other long proposal submitted before genesis should be
    // considered
    assert_eq!(
        *gov.latest_reward_event(),
        RewardEvent {
            day_after_genesis: 2,
            actual_timestamp_seconds: fake_driver.now(),
            settled_proposals: vec![pre_genesis_proposal_that_should_settle_in_period_2_pid],
            distributed_e8s_equivalent: gov.latest_reward_event().distributed_e8s_equivalent,
            total_available_e8s_equivalent: gov
                .latest_reward_event()
                .total_available_e8s_equivalent,
            rounds_since_last_distribution: Some(1),
            latest_round_available_e8s_equivalent: gov
                .latest_reward_event()
                .latest_round_available_e8s_equivalent
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
    reward_pot_e8s: u64,
) -> Vec<u64> {
    reset_stable_memory();
    let proposals: Vec<fake::ProposalNeuronBehavior> =
        proposals.into_iter().map(|x| x.into()).collect();

    let mut fake_driver = fake::FakeDriver::default()
        .at(DEFAULT_TEST_START_TIMESTAMP_SECONDS)
        .with_supply(Tokens::from_e8s(365_250 * reward_pot_e8s / 100));

    let neurons = stakes_e8s
        .iter()
        .enumerate()
        .map(|(i, stake_e8s)| api::Neuron {
            id: Some(NeuronId { id: i as u64 }),
            controller: Some(principal(i as u64)),
            cached_neuron_stake_e8s: *stake_e8s,
            dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
            account: fake_driver
                .random_byte_array()
                .expect("Could not get random byte array")
                .to_vec(),
            ..Default::default()
        })
        .collect();

    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_neurons(neurons)
        .with_neuron_management_voting_period(10)
        .with_wait_for_quiet_threshold(10)
        .build();

    let gov = Governance::new(
        governance_proto,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );
    set_governance_for_tests(gov);
    let gov = governance_mut();
    schedule_tasks();

    let expected_initial_event = RewardEvent {
        day_after_genesis: 0,
        actual_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS,
        settled_proposals: vec![],
        distributed_e8s_equivalent: 0,
        total_available_e8s_equivalent: 0,
        rounds_since_last_distribution: Some(0),
        latest_round_available_e8s_equivalent: Some(0),
    };
    assert_eq!(*gov.latest_reward_event(), expected_initial_event);

    for (i, behavior) in (1_u64..).zip(proposals.iter()) {
        behavior.propose_and_vote(gov, format!("proposal {i}"));
    }

    // Let's advance time by one reward periods. All proposals should be considered
    // for reward.
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    // Disable wait for quiet.
    for p in &mut gov.heap_data.proposals.values_mut() {
        if let Some(wait_for_quiet_state) = &mut p.wait_for_quiet_state {
            wait_for_quiet_state.current_deadline_timestamp_seconds = fake_driver.now() - 1;
        }
    }
    gov.run_periodic_tasks().now_or_never();

    fake_driver.advance_time_by(1);
    run_pending_timers();

    run_pending_timers_every_interval_for_count(core::time::Duration::from_secs(10), 3);

    // Inspect latest_reward_event.
    let actual_reward_event = gov.latest_reward_event();
    assert_eq!(
        *actual_reward_event,
        RewardEvent {
            day_after_genesis: 1,
            actual_timestamp_seconds: DEFAULT_TEST_START_TIMESTAMP_SECONDS
                + REWARD_DISTRIBUTION_PERIOD_SECONDS
                + 1,
            settled_proposals: (1_u64..=proposals.len() as u64)
                .map(|id| ProposalId { id })
                .collect(),
            // Don't assert on distributed_e8s_equivalent here -- the assertions
            // is the job of the caller
            distributed_e8s_equivalent: actual_reward_event.distributed_e8s_equivalent,
            total_available_e8s_equivalent: reward_pot_e8s,
            rounds_since_last_distribution: Some(1),
            latest_round_available_e8s_equivalent: Some(reward_pot_e8s)
        }
    );
    assert!(
        actual_reward_event.distributed_e8s_equivalent
            <= actual_reward_event.total_available_e8s_equivalent,
        "{actual_reward_event:#?}",
    );

    (0_u64..stakes_e8s.len() as u64)
        .map(|id| {
            gov.neuron_store
                .with_neuron(&NeuronId { id }, |n| n.clone())
                .unwrap()
                .maturity_e8s_equivalent
        })
        .collect()
}

proptest! {
#![proptest_config(ProptestConfig {
    cases: 100, .. ProptestConfig::default()
})]
#[test]
fn test_topic_weights(stake in 1u64..1_000_000_000) {
    // Check that voting on
    // 1. a governance proposal yields 20 times the voting power
    // 3. other proposals yield 1 time the voting power

    // Test alloacting 100 maturity to two neurons with equal stake where
    // 1. first neuron voting on a gov proposal (20x) and
    // 2. second neuron voting on a network proposal (1x).
    // Overall reward weights are 2 * (20+1) = 42
    // First neuron gets 20/42 * 100 = 47.61 truncated to 47.
    // Second neuron gets 1/42 * 100 = 2.38 truncated to 2.
    assert_eq!(
        compute_maturities(vec![stake, stake], vec!["P-G", "-PN"], USUAL_REWARD_POT_E8S),
        vec![47, 2],
    );

    // First neuron proposes and votes on a governance proposal.
    // Second neuron proposes and votes on five network economics proposals.
    // The first neuron receives 20x the voting power and
    // the second neuron receives 5x the voting power.
    // Thus, the ratio of voting rewards ought to be 20:5.
    // Note that compute_maturities returns the resulting maturities
    // when 100 e8s of voting rewards are distributed.
    assert_eq!(
        compute_maturities(vec![stake, stake], vec!["P-G", "-PN", "-PN", "-PN", "-PN", "-PN"], USUAL_REWARD_POT_E8S),
        vec![40, 10],
    );
    // Make sure that, when voting on proposals of the same type in
    // the ratio 1:4, they get voting rewards in the ratio 1:4.
    assert_eq!(
        compute_maturities(vec![stake, stake], vec!["P-N", "-PN", "-PN", "-PN", "-PN"], USUAL_REWARD_POT_E8S),
        vec![10, 40],
    );
    assert_eq!(
        compute_maturities(vec![stake, stake], vec!["P-G", "-PG", "-PG", "-PG", "-PG"], USUAL_REWARD_POT_E8S),
        vec![10, 40],
    );
}

}

#[test]
fn test_random_voting_rewards_scenarios() {
    fn helper(seed: u64) -> Vec<fake::ProposalNeuronBehavior> {
        let mut rng = StdRng::seed_from_u64(seed);
        let neuron_weights = vec![200, 500, 300]; // Notice that the shares are 20%, 50%, and 30%.
        let total_neuron_weight: u64 = neuron_weights.iter().sum();
        assert_eq!(total_neuron_weight, 1000);
        let neuron_count = neuron_weights.len();
        const PROPOSAL_COUNT: usize = 3;
        // The compute_maturities function constructs the Governance object just
        // so such that this ends up being the size of the reward pot.
        const REWARD_POT_E8S: u64 = E8;

        fn proposal_weight(proposal_topic: fake::ProposalTopicBehavior) -> u64 {
            match proposal_topic {
                fake::ProposalTopicBehavior::Governance => 20_00,
                fake::ProposalTopicBehavior::NetworkEconomics => 1_00,
            }
        }

        // Generate some random behavior for the neurons.
        let mut proposals = vec![];
        let mut total_proposal_weight = 0;
        for _proposal_index in 0..PROPOSAL_COUNT {
            let proposer = rng.gen_range(0..neuron_count) as u64;

            let mut votes = BTreeMap::new();
            for (neuron_id, _w) in neuron_weights.iter().enumerate() {
                let neuron_id = neuron_id as u64;

                if neuron_id == proposer {
                    continue;
                }

                match [Vote::Unspecified, Vote::Yes, Vote::No]
                    .iter()
                    .choose(&mut rng)
                    .unwrap()
                {
                    Vote::Unspecified => continue,
                    vote => {
                        votes.insert(neuron_id, *vote);
                    }
                }
            }

            let proposal_topic = *[
                fake::ProposalTopicBehavior::Governance,
                fake::ProposalTopicBehavior::NetworkEconomics,
            ]
            .iter()
            .choose(&mut rng)
            .unwrap();
            total_proposal_weight += proposal_weight(proposal_topic);

            proposals.push(fake::ProposalNeuronBehavior {
                proposer,
                votes,
                proposal_topic,
            });
        }

        // Calculate the expected voting rewards.
        let mut all_expected_voting_rewards_e8s = vec![0, 0, 0];
        for proposal in &proposals {
            for (neuron_id, neuron_weight) in neuron_weights.iter().enumerate() {
                let neuron_id = neuron_id as u64;

                // Skip neurons that didn't vote.
                let earned =
                    neuron_id == proposal.proposer || proposal.votes.contains_key(&neuron_id);
                if !earned {
                    continue;
                }

                let reward_e8s =
                    REWARD_POT_E8S * proposal_weight(proposal.proposal_topic) * neuron_weight
                        / total_proposal_weight
                        / total_neuron_weight;

                all_expected_voting_rewards_e8s[neuron_id as usize] += reward_e8s;
            }
        }

        // Assert that governance generates the same result (but more complicated-ly).
        let all_observed_voting_rewards_e8s =
            compute_maturities(neuron_weights, proposals.clone(), REWARD_POT_E8S);
        assert_eq!(
            all_observed_voting_rewards_e8s.len(),
            3,
            "seed: {} proposals:\n{:#?}",
            seed,
            proposals,
        );
        // Assert that observed rewards are within 0.2% of expected.
        const EPSILON: f64 = 0.002;
        for (observed_neuron_rewards_e8s, expected_neuron_rewards_e8s) in
            all_observed_voting_rewards_e8s
                .iter()
                .zip(&all_expected_voting_rewards_e8s)
        {
            if *expected_neuron_rewards_e8s == 0 {
                assert_eq!(
                    *observed_neuron_rewards_e8s,
                    0,
                    "observed = {:?} vs expected = {:?}, seed = {}, proposals:\n{:#?}",
                    all_observed_voting_rewards_e8s,
                    all_expected_voting_rewards_e8s,
                    seed,
                    proposals,
                );
                continue;
            }

            let relative_diff = (*observed_neuron_rewards_e8s as f64
                - *expected_neuron_rewards_e8s as f64)
                / (*expected_neuron_rewards_e8s as f64);
            assert!(
                (-EPSILON..=EPSILON).contains(&relative_diff),
                "observed = {all_observed_voting_rewards_e8s:?} vs expected = {all_expected_voting_rewards_e8s:?}, seed = {seed}, proposals:\n{proposals:#?}",
            );
        }

        proposals
    }

    const SCENARIO_COUNT: u64 = 300;
    let mut unique_scenarios = HashSet::new();
    for seed in 1..=SCENARIO_COUNT {
        unique_scenarios.insert(helper(seed));
    }

    // Assert that many different scenarios were actually generated (to make
    // sure that our test code is not buggy).
    //
    // By my calculations, there are 81 ^ 3 = 531_441 unique scenarios.
    // Therefore, the vast majority of randomly generated scenarios should be
    // unique.
    //
    // This shouldn't be flaky, because we use a deterministic set of seeds for
    // our randon number generator.
    assert!(
        unique_scenarios.len() > SCENARIO_COUNT as usize - 100,
        "{}",
        unique_scenarios.len()
    );

    // Make sure that deduping actually works.
    let len = unique_scenarios.len();
    for scenario in unique_scenarios.clone() {
        unique_scenarios.insert(scenario);
    }
    assert_eq!(unique_scenarios.len(), len);
}

/// Check that, if all stakes are scaled uniformly, the maturities are
/// unchanged.
#[test]
fn test_maturities_are_invariant_by_stake_scaling() {
    assert_eq!(
        compute_maturities(vec![1], vec!["P"], USUAL_REWARD_POT_E8S),
        vec![100]
    );
    assert_eq!(
        compute_maturities(vec![2], vec!["P"], USUAL_REWARD_POT_E8S),
        vec![100]
    );
    assert_eq!(
        compute_maturities(vec![43_330], vec!["P"], USUAL_REWARD_POT_E8S),
        vec![100]
    );
}

/// Check that, if there is no proposal in the reward period, maturities do not
/// increase.
#[test]
fn test_no_maturity_increase_if_no_proposal() {
    // Single neuron
    assert_eq!(
        compute_maturities(vec![1], Vec::<&str>::new(), USUAL_REWARD_POT_E8S),
        vec![0]
    );
    // Two neurons
    assert_eq!(
        compute_maturities(vec![1, 5], Vec::<&str>::new(), USUAL_REWARD_POT_E8S),
        vec![0, 0],
    );
}

/// In this test, one neuron does nothing. It should get no maturity.
/// The other neuron does vote and thus receives 50 out 100.
#[test]
fn test_passive_neurons_dont_get_mature() {
    assert_eq!(
        compute_maturities(vec![1, 1], vec!["P-"], USUAL_REWARD_POT_E8S),
        vec![50, 0]
    );
    assert_eq!(
        compute_maturities(vec![1, 1], vec!["-P"], USUAL_REWARD_POT_E8S),
        vec![0, 50]
    );
}

/// Tests that proposing, voting yes, and voting no all result in the same
/// maturity increase
#[test]
fn test_proposing_voting_yes_voting_no_are_equivalent_for_rewards() {
    assert_eq!(
        compute_maturities(vec![1, 1], vec!["Py"], USUAL_REWARD_POT_E8S),
        vec![50, 50]
    );
    assert_eq!(
        compute_maturities(vec![1, 1], vec!["Pn"], USUAL_REWARD_POT_E8S),
        vec![50, 50]
    );
    assert_eq!(
        compute_maturities(vec![1, 1], vec!["yP"], USUAL_REWARD_POT_E8S),
        vec![50, 50]
    );
    assert_eq!(
        compute_maturities(vec![1, 1], vec!["nP"], USUAL_REWARD_POT_E8S),
        vec![50, 50]
    );
}

/// In this test, there are 4 neurons, which are not always active: they
/// participate actively (as proposer or voter) on 3/4 of the proposals. Since
/// they are all behaving similarly, they all get an identical maturity.
/// Total maturity is 100 and we have 4 neurons and 4 proposals. Hence every vote is worth
/// 100/(4*4)=6.25
/// Thus a neuron that votes 3 times, receives 3*6.25 = 18.75 truncated to 18.
#[test]
fn test_neuron_sometimes_active_sometimes_passive_which_proposal_does_not_matter() {
    assert_eq!(
        compute_maturities(
            vec![1, 1, 1, 1],
            vec!["-Pyn", "P-yn", "Py-n", "Pyn-"],
            USUAL_REWARD_POT_E8S
        ),
        vec![18, 18, 18, 18]
    );
}

/// In this test, one neuron is always active, but the other not always. The
/// more active neuron should get more maturity.
#[test]
fn test_active_neuron_gets_more_mature_than_less_active_one() {
    assert_eq!(
        compute_maturities(vec![1, 1], vec!["P-", "P-", "yP"], USUAL_REWARD_POT_E8S),
        // We have 2 neurons (with stake 1 each) and 3 proposals
        // Thus, out of 100 maturity, one vote is worth 100/(2*3)=16.6
        vec![50, 16] // first neuron voted 3 times, second 1 time
    );
    assert_eq!(
        compute_maturities(
            vec![2, 1, 1], // First neuron has more stake not to trigger wait for quiet.
            vec!["P--", "P--", "Py-", "P-y", "Pn-", "P-n", "Pyn"],
            USUAL_REWARD_POT_E8S,
        ),
        // We have a total stake of 4 and 7 proposals.
        // Thus, out of 100 maturity, one vote is worth 100/(4*7)=3.57
        // The first neuron (with a stake of 2) votes 7 times and thus receives 2*7*100/(4*7)=50
        // The second neuron (with a stake of 1) votes 3 times and thus receives 1*3*100/(4*7)=10.71
        // The third neuron votes like the second neuron.
        vec![50, 10, 10]
    );
}

#[test]
fn test_more_stakes_gets_more_maturity() {
    assert_eq!(
        compute_maturities(vec![3, 1], vec!["Py"], USUAL_REWARD_POT_E8S),
        vec![75, 25]
    );
    assert_eq!(
        compute_maturities(vec![3, 1], vec!["yP"], USUAL_REWARD_POT_E8S),
        vec![75, 25]
    );
}

/// This test combines differences in activity and differences in stakes to
/// compute rewards.
#[test]
fn test_reward_complex_scenario() {
    assert_eq!(
        compute_maturities(
            vec![3, 1, 1],
            vec!["-P-", "--P", "y-P", "P-n"],
            USUAL_REWARD_POT_E8S
        ),
        // First neuron voted twice, 2 * 3 = 6 used voting rights
        // Second neuron voted once, 1 * 1 = 1 used voting rights
        // Third neuron voted 3 times, 3 * 1 = 3 used voting rights
        // Total 10 used voting rights
        // There are 4 proposals and a total stake of 5. Thus every vote (per stake)
        // is worth 100/(4*5) = 5.
        // As a consequence the first neuron receives 6 * 5 = 30, the second 1*5 and
        // the third neuron 3*5=15.
        vec![30, 5, 15]
    );
}

fn fixture_for_approve_kyc() -> api::Governance {
    let mut driver = fake::FakeDriver::default();
    let principal1 = PrincipalId::new_self_authenticating(b"SID1");
    let principal2 = PrincipalId::new_self_authenticating(b"SID2");
    let principal3 = PrincipalId::new_self_authenticating(b"SID3");

    let neurons = vec![
        api::Neuron {
            id: Some(NeuronId { id: 1 }),
            controller: Some(principal1),
            cached_neuron_stake_e8s: 10 * E8,
            account: driver
                .random_byte_array()
                .expect("Could not get random byte array")
                .to_vec(),
            kyc_verified: false,
            dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
            aging_since_timestamp_seconds: u64::MAX,
            ..Default::default()
        },
        api::Neuron {
            id: Some(NeuronId { id: 2 }),
            controller: Some(principal2),
            cached_neuron_stake_e8s: 10 * E8,
            account: driver
                .random_byte_array()
                .expect("Could not get random byte array")
                .to_vec(),
            kyc_verified: false,
            dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
            aging_since_timestamp_seconds: u64::MAX,
            ..Default::default()
        },
        api::Neuron {
            id: Some(NeuronId { id: 3 }),
            controller: Some(principal2),
            cached_neuron_stake_e8s: 10 * E8,
            account: driver
                .random_byte_array()
                .expect("Could not get random byte array")
                .to_vec(),
            kyc_verified: false,
            dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
            aging_since_timestamp_seconds: u64::MAX,
            ..Default::default()
        },
        api::Neuron {
            id: Some(NeuronId { id: 4 }),
            controller: Some(principal3),
            cached_neuron_stake_e8s: 10 * E8,
            account: driver
                .random_byte_array()
                .expect("Could not get random byte array")
                .to_vec(),
            kyc_verified: false,
            dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
            aging_since_timestamp_seconds: u64::MAX,
            ..Default::default()
        },
    ];

    GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(api::NetworkEconomics::with_default_values())
        .with_neurons(neurons)
        .build()
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
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_approve_kyc() {
    let governance_proto = fixture_for_approve_kyc();
    let driver = fake::FakeDriver::default()
        .with_ledger_from_neurons(
            &governance_proto
                .neurons
                .values()
                .cloned()
                .collect::<Vec<api::Neuron>>(),
        )
        .with_supply(Tokens::from_tokens(1_000_000).unwrap());
    let mut gov = Governance::new(
        governance_proto,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    let neuron_a = gov
        .neuron_store
        .with_neuron(&NeuronId::from_u64(1), |n| n.clone())
        .expect("Neuron not found");
    let neuron_b = gov
        .neuron_store
        .with_neuron(&NeuronId::from_u64(2), |n| n.clone())
        .expect("Neuron not found");

    let principal1 = neuron_a.controller();
    let principal2 = neuron_b.controller();

    // Test that non kyc'd neurons can't be disbursed to accounts.
    let result = gov
        .disburse_neuron(
            &neuron_a.id(),
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
            &neuron_b.id(),
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

    assert!(
        !gov.neuron_store
            .with_neuron(&NeuronId::from_u64(1), |n| n.kyc_verified)
            .expect("Neuron not found")
    );
    assert!(
        !gov.neuron_store
            .with_neuron(&NeuronId::from_u64(2), |n| n.kyc_verified)
            .expect("Neuron not found")
    );
    assert!(
        !gov.neuron_store
            .with_neuron(&NeuronId::from_u64(3), |n| n.kyc_verified)
            .expect("Neuron not found")
    );
    assert!(
        !gov.neuron_store
            .with_neuron(&NeuronId::from_u64(4), |n| n.kyc_verified)
            .expect("Neuron not found")
    );

    gov.approve_genesis_kyc(&[principal1, principal2]).unwrap();

    assert!(
        gov.neuron_store
            .with_neuron(&NeuronId::from_u64(1), |n| n.kyc_verified)
            .expect("Neuron not found")
    );
    assert!(
        gov.neuron_store
            .with_neuron(&NeuronId::from_u64(2), |n| n.kyc_verified)
            .expect("Neuron not found")
    );
    assert!(
        gov.neuron_store
            .with_neuron(&NeuronId::from_u64(3), |n| n.kyc_verified)
            .expect("Neuron not found")
    );
    assert!(
        !gov.neuron_store
            .with_neuron(&NeuronId::from_u64(4), |n| n.kyc_verified)
            .expect("Neuron not found")
    );

    // Disbursing should now work.
    let _ = gov
        .disburse_neuron(
            &neuron_a.id(),
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
            &neuron_b.id(),
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

    let neuron_a = api::Neuron {
        id: Some(NeuronId { id: 1 }),
        controller: Some(principal1),
        account: driver
            .random_byte_array()
            .expect("Could not get random byte array")
            .to_vec(),
        dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
        aging_since_timestamp_seconds: u64::MAX,
        ..Default::default()
    };
    let neuron_b = api::Neuron {
        id: Some(NeuronId { id: 2 }),
        controller: Some(principal2),
        account: driver
            .random_byte_array()
            .expect("Could not get random byte array")
            .to_vec(),
        dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
        aging_since_timestamp_seconds: u64::MAX,
        ..Default::default()
    };
    let neuron_c = api::Neuron {
        id: Some(NeuronId { id: 3 }),
        controller: Some(principal2),
        account: driver
            .random_byte_array()
            .expect("Could not get random byte array")
            .to_vec(),
        dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
        aging_since_timestamp_seconds: u64::MAX,
        ..Default::default()
    };
    let neuron_d = api::Neuron {
        id: Some(NeuronId { id: 4 }),
        controller: Some(principal2),
        hot_keys: vec![principal4],
        account: driver
            .random_byte_array()
            .expect("Could not get random byte array")
            .to_vec(),
        dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
        aging_since_timestamp_seconds: u64::MAX,
        ..Default::default()
    };

    let mut governance_init = empty_fixture();
    governance_init.neurons = btreemap! {
        1 => neuron_a,
        2 => neuron_b,
        3 => neuron_c,
        4 => neuron_d,
    };

    let driver = fake::FakeDriver::default();
    let gov = Governance::new(
        governance_init,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    assert_eq!(
        gov.get_neuron_ids_by_principal(&principal1),
        btreeset! { NeuronId { id: 1 } }
    );
    assert_eq!(
        gov.get_neuron_ids_by_principal(&principal2),
        btreeset! { NeuronId { id: 2 }, NeuronId { id: 3 }, NeuronId { id: 4 } }
    );
    assert_eq!(
        gov.get_neuron_ids_by_principal(&principal3),
        BTreeSet::<NeuronId>::new()
    );
    assert_eq!(gov.get_neuron_ids_by_principal(&principal3), btreeset! {});
    assert_eq!(
        gov.get_neuron_ids_by_principal(&principal4),
        btreeset! { NeuronId { id: 4 } }
    );
}

fn empty_fixture() -> api::Governance {
    api::Governance {
        economics: Some(api::NetworkEconomics::with_default_values()),
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
        CommandResponse::Error(error) => Err(GovernanceError::from(error)),
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
        .at(START_TIMESTAMP_SECONDS)
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
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Add a stake transfer for this neuron, emulating a ledger call.
    let nid =
        claim_or_refresh_neuron_by_memo(&mut gov, &from, None, to_subaccount, Memo(nonce), None)
            .unwrap();

    assert_eq!(gov.neuron_store.len(), 1);

    assert!(
        dissolve_delay_seconds >= INITIAL_NEURON_DISSOLVE_DELAY,
        "Dissolve delay too low, as it is below the minimum threshold."
    );

    let increase_by = dissolve_delay_seconds.saturating_sub(INITIAL_NEURON_DISSOLVE_DELAY);

    if increase_by > 0 {
        gov.neuron_store
            .with_neuron_mut(&nid, |neuron| {
                neuron.configure(
                    &from,
                    driver.now(),
                    &Configure {
                        operation: Some(Operation::IncreaseDissolveDelay(IncreaseDissolveDelay {
                            additional_dissolve_delay_seconds: increase_by as u32,
                        })),
                    },
                )
            })
            .expect("Neuron not found")
            .expect("Configure failed");
    }
    (driver, gov, nid, to_subaccount)
}

/// Creates a neuron that has accumulated some maturity.
///
/// If `dissolved` is true, the returned neuron is in the "dissolved" state,
/// otherwise the returned neuron is in the "not-dissolving" state.
fn create_mature_neuron(dissolved: bool) -> (fake::FakeDriver, Governance, api::Neuron) {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds =
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
    let neuron_stake_e8s = 100_000_000;

    let (mut driver, mut gov, id, to_subaccount) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    // Make sure the neuron was created with the right details.
    let expected_voting_power = neuron_stake_e8s
        // Age bonus.
        * 17
        / 16;
    assert_eq!(
        gov.get_full_neuron(&id, &from).unwrap(),
        api::Neuron {
            id: Some(id),
            account: to_subaccount.to_vec(),
            controller: Some(from),
            cached_neuron_stake_e8s: neuron_stake_e8s,
            created_timestamp_seconds: driver.now(),
            aging_since_timestamp_seconds: driver.now(),
            dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
                dissolve_delay_seconds
            )),
            kyc_verified: true,
            visibility: Some(Visibility::Private as i32),
            voting_power_refreshed_timestamp_seconds: Some(START_TIMESTAMP_SECONDS),
            deciding_voting_power: Some(expected_voting_power),
            potential_voting_power: Some(expected_voting_power),
            maturity_disbursements_in_progress: Some(vec![]),
            ..Default::default()
        }
    );
    assert_eq!(gov.get_neuron_ids_by_principal(&from), btreeset! { id });

    // Dissolve the neuron if `dissolved` is true
    if dissolved {
        gov.neuron_store
            .with_neuron_mut(&id, |neuron| {
                neuron.configure(
                    &from,
                    driver.now(),
                    &Configure {
                        operation: Some(Operation::StartDissolving(StartDissolving {})),
                    },
                )
            })
            .expect("Neuron not found")
            .expect("Configure neuron failed.");
        // Advance the time in the env
        driver.advance_time_by(
            VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS + 1,
        );

        // The neuron state should now be "Dissolved", meaning we can
        // now disburse the neuron.
        let neuron_info = gov.get_neuron_info(&id, *RANDOM_PRINCIPAL_ID).unwrap();
        assert_eq!(neuron_info.state, NeuronState::Dissolved as i32);
    } else {
        driver.advance_time_by(
            VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS + 1,
        );
    }

    gov.neuron_store
        .with_neuron_mut(&id, |neuron| {
            let neuron_fees_e8s = 50_000_000; // 0.5 ICP
            let neuron_maturity = 25_000_000;
            // Pretend the neuron has some rewards and fees to pay.
            neuron.neuron_fees_e8s = neuron_fees_e8s;
            // .. and some maturity to collect.
            neuron.maturity_e8s_equivalent = neuron_maturity;
        })
        .expect("Neuron not found");

    let neuron = gov.get_full_neuron(&id, &from).unwrap();

    (driver, gov, neuron)
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_neuron_lifecycle() {
    let (driver, mut gov, neuron) = create_mature_neuron(true);

    let id = neuron.id.unwrap();
    let from = neuron.controller.unwrap();
    let neuron_stake_e8s = neuron.cached_neuron_stake_e8s;
    let neuron_fees_e8s = neuron.neuron_fees_e8s;

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
        // In the end, the user's account should have the stake - fees
        // - transaction fees.
        neuron_stake_e8s
            - neuron_fees_e8s
            - gov
                .heap_data
                .economics
                .as_ref()
                .unwrap()
                .transaction_fee_e8s,
    );
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_disburse_to_subaccount() {
    let (driver, mut gov, neuron) = create_mature_neuron(true);

    let id = neuron.id.unwrap();
    let from = neuron.controller.unwrap();
    let neuron_stake_e8s = neuron.cached_neuron_stake_e8s;
    let neuron_fees_e8s = neuron.neuron_fees_e8s;

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
        // In the end, the user's account should have the stake - fees
        // - transaction fees.
        neuron_stake_e8s
            - neuron_fees_e8s
            - gov
                .heap_data
                .economics
                .as_ref()
                .unwrap()
                .transaction_fee_e8s,
    );
}

#[test]
fn test_nns1_520() {
    let (driver, mut gov, neuron) = create_mature_neuron(true);

    let id = neuron.id.unwrap();
    let from = neuron.controller.unwrap();
    let neuron_stake_e8s = neuron.cached_neuron_stake_e8s;
    let neuron_fees_e8s = neuron.neuron_fees_e8s;

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
        // In the end, the user's account should have the stake - fees
        // - transaction fees.
        neuron_stake_e8s
            - neuron_fees_e8s
            - gov
                .heap_data
                .economics
                .as_ref()
                .unwrap()
                .transaction_fee_e8s,
    );

    assert_eq!(
        gov.neuron_store
            .with_neuron(&id, |n| n.cached_neuron_stake_e8s)
            .expect("Neuron not found"),
        0
    );
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_disburse_to_main_account() {
    let (driver, mut gov, neuron) = create_mature_neuron(true);

    let id = neuron.id.unwrap();
    let from = neuron.controller.unwrap();
    let neuron_stake_e8s = neuron.cached_neuron_stake_e8s;
    let neuron_fees_e8s = neuron.neuron_fees_e8s;

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
        // In the end, the user's account should have the stake - fees
        // - transaction fees.
        neuron_stake_e8s
            - neuron_fees_e8s
            - gov
                .heap_data
                .economics
                .as_ref()
                .unwrap()
                .transaction_fee_e8s,
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
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    (driver, gov, to_subaccount)
}

fn claim_neuron_by_memo(
    gov: &mut Governance,
    owner: PrincipalId,
    memo: u64,
) -> ManageNeuronResponse {
    gov.manage_neuron(
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
    .unwrap()
}

/// Tests that the controller of a neuron (the principal whose hash was used
/// to build the subaccount) can claim a neuron just with the memo.
#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_claim_neuron_by_memo_only() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let memo = 1234u64;
    let stake = Tokens::from_tokens(10u64).unwrap();
    let (_, mut gov, _) = governance_with_staked_unclaimed_neuron(&owner, memo, stake);

    let manage_neuron_response = claim_neuron_by_memo(&mut gov, owner, memo);

    let nid = match manage_neuron_response.command.unwrap() {
        CommandResponse::ClaimOrRefresh(response) => response.refreshed_neuron_id,
        CommandResponse::Error(error) => panic!("Error claiming neuron: {error:?}"),
        _ => panic!("Invalid response."),
    };

    assert!(nid.is_some());
    let nid = nid.unwrap();
    let neuron = gov.neuron_store.with_neuron(&nid, |n| n.clone()).unwrap();
    assert_eq!(neuron.controller(), owner);
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_claim_neuron_without_minimum_stake_fails() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let memo = 1234u64;
    let stake = Tokens::from_e8s(50000000u64);
    let (_, mut gov, _) = governance_with_staked_unclaimed_neuron(&owner, memo, stake);

    let manage_neuron_response = claim_neuron_by_memo(&mut gov, owner, memo);

    match manage_neuron_response.command.unwrap() {
        CommandResponse::Error(error) => {
            assert_eq!(
                ErrorType::try_from(error.error_type).unwrap(),
                ErrorType::InsufficientFunds
            );
        }
        _ => panic!("Invalid response."),
    };
}

fn do_test_claim_neuron_by_memo_and_controller(owner: PrincipalId, caller: PrincipalId) {
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
        CommandResponse::Error(error) => panic!("Error claiming neuron: {error:?}"),
        _ => panic!("Invalid response."),
    };

    assert!(nid.is_some());
    let nid = nid.unwrap();
    let neuron = gov.neuron_store.with_neuron(&nid, |n| n.clone()).unwrap();
    assert_eq!(neuron.controller(), owner);
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());
}

/// Like the above, but explicitly sets the controller in the MemoAndController
/// struct.
#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_claim_neuron_memo_and_controller_by_controller() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    do_test_claim_neuron_by_memo_and_controller(owner, owner);
}

/// Tests that a non-controller can claim a neuron for the controller (the
/// principal whose id was used to build the subaccount).
#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_claim_neuron_memo_and_controller_by_proxy() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let caller = *TEST_NEURON_2_OWNER_PRINCIPAL;
    do_test_claim_neuron_by_memo_and_controller(owner, caller);
}

/// Tests that a non-controller can't claim a neuron for themselves.
#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
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
    let (mut driver, mut gov, nid, subaccount) = governance_with_staked_neuron(
        INITIAL_NEURON_DISSOLVE_DELAY,
        stake.get_e8s(),
        0,
        owner,
        memo.0,
    );

    let neuron = gov.neuron_store.with_neuron(&nid, |n| n.clone()).unwrap();
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());

    driver.add_funds_to_account(
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(subaccount)),
        stake.get_e8s(),
    );

    // stake shouldn't have changed.
    let neuron = gov.neuron_store.with_neuron(&nid, |n| n.clone()).unwrap();
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
        CommandResponse::Error(error) => panic!("Error claiming neuron: {error:?}"),
        _ => panic!("Invalid response."),
    };

    assert!(nid.is_some());
    let nid = nid.unwrap();
    let neuron = gov.neuron_store.with_neuron(&nid, |n| n.clone()).unwrap();
    assert_eq!(neuron.controller(), owner);
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s() * 2);
}

/// Tests that a neuron can be refreshed by memo by it's controller.
#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_refresh_neuron_by_memo_by_controller() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    refresh_neuron_by_memo(owner, owner);
}

/// Tests that a neuron can be refreshed by memo by proxy.
#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
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
    let (mut driver, mut gov, nid, subaccount) = governance_with_staked_neuron(
        INITIAL_NEURON_DISSOLVE_DELAY,
        stake.get_e8s(),
        0,
        owner,
        memo.0,
    );

    let neuron = gov.neuron_store.with_neuron(&nid, |n| n.clone()).unwrap();
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());

    driver.add_funds_to_account(
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(subaccount)),
        stake.get_e8s(),
    );

    // stake shouldn't have changed.
    let neuron = gov
        .neuron_store
        .with_neuron(&nid, |n| n.clone())
        .unwrap()
        .clone();
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());

    let neuron_id_or_subaccount = match refresh_by {
        RefreshBy::NeuronId => NeuronIdOrSubaccount::NeuronId(neuron.id()),
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
        CommandResponse::Error(error) => panic!("Error claiming neuron: {error:?}"),
        _ => panic!("Invalid response."),
    };

    assert!(nid.is_some());
    let nid = nid.unwrap();
    let neuron = gov.neuron_store.with_neuron(&nid, |n| n.clone()).unwrap();
    assert_eq!(neuron.controller(), owner);
    assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s() * 2);
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_refresh_neuron_by_id_by_controller() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    refresh_neuron_by_id_or_subaccount(owner, owner, RefreshBy::NeuronId);
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_refresh_neuron_by_id_by_proxy() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    refresh_neuron_by_id_or_subaccount(owner, caller, RefreshBy::NeuronId);
}

/// Tests that a neuron can be refreshed by subaccount, and that anyone can do
/// it.
#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_refresh_neuron_by_subaccount_by_controller() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    refresh_neuron_by_id_or_subaccount(owner, owner, RefreshBy::Subaccount);
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_refresh_neuron_by_subaccount_by_proxy() {
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let caller = *TEST_NEURON_1_OWNER_PRINCIPAL;
    refresh_neuron_by_id_or_subaccount(owner, caller, RefreshBy::Subaccount);
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_claim_or_refresh_neuron_does_not_overflow() {
    let (mut driver, mut gov, neuron) = create_mature_neuron(true);
    let nid = neuron.id.unwrap();
    let subaccount = Subaccount::try_from(&neuron.account[..]).unwrap();

    gov.with_neuron_mut(&nid, |neuron| {
        // Increase the dissolve delay, this will make the neuron start aging from
        // 'now'.
        neuron
            .configure(
                &TEST_NEURON_1_OWNER_PRINCIPAL,
                driver.now(),
                &Configure {
                    operation: Some(Operation::IncreaseDissolveDelay(IncreaseDissolveDelay {
                        additional_dissolve_delay_seconds: 6
                            * ic_nervous_system_common::ONE_MONTH_SECONDS as u32,
                    })),
                },
            )
            .unwrap();
    })
    .unwrap();

    // Advance the current time, so that the neuron has accumulated
    // some age.
    driver.advance_time_by(12 * ic_nervous_system_common::ONE_MONTH_SECONDS);

    let neuron_info = gov.get_neuron_info(&nid, *RANDOM_PRINCIPAL_ID).unwrap();
    assert_eq!(
        neuron_info.age_seconds,
        12 * ic_nervous_system_common::ONE_MONTH_SECONDS,
    );
    let previous_stake_e8s = neuron_info.stake_e8s;

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
    assert_eq!(
        gov.get_neuron_info(&nid, *RANDOM_PRINCIPAL_ID)
            .unwrap()
            .stake_e8s,
        previous_stake_e8s + 100_000_000_000_000
    );
}

#[test]
fn test_rate_limiting_neuron_creation() {
    let current_peak = MAX_NEURON_CREATION_SPIKE;
    let minimum_wait_for_capacity_increase = MINIMUM_SECONDS_BETWEEN_ALLOWANCE_INCREASE;

    // Some neurons with maturity and stake so we can spawn and split
    let staked_neurons = (1..=(current_peak - 1))
        .map(|i| {
            let controller = PrincipalId::new_user_test_id(i);
            let nonce = 1234u64;
            api::Neuron {
                id: Some(NeuronId::from_u64(i)),
                account: ledger::compute_neuron_staking_subaccount(controller, nonce).into(),
                controller: Some(controller),
                cached_neuron_stake_e8s: 10 * E8,
                neuron_fees_e8s: 0,
                created_timestamp_seconds: 0,
                aging_since_timestamp_seconds: 0,
                maturity_e8s_equivalent: 10 * E8,
                staked_maturity_e8s_equivalent: Some(10 * E8),
                dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
                    VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
                )),
                ..Default::default()
            }
        })
        .collect::<Vec<_>>();

    let (driver, mut gov) = governance_with_neurons(&staked_neurons);

    for i in 1..=(current_peak - 1) {
        let neuron_id = NeuronId::from_u64(i);
        // Split
        let controller = gov
            .neuron_store
            .with_neuron(&neuron_id, |neuron| neuron.controller())
            .unwrap();
        gov.split_neuron(
            &neuron_id,
            &controller,
            &Split {
                amount_e8s: 5 * E8,
                memo: None,
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

        // spawn should not be rate limited
        let controller = gov
            .neuron_store
            .with_neuron(&neuron_id, |neuron| neuron.controller())
            .unwrap();
        gov.spawn_neuron(
            &neuron_id,
            &controller,
            &Spawn {
                new_controller: Some(PrincipalId::new_user_test_id(i * 2)),
                nonce: None,
                percentage_to_spawn: Some(40),
            },
        )
        .expect(
            "We unexpectedly hit the rate limit, which means spawn is not exempt from the limits. \
                This is an error.",
        );
    }

    // Claim our first neuron... should affect limits
    let controller = PrincipalId::new_user_test_id(100);
    let nonce = 0;
    let amount_e8s = 10 * E8;
    let new_neuron_subaccount = ledger::compute_neuron_staking_subaccount(controller, nonce);
    let driver = driver.with_ledger_accounts(vec![fake::FakeAccount {
        id: AccountIdentifier::new(
            ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
            Some(new_neuron_subaccount),
        ),
        amount_e8s,
    }]);

    let result: ManageNeuronResponse = claim_neuron_by_memo(&mut gov, controller, nonce);
    result.panic_if_error("Could not claim neuron!");

    // Claim another neuron, which should then fail
    let controller = PrincipalId::new_user_test_id(101);
    let nonce = 1;
    let new_neuron_subaccount = ledger::compute_neuron_staking_subaccount(controller, nonce);
    let mut driver = driver.with_ledger_accounts(vec![fake::FakeAccount {
        id: AccountIdentifier::new(
            ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
            Some(new_neuron_subaccount),
        ),
        amount_e8s,
    }]);

    let result: ManageNeuronResponse = claim_neuron_by_memo(&mut gov, controller, nonce);

    match result.command {
        Some(CommandResponse::Error(e)) => {
            assert_eq!(
                e,
                api::GovernanceError::new_with_message(
                    api::governance_error::ErrorType::Unavailable,
                    "Reached maximum number of neurons that can be created in this hour. \
                        Please wait and try again later."
                )
            )
        }
        r => panic!("We did not get a rate limited response!, {r:?}"),
    }

    // Advance time by just enough to reset the rate limit
    driver.advance_time_by(minimum_wait_for_capacity_increase + 1);

    // Now we should be able to again claim a neuron.
    // NOTE: IT IS ESSENTIAL that something is different about these parameters, or the call
    // will succeed because that neuron had already been claimed.
    let controller = PrincipalId::new_user_test_id(102);
    let nonce = 2;
    let amount_e8s = 10 * E8;
    let new_neuron_subaccount = ledger::compute_neuron_staking_subaccount(controller, nonce);
    driver = driver.with_ledger_accounts(vec![fake::FakeAccount {
        id: AccountIdentifier::new(
            ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
            Some(new_neuron_subaccount),
        ),
        amount_e8s,
    }]);

    let result: ManageNeuronResponse = claim_neuron_by_memo(&mut gov, controller, nonce);
    result.panic_if_error(&format!("Could not claim neuron with nonce: {nonce}!"));

    // But we should only be able to create one after that time period.
    let controller = PrincipalId::new_user_test_id(103);
    let nonce = 3;
    let amount_e8s = 10 * E8;
    let new_neuron_subaccount = ledger::compute_neuron_staking_subaccount(controller, nonce);
    driver.with_ledger_accounts(vec![fake::FakeAccount {
        id: AccountIdentifier::new(
            ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
            Some(new_neuron_subaccount),
        ),
        amount_e8s,
    }]);

    let result: ManageNeuronResponse = claim_neuron_by_memo(&mut gov, controller, nonce);
    match result.command {
        Some(CommandResponse::Error(e)) => {
            assert_eq!(
                e,
                api::GovernanceError::new_with_message(
                    api::governance_error::ErrorType::Unavailable,
                    "Reached maximum number of neurons that can be created in this hour. \
                        Please wait and try again later."
                )
            )
        }
        r => panic!("We did not get a rate limited response!, {r:?}"),
    }
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_cant_disburse_without_paying_fees() {
    let (driver, mut gov, neuron) = create_mature_neuron(true);

    let id = neuron.id.unwrap();
    let from = neuron.controller.unwrap();
    let neuron_stake_e8s = neuron.cached_neuron_stake_e8s;
    let neuron_fees_e8s = neuron.neuron_fees_e8s;

    // Try to disburse more than the stake amount, this should fail.
    // and cause the neuron to be unchanged.
    let result = gov
        .disburse_neuron(
            &id,
            &from,
            &Disburse {
                amount: Some(Amount {
                    e8s: 1000 * 100_000_000,
                }),
                to_account: Some(AccountIdentifier::new(from, None).into()),
            },
        )
        .now_or_never()
        .unwrap();

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().error_type, ErrorType::External as i32);

    assert_eq!(
        0,
        gov.neuron_store
            .with_neuron(&id, |neuron| neuron.neuron_fees_e8s)
            .expect("Neuron not found")
    );
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
    assert_eq!(result.unwrap_err().error_type, ErrorType::External as i32);

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
        // In the end, the user's account should have the stake - fees
        // - transaction fees.
        neuron_stake_e8s
            - neuron_fees_e8s
            - gov
                .heap_data
                .economics
                .as_ref()
                .unwrap()
                .transaction_fee_e8s,
    );
}

/// Checks that split_neuron fails if the preconditions are not met. In
/// particular, an attempt to split a neuron fails if:
/// * 1. the neuron does not exist.
/// * 2. the caller is not the neuron's controller.
/// * 3. the parent neuron would be left with less than the minimum stake.
/// * 4. the child neuron would have less than the minimum stake.
///
/// In all these cases it must thus hold that:
/// * the correct error is returned
/// * the parent neuron is unchanged
/// * the list of all neurons remained unchanged
/// * the list of accounts is unchanged
#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_neuron_split_fails() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds =
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;

    let (driver, mut gov, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    let neuron = gov
        .neuron_store
        .with_neuron(&id, |neuron| neuron.clone())
        .expect("Neuron not found");

    let transaction_fee = gov
        .heap_data
        .economics
        .as_ref()
        .unwrap()
        .transaction_fee_e8s;
    let min_neuron_stake = gov
        .heap_data
        .economics
        .as_ref()
        .unwrap()
        .neuron_minimum_stake_e8s;

    assert_eq!(
        gov.get_neuron_info(&id, *RANDOM_PRINCIPAL_ID)
            .unwrap()
            .state,
        NeuronState::NotDissolving as i32
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
                memo: None,
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
                memo: None,
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
                memo: None,
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
                memo: None,
            },
        )
        .now_or_never()
        .unwrap();
    assert_matches!(
       split_res_4,
       Err(GovernanceError{error_type: code, error_message: msg})
           if code == InsufficientFunds as i32 && msg.to_lowercase().contains("at the minimum, one needs the minimum neuron stake"));

    // Parent neuron did not change
    assert_eq!(
        gov.neuron_store.with_neuron(&id, |n| n.clone()).unwrap(),
        neuron_before
    );
    // There is still only one neuron
    assert_eq!(gov.neuron_store.len(), 1);
    //  There is still only one ledger account.
    driver.assert_num_neuron_accounts_exist(1);
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_neuron_split() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds =
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;
    let maturity_e8s = 500_000_000;
    let staked_maturity_e8s = 400_000_000;

    let (mut driver, mut governance, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    driver.advance_time_by(1234);

    let neuron_state = {
        governance
            .neuron_store
            .with_neuron_mut(&id, |neuron| {
                // Make sure the parent neuron also has maturity and staked maturity.
                neuron.maturity_e8s_equivalent = maturity_e8s;
                neuron.staked_maturity_e8s_equivalent = Some(staked_maturity_e8s);
            })
            .expect("Neuron not found");
        governance
            .get_neuron_info(&id, *RANDOM_PRINCIPAL_ID)
            .unwrap()
            .state
    };

    assert_eq!(neuron_state, NeuronState::NotDissolving as i32);

    let transaction_fee = governance
        .heap_data
        .economics
        .as_ref()
        .unwrap()
        .transaction_fee_e8s;

    let child_nid = governance
        .split_neuron(
            &id,
            &from,
            &Split {
                amount_e8s: 200_000_000,
                memo: None,
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    // We should now have 2 neurons.
    assert_eq!(governance.neuron_store.len(), 2);
    // And we should have two ledger accounts.
    driver.assert_num_neuron_accounts_exist(2);

    let child_neuron = governance
        .get_full_neuron(&child_nid, &from)
        .expect("The child neuron is missing");
    let parent_neuron = governance
        .get_full_neuron(&id, &from)
        .expect("The parent neuron is missing");

    assert_eq!(
        parent_neuron.cached_neuron_stake_e8s,
        neuron_stake_e8s - 200_000_000
    );
    assert_eq!(parent_neuron.maturity_e8s_equivalent, 400_000_000);
    assert_eq!(
        parent_neuron.staked_maturity_e8s_equivalent,
        Some(320_000_000)
    );
    assert_eq!(child_neuron.controller, parent_neuron.controller);
    assert_eq!(
        child_neuron.cached_neuron_stake_e8s,
        200_000_000 - transaction_fee
    );
    assert_eq!(child_neuron.maturity_e8s_equivalent, 100_000_000);
    assert_eq!(
        child_neuron.staked_maturity_e8s_equivalent,
        Some(80_000_000)
    );
    assert_eq!(child_neuron.created_timestamp_seconds, driver.now(),);
    assert_ne!(
        child_neuron.created_timestamp_seconds,
        parent_neuron.created_timestamp_seconds,
    );
    assert_eq!(
        child_neuron.aging_since_timestamp_seconds,
        parent_neuron.aging_since_timestamp_seconds
    );
    assert_eq!(child_neuron.dissolve_state, parent_neuron.dissolve_state);
    assert_eq!(child_neuron.kyc_verified, true);
    assert_eq!(
        child_neuron.voting_power_refreshed_timestamp_seconds,
        Some(driver.now()),
    );
    assert!(
        child_neuron
            .voting_power_refreshed_timestamp_seconds
            .unwrap()
            > parent_neuron
                .voting_power_refreshed_timestamp_seconds
                .unwrap(),
        "{:?} vs. {:?}",
        child_neuron.voting_power_refreshed_timestamp_seconds,
        parent_neuron.voting_power_refreshed_timestamp_seconds,
    );

    let neuron_ids = governance.get_neuron_ids_by_principal(&from);
    let expected_neuron_ids = btreeset! { id, child_nid };
    assert_eq!(neuron_ids, expected_neuron_ids);

    let child_neuron_split_by_memo_id = governance
        .split_neuron(
            &id,
            &from,
            &Split {
                amount_e8s: 200_000_000,
                memo: Some(1234),
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    assert_eq!(governance.neuron_store.len(), 3);
    let child_neuron_split_by_memo = governance
        .get_full_neuron(&child_neuron_split_by_memo_id, &from)
        .expect("The child neuron is missing");
    assert_eq!(
        child_neuron_split_by_memo.account,
        ledger::compute_neuron_split_subaccount_bytes(from, 1234).to_vec(),
    );
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_seed_neuron_split() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds =
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;

    let (_driver, mut gov, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    gov.with_neuron_mut(&id, |neuron| {
        neuron.neuron_type = Some(NeuronType::Seed as i32);
        neuron.clone()
    })
    .expect("Neuron did not exist");

    let transaction_fee = gov
        .heap_data
        .economics
        .as_ref()
        .unwrap()
        .transaction_fee_e8s;

    assert_eq!(
        gov.get_neuron_info(&id, *RANDOM_PRINCIPAL_ID)
            .unwrap()
            .state,
        NeuronState::NotDissolving as i32
    );

    let child_nid = gov
        .split_neuron(
            &id,
            &from,
            &Split {
                amount_e8s: 100_000_000 + transaction_fee,
                memo: None,
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    let child_neuron = gov
        .get_full_neuron(&child_nid, &from)
        .expect("The child neuron is missing");
    let parent_neuron = gov
        .get_full_neuron(&id, &from)
        .expect("The parent neuron is missing");

    assert_eq!(child_neuron.controller, parent_neuron.controller);
    assert_eq!(child_neuron.cached_neuron_stake_e8s, 100_000_000);
    assert_eq!(
        child_neuron.created_timestamp_seconds,
        parent_neuron.created_timestamp_seconds
    );
    assert_eq!(
        child_neuron.aging_since_timestamp_seconds,
        parent_neuron.aging_since_timestamp_seconds
    );
    assert_eq!(child_neuron.dissolve_state, parent_neuron.dissolve_state);
    assert_eq!(child_neuron.kyc_verified, true);
    assert_eq!(child_neuron.neuron_type, Some(NeuronType::Seed as i32));
}

// Spawn neurons has the least priority in the periodic tasks, so we need to run
// them often enough to make sure it happens.
fn run_periodic_tasks_often_enough_to_update_maturity_modulation(gov: &mut Governance) {
    for _i in 0..5 {
        gov.run_periodic_tasks().now_or_never();
    }
}

/// Checks that:
/// * An attempt to spawn a neuron does nothing if the parent has too little
///   maturity.
/// * When the parent neuron has sufficient maturity, a new neuron may be spawn.
/// * The spawned neuron always has neuron_type: None, even if the parent's
///   neuron_type is NeuronType::Seed.
#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_neuron_spawn() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds =
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;

    let (mut driver, mut gov, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );
    run_periodic_tasks_often_enough_to_update_maturity_modulation(&mut gov);

    assert_eq!(
        gov.get_neuron_info(&id, *RANDOM_PRINCIPAL_ID)
            .unwrap()
            .state,
        NeuronState::NotDissolving as i32
    );

    let child_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;

    let neuron_before = gov
        .with_neuron_mut(&id, |neuron| {
            // Starts with too little maturity
            neuron.maturity_e8s_equivalent = 187;
            assert!(
                neuron.maturity_e8s_equivalent
                    < NetworkEconomics::with_default_values().neuron_minimum_stake_e8s
            );
            neuron.neuron_type = Some(NeuronType::Seed as i32);

            neuron.clone()
        })
        .expect("Neuron did not exist");

    // An attempt to spawn a neuron should simply return an error and
    // change nothing.
    let spawn_res = gov.spawn_neuron(
        &id,
        &from,
        &Spawn {
            new_controller: Some(child_controller),
            nonce: None,
            percentage_to_spawn: None,
        },
    );
    assert_matches!(
        spawn_res,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == InsufficientFunds as i32 && msg.to_lowercase().contains("maturity"));

    assert_eq!(
        gov.with_neuron(&id, |neuron| { neuron.clone() }).unwrap(),
        neuron_before
    );

    let parent_maturity_e8s_equivalent: u64 = 123_456_789;
    assert!(
        parent_maturity_e8s_equivalent
            > NetworkEconomics::with_default_values().neuron_minimum_stake_e8s
    );

    // Artificially set the neuron's maturity to sufficient value
    gov.with_neuron_mut(&id, |neuron| {
        neuron.maturity_e8s_equivalent = parent_maturity_e8s_equivalent;
    })
    .expect("Neuron did not exist");

    // Advance the time so that we can check that the spawned neuron has the age
    // and the right creation timestamp
    driver.advance_time_by(1234);

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
        .unwrap();

    // We should now have 2 neurons.
    assert_eq!(gov.neuron_store.len(), 2);
    // .. but only one ledger account since the neuron's maturity hasn't been minted yet.
    driver.assert_num_neuron_accounts_exist(1);

    let parent_neuron = gov
        .with_neuron(&id, |neuron| neuron.clone())
        .expect("The parent neuron is missing");
    assert_eq!(parent_neuron.maturity_e8s_equivalent, 0);

    let child_neuron = gov
        .get_full_neuron(&child_nid, &child_controller)
        .expect("The child neuron is missing");

    assert_eq!(child_neuron.controller, Some(child_controller));
    assert_eq!(child_neuron.cached_neuron_stake_e8s, 0);
    assert_eq!(child_neuron.created_timestamp_seconds, driver.now());
    assert_eq!(child_neuron.aging_since_timestamp_seconds, u64::MAX);
    assert_eq!(
        child_neuron.spawn_at_timestamp_seconds,
        Some(driver.now() + 7 * 86400)
    );
    assert_eq!(
        child_neuron.dissolve_state,
        Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(
            driver.now()
                + gov
                    .heap_data
                    .economics
                    .as_ref()
                    .unwrap()
                    .neuron_spawn_dissolve_delay_seconds
        ))
    );
    assert_eq!(child_neuron.kyc_verified, true);
    assert_eq!(
        child_neuron.maturity_e8s_equivalent,
        parent_maturity_e8s_equivalent
    );
    assert_eq!(child_neuron.neuron_type, None);
    assert_eq!(
        child_neuron.voting_power_refreshed_timestamp_seconds,
        Some(driver.now()),
    );
    assert!(
        child_neuron
            .voting_power_refreshed_timestamp_seconds
            .unwrap()
            > parent_neuron.voting_power_refreshed_timestamp_seconds(),
        "{:?} vs. {:?}",
        child_neuron.voting_power_refreshed_timestamp_seconds,
        parent_neuron.voting_power_refreshed_timestamp_seconds(),
    );

    let creation_timestamp = driver.now();

    // Running periodic tasks shouldn't cause the ICP to be minted.
    gov.maybe_spawn_neurons().now_or_never().unwrap();
    driver.assert_num_neuron_accounts_exist(1);

    // Advance the time by one week, should cause the neuron's ICP
    // to be minted.
    driver.advance_time_by(7 * 86400);
    gov.maybe_spawn_neurons().now_or_never().unwrap();
    driver.assert_num_neuron_accounts_exist(2);

    let child_neuron = gov
        .get_full_neuron(&child_nid, &child_controller)
        .expect("The child neuron is missing");

    assert_eq!(child_neuron.controller, Some(child_controller));
    assert_eq!(
        child_neuron.cached_neuron_stake_e8s,
        (parent_maturity_e8s_equivalent as f64 * 1.01f64) as u64
    );
    assert_eq!(child_neuron.created_timestamp_seconds, creation_timestamp);
    assert_eq!(child_neuron.aging_since_timestamp_seconds, u64::MAX);
    assert_eq!(child_neuron.spawn_at_timestamp_seconds, None);
    assert_eq!(
        child_neuron.dissolve_state,
        Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(
            creation_timestamp
                + gov
                    .heap_data
                    .economics
                    .as_ref()
                    .unwrap()
                    .neuron_spawn_dissolve_delay_seconds
        ))
    );
    assert_eq!(child_neuron.kyc_verified, true);
    assert_eq!(child_neuron.maturity_e8s_equivalent, 0);
    assert_eq!(child_neuron.neuron_type, None);
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_neuron_spawn_with_subaccount() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds =
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;

    let (mut driver, mut gov, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );
    run_periodic_tasks_often_enough_to_update_maturity_modulation(&mut gov);

    assert_eq!(
        gov.get_neuron_info(&id, *RANDOM_PRINCIPAL_ID)
            .unwrap()
            .state,
        NeuronState::NotDissolving as i32
    );

    let neuron_before = gov
        .with_neuron_mut(&id, |neuron| {
            // Starts with too little maturity
            neuron.maturity_e8s_equivalent = 187;
            assert!(
                neuron.maturity_e8s_equivalent
                    < NetworkEconomics::with_default_values().neuron_minimum_stake_e8s
            );
            neuron.clone()
        })
        .expect("Neuron did not exist");

    let child_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;

    // An attempt to spawn a neuron should simply return an error and
    // change nothing.
    let spawn_res = gov.spawn_neuron(
        &id,
        &from,
        &Spawn {
            new_controller: Some(child_controller),
            nonce: None,
            percentage_to_spawn: None,
        },
    );
    assert_matches!(
        spawn_res,
        Err(GovernanceError{error_type: code, error_message: msg})
            if code == InsufficientFunds as i32 && msg.to_lowercase().contains("maturity"));
    assert_eq!(
        gov.with_neuron(&id, |neuron| { neuron.clone() }).unwrap(),
        neuron_before
    );

    // Artificially set the neuron's maturity to sufficient value
    let parent_maturity_e8s_equivalent: u64 = 123_456_789;
    assert!(
        parent_maturity_e8s_equivalent
            > NetworkEconomics::with_default_values().neuron_minimum_stake_e8s
    );
    gov.with_neuron_mut(&id, |neuron| {
        neuron.maturity_e8s_equivalent = parent_maturity_e8s_equivalent;
    })
    .expect("Neuron did not exist");

    // Advance the time so that we can check that the spawned neuron has the age
    // and the right creation timestamp
    driver.advance_time_by(1);

    // Nonce used for spawn (given as input).
    let nonce_spawn = driver.random_u64().expect("Could not get random number");

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
        .unwrap();

    let creation_timestamp = driver.now();

    // We should now have 2 neurons.
    assert_eq!(gov.neuron_store.len(), 2);
    // And we should have one ledger accounts.
    driver.assert_num_neuron_accounts_exist(1);

    // Running periodic tasks shouldn't cause the ICP to be minted.
    gov.maybe_spawn_neurons().now_or_never().unwrap();
    driver.assert_num_neuron_accounts_exist(1);

    let parent_neuron = gov
        .with_neuron(&id, |neuron| neuron.clone())
        .expect("The parent neuron is missing");
    // Maturity on the parent neuron should be reset.
    assert_eq!(parent_neuron.maturity_e8s_equivalent, 0);

    // Advance the time by one week, should cause the neuron's ICP
    // to be minted.
    driver.advance_time_by(7 * 86400);
    gov.maybe_spawn_neurons().now_or_never().unwrap();
    driver.assert_num_neuron_accounts_exist(2);

    let child_neuron = gov
        .get_full_neuron(&child_nid, &child_controller)
        .expect("The child neuron is missing");

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
        child_neuron.account, expected_subaccount,
        "Sub-account doesn't match expected sub-account (with nonce)."
    );
    assert_eq!(child_neuron.controller, Some(child_controller));
    assert_eq!(
        child_neuron.cached_neuron_stake_e8s,
        (parent_maturity_e8s_equivalent as f64 * 1.01f64) as u64
    );
    assert_eq!(child_neuron.created_timestamp_seconds, creation_timestamp);
    assert_eq!(child_neuron.aging_since_timestamp_seconds, u64::MAX);
    assert_eq!(child_neuron.spawn_at_timestamp_seconds, None);
    assert_eq!(
        child_neuron.dissolve_state,
        Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(
            creation_timestamp
                + gov
                    .heap_data
                    .economics
                    .as_ref()
                    .unwrap()
                    .neuron_spawn_dissolve_delay_seconds
        ))
    );
    assert_eq!(child_neuron.kyc_verified, true);
    assert_eq!(child_neuron.maturity_e8s_equivalent, 0);
}

#[test]
fn test_maturity_correctly_reset_if_spawn_fails() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds =
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;

    let (mut driver, mut gov, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );
    run_periodic_tasks_often_enough_to_update_maturity_modulation(&mut gov);

    assert_eq!(
        gov.get_neuron_info(&id, *RANDOM_PRINCIPAL_ID)
            .unwrap()
            .state,
        NeuronState::NotDissolving as i32
    );

    // Artificially set the neuron's maturity to sufficient value
    let parent_maturity_e8s_equivalent: u64 = 123_456_789;
    assert!(
        parent_maturity_e8s_equivalent
            > NetworkEconomics::with_default_values().neuron_minimum_stake_e8s
    );
    gov.with_neuron_mut(&id, |neuron| {
        neuron.maturity_e8s_equivalent = parent_maturity_e8s_equivalent;
    })
    .expect("Neuron did not exist");

    // Advance the time so that we can check that the spawned neuron has the age
    // and the right creation timestamp
    driver.advance_time_by(1);

    // Nonce used for spawn (given as input).
    let nonce_spawn = driver.random_u64().expect("Could not get random number");

    let child_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;

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
        .unwrap();

    let creation_timestamp = driver.now();

    // We should now have 2 neurons.
    assert_eq!(gov.neuron_store.len(), 2);
    // And we should have one ledger accounts.
    driver.assert_num_neuron_accounts_exist(1);

    // Running periodic tasks shouldn't cause the ICP to be minted.
    gov.maybe_spawn_neurons().now_or_never().unwrap();
    driver.assert_num_neuron_accounts_exist(1);

    let parent_neuron = gov
        .with_neuron(&id, |neuron| neuron.clone())
        .expect("The parent neuron is missing");
    // Maturity on the parent neuron should be reset.
    assert_eq!(parent_neuron.maturity_e8s_equivalent, 0);

    // Advance the time by one week, should cause the neuron's ICP
    // to be minted.
    driver.advance_time_by(7 * 86400);
    driver.fail_next_ledger_call();

    gov.maybe_spawn_neurons().now_or_never().unwrap();

    //Driver should fail to finish spawning neurons now (i.e. minting) b/c ledger returns error

    driver.assert_num_neuron_accounts_exist(1);

    let child_neuron = gov
        .get_full_neuron(&child_nid, &child_controller)
        .expect("The child neuron is missing");

    assert_eq!(child_neuron.created_timestamp_seconds, creation_timestamp);
    assert_eq!(child_neuron.aging_since_timestamp_seconds, u64::MAX);
    assert_eq!(child_neuron.spawn_at_timestamp_seconds, Some(1730737555));
    assert_eq!(
        child_neuron.dissolve_state,
        Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(
            creation_timestamp
                + gov
                    .heap_data
                    .economics
                    .as_ref()
                    .unwrap()
                    .neuron_spawn_dissolve_delay_seconds
        ))
    );
    assert_eq!(child_neuron.kyc_verified, true);
    assert_eq!(child_neuron.cached_neuron_stake_e8s, 0);
    // We expect maturity modulation of 100 basis points, which is 1%, because of the
    // result returned from FakeDriver when pretending to be CMC.
    assert_eq!(
        gov.heap_data
            .cached_daily_maturity_modulation_basis_points
            .unwrap(),
        100
    );
    // The value here should be reset to the original value, without being modulated.
    assert_eq!(child_neuron.maturity_e8s_equivalent, 123_456_789);
}

/// Checks that:
/// * Specifying a percentage_to_spawn different from 100 lead to the proper fractional maturity
///   to be spawned.
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
    let dissolve_delay_seconds =
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
    let neuron_stake_e8s = 1_000_000_000;

    let (mut driver, mut gov, id, _) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );
    run_periodic_tasks_often_enough_to_update_maturity_modulation(&mut gov);

    let neuron = gov
        .with_neuron(&id, |neuron| neuron.clone())
        .expect("Neuron did not exist");
    assert_eq!(
        gov.get_neuron_info(&id, *RANDOM_PRINCIPAL_ID)
            .unwrap()
            .state,
        NeuronState::NotDissolving as i32
    );

    let child_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;

    // An attempt to spawn a neuron should simply return an error and
    // change nothing.
    let neuron_before = neuron;
    assert_eq!(
        gov.neuron_store.with_neuron(&id, |n| n.clone()).unwrap(),
        neuron_before
    );

    // Artificially set the neuron's maturity to sufficient value
    let parent_maturity_e8s_equivalent: u64 = parent_maturity;
    assert!(
        parent_maturity_e8s_equivalent
            > NetworkEconomics::with_default_values().neuron_minimum_stake_e8s
    );
    gov.with_neuron_mut(&id, |neuron| {
        neuron.maturity_e8s_equivalent = parent_maturity_e8s_equivalent;
    })
    .expect("Neuron did not exist");

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
        .unwrap();

    let creation_timestamp = driver.now();

    // We should now have 2 neurons.
    assert_eq!(gov.neuron_store.len(), 2);
    // And we should have 1 ledger accounts.
    driver.assert_num_neuron_accounts_exist(1);

    let parent_neuron = gov
        .get_full_neuron(&id, &from)
        .expect("The parent neuron is missing");

    // Running periodic tasks shouldn't cause the ICP to be minted.
    gov.maybe_spawn_neurons().now_or_never().unwrap();
    driver.assert_num_neuron_accounts_exist(1);

    // Some maturity should be remaining on the parent neuron.
    assert_eq!(
        parent_neuron.maturity_e8s_equivalent,
        expected_remaining_maturity
    );

    // Advance the time by one week, should cause the neuron's ICP
    // to be minted.
    driver.advance_time_by(7 * 86400);
    gov.maybe_spawn_neurons().now_or_never().unwrap();
    driver.assert_num_neuron_accounts_exist(2);

    let child_neuron = gov
        .get_full_neuron(&child_nid, &child_controller)
        .expect("The child neuron is missing");

    assert_eq!(child_neuron.controller, Some(child_controller));
    assert_eq!(
        child_neuron.cached_neuron_stake_e8s,
        (expected_spawned_maturity as f64 * 1.01f64) as u64
    );
    assert_eq!(child_neuron.created_timestamp_seconds, creation_timestamp);
    assert_eq!(child_neuron.aging_since_timestamp_seconds, u64::MAX);
    assert_eq!(child_neuron.spawn_at_timestamp_seconds, None);
    assert_eq!(
        child_neuron.dissolve_state,
        Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(
            creation_timestamp
                + gov
                    .heap_data
                    .economics
                    .as_ref()
                    .unwrap()
                    .neuron_spawn_dissolve_delay_seconds
        ))
    );
    assert_eq!(child_neuron.kyc_verified, true);
    assert_eq!(child_neuron.maturity_e8s_equivalent, 0);
}

#[test]
fn test_staked_maturity() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds =
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
    let neuron_stake_e8s = 10 * 100_000_000; // 10 ICP

    let (mut driver, gov, id, _to_subaccount) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    set_governance_for_tests(gov);
    let gov = governance_mut();
    schedule_tasks();

    gov.neuron_store
        .with_neuron_mut(&id, |neuron| {
            assert_eq!(neuron.maturity_e8s_equivalent, 0);
            assert_eq!(neuron.staked_maturity_e8s_equivalent, None);

            // Configure the neuron to auto-stake any future maturity.
            neuron.configure(
                &from,
                driver.now(),
                &Configure {
                    operation: Some(Operation::ChangeAutoStakeMaturity(
                        ChangeAutoStakeMaturity {
                            requested_setting_for_auto_stake_maturity: true,
                        },
                    )),
                },
            )
        })
        .expect("Neuron not found")
        .expect("Configuring neuron failed");

    // Now make a proposal and have it be accepted.
    let _ = match gov
        .manage_neuron(
            &from,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(id)),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    title: Some("Dummy governance proposal".to_string()),
                    summary: "".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::Motion(Motion {
                        motion_text: "".to_string(),
                    })),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .panic_if_error("Couldn't submit proposal.")
        .command
        .unwrap()
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp.proposal_id.unwrap(),
        _ => panic!("Invalid response"),
    };

    // Advance time by 5 days and run periodic tasks so that the neuron is granted (staked) maturity.
    driver.advance_time_by(5 * 24 * 3600);
    run_pending_timers();
    gov.run_periodic_tasks().now_or_never();

    let neuron = gov
        .neuron_store
        .with_neuron(&id, |neuron| neuron.clone())
        .unwrap();
    assert!(neuron.staked_maturity_e8s_equivalent.is_some());
    // Neuron should get the maturity equivalent of 5 days as staked maturity.
    assert_eq!(
        neuron.staked_maturity_e8s_equivalent.unwrap(),
        54719555847781u64
    );
    assert_eq!(neuron.maturity_e8s_equivalent, 0);

    // Try to spawn, should fail, since there's no regular maturity.
    match gov
        .manage_neuron(
            &from,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(id)),
                command: Some(manage_neuron::Command::Spawn(Spawn {
                    new_controller: None,
                    nonce: None,
                    percentage_to_spawn: None,
                })),
            },
        )
        .now_or_never()
        .unwrap()
        .command
        .unwrap()
    {
        manage_neuron_response::Command::Error(e) => {
            e.error_message.contains("There isn't enough maturity")
        }
        _ => panic!("Invalid response"),
    };

    // Now set the neuron to dissolve and advance time
    gov.neuron_store
        .with_neuron_mut(&id, |neuron| {
            assert_eq!(neuron.maturity_e8s_equivalent, 0);
            assert_eq!(
                neuron.staked_maturity_e8s_equivalent,
                Some(54719555847781u64)
            );

            // Configure the neuron to auto-stake any future maturity.
            neuron.configure(
                &from,
                driver.now(),
                &Configure {
                    operation: Some(Operation::StartDissolving(StartDissolving {})),
                },
            )
        })
        .expect("Neuron not found")
        .expect("Configuring neuron failed");

    driver.advance_time_by(
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
    );
    run_pending_timers();
    gov.unstake_maturity_of_dissolved_neurons();

    // All the maturity should now be regular maturity
    let neuron = gov
        .neuron_store
        .with_neuron(&id, |neuron| neuron.clone())
        .expect("Neuron not found");
    assert_eq!(neuron.maturity_e8s_equivalent, 54719555847781u64);
    assert_eq!(neuron.staked_maturity_e8s_equivalent, None);
}

/// It used to be that controllers must be self-authenticating. Later (Jun, 2024) we got rid of that
/// requirement. That is, the controller can be any type of principal (including canister).
/// Discussed here:
/// https://forum.dfinity.org/t/reevaluating-neuron-control-restrictions/28597
#[tokio::test]
async fn test_neuron_with_non_self_authenticating_controller_is_now_allowed() {
    // Step 1: Prepare the world.

    let controller = PrincipalId::new_user_test_id(42);
    assert!(!controller.is_self_authenticating(), "{controller:?}");

    let memo = 43;
    let neuron_subaccount = Subaccount(compute_neuron_staking_subaccount_bytes(controller, memo));

    let amount_e8s = 10 * E8;

    // Step 1.1: Initialize ledger with 10 ICP in the (governance) subaccount where
    // (non-self-authenticating) controller will claim new a neuron.
    let driver = fake::FakeDriver::default()
        .at(56)
        .with_ledger_accounts(vec![fake::FakeAccount {
            id: AccountIdentifier::new(
                ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
                Some(neuron_subaccount),
            ),
            amount_e8s,
        }])
        .with_supply(Tokens::from_tokens(400_000_000).unwrap());

    // Step 1.2: Construct Governance.
    let mut gov = Governance::new(
        empty_fixture(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Call code under test.

    let claim_or_refresh = manage_neuron::Command::ClaimOrRefresh(ClaimOrRefresh {
        by: Some(By::Memo(memo)),
    });
    let manage_neuron = ManageNeuron {
        id: None,
        neuron_id_or_subaccount: None,
        command: Some(claim_or_refresh),
    };
    let caller = controller;
    let result: ManageNeuronResponse = gov.manage_neuron(&caller, &manage_neuron).await;

    // Step 3: Inspect result(s).

    // Step 3.1: Assert that a plausible neuron ID was returned.
    let manage_neuron_response::Command::ClaimOrRefresh(manage_neuron_response) =
        result.command.as_ref().unwrap()
    else {
        panic!("{result:#?}");
    };
    let Some(neuron_id) = manage_neuron_response.refreshed_neuron_id else {
        panic!("{result:#?}");
    };
    assert!(neuron_id.id > 0, "{result:#?}");

    // Step 3.2: Inspect the new neuron's controller.
    let neuron = gov.get_full_neuron(&neuron_id, &caller).unwrap();
    assert_eq!(neuron.controller.unwrap(), controller, "{:#?}", neuron);
}

#[test]
#[cfg_attr(feature = "tla", with_tla_trace_check)]
fn test_disburse_to_neuron() {
    let from = *TEST_NEURON_1_OWNER_PRINCIPAL;
    // Compute the subaccount to which the transfer would have been made
    let nonce = 1234u64;

    let block_height = 543212234;
    let dissolve_delay_seconds =
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS;
    let neuron_stake_e8s = 10 * 100_000_000; // 10 ICP

    let (mut driver, mut gov, id, _to_subaccount) = governance_with_staked_neuron(
        dissolve_delay_seconds,
        neuron_stake_e8s,
        block_height,
        from,
        nonce,
    );

    let transaction_fee = gov
        .heap_data
        .economics
        .as_ref()
        .unwrap()
        .transaction_fee_e8s;

    gov.with_neuron_mut(&id, |parent_neuron| {
        parent_neuron.neuron_type = Some(NeuronType::Seed as i32);
        // Now Set the neuron to start dissolving
        parent_neuron.configure(
            &from,
            driver.now(),
            &Configure {
                operation: Some(Operation::StartDissolving(StartDissolving {})),
            },
        )?;
        Ok::<(), GovernanceError>(())
    })
    .expect("Could not find neuron")
    .expect("Configure did not work");

    // Add a followee. Later, it is asserted that child neurons do not inherit this.
    {
        gov.with_neuron_mut(&id, |parent_neuron| {
            let topic = Topic::Unspecified as i32;
            assert!(
                parent_neuron
                    .followees
                    .insert(topic, Followees { followees: vec![] })
                    .is_none(),
                "{parent_neuron:#?}",
            );
            let followees = parent_neuron.followees.get_mut(&topic).unwrap();
            followees.followees.push(NeuronId { id: 42 });
        })
        .expect("Could not find neuron");
    }

    // Advance the time in the env
    driver.advance_time_by(
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS + 1,
    );

    let parent_neuron_info = gov.get_neuron_info(&id, *RANDOM_PRINCIPAL_ID).unwrap();
    // The neuron state should now be "Dissolved", meaning we can
    // now disburse the neuron.
    assert_eq!(parent_neuron_info.state, NeuronState::Dissolved as i32);

    let child_controller = *TEST_NEURON_2_OWNER_PRINCIPAL;

    let child_nid = gov
        .disburse_to_neuron(
            &id,
            &from,
            &DisburseToNeuron {
                new_controller: Some(child_controller),
                amount_e8s: 2 * 100_000_000 + transaction_fee, // 2 ICP + transaction_fee
                dissolve_delay_seconds: 24 * 60 * 60,          // 1 day.
                kyc_verified: true,
                nonce,
            },
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    // We should now have 2 neurons.
    assert_eq!(gov.neuron_store.len(), 2);
    // And we should have two ledger accounts.
    driver.assert_num_neuron_accounts_exist(2);

    let child_neuron = gov
        .get_full_neuron(&child_nid, &child_controller)
        .expect("The child neuron is missing");
    let parent_neuron = gov
        .get_full_neuron(&id, &from)
        .expect("The parent neuron is missing");

    assert_eq!(
        parent_neuron.cached_neuron_stake_e8s,
        neuron_stake_e8s - 2 * 100_000_000 - transaction_fee
    );

    assert_eq!(child_neuron.controller, Some(child_controller));
    assert_eq!(child_neuron.cached_neuron_stake_e8s, 2 * 100_000_000);
    assert_eq!(child_neuron.created_timestamp_seconds, driver.now());
    assert_eq!(child_neuron.aging_since_timestamp_seconds, driver.now());
    assert_eq!(
        child_neuron.dissolve_state,
        Some(api::neuron::DissolveState::DissolveDelaySeconds(
            24 * 60 * 60
        ))
    );
    assert_eq!(child_neuron.kyc_verified, true);
    // We expect the child's followees not to be inherited from parent.
    // Instead, child is supposed to have the default followees.
    assert_ne!(child_neuron.followees, parent_neuron.followees);
    assert_eq!(
        child_neuron.followees,
        gov.heap_data
            .default_followees
            .iter()
            .map(|(id, followees)| (*id, api::neuron::Followees::from(followees.clone()),))
            .collect(),
    );
    assert_eq!(
        child_neuron.voting_power_refreshed_timestamp_seconds,
        Some(driver.now()),
    );
    assert!(
        child_neuron
            .voting_power_refreshed_timestamp_seconds
            .unwrap()
            > parent_neuron
                .voting_power_refreshed_timestamp_seconds
                .unwrap(),
        "{:?} vs. {:?}",
        child_neuron.voting_power_refreshed_timestamp_seconds,
        parent_neuron.voting_power_refreshed_timestamp_seconds,
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

fn governance_with_neurons(neurons: &[api::Neuron]) -> (fake::FakeDriver, Governance) {
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

    let mut governance_init = empty_fixture();
    governance_init.neurons.extend(
        neurons
            .iter()
            .map(|n| (n.id.as_ref().unwrap().id, n.clone())),
    );

    let gov = Governance::new(
        governance_init,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    assert_eq!(gov.neuron_store.len(), neurons.len());
    (driver, gov)
}

#[tokio::test]
async fn test_not_for_profit_neurons() {
    let p = match std::env::var("NEURON_CSV_PATH") {
        Ok(v) => PathBuf::from(v),
        Err(_) => PathBuf::from("tests/neurons.csv"),
    };

    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let normal_neuron = init_neurons[&42].clone();

    // Add the normal neuron as a followee of the not-for-profit neuron.
    init_neurons.get_mut(&25).unwrap().followees.insert(
        Topic::NeuronManagement as i32,
        Followees {
            followees: vec![normal_neuron.id.unwrap()],
        }
        .into(),
    );

    let (_, mut gov) = governance_with_neurons(
        init_neurons
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .as_slice(),
    );

    let not_for_profit_neuron = init_neurons[&25].clone();

    // A normal neuron can't issue a manage neuron proposal to disburse,
    // split or disburse-to-neuron.
    let result = gov
        .make_proposal(
            normal_neuron.id.as_ref().unwrap(),
            normal_neuron.controller.as_ref().unwrap(),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        normal_neuron.id.unwrap(),
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
        )
        .await;
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().error_type,
        ErrorType::NotAuthorized as i32
    );

    // A not for profit neuron, on the other hand, can.
    // The followee of the managed neuron must make the proposal, in this case.
    let result = gov
        .make_proposal(
            normal_neuron.id.as_ref().unwrap(),
            normal_neuron.controller.as_ref().unwrap(),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                        not_for_profit_neuron.id.unwrap(),
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
        )
        .await;

    result.expect("Failed.");
}

#[test]
fn test_hot_keys_cant_change_followees_of_manage_neuron_topic() {
    let p = match std::env::var("NEURON_CSV_PATH") {
        Ok(v) => PathBuf::from(v),
        Err(_) => PathBuf::from("tests/neurons.csv"),
    };
    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let second_neuron = init_neurons[&42].clone();

    // Add the controller of the second neuron as a hot key of the first one.
    init_neurons
        .get_mut(&25)
        .unwrap()
        .hot_keys
        .push(*second_neuron.controller.as_ref().unwrap());

    let (_, mut gov) = governance_with_neurons(
        init_neurons
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .as_slice(),
    );

    let first_neuron = init_neurons[&25].clone();

    // The controller of the second neuron should now be able
    // change the followees of most topics.
    let result = gov
        .manage_neuron(
            second_neuron.controller.as_ref().unwrap(),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    first_neuron.id.unwrap(),
                )),
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::NetworkEconomics as i32,
                    followees: vec![second_neuron.id.unwrap()],
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
                    first_neuron.id.unwrap(),
                )),
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::NeuronManagement as i32,
                    followees: vec![second_neuron.id.unwrap()],
                })),
            },
        )
        .now_or_never()
        .unwrap();

    assert!(result.is_err());
    assert_eq!(
        result.clone().err().unwrap().error_type,
        api::governance_error::ErrorType::NotAuthorized as i32,
    );
    assert_eq!(
        result.err().unwrap().error_message,
        "Caller is not authorized to manage following of neuron for the ManageNeuron topic."
    );
}

#[test]
fn test_add_and_remove_hot_key() {
    let p = match std::env::var("NEURON_CSV_PATH") {
        Ok(v) => PathBuf::from(v),
        Err(_) => PathBuf::from("tests/neurons.csv"),
    };
    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let (_, mut gov) = governance_with_neurons(
        init_neurons
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .as_slice(),
    );

    let neuron = init_neurons[&25].clone();
    let new_controller = init_neurons[&42].controller.unwrap();

    assert!(
        !gov.neuron_store
            .get_neuron_ids_readable_by_caller(new_controller)
            .contains(neuron.id.as_ref().unwrap())
    );
    // Add a hot key to the neuron and make sure that gets reflected in the
    // principal to neuron ids index.
    let result = gov
        .manage_neuron(
            neuron.controller.as_ref().unwrap(),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron.id.unwrap())),
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
    assert!(
        gov.neuron_store
            .get_neuron_ids_readable_by_caller(new_controller)
            .contains(neuron.id.as_ref().unwrap())
    );

    // Remove a hot key from that neuron and make sure that gets reflected in
    // the principal to neuron ids index.
    let result = gov
        .manage_neuron(
            neuron.controller.as_ref().unwrap(),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron.id.unwrap())),
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
    assert!(
        !gov.neuron_store
            .get_neuron_ids_readable_by_caller(new_controller)
            .contains(neuron.id.as_ref().unwrap())
    );
}

#[test]
fn test_manage_and_reward_node_providers() {
    let p = match std::env::var("NEURON_CSV_PATH") {
        Ok(v) => PathBuf::from(v),
        Err(_) => PathBuf::from("tests/neurons.csv"),
    };
    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let voter_pid = *init_neurons[&42].controller.as_ref().unwrap();

    let voter_neuron = init_neurons[&42].id.unwrap();
    init_neurons.get_mut(&42).unwrap().dissolve_state =
        Some(api::neuron::DissolveState::DissolveDelaySeconds(
            VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
        ));
    let np_pid = PrincipalId::new_self_authenticating(&[14]);

    let (driver, mut gov) = governance_with_neurons(
        init_neurons
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .as_slice(),
    );

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
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
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
        .panic_if_error("Couldn't submit proposal.")
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
    assert_eq!(
        info.status,
        ProposalStatus::Failed as i32,
        "info: {:?}",
        info
    );
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
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
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
        .panic_if_error("Couldn't submit proposal to add NP.")
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
    assert!(
        gov.manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
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
        .err()
        .unwrap()
        .error_message
        .contains("cannot add already existing Node Provider")
    );

    // Rewarding the node provider to the default account should now work.
    let pid = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
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
        .panic_if_error("Couldn't submit proposal.")
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
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
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
        .panic_if_error("Couldn't submit proposal.")
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
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
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
        .panic_if_error("Couldn't submit proposal.")
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
    let neuron = gov
        .neuron_store
        .with_active_neurons_iter(|mut iter| iter.find(|x| x.controller() == np_pid).unwrap());
    assert_eq!(neuron.stake_e8s(), 99_999_999);
    // Find the transaction in the ledger...
    driver.assert_account_contains(
        &AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(neuron.subaccount())),
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
        .panic_if_error("Couldn't submit proposal.")
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
    let p = match std::env::var("NEURON_CSV_PATH") {
        Ok(v) => PathBuf::from(v),
        Err(_) => PathBuf::from("tests/neurons.csv"),
    };
    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let voter_pid = *init_neurons[&42].controller.as_ref().unwrap();

    let voter_neuron = init_neurons[&42].id.unwrap();
    init_neurons.get_mut(&42).unwrap().dissolve_state =
        Some(api::neuron::DissolveState::DissolveDelaySeconds(
            VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
        ));
    let np_pid_0 = PrincipalId::new_self_authenticating(&[14]);
    let np_pid_1 = PrincipalId::new_self_authenticating(&[15]);
    let np_pid_2 = PrincipalId::new_self_authenticating(&[16]);

    let (driver, mut gov) = governance_with_neurons(
        init_neurons
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .as_slice(),
    );

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
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
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
        .panic_if_error("Couldn't submit proposal.")
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
    assert_eq!(
        info.status,
        ProposalStatus::Failed as i32,
        "info: {:?}",
        info
    );
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
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
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
            .panic_if_error("Couldn't submit proposal.")
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
        assert!(
            gov.manage_neuron(
                &voter_pid,
                &ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
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
            .err()
            .unwrap()
            .error_message
            .contains("cannot add already existing Node Provider")
        );
    }

    let to_subaccount = Subaccount({
        let mut sha = Sha256::new();
        sha.write(b"my_account");
        sha.finish()
    });

    let manage_neuron_cmd = ManageNeuron {
        id: None,
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron)),
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
        .panic_if_error("Couldn't submit proposal.")
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
    let neuron = gov
        .neuron_store
        .with_active_neurons_iter(|mut iter| iter.find(|x| x.controller() == np_pid_2).unwrap());
    assert_eq!(neuron.stake_e8s(), 99_999_999);
    // Find the transaction in the ledger...
    driver.assert_account_contains(
        &AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(neuron.subaccount())),
        99_999_999,
    );

    // Remove the first and third NPs
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
        .panic_if_error("Couldn't submit proposal.")
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
        .panic_if_error("Couldn't submit proposal.")
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
        .panic_if_error("Couldn't submit proposal.")
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
    let p = match std::env::var("NEURON_CSV_PATH") {
        Ok(v) => PathBuf::from(v),
        Err(_) => PathBuf::from("tests/neurons.csv"),
    };
    let mut builder = GovernanceCanisterInitPayloadBuilder::new();
    let init_neurons = &mut builder.add_all_neurons_from_csv_file(&p).proto.neurons;

    let voter_pid = *init_neurons[&42].controller.as_ref().unwrap();
    let voter_neuron = init_neurons[&42].id.unwrap();
    init_neurons.get_mut(&42).unwrap().dissolve_state =
        Some(api::neuron::DissolveState::DissolveDelaySeconds(
            VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
        ));
    let (_, mut gov) = governance_with_neurons(
        init_neurons
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .as_slice(),
    );

    gov.heap_data.economics.as_mut().unwrap().reject_cost_e8s = 1234;
    gov.heap_data
        .economics
        .as_mut()
        .unwrap()
        .neuron_minimum_stake_e8s = 1234;

    // Verify that neuron_minimum_dissolve_delay_to_vote_seconds is set to 6 months by default.
    assert_eq!(
        gov.heap_data
            .economics
            .as_ref()
            .unwrap()
            .voting_power_economics
            .unwrap()
            .neuron_minimum_dissolve_delay_to_vote_seconds,
        Some(VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS),
    );

    // A value that differs from the default, useful for testing that the proposal has
    // the intended effect.
    let nondefault_neuron_minimum_dissolve_delay_to_vote_seconds =
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS / 2;

    // Smoke test
    assert_ne!(
        nondefault_neuron_minimum_dissolve_delay_to_vote_seconds,
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
    );

    // Propose to change some, NetworkEconomics parameters.
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
                        voting_power_economics: Some(VotingPowerEconomics {
                            start_reducing_voting_power_after_seconds: Some(42),
                            clear_following_after_seconds: Some(4242),
                            neuron_minimum_dissolve_delay_to_vote_seconds: Some(
                                nondefault_neuron_minimum_dissolve_delay_to_vote_seconds,
                            ),
                        }),
                        ..Default::default()
                    })),
                }))),
            },
        )
        .now_or_never()
        .unwrap()
        .panic_if_error("Couldn't submit proposal.")
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

    // Verify that only the two fields specified by the proposal are changed.
    assert_eq!(
        gov.heap_data.economics.as_ref().unwrap(),
        &NetworkEconomics {
            reject_cost_e8s: 56789,
            voting_power_economics: Some(VotingPowerEconomics {
                start_reducing_voting_power_after_seconds: Some(42),
                clear_following_after_seconds: Some(4242),
                neuron_minimum_dissolve_delay_to_vote_seconds: Some(
                    nondefault_neuron_minimum_dissolve_delay_to_vote_seconds
                ),
            }),

            // No changes to the rest.
            neuron_minimum_stake_e8s: 1234,
            ..NetworkEconomics::with_default_values()
        },
    );
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
        ballots: hashmap! {
            1 => ballot(Vote::Yes),
            2 => ballot(Vote::Yes),
            3 => ballot(Vote::Yes),
            4 => ballot(Vote::No),
            5 => ballot(Vote::Unspecified),
        },
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
fn fixture_for_proposals(proposal_id: ProposalId, payload: Vec<u8>) -> api::Governance {
    let execute_nns_function = api::ExecuteNnsFunction {
        nns_function: NnsFunction::ClearProvisionalWhitelist as i32,
        payload,
    };
    let proposal = api::Proposal {
        title: Some("A Reasonable Title".to_string()),
        action: Some(api::proposal::Action::ExecuteNnsFunction(
            execute_nns_function,
        )),
        ..Default::default()
    };
    let proposal_data = api::ProposalData {
        id: Some(proposal_id),
        proposal: Some(proposal),
        topic: Some(Topic::NetworkEconomics as i32),
        ..Default::default()
    };
    api::Governance {
        economics: Some(api::NetworkEconomics::with_default_values()),
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
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    let caller = &principal(1);

    // ACT
    let result = gov.get_proposal_info(caller, proposal_id).unwrap();

    // ASSERT
    assert_eq!(Topic::NetworkEconomics as i32, result.topic);
    let action = result.proposal.unwrap().action.unwrap();
    assert_matches!(
        action,
        ApiAction::ExecuteNnsFunction(eu) if eu.payload == [1, 2, 3]
    );
}

#[tokio::test]
async fn test_make_proposal_message() {
    let principal1 = principal(1);

    let mut driver = fake::FakeDriver::default();

    let proposal = Proposal {
        action: Some(Action::CreateServiceNervousSystem(
            CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone(),
        )),
        // Fill in the rest of the fields with those of a motion proposal.
        // (They are not relevant to this test.)
        ..new_motion_proposal()
    };

    let governance_init = api::Governance {
        wait_for_quiet_threshold_seconds: 100,
        economics: Some(api::NetworkEconomics::with_default_values()),
        neurons: btreemap! {
            1 => api::Neuron {
                id: Some(NeuronId { id: 1 }),
                controller: Some(principal1),
                hot_keys: vec![],
                cached_neuron_stake_e8s: 10 * E8,
                account: driver.random_byte_array().expect("Could not get random byte array").to_vec(),
                dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS)),
                ..Default::default()
            },
        },
        ..Default::default()
    };

    let mut gov = Governance::new(
        governance_init,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // submit proposal
    let make_proposal_response = match gov
        .manage_neuron(
            &principal1,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 1 })),
                command: Some(Command::MakeProposal(Box::new(proposal))),
            },
        )
        .await
        .command
        .expect("Couldn't submit proposal.")
    {
        manage_neuron_response::Command::MakeProposal(resp) => resp,
        r => panic!("Invalid response {r:?}"),
    };

    assert_eq!(
        make_proposal_response.message,
        Some("The proposal has been created successfully.".to_string())
    )
}

#[tokio::test]
async fn test_max_number_of_proposals_with_ballots() {
    let mut fake_driver = fake::FakeDriver::default();
    let proto = api::Governance {
        wait_for_quiet_threshold_seconds: 5,
        ..fixture_two_neurons_second_is_bigger()
    };
    let gov = Governance::new(
        proto,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );
    set_governance_for_tests(gov);
    let gov = governance_mut();
    schedule_tasks();

    // Vote with neuron 1. It is smaller, so proposals are not auto-accepted.
    for i in 0..MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS {
        gov.make_proposal(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &principal(1),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: format!("proposal {i} summary"),
                action: Some(proposal::Action::Motion(Motion {
                    motion_text: "dummy text".to_string(),
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    assert_eq!(
        gov.get_pending_proposals(&PrincipalId::new_anonymous())
            .len(),
        MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS,
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
    ).await, Err(GovernanceError{error_type, error_message: _}) if error_type==ResourceExhausted as i32);
    // Let's try an Installcode for Governance itself. This proposal type is whitelisted, so it can
    // be submitted even though the max is reached.
    assert_matches!(
        gov.make_proposal(
            &NeuronId { id: 1 },
            // Must match neuron 1's serialized_id.
            &principal(1),
            &Proposal {
                title: Some("A Reasonable Title".to_string()),
                summary: "InstallCode for Governance should go through despite the limit"
                    .to_string(),
                action: Some(proposal::Action::InstallCode(InstallCode {
                    canister_id: Some(GOVERNANCE_CANISTER_ID.get()),
                    wasm_module: Some(vec![1, 2, 3]),
                    install_mode: Some(CanisterInstallMode::Upgrade as i32),
                    arg: Some(vec![4, 5, 6]),
                    skip_stopping_before_installing: None,
                    wasm_module_hash: Some(vec![7, 8, 9]),
                    arg_hash: Some(vec![10, 11, 12]),
                })),
                ..Default::default()
            },
        )
        .await,
        Ok(_)
    );

    fake_driver.advance_time_by(10);
    gov.run_periodic_tasks().now_or_never().unwrap();
    run_pending_timers();

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
    ).await, Err(GovernanceError{error_type, error_message: _}) if error_type==ResourceExhausted as i32);

    // Let's make a reward event happen
    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS);
    gov.run_periodic_tasks().now_or_never().unwrap();
    run_pending_timers();

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
    .await
    .unwrap();
}

#[test]
fn test_proposal_gc() {
    let proposals = (1..1000)
        .map(|id| {
            (
                id,
                ProposalData {
                    id: Some(ProposalId { id }),
                    decided_timestamp_seconds: 60,
                    reward_event_round: 1,
                    proposal: Some(Proposal {
                        title: Some("A Reasonable Title".to_string()),
                        action: Some(if id % 2 == 0 {
                            Action::ManageNeuron(Box::new(ManageNeuron {
                                ..Default::default()
                            }))
                        } else {
                            Action::ExecuteNnsFunction(ExecuteNnsFunction {
                                nns_function: NnsFunction::NnsCanisterInstall as i32,
                                ..Default::default()
                            })
                        }),
                        ..Default::default()
                    }),
                    topic: Some(if id % 2 == 0 {
                        Topic::NeuronManagement as i32
                    } else {
                        Topic::ProtocolCanisterManagement as i32
                    }),
                    ..Default::default()
                },
            )
        })
        .collect::<BTreeMap<u64, _>>();
    let governance_init = api::Governance {
        economics: Some(api::NetworkEconomics::with_default_values()),
        ..Default::default()
    };
    // Set timestamp to 30 days
    let mut driver = fake::FakeDriver::default().at(60 * 60 * 24 * 30);
    let mut gov = Governance::new(
        governance_init,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    gov.heap_data.proposals = proposals.clone();
    assert_eq!(999, gov.heap_data.proposals.len());
    // First check GC does not take place if
    // latest_gc_{timestamp_seconds|num_proposals} are both close to
    // their current values.
    gov.latest_gc_timestamp_seconds = driver.now() - 60;
    gov.latest_gc_num_proposals = gov.heap_data.proposals.len() - 10;
    assert!(!gov.maybe_gc());
    // Now, assume that 500 proposals has been added since the last run...
    gov.latest_gc_num_proposals = gov.heap_data.proposals.len() - 500;
    assert!(gov.maybe_gc());
    // We keep max 100 proposals per topic and only two topics are
    // present in the list of proposals.
    assert!(gov.heap_data.proposals.len() <= 200);
    // Check that the proposals with high IDs have been kept and the
    // proposals with low IDs have been purged.
    for i in 1..800 {
        assert!(!gov.heap_data.proposals.contains_key(&i));
    }
    for i in 800..1000 {
        assert!(gov.heap_data.proposals.contains_key(&i));
    }
    // Check that garbage collected proposals are tracked with their topics
    assert_eq!(
        gov.heap_data.topic_of_garbage_collected_proposals,
        (1..800)
            .map(|i| {
                let topic = if i % 2 == 0 {
                    Topic::NeuronManagement
                } else {
                    Topic::ProtocolCanisterManagement
                };
                (i, topic)
            })
            .collect()
    );

    // Running again, nothing should change...
    assert!(!gov.maybe_gc());
    // Reset all proposals.
    gov.heap_data.proposals = proposals;
    gov.latest_gc_timestamp_seconds = driver.now() - 60;
    gov.latest_gc_num_proposals = gov.heap_data.proposals.len() - 10;
    assert!(!gov.maybe_gc());
    // Advance time by two days...
    driver.advance_time_by(60 * 60 * 24 * 2);
    // This ought to induce GC.
    assert!(gov.maybe_gc());
    assert!(gov.heap_data.proposals.len() <= 200);
    // Advance time by a little.
    driver.advance_time_by(60);
    // No GC should be induced.
    assert!(!gov.maybe_gc());
}

#[test]
fn test_gc_ignores_exempt_proposals() {
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
                    sns_token_swap_lifecycle: Some(Lifecycle::Committed as i32),
                    proposal: Some(Proposal {
                        title: Some("A Reasonable Title".to_string()),
                        action: Some(Action::CreateServiceNervousSystem(
                            CreateServiceNervousSystem::default(),
                        )),
                        ..Default::default()
                    }),
                    topic: Some(Topic::SnsAndCommunityFund as i32),
                    ..Default::default()
                },
            )
        })
        .collect::<BTreeMap<u64, ProposalData>>();
    let governance_init = api::Governance {
        economics: Some(api::NetworkEconomics::with_default_values()),
        ..Default::default()
    };
    // Set timestamp to 30 days
    let driver = fake::FakeDriver::default().at(60 * 60 * 24 * 30);
    let mut gov = Governance::new(
        governance_init,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    gov.heap_data.proposals = props;
    assert_eq!(999, gov.heap_data.proposals.len());
    gov.latest_gc_timestamp_seconds = driver.now() - 60;
    // Garbage collection should run, but not remove any of the exempt proposals
    assert!(gov.maybe_gc());
    assert_eq!(999, gov.heap_data.proposals.len());
}

#[tokio::test]
async fn test_id_v1_works() {
    let driver = fake::FakeDriver::default();

    let mut gov = Governance::new(
        fixture_for_manage_neuron(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
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
    .await
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
    fn test_can_follow_by(make_neuron_id: fn(&api::Neuron) -> NeuronIdOrSubaccount) {
        reset_stable_memory();
        let driver = fake::FakeDriver::default();
        let mut gov = Governance::new(
            fixture_for_manage_neuron(),
            driver.get_fake_env(),
            driver.get_fake_ledger(),
            driver.get_fake_cmc(),
            driver.get_fake_randomness_generator(),
        );

        let nid = NeuronId { id: 2 };
        let folowee = NeuronId { id: 1 };

        // Check that the neuron isn't following anyone beforehand
        let neuron = gov
            .get_full_neuron(&nid, &principal(2))
            .expect("Failed to get neuron");
        let f = neuron.followees.get(&(Topic::Unspecified as i32));
        assert_eq!(f, None);
        let neuron_id_or_subaccount = make_neuron_id(&neuron);

        // Start following
        gov.manage_neuron(
            // Must match neuron 5's serialized_id.
            &principal(2),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(neuron_id_or_subaccount.clone()),
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::Unspecified as i32,
                    followees: [folowee].to_vec(),
                })),
            },
        )
        .now_or_never()
        .unwrap()
        .panic_if_error("Manage neuron failed");

        // Check that you're actually following
        let neuron = gov.neuron_store.with_neuron(&nid, |n| n.clone()).unwrap();

        let f = neuron
            .followees
            .get(&(Topic::Unspecified as i32))
            .unwrap()
            .followees
            .clone();
        assert_eq!(
            f,
            vec![folowee],
            "failed to start following neuron {:?} by {:?}",
            folowee,
            neuron_id_or_subaccount
        );
    }

    test_can_follow_by(|n| NeuronIdOrSubaccount::NeuronId(n.id.unwrap()));
    test_can_follow_by(|n| NeuronIdOrSubaccount::Subaccount(n.account.to_vec()));
}
#[test]
fn test_merge_maturity_returns_expected_error() {
    let mut nns = NNSBuilder::new()
        .add_neuron(NeuronBuilder::new(100, 1, principal(1)).set_dissolve_delay(
            VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
        ))
        .create();

    let id = NeuronId { id: 100 };

    // This is inlined because the method is removed, so we don't need a general purpose test method
    let result1 = nns
        .governance
        .manage_neuron(
            &principal(1),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(id)),
                command: Some(Command::MergeMaturity(MergeMaturity {
                    percentage_to_merge: 10,
                })),
            },
        )
        .now_or_never()
        .unwrap()
        .command
        .unwrap();
    let result = match result1 {
        manage_neuron_response::Command::Error(e) => Err(GovernanceError::from(e)),
        manage_neuron_response::Command::MergeMaturity(response) => Ok(response),
        _ => panic!("Merge maturity command returned unexpected response"),
    };
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert_eq!(error.error_type, ErrorType::InvalidCommand as i32);
    assert_eq!(
        error.error_message,
        "The command MergeMaturity is no longer available, as this functionality was \
        superseded by StakeMaturity. Use StakeMaturity instead.",
    );
}

#[test]
fn test_manage_neuron_merge_maturity_returns_expected_error() {
    let fake_driver = fake::FakeDriver::default();
    let id: u64 = 1;
    // This fixture works well for us since we just need a single neuron to make this call with.
    let fixture = fixture_for_dissolving_neuron_tests(
        id,
        api::neuron::DissolveState::DissolveDelaySeconds(
            VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
        ),
        DEFAULT_TEST_START_TIMESTAMP_SECONDS,
    );
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );

    let response = gov
        .manage_neuron(
            &principal(id),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id })),
                command: Some(Command::MergeMaturity(MergeMaturity {
                    percentage_to_merge: 10,
                })),
            },
        )
        .now_or_never()
        .unwrap();

    assert_eq!(
        response,
        ManageNeuronResponse {
            command: Some(CommandResponse::Error(
                api::GovernanceError::new_with_message(
                    api::governance_error::ErrorType::InvalidCommand,
                    "The command MergeMaturity is no longer available, as this functionality was \
                superseded by StakeMaturity. Use StakeMaturity instead."
                )
            )),
        }
    );
}

/// Creates a fixture with one neuron, aging since the test start timestamp, in
/// a given dissolve_state.
fn fixture_for_dissolving_neuron_tests(
    id: u64,
    dissolve_state: api::neuron::DissolveState,
    aging_since_timestamp_seconds: u64,
) -> api::Governance {
    api::Governance {
        economics: Some(api::NetworkEconomics::default()),
        neurons: btreemap! {
            1 => api::Neuron {
                id: Some(NeuronId { id }),
                account: account(id),
                controller: Some(principal(id)),
                dissolve_state: Some(dissolve_state),
                aging_since_timestamp_seconds,
                ..Default::default()
            }
        },
        ..Default::default()
    }
}

/// Tests that a neuron in a non-dissolving state changes to a dissolving state
/// when a "start_dissolving" command is issued. Also tests that the neuron ages
/// appropriately in both states.
#[test]
fn test_start_dissolving() {
    let mut fake_driver = fake::FakeDriver::default();
    let id: u64 = 1;
    let fixture = fixture_for_dissolving_neuron_tests(
        id,
        api::neuron::DissolveState::DissolveDelaySeconds(
            VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
        ),
        DEFAULT_TEST_START_TIMESTAMP_SECONDS,
    );
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );

    // Advance time so that the neuron has age.
    fake_driver.advance_time_by(1);

    let neuron_info = gov
        .get_neuron_info(&NeuronId { id }, *RANDOM_PRINCIPAL_ID)
        .unwrap();
    assert_eq!(
        neuron_info.dissolve_delay_seconds,
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS
    );
    assert_eq!(neuron_info.state, NeuronState::NotDissolving as i32);
    assert_eq!(neuron_info.age_seconds, 1);

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
    .panic_if_error("Manage neuron failed");

    let neuron_info = gov
        .get_neuron_info(&NeuronId { id }, *RANDOM_PRINCIPAL_ID)
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolving as i32);
    assert_eq!(neuron_info.age_seconds, 0);
}

/// Tests that a neuron in a dissolving state will panic if a "start_dissolving"
/// command is issued.
#[test]
#[should_panic(expected = "Manage neuron failed: RequiresNotDissolving: ")]
fn test_start_dissolving_panics() {
    let fake_driver = fake::FakeDriver::default();
    let id: u64 = 1;
    let fixture = fixture_for_dissolving_neuron_tests(
        id,
        api::neuron::DissolveState::WhenDissolvedTimestampSeconds(
            DEFAULT_TEST_START_TIMESTAMP_SECONDS,
        ),
        u64::MAX,
    );
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );

    let neuron_info = gov
        .get_neuron_info(&NeuronId { id }, *RANDOM_PRINCIPAL_ID)
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolved as i32);

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
    .panic_if_error("Manage neuron failed");
}

/// Tests that a neuron in a dissolving state will stop dissolving if a
/// "stop_dissolving" command is issued, and that the neuron will age when not
/// dissolving.
#[test]
fn test_stop_dissolving() {
    let mut fake_driver = fake::FakeDriver::default();
    let id: u64 = 1;
    let fixture = fixture_for_dissolving_neuron_tests(
        id,
        api::neuron::DissolveState::WhenDissolvedTimestampSeconds(
            DEFAULT_TEST_START_TIMESTAMP_SECONDS
                + VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
        ),
        u64::MAX,
    );
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );

    let neuron_info = gov
        .get_neuron_info(&NeuronId { id }, *RANDOM_PRINCIPAL_ID)
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolving as i32);
    assert_eq!(
        neuron_info.dissolve_delay_seconds,
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS
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
    .panic_if_error("Manage neuron failed");

    // Advance time so that the neuron has age.
    fake_driver.advance_time_by(1);

    let neuron_info = gov
        .get_neuron_info(&NeuronId { id }, *RANDOM_PRINCIPAL_ID)
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::NotDissolving as i32);
    assert_eq!(
        neuron_info.dissolve_delay_seconds,
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS
    );
    assert_eq!(neuron_info.age_seconds, 1);
}

/// Tests that a neuron in a non-dissolving state will panic if a
/// "stop_dissolving" command is issued.
#[test]
#[should_panic(expected = "Manage neuron failed: RequiresDissolving: ")]
fn test_stop_dissolving_panics() {
    let fake_driver = fake::FakeDriver::default();
    let id: u64 = 1;
    let fixture = fixture_for_dissolving_neuron_tests(
        id,
        api::neuron::DissolveState::DissolveDelaySeconds(
            VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
        ),
        DEFAULT_TEST_START_TIMESTAMP_SECONDS,
    );
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );

    let neuron_info = gov
        .get_neuron_info(&NeuronId { id }, *RANDOM_PRINCIPAL_ID)
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::NotDissolving as i32);
    assert_eq!(
        neuron_info.dissolve_delay_seconds,
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS
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
    .panic_if_error("Manage neuron failed");
}

#[test]
fn test_update_node_provider() {
    let (_, mut gov, neuron) = create_mature_neuron(false);
    let id = neuron.id.unwrap();
    let neuron = gov
        .neuron_store
        .with_neuron(&id, |n| n.clone())
        .unwrap()
        .clone();
    let controller = neuron.controller();
    let account = AccountIdentifier::new(
        ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
        Some(neuron.subaccount()),
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
        reward_account: Some(AccountIdentifierProto {
            hash: account.to_vec(),
        }),
    };

    gov.heap_data.node_providers.push(np);

    let hex = "b6a3539e69c6b75fe3c87b1ff82b1fc7f189a6113b77ba653b2e5eed67c95632";
    let new_reward_account = AccountIdentifier::from_hex(hex).unwrap();
    let new_reward_account = AccountIdentifierProto {
        hash: new_reward_account.to_vec(),
    };
    let update_np = UpdateNodeProvider {
        reward_account: Some(new_reward_account.clone()),
    };

    // Updating an existing Node Provider with a valid reward account should succeed
    assert!(
        gov.update_node_provider(&controller, update_np.clone())
            .is_ok()
    );
    assert_eq!(
        gov.heap_data
            .node_providers
            .first()
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

    // Attempting to update a non-existent Node Provider with a valid reward account
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
    .panic_if_error("Manage neuron failed");
}

/// Tests the command to increase dissolve delay of a given neuron. Tests five
/// scenarios:
/// * A non dissolving neuron and an increment lower than the maximum one.
/// * A non dissolving neuron and an increment higher than the maximum one.
/// * A dissolving neuron and an increment lower than the maximum one.
/// * A dissolving neuron and an increment higher than the maximum one.
/// * A dissolved neuron.
#[test]
fn test_increase_dissolve_delay() {
    let principal_id = 1;
    let fake_driver = fake::FakeDriver::default();
    let fixture = api::Governance {
        economics: Some(api::NetworkEconomics::default()),
        neurons: btreemap! {
            1 => api::Neuron {
                id: Some(NeuronId { id: 1 }),
                account: account(1),
                controller: Some(principal(principal_id)),
                dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
                    VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
                )),
                ..Default::default()
            },
            2 => api::Neuron {
                id: Some(NeuronId { id: 2 }),
                account: account(2),
                controller: Some(principal(principal_id)),
                dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(
                    DEFAULT_TEST_START_TIMESTAMP_SECONDS
                        + VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS,
                )),
                aging_since_timestamp_seconds: u64::MAX,
                ..Default::default()
            },
            3 => api::Neuron {
                id: Some(NeuronId { id: 3 }),
                account: account(3),
                controller: Some(principal(principal_id)),
                dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(
                    DEFAULT_TEST_START_TIMESTAMP_SECONDS - 1,
                )),
                aging_since_timestamp_seconds: u64::MAX,
                ..Default::default()
            }
        },
        ..Default::default()
    };
    let mut gov = Governance::new(
        fixture,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );
    // Tests for neuron 1. Non-dissolving.
    increase_dissolve_delay(&mut gov, principal_id, 1, 1);

    let neuron_info = gov
        .get_neuron_info(&NeuronId { id: 1 }, *RANDOM_PRINCIPAL_ID)
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::NotDissolving as i32);
    assert_eq!(
        neuron_info.dissolve_delay_seconds,
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS + 1
    );

    increase_dissolve_delay(
        &mut gov,
        principal_id,
        1,
        u32::try_from(MAX_DISSOLVE_DELAY_SECONDS + 1)
            .expect("MAX_DISSOLVE_DELAY_SECONDS larger than u32"),
    );
    let neuron_info = gov
        .get_neuron_info(&NeuronId { id: 1 }, *RANDOM_PRINCIPAL_ID)
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::NotDissolving as i32);
    assert_eq!(
        neuron_info.dissolve_delay_seconds,
        MAX_DISSOLVE_DELAY_SECONDS
    );

    // Tests for neuron 2. Dissolving.
    increase_dissolve_delay(&mut gov, principal_id, 2, 1);
    let neuron_info = gov
        .get_neuron_info(&NeuronId { id: 2 }, *RANDOM_PRINCIPAL_ID)
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolving as i32);
    assert_eq!(
        neuron_info.dissolve_delay_seconds,
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS + 1
    );

    increase_dissolve_delay(
        &mut gov,
        principal_id,
        2,
        u32::try_from(MAX_DISSOLVE_DELAY_SECONDS + 1)
            .expect("MAX_DISSOLVE_DELAY_SECONDS larger than u32"),
    );
    let neuron_info = gov
        .get_neuron_info(&NeuronId { id: 2 }, *RANDOM_PRINCIPAL_ID)
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::Dissolving as i32);
    assert_eq!(
        neuron_info.dissolve_delay_seconds,
        MAX_DISSOLVE_DELAY_SECONDS
    );

    // Tests for neuron 3. Dissolved.
    increase_dissolve_delay(
        &mut gov,
        principal_id,
        3,
        u32::try_from(VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS)
            .expect("VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS larger than u32"),
    );
    let neuron_info = gov
        .get_neuron_info(&NeuronId { id: 3 }, *RANDOM_PRINCIPAL_ID)
        .unwrap();
    assert_eq!(neuron_info.state, NeuronState::NotDissolving as i32);
    assert_eq!(
        neuron_info.dissolve_delay_seconds,
        VotingPowerEconomics::DEFAULT_NEURON_MINIMUM_DISSOLVE_DELAY_TO_VOTE_SECONDS
    );
}

// Test scenario. There are three neurons 1, 2, and 3 with stakes 10,
// 20, and 100 ICP. The first neuron is controlled by principal A and
// the second and third by principal B.
//
// At first none of the neurons have joined the Neurons' Fund. The
// global metric of total ICP in the Neurons' Fund should be zero and
// the total ICP in neurons should be 130.
//
// Principal A tries to join the Neurons' Fund for neuron 3. This
// should fail as A is not the controller.
//
// Principal B now tries to join the Neurons' Fund for neuron 3. This
// should succeed and the global metric should now show that 100 ICP
// are in the Neurons' Fund.
//
// Principal A tries to join the Neurons' Fund for neuron 1. This
// should succeed and the global metric should now show 110 ICP in the
// Neurons' Fund.
//
// The time advances.
//
// Principal B tries to join the Neurons' Fund for neuron 3
// (again). This should fail as this neuron is already in the
// Neurons' Fund.
//
// At the end of all this, 110 ICP should be reported as being in the
// Neurons' Fund and 130 ICP reported as the total ICP in neurons.
#[test]
fn test_join_neurons_fund() {
    let now = 778899;
    let principal_a = 42;
    let principal_b = 128;
    let fixture = api::Governance {
        economics: Some(api::NetworkEconomics::default()),
        neurons: btreemap! {
            1 => api::Neuron {
                id: Some(NeuronId { id: 1 }),
                account: account(1),
                cached_neuron_stake_e8s: 10 * E8,
                controller: Some(principal(principal_a)),
                dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
                aging_since_timestamp_seconds: u64::MAX,
                ..Default::default()
            },
            2 => api::Neuron {
                id: Some(NeuronId { id: 2 }),
                account: account(2),
                cached_neuron_stake_e8s: 20 * 100_000_000,
                controller: Some(principal(principal_b)),
                dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
                aging_since_timestamp_seconds: u64::MAX,
                ..Default::default()
            },
            3 => api::Neuron {
                id: Some(NeuronId { id: 3 }),
                account: account(3),
                cached_neuron_stake_e8s: 100 * 100_000_000,
                controller: Some(principal(principal_b)),
                dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
                aging_since_timestamp_seconds: u64::MAX,
                ..Default::default()
            }
        },
        ..Default::default()
    };
    let total_icp_suppply = Tokens::new(200, 0).unwrap();
    let mut driver = fake::FakeDriver::default()
        .at(60 * 60 * 24 * 30)
        .with_supply(total_icp_suppply);
    let mut gov = Governance::new(
        fixture,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );
    {
        let actual_metrics = gov.compute_cached_metrics(now, total_icp_suppply);
        assert_eq!(200, actual_metrics.total_supply_icp);
        assert_eq!(130 * 100_000_000, actual_metrics.total_staked_e8s);
        assert_eq!(0, actual_metrics.community_fund_total_staked_e8s);
    }
    // Try to join Neurons' Fund with the wrong controller (A instead of B).
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
        assert_eq!(
            result.err().unwrap().error_type,
            api::governance_error::ErrorType::NotAuthorized as i32,
        );
    }
    // Join the Neurons' Fund for neuron 3.
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
        let actual_metrics = gov.compute_cached_metrics(now, total_icp_suppply);
        assert_eq!(200, actual_metrics.total_supply_icp);
        assert_eq!(130 * 100_000_000, actual_metrics.total_staked_e8s);
        assert_eq!(
            100 * 100_000_000,
            actual_metrics.community_fund_total_staked_e8s
        );
        // 30 days in now
        assert_eq!(
            Some(60 * 60 * 24 * 30),
            gov.neuron_store
                .with_neuron(&NeuronId::from_u64(3), |n| n
                    .joined_community_fund_timestamp_seconds)
                .expect("Neuron not found")
        );
        // Check that neuron info displays the same information.
        let neuron_info = gov
            .get_neuron_info(&NeuronId { id: 3 }, principal(principal_b))
            .unwrap();
        assert_eq!(
            Some(60 * 60 * 24 * 30),
            neuron_info.joined_community_fund_timestamp_seconds
        );
    }
    // Advance time by two days...
    driver.advance_time_by(60 * 60 * 24 * 2);
    // Join the Neurons' Fund for neuron 1.
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
        let actual_metrics = gov.compute_cached_metrics(now, total_icp_suppply);
        assert_eq!(200, actual_metrics.total_supply_icp);
        assert_eq!(130 * 100_000_000, actual_metrics.total_staked_e8s);
        assert_eq!(
            110 * 100_000_000,
            actual_metrics.community_fund_total_staked_e8s
        );
        // 32 days in now
        assert_eq!(
            60 * 60 * 24 * 32,
            gov.neuron_store
                .with_neuron(&NeuronId::from_u64(1), |n| n
                    .joined_community_fund_timestamp_seconds
                    .unwrap_or(0))
                .expect("Neuron not found")
        );
    }
    // Principal B tries to join the Neurons' Fund for neuron 3
    // (again). This should fail as this neuron is already in the
    // Neurons' Fund.
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
            result.err().unwrap().error_type,
            api::governance_error::ErrorType::AlreadyJoinedCommunityFund as i32,
        );
    }
    // Principal B leaves the Neurons' Fund for Neuron 3
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
                            operation: Some(Operation::LeaveCommunityFund(LeaveCommunityFund {})),
                        },
                    )),
                },
            )
            .now_or_never()
            .unwrap();
        assert!(result.is_ok());
    }
    // Principal B tries to leave the Neurons' Fund again for neuron 3, should fail
    // since it already left.
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
                            operation: Some(Operation::LeaveCommunityFund(LeaveCommunityFund {})),
                        },
                    )),
                },
            )
            .now_or_never()
            .unwrap();
        assert_eq!(
            result.err().unwrap().error_type,
            api::governance_error::ErrorType::NotInTheCommunityFund as i32,
        );
    }
    // Run periodic tasks to populate metrics. Need to call it twice
    // as the first call will just distribute rewards.
    gov.run_periodic_tasks().now_or_never();
    gov.run_periodic_tasks().now_or_never();
    let actual_metrics = gov.heap_data.metrics.unwrap();
    assert_eq!(200, actual_metrics.total_supply_icp);
    assert_eq!(130 * 100_000_000, actual_metrics.total_staked_e8s);
    assert_eq!(
        10 * 100_000_000,
        actual_metrics.community_fund_total_staked_e8s
    );
    // Neuron 2 is not in the fund.
    assert_eq!(
        0,
        gov.neuron_store
            .with_neuron(&NeuronId::from_u64(2), |n| n
                .joined_community_fund_timestamp_seconds
                .unwrap_or(0))
            .expect("Neuron not found")
    );
}

/// Calls governance.manage_neuron, but this has a more streamlined interface.
///
/// In particular, instead of saying
///
///     neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id)),
///
/// you simply do
///
///     neuron_id,
///
/// Also, instead of saying,
///
///     command: Some(Command::DoSomething(DoSomething { ... })),
///
/// you simply say,
///
///     DoSomething { ... }
///
/// (This makes use of Command::from(do_something), which is defined in
/// ic_nns_governance::pb::v1::convert_struct_to_enum::...)
///
/// (This unburies the lede in multiple ways.)
fn manage_neuron<MyCommand>(
    caller: PrincipalId,
    neuron_id: NeuronId,
    command: MyCommand,
    governance: &mut Governance,
) -> CommandResponse
where
    Command: From<MyCommand>,
{
    governance
        .manage_neuron(
            &caller,
            &ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id)),
                command: Some(Command::from(command)),
                id: None,
            },
        )
        .now_or_never()
        .unwrap()
        .command
        .unwrap()
}

/// A specialized version of manage_neuron specifically for configuring a neuron.
///
/// Here, instead of having to say
///
///     Configure { operation: Some(Operation::SetFoo(SetFoo { ... })) }
///
/// you simply say,
///
///     SetFoo { ... }
///
/// (This makes use of Operation::from(set_foo), which is defined in
/// ic_nns_governance::pb::v1::convert_struct_to_enum::...)
///
/// (Because the other bits carry zero information.)
fn configure_neuron<MyOperation>(
    caller: PrincipalId,
    neuron_id: NeuronId,
    operation: MyOperation,
    governance: &mut Governance,
) -> Result<ConfigureResponse, GovernanceError>
where
    Operation: From<MyOperation>, // That is, Operation::from(operation) is valid.
{
    let result = manage_neuron(
        caller,
        neuron_id,
        Configure {
            operation: Some(Operation::from(operation)),
        },
        governance,
    );

    match result {
        CommandResponse::Configure(ok) => Ok(ok),
        CommandResponse::Error(err) => Err(GovernanceError::from(err)),
        _ => panic!("{result:#?}"),
    }
}

/// Visibility is explained in this (passed) motion proposal:
/// https://dashboard.internetcomputer.org/proposal/130832
#[test]
fn test_neuron_set_visibility() {
    // Step 1: Prepare the world.

    let controller = PrincipalId::new_user_test_id(1);

    let typical_neuron = api::Neuron {
        // The last line in this block already has this effect, making this line
        // technically superfluous. However, since this is the operative field
        // to this test, we want to be explicit.
        visibility: None,

        id: Some(NeuronId { id: 1 }),
        account: account(1),
        cached_neuron_stake_e8s: 10 * E8,
        controller: Some(controller),
        dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
            ONE_YEAR_SECONDS,
        )),
        aging_since_timestamp_seconds: 1_721_727_936,
        ..Default::default()
    };

    // The salient difference between this and typical_neuron is that this is a
    // known neuron. In particular, this has the same controller.
    let known_neuron = api::Neuron {
        known_neuron_data: Some(api::KnownNeuronData::default()),

        id: Some(NeuronId { id: 2 }),
        account: account(2),
        cached_neuron_stake_e8s: 10 * E8,
        controller: Some(controller),
        dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
            ONE_YEAR_SECONDS,
        )),
        aging_since_timestamp_seconds: 1_721_727_936,
        ..Default::default()
    };

    let governance_init = api::Governance {
        economics: Some(api::NetworkEconomics::default()),
        neurons: btreemap! {
            1 => typical_neuron.clone(),
            2 => known_neuron.clone(),
        },
        ..Default::default()
    };

    let total_icp_suppply = Tokens::new(200, 0).unwrap();
    let driver = fake::FakeDriver::default()
        .at(60 * 60 * 24 * 30)
        .with_supply(total_icp_suppply);
    let mut governance = Governance::new(
        governance_init,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Call the code under test.

    let typical_configure_response = configure_neuron(
        controller,
        typical_neuron.id.unwrap(),
        SetVisibility {
            visibility: Some(Visibility::Public as i32),
        },
        &mut governance,
    );

    let known_neuron_configure_response = configure_neuron(
        controller,
        known_neuron.id.unwrap(),
        SetVisibility {
            visibility: Some(Visibility::Private as i32),
        },
        &mut governance,
    );

    // Step 3: Verify results.

    // Step 3.1: Inspect responses.

    assert_eq!(typical_configure_response, Ok(ConfigureResponse {}));

    {
        let err = known_neuron_configure_response.unwrap_err();
        let GovernanceError {
            error_type,
            error_message,
        } = &err;

        assert_eq!(
            ErrorType::try_from(*error_type),
            Ok(ErrorType::PreconditionFailed),
            "{:?}",
            err,
        );

        let message = error_message.to_lowercase();
        for key_word in ["known", "visibility", "not allowed"] {
            assert!(message.contains(key_word), "{err:?}",);
        }
    }

    // Step 3.2: Inspect neurons themselves (in particular, their visibility).

    let assert_neuron_visibility = |neuron_id: NeuronId, expected_visibility: Visibility| {
        let neuron = governance
            .with_neuron(&neuron_id, |neuron| neuron.clone())
            .unwrap();

        assert_eq!(
            neuron.visibility() as i32,
            expected_visibility as i32,
            "{:#?}",
            neuron,
        );
    };

    assert_neuron_visibility(typical_neuron.id.unwrap(), Visibility::Public);

    assert_neuron_visibility(known_neuron.id.unwrap(), Visibility::Public);
}

#[test]
fn test_deciding_and_potential_voting_power() {
    // Step 1: Prepare the world.

    let neuron = api::Neuron {
        id: Some(NeuronId { id: 42 }),
        controller: Some(PrincipalId::new_user_test_id(42)),
        account: account(42),

        // Factors that affect POTENTIAL voting power.
        cached_neuron_stake_e8s: 10 * E8, // Base
        // Bonuses factors.
        dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
            8 * ONE_YEAR_SECONDS,
        )),
        // (Remember, birth day does not change with time, but age does...)
        aging_since_timestamp_seconds: START_TIMESTAMP_SECONDS,

        // Additional factor that affects DECIDING voting power.
        voting_power_refreshed_timestamp_seconds: Some(START_TIMESTAMP_SECONDS),

        ..Default::default()
    };

    let controller = neuron.controller.unwrap();

    let governance_init = api::Governance {
        economics: Some(api::NetworkEconomics::with_default_values()),
        neurons: btreemap! {
            42 => neuron,
        },
        ..Default::default()
    };

    let mut driver = fake::FakeDriver::default()
        .at(START_TIMESTAMP_SECONDS)
        .with_supply(Tokens::new(200, 0).unwrap());

    let governance = Governance::new(
        governance_init,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    let original_potential_voting_power = governance
        .with_neuron(&NeuronId { id: 42 }, |neuron| {
            neuron.potential_voting_power(START_TIMESTAMP_SECONDS)
        })
        .unwrap();
    // There is a 2x dissolve delay bonus (and no age bonus).
    assert_eq!(original_potential_voting_power, 20 * E8);

    // Step 2: Call the code under test.
    let mut previous_timestamp_seconds = START_TIMESTAMP_SECONDS
        // This is a little hack so that the inequality assertion near the end
        // of get_voting_power_ratio works on the first call.
        - 1;
    let mut previous_potential_voting_power = original_potential_voting_power
        // Ditto above hack.
        - 1;
    let mut get_voting_power_ratio = |seconds_since_start| -> f64 {
        // Advance time.
        let new_timestamp_seconds = START_TIMESTAMP_SECONDS + seconds_since_start;
        assert!(
            new_timestamp_seconds > previous_timestamp_seconds,
            "{new_timestamp_seconds} vs. {previous_timestamp_seconds}",
        );
        driver.advance_time_by(new_timestamp_seconds - previous_timestamp_seconds);
        previous_timestamp_seconds = new_timestamp_seconds;

        // Read back the neuron (both in full, and abstract forms).

        let full_neuron = governance
            .get_full_neuron(&NeuronId { id: 42 }, &controller)
            .unwrap();

        let neuron_info = governance
            .get_neuron_info(&NeuronId { id: 42 }, controller)
            .unwrap();

        // Compare the two. They should at least be consistent.
        assert_eq!(
            full_neuron.potential_voting_power,
            neuron_info.potential_voting_power
        );
        assert_eq!(
            full_neuron.deciding_voting_power,
            neuron_info.deciding_voting_power
        );

        let deciding_voting_power = full_neuron.deciding_voting_power.unwrap();
        let potential_voting_power = full_neuron.potential_voting_power.unwrap();

        // Because of age bonus, voting power increases.
        assert!(
            potential_voting_power > previous_potential_voting_power,
            "{potential_voting_power} vs. {previous_potential_voting_power}",
        );
        previous_potential_voting_power = potential_voting_power;

        println!("{deciding_voting_power} vs. {potential_voting_power}");
        deciding_voting_power as f64 / potential_voting_power as f64
    };

    // Step 3: Inspect results.

    // Step 3.1: For 6 months, there is no reduction in voting power
    // (i.e. deciding voting power == potential voting power).
    for seconds_after_start in [
        0,
        1,
        2,
        3,
        ONE_MONTH_SECONDS,
        2 * ONE_MONTH_SECONDS,
        3 * ONE_MONTH_SECONDS,
        6 * ONE_MONTH_SECONDS - 1,
    ] {
        assert_eq!(
            get_voting_power_ratio(seconds_after_start),
            1.0,
            "at {} seconds ({} months) after start.",
            seconds_after_start,
            seconds_after_start / ONE_MONTH_SECONDS,
        );
    }

    // Step 3.2 (the interesting phase): Then, for the next month, voting power goes down linearly.
    for (seconds_after_decline_starts, expected_ratio) in [
        (0, 1.0),
        (ONE_MONTH_SECONDS / 5, 0.8),
        (ONE_MONTH_SECONDS / 2, 0.5),
        (ONE_MONTH_SECONDS / 4 * 3, 0.25),
        (ONE_MONTH_SECONDS / 100 * 99, 0.01),
    ] {
        let observed_ratio =
            get_voting_power_ratio(6 * ONE_MONTH_SECONDS + seconds_after_decline_starts);

        fn abs_relative_error(observed: f64, expected: f64) -> f64 {
            ((observed - expected) / expected).abs()
        }

        assert!(
            abs_relative_error(observed_ratio, expected_ratio) < 5e-5,
            "{} vs. {} @ {} months after start of decline.",
            observed_ratio,
            expected_ratio,
            seconds_after_decline_starts as f64 / ONE_MONTH_SECONDS as f64,
        );
    }

    // Step 3.3: Once voting power decline finishes, deciding voting power stays at 0.
    for seconds_after_decline_ends in [
        0,
        1,
        2,
        3,
        ONE_MONTH_SECONDS,
        2 * ONE_MONTH_SECONDS,
        3 * ONE_MONTH_SECONDS,
        6 * ONE_MONTH_SECONDS - 1,
        6 * ONE_MONTH_SECONDS,
    ] {
        assert_eq!(
            get_voting_power_ratio(7 * ONE_MONTH_SECONDS + seconds_after_decline_ends),
            0.0,
            "{} seconds after deciding voting power decline ends.",
            seconds_after_decline_ends,
        );
    }
}

#[test]
fn test_include_public_neurons_in_full_neurons() {
    // Step 1: Prepare the world.

    let controller = PrincipalId::new_user_test_id(1);
    let caller = PrincipalId::new_user_test_id(2);
    assert_ne!(caller, controller);

    let new_neuron = |id, visibility, known_neuron_data| {
        let account = account(id);
        let id = Some(NeuronId { id });

        let visibility = match visibility {
            Visibility::Unspecified => None,
            ok => Some(ok as i32),
        };

        api::Neuron {
            visibility,
            known_neuron_data,

            id,
            account,

            cached_neuron_stake_e8s: 10 * E8,
            controller: Some(controller),
            dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
                8 * ONE_YEAR_SECONDS,
            )),
            aging_since_timestamp_seconds: START_TIMESTAMP_SECONDS,
            voting_power_refreshed_timestamp_seconds: Some(START_TIMESTAMP_SECONDS),
            deciding_voting_power: Some(20 * E8),
            potential_voting_power: Some(20 * E8),
            maturity_disbursements_in_progress: Some(vec![]),

            ..Default::default()
        }
    };

    let legacy_neuron = new_neuron(1, Visibility::Unspecified, None); // We say this is legacy, because its visibility is None.
    let known_neuron = new_neuron(
        2,
        Visibility::Unspecified,
        Some(api::KnownNeuronData {
            name: "".to_string(),
            description: None,
            links: Some(vec![]),
            committed_topics: Some(vec![]),
        }),
    );
    let explicitly_private_neuron = new_neuron(3, Visibility::Private, None);
    let explicitly_public_neuron = new_neuron(4, Visibility::Public, None);
    let caller_controlled_neuron = api::Neuron {
        id: Some(NeuronId { id: 5 }),
        account: account(5),
        controller: Some(caller),
        ..legacy_neuron.clone()
    };

    let governance_init = api::Governance {
        economics: Some(api::NetworkEconomics::default()),
        neurons: btreemap! {
            1 => legacy_neuron.clone(),
            2 => known_neuron.clone(),
            3 => explicitly_private_neuron.clone(),
            4 => explicitly_public_neuron.clone(),
            5 => caller_controlled_neuron.clone(),
        },
        ..Default::default()
    };

    let total_icp_suppply = Tokens::new(200, 0).unwrap();
    let driver = fake::FakeDriver::default()
        .at(START_TIMESTAMP_SECONDS)
        .with_supply(total_icp_suppply);
    let governance = Governance::new(
        governance_init,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Call the code under test.

    let list_neurons_response = governance.list_neurons(
        &ListNeurons {
            // Try to read all neurons that are not controlled by caller. Only the public ones
            // should appear in full_neurons.
            neuron_ids: vec![1, 2, 3, 4],

            // This is the operative input for this test.
            include_public_neurons_in_full_neurons: Some(true),

            // This is to make sure that existing behavior still works.
            include_neurons_readable_by_caller: true,

            // This should have no effect.
            include_empty_neurons_readable_by_caller: Some(true),

            page_number: None,
            page_size: None,
            neuron_subaccounts: None,
        },
        caller,
    );

    // Step 3: Inspect results.

    let mut expected_full_neurons = vec![
        known_neuron,
        explicitly_public_neuron,
        // In particular, legacy and explicitly_private are NOT in the result.

        // This behavior already existed. This just makes sure that we did not break it.
        caller_controlled_neuron,
    ];

    for neuron in &mut expected_full_neurons {
        if neuron.known_neuron_data.is_some() {
            neuron.visibility = Some(Visibility::Public as i32);
            // Known neuron data does not appear in list_neurons response.
            neuron.known_neuron_data = None;
        }
        let visibility = &mut neuron.visibility;
        if visibility.is_none() {
            *visibility = Some(Visibility::Private as i32);
        }
    }

    assert_eq!(list_neurons_response.full_neurons, expected_full_neurons);
}

#[tokio::test]
async fn test_refresh_voting_power() {
    // Step 1: Prepare the world. This mostly consists of constructing a
    // Governance with one neuron. The code under test will operate on that
    // neuron.

    let controller = PrincipalId::new_user_test_id(42);
    let hot_key = PrincipalId::new_user_test_id(43);

    let neuron = api::Neuron {
        id: Some(NeuronId { id: 42 }),
        account: account(42),
        hot_keys: vec![hot_key],
        cached_neuron_stake_e8s: 10 * E8,
        controller: Some(controller),
        dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
            ONE_YEAR_SECONDS,
        )),
        aging_since_timestamp_seconds: 1_721_727_936,
        voting_power_refreshed_timestamp_seconds: Some(START_TIMESTAMP_SECONDS),

        ..Default::default()
    };

    let governance_init = api::Governance {
        economics: Some(api::NetworkEconomics::default()),
        neurons: btreemap! {
            42 => neuron,
        },
        ..Default::default()
    };

    let total_icp_suppply = Tokens::new(200, 0).unwrap();
    let mut driver = fake::FakeDriver::default()
        .at(START_TIMESTAMP_SECONDS)
        .with_supply(total_icp_suppply);

    let mut governance = Governance::new(
        governance_init,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    let delta_seconds = 99;
    driver.advance_time_by(delta_seconds);

    // Step 2: Call code under test, which modifies the one neuron.
    async fn refresh_voting_power(
        governance: &mut Governance,
        caller: PrincipalId,
    ) -> manage_neuron_response::Command {
        let refresh_voting_power = ManageNeuron {
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 42 })),
            command: Some(manage_neuron::Command::RefreshVotingPower(
                RefreshVotingPower {},
            )),
            id: None,
        };

        governance
            .manage_neuron(&caller, &refresh_voting_power)
            .await
            .command
            .unwrap()
    }

    // Step 3: Inspect the neuron.
    let get_voting_power_refreshed_timestamp_seconds = |governance: &mut Governance| {
        governance
            .with_neuron(&NeuronId { id: 42 }, |neuron| {
                neuron.voting_power_refreshed_timestamp_seconds()
            })
            .unwrap()
    };

    // Sad case: Rando principal tries to refresh voting power.
    let rando_principal = PrincipalId::new_user_test_id(0xDEAD_BEEF);
    let err = refresh_voting_power(&mut governance, rando_principal).await;
    assert_eq!(
        get_voting_power_refreshed_timestamp_seconds(&mut governance),
        START_TIMESTAMP_SECONDS,
    );
    match err {
        manage_neuron_response::Command::Error(error) => {
            let api::GovernanceError {
                error_type,
                error_message,
            } = &error;

            assert_eq!(
                ErrorType::try_from(*error_type),
                Ok(ErrorType::NotAuthorized),
                "{:?}",
                error
            );

            let error_message = error_message.to_lowercase();
            for key_word in ["auth", "refresh", "voting power", "42"] {
                assert!(error_message.contains(key_word), "{error:?}");
            }
        }

        wrong => panic!("{wrong:?}"),
    }

    // Main happy case: Controller tries to refresh voting power.
    match refresh_voting_power(&mut governance, controller).await {
        manage_neuron_response::Command::RefreshVotingPower(_ok) => {}
        wrong => panic!("{wrong:?}"),
    }
    assert_eq!(
        get_voting_power_refreshed_timestamp_seconds(&mut governance),
        START_TIMESTAMP_SECONDS + 99,
    );

    // Secondary happy case: Hot key tries to refresh voting power.
    let delta_seconds = 51;
    driver.advance_time_by(delta_seconds);
    match refresh_voting_power(&mut governance, hot_key).await {
        manage_neuron_response::Command::RefreshVotingPower(_ok) => {}
        wrong => panic!("{wrong:?}"),
    }
    assert_eq!(
        get_voting_power_refreshed_timestamp_seconds(&mut governance),
        START_TIMESTAMP_SECONDS + 99 + 51,
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

    let neurons = neuron_votes
        .iter()
        .enumerate()
        .map(|(i, neuron_vote)| api::Neuron {
            id: Some(NeuronId { id: i as u64 }),
            account: account(i as u64),
            dissolve_state: NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE,
            controller: Some(principal(i as u64)),
            cached_neuron_stake_e8s: neuron_vote.stake,
            ..api::Neuron::default()
        })
        .collect();

    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_neurons(neurons)
        .with_wait_for_quiet_threshold(initial_expiration_seconds)
        .build();

    let mut gov = Governance::new(
        governance_proto,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
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
        .now_or_never()
        .unwrap()
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
            let result = fake::register_vote(
                &mut gov,
                principal(i as u64),
                NeuronId { id: i as u64 },
                pid,
                vote_and_time.0,
            );
            let successful_response = ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::RegisterVote(
                    manage_neuron_response::RegisterVoteResponse {},
                )),
            };
            let deadline_passed_response = ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::Error(
                    api::GovernanceError::new_with_message(
                        api::governance_error::ErrorType::PreconditionFailed,
                        "Proposal deadline has passed.",
                    ),
                )),
            };
            if result == successful_response || result == deadline_passed_response {
                // Vote was successful or the deadline has passed
            } else {
                panic!("Unexpected response: {result:?}");
            }
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

/// Simulates a situation in which most of the voting is done at the beginning of
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
        let vote = if i % 2 == 0 { Vote::Yes } else { Vote::No };
        neuron_votes.push(NeuronVote {
            vote_and_time: Some((vote, 80 * i)),
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
#[tokio::test]
async fn test_known_neurons() {
    let mut driver = fake::FakeDriver::default();

    let neurons = vec![
        api::Neuron {
            id: Some(NeuronId { id: 1 }),
            account: driver
                .random_byte_array()
                .expect("Could not get random byte array")
                .to_vec(),
            controller: Some(principal(1)),
            cached_neuron_stake_e8s: 100_000_000,
            dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
                MAX_DISSOLVE_DELAY_SECONDS,
            )),
            ..Default::default()
        },
        api::Neuron {
            id: Some(NeuronId { id: 2 }),
            account: driver
                .random_byte_array()
                .expect("Could not get random byte array")
                .to_vec(),
            controller: Some(principal(2)),
            cached_neuron_stake_e8s: 100_000_000,
            dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
                MAX_DISSOLVE_DELAY_SECONDS,
            )),
            ..Default::default()
        },
        api::Neuron {
            id: Some(NeuronId { id: 3 }),
            account: driver
                .random_byte_array()
                .expect("Could not get random byte array")
                .to_vec(),
            controller: Some(principal(3)),
            cached_neuron_stake_e8s: 100_000_000_000,
            dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
                MAX_DISSOLVE_DELAY_SECONDS,
            )),
            ..Default::default()
        },
    ];

    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(api::NetworkEconomics::with_default_values())
        .with_neurons(neurons)
        .build();

    let mut gov = Governance::new(
        governance_proto,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
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
                    links: vec![],
                    committed_topics: vec![],
                }),
            })),
            ..Default::default()
        },
    )
    .await
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
                    links: vec![],
                    committed_topics: vec![],
                }),
            })),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        gov.get_neuron_info(&NeuronId { id: 1 }, *RANDOM_PRINCIPAL_ID)
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
                links: vec![],
                committed_topics: vec![],
            }),
        },
        KnownNeuron {
            id: Some(NeuronId { id: 2 }),
            known_neuron_data: Some(KnownNeuronData {
                name: "Two".to_string(),
                description: None,
                links: vec![],
                committed_topics: vec![],
            }),
        },
    ];
    let mut sorted_response_known_neurons = gov.list_known_neurons().known_neurons;
    sorted_response_known_neurons
        .sort_by(|a, b| a.id.as_ref().unwrap().id.cmp(&b.id.as_ref().unwrap().id));
    assert_eq!(sorted_response_known_neurons, expected_known_neurons);

    // This proposal tries to name neuron 1 with the already existing name "Two", this should fail.
    gov.make_proposal(
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
                    links: vec![],
                    committed_topics: vec![],
                }),
            })),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();

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
                    links: vec![],
                    committed_topics: vec![],
                }),
            })),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        gov.get_neuron_info(&NeuronId { id: 2 }, *RANDOM_PRINCIPAL_ID)
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

    let known_neuron_name_set = gov
        .neuron_store
        .list_known_neuron_ids()
        .into_iter()
        .flat_map(|neuron_id| {
            gov.neuron_store
                .with_neuron(&neuron_id, |neuron| {
                    neuron.known_neuron_data().map(|data| data.name.clone())
                })
                .unwrap()
        })
        .collect::<HashSet<_>>();

    // Test that we have them all
    assert_eq!(expected_known_neuron_name_set, known_neuron_name_set);
    // Test that they're in the index
    assert_eq!(
        gov.neuron_store.known_neuron_id_by_name("One"),
        Some(NeuronId { id: 1 })
    );
    assert_eq!(
        gov.neuron_store.known_neuron_id_by_name("Zwei"),
        Some(NeuronId { id: 2 })
    );
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct ExpectedCallCanisterMethodCallArguments<'a> {
    target: CanisterId,
    method_name: &'a str,
    request: Vec<u8>,
}

#[allow(clippy::type_complexity)]
struct MockEnvironment<'a> {
    expected_call_canister_method_calls: Arc<
        Mutex<
            VecDeque<(
                ExpectedCallCanisterMethodCallArguments<'a>,
                Result<Vec<u8>, (Option<i32>, String)>,
            )>,
        >,
    >,

    // If Some, tokio::time::sleep will be used to ensure that
    // call_canister_method actually does .await internally.
    call_canister_method_min_duration: Option<std::time::Duration>,
}

#[track_caller]
fn assert_calls_eq(
    observed: &ExpectedCallCanisterMethodCallArguments,
    expected: &ExpectedCallCanisterMethodCallArguments,
) {
    assert_eq!(
        (observed.target, observed.method_name),
        (expected.target, expected.method_name),
        "unexpected call to {}.{}",
        observed.target,
        observed.method_name
    );
    match observed.method_name {
        "deploy_new_sns" => {
            assert_eq!(
                Decode!(&observed.request, DeployNewSnsRequest).unwrap(),
                Decode!(&expected.request, DeployNewSnsRequest).unwrap(),
                "unexpected call request to {}.{}",
                observed.target,
                observed.method_name,
            );
        }
        _ => {
            assert_eq!(
                observed.request, expected.request,
                "unexpected call request to {}.{}",
                observed.target, observed.method_name,
            );
        }
    }
}

#[async_trait]
impl Environment for MockEnvironment<'_> {
    async fn call_canister_method(
        &self,
        target: CanisterId,
        method_name: &str,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        let (observed_call, result) = self
            .expected_call_canister_method_calls
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| {
                panic!(
                    "A canister call was observed, but no more calls were expected.\n\
                     target: {}\n\
                     method_name: {}\n\
                     request.len(): {}",
                    target,
                    method_name,
                    request.len(),
                );
            });

        let expected_call = ExpectedCallCanisterMethodCallArguments {
            target,
            method_name,
            request: request.clone(),
        };
        assert_calls_eq(&observed_call, &expected_call);

        // If requested, use the .await operator.
        if let Some(call_canister_method_min_duration) = self.call_canister_method_min_duration {
            tokio::time::sleep(call_canister_method_min_duration).await;
        }

        result
    }

    // Other methods don't do anything interesting. We implement them mostly
    // to fulfill the trait requirements.

    fn now(&self) -> u64 {
        DEFAULT_TEST_START_TIMESTAMP_SECONDS
    }

    fn execute_nns_function(
        &self,
        _proposal_id: u64,
        _update: &ExecuteNnsFunction,
    ) -> Result<(), GovernanceError> {
        panic!("Unexpected call to Environment::execute_nns_function");
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        HeapGrowthPotential::NoIssue
    }
}

type CanisterCallResult = Result<Vec<u8>, (Option<i32>, String)>;

lazy_static! {
    static ref INIT: sns_swap_pb::Init = sns_swap_pb::Init {
        nns_governance_canister_id: GOVERNANCE_CANISTER_ID.to_string(),
        sns_governance_canister_id: SNS_GOVERNANCE_CANISTER_ID.to_string(),
        sns_ledger_canister_id: SNS_LEDGER_CANISTER_ID.to_string(),
        icp_ledger_canister_id: ICP_LEDGER_CANISTER_ID.to_string(),
        sns_root_canister_id: SNS_ROOT_CANISTER_ID.to_string(),

        fallback_controller_principal_ids: vec![DEVELOPER_PRINCIPAL_ID.to_string()],

        // These values are similar to, but different from the standard
        // values. This allows our tests to detect accidental usage of the
        // standard values by code under test.
        transaction_fee_e8s: Some(12_345),
        neuron_minimum_stake_e8s: Some(123_456_789),
        confirmation_text: None,
        restricted_countries: None,
        min_participants: None, // TODO[NNS1-2339]
        min_icp_e8s: None, // TODO[NNS1-2339]
        max_icp_e8s: None, // TODO[NNS1-2339]
        min_direct_participation_icp_e8s: None, // TODO[NNS1-2339]
        max_direct_participation_icp_e8s: None, // TODO[NNS1-2339]
        min_participant_icp_e8s: None, // TODO[NNS1-2339]
        max_participant_icp_e8s: None, // TODO[NNS1-2339]
        swap_start_timestamp_seconds: None, // TODO[NNS1-2339]
        swap_due_timestamp_seconds: None, // TODO[NNS1-2339]
        sns_token_e8s: None, // TODO[NNS1-2339]
        neuron_basket_construction_parameters: None, // TODO[NNS1-2339]
        nns_proposal_id: None, // TODO[NNS1-2339]
        should_auto_finalize: Some(true),
        neurons_fund_participation_constraints: None,
        neurons_fund_participation: None,
    };
}

lazy_static! {

    // Collectively, the Neurons' Fund neurons have 100e-8 ICP in maturity.
    // Neurons 1 and 2 belong to principal(1); neuron 3 belongs to principal(2).
    // Neuron 4 also belongs to principal(1), but is NOT a Neurons' Fund neuron.
    static ref SWAP_ID_TO_NEURON: Vec<api::Neuron> = {
        let neuron_base = api::Neuron {
            cached_neuron_stake_e8s: 100_000 * E8,
            dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
                MAX_DISSOLVE_DELAY_SECONDS,
            )),
            ..Default::default()
        };

        vec![
            api::Neuron {
                id: Some(NeuronId { id: 1 }),
                account: account(1),
                controller: Some(principal(1)),
                maturity_e8s_equivalent: 1_200_000 * E8,
                joined_community_fund_timestamp_seconds: Some(1),
                ..neuron_base.clone()
            },
            api::Neuron {
                id: Some(NeuronId { id: 2 }),
                account: account(2),
                controller: Some(principal(1)),
                maturity_e8s_equivalent: 200_000 * E8,
                joined_community_fund_timestamp_seconds: Some(1),
                ..neuron_base.clone()
            },
            api::Neuron {
                id: Some(NeuronId { id: 3 }),
                account: account(3),
                controller: Some(principal(2)),
                maturity_e8s_equivalent: 600_000 * E8,
                joined_community_fund_timestamp_seconds: Some(1),
                ..neuron_base.clone()
            },

            // Unlike the foregoing neurons, this one is NOT a CF neuron.
            api::Neuron {
                id: Some(NeuronId { id: 4 }),
                account: account(4),
                controller: Some(principal(1)),
                maturity_e8s_equivalent: 1_000_000 * E8,
                ..neuron_base
            },
        ]
    };

    static ref CF_PARTICIPANTS: Vec<sns_swap_pb::CfParticipant> = {
        #[allow(deprecated)] // TODO[#NNS-2338]: Remove this once hotkey_principal is removed.
        let mut result = vec![
            sns_swap_pb::CfParticipant {
                controller: Some(principal(1)),
                hotkey_principal: String::new(),
                cf_neurons: vec![
                    sns_swap_pb::CfNeuron::try_new(
                        1,
                        NEURONS_FUND_INVESTMENT_E8S * 60 / 100,
                        vec![],
                    ).unwrap(),
                    sns_swap_pb::CfNeuron::try_new(
                        2,
                        NEURONS_FUND_INVESTMENT_E8S * 10 / 100,
                        vec![],
                    ).unwrap(),
                ],
            },
            sns_swap_pb::CfParticipant {
                controller: Some(principal(2)),
                hotkey_principal: String::new(),
                cf_neurons: vec![
                    sns_swap_pb::CfNeuron::try_new(
                        3,
                        NEURONS_FUND_INVESTMENT_E8S * 30 / 100,
                        vec![],
                    ).unwrap()
                ],
            },
        ];
        result.sort_by_key(|p1| p1.try_get_controller().unwrap());
        result
    };

    static ref NEURONS_FUND_PARTICIPATION_LIMITS: NeuronsFundParticipationLimits = NeuronsFundParticipationLimits {
        max_theoretical_neurons_fund_participation_amount_icp: dec!(333_000.0),
        contribution_threshold_icp: dec!(75_000.0),
        one_third_participation_milestone_icp: dec!(225_000.0),
        full_participation_milestone_icp: dec!(375_000.0),
    };

    static ref SERIALIZED_IDEAL_MATCHING_FUNCTION_REPR: Option<String> = Some(
        PolynomialMatchingFunction::new(2_000_000 * E8, *NEURONS_FUND_PARTICIPATION_LIMITS, false).unwrap().serialize()
    );

    static ref INITIAL_NEURONS_FUND_PARTICIPATION: Option<NeuronsFundParticipation> =
    Some(NeuronsFundParticipation {
        ideal_matched_participation_function: Some(
            IdealMatchedParticipationFunction {
                serialized_representation: SERIALIZED_IDEAL_MATCHING_FUNCTION_REPR.clone(),
            },
        ),
        neurons_fund_reserves: Some(
            NeuronsFundSnapshot {
                neurons_fund_neuron_portions: vec![
                    NeuronsFundNeuronPortion {
                        nns_neuron_id: Some(
                            NeuronId {
                                id: 1,
                            },
                        ),
                        amount_icp_e8s: Some(
                            27000000000,
                        ),
                        maturity_equivalent_icp_e8s: Some(
                            1_200_000 * E8,
                        ),
                        controller: Some(principal(1)),
                        hotkeys: Vec::new(),
                        is_capped: Some(
                            false,
                        ),
                    },
                    NeuronsFundNeuronPortion {
                        nns_neuron_id: Some(
                            NeuronId {
                                id: 3,
                            },
                        ),
                        amount_icp_e8s: Some(
                            13500000000,
                        ),
                        maturity_equivalent_icp_e8s: Some(
                            600_000 * E8,
                        ),
                        controller: Some(principal(2)),
                        hotkeys: Vec::new(),
                        is_capped: Some(
                            false,
                        ),
                    },
                ],
            },
        ),
        swap_participation_limits: Some(
            SwapParticipationLimits {
                min_direct_participation_icp_e8s: Some(
                    36_000 * E8,
                ),
                max_direct_participation_icp_e8s: Some(
                    9000000000000,
                ),
                min_participant_icp_e8s: Some(
                    50 * E8,
                ),
                max_participant_icp_e8s: Some(
                    1_000 * E8,
                ),
            },
        ),
        direct_participation_icp_e8s: Some(
            9000000000000,
        ),
        total_maturity_equivalent_icp_e8s: Some(
            2_000_000 * E8,
        ),
        max_neurons_fund_swap_participation_icp_e8s: Some(
            45000000000,
        ),
        intended_neurons_fund_participation_icp_e8s: Some(
            45000000000,
        ),
        allocated_neurons_fund_participation_icp_e8s: Some(
            40500000000,
        ),
    });

    static ref INITIAL_NEURONS_FUND_PARTICIPATION_ABORT: Option<NeuronsFundParticipation> =
    Some(NeuronsFundParticipation {
        ideal_matched_participation_function: Some(
            IdealMatchedParticipationFunction {
                serialized_representation: SERIALIZED_IDEAL_MATCHING_FUNCTION_REPR.clone(),
            },
        ),
        neurons_fund_reserves: Some(
            NeuronsFundSnapshot {
                neurons_fund_neuron_portions: vec![],
            },
        ),
        swap_participation_limits: Some(
            SwapParticipationLimits {
                min_direct_participation_icp_e8s: Some(
                    3600000000000,
                ),
                max_direct_participation_icp_e8s: Some(
                    9000000000000,
                ),
                min_participant_icp_e8s: Some(
                    5000000000,
                ),
                max_participant_icp_e8s: Some(
                    100000000000,
                ),
            },
        ),
        direct_participation_icp_e8s: Some(
            0,
        ),
        total_maturity_equivalent_icp_e8s: Some(
            2_000_000 * E8,
        ),
        max_neurons_fund_swap_participation_icp_e8s: Some(
            45000000000,
        ),
        intended_neurons_fund_participation_icp_e8s: Some(
            0,
        ),
        allocated_neurons_fund_participation_icp_e8s: Some(
            0,
        ),
    });

    static ref INITIAL_NEURONS_FUND_PARTICIPATION_COMMIT: Option<NeuronsFundParticipation> =
    Some(NeuronsFundParticipation {
        ideal_matched_participation_function: Some(
            IdealMatchedParticipationFunction {
                serialized_representation: SERIALIZED_IDEAL_MATCHING_FUNCTION_REPR.clone(),
            },
        ),
        neurons_fund_reserves: Some(
            NeuronsFundSnapshot {
                neurons_fund_neuron_portions: vec![
                    NeuronsFundNeuronPortion {
                        nns_neuron_id: Some(
                            NeuronId {
                                id: 1,
                            },
                        ),
                        amount_icp_e8s: Some(
                            11333333333,
                        ),
                        maturity_equivalent_icp_e8s: Some(
                            120000000000000,
                        ),
                        controller: Some(principal(1)),
                        hotkeys: Vec::new(),
                        is_capped: Some(
                            false,
                        ),
                    },
                    NeuronsFundNeuronPortion {
                        nns_neuron_id: Some(
                            NeuronId {
                                id: 3,
                            },
                        ),
                        amount_icp_e8s: Some(
                            5666666667,
                        ),
                        maturity_equivalent_icp_e8s: Some(
                            60000000000000,
                        ),
                        controller: Some(principal(2)),
                        hotkeys: Vec::new(),
                        is_capped: Some(
                            false,
                        ),
                    },
                ],
            },
        ),
        swap_participation_limits: Some(
            SwapParticipationLimits {
                min_direct_participation_icp_e8s: Some(
                    3600000000000,
                ),
                max_direct_participation_icp_e8s: Some(
                    9000000000000,
                ),
                min_participant_icp_e8s: Some(
                    5000000000,
                ),
                max_participant_icp_e8s: Some(
                    100000000000,
                ),
            },
        ),
        direct_participation_icp_e8s: Some(
            8500000000000,
        ),
        total_maturity_equivalent_icp_e8s: Some(
            2_000_000 * E8,
        ),
        max_neurons_fund_swap_participation_icp_e8s: Some(
            45000000000,
        ),
        intended_neurons_fund_participation_icp_e8s: Some(
            18888888889,
        ),
        allocated_neurons_fund_participation_icp_e8s: Some(
            17000000000,
        ),
    });

    static ref NEURONS_FUND_FULL_REFUNDS: Option<NeuronsFundSnapshot> =
    Some(NeuronsFundSnapshot {
        neurons_fund_neuron_portions: vec![
            NeuronsFundNeuronPortion {
                nns_neuron_id: Some(
                    NeuronId {
                        id: 1,
                    },
                ),
                amount_icp_e8s: Some(
                    27000000000,
                ),
                maturity_equivalent_icp_e8s: Some(
                    120000000000000,
                ),
                controller: Some(principal(1)),
                hotkeys: Vec::new(),
                is_capped: Some(
                    false,
                ),
            },
            NeuronsFundNeuronPortion {
                nns_neuron_id: Some(
                    NeuronId {
                        id: 3,
                    },
                ),
                amount_icp_e8s: Some(
                    13500000000,
                ),
                maturity_equivalent_icp_e8s: Some(
                    60000000000000,
                ),
                controller: Some(principal(2)),
                hotkeys: Vec::new(),
                is_capped: Some(
                    false,
                ),
            },
        ],
    });

    static ref NEURONS_FUND_PARTIAL_REFUNDS: Option<NeuronsFundSnapshot> =
    Some(NeuronsFundSnapshot {
        neurons_fund_neuron_portions: vec![
            NeuronsFundNeuronPortion {
                nns_neuron_id: Some(
                    NeuronId {
                        id: 1,
                    },
                ),
                amount_icp_e8s: Some(
                    15666666667,
                ),
                controller: Some(principal(1)),
                hotkeys: Vec::new(),
                maturity_equivalent_icp_e8s: Some(
                    120000000000000,
                ),
                is_capped: Some(
                    false,
                ),
            },
            NeuronsFundNeuronPortion {
                nns_neuron_id: Some(
                    NeuronId {
                        id: 3,
                    },
                ),
                amount_icp_e8s: Some(
                    7833333333,
                ),
                controller: Some(principal(2)),
                hotkeys: Vec::new(),
                maturity_equivalent_icp_e8s: Some(
                    60000000000000,
                ),
                is_capped: Some(
                    false,
                ),
            },
        ],
    });

    static ref NEURONS_FUND_DATA_BEFORE_SETTLE: Option<NeuronsFundData> = Some(NeuronsFundData {
        initial_neurons_fund_participation: INITIAL_NEURONS_FUND_PARTICIPATION.clone(),
        final_neurons_fund_participation: None,
        neurons_fund_refunds: None,
    });

    static ref NEURONS_FUND_DATA_WITH_EARLY_REFUNDS: Option<NeuronsFundData> = Some(NeuronsFundData {
        initial_neurons_fund_participation: INITIAL_NEURONS_FUND_PARTICIPATION.clone(),
        final_neurons_fund_participation: None,
        neurons_fund_refunds: NEURONS_FUND_FULL_REFUNDS.clone(),
    });

    static ref NEURONS_FUND_DATA_AFTER_SETTLE_ABORT: Option<NeuronsFundData> = Some(NeuronsFundData {
        initial_neurons_fund_participation: INITIAL_NEURONS_FUND_PARTICIPATION.clone(),
        final_neurons_fund_participation: INITIAL_NEURONS_FUND_PARTICIPATION_ABORT.clone(),
        neurons_fund_refunds: NEURONS_FUND_FULL_REFUNDS.clone(),
    });

    static ref NEURONS_FUND_DATA_AFTER_SETTLE_COMMIT: Option<NeuronsFundData> = Some(NeuronsFundData {
        initial_neurons_fund_participation: INITIAL_NEURONS_FUND_PARTICIPATION.clone(),
        final_neurons_fund_participation: INITIAL_NEURONS_FUND_PARTICIPATION_COMMIT.clone(),
        neurons_fund_refunds: NEURONS_FUND_PARTIAL_REFUNDS.clone(),
    });

    static ref NEURONS_FUND_PARTICIPATION_CONSTRAINTS: Option<NeuronsFundParticipationConstraints> = Some(
        NeuronsFundParticipationConstraints {
            min_direct_participation_threshold_icp_e8s: Some(36_000 * E8),
            max_neurons_fund_participation_icp_e8s: Some(40500000000),
            coefficient_intervals: vec![
                LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(0),
                    to_direct_participation_icp_e8s: Some(8177194571439),
                    slope_numerator: Some(0),
                    slope_denominator: Some(200000000000000),
                    intercept_icp_e8s: Some(0),
                },
                LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(8177194571439),
                    to_direct_participation_icp_e8s: Some(8442528238562),
                    slope_numerator: Some(120000000000000),
                    slope_denominator: Some(200000000000000),
                    intercept_icp_e8s: Some(0),
                },
                LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(8442528238562),
                    to_direct_participation_icp_e8s: Some(u64::MAX),
                    slope_numerator: Some(180000000000000),
                    slope_denominator: Some(200000000000000),
                    intercept_icp_e8s: Some(0),
                },
            ],
            ideal_matched_participation_function: Some(IdealMatchedParticipationFunctionSwapPb {
                serialized_representation: SERIALIZED_IDEAL_MATCHING_FUNCTION_REPR.clone(),
            })
        }
    );

    static ref EXPECTED_LIST_DEPLOYED_SNSES_CALL: (ExpectedCallCanisterMethodCallArguments<'static>, CanisterCallResult) = (
        ExpectedCallCanisterMethodCallArguments {
            target: SNS_WASM_CANISTER_ID,
            method_name: "list_deployed_snses",
            request: Encode!(&ListDeployedSnsesRequest {}).unwrap(),
        },
        Ok(Encode!(&ListDeployedSnsesResponse {
            instances: vec![DeployedSns {
                swap_canister_id: Some(*TARGET_SWAP_CANISTER_ID),
                ..Default::default() // Not realistic, but other fields are not actually used.
            },],
        })
        .unwrap()),
    );

    static ref EXPECTED_FAILING_LIST_DEPLOYED_SNSES_CALL: (ExpectedCallCanisterMethodCallArguments<'static>, CanisterCallResult) = (
        ExpectedCallCanisterMethodCallArguments {
            target: SNS_WASM_CANISTER_ID,
            method_name: "list_deployed_snses",
            request: Encode!(&ListDeployedSnsesRequest {}).unwrap(),
        },
        Err((
            None, "list_deployed_snses failed for no apparent reason.".to_string()
        ))
    );

    static ref EXPECTED_SWAP_GET_STATE_CALL: (ExpectedCallCanisterMethodCallArguments<'static>, CanisterCallResult) = (
        ExpectedCallCanisterMethodCallArguments {
            target: CanisterId::try_from(*TARGET_SWAP_CANISTER_ID).unwrap(),
            method_name: "get_state",
            request: Encode!(&sns_swap_pb::GetStateRequest {}).unwrap(),
        },
        Ok(Encode!(&sns_swap_pb::GetStateResponse {
            swap: Some(sns_swap_pb::Swap {
                init: Some(INIT.clone()),
                ..Default::default() // Not realistic, but good enough for tests, which only use Init.
            }),
            ..Default::default() // Ditto previous comment.
        })
        .unwrap()),
    );

    static ref EXPECTED_SNS_ROOT_GET_SNS_CANISTERS_SUMMARY_CALL: (ExpectedCallCanisterMethodCallArguments<'static>, CanisterCallResult) = (
        ExpectedCallCanisterMethodCallArguments {
            target: (*SNS_ROOT_CANISTER_ID).try_into().unwrap(),
            method_name: "get_sns_canisters_summary",
            request: Encode!(&GetSnsCanistersSummaryRequest { update_canister_list: None }).unwrap(),
        },
        Ok(Encode!(&GetSnsCanistersSummaryResponse {
            root: Some(ic_sns_root::CanisterSummary {
                canister_id: Some(*SNS_ROOT_CANISTER_ID),
                status: Some(CanisterStatusResultV2::new(
                    CanisterStatusType::Running,
                    Some(vec![0xCA, 0xFE]),  // module_hash
                    vec![PrincipalId::new_user_test_id(647671)], // controllers
                    NumBytes::from(485082), // memory_size
                    766182, // cycles
                    808216, // compute_allocation
                    Some(517576), // memory_allocation
                    448076, // freezing_threshold
                    268693, // idle_cycles_burned_per_day
                    (3.5 * (1 << 30) as f32) as u64, // wasm_memory_limit (3.5gb)
                    123478, // wasm_memory_threshold
                    MemoryMetricsFromManagementCanister::default(), // memory_metrics
                )),
            }),
            governance: Some(ic_sns_root::CanisterSummary {
                canister_id: Some(*SNS_GOVERNANCE_CANISTER_ID),
                status: None,
            }),
            ledger: Some(ic_sns_root::CanisterSummary {
                canister_id: Some(*SNS_LEDGER_CANISTER_ID),
                status: None,
            }),
            swap: Some(ic_sns_root::CanisterSummary {
                canister_id: Some(*TARGET_SWAP_CANISTER_ID),
                status: None,
            }),
            dapps: vec![ic_sns_root::CanisterSummary {
                canister_id: Some(*DAPP_CANISTER_ID),
                status: None,
            }],
            archives: vec![ic_sns_root::CanisterSummary {
                canister_id: Some(*SNS_LEDGER_ARCHIVE_CANISTER_ID),
                status: None,
            }],
            index: Some(ic_sns_root::CanisterSummary {
                canister_id: Some(*SNS_LEDGER_INDEX_CANISTER_ID),
                status: None,
            }),
        })
        .unwrap()),
    );

    static ref EXPECTED_SWAP_BACKGROUND_INFORMATION: SwapBackgroundInformation = SwapBackgroundInformation {
        root_canister_summary: Some(swap_background_information::CanisterSummary {
            canister_id: Some(*SNS_ROOT_CANISTER_ID),
            status: Some(swap_background_information::CanisterStatusResultV2 {
                status: Some(swap_background_information::CanisterStatusType::Running as i32),
                module_hash: vec![0xCA, 0xFE],
                controllers: vec![PrincipalId::new_user_test_id(647671)],
                memory_size: Some(485082),
                cycles: Some(766182),
                freezing_threshold: Some(448076),
                idle_cycles_burned_per_day: Some(268693),
            }),
        }),

        governance_canister_summary: Some(swap_background_information::CanisterSummary {
            canister_id: Some(*SNS_GOVERNANCE_CANISTER_ID),
            status: None,
        }),
        ledger_canister_summary: Some(swap_background_information::CanisterSummary {
            canister_id: Some(*SNS_LEDGER_CANISTER_ID),
            status: None,
        }),
        swap_canister_summary: Some(swap_background_information::CanisterSummary {
            canister_id: Some(*TARGET_SWAP_CANISTER_ID),
            status: None,
        }),
        ledger_archive_canister_summaries: vec![swap_background_information::CanisterSummary {
            canister_id: Some(*SNS_LEDGER_ARCHIVE_CANISTER_ID),
            status: None,
        }],
        ledger_index_canister_summary: Some(swap_background_information::CanisterSummary {
            canister_id: Some(*SNS_LEDGER_INDEX_CANISTER_ID),
            status: None,
        }),
        dapp_canister_summaries: vec![swap_background_information::CanisterSummary {
            canister_id: Some(*DAPP_CANISTER_ID),
            status: None,
        }],

        fallback_controller_principal_ids: vec![*DEVELOPER_PRINCIPAL_ID],
    };

    static ref CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL: Proposal = Proposal {
        title: Some("Create a Service Nervous System".to_string()),
        summary: "".to_string(),
        action: Some(proposal::Action::CreateServiceNervousSystem(CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone())),
        ..Default::default()
    };

    static ref SNS_INIT_PAYLOAD: SnsInitPayload = {
        let create_service_nervous_system = CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING.clone();

        // The computation for swap_start_timestamp_seconds and swap_due_timestamp_seconds below
        // is inlined from `Governance::make_sns_init_payload`.
        let (swap_start_timestamp_seconds, swap_due_timestamp_seconds) = {
            let random_swap_start_time = GlobalTimeOfDay {
                seconds_after_utc_midnight: Some(RANDOM_U64)
            };

            let start_time = create_service_nervous_system
                .swap_parameters
                .as_ref()
                .and_then(|swap_parameters| swap_parameters.start_time);

            let duration = create_service_nervous_system
                .swap_parameters
                .as_ref()
                .and_then(|swap_parameters| swap_parameters.duration);

            CreateServiceNervousSystem::swap_start_and_due_timestamps(
                start_time.unwrap_or(random_swap_start_time),
                duration.unwrap_or_default(),
                DEFAULT_TEST_START_TIMESTAMP_SECONDS,
            )
            .expect(
                "Cannot compute swap_start_timestamp_seconds, swap_due_timestamp_seconds \
                 for SNS_INIT_PAYLOAD."
            )
        };

        let sns_init_payload = SnsInitPayload::try_from(ApiCreateServiceNervousSystem::from(create_service_nervous_system))
            .expect(
                "Cannot build SNS_INIT_PAYLOAD from \
                CREATE_SERVICE_NERVOUS_SYSTEM_WITH_MATCHED_FUNDING."
            );

        SnsInitPayload {
            neurons_fund_participation_constraints: NEURONS_FUND_PARTICIPATION_CONSTRAINTS.clone(),
            nns_proposal_id: Some(1),
            swap_start_timestamp_seconds: Some(swap_start_timestamp_seconds),
            swap_due_timestamp_seconds: Some(swap_due_timestamp_seconds),
            ..sns_init_payload
        }
    };

    static ref EXPECTED_DEPLOY_NEW_SNS_CALL: (ExpectedCallCanisterMethodCallArguments<'static>, CanisterCallResult) = (
        ExpectedCallCanisterMethodCallArguments {
            target: SNS_WASM_CANISTER_ID,
            method_name: "deploy_new_sns",
            request: Encode!(&DeployNewSnsRequest {
                sns_init_payload: Some(SNS_INIT_PAYLOAD.clone())
            }).unwrap(),
        },
        Ok(Encode!(&DeployNewSnsResponse {
            error: None,
            ..Default::default()
        }).unwrap())
    );

    static ref FAILING_DEPLOY_NEW_SNS_CALL: (ExpectedCallCanisterMethodCallArguments<'static>, CanisterCallResult) = (
        ExpectedCallCanisterMethodCallArguments {
            target: SNS_WASM_CANISTER_ID,
            method_name: "deploy_new_sns",
            request: Encode!(&DeployNewSnsRequest {
                sns_init_payload: Some(SNS_INIT_PAYLOAD.clone())
            }).unwrap(),
        },
        Err((
            None, "deploy_new_sns failed for no apparent reason.".to_string()
        ))
    );
}

//TODO: this is displayed as dead code even though it is used
//in `lazy_static!`
#[allow(dead_code)]
const NEURONS_FUND_INVESTMENT_E8S: u64 = 61 * E8;

/// Failure when settling the Neurons' fund should result in the Lifecycle remaining
/// what it was before the method invocation.
#[tokio::test]
async fn test_settle_neurons_fund_participation_restores_lifecycle_on_sns_w_failure() {
    use settle_neurons_fund_participation_request::{Committed, Result};

    // Step 1: Prepare the world.

    let neurons = SWAP_ID_TO_NEURON.clone();

    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(api::NetworkEconomics::with_default_values())
        .with_neurons(neurons)
        .build();

    let expected_call_canister_method_calls: Arc<Mutex<VecDeque<_>>> = Arc::new(Mutex::new(
        [
            // Called during proposal execution
            EXPECTED_DEPLOY_NEW_SNS_CALL.clone(),
            // Called during first settlement call
            EXPECTED_FAILING_LIST_DEPLOYED_SNSES_CALL.clone(),
        ]
        .into(),
    ));

    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        governance_proto,
        Arc::new(MockEnvironment {
            expected_call_canister_method_calls: Arc::clone(&expected_call_canister_method_calls),
            call_canister_method_min_duration: None,
        }),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Run code under test.

    // Create a CreateServiceNervousSystem proposal that will decrement NF neuron's stake
    // by a measurable amount.
    let proposal_id = gov
        .make_proposal(
            &NeuronId { id: 1 },
            &principal(1),
            &CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL,
        )
        .await
        .unwrap();

    // Step 3: Inspect results.
    let proposal = gov.get_proposal_data(proposal_id).unwrap();
    // Assert that the proposal is executed and the lifecycle has been set
    assert!(proposal.executed_timestamp_seconds > 0, "{proposal:?}");
    assert_eq!(
        proposal.sns_token_swap_lifecycle,
        Some(sns_swap_pb::Lifecycle::Open as i32)
    );

    // Calculate the AccountIdentifier of SNS Governance for balance lookups
    let sns_governance_icp_account =
        AccountIdentifier::new(*SNS_GOVERNANCE_CANISTER_ID, /* Subaccount*/ None);

    // Get the treasury accounts balance
    let sns_governance_treasury_balance_before_commitment = driver
        .get_fake_ledger()
        .account_balance(sns_governance_icp_account)
        .await
        .unwrap();

    // The value should be zero since the maturity has not been minted
    assert_eq!(
        sns_governance_treasury_balance_before_commitment.get_e8s(),
        0
    );

    // Settle the Neurons' Fund participation. This should fail due to
    // `EXPECTED_FAILING_LIST_DEPLOYED_SNSES_CALL`.
    let response = gov
        .settle_neurons_fund_participation(
            *TARGET_SWAP_CANISTER_ID,
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(proposal.id.unwrap().id),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: Some(*SNS_GOVERNANCE_CANISTER_ID),
                    total_direct_participation_icp_e8s: Some(45_000 * E8),
                    total_neurons_fund_participation_icp_e8s: Some(50_000 * E8),
                })),
            },
        )
        .await;

    let settle_neurons_fund_participation_response =
        assert_matches!(response, Err(err) => err.to_string());
    assert!(
        settle_neurons_fund_participation_response
            .contains("not authorized to settle Neurons' Fund participation"),
        "unexpected settle_neurons_fund_participation_response: {settle_neurons_fund_participation_response:?}",
    );
    assert!(
        settle_neurons_fund_participation_response.contains("list_deployed_snses failed"),
        "unexpected settle_neurons_fund_participation_response: {settle_neurons_fund_participation_response:?}",
    );

    // Get the treasury account's balance again
    let sns_governance_treasury_balance_after_commitment = driver
        .get_fake_ledger()
        .account_balance(sns_governance_icp_account)
        .await
        .unwrap();

    // The balance should still be zero.
    assert_eq!(
        sns_governance_treasury_balance_after_commitment.get_e8s(),
        0
    );

    // Make sure the ProposalData's sns_token_swap_lifecycle is still Open.
    let proposal = gov.get_proposal_data(proposal_id).unwrap();
    assert_eq!(
        proposal.sns_token_swap_lifecycle,
        Some(sns_swap_pb::Lifecycle::Open as i32)
    );

    // Inspect the proposal fields related to the Neurons' Fund
    assert_eq!(proposal.neurons_fund_data, *NEURONS_FUND_DATA_BEFORE_SETTLE);
}

/// Failure when settling the Neurons' Fund should result in the Lifecycle remaining
/// what it was before the method invocation.
#[tokio::test]
async fn test_settle_neurons_fund_participation_restores_lifecycle_on_ledger_failure() {
    use settle_neurons_fund_participation_request::{Committed, Result};

    // Step 1: Prepare the world.

    let neurons = SWAP_ID_TO_NEURON.clone();

    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(api::NetworkEconomics::with_default_values())
        .with_neurons(neurons)
        .build();

    let expected_call_canister_method_calls: Arc<Mutex<VecDeque<_>>> = Arc::new(Mutex::new(
        [
            // Called during proposal execution
            EXPECTED_DEPLOY_NEW_SNS_CALL.clone(),
            // Called during first settlement call
            EXPECTED_LIST_DEPLOYED_SNSES_CALL.clone(),
        ]
        .into(),
    ));

    let driver = fake::FakeDriver::default();
    let icp_ledger: SpyLedger = SpyLedger::new(vec![LedgerReply::TransferFunds(Err(
        NervousSystemError::new_with_message("Error conducting the transfer"),
    ))]);
    let mut gov = Governance::new(
        governance_proto,
        Arc::new(MockEnvironment {
            expected_call_canister_method_calls: Arc::clone(&expected_call_canister_method_calls),
            call_canister_method_min_duration: None,
        }),
        Arc::new(icp_ledger),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Run code under test.

    // Create a CreateServiceNervousSystem proposal that will decrement NF neuron's stake
    // by a measurable amount.
    let proposal_id = gov
        .make_proposal(
            &NeuronId { id: 1 },
            &principal(1),
            &CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL,
        )
        .await
        .unwrap();

    // Step 3: Inspect results.
    let proposal = gov.get_proposal_data(proposal_id).unwrap();
    // Assert that the proposal is executed and the lifecycle has been set
    assert!(proposal.executed_timestamp_seconds > 0, "{proposal:?}");
    assert_eq!(
        proposal.sns_token_swap_lifecycle,
        Some(sns_swap_pb::Lifecycle::Open as i32)
    );

    // Calculate the AccountIdentifier of SNS Governance for balance lookups
    let sns_governance_icp_account =
        AccountIdentifier::new(*SNS_GOVERNANCE_CANISTER_ID, /* Subaccount*/ None);

    // Get the treasury accounts balance
    let sns_governance_treasury_balance_before_commitment = driver
        .get_fake_ledger()
        .account_balance(sns_governance_icp_account)
        .await
        .unwrap();

    // The value should be zero since the maturity has not been minted
    assert_eq!(
        sns_governance_treasury_balance_before_commitment.get_e8s(),
        0
    );

    // Settle the Neurons' Fund participation. This should fail due to the ICP Ledger transfer error.
    let response = gov
        .settle_neurons_fund_participation(
            *TARGET_SWAP_CANISTER_ID,
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(proposal.id.unwrap().id),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: Some(*SNS_GOVERNANCE_CANISTER_ID),
                    total_direct_participation_icp_e8s: Some(85_000 * E8),
                    total_neurons_fund_participation_icp_e8s: Some(50_000 * E8),
                })),
            },
        )
        .await;

    let settle_neurons_fund_participation_response =
        assert_matches!(response, Err(err) => err.to_string());
    assert!(
        settle_neurons_fund_participation_response
            .contains("Minting ICP from the Neuron's Fund failed"),
        "unexpected settle_neurons_fund_participation_response: {settle_neurons_fund_participation_response:?}",
    );
    assert!(
        settle_neurons_fund_participation_response.contains("Error conducting the transfer"),
        "unexpected settle_neurons_fund_participation_response: {settle_neurons_fund_participation_response:?}",
    );

    // Get the treasury account's balance again
    let sns_governance_treasury_balance_after_commitment = driver
        .get_fake_ledger()
        .account_balance(sns_governance_icp_account)
        .await
        .unwrap();

    // The balance should still be zero.
    assert_eq!(
        sns_governance_treasury_balance_after_commitment.get_e8s(),
        0
    );

    // Make sure the ProposalData's sns_token_swap_lifecycle is still Open.
    let proposal = gov.get_proposal_data(proposal_id).unwrap();
    assert_eq!(
        proposal.sns_token_swap_lifecycle,
        Some(sns_swap_pb::Lifecycle::Open as i32)
    );

    // Inspect the proposal fields related to the Neurons' Fund
    assert_eq!(proposal.neurons_fund_data, *NEURONS_FUND_DATA_BEFORE_SETTLE);
}

fn assert_neurons_fund_unchanged(gov: &Governance, original_state: Vec<api::Neuron>) {
    for original_neuron in original_state {
        let id = original_neuron.id.unwrap().id;
        let current_neuron = gov
            .neuron_store
            .with_neuron(&NeuronId { id }, |n| n.clone())
            .unwrap();
        assert_eq!(
            current_neuron.maturity_e8s_equivalent,
            original_neuron.maturity_e8s_equivalent
        );
    }
}

#[tokio::test]
async fn test_create_service_nervous_system_failure_due_to_swap_deployment_error() {
    // Step 1: Prepare the world.

    let neurons = SWAP_ID_TO_NEURON.clone();

    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(api::NetworkEconomics::with_default_values())
        .with_neurons(neurons)
        .build();

    let expected_call_canister_method_calls: Arc<Mutex<VecDeque<_>>> = Arc::new(Mutex::new(
        [
            // Called during proposal execution
            FAILING_DEPLOY_NEW_SNS_CALL.clone(),
        ]
        .into(),
    ));

    let driver = fake::FakeDriver::default().with_ledger_accounts(vec![]); // Initialize the minting account
    let mut gov = Governance::new(
        governance_proto,
        Arc::new(MockEnvironment {
            expected_call_canister_method_calls: Arc::clone(&expected_call_canister_method_calls),
            call_canister_method_min_duration: None,
        }),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Run code under test. This is done indirectly via proposal. The
    // proposal is executed right away, because of the "passage of time", as
    // experienced via the MockEnvironment in gov.
    gov.make_proposal(
        &NeuronId { id: 1 },
        &principal(1),
        &CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL,
    )
    .await
    .unwrap();

    // Step 3: Inspect results.

    // Step 3.1: Inspect the proposal. In particular, look at its execution status.
    assert_eq!(
        gov.heap_data.proposals.len(),
        1,
        "{:#?}",
        gov.heap_data.proposals
    );
    let mut proposals: Vec<(_, _)> = gov.heap_data.proposals.iter().collect();
    let (_id, proposal) = proposals.pop().unwrap();
    assert_eq!(
        proposal.proposal.as_ref().unwrap().title.as_ref().unwrap(),
        "Create a Service Nervous System",
        "{:#?}",
        proposal.proposal.as_ref().unwrap()
    );
    assert_eq!(proposal.executed_timestamp_seconds, 0, "{:#?}", proposal);
    assert_eq!(proposal.sns_token_swap_lifecycle, None);
    assert_eq!(
        proposal.failed_timestamp_seconds, DEFAULT_TEST_START_TIMESTAMP_SECONDS,
        "{:#?}",
        proposal
    );
    assert_matches!(proposal.failure_reason, Some(_), "{:#?}", proposal);
    assert_eq!(proposal.derived_proposal_information, None);

    assert_eq!(
        proposal.neurons_fund_data,
        *NEURONS_FUND_DATA_WITH_EARLY_REFUNDS
    );

    // Assert that maturity of (all) Neurons' Fund neurons has been restored.
    let reserved_neurons_portions = NEURONS_FUND_DATA_WITH_EARLY_REFUNDS
        .as_ref()
        .unwrap()
        .initial_neurons_fund_participation
        .as_ref()
        .unwrap()
        .neurons_fund_reserves
        .as_ref()
        .unwrap()
        .neurons_fund_neuron_portions
        .clone();
    for portion in reserved_neurons_portions {
        let current_neuron = gov
            .neuron_store
            .with_neuron(&portion.nns_neuron_id.unwrap(), |neuron| neuron.clone())
            .unwrap();
        assert_eq!(
            Some(current_neuron.maturity_e8s_equivalent),
            portion.maturity_equivalent_icp_e8s
        );
    }
}

#[tokio::test]
async fn test_create_service_nervous_system_settles_neurons_fund_commit() {
    // Step 1: Prepare the world.

    let neurons = SWAP_ID_TO_NEURON.clone();

    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(api::NetworkEconomics::with_default_values())
        .with_neurons(neurons)
        .build();

    let expected_call_canister_method_calls: Arc<Mutex<VecDeque<_>>> = Arc::new(Mutex::new(
        [
            // Called during proposal execution
            EXPECTED_DEPLOY_NEW_SNS_CALL.clone(),
            // Called during settlement
            EXPECTED_LIST_DEPLOYED_SNSES_CALL.clone(),
        ]
        .into(),
    ));

    let driver = fake::FakeDriver::default().with_ledger_accounts(vec![]); // Initialize the minting account
    let mut gov = Governance::new(
        governance_proto,
        Arc::new(MockEnvironment {
            expected_call_canister_method_calls: Arc::clone(&expected_call_canister_method_calls),
            call_canister_method_min_duration: None,
        }),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Run code under test. This is done indirectly via proposal. The
    // proposal is executed right away, because of the "passage of time", as
    // experienced via the MockEnvironment in gov.
    gov.make_proposal(
        &NeuronId { id: 1 },
        &principal(1),
        &CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL,
    )
    .await
    .unwrap();

    // Step 3: Inspect results.

    // Step 3.1: Inspect the proposal. In particular, look at its execution status.
    assert_eq!(
        gov.heap_data.proposals.len(),
        1,
        "{:#?}",
        gov.heap_data.proposals
    );
    let mut proposals: Vec<(_, _)> = gov.heap_data.proposals.iter().collect();
    let (_id, proposal) = proposals.pop().unwrap();
    assert_eq!(
        proposal.proposal.as_ref().unwrap().title.as_ref().unwrap(),
        "Create a Service Nervous System",
        "{:#?}",
        proposal.proposal.as_ref().unwrap()
    );
    assert_eq!(
        proposal.executed_timestamp_seconds, DEFAULT_TEST_START_TIMESTAMP_SECONDS,
        "{:#?}",
        proposal
    );
    assert_eq!(
        proposal.sns_token_swap_lifecycle,
        Some(Lifecycle::Open as i32)
    );
    assert_eq!(proposal.failed_timestamp_seconds, 0, "{:#?}", proposal);
    assert_eq!(proposal.failure_reason, None, "{:#?}", proposal);
    assert_eq!(proposal.derived_proposal_information, None);

    assert_eq!(proposal.neurons_fund_data, *NEURONS_FUND_DATA_BEFORE_SETTLE);

    // Assert some of the maturity has been decremented and is held in escrow
    let reserved_neurons_portions = NEURONS_FUND_DATA_BEFORE_SETTLE
        .as_ref()
        .unwrap()
        .initial_neurons_fund_participation
        .as_ref()
        .unwrap()
        .neurons_fund_reserves
        .as_ref()
        .unwrap()
        .neurons_fund_neuron_portions
        .clone();
    for portion in reserved_neurons_portions {
        let current_neuron = gov
            .neuron_store
            .with_neuron(&portion.nns_neuron_id.unwrap(), |neuron| neuron.clone())
            .unwrap();
        assert!(
            current_neuron.maturity_e8s_equivalent + portion.amount_icp_e8s.unwrap()
                == portion.maturity_equivalent_icp_e8s.unwrap()
        );
    }

    // Settle NF participation (Commit).
    {
        use settle_neurons_fund_participation_request::{Committed, Result};
        let response = gov
            .settle_neurons_fund_participation(
                *TARGET_SWAP_CANISTER_ID,
                SettleNeuronsFundParticipationRequest {
                    nns_proposal_id: Some(proposal.id.unwrap().id),
                    result: Some(Result::Committed(Committed {
                        sns_governance_canister_id: Some(*SNS_GOVERNANCE_CANISTER_ID),
                        // This amount should result in some NF funds and some refunds.
                        total_direct_participation_icp_e8s: Some(85_000 * E8),
                        total_neurons_fund_participation_icp_e8s: Some(69_439_371_803),
                    })),
                },
            )
            .await;
        assert!(response.is_ok(), "Expected Ok result, got {response:?}");

        // Re-inspect the proposal.
        let mut proposals: Vec<(_, _)> = gov.heap_data.proposals.iter().collect();
        assert_eq!(proposals.len(), 1);
        let (_id, proposal) = proposals.pop().unwrap();

        // Unlike a short while ago (right before this block), we are now settled
        assert_eq!(
            proposal.sns_token_swap_lifecycle,
            Some(Lifecycle::Committed as i32),
        );
        assert_eq!(
            proposal.neurons_fund_data,
            *NEURONS_FUND_DATA_AFTER_SETTLE_COMMIT
        );
    }

    // Step 3.2: Make sure expected canister call(s) take place.
    assert!(
        expected_call_canister_method_calls
            .lock()
            .unwrap()
            .is_empty(),
        "Calls that should have been made, but were not: {expected_call_canister_method_calls:#?}",
    );
}

#[tokio::test]
async fn test_create_service_nervous_system_settles_neurons_fund_abort() {
    // Step 1: Prepare the world.

    let neurons = SWAP_ID_TO_NEURON.clone();

    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(api::NetworkEconomics::with_default_values())
        .with_neurons(neurons)
        .build();

    let expected_call_canister_method_calls: Arc<Mutex<VecDeque<_>>> = Arc::new(Mutex::new(
        [
            // Called during proposal execution
            EXPECTED_DEPLOY_NEW_SNS_CALL.clone(),
            // Called during settlement
            EXPECTED_LIST_DEPLOYED_SNSES_CALL.clone(),
        ]
        .into(),
    ));

    let driver = fake::FakeDriver::default().with_ledger_accounts(vec![]); // Initialize the minting account
    let mut gov = Governance::new(
        governance_proto,
        Arc::new(MockEnvironment {
            expected_call_canister_method_calls: Arc::clone(&expected_call_canister_method_calls),
            call_canister_method_min_duration: None,
        }),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Run code under test. This is done indirectly via proposal. The
    // proposal is executed right away, because of the "passage of time", as
    // experienced via the MockEnvironment in gov.
    gov.make_proposal(
        &NeuronId { id: 1 },
        &principal(1),
        &CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL,
    )
    .await
    .unwrap();

    // Step 3: Inspect results.

    // Step 3.1: Inspect the proposal. In particular, look at its execution status.
    assert_eq!(
        gov.heap_data.proposals.len(),
        1,
        "{:#?}",
        gov.heap_data.proposals
    );

    let mut proposals: Vec<(_, _)> = gov.heap_data.proposals.iter().collect();
    let (_id, proposal) = proposals.pop().unwrap();

    assert_eq!(
        proposal.proposal.as_ref().unwrap().title.as_ref().unwrap(),
        "Create a Service Nervous System",
        "{:#?}",
        proposal.proposal.as_ref().unwrap()
    );
    assert_eq!(
        proposal.executed_timestamp_seconds, DEFAULT_TEST_START_TIMESTAMP_SECONDS,
        "{:#?}",
        proposal
    );
    assert_eq!(
        proposal.sns_token_swap_lifecycle,
        Some(Lifecycle::Open as i32)
    );
    assert_eq!(proposal.failed_timestamp_seconds, 0, "{:#?}", proposal);
    assert_eq!(proposal.failure_reason, None, "{:#?}", proposal);
    assert_eq!(proposal.derived_proposal_information, None);
    assert_eq!(proposal.neurons_fund_data, *NEURONS_FUND_DATA_BEFORE_SETTLE);

    // Assert some of the maturity has been decremented and is held in escrow
    let reserved_neurons_portions = NEURONS_FUND_DATA_BEFORE_SETTLE
        .as_ref()
        .unwrap()
        .initial_neurons_fund_participation
        .as_ref()
        .unwrap()
        .neurons_fund_reserves
        .as_ref()
        .unwrap()
        .neurons_fund_neuron_portions
        .clone();
    for portion in reserved_neurons_portions {
        let current_neuron = gov
            .neuron_store
            .with_neuron(&portion.nns_neuron_id.unwrap(), |neuron| neuron.clone())
            .unwrap();
        assert!(
            current_neuron.maturity_e8s_equivalent + portion.amount_icp_e8s.unwrap()
                == portion.maturity_equivalent_icp_e8s.unwrap()
        );
    }

    // Settle NF participation (Abort).
    {
        use settle_neurons_fund_participation_request::{Aborted, Result};
        let response = gov
            .settle_neurons_fund_participation(
                *TARGET_SWAP_CANISTER_ID,
                SettleNeuronsFundParticipationRequest {
                    nns_proposal_id: Some(proposal.id.unwrap().id),
                    result: Some(Result::Aborted(Aborted {})),
                },
            )
            .await;

        assert!(response.is_ok(), "Expected Ok result, got {response:?}");

        // Re-inspect the proposal.
        let mut proposals: Vec<(_, _)> = gov.heap_data.proposals.iter().collect();
        assert_eq!(proposals.len(), 1);
        let (_id, proposal) = proposals.pop().unwrap();

        // Unlike a short while ago (right before this block), we are now aborted
        assert_eq!(
            proposal.sns_token_swap_lifecycle,
            Some(Lifecycle::Aborted as i32),
        );

        assert_neurons_fund_unchanged(&gov, SWAP_ID_TO_NEURON.clone());

        assert_eq!(
            proposal.neurons_fund_data,
            *NEURONS_FUND_DATA_AFTER_SETTLE_ABORT
        );
    }

    // Step 3.2: Make sure expected canister call(s) take place.
    assert!(
        expected_call_canister_method_calls
            .lock()
            .unwrap()
            .is_empty(),
        "Calls that should have been made, but were not: {expected_call_canister_method_calls:#?}",
    );
}

#[tokio::test]
async fn test_create_service_nervous_system_proposal_execution_fails() {
    // Step 1: Prepare the world.

    let neurons = SWAP_ID_TO_NEURON.clone();

    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(api::NetworkEconomics::with_default_values())
        .with_neurons(neurons)
        .build();

    let expected_call_canister_method_calls: Arc<Mutex<VecDeque<_>>> = Arc::new(Mutex::new(
        [
            // Called during proposal execution
            (
                EXPECTED_DEPLOY_NEW_SNS_CALL.0.clone(),
                // Error from SNS-W
                Ok(Encode!(&DeployNewSnsResponse {
                    error: Some(SnsWasmError {
                        message: "Error encountered".to_string()
                    }),
                    ..Default::default()
                })
                .unwrap()),
            ),
        ]
        .into(),
    ));

    let driver = fake::FakeDriver::default().with_ledger_accounts(vec![]); // Initialize the minting account
    let mut gov = Governance::new(
        governance_proto,
        // This is where the main expectation is set. To wit, we expect that
        // execution of the proposal will cause governance to call out to the
        // swap canister.
        Arc::new(MockEnvironment {
            expected_call_canister_method_calls: Arc::clone(&expected_call_canister_method_calls),
            call_canister_method_min_duration: None,
        }),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Run code under test. This is done indirectly via proposal. The
    // proposal is executed right away, because of the "passage of time", as
    // experienced via the MockEnvironment in gov.
    gov.make_proposal(
        &NeuronId { id: 1 },
        &principal(1),
        &CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL,
    )
    .await
    .unwrap();

    // Step 3: Inspect results.

    // Step 3.1: Inspect the proposal. In particular, look at its execution status.
    assert_eq!(
        gov.heap_data.proposals.len(),
        1,
        "{:#?}",
        gov.heap_data.proposals
    );
    let mut proposals: Vec<(_, _)> = gov.heap_data.proposals.iter().collect();
    let (_id, proposal) = proposals.pop().unwrap();
    assert_eq!(
        proposal.proposal.as_ref().unwrap().title.as_ref().unwrap(),
        "Create a Service Nervous System",
        "{:#?}",
        proposal.proposal.as_ref().unwrap()
    );
    assert_eq!(proposal.sns_token_swap_lifecycle, None);
    assert_eq!(proposal.executed_timestamp_seconds, 0, "{:#?}", proposal);
    assert_eq!(
        proposal.neurons_fund_data,
        *NEURONS_FUND_DATA_WITH_EARLY_REFUNDS
    );
    assert_ne!(proposal.failed_timestamp_seconds, 0, "{:#?}", proposal);
    let failure_reason = proposal.failure_reason.clone().unwrap();
    assert_eq!(
        failure_reason.error_type,
        ErrorType::External as i32,
        "{:#?}",
        proposal,
    );
    assert!(
        failure_reason.error_message.contains("Error encountered"),
        "proposal = {proposal:#?}.",
    );
    assert_eq!(proposal.derived_proposal_information, None);

    assert_neurons_fund_unchanged(&gov, SWAP_ID_TO_NEURON.clone());

    // Step 3.2: Make sure expected canister call(s) take place.
    assert!(
        expected_call_canister_method_calls
            .lock()
            .unwrap()
            .is_empty(),
        "Calls that should have been made, but were not: {expected_call_canister_method_calls:#?}",
    );
}

#[tokio::test]
async fn test_settle_neurons_fund_is_idempotent_for_create_service_nervous_system() {
    use settle_neurons_fund_participation_request::{Committed, Result};

    let neurons = SWAP_ID_TO_NEURON.clone();

    // Step 1: Prepare the world.
    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(api::NetworkEconomics::with_default_values())
        .with_neurons(neurons)
        .build();

    let expected_call_canister_method_calls: Arc<Mutex<VecDeque<_>>> = Arc::new(Mutex::new(
        [
            // Called during proposal execution
            EXPECTED_DEPLOY_NEW_SNS_CALL.clone(),
            // Called during first settlement call
            EXPECTED_LIST_DEPLOYED_SNSES_CALL.clone(),
            // Called during second settlement call
            EXPECTED_LIST_DEPLOYED_SNSES_CALL.clone(),
            // Called during third settlement call
            EXPECTED_LIST_DEPLOYED_SNSES_CALL.clone(),
        ]
        .into(),
    ));

    let driver = fake::FakeDriver::default().with_ledger_accounts(vec![]); // Initialize the minting account
    let mut gov = Governance::new(
        governance_proto,
        Arc::new(MockEnvironment {
            expected_call_canister_method_calls: Arc::clone(&expected_call_canister_method_calls),
            call_canister_method_min_duration: None,
        }),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Step 2: Run code under test.

    // Create a CreateServiceNervousSystem proposal that will decrement NF neuron's stake a measurable amount
    let proposal_id = gov
        .make_proposal(
            &NeuronId { id: 1 },
            &principal(1),
            &CREATE_SERVICE_NERVOUS_SYSTEM_PROPOSAL,
        )
        .await
        .unwrap();

    let proposal = gov.get_proposal_data(proposal_id).unwrap();
    // Assert that the proposal is executed and the lifecycle has been set
    assert!(proposal.executed_timestamp_seconds > 0);
    assert_eq!(
        proposal.sns_token_swap_lifecycle,
        Some(sns_swap_pb::Lifecycle::Open as i32)
    );

    // Calculate the AccountIdentifier of SNS Governance for balance lookups
    let sns_governance_icp_account =
        AccountIdentifier::new(*SNS_GOVERNANCE_CANISTER_ID, /* Subaccount*/ None);

    // Get the treasury accounts balance
    let sns_governance_treasury_balance_before_commitment = driver
        .get_fake_ledger()
        .account_balance(sns_governance_icp_account)
        .await
        .unwrap();

    // The value should be zero since the maturity has not been minted
    assert_eq!(
        sns_governance_treasury_balance_before_commitment.get_e8s(),
        0
    );

    // Settle the Neurons' Fund participation for the first time.
    let response = gov
        .settle_neurons_fund_participation(
            *TARGET_SWAP_CANISTER_ID,
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(proposal.id.unwrap().id),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: Some(*SNS_GOVERNANCE_CANISTER_ID),
                    // This amount should result in some NF funds and some refunds.
                    total_direct_participation_icp_e8s: Some(85_000 * E8),
                    total_neurons_fund_participation_icp_e8s: Some(69_439_371_803),
                })),
            },
        )
        .await;

    assert!(response.is_ok(), "Expected Ok result, got {response:?}");

    // Get the treasury account's balance again
    let sns_governance_treasury_balance_after_commitment = driver
        .get_fake_ledger()
        .account_balance(sns_governance_icp_account)
        .await
        .unwrap();

    // The balance should now not be zero.
    assert!(sns_governance_treasury_balance_after_commitment.get_e8s() > 0);
    assert!(
        sns_governance_treasury_balance_after_commitment
            > sns_governance_treasury_balance_before_commitment
    );

    // Make sure the ProposalData's sns_token_swap_lifecycle was also set, as this is how
    // idempotency is achieved
    let proposal = gov.get_proposal_data(proposal_id).unwrap();
    assert_eq!(
        proposal.sns_token_swap_lifecycle,
        Some(sns_swap_pb::Lifecycle::Committed as i32)
    );
    // Inspect the proposal fields related to the Neurons' Fund
    assert_eq!(
        proposal.neurons_fund_data,
        *NEURONS_FUND_DATA_AFTER_SETTLE_COMMIT
    );

    // Settle the Neurons' Fund participation for the second time.
    let response = gov
        .settle_neurons_fund_participation(
            *TARGET_SWAP_CANISTER_ID,
            SettleNeuronsFundParticipationRequest {
                nns_proposal_id: Some(proposal.id.unwrap().id),
                result: Some(Result::Committed(Committed {
                    sns_governance_canister_id: Some(*SNS_GOVERNANCE_CANISTER_ID),
                    // This amount should result in some NF funds and some refunds.
                    total_direct_participation_icp_e8s: Some(40_000 * E8),
                    total_neurons_fund_participation_icp_e8s: Some(69_439_371_803),
                })),
            },
        )
        .await;

    assert!(response.is_ok(), "Expected Ok result, got {response:?}");

    // Get the treasury account's balance again
    let sns_governance_treasury_balance_after_second_settle_call = driver
        .get_fake_ledger()
        .account_balance(sns_governance_icp_account)
        .await
        .unwrap();

    // Assert that no work has been done, the balance should not have changed
    assert_eq!(
        sns_governance_treasury_balance_after_commitment,
        sns_governance_treasury_balance_after_second_settle_call
    );

    // Assert that the ProposalData's sns_token_swap_lifecycle hasn't changed
    let proposal = gov.get_proposal_data(proposal_id).unwrap();
    assert_eq!(
        proposal.sns_token_swap_lifecycle,
        Some(sns_swap_pb::Lifecycle::Committed as i32)
    );
    // Inspect the proposal fields related to the Neurons' Fund
    assert_eq!(
        proposal.neurons_fund_data,
        *NEURONS_FUND_DATA_AFTER_SETTLE_COMMIT
    );
}

#[tokio::test]
async fn distribute_rewards_test() {
    // Step 1: Prepare the world.

    let genesis_timestamp_seconds = 1;

    // We want to have a positive reward purse for this test, and that depends
    // on the current token supply.
    let account_id = AccountIdentifier::new(
        ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
        None,
    );
    let helper = fake::FakeDriver::default().with_ledger_accounts(vec![fake::FakeAccount {
        id: account_id,
        amount_e8s: 1_000_000_000_000,
    }]);

    // Make sure that we begin the test a "long" time after the UNIX epoch.
    let now = helper.state.lock().unwrap().now;
    assert!(now > 30 * 24 * 60 * 60);

    // Step 1.1: Craft many neurons.
    // A number whose only significance is that it is not Protocol Buffers default (i.e. 0.0).
    let starting_maturity = 3;
    let neuron_range = 100..200;
    let neurons = neuron_range
        .clone()
        .map(|id| api::Neuron {
            id: Some(NeuronId { id }),
            account: account(id),
            controller: Some(principal(id)),
            cached_neuron_stake_e8s: 1_000_000_000,
            maturity_e8s_equivalent: starting_maturity,
            dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(
                ONE_YEAR_SECONDS,
            )),
            aging_since_timestamp_seconds: now - 1,
            ..Default::default()
        })
        .collect::<Vec<api::Neuron>>();

    // Step 1.2: Craft many ProposalData objects.
    let wait_for_quiet_threshold_seconds = 99;
    let proposal_data_list: Vec<ProposalData> = (5000..6000)
        .map(|id| {
            let p = ProposalData {
                id: Some(ProposalId { id }),
                proposal: Some(Proposal {
                    action: Some(proposal::Action::Motion(Motion {
                        motion_text: "For great justice.".to_string(),
                    })),
                    ..Default::default()
                }),
                ballots: neurons
                    .iter()
                    .map(|n| {
                        let ballot = Ballot {
                            vote: Vote::Yes as i32,
                            voting_power: 1_000_000_000,
                        };

                        (n.id.as_ref().unwrap().id, ballot)
                    })
                    .collect(),
                decided_timestamp_seconds: now - 100,
                executed_timestamp_seconds: now - 99,
                ..Default::default()
            };

            assert_eq!(
                p.reward_status(now, wait_for_quiet_threshold_seconds),
                ProposalRewardStatus::ReadyToSettle,
            );

            p
        })
        .collect();

    // Step 1.3: Craft a Governance.
    let governance_init = api::Governance {
        genesis_timestamp_seconds,
        wait_for_quiet_threshold_seconds,
        short_voting_period_seconds: wait_for_quiet_threshold_seconds,
        neuron_management_voting_period_seconds: Some(wait_for_quiet_threshold_seconds),
        economics: Some(api::NetworkEconomics {
            max_proposals_to_keep_per_topic: 9999,
            ..Default::default()
        }),
        neurons: neurons
            .iter()
            .map(|n| (n.id.as_ref().unwrap().id, n.clone()))
            .collect(),
        // Last reward event was a "long time ago".
        // This should cause rewards to be distributed.
        latest_reward_event: Some(api::RewardEvent {
            day_after_genesis: 1,
            actual_timestamp_seconds: 1,
            settled_proposals: vec![],
            distributed_e8s_equivalent: 0,
            total_available_e8s_equivalent: 0,
            rounds_since_last_distribution: Some(1),
            latest_round_available_e8s_equivalent: Some(0),
        }),

        ..Default::default()
    };
    let mut governance = Governance::new(
        governance_init,
        helper.get_fake_env(),
        helper.get_fake_ledger(),
        helper.get_fake_cmc(),
        helper.get_fake_randomness_generator(),
    );
    governance.heap_data.proposals = proposal_data_list
        .iter()
        .map(|p| (p.id.unwrap().id, p.clone()))
        .collect();

    set_governance_for_tests(governance);
    let governance = governance_mut();
    schedule_tasks();
    // Prevent gc.
    governance.latest_gc_timestamp_seconds = now;

    // Step 2: Run code under test.
    governance.run_periodic_tasks().await;
    run_pending_timers_every_interval_for_count(std::time::Duration::from_secs(2), 200);

    // Step 3: Inspect results.

    // Step 3.1: Inspect neurons to make sure they have been rewarded for voting.
    governance.neuron_store.with_active_neurons_iter(|iter| {
        for neuron in iter {
            let current_neuron_maturity = neuron.maturity_e8s_equivalent;

            assert_ne!(
                current_neuron_maturity, starting_maturity,
                "neuron: {:#?}",
                neuron,
            );
        }
    });

    // Step 3.2: Inspect the latest_reward_event.
    let reward_event = governance.heap_data.latest_reward_event.as_ref().unwrap();
    assert_eq!(
        reward_event
            .settled_proposals
            .iter()
            .map(|p| p.id)
            .collect::<HashSet<_>>(),
        proposal_data_list
            .iter()
            .map(|p| p.id.as_ref().unwrap().id)
            .collect(),
        "{:#?}",
        reward_event,
    );
    assert_ne!(
        reward_event.distributed_e8s_equivalent, 0,
        "{:#?}",
        reward_event,
    );
}

#[test]
fn test_no_proposal_title_is_invalid() {
    let result = validate_proposal_title(&None);
    assert!(result.is_err());
}

#[test]
fn test_short_proposal_title_is_invalid() {
    let result = validate_proposal_title(&Some("hi".to_string()));
    assert!(result.is_err());
}

#[test]
fn test_long_proposal_title_is_invalid() {
    let long_title = "Z".repeat(300);

    let result = validate_proposal_title(&Some(long_title));
    assert!(result.is_err());
}

#[test]
fn test_accept_reasonable_proposal_title() {
    let result = validate_proposal_title(&Some("When In The Course of Human Events".to_string()));
    assert!(result.is_ok());
}

// More exhaustive testing of the url validation function happens in sns/governance/src/types.rs `test_sns_metadata_validate()`
#[tokio::test]
async fn test_proposal_url_not_on_list_fails() {
    let fake_driver = fake::FakeDriver::default()
        .at(78)
        .with_supply(Tokens::from_e8s(500_000));
    let governance_proto = fixture_two_neurons_second_is_bigger();
    let mut gov = Governance::new(
        governance_proto,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );

    // Submit a proposal with a url not on the whitelist
    gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "proposal 1 (long)".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "a".to_string(),
            })),
            url: "https://foo.com".to_string(),
        },
    )
    .await
    .unwrap_err();

    // Submit a proposal with a URL on the whitelist
    gov.make_proposal(
        &NeuronId { id: 1 },
        // Must match neuron 1's serialized_id.
        &principal(1),
        &Proposal {
            title: Some("A Reasonable Title".to_string()),
            summary: "proposal 1 (long)".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "a".to_string(),
            })),
            url: "https://forum.dfinity.org/anything".to_string(),
        },
    )
    .await
    .unwrap();
}

#[test]
fn test_ready_to_be_settled_proposals_ids() {
    // Step 1: Prepare the world.

    let genesis_timestamp_seconds = 123_456_789;
    let mut fake_driver = fake::FakeDriver::default().at(genesis_timestamp_seconds);

    let end_of_reward_round_1_timestamp_seconds =
        genesis_timestamp_seconds + REWARD_DISTRIBUTION_PERIOD_SECONDS;
    // Enters reward_status == ReadyToSettle just before the end of round 1.
    let proposal_1 = api::ProposalData {
        id: Some(ProposalId { id: 1 }),
        wait_for_quiet_state: Some(api::WaitForQuietState {
            current_deadline_timestamp_seconds: end_of_reward_round_1_timestamp_seconds - 5,
        }),
        ..Default::default()
    };
    // Enters reward_status == ReadyToSettle shortly after end of round 1.
    let proposal_2 = api::ProposalData {
        id: Some(ProposalId { id: 2 }),
        wait_for_quiet_state: Some(api::WaitForQuietState {
            current_deadline_timestamp_seconds: end_of_reward_round_1_timestamp_seconds + 5,
        }),
        ..Default::default()
    };

    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_genesis_timestamp(genesis_timestamp_seconds)
        .with_proposals(vec![proposal_1, proposal_2])
        .build();

    let governance = Governance::new(
        governance_proto,
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );
    let rewardable_proposal_ids = |now_timestamp_seconds| -> Vec<u64> {
        governance
            .ready_to_be_settled_proposal_ids(now_timestamp_seconds)
            .map(|id| id.id)
            .collect::<Vec<u64>>()
    };

    // Step 2 & 3: Run code under test and inspect results.

    // Since no proposal has entered reward_status == ReadyToSettle, we
    // really do not expect to see anything yet.
    assert_eq!(
        rewardable_proposal_ids(fake_driver.now()),
        Vec::<u64>::new()
    );

    fake_driver.advance_time_by(REWARD_DISTRIBUTION_PERIOD_SECONDS - 6);
    // At this point, both proposals are still accepting proposals; therefore,
    // we still see nothing as rewardable.
    assert_eq!(
        rewardable_proposal_ids(fake_driver.now()),
        Vec::<u64>::new()
    );

    fake_driver.advance_time_by(2);
    // We are now at 4 seconds before the end of the first reward round.
    // At this point, proposal 1 is no longer accepting votes.
    assert_eq!(rewardable_proposal_ids(fake_driver.now()), vec![1]);

    fake_driver.advance_time_by(8);
    // We are now 4 seconds after the end of the first reward round, barely into
    // the second round. At the point proposal 2 is almost done accepting votes,
    // but not quite.
    assert_eq!(rewardable_proposal_ids(fake_driver.now()), vec![1]);

    fake_driver.advance_time_by(2);
    // Finally, proposal 2 is done accepting votes, and is therefore ready for
    // rewarding.
    assert_eq!(rewardable_proposal_ids(fake_driver.now()), vec![1, 2]);

    fake_driver.advance_time_by(10);
    // After advancing by more time, the both proposals continue to be waiting
    // for rewards (because in this test, no rewards are given).
    assert_eq!(rewardable_proposal_ids(fake_driver.now()), vec![1, 2]);
}

#[tokio::test]
async fn test_metrics() {
    let now = 100;
    let neurons = btreemap! {
        // Not Dissolving neurons: 100m + 200m.
        1 => api::Neuron {
            id: Some(NeuronId {
                id: 1
            }),
            account: account(1),
            controller: Some(principal(1)),
            cached_neuron_stake_e8s: 100_000_000,
            dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(1)),
            neuron_type: Some(NeuronType::Seed as i32),
            ..Default::default()
        },
        2 => api::Neuron {
            id: Some(NeuronId {
                id: 2
            }),
            account: account(2),
            controller: Some(principal(2)),
            cached_neuron_stake_e8s: 200_000_000,
            dissolve_state: Some(api::neuron::DissolveState::DissolveDelaySeconds(ONE_YEAR_SECONDS)),
            neuron_type: Some(NeuronType::Ect as i32),
            ..Default::default()
        },
        // Dissolving neurons: 300m.
        3 => api::Neuron {
            id: Some(NeuronId {
                id: 3
            }),
            account: account(3),
            controller: Some(principal(3)),
            cached_neuron_stake_e8s: 300_000_000,
            dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(
                now + ONE_YEAR_SECONDS * 3,
            )),
            aging_since_timestamp_seconds: u64::MAX,
            ..Default::default()
        },
        // Dissolved neurons: 400m.
        4 => api::Neuron {
            id: Some(NeuronId {
                id: 4
            }),
            account: account(4),
            controller: Some(principal(4)),
            cached_neuron_stake_e8s: 400_000_000,
            dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(
                0,
            )),
            aging_since_timestamp_seconds: u64::MAX,
            ..Default::default()
        }
    };

    let economics = api::NetworkEconomics {
        neuron_minimum_stake_e8s: 100_000_000,
        ..Default::default()
    };

    let governance_init = api::Governance {
        economics: Some(economics),
        neurons,
        ..Default::default()
    };

    let expected_metrics = GovernanceCachedMetrics {
        timestamp_seconds: 100,
        total_supply_icp: 0,
        dissolving_neurons_count: 1,
        dissolving_neurons_e8s_buckets: hashmap! { 6 => 300000000.0 },
        dissolving_neurons_count_buckets: hashmap! { 6 => 1 },
        not_dissolving_neurons_count: 2,
        not_dissolving_neurons_e8s_buckets: hashmap! {
            2 => 200000000.0,
            0 => 100000000.0
        },
        not_dissolving_neurons_count_buckets: hashmap! {
            0 => 1,
            2 => 1
        },
        dissolved_neurons_count: 1,
        dissolved_neurons_e8s: 400000000,
        garbage_collectable_neurons_count: 0,
        neurons_with_invalid_stake_count: 0,
        total_staked_e8s: 1000000000,
        neurons_with_less_than_6_months_dissolve_delay_count: 2,
        neurons_with_less_than_6_months_dissolve_delay_e8s: 500000000,
        community_fund_total_staked_e8s: 0,
        community_fund_total_maturity_e8s_equivalent: 0,
        neurons_fund_total_active_neurons: 0,
        total_locked_e8s: 600_000_000,
        total_maturity_e8s_equivalent: 0_u64,
        total_staked_maturity_e8s_equivalent: 0_u64,
        dissolving_neurons_staked_maturity_e8s_equivalent_buckets: hashmap! { 6 => 0.0 },
        dissolving_neurons_staked_maturity_e8s_equivalent_sum: 0_u64,
        not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets: hashmap! {
            0 => 0.0,
            2 => 0.0
        },
        not_dissolving_neurons_staked_maturity_e8s_equivalent_sum: 0_u64,
        seed_neuron_count: 1_u64,
        ect_neuron_count: 1_u64,
        total_staked_e8s_seed: 100000000_u64,
        total_staked_e8s_ect: 200000000_u64,
        total_staked_maturity_e8s_equivalent_seed: 0,
        total_staked_maturity_e8s_equivalent_ect: 0,
        dissolving_neurons_e8s_buckets_seed: Default::default(),
        dissolving_neurons_e8s_buckets_ect: Default::default(),
        not_dissolving_neurons_e8s_buckets_seed: hashmap! {0 => 100000000.0},
        not_dissolving_neurons_e8s_buckets_ect: hashmap! {2 => 200000000.0},
        // Garbage values, because this test was written before this feature.
        total_voting_power_non_self_authenticating_controller: Some(0xDEAD),
        total_staked_e8s_non_self_authenticating_controller: Some(0xBEEF),
        spawning_neurons_count: 0,
        non_self_authenticating_controller_neuron_subset_metrics: None,
        public_neuron_subset_metrics: None,
        declining_voting_power_neuron_subset_metrics: None,
        fully_lost_voting_power_neuron_subset_metrics: None,
    };

    let driver = fake::FakeDriver::default().at(60 * 60 * 24 * 30);
    let mut gov = Governance::new(
        governance_init,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    let actual_metrics = gov.compute_cached_metrics(now, Tokens::new(0, 0).unwrap());
    assert_eq!(
        expected_metrics,
        GovernanceCachedMetrics {
            // Garbage values, because this test was written before this feature.
            total_voting_power_non_self_authenticating_controller: Some(0xDEAD),
            total_staked_e8s_non_self_authenticating_controller: Some(0xBEEF),
            non_self_authenticating_controller_neuron_subset_metrics: None,
            public_neuron_subset_metrics: None,
            declining_voting_power_neuron_subset_metrics: None,
            fully_lost_voting_power_neuron_subset_metrics: None,

            ..actual_metrics
        },
        "Cached metrics don't match expected metrics."
    );

    gov.run_periodic_tasks().now_or_never();

    // Check again after periodic task.
    let actual_metrics = gov.compute_cached_metrics(now, Tokens::new(0, 0).unwrap());
    assert_eq!(
        expected_metrics,
        GovernanceCachedMetrics {
            // Garbage values, because this test was written before this feature.
            total_voting_power_non_self_authenticating_controller: Some(0xDEAD),
            total_staked_e8s_non_self_authenticating_controller: Some(0xBEEF),
            non_self_authenticating_controller_neuron_subset_metrics: None,
            public_neuron_subset_metrics: None,
            declining_voting_power_neuron_subset_metrics: None,
            fully_lost_voting_power_neuron_subset_metrics: None,

            ..actual_metrics
        },
        "Invalid metrics after period tasks execution."
    );

    // Check result of query.
    let expected_metrics = GovernanceCachedMetrics {
        timestamp_seconds: 60 * 60 * 24 * 30,
        total_supply_icp: 0,
        dissolving_neurons_count: 1,
        dissolving_neurons_e8s_buckets: hashmap! { 5 => 300000000.0 },
        dissolving_neurons_count_buckets: hashmap! { 5 => 1 },
        not_dissolving_neurons_count: 2,
        not_dissolving_neurons_e8s_buckets: hashmap! {
            2 => 200000000.0,
            0 => 100000000.0
        },
        not_dissolving_neurons_count_buckets: hashmap! {
            0 => 1,
            2 => 1
        },
        dissolved_neurons_count: 1,
        dissolved_neurons_e8s: 400000000,
        garbage_collectable_neurons_count: 0,
        neurons_with_invalid_stake_count: 0,
        total_staked_e8s: 1000000000,
        neurons_with_less_than_6_months_dissolve_delay_count: 2,
        neurons_with_less_than_6_months_dissolve_delay_e8s: 500000000,
        community_fund_total_staked_e8s: 0,
        community_fund_total_maturity_e8s_equivalent: 0,
        neurons_fund_total_active_neurons: 0,
        total_locked_e8s: 600_000_000,
        total_maturity_e8s_equivalent: 0,
        total_staked_maturity_e8s_equivalent: 0_u64,
        dissolving_neurons_staked_maturity_e8s_equivalent_buckets: hashmap! { 5 => 0.0 },
        dissolving_neurons_staked_maturity_e8s_equivalent_sum: 0_u64,
        not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets: hashmap! { 0 => 0.0, 2 => 0.0
        },
        not_dissolving_neurons_staked_maturity_e8s_equivalent_sum: 0_u64,
        seed_neuron_count: 1_u64,
        ect_neuron_count: 1_u64,
        total_staked_e8s_seed: 100000000_u64,
        total_staked_e8s_ect: 200000000_u64,
        total_staked_maturity_e8s_equivalent_seed: 0_u64,
        total_staked_maturity_e8s_equivalent_ect: 0_u64,
        dissolving_neurons_e8s_buckets_seed: Default::default(),
        dissolving_neurons_e8s_buckets_ect: Default::default(),
        not_dissolving_neurons_e8s_buckets_seed: hashmap! { 0 => 100000000.0 },
        not_dissolving_neurons_e8s_buckets_ect: hashmap! { 2 => 200000000.0 },
        spawning_neurons_count: 0,
        // Garbage values, because this test was written before this feature.
        total_voting_power_non_self_authenticating_controller: Some(0xDEAD),
        total_staked_e8s_non_self_authenticating_controller: Some(0xBEEF),
        non_self_authenticating_controller_neuron_subset_metrics: None,
        public_neuron_subset_metrics: None,
        declining_voting_power_neuron_subset_metrics: None,
        fully_lost_voting_power_neuron_subset_metrics: None,
    };
    let metrics = gov.get_metrics().expect("Error while querying metrics.");
    assert_eq!(
        expected_metrics,
        GovernanceCachedMetrics {
            // Garbage values, because this test was written before this feature.
            total_voting_power_non_self_authenticating_controller: Some(0xDEAD),
            total_staked_e8s_non_self_authenticating_controller: Some(0xBEEF),
            non_self_authenticating_controller_neuron_subset_metrics: None,
            public_neuron_subset_metrics: None,
            declining_voting_power_neuron_subset_metrics: None,
            fully_lost_voting_power_neuron_subset_metrics: None,

            ..metrics
        },
        "Queried metrics don't match expected metrics."
    );

    // Ensure that metrics match our set of neurons.
    assert_eq!(
        1000000000, metrics.total_staked_e8s,
        "Invalid total staked e8s"
    );
    assert_eq!(
        400000000, metrics.dissolved_neurons_e8s,
        "Invalid dissolved e8s"
    );
    assert_eq!(
        600000000,
        metrics.total_staked_e8s - metrics.dissolved_neurons_e8s,
        "Invalid locked verification"
    );
}

#[test]
fn swap_start_and_due_timestamps_if_start_time_is_before_swap_approved() {
    let swap_start_time_of_day = GlobalTimeOfDay::from_hh_mm(12, 0).unwrap();
    let duration = Duration {
        seconds: Some(60 * 60 * 24 * 30),
    };

    let day_offset = 10;
    let swap_approved_timestamp_seconds = day_offset * ONE_DAY_SECONDS
        + swap_start_time_of_day.seconds_after_utc_midnight.unwrap()
        - 1;
    let (start, due) = CreateServiceNervousSystem::swap_start_and_due_timestamps(
        swap_start_time_of_day,
        duration,
        swap_approved_timestamp_seconds,
    )
    .unwrap();

    assert_eq!(
        day_offset * ONE_DAY_SECONDS
            + swap_start_time_of_day.seconds_after_utc_midnight.unwrap()
            + ONE_DAY_SECONDS,
        start
    );
    assert_eq!(start + duration.seconds.unwrap(), due)
}

#[test]
fn swap_start_and_due_timestamps_if_start_time_is_after_swap_approved() {
    let swap_start_time_of_day = GlobalTimeOfDay::from_hh_mm(12, 0).unwrap();
    let duration = Duration {
        seconds: Some(60 * 60 * 24 * 30),
    };

    let day_offset = 10;
    let swap_approved_timestamp_seconds = day_offset * ONE_DAY_SECONDS
        + swap_start_time_of_day.seconds_after_utc_midnight.unwrap()
        + 1;
    let (start, due) = CreateServiceNervousSystem::swap_start_and_due_timestamps(
        swap_start_time_of_day,
        duration,
        swap_approved_timestamp_seconds,
    )
    .unwrap();

    assert_eq!(
        day_offset * ONE_DAY_SECONDS
            + swap_start_time_of_day.seconds_after_utc_midnight.unwrap()
            + ONE_DAY_SECONDS
            + ONE_DAY_SECONDS,
        start
    );
    assert_eq!(start + duration.seconds.unwrap(), due)
}

#[test]
fn swap_start_and_due_timestamps_if_start_time_is_when_swap_approved() {
    let swap_start_time_of_day = GlobalTimeOfDay::from_hh_mm(12, 0).unwrap();
    let duration = Duration {
        seconds: Some(60 * 60 * 24 * 30),
    };

    let day_offset = 10;
    let swap_approved_timestamp_seconds =
        day_offset * ONE_DAY_SECONDS + swap_start_time_of_day.seconds_after_utc_midnight.unwrap();
    let (start, due) = CreateServiceNervousSystem::swap_start_and_due_timestamps(
        swap_start_time_of_day,
        duration,
        swap_approved_timestamp_seconds,
    )
    .unwrap();

    assert_eq!(
        day_offset * ONE_DAY_SECONDS
            + swap_start_time_of_day.seconds_after_utc_midnight.unwrap()
            + ONE_DAY_SECONDS
            + ONE_DAY_SECONDS,
        start
    );
    assert_eq!(start + duration.seconds.unwrap(), due)
}

#[test]
fn randomly_pick_swap_start() {
    let fake_driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        Default::default(),
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );

    // Generate "zillions" of outputs, and count their occurrences.
    let mut start_time_to_count = BTreeMap::new();
    const ITERATION_COUNT: u64 = 50;
    for _ in 0..ITERATION_COUNT {
        let GlobalTimeOfDay {
            seconds_after_utc_midnight,
        } = gov.randomly_pick_swap_start();

        *start_time_to_count
            .entry(seconds_after_utc_midnight.unwrap())
            .or_insert(0) += 1;
    }

    // Assert that values are multiples of 15 minutes and within a single 24 hour period.
    for seconds_after_utc_midnight in start_time_to_count.keys() {
        assert_eq!(
            seconds_after_utc_midnight % (15 * 60),
            0,
            "A random start time was not at a 15 minute interval from midnight: {}",
            seconds_after_utc_midnight
        );

        assert!(*seconds_after_utc_midnight < ONE_DAY_SECONDS);
    }
}

#[test]
fn compute_closest_proposal_deadline_timestamp_seconds_no_wfq_fallback() {
    let proposal_timestamp_seconds = 5;
    let proposal_voting_period = 2;

    let proposal_1 = ProposalData {
        proposal_timestamp_seconds,
        // make sure the proposal is open
        decided_timestamp_seconds: 0,
        wait_for_quiet_state: None,
        proposal: Some(Proposal {
            action: Some(Action::CreateServiceNervousSystem(
                CREATE_SERVICE_NERVOUS_SYSTEM.clone(),
            )),
            ..Default::default()
        }),
        ..Default::default()
    };

    let fake_driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        api::Governance {
            short_voting_period_seconds: 1,
            neuron_management_voting_period_seconds: Some(1),
            wait_for_quiet_threshold_seconds: proposal_voting_period,
            ..Default::default()
        },
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );
    gov.heap_data.proposals.insert(1, proposal_1);

    // Check that the closest deadline is the one for the proposal we injected.
    // Since its wait_for_quiet_state is None, the deadline should default to
    // the creation time + the voting period.
    let closest_proposal_deadline_timestamp_seconds =
        gov.compute_closest_proposal_deadline_timestamp_seconds();
    let expected_closest_proposal_deadline_timestamp_seconds =
        proposal_timestamp_seconds + proposal_voting_period;
    assert_eq!(
        closest_proposal_deadline_timestamp_seconds,
        expected_closest_proposal_deadline_timestamp_seconds,
    );
}

#[test]
fn compute_closest_proposal_deadline_timestamp_seconds_incorporates_wfq() {
    let proposal_timestamp_seconds = 5;
    let proposal_voting_period = 2;

    let proposal_1 = ProposalData {
        proposal_timestamp_seconds,
        // make sure the proposal is open
        decided_timestamp_seconds: 0,
        wait_for_quiet_state: Some(WaitForQuietState {
            current_deadline_timestamp_seconds: proposal_timestamp_seconds
                + proposal_voting_period
                + 1,
        }),
        proposal: Some(Proposal {
            action: Some(Action::CreateServiceNervousSystem(
                CREATE_SERVICE_NERVOUS_SYSTEM.clone(),
            )),
            ..Default::default()
        }),
        ..Default::default()
    };

    let fake_driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        api::Governance {
            short_voting_period_seconds: 1,
            neuron_management_voting_period_seconds: Some(1),
            wait_for_quiet_threshold_seconds: proposal_voting_period,
            ..Default::default()
        },
        fake_driver.get_fake_env(),
        fake_driver.get_fake_ledger(),
        fake_driver.get_fake_cmc(),
        fake_driver.get_fake_randomness_generator(),
    );
    gov.heap_data.proposals.insert(1, proposal_1);

    // Check that the closest deadline is the one for the proposal we injected,
    // based on its wait_for_quiet period rather than its default deadline.
    let closest_proposal_deadline_timestamp_seconds =
        gov.compute_closest_proposal_deadline_timestamp_seconds();
    let expected_closest_proposal_deadline_timestamp_seconds =
        proposal_timestamp_seconds + proposal_voting_period + 1;
    assert_eq!(
        closest_proposal_deadline_timestamp_seconds,
        expected_closest_proposal_deadline_timestamp_seconds,
    );
}

#[test]
fn voting_period_seconds_topic_dependency() {
    let governance_proto = GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_short_voting_period(1)
        .with_neuron_management_voting_period(2)
        .with_wait_for_quiet_threshold(3)
        .build();

    let driver = fake::FakeDriver::default(); // Initialize the minting account
    let gov = Governance::new(
        governance_proto,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    let voting_period_fun = gov.voting_period_seconds();

    assert_eq!(voting_period_fun(Topic::ExchangeRate), 1);

    assert_eq!(voting_period_fun(Topic::NeuronManagement), 2);

    assert_eq!(voting_period_fun(Topic::Governance), 3); // any other topic should be 3
    assert_eq!(voting_period_fun(Topic::ApplicationCanisterManagement), 3);
}

/// Our cast of characters in this scenario consists of a bunch of neurons, each
/// representing a different visibility case:
///
///     * None, but not a known neuron: These neurons have not explicitly
///       selected a visibility. These are treated the same as Private.
///
///     * (Explicitly) Private: Before private neuron enforcement is enabled,
///       these neurons behave as before: NeuronInfo is not redacted.
///
///     * Public: These are never redacted.
///
///     * Known: These are treated the same as Public. However, the Protocol
///       Buffers visibility field would often have no value.
///
/// When private neurons are enforced, this means that a couple of fields in
/// NeuronInfo are redacted when being read by some "random" principal.
///
/// Otherwise (i.e. private neurons are not enforced, or the neuron is public
/// (or both)), NeuronInfo is not redacted
///
/// Fine print:
///
///     1. By random principal, we mean not the controller, nor a hot key.
///
///     2. The specific affected fields are recent_ballots and
///        joined_community_fund_timestamp_seconds.
#[test]
fn test_neuron_info_private_enforcement() {
    // Step 1: Prepare the world.

    let mut random = rand::rngs::StdRng::seed_from_u64(/* seed = */ 42);

    // Step 1.1: Select values that all neurons will share.

    let controller = PrincipalId::new_user_test_id(random.r#gen());
    let hot_key = PrincipalId::new_user_test_id(random.r#gen());

    let proposal_id = random.r#gen();
    let recent_ballots = vec![api::BallotInfo {
        proposal_id: Some(ProposalId { id: proposal_id }),
        vote: Vote::Yes as i32,
    }];

    let joined_community_fund_timestamp_seconds = Some(random.r#gen());

    // Step 1.2: Assemble the common neuron values.
    let base_neuron = {
        let controller = Some(controller);
        let hot_keys = vec![hot_key];
        let recent_ballots = recent_ballots.clone();

        let dissolve_state = Some(api::neuron::DissolveState::DissolveDelaySeconds(
            random.r#gen(),
        ));
        let cached_neuron_stake_e8s = random.r#gen();

        api::Neuron {
            controller,
            hot_keys,
            recent_ballots,
            joined_community_fund_timestamp_seconds,

            // Not used. For validity and realism.
            dissolve_state,
            cached_neuron_stake_e8s,

            ..Default::default()
        }
    };

    // Step 1.3: Construct all neurons.
    let mut new_neuron = || {
        let id = Some(NeuronId { id: random.r#gen() });
        let account = (0..32).map(|_| random.r#gen()).collect();

        api::Neuron {
            id,
            account,
            ..base_neuron.clone()
        }
    };
    let no_explicit_visibility_neuron = new_neuron();
    let private_neuron = api::Neuron {
        visibility: Some(Visibility::Private as i32),
        ..new_neuron()
    };
    let public_neuron = api::Neuron {
        visibility: Some(Visibility::Public as i32),
        ..new_neuron()
    };
    let known_neuron = api::Neuron {
        known_neuron_data: Some(api::KnownNeuronData {
            name: "Hello, world!".to_string(),
            description: Some("All the best votes.".to_string()),
            links: Some(vec![]),
            committed_topics: Some(vec![]),
        }),
        ..new_neuron()
    };

    // Step 1.4: Assumble the neurons into a Governance, the root test datum.
    let governance_proto = GovernanceProtoBuilder::new()
        .with_neurons(vec![
            no_explicit_visibility_neuron.clone(),
            private_neuron.clone(),
            public_neuron.clone(),
            known_neuron.clone(),
        ])
        .build();
    let driver = fake::FakeDriver::default();
    let governance = Governance::new(
        governance_proto,
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    let main = |neuron_id_to_expect_redact: Vec<(NeuronId, bool)>| {
        for (neuron_id, expect_redact) in neuron_id_to_expect_redact {
            // Step 2: Call the code under test.

            let random_principal_id = PrincipalId::new_user_test_id(617_157_922);

            // Step 2.1: Call get_neuron_info.
            let get_neuron_info =
                |requester| governance.get_neuron_info(&neuron_id, requester).unwrap();
            let controller_get_result = get_neuron_info(controller);
            let hot_key_get_result = get_neuron_info(hot_key);
            let random_principal_get_result = get_neuron_info(random_principal_id);

            // Step 2.2: Call list_neurons.
            let list_neurons = |requester| {
                governance.list_neurons(
                    &ListNeurons {
                        neuron_ids: vec![neuron_id.id],
                        include_neurons_readable_by_caller: false,
                        include_empty_neurons_readable_by_caller: None,
                        include_public_neurons_in_full_neurons: None,
                        page_number: None,
                        page_size: None,
                        neuron_subaccounts: None,
                    },
                    requester,
                )
            };
            let controller_list_result = list_neurons(controller);
            let hot_key_list_result = list_neurons(hot_key);
            let random_principal_list_result = list_neurons(random_principal_id);

            // Step 3: Inspect results.

            // Step 3.1: Inspect get_neuron_info results.

            // Step 3.1.1: NF status and recent ballots are not redacted when controller calls.
            assert_eq!(
                controller_get_result.joined_community_fund_timestamp_seconds,
                joined_community_fund_timestamp_seconds,
                "{:#?}",
                controller_get_result,
            );
            assert_eq!(
                controller_get_result.recent_ballots, recent_ballots,
                "{:#?}",
                controller_get_result,
            );

            // Step 3.1.2: Ditto for hot_key.
            assert_eq!(hot_key_get_result, controller_get_result);

            // Step 3.1.3: When random principal calls, ballots and NF status
            // are redacted, unless private neurons are not enforced, or the
            // neuron is public (either explicitly, or as a known neuron).
            if expect_redact {
                assert_eq!(
                    random_principal_get_result.joined_community_fund_timestamp_seconds, None,
                    "{:#?}",
                    random_principal_get_result,
                );
                assert_eq!(
                    random_principal_get_result.recent_ballots,
                    vec![],
                    "{:#?}",
                    random_principal_get_result,
                );
            } else {
                assert_eq!(random_principal_get_result, controller_get_result)
            }

            // Step 3.2: list_neurons results are supposed to be consistent with get_neuron_info
            // except for known neuron data as it's too much data to include in the list_neurons response.
            assert_eq!(
                controller_list_result.neuron_infos,
                hashmap! {
                    neuron_id.id => NeuronInfo {
                        known_neuron_data: None,
                        ..controller_get_result
                    },
                },
                "{:#?}",
                controller_list_result,
            );
            assert_eq!(
                hot_key_list_result.neuron_infos,
                hashmap! {
                    neuron_id.id => NeuronInfo {
                        known_neuron_data: None,
                        ..hot_key_get_result
                    },
                },
                "{:#?}",
                hot_key_list_result,
            );
            assert_eq!(
                random_principal_list_result.neuron_infos,
                hashmap! {
                    neuron_id.id => NeuronInfo {
                        known_neuron_data: None,
                        ..random_principal_get_result
                    },
                },
                "{:#?}",
                random_principal_list_result,
            );
        }
    };

    let neuron_id_to_expect_redact = vec![
        (no_explicit_visibility_neuron.id.unwrap(), true),
        (private_neuron.id.unwrap(), true),
        // Unlike the previous two lines, expect_redact is false here,
        // because these neurons are public (either explicitly, or by being
        // a known neuron).
        (public_neuron.id.unwrap(), false),
        (known_neuron.id.unwrap(), false),
    ];
    main(neuron_id_to_expect_redact);

    for (neuron_id, expected_visibility) in [
        (
            no_explicit_visibility_neuron.id.unwrap(),
            Visibility::Private,
        ),
        (private_neuron.id.unwrap(), Visibility::Private),
        (public_neuron.id.unwrap(), Visibility::Public),
        (known_neuron.id.unwrap(), Visibility::Public),
    ] {
        let neuron_info = governance.get_neuron_info(&neuron_id, controller).unwrap();
        assert_eq!(
            neuron_info.visibility,
            Some(expected_visibility as i32),
            "{:?}",
            neuron_info,
        );
    }
}

/// Fixture for testing private neuron follow restrictions.
/// This fixture creates 4 neurons. Neurons 1 and 2 share a controller (principal 100).
/// Neuron 3 has a different controller (principal 200).
/// Neuron 4, with ID 1000, is the manager of all.
fn fixture_for_follow_private_neuron_restrictions() -> api::Governance {
    let mut driver = fake::FakeDriver::default();
    let followee = hashmap! {
    Topic::NeuronManagement as i32 => api::neuron::Followees {
            followees: vec![NeuronId { id: MANAGER_ID }]
        },
    };
    // A 'default' neuron, extended with additional fields below.
    let mut neuron = move |id, controller, visibility| api::Neuron {
        id: Some(NeuronId { id }),
        controller,
        cached_neuron_stake_e8s: 10 * E8, // 10 ICP
        account: driver
            .random_byte_array()
            .expect("Could not get random byte array")
            .to_vec(),
        dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
        aging_since_timestamp_seconds: u64::MAX,
        visibility,
        followees: followee.clone(),
        ..Default::default()
    };

    let neurons = vec![
        neuron(
            1,
            Some(principal(NEURON_1_CONTROLLER)),
            Some(Visibility::Private as i32),
        ),
        neuron(
            2,
            Some(principal(NEURON_2_CONTROLLER)),
            Some(Visibility::Private as i32),
        ),
        neuron(
            3,
            Some(principal(NEURON_3_CONTROLLER)),
            Some(Visibility::Private as i32),
        ),
        neuron(
            MANAGER_ID,
            Some(principal(MANAGER_ID)),
            Some(Visibility::Public as i32),
        ),
    ];

    GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(api::NetworkEconomics::with_default_values())
        .with_neurons(neurons)
        .with_short_voting_period(1)
        .with_neuron_management_voting_period(1)
        .with_wait_for_quiet_threshold(10)
        .build()
}

// Tests that a neuron can follow another private neuron if they have the same controller.
#[tokio::test]
async fn test_follow_private_neuron_same_controller() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_follow_private_neuron_restrictions(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Make a proposal to have neuron 2 follow neuron 1.
    gov.make_proposal(
        &NeuronId { id: MANAGER_ID },
        &principal(MANAGER_ID),
        &Proposal {
            title: Some("N2 follow N1".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 2 })),
                id: None,
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::ParticipantManagement as i32,
                    followees: [NeuronId { id: 1 }].to_vec(),
                })),
            }))),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        ProposalStatus::Executed,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );

    assert!(
        gov.get_full_neuron(&NeuronId { id: 2 }, &principal(NEURON_2_CONTROLLER))
            .unwrap()
            .followees
            .get(&(Topic::ParticipantManagement as i32))
            .unwrap()
            .followees
            .contains(&NeuronId { id: 1 })
    );
}

// Tests that a neuron cannot follow another private neuron if
// neither its controller is a hot key of the followed neuron nor they
// have the same controller.
#[tokio::test]
async fn test_follow_private_neuron_fails() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_follow_private_neuron_restrictions(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Make a proposal to have neuron 3 follow neuron 1.
    // This proposal should fail because neuron 3 has neither the same
    // controller as neuron 1 nor is its controller a hot key of neuron 1.
    gov.make_proposal(
        &NeuronId { id: MANAGER_ID },
        &principal(MANAGER_ID),
        &Proposal {
            title: Some("N3 follow N1".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 3 })),
                id: None,
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::Kyc as i32,
                    followees: [NeuronId { id: 1 }].to_vec(),
                })),
            }))),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        ProposalStatus::Failed,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );

    assert!(
        !gov.get_full_neuron(&NeuronId { id: 3 }, &principal(NEURON_3_CONTROLLER))
            .unwrap()
            .followees
            .contains_key(&(Topic::Kyc as i32))
    );
}

// Tests that a neuron can follow another private neuron if
// its controller is a hot key of the followed neuron.
#[tokio::test]
async fn test_follow_private_neuron_hotkeys() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_follow_private_neuron_restrictions(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Set a shared hotkey for neurons 1 and 3.
    let result = gov
        .manage_neuron(
            &principal(NEURON_1_CONTROLLER),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 1 })),
                command: Some(manage_neuron::Command::Configure(
                    manage_neuron::Configure {
                        operation: Some(manage_neuron::configure::Operation::AddHotKey(
                            manage_neuron::AddHotKey {
                                new_hot_key: Some(principal(NEURON_3_CONTROLLER)),
                            },
                        )),
                    },
                )),
            },
        )
        .now_or_never()
        .unwrap();

    assert!(result.is_ok());
    // Make a proposal to have neuron 3 follow neuron 1.
    gov.make_proposal(
        &NeuronId { id: MANAGER_ID },
        &principal(MANAGER_ID),
        &Proposal {
            title: Some("N3 follow N1".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 3 })),
                id: None,
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::NetworkEconomics as i32,
                    followees: [NeuronId { id: 1 }].to_vec(),
                })),
            }))),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        ProposalStatus::Executed,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );

    assert!(
        gov.get_full_neuron(&NeuronId { id: 3 }, &principal(NEURON_3_CONTROLLER))
            .unwrap()
            .followees
            .get(&(Topic::NetworkEconomics as i32))
            .unwrap()
            .followees
            .contains(&NeuronId { id: 1 })
    );
}

// Tests that a public neuron can always be followed.
#[tokio::test]
async fn test_follow_public_neuron_succeeds() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_follow_private_neuron_restrictions(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Make neuron 1 public.
    let result = gov
        .manage_neuron(
            &principal(NEURON_1_CONTROLLER),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 1 })),
                command: Some(manage_neuron::Command::Configure(
                    manage_neuron::Configure {
                        operation: Some(manage_neuron::configure::Operation::SetVisibility(
                            manage_neuron::SetVisibility {
                                visibility: Some(Visibility::Public as i32),
                            },
                        )),
                    },
                )),
            },
        )
        .now_or_never()
        .unwrap();

    assert!(result.is_ok());

    // Make a proposal to have neuron 3 follow neuron 1.
    gov.make_proposal(
        &NeuronId { id: MANAGER_ID },
        &principal(MANAGER_ID),
        &Proposal {
            title: Some("N3 follow N1".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 3 })),
                id: None,
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::SubnetRental as i32,
                    followees: [NeuronId { id: 1 }].to_vec(),
                })),
            }))),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        ProposalStatus::Executed,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );

    assert!(
        gov.get_full_neuron(&NeuronId { id: 3 }, &principal(NEURON_3_CONTROLLER))
            .unwrap()
            .followees
            .get(&(Topic::SubnetRental as i32))
            .unwrap()
            .followees
            .contains(&NeuronId { id: 1 })
    );
}

// Test that a pirvate neuron can be followed on the
// NeuronManagement topic.
#[tokio::test]
async fn test_follow_private_neuron_neuron_management() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_follow_private_neuron_restrictions(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Make a proposal to have neuron 3 follow neuron 1.
    gov.make_proposal(
        &NeuronId { id: MANAGER_ID },
        &principal(MANAGER_ID),
        &Proposal {
            title: Some("N3 follow N1".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 3 })),
                id: None,
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::NeuronManagement as i32,
                    followees: [NeuronId { id: 1 }].to_vec(),
                })),
            }))),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        ProposalStatus::Executed,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );

    assert!(
        gov.get_full_neuron(&NeuronId { id: 3 }, &principal(NEURON_3_CONTROLLER))
            .unwrap()
            .followees
            .get(&(Topic::NeuronManagement as i32))
            .unwrap()
            .followees
            .contains(&NeuronId { id: 1 })
    );
}

/// Fixture for testing grandfathering behavior.
/// It creates 2 neurons. Neuron 2 follows neuron 1, which according
/// to the restrictions should not be allowed. However, since
/// neuron 2 is grandfathered, it should be allowed.
fn fixture_for_grandfathering() -> api::Governance {
    let mut driver = fake::FakeDriver::default();
    let followee = hashmap! {
    Topic::NeuronManagement as i32 => api::neuron::Followees {
            followees: vec![NeuronId { id: MANAGER_ID }]
        },
    };
    // A 'default' neuron, extended with additional fields below.
    let mut neuron = move |id, controller, visibility| api::Neuron {
        id: Some(NeuronId { id }),
        controller,
        cached_neuron_stake_e8s: 10 * E8, // 10 ICP
        account: driver
            .random_byte_array()
            .expect("Could not get random byte array")
            .to_vec(),
        dissolve_state: Some(api::neuron::DissolveState::WhenDissolvedTimestampSeconds(0)),
        aging_since_timestamp_seconds: u64::MAX,
        visibility,
        followees: followee.clone(),
        ..Default::default()
    };

    let neurons = vec![
        api::Neuron {
            followees: hashmap! {
            Topic::NeuronManagement as i32 => api::neuron::Followees {
                    followees: vec![NeuronId { id: MANAGER_ID }]
                },
            },
            ..neuron(
                1,
                Some(principal(NEURON_1_CONTROLLER)),
                Some(Visibility::Private as i32),
            )
        },
        api::Neuron {
            followees: hashmap! {
                Topic::NeuronManagement as i32 => api::neuron::Followees {
                        followees: vec![NeuronId { id: MANAGER_ID }]
                },
                // By default, neuron 2 cannot follow neuron 1 on Topic::Governance
                // since they have different controllers and neuron 1 is private.
                Topic::Governance as i32 => api::neuron::Followees {
                        followees: vec![NeuronId { id: 1 }]
                },
            },
            ..neuron(
                2,
                Some(principal(NEURON_3_CONTROLLER)),
                Some(Visibility::Private as i32),
            )
        },
        neuron(
            MANAGER_ID,
            Some(principal(MANAGER_ID)),
            Some(Visibility::Public as i32),
        ),
    ];

    GovernanceProtoBuilder::new()
        .with_instant_neuron_operations()
        .with_economics(api::NetworkEconomics::with_default_values())
        .with_neurons(neurons)
        .with_short_voting_period(1)
        .with_neuron_management_voting_period(1)
        .with_wait_for_quiet_threshold(10)
        .build()
}

#[tokio::test]
async fn test_grandfathering() {
    let driver = fake::FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_grandfathering(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
        driver.get_fake_cmc(),
        driver.get_fake_randomness_generator(),
    );

    // Make a proposal to have neuron 2 follow neuron 1.
    gov.make_proposal(
        &NeuronId { id: MANAGER_ID },
        &principal(MANAGER_ID),
        &Proposal {
            title: Some("N2 follow N1".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 2 })),
                id: None,
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::ExchangeRate as i32,
                    followees: [NeuronId { id: 1 }].to_vec(),
                })),
            }))),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        ProposalStatus::Failed,
        gov.get_proposal_data(ProposalId { id: 1 })
            .unwrap()
            .status()
    );

    // Set a shared hotkey for neurons 1 and 2.
    let result = gov
        .manage_neuron(
            &principal(NEURON_1_CONTROLLER),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 1 })),
                command: Some(manage_neuron::Command::Configure(
                    manage_neuron::Configure {
                        operation: Some(manage_neuron::configure::Operation::AddHotKey(
                            manage_neuron::AddHotKey {
                                new_hot_key: Some(principal(NEURON_3_CONTROLLER)),
                            },
                        )),
                    },
                )),
            },
        )
        .now_or_never()
        .unwrap();

    assert!(result.is_ok());

    // Make a proposal to have neuron 2 follow neuron 1.
    gov.make_proposal(
        &NeuronId { id: MANAGER_ID },
        &principal(MANAGER_ID),
        &Proposal {
            title: Some("N2 follow N1".to_string()),
            action: Some(proposal::Action::ManageNeuron(Box::new(ManageNeuron {
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId { id: 2 })),
                id: None,
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::ExchangeRate as i32,
                    followees: [NeuronId { id: 1 }].to_vec(),
                })),
            }))),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(
        ProposalStatus::Executed,
        gov.get_proposal_data(ProposalId { id: 2 })
            .unwrap()
            .status()
    );

    assert!(
        gov.get_full_neuron(&NeuronId { id: 2 }, &principal(NEURON_3_CONTROLLER))
            .unwrap()
            .followees
            .get(&(Topic::ExchangeRate as i32))
            .unwrap()
            .followees
            .contains(&NeuronId { id: 1 })
    );
}
