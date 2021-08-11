//! The unit tests for `Governance` use *test fixtures*. The fixtures
//! are defi data_source: (), timestamp_seconds: ()ned as small but
//! complex/weird configurations of neurons and proposals against which several
//! tests are run.

use assert_matches::assert_matches;
use async_trait::async_trait;
use candid::Encode;
use futures::future::FutureExt;
use ic_base_types::PrincipalId;
use ic_crypto_sha256::Sha256;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::ids::{TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::{
    governance::{
        Environment, Governance, Ledger, EXECUTE_NNS_FUNCTION_PAYLOAD_LISTING_BYTES_MAX,
        MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS, PROPOSAL_MOTION_TEXT_BYTES_MAX,
        REWARD_DISTRIBUTION_PERIOD_SECONDS,
    },
    init::GovernanceCanisterInitPayloadBuilder,
    pb::v1::{
        add_or_remove_node_provider::Change,
        claim_or_refresh_neuron_from_account_response::Result as ClaimOrRefreshResult,
        governance_error::ErrorType,
        governance_error::ErrorType::InsufficientFunds,
        governance_error::ErrorType::NotAuthorized,
        governance_error::ErrorType::PreconditionFailed,
        manage_neuron,
        manage_neuron::claim_or_refresh::By,
        manage_neuron::configure::Operation,
        manage_neuron::disburse::Amount,
        manage_neuron::ClaimOrRefresh,
        manage_neuron::Command,
        manage_neuron::Configure,
        manage_neuron::Disburse,
        manage_neuron::DisburseToNeuron,
        manage_neuron::IncreaseDissolveDelay,
        manage_neuron::NeuronIdOrSubaccount,
        manage_neuron::SetDissolveTimestamp,
        manage_neuron::Spawn,
        manage_neuron::Split,
        manage_neuron::StartDissolving,
        manage_neuron_response, neuron,
        neuron::DissolveState,
        neuron::Followees,
        proposal,
        reward_node_provider::{RewardMode, RewardToAccount, RewardToNeuron},
        AddOrRemoveNodeProvider, Ballot, BallotInfo, ClaimOrRefreshNeuronFromAccount,
        ExecuteNnsFunction, Governance as GovernanceProto, GovernanceError, ListNeurons,
        ListNeuronsResponse, ListProposalInfo, ManageNeuron, Motion, NetworkEconomics, Neuron,
        NeuronStakeTransfer, NeuronState, NnsFunction, NodeProvider, Proposal, ProposalData,
        ProposalStatus, RewardEvent, RewardNodeProvider, SetDefaultFollowees, Tally, Topic, Vote,
    },
};
use ledger_canister::{AccountIdentifier, ICPTs, Memo};
use maplit::hashmap;
use rand::rngs::StdRng;
use rand_core::{RngCore, SeedableRng};
use registry_canister::mutations::{
    do_add_node_operator::AddNodeOperatorPayload,
    do_update_icp_xdr_conversion_rate::UpdateIcpXdrConversionRatePayload,
};
use std::collections::hash_map::Entry;
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::iter;
use std::iter::once;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

use ic_nns_governance::governance::{
    HeapGrowthPotential, MAX_DISSOLVE_DELAY_SECONDS, MAX_NEURON_AGE_FOR_AGE_BONUS,
    MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS,
};
use ic_nns_governance::pb::v1::governance_error::ErrorType::{NotFound, ResourceExhausted};
use ic_nns_governance::pb::v1::manage_neuron::MergeMaturity;
use ic_nns_governance::pb::v1::manage_neuron_response::MergeMaturityResponse;
use ic_nns_governance::pb::v1::proposal::Action;
use ic_nns_governance::pb::v1::ProposalRewardStatus::{AcceptVotes, ReadyToSettle};
use ic_nns_governance::pb::v1::ProposalStatus::Rejected;
use ic_nns_governance::pb::v1::{ManageNeuronResponse, ProposalRewardStatus, RewardNodeProviders};
use ledger_canister::Subaccount;

const DEFAULT_TEST_START_TIMESTAMP_SECONDS: u64 = 999_111_000_u64;

#[derive(Clone, Debug)]
struct FakeAccount {
    id: AccountIdentifier,
    amount_e8s: u64,
}

type LedgerMap = HashMap<AccountIdentifier, u64>;

/// The state required for fake implementations of `Environment` and
/// `Ledger`.
struct FakeState {
    pub now: u64,
    pub rng: StdRng,
    pub accounts: LedgerMap,
}

impl Default for FakeState {
    fn default() -> Self {
        Self {
            // It's a good idea to use a non-zero default timestamp
            // because: (1) time 0 is a reserved value; timestamps are
            // stored as primitive integers in the governance proto,
            // so there is no distinction between "zero" and "unset";
            // (2) it makes it easy to create neurons that have a
            // non-zero age.
            //
            // In addition, we use an easily-recognizable timestamp.
            now: DEFAULT_TEST_START_TIMESTAMP_SECONDS,
            // Seed the random number generator with a constant seed
            // to make the tests deterministic. Make sure this seed is
            // different from other seeds so test data generated from
            // different places doesn't conflict.
            rng: StdRng::seed_from_u64(9539),
            accounts: HashMap::new(),
        }
    }
}

/// A struct that produces a fake enviroment where time can be
/// advanced, and ledger accounts manipulated.
struct FakeDriver {
    state: Arc<Mutex<FakeState>>,
}

/// Create a default mock driver.
impl Default for FakeDriver {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(Default::default())),
        }
    }
}

impl FakeDriver {
    pub fn minting_account() -> AccountIdentifier {
        AccountIdentifier::new(
            ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
            None,
        )
    }

    /// Constructs a mock driver that starts at the given timestamp.
    pub fn at(self, timestamp: u64) -> FakeDriver {
        self.state.lock().unwrap().now = timestamp;
        self
    }

    pub fn with_ledger_accounts(self, accounts: Vec<FakeAccount>) -> FakeDriver {
        let mut ledger_map = LedgerMap::default();
        // Add the account for the minting canister.
        ledger_map.insert(FakeDriver::minting_account(), 0);
        for FakeAccount { id, amount_e8s } in accounts {
            ledger_map.insert(id, amount_e8s);
        }
        self.state.lock().unwrap().accounts = ledger_map;
        self
    }

    pub fn with_ledger_from_neurons(self, neurons: &[Neuron]) -> FakeDriver {
        let accounts: Vec<FakeAccount> = neurons
            .iter()
            .map(|n| FakeAccount {
                id: AccountIdentifier::new(
                    GOVERNANCE_CANISTER_ID.get(),
                    Some(Subaccount(n.account.as_slice().try_into().unwrap())),
                ),
                amount_e8s: n.cached_neuron_stake_e8s,
            })
            .collect();
        self.with_ledger_accounts(accounts)
    }

    pub fn with_supply(self, supply: ICPTs) -> FakeDriver {
        {
            let old_supply = self.get_supply();
            let accounts = &mut self.state.lock().unwrap().accounts;
            let minting = accounts.entry(FakeDriver::minting_account()).or_default();
            assert!(old_supply >= ICPTs::from_e8s(*minting));
            let old_in_use = (old_supply - ICPTs::from_e8s(*minting)).unwrap();
            assert!(supply >= old_in_use);
            *minting = (supply - old_in_use).unwrap().get_e8s();
        }
        self
    }

    pub fn get_supply(&self) -> ICPTs {
        ICPTs::from_e8s(
            self.state
                .lock()
                .unwrap()
                .accounts
                .iter()
                .map(|(_, y)| y)
                .sum(),
        )
    }

    /// Increases the time by the given amount.
    pub fn advance_time_by(&mut self, delta_seconds: u64) {
        self.state.lock().unwrap().now += delta_seconds;
    }

    /// Contructs an `Environment` that interacts with this driver.
    pub fn get_fake_env(&self) -> Box<dyn Environment> {
        Box::new(FakeDriver {
            state: Arc::clone(&self.state),
        })
    }

    /// Contructs a `Ledger` that interacts with this driver.
    pub fn get_fake_ledger(&self) -> Box<dyn Ledger> {
        Box::new(FakeDriver {
            state: Arc::clone(&self.state),
        })
    }

    /// Reads the time.
    fn now(&self) -> u64 {
        self.state.lock().unwrap().now
    }

    fn create_account_with_funds(&mut self, to: AccountIdentifier, amount_e8s: u64) {
        let accounts = &mut self.state.try_lock().unwrap().accounts;
        match accounts.entry(to) {
            Entry::Occupied(_) => panic!("Account exists"),
            Entry::Vacant(v) => {
                v.insert(amount_e8s);
            }
        }
    }

    fn assert_account_contains(&self, account: &AccountIdentifier, amount_e8s: u64) {
        assert_eq!(
            *self
                .state
                .try_lock()
                .unwrap()
                .accounts
                .get(account)
                .expect("Account doesn't exist."),
            amount_e8s
        );
    }

    fn assert_num_neuron_accounts_exist(&self, num_accounts: usize) {
        assert_eq!(
            self.state.lock().unwrap().accounts.len() - 1, // Deduct the default ledger account.
            num_accounts
        );
    }
}

#[async_trait]
impl Ledger for FakeDriver {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to_account: AccountIdentifier,
        _: u64,
    ) -> Result<u64, GovernanceError> {
        let from_account = AccountIdentifier::new(
            ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
            from_subaccount,
        );
        println!(
            "Issuing ledger transfer from account {} (subaccount {}) to account {} amount {} fee {}",
            from_account, from_subaccount.as_ref().map_or_else(||"None".to_string(), ToString::to_string), to_account, amount_e8s, fee_e8s
        );
        let accounts = &mut self.state.try_lock().unwrap().accounts;

        let from_e8s = accounts.get_mut(&from_account).ok_or_else(|| {
            GovernanceError::new_with_message(ErrorType::External, "Source account doesn't exist")
        })?;

        let requested_e8s = amount_e8s + fee_e8s;

        if *from_e8s < requested_e8s {
            return Err(GovernanceError::new_with_message(
                ErrorType::InsufficientFunds,
                format!("available {} requested {}", *from_e8s, requested_e8s),
            ));
        }

        *from_e8s -= requested_e8s;

        *accounts.entry(to_account).or_default() += amount_e8s - fee_e8s;

        Ok(0)
    }

    async fn total_supply(&self) -> Result<ICPTs, GovernanceError> {
        Ok(self.get_supply())
    }

    async fn account_balance(&self, account: AccountIdentifier) -> Result<ICPTs, GovernanceError> {
        let accounts = &mut self.state.try_lock().unwrap().accounts;
        let account_e8s = accounts.get(&account).unwrap_or(&0);
        Ok(ICPTs::from_e8s(*account_e8s))
    }
}

impl Environment for FakeDriver {
    fn now(&self) -> u64 {
        self.state.try_lock().unwrap().now
    }

    fn random_u64(&mut self) -> u64 {
        self.state.try_lock().unwrap().rng.next_u64()
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.state.try_lock().unwrap().rng.fill_bytes(&mut bytes);
        //println!("random bytes {:?}\n", bytes);
        bytes
    }

    fn execute_nns_function(
        &self,
        _proposal_id: u64,
        _update: &ExecuteNnsFunction,
    ) -> Result<(), GovernanceError> {
        panic!("unexpected call")
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        HeapGrowthPotential::NoIssue
    }
}

/// Constructs a test principal id from an integer.
/// Convenience functions to make creating neurons more concise.
fn principal(i: u64) -> PrincipalId {
    PrincipalId::try_from(format!("SID{}", i).as_bytes().to_vec()).unwrap()
}

/// Issues a manage_neuron command to register a vote
fn register_vote(
    governance: &mut Governance,
    caller: PrincipalId,
    neuron_id: NeuronId,
    pid: ProposalId,
    vote: Vote,
) -> ManageNeuronResponse {
    let manage_neuron = ManageNeuron {
        id: None,
        neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(neuron_id)),
        command: Some(manage_neuron::Command::RegisterVote(
            manage_neuron::RegisterVote {
                proposal: Some(pid),
                vote: vote as i32,
            },
        )),
    };
    governance
        .manage_neuron(&caller, &manage_neuron)
        .now_or_never()
        .unwrap()
}

/// Issues a manage_neuron command to register a vote, and asserts that it
/// worked.
fn register_vote_assert_success(
    governance: &mut Governance,
    caller: PrincipalId,
    neuron_id: NeuronId,
    pid: ProposalId,
    vote: Vote,
) {
    let result = register_vote(governance, caller, neuron_id, pid, vote);
    assert_eq!(
        result,
        ManageNeuronResponse {
            command: Some(manage_neuron_response::Command::RegisterVote(
                manage_neuron_response::RegisterVoteResponse {}
            ))
        }
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
    behavior: impl Into<ProposalNeuronBehavior>,
    expected_after_voting: ProposalStatus,
    expected_after_expiration: ProposalStatus,
) {
    let expiration_seconds = 17; // Arbitrary duration
    let econ = NetworkEconomics {
        reject_cost_e8s: 0,          // It's the default, but specify for emphasis
        neuron_minimum_stake_e8s: 0, // It's the default, but specify for emphasis
        ..NetworkEconomics::default()
    };
    let mut fake_driver = FakeDriver::default();
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

const NOTDISSOLVING_MIN_DISSOLVE_DELAY_TO_VOTE: Option<DissolveState> = Some(
    DissolveState::DissolveDelaySeconds(MIN_DISSOLVE_DELAY_FOR_VOTE_ELIGIBILITY_SECONDS),
);
const NOTDISSOLVING_MAX_DISSOLVE_DELAY: Option<DissolveState> = Some(
    DissolveState::DissolveDelaySeconds(MAX_DISSOLVE_DELAY_SECONDS),
);

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
                cached_neuron_stake_e8s: 1,
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
                cached_neuron_stake_e8s: 8,
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
                cached_neuron_stake_e8s: 8,
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
                cached_neuron_stake_e8s: 1,
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
                cached_neuron_stake_e8s: 1,
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
        "nP",
        ProposalStatus::Rejected,
        ProposalStatus::Rejected,
    );
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
fn fixture_for_following() -> GovernanceProto {
    let mut driver = FakeDriver::default();
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
                        Topic::Governance as i32,
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
            (7, neuron(7)),
            (8, neuron(8)),
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
/// - As neuron 2 follows neurons 1 and 3 on the Governance topic, 2 should vote
///   yes as 1 votes implicitly by proposing and 3 votes by following 5 and 6.
#[test]
fn test_cascade_following() {
    let driver = FakeDriver::default();
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
            summary: "test".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "dummy text".to_string(),
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
    register_vote_assert_success(
        &mut gov,
        principal(5),
        NeuronId { id: 5 },
        ProposalId { id: 1 },
        Vote::Yes,
    );
    register_vote_assert_success(
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
    let driver = FakeDriver::default();
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
    let driver = FakeDriver::default();
    let mut gov = Governance::new(
        fixture_for_following(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    let node_provider = NodeProvider {
        id: Some(PrincipalId::try_from(b"SID2".to_vec()).unwrap()),
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
    let driver = FakeDriver::default();
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
            summary: "test".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "dummy text".to_string(),
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
    let driver = FakeDriver::default();
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
            summary: "test".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "dummy text".to_string(),
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
    let driver = FakeDriver::default();
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
            summary: "test".to_string(),
            action: Some(proposal::Action::Motion(Motion {
                motion_text: "dummy text".to_string(),
            })),
            ..Default::default()
        },
    )
    .unwrap();
    // No controller for 4 yet.
    let result = register_vote(
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
    register_vote_assert_success(
        &mut gov,
        principal(4),
        NeuronId { id: 4 },
        ProposalId { id: 1 },
        Vote::No,
    );
    register_vote_assert_success(
        &mut gov,
        principal(5),
        NeuronId { id: 5 },
        ProposalId { id: 1 },
        Vote::No,
    );
    register_vote_assert_success(
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
    let mut driver = FakeDriver::default();
    // A 'default' neuron, extended with additional fields below.
    let mut neuron = move |id| Neuron {
        id: Some(NeuronId { id }),
        cached_neuron_stake_e8s: 1_000_000_000, // 10 ICP
        account: driver.random_byte_array().to_vec(),
        ..Default::default()
    };
    GovernanceProto {
        economics: Some(NetworkEconomics::with_default_values()),
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
    let driver = FakeDriver::default();
    let gov = Governance::new(
        fixture_for_manage_neuron(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );
    // Test  that anybody  can call `get_neuron_info`  as long  as the
    // neuron exists.
    assert_eq!(
        1066,
        gov.get_neuron_info(&NeuronId { id: 1 })
            .unwrap()
            .created_timestamp_seconds
    );
    // But not if it doesn't exist.
    assert_eq!(
        ErrorType::NotFound as i32,
        gov.get_neuron_info(&NeuronId { id: 100 })
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
    let driver = FakeDriver::default();
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
    let result = register_vote(
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
    register_vote_assert_success(
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
    let driver = FakeDriver::default();
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
    let mut driver = FakeDriver::default();
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
                    cached_neuron_stake_e8s: 51,
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
    let fake_driver = FakeDriver::default();
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
    let mut fake_driver = FakeDriver::default()
        .at(56)
        // To make assertion easy to sanity-check, the total supply of ICPs is chosen
        // so that the reward supply for the first day is 100 (365_250 * 10% / 365.25 = 100).
        // On next days it will be a bit less, but it is still easy to verify by eye
        // the order of magnitude.
        .with_supply(ICPTs::from_e8s(365_250));
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
    let mut fake_driver = FakeDriver::default()
        .at(3)
        // We need a positive supply to ensure that there can be voting rewards
        .with_supply(ICPTs::from_e8s(1_234_567_890));
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
    let mut fake_driver = FakeDriver::default()
        .at(2500) // Just a little before the proposal happened.
        // To make assertion easy to sanity-check, the total supply of ICPs is chosen
        // so that the reward supply for the first day is 100 (365_250 * 10% / 365.25 = 100).
        .with_supply(ICPTs::from_e8s(365_250));
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
    let mut fake_driver = FakeDriver::default()
        .at(78)
        // To make assertion easy to sanity-check, the total supply of ICPs is chosen
        // so that the reward supply for the first day is 100 (365_250 * 10% / 365.25 = 100).
        .with_supply(ICPTs::from_e8s(365_250));
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

/// A struct to help setting up tests concisely thanks to a concise format to
/// specifies who proposes something and who votes on that proposal.
struct ProposalNeuronBehavior {
    /// Neuron id of the proposer.
    proposer: u64,
    /// Map neuron id of voters to their votes.
    votes: BTreeMap<u64, Vote>,
}

impl ProposalNeuronBehavior {
    /// Creates a proposal from the specified proposer, and register the
    /// specified votes.
    ///
    /// This function assumes that:
    /// - neuron of id `i` has for controller `principal(i)`
    fn propose_and_vote(&self, gov: &mut Governance, summary: String) -> ProposalId {
        // Submit proposal
        let pid = gov
            .make_proposal(
                &NeuronId { id: self.proposer },
                &principal(self.proposer),
                &Proposal {
                    summary,
                    action: Some(proposal::Action::Motion(Motion {
                        motion_text: "me like proposals".to_string(),
                    })),
                    ..Default::default()
                },
            )
            .unwrap();
        // Vote
        for (voter, vote) in &self.votes {
            register_vote_assert_success(
                gov,
                principal(*voter),
                NeuronId { id: *voter },
                pid,
                *vote,
            );
        }
        pid
    }
}

impl From<&str> for ProposalNeuronBehavior {
    /// Format:
    ///
    /// Each character corresponds to the behavior of one neuron, in order.
    ///
    /// "-" means "does not vote"
    /// "y" means "votes yes"
    /// "n" means "votes no"
    /// "P" means "proposes"
    ///
    /// Example:
    /// "--yP-ny" means:
    /// neuron 3 proposes, neurons 2 and 6 votes yes, neuron 5 votes no, neurons
    /// 0, 1, and 4 do not vote.
    fn from(str: &str) -> ProposalNeuronBehavior {
        ProposalNeuronBehavior {
            proposer: str.find('P').unwrap() as u64,
            votes: str
                .chars()
                .map(|c| match c {
                    'y' => Vote::Yes,
                    'n' => Vote::No,
                    _ => Vote::Unspecified,
                })
                .zip(0_u64..)
                .filter(|(vote, _)| *vote != Vote::Unspecified)
                .map(|(vote, id)| (id, vote))
                .collect(),
        }
    }
}

/// Test helper where several proposals are created and voted on by various
/// neurons. The final maturities are returned.
///
/// In this test, all proposals last 1 second, which is smaller than the reward
/// period. This allows to have tests where everything interesting happens in
/// the first reward period.
fn compute_maturities(
    stakes_e8s: Vec<u64>,
    proposals: Vec<impl Into<ProposalNeuronBehavior>>,
) -> Vec<u64> {
    let proposals: Vec<ProposalNeuronBehavior> = proposals.into_iter().map(|x| x.into()).collect();

    let mut fake_driver = FakeDriver::default()
        // To make assertion easy to sanity-check, the total supply of ICPs is chosen
        // so that the reward supply for the first day is 100 (365_250 * 10% / 365.25 = 100).
        .with_supply(ICPTs::from_e8s(365_250));

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
        wait_for_quiet_threshold_seconds: 1,
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

/// Check that, if all stakes are scaled uniformly, the maturities are
/// unchanged.
#[test]
fn test_maturities_are_invariant_by_stake_scaling() {
    assert_eq!(compute_maturities(vec![1], vec!["P"]), vec![100]);
    assert_eq!(compute_maturities(vec![2], vec!["P"],), vec![100]);
    assert_eq!(compute_maturities(vec![43_330], vec!["P"]), vec![100]);
}

/// Check that, if there is no proposal in the reward period, maturities do not
/// increases.
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
            vec![1, 1, 1],
            vec!["P--", "P--", "Py-", "P-y", "Pn-", "P-n"]
        ),
        vec![60, 20, 20] // first neuron votes 6 times, second 2 times, third 2 times.
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
    let mut driver = FakeDriver::default();
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
    let driver = FakeDriver::default()
        .with_ledger_from_neurons(
            &fixture
                .neurons
                .iter()
                .map(|(_, y)| y)
                .cloned()
                .collect::<Vec<Neuron>>(),
        )
        .with_supply(ICPTs::from_icpts(1_000_000).unwrap());
    let mut gov = Governance::new(fixture, driver.get_fake_env(), driver.get_fake_ledger());
    let neuron_a = gov.proto.neurons.get(&1).unwrap().clone();
    let neuron_b = gov.proto.neurons.get(&2).unwrap().clone();

    let principal1 = *neuron_a.controller.as_ref().unwrap();
    let principal2 = *neuron_b.controller.as_ref().unwrap();

    // Test that non kyc'd neurons can't be disbursed to accounts.
    let result = gov
        .disburse_neuron(
            &neuron_a.id.as_ref().unwrap(),
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
            &neuron_b.id.as_ref().unwrap(),
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
            &neuron_a.id.as_ref().unwrap(),
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
            &neuron_b.id.as_ref().unwrap(),
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
    let mut driver = FakeDriver::default();

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

    let driver = FakeDriver::default();
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

fn governance_with_staked_neuron(
    dissolve_delay_seconds: u64,
    neuron_stake_e8s: u64,
    block_height: u64,
    from: PrincipalId,
    nonce: u64,
) -> (FakeDriver, Governance, NeuronId, Subaccount) {
    let to_subaccount = Subaccount({
        let mut sha = Sha256::new();
        sha.write(&[0x0c]);
        sha.write(b"neuron-stake");
        sha.write(&from.as_slice());
        sha.write(&nonce.to_be_bytes());
        sha.finish()
    });

    let driver = FakeDriver::default()
        .at(56)
        .with_ledger_accounts(vec![FakeAccount {
            id: AccountIdentifier::new(
                ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
                Some(to_subaccount),
            ),
            amount_e8s: neuron_stake_e8s,
        }])
        .with_supply(ICPTs::from_icpts(400_000_000).unwrap());
    let mut gov = Governance::new(
        empty_fixture(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );

    // Add a stake transfer for this neuron, emulating a ledger call.
    let nid = gov
        .claim_or_top_up_neuron_from_notification(NeuronStakeTransfer {
            transfer_timestamp: driver.get_fake_env().now(),
            from: Some(from),
            from_subaccount: Vec::new(),
            to_subaccount: to_subaccount.to_vec(),
            neuron_stake_e8s,
            block_height,
            memo: nonce,
        })
        .now_or_never()
        .unwrap()
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
fn create_mature_neuron(dissolved: bool) -> (FakeDriver, Governance, Neuron) {
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
            transfer: Some(NeuronStakeTransfer {
                transfer_timestamp: driver.now(),
                from: Some(from),
                from_subaccount: Vec::new(),
                to_subaccount: to_subaccount.to_vec(),
                neuron_stake_e8s,
                block_height,
                memo: nonce,
            }),
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
        // - transaction fees * 2.
        neuron_stake_e8s - neuron_fees_e8s + neuron_maturity
            - gov.proto.economics.as_ref().unwrap().transaction_fee_e8s * 2,
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
        // - transaction fees * 2.
        neuron_stake_e8s - neuron_fees_e8s + neuron_maturity
            - gov.proto.economics.as_ref().unwrap().transaction_fee_e8s * 2,
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
        // - transaction fees * 2.
        neuron_stake_e8s - neuron_fees_e8s + neuron_maturity
            - gov.proto.economics.as_ref().unwrap().transaction_fee_e8s * 2,
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
        // - transaction fees * 2.
        neuron_stake_e8s - neuron_fees_e8s + neuron_maturity
            - gov.proto.economics.as_ref().unwrap().transaction_fee_e8s * 2,
    );
}

#[test]
fn test_top_up_stake() {
    let (mut driver, mut gov, neuron) = create_mature_neuron(true);
    let nid = neuron.id.unwrap();
    let neuron = gov.get_neuron_mut(&nid).unwrap();
    let account = neuron.account.clone();

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
    driver.advance_time_by(6 * ic_nns_governance::governance::ONE_MONTH_SECONDS);

    assert_eq!(
        neuron.aging_since_timestamp_seconds,
        driver.now() - 6 * ic_nns_governance::governance::ONE_MONTH_SECONDS - 1,
    );

    let block_height = 543212234;
    // Note that the nonce must match the nonce chosen in the original
    // transfer.
    let nonce = 1234u64;

    // Double the stake of the existing neuron.
    let nid_result = gov
        .claim_or_top_up_neuron_from_notification(NeuronStakeTransfer {
            transfer_timestamp: driver.now(),
            from: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            from_subaccount: Vec::new(),
            to_subaccount: account,
            neuron_stake_e8s: 100_000_000,
            block_height,
            memo: nonce,
        })
        .now_or_never()
        .unwrap()
        .unwrap();

    assert_eq!(nid_result, nid);
    let neuron = gov.get_neuron_mut(&nid).unwrap();
    assert_eq!(neuron.cached_neuron_stake_e8s, 200_000_000);
    assert_eq!(
        neuron.aging_since_timestamp_seconds,
        driver.now() - 3 * ic_nns_governance::governance::ONE_MONTH_SECONDS
    );
}

#[test]
fn test_claim_or_top_up_neuron_from_notification_does_not_overflow() {
    let (mut driver, mut gov, neuron) = create_mature_neuron(true);
    let nid = neuron.id.unwrap();
    let neuron = gov.get_neuron_mut(&nid).unwrap();
    let account = neuron.account.clone();

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

    let block_height = 543212234;
    // Note that the nonce must match the nonce chosen in the original
    // transfer.
    let nonce = 1234u64;

    // Double the stake of the existing neuron.
    let nid_result = gov
        .claim_or_top_up_neuron_from_notification(NeuronStakeTransfer {
            transfer_timestamp: driver.now(),
            from: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            from_subaccount: Vec::new(),
            to_subaccount: account,
            neuron_stake_e8s: 100_000_000_000_000,
            block_height,
            memo: nonce,
        })
        .now_or_never()
        .unwrap()
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
fn test_refresh_stake() {
    let (mut driver, mut gov, neuron) = create_mature_neuron(true);
    let nid = neuron.id.unwrap();
    let neuron = gov.get_neuron_mut(&nid).unwrap();
    let account = neuron.account.clone();

    // Increase the dissolve delay, this will make the neuron start
    // aging from some time <= now.
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
    driver.advance_time_by(6 * ic_nns_governance::governance::ONE_MONTH_SECONDS);

    let age_before_refresh = neuron.age_seconds(driver.now());
    assert!(age_before_refresh > 0);

    // Transfer more into the neuron's account (by minting).
    let new_transfer = ICPTs::from_icpts(1).unwrap();
    let memo = Memo(1234);
    let controller = neuron.controller.unwrap();
    driver
        .get_fake_ledger()
        .transfer_funds(
            new_transfer.get_e8s(),
            0,
            None,
            AccountIdentifier::new(
                GOVERNANCE_CANISTER_ID.get(),
                Some(Subaccount(account[..].try_into().unwrap())),
            ),
            memo.0,
        )
        .now_or_never()
        .unwrap()
        .unwrap();

    let result = gov
        .claim_or_refresh_neuron_from_account(
            &controller,
            &ClaimOrRefreshNeuronFromAccount {
                controller: None,
                memo: memo.0,
            },
        )
        .now_or_never()
        .unwrap();

    if let ClaimOrRefreshResult::Error(_) = result.result.unwrap() {
        panic!("Result returned an error.");
    }

    let neuron = gov.get_neuron_mut(&nid).unwrap();
    assert_eq!(neuron.cached_neuron_stake_e8s, 200_000_000);
    // Doubling the stake should half the age.
    assert_eq!(neuron.age_seconds(driver.now()), age_before_refresh / 2);
}

#[test]
fn test_claim_neuron_from_account() {
    // Create the ledger with an account corresponding to a neuron stake event
    // of which the governance canister was not notified.
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let memo = Memo(12345);
    let stake = ICPTs::from_icpts(1000).unwrap();
    let gov_subaccount = Subaccount::try_from(
        &{
            let mut state = Sha256::new();
            state.write(&[0x0c]);
            state.write(b"neuron-stake");
            state.write(&owner.as_slice());
            state.write(&memo.0.to_be_bytes());
            state.finish()
        }[..],
    )
    .expect("Couldn't build subaccount from hash.");
    let driver = FakeDriver::default()
        .at(56)
        .with_ledger_accounts(vec![FakeAccount {
            id: AccountIdentifier::new(
                ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
                Some(gov_subaccount),
            ),
            amount_e8s: stake.get_e8s(),
        }])
        .with_supply(ICPTs::from_icpts(400_000_000).unwrap());
    let mut gov = Governance::new(
        empty_fixture(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );

    let result = gov
        .claim_or_refresh_neuron_from_account(
            &owner,
            &ClaimOrRefreshNeuronFromAccount {
                controller: None,
                memo: memo.0,
            },
        )
        .now_or_never()
        .unwrap();

    match result.result.unwrap() {
        ClaimOrRefreshResult::Error(_) => panic!("Result returned an error"),
        ClaimOrRefreshResult::NeuronId(nid) => {
            let neuron = gov.get_neuron(&nid);
            assert!(neuron.is_ok());
            let neuron = neuron.unwrap();
            assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());
        }
    }
}

#[test]
fn test_claim_through_management() {
    // Create the ledger with an account corresponding to a neuron stake event
    // of which the governance canister was not notified.
    let owner = *TEST_NEURON_1_OWNER_PRINCIPAL;
    let memo = Memo(12345);
    let stake = ICPTs::from_icpts(1000).unwrap();
    let gov_subaccount = Subaccount::try_from(
        &{
            let mut state = Sha256::new();
            state.write(&[0x0c]);
            state.write(b"neuron-stake");
            state.write(&owner.as_slice());
            state.write(&memo.0.to_be_bytes());
            state.finish()
        }[..],
    )
    .expect("Couldn't build subaccount from hash.");
    let driver = FakeDriver::default()
        .at(56)
        .with_ledger_accounts(vec![FakeAccount {
            id: AccountIdentifier::new(
                ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
                Some(gov_subaccount),
            ),
            amount_e8s: stake.get_e8s(),
        }])
        .with_supply(ICPTs::from_icpts(400_000_000).unwrap());

    let mut gov = Governance::new(
        empty_fixture(),
        driver.get_fake_env(),
        driver.get_fake_ledger(),
    );

    // Check you can refresh by subaccount
    let result = gov
        .manage_neuron(
            &owner,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::Subaccount(
                    gov_subaccount.to_vec(),
                )),
                command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                    by: Some(By::Memo(memo.0)),
                })),
            },
        )
        .now_or_never()
        .unwrap();

    let nid = match result.command.unwrap() {
        manage_neuron_response::Command::ClaimOrRefresh(
            manage_neuron_response::ClaimOrRefreshResponse {
                refreshed_neuron_id: Some(nid),
            },
        ) => {
            let neuron = gov.get_neuron(&nid);
            assert!(neuron.is_ok());
            let neuron = neuron.unwrap();
            assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());
            nid
        }
        _ => panic!("Unexpected response from ClaimOrRefresh"),
    };

    // Check you can refresh by neuron ID
    let result = gov
        .manage_neuron(
            &owner,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(nid)),
                command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                    by: Some(By::Memo(memo.0)),
                })),
            },
        )
        .now_or_never()
        .unwrap();

    match result.command.unwrap() {
        manage_neuron_response::Command::ClaimOrRefresh(
            manage_neuron_response::ClaimOrRefreshResponse {
                refreshed_neuron_id: Some(nid),
            },
        ) => {
            let neuron = gov.get_neuron(&nid);
            assert!(neuron.is_ok());
            let neuron = neuron.unwrap();
            assert_eq!(neuron.cached_neuron_stake_e8s, stake.get_e8s());
        }
        _ => panic!("Unexpected response from ClaimOrRefresh"),
    };
}

#[test]
fn test_cant_disburse_without_paying_fees() {
    let (driver, mut gov, neuron) = create_mature_neuron(true);

    let id = neuron.id.clone().unwrap();
    let from = neuron.controller.clone().unwrap();
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
    assert_eq!(
        result.unwrap_err().error_type(),
        ErrorType::InsufficientFunds
    );

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
    assert_eq!(
        result.unwrap_err().error_type(),
        ErrorType::InsufficientFunds
    );

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
        // - transaction fees * 2.
        neuron_stake_e8s - neuron_fees_e8s + neuron_maturity
            - gov.proto.economics.as_ref().unwrap().transaction_fee_e8s * 2,
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
            account: child_subaccount.clone(),
            controller: parent_neuron.controller,
            cached_neuron_stake_e8s: 100_000_000,
            created_timestamp_seconds: parent_neuron.created_timestamp_seconds,
            aging_since_timestamp_seconds: parent_neuron.aging_since_timestamp_seconds,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                parent_neuron.dissolve_delay_seconds(driver.get_fake_env().now())
            )),
            transfer: Some(NeuronStakeTransfer {
                transfer_timestamp: driver.now(),
                from: Some(ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID)),
                from_subaccount: parent_neuron.account.clone(),
                to_subaccount: child_subaccount,
                neuron_stake_e8s: 100_000_000,
                block_height: 0,
                memo: child_neuron.transfer.as_ref().unwrap().memo,
            }),
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
            account: child_subaccount.clone(),
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
            transfer: Some(NeuronStakeTransfer {
                transfer_timestamp: driver.now(),
                from: Some(ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID)),
                from_subaccount: Vec::new(),
                to_subaccount: child_subaccount,
                neuron_stake_e8s: parent_maturity_e8s_equivalent,
                block_height: 0,
                memo: child_neuron.transfer.as_ref().unwrap().memo,
            }),
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

    let (mut driver, mut gov, id, to_subaccount) = governance_with_staked_neuron(
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
            account: child_subaccount.clone(),
            controller: Some(child_controller),
            cached_neuron_stake_e8s: 2 * 100_000_000,
            created_timestamp_seconds: driver.now(),
            aging_since_timestamp_seconds: driver.now(),
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(24 * 60 * 60)),
            transfer: Some(NeuronStakeTransfer {
                transfer_timestamp: driver.now(),
                from: Some(ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID)),
                from_subaccount: to_subaccount.to_vec(),
                to_subaccount: child_subaccount,
                neuron_stake_e8s: 2 * 100_000_000,
                block_height: 0,
                memo: child_neuron.transfer.as_ref().unwrap().memo,
            }),
            kyc_verified: true,
            ..Default::default()
        }
    );

    let to_subaccount = {
        let mut state = Sha256::new();
        state.write(&[0x0c]);
        state.write(b"neuron-split");
        state.write(&child_controller.as_slice());
        state.write(&nonce.to_be_bytes());
        state.finish()
    };

    assert_eq!(child_neuron.account, to_subaccount);
}

fn governance_with_neurons(neurons: &[Neuron]) -> (FakeDriver, Governance) {
    let accounts: Vec<FakeAccount> = neurons
        .iter()
        .map(|n| FakeAccount {
            id: AccountIdentifier::new(
                GOVERNANCE_CANISTER_ID.get(),
                Some(Subaccount(n.account.as_slice().try_into().unwrap())),
            ),
            amount_e8s: n.cached_neuron_stake_e8s,
        })
        .collect();
    let driver = FakeDriver::default()
        .at(56)
        .with_ledger_accounts(accounts)
        .with_supply(ICPTs::from_icpts(100_000_000_000).unwrap());

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
        &normal_neuron.id.as_ref().unwrap(),
        &normal_neuron.controller.as_ref().unwrap(),
        &Proposal {
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
        &normal_neuron.id.as_ref().unwrap(),
        &normal_neuron.controller.as_ref().unwrap(),
        &Proposal {
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
            &second_neuron.controller.as_ref().unwrap(),
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(
                    first_neuron.id.as_ref().unwrap().clone(),
                )),
                command: Some(manage_neuron::Command::Follow(manage_neuron::Follow {
                    topic: Topic::Governance as i32,
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
            &second_neuron.controller.as_ref().unwrap(),
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
    let new_controller = init_neurons[&42].controller.clone().unwrap();

    assert!(!gov
        .principal_to_neuron_ids_index
        .get(&new_controller)
        .unwrap()
        .contains(&neuron.id.as_ref().unwrap().id));
    // Add a hot key to the neuron and make sure that gets reflected in the
    // principal to neuron ids index.
    let result = gov
        .manage_neuron(
            &neuron.controller.as_ref().unwrap(),
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
            &neuron.controller.as_ref().unwrap(),
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
                    summary: "Reward this NP...".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::RewardNodeProvider(RewardNodeProvider {
                        node_provider: Some(NodeProvider { id: Some(np_pid) }),
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
                    summary: "Just want to add this NP.".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::AddOrRemoveNodeProvider(
                        AddOrRemoveNodeProvider {
                            change: Some(Change::ToAdd(NodeProvider { id: Some(np_pid) })),
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
        NodeProvider { id: Some(np_pid) }
    );

    // Adding the same node provider again should fail.
    let pid = match gov
        .manage_neuron(
            &voter_pid,
            &ManageNeuron {
                id: None,
                neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(voter_neuron.clone())),
                command: Some(manage_neuron::Command::MakeProposal(Box::new(Proposal {
                    summary: "Just want to add this NP.".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::AddOrRemoveNodeProvider(
                        AddOrRemoveNodeProvider {
                            change: Some(Change::ToAdd(NodeProvider { id: Some(np_pid) })),
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
                    summary: "Reward this NP...".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::RewardNodeProvider(RewardNodeProvider {
                        node_provider: Some(NodeProvider { id: Some(np_pid) }),
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
                    summary: "Reward this NP...".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::RewardNodeProvider(RewardNodeProvider {
                        node_provider: Some(NodeProvider { id: Some(np_pid) }),
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
                    summary: "Reward this NP...".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::RewardNodeProvider(RewardNodeProvider {
                        node_provider: Some(NodeProvider { id: Some(np_pid) }),
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
        .find(|(_, x)| x.controller == Some(np_pid) && x.transfer.is_some())
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
                    summary: "Just want to remove this NP.".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::AddOrRemoveNodeProvider(
                        AddOrRemoveNodeProvider {
                            change: Some(Change::ToRemove(NodeProvider { id: Some(np_pid) })),
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
                    summary: "Reward this NP...".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::RewardNodeProvider(RewardNodeProvider {
                        node_provider: Some(NodeProvider { id: Some(np_pid_1) }),
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
                        summary: "Just want to add this other NP.".to_string(),
                        url: "".to_string(),
                        action: Some(proposal::Action::AddOrRemoveNodeProvider(
                            AddOrRemoveNodeProvider {
                                change: Some(Change::ToAdd(NodeProvider { id: Some(np_pid) })),
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
            NodeProvider { id: Some(np_pid_0) }
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
                        summary: "Just want to add this other NP.".to_string(),
                        url: "".to_string(),
                        action: Some(proposal::Action::AddOrRemoveNodeProvider(
                            AddOrRemoveNodeProvider {
                                change: Some(Change::ToAdd(NodeProvider { id: Some(np_pid) })),
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
            summary: "Reward these NPs...".to_string(),
            url: "".to_string(),
            action: Some(proposal::Action::RewardNodeProviders(RewardNodeProviders {
                rewards: vec![
                    RewardNodeProvider {
                        node_provider: Some(NodeProvider { id: Some(np_pid_0) }),
                        amount_e8s: 10 * 100_000_000,
                        reward_mode: Some(RewardMode::RewardToAccount(RewardToAccount {
                            to_account: Some(AccountIdentifier::new(np_pid_0, None).into()),
                        })),
                    },
                    RewardNodeProvider {
                        node_provider: Some(NodeProvider { id: Some(np_pid_1) }),
                        amount_e8s: 10 * 100_000_000,
                        reward_mode: Some(RewardMode::RewardToAccount(RewardToAccount {
                            to_account: Some(
                                AccountIdentifier::new(np_pid_1, Some(to_subaccount)).into(),
                            ),
                        })),
                    },
                    RewardNodeProvider {
                        node_provider: Some(NodeProvider { id: Some(np_pid_2) }),
                        amount_e8s: 99_999_999,
                        reward_mode: Some(RewardMode::RewardToNeuron(RewardToNeuron {
                            dissolve_delay_seconds: 10,
                        })),
                    },
                ],
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
        .find(|(_, x)| x.controller == Some(np_pid_2) && x.transfer.is_some())
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
                    summary: "Just want to remove this NP.".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::AddOrRemoveNodeProvider(
                        AddOrRemoveNodeProvider {
                            change: Some(Change::ToRemove(NodeProvider { id: Some(np_pid_0) })),
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
                    summary: "Just want to remove this NP.".to_string(),
                    url: "".to_string(),
                    action: Some(proposal::Action::AddOrRemoveNodeProvider(
                        AddOrRemoveNodeProvider {
                            change: Some(Change::ToRemove(NodeProvider { id: Some(np_pid_2) })),
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
        sha.write(&from.as_slice());
        sha.write(&nonce.to_be_bytes());
        sha.finish()
    });

    driver.create_account_with_funds(
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(to_subaccount)),
        neuron_stake_e8s,
    );

    // Add a stake transfer for this neuron, emulating a ledger call.
    let id = gov
        .claim_or_top_up_neuron_from_notification(NeuronStakeTransfer {
            transfer_timestamp: driver.get_fake_env().now(),
            from: Some(from),
            from_subaccount: Vec::new(),
            to_subaccount: to_subaccount.to_vec(),
            neuron_stake_e8s,
            block_height: 0,
            memo: nonce,
        })
        .now_or_never()
        .unwrap()
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
        sha.write(&from.as_slice());
        sha.write(&nonce.to_be_bytes());
        sha.finish()
    });

    driver.create_account_with_funds(
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(to_subaccount)),
        neuron_stake_e8s,
    );

    let id2 = gov
        .claim_or_top_up_neuron_from_notification(NeuronStakeTransfer {
            transfer_timestamp: driver.get_fake_env().now(),
            from: Some(from),
            from_subaccount: Vec::new(),
            to_subaccount: to_subaccount.to_vec(),
            neuron_stake_e8s,
            block_height: 0,
            memo: nonce,
        })
        .now_or_never()
        .unwrap()
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
    pinfo.recompute_tally(10);
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
    let driver = FakeDriver::default();
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
    let driver = FakeDriver::default();
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
    let driver = FakeDriver::default();
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
    let driver = FakeDriver::default();
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
    let driver = FakeDriver::default();
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
    let mut driver = FakeDriver::default();
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
    let mut driver = FakeDriver::default().at(20);
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
    let driver = FakeDriver::default();
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
    let mut fake_driver = FakeDriver::default();
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
    let mut driver = FakeDriver::default().at(60 * 60 * 24 * 30);
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
    let driver = FakeDriver::default();

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
        let driver = FakeDriver::default();
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

#[test]
fn test_merge_maturity_of_neuron() {
    let (driver, mut gov, neuron) = create_mature_neuron(false);

    let id = neuron.id.clone().unwrap();
    let controller = neuron.controller.clone().unwrap();
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
    driver: &FakeDriver,
) {
    let neuron = gov.get_neuron(&id).unwrap().clone();
    let account = AccountIdentifier::new(
        ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
        Some(Subaccount::try_from(neuron.account.as_slice()).unwrap()),
    );
    let response = merge_maturity(gov, id.clone(), &controller, percentage_to_merge).unwrap();
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
    neuron.cached_neuron_stake_e8s = ICPTs::new(5, 0).unwrap().get_e8s();
    neuron.aging_since_timestamp_seconds = 0;
    neuron.update_stake(ICPTs::new(10, 0).unwrap().get_e8s(), now);
    assert_eq!(neuron.aging_since_timestamp_seconds, 5);
    assert_eq!(
        neuron.cached_neuron_stake_e8s,
        ICPTs::new(10, 0).unwrap().get_e8s()
    );

    // Increase the stake by a random amount
    let mut neuron = Neuron::default();
    let now = 10000;
    neuron.cached_neuron_stake_e8s = ICPTs::new(50, 0).unwrap().get_e8s();
    neuron.aging_since_timestamp_seconds = 0;
    neuron.update_stake(ICPTs::new(58, 0).unwrap().get_e8s(), now);
    let expected_aging_since_timestamp_seconds = 1380;
    assert_eq!(
        neuron.aging_since_timestamp_seconds,
        expected_aging_since_timestamp_seconds
    );
    assert_eq!(
        neuron.cached_neuron_stake_e8s,
        ICPTs::new(58, 0).unwrap().get_e8s()
    );
}
