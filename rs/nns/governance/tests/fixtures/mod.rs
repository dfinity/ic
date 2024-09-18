// Unused imports are allowed for the time being, since I intend to move more
// and more code in future from governance.rs to here, and that code will
// likely need many of the imports that are currently unused below.
#![allow(unused_imports)]
#![allow(dead_code)]
use crate::fixtures::environment_fixture::{
    CanisterCallReply, EnvironmentFixture, EnvironmentFixtureState,
};
use async_trait::async_trait;
use candid::Encode;
use comparable::Comparable;
use futures::future::FutureExt;
use ic_base_types::{CanisterId, PrincipalId};
use ic_crypto_sha2::Sha256;
use ic_nervous_system_common::{cmc::CMC, ledger::IcpLedger, NervousSystemError};
use ic_nns_common::{
    pb::v1::{NeuronId, ProposalId},
    types::UpdateIcpXdrConversionRatePayload,
};
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_nns_governance::{
    governance::{
        governance_minting_account, neuron_subaccount, Environment, Governance, HeapGrowthPotential,
    },
    governance_proto_builder::GovernanceProtoBuilder,
    pb::v1::{
        manage_neuron,
        manage_neuron::{Command, Merge, MergeMaturity, NeuronIdOrSubaccount},
        manage_neuron_response,
        manage_neuron_response::MergeMaturityResponse,
        neuron,
        neuron::DissolveState,
        proposal, ExecuteNnsFunction, Governance as GovernanceProto, GovernanceError, ManageNeuron,
        ManageNeuronResponse, Motion, NetworkEconomics, Neuron, NeuronType, NnsFunction, Proposal,
        ProposalData, RewardEvent, Topic, Vote, XdrConversionRate as XdrConversionRatePb,
    },
};
use icp_ledger::{AccountIdentifier, Subaccount, Tokens};
use rand::{prelude::StdRng, RngCore, SeedableRng};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    convert::{TryFrom, TryInto},
    sync::Arc,
};
use tokio::sync::Mutex;

pub mod environment_fixture;

const DEFAULT_TEST_START_TIMESTAMP_SECONDS: u64 = 999_111_000_u64;

type LedgerMap = BTreeMap<AccountIdentifier, u64>;

/// Constructs a test principal id from an integer.
/// Convenience functions to make creating neurons more concise.
pub fn principal(i: u64) -> PrincipalId {
    PrincipalId::try_from(format!("SID{}", i).as_bytes().to_vec()).unwrap()
}

/// Constructs a test neuron's account.
pub fn account(i: u64) -> Vec<u8> {
    let mut account = vec![0; 32];
    for (destination, data) in account.iter_mut().zip(i.to_le_bytes().iter().cycle()) {
        *destination = *data;
    }
    account
}

// Constructs a simple motion proposal for tests where the content does not
// matter.
pub fn new_motion_proposal() -> Proposal {
    Proposal {
        title: Some("A Reasonable Title".to_string()),
        summary: "Summary".to_string(),
        action: Some(proposal::Action::Motion(Motion {
            motion_text: "Some proposal".to_string(),
        })),
        ..Default::default()
    }
}

pub fn prorated_neuron_age(
    aging_since: u64,
    old_stake_e8s: u64,
    new_stake_e8s: u64,
    now: u64,
) -> u64 {
    if aging_since < now && old_stake_e8s <= new_stake_e8s {
        let old_stake = old_stake_e8s as u128;
        let old_age = now.saturating_sub(aging_since) as u128;
        let new_age = (old_age * old_stake) / (new_stake_e8s as u128);
        now.saturating_sub(new_age as u64)
    } else {
        u64::MAX
    }
}

/// The LedgerFixture allows for independent testing of Ledger functionality.
#[derive(Clone, Default)]
pub struct LedgerFixture {
    accounts: LedgerMap,
}

impl LedgerFixture {
    pub fn get_supply(&self) -> Tokens {
        Tokens::from_e8s(self.accounts.values().sum())
    }
}

pub struct LedgerBuilder {
    ledger_fixture: LedgerFixture,
}

impl LedgerBuilder {
    pub fn create(self) -> LedgerFixture {
        self.ledger_fixture
    }

    pub fn minting_account() -> AccountIdentifier {
        governance_minting_account()
    }

    pub fn add_account(&mut self, ident: AccountIdentifier, amount: u64) -> &mut Self {
        self.ledger_fixture.accounts.insert(ident, amount);
        self
    }

    pub fn try_add_account(&mut self, ident: AccountIdentifier, amount: u64) -> &mut Self {
        self.ledger_fixture.accounts.entry(ident).or_insert(amount);
        self
    }

    pub fn neuron_account_id(neuron: &Neuron) -> AccountIdentifier {
        neuron_subaccount(Subaccount::try_from(neuron.account.as_slice()).unwrap())
    }
}

impl Default for LedgerBuilder {
    fn default() -> Self {
        let mut ledger_builder = LedgerBuilder {
            ledger_fixture: LedgerFixture::default(),
        };

        // Always insert the minting_account.
        ledger_builder.add_account(LedgerBuilder::minting_account(), 0);
        ledger_builder
    }
}

pub struct EnvironmentBuilder {
    environment_fixture_state: EnvironmentFixtureState,
}
impl EnvironmentBuilder {
    pub fn create(self) -> EnvironmentFixture {
        EnvironmentFixture::new(self.environment_fixture_state)
    }

    pub fn set_start_time(&mut self, start_time_seconds: u64) -> &mut Self {
        self.environment_fixture_state.now = start_time_seconds;
        self
    }

    pub fn push_mock_reply(&mut self, canister_call_reply: CanisterCallReply) -> &mut Self {
        self.environment_fixture_state
            .mocked_canister_replies
            .push_back(canister_call_reply);
        self
    }
}

impl Default for EnvironmentBuilder {
    fn default() -> Self {
        EnvironmentBuilder {
            environment_fixture_state: EnvironmentFixtureState {
                now: 0,
                rng: StdRng::seed_from_u64(9539),
                observed_canister_calls: VecDeque::new(),
                mocked_canister_replies: VecDeque::new(),
            },
        }
    }
}

/// The NeuronBuilder is used for creating neurons on behalf of the governance
/// canister. The principal id and subaccount identifier are both derived from
/// the neuron id, which is provided by the caller.
pub struct NeuronBuilder {
    ident: u64,
    stake: u64,
    owner: Option<PrincipalId>,
    hot_keys: Vec<PrincipalId>,
    age_timestamp: Option<u64>,
    created_seconds: Option<u64>,
    maturity: u64,
    staked_maturity: u64,
    neuron_fees: u64,
    dissolve_state: Option<neuron::DissolveState>,
    followees: HashMap<i32, neuron::Followees>,
    kyc_verified: bool,
    not_for_profit: bool,
    joined_community_fund: Option<u64>,
    spawn_at_timestamp_seconds: Option<u64>,
    neuron_type: Option<i32>,
}

impl From<Neuron> for NeuronBuilder {
    fn from(neuron: Neuron) -> Self {
        NeuronBuilder {
            ident: 0,
            stake: neuron.cached_neuron_stake_e8s,
            owner: None,
            hot_keys: neuron.hot_keys,
            age_timestamp: if neuron.aging_since_timestamp_seconds == u64::MAX {
                None
            } else {
                Some(neuron.aging_since_timestamp_seconds)
            },
            created_seconds: Some(neuron.created_timestamp_seconds),
            maturity: neuron.maturity_e8s_equivalent,
            staked_maturity: neuron.staked_maturity_e8s_equivalent.unwrap_or(0),
            neuron_fees: neuron.neuron_fees_e8s,
            dissolve_state: neuron.dissolve_state,
            followees: neuron.followees,
            kyc_verified: neuron.kyc_verified,
            not_for_profit: neuron.not_for_profit,
            joined_community_fund: neuron.joined_community_fund_timestamp_seconds,
            spawn_at_timestamp_seconds: None,
            neuron_type: neuron.neuron_type,
        }
    }
}

impl NeuronBuilder {
    pub fn new(ident: u64, stake: u64, owner: PrincipalId) -> Self {
        NeuronBuilder {
            ident,
            stake,
            owner: Some(owner),
            hot_keys: Vec::new(),
            age_timestamp: None,
            created_seconds: None,
            maturity: 0,
            staked_maturity: 0,
            neuron_fees: 0,
            dissolve_state: None,
            followees: HashMap::new(),
            kyc_verified: true,
            not_for_profit: false,
            joined_community_fund: None,
            spawn_at_timestamp_seconds: None,
            neuron_type: None,
        }
    }

    pub fn set_dissolve_delay(mut self, seconds: u64) -> Self {
        self.dissolve_state = Some(DissolveState::DissolveDelaySeconds(seconds));
        self
    }

    pub fn set_ident(mut self, ident: u64) -> Self {
        self.ident = ident;
        self
    }

    pub fn set_owner(mut self, owner: PrincipalId) -> Self {
        self.owner = Some(owner);
        self
    }

    pub fn set_hotkeys(mut self, hotkeys: Vec<PrincipalId>) -> Self {
        self.hot_keys = hotkeys;
        self
    }

    pub fn set_neuron_fees(mut self, fees: u64) -> Self {
        self.neuron_fees = fees;
        self
    }

    pub fn set_maturity(mut self, maturity: u64) -> Self {
        self.maturity = maturity;
        self
    }

    pub fn set_staked_maturity(mut self, staked_maturity: u64) -> Self {
        self.staked_maturity = staked_maturity;
        self
    }
    pub fn set_creation_timestamp(mut self, secs: u64) -> Self {
        self.created_seconds = Some(secs);
        self
    }

    pub fn set_aging_since_timestamp(mut self, secs: u64) -> Self {
        self.age_timestamp = Some(secs);
        self
    }

    #[allow(dead_code)]
    pub fn start_dissolving(mut self, now: u64) -> Self {
        if let Some(DissolveState::DissolveDelaySeconds(secs)) = self.dissolve_state {
            self.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(now + secs));
        }
        self
    }

    pub fn set_dissolve_state(mut self, state: Option<DissolveState>) -> Self {
        self.dissolve_state = state;
        self
    }

    pub fn set_kyc_verified(mut self, kyc: bool) -> Self {
        self.kyc_verified = kyc;
        self
    }

    pub fn set_not_for_profit(mut self, nfp: bool) -> Self {
        self.not_for_profit = nfp;
        self
    }

    pub fn set_joined_community_fund(mut self, secs: u64) -> Self {
        self.joined_community_fund = Some(secs);
        self
    }

    pub fn insert_managers(mut self, managers: neuron::Followees) -> Self {
        self.followees
            .insert(Topic::NeuronManagement as i32, managers);
        self
    }

    pub fn insert_followees(mut self, topic: Topic, followees: neuron::Followees) -> Self {
        self.followees.insert(topic as i32, followees);
        self
    }

    pub fn set_spawn_at_timestamp_seconds(
        mut self,
        spawn_at_timestamp_seconds: Option<u64>,
    ) -> Self {
        self.spawn_at_timestamp_seconds = spawn_at_timestamp_seconds;
        self
    }

    pub fn set_neuron_type(mut self, neuron_type: NeuronType) -> Self {
        self.neuron_type = Some(neuron_type as i32);
        self
    }

    pub fn create(self, now: u64, ledger: &mut LedgerBuilder) -> Neuron {
        let subaccount = Self::subaccount(self.owner, self.ident);
        ledger.add_account(neuron_subaccount(subaccount), self.stake);
        subaccount.to_vec();

        Neuron {
            id: Some(NeuronId { id: self.ident }),
            account: subaccount.to_vec(),
            controller: self.owner,
            hot_keys: self.hot_keys,
            cached_neuron_stake_e8s: self.stake,
            neuron_fees_e8s: self.neuron_fees,
            created_timestamp_seconds: self.created_seconds.unwrap_or(now),
            aging_since_timestamp_seconds: match self.dissolve_state {
                Some(DissolveState::WhenDissolvedTimestampSeconds(_)) => u64::MAX,
                _ => match self.age_timestamp {
                    None => now,
                    Some(secs) => secs,
                },
            },
            maturity_e8s_equivalent: self.maturity,
            staked_maturity_e8s_equivalent: if self.staked_maturity == 0 {
                None
            } else {
                Some(self.staked_maturity)
            },
            dissolve_state: self.dissolve_state,
            kyc_verified: self.kyc_verified,
            not_for_profit: self.not_for_profit,
            followees: self.followees,
            joined_community_fund_timestamp_seconds: self.joined_community_fund,
            spawn_at_timestamp_seconds: self.spawn_at_timestamp_seconds,
            neuron_type: self.neuron_type,
            ..Neuron::default()
        }
    }

    pub fn subaccount(owner: Option<PrincipalId>, nonce: u64) -> Subaccount {
        Subaccount({
            let mut sha = Sha256::new();
            sha.write(&[0x0c]);
            sha.write(b"neuron-stake");
            if let Some(o) = owner {
                sha.write(o.as_slice());
                sha.write(&nonce.to_be_bytes());
            }
            sha.finish()
        })
    }

    pub fn add_followees(mut self, index: i32, followees: neuron::Followees) -> Self {
        self.followees.insert(index, followees);
        self
    }
}

pub struct NNSFixtureState {
    ledger: LedgerFixture,
    environment: EnvironmentFixture,
}

#[derive(Clone)]
pub struct NNSFixture {
    nns_state: Arc<Mutex<NNSFixtureState>>,
}

impl NNSFixture {
    pub fn new(state: NNSFixtureState) -> Self {
        NNSFixture {
            nns_state: Arc::new(Mutex::new(state)),
        }
    }
}

#[async_trait]
impl IcpLedger for NNSFixture {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to_account: AccountIdentifier,
        _: u64,
    ) -> Result<u64, NervousSystemError> {
        // Minting operations (sending ICP from Gov main account) should just create ICP.
        let is_minting_operation = from_subaccount.is_none();

        let from_account = from_subaccount.map_or(governance_minting_account(), neuron_subaccount);
        println!(
            "Issuing ledger transfer from account {} (subaccount {}) to account {} amount {} fee {}",
            from_account, from_subaccount.as_ref().map_or_else(||"None".to_string(), ToString::to_string), to_account, amount_e8s, fee_e8s
        );
        let accounts = &mut self.nns_state.try_lock().unwrap().ledger.accounts;

        let from_e8s = accounts
            .get_mut(&from_account)
            .ok_or_else(|| NervousSystemError::new_with_message("Source account doesn't exist"))?;

        let requested_e8s = amount_e8s + fee_e8s;

        if !is_minting_operation {
            if *from_e8s < requested_e8s {
                return Err(NervousSystemError::new_with_message(format!(
                    "Insufficient funds. Available {} requested {}",
                    *from_e8s, requested_e8s
                )));
            }
            *from_e8s -= requested_e8s;
        }

        *accounts.entry(to_account).or_default() += amount_e8s;

        Ok(0)
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        Ok(self.nns_state.try_lock().unwrap().ledger.get_supply())
    }

    async fn account_balance(
        &self,
        account: AccountIdentifier,
    ) -> Result<Tokens, NervousSystemError> {
        let accounts = &mut self.nns_state.try_lock().unwrap().ledger.accounts;
        let account_e8s = accounts.get(&account).unwrap_or(&0);
        Ok(Tokens::from_e8s(*account_e8s))
    }

    fn canister_id(&self) -> CanisterId {
        LEDGER_CANISTER_ID
    }
}

#[async_trait]
impl Environment for NNSFixture {
    fn now(&self) -> u64 {
        self.nns_state.try_lock().unwrap().environment.now()
    }

    fn random_u64(&mut self) -> u64 {
        self.nns_state.try_lock().unwrap().environment.random_u64()
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        self.nns_state
            .try_lock()
            .unwrap()
            .environment
            .random_byte_array()
    }

    fn execute_nns_function(
        &self,
        proposal_id: u64,
        update: &ExecuteNnsFunction,
    ) -> Result<(), GovernanceError> {
        self.nns_state
            .try_lock()
            .unwrap()
            .environment
            .execute_nns_function(proposal_id, update)
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        self.nns_state
            .try_lock()
            .unwrap()
            .environment
            .heap_growth_potential()
    }

    async fn call_canister_method(
        &self,
        target: CanisterId,
        method_name: &str,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        self.nns_state
            .try_lock()
            .unwrap()
            .environment
            .call_canister_method(target, method_name, request)
            .now_or_never()
            .expect("FUCK ME") // TODO
    }
}

#[async_trait]
impl CMC for NNSFixture {
    async fn neuron_maturity_modulation(&mut self) -> Result<i32, String> {
        Ok(100)
    }
}

/// The NNSState is used to capture all of the salient details of the NNS
/// environment, so that we can compute the "delta", or what changed between
/// actions.
#[derive(Clone, Default, comparable::Comparable)]
#[compare_default]
pub struct NNSState {
    now: u64,
    accounts: LedgerMap,
    governance_proto: GovernanceProto,
    // Attributes from `Governance`, which itself is not clonable
    latest_gc_num_proposals: usize,
}

/// When testing proposals, three different proposal topics available:
/// Governance, NetworkEconomics, and ExchangeRate.
enum ProposalTopicBehaviour {
    Governance,
    NetworkEconomics,
    ExchangeRate,
}

/// A struct to help setting up tests concisely thanks to a concise format to
/// specifies who proposes something and who votes on that proposal.
pub struct ProposalNeuronBehavior {
    /// Neuron id of the proposer.
    proposer: u64,
    /// Map neuron id of voters to their votes.
    votes: BTreeMap<u64, Vote>,
    /// Keep track of proposal topic to use.
    proposal_topic: ProposalTopicBehaviour,
}

impl ProposalNeuronBehavior {
    /// Creates a proposal from the specified proposer, and register the
    /// specified votes.
    ///
    /// This function assumes that:
    /// - neuron of id `i` has for controller `principal(i)`
    pub fn propose_and_vote(&self, nns: &mut NNS, summary: String) -> ProposalId {
        // Submit proposal
        let action = match self.proposal_topic {
            ProposalTopicBehaviour::Governance => proposal::Action::Motion(Motion {
                motion_text: format!("summary: {}", summary),
            }),
            ProposalTopicBehaviour::NetworkEconomics => {
                proposal::Action::ManageNetworkEconomics(NetworkEconomics {
                    ..Default::default()
                })
            }
            ProposalTopicBehaviour::ExchangeRate => {
                proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
                    nns_function: NnsFunction::IcpXdrConversionRate as i32,
                    payload: Encode!(&UpdateIcpXdrConversionRatePayload {
                        xdr_permyriad_per_icp: 1000000,
                        data_source: "".to_string(),
                        timestamp_seconds: 0,
                        reason: None,
                    })
                    .unwrap(),
                })
            }
        };
        let pid = nns
            .governance
            .make_proposal(
                &NeuronId { id: self.proposer },
                &principal(self.proposer),
                &Proposal {
                    title: Some("A Reasonable Title".to_string()),
                    summary,
                    action: Some(action),
                    ..Default::default()
                },
            )
            .unwrap();
        // Vote
        for (voter, vote) in &self.votes {
            nns.register_vote_assert_success(
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
    /// Format: <neuron_behaviour> * <proposal_topic>?
    ///
    /// neuron_behaviour: each subsequentcharacter corresponds to the
    /// behavior of one neuron, in order.
    ///
    /// "-" means "does not vote"
    /// "y" means "votes yes"
    /// "n" means "votes no"
    /// "P" means "proposes"
    ///
    /// proposal_type: if the first character is one of 'G', 'N'
    /// (default), or 'E', the proposal type used is 'Motion',
    /// 'NetworkEconomics', or 'IcpXdrConversionRate'.
    ///
    /// Example:
    /// "--yP-nyE" means:
    ///
    /// neuron 3 proposes, neurons 2 and 6 votes yes, neuron 5 votes
    /// no, neurons 0, 1, and 4 do not vote; the proposal topic is
    /// ExchangeRate.
    fn from(str: &str) -> ProposalNeuronBehavior {
        // Look at the last letter to figure out if it specifies a proposal type.
        let last_chr = str.chars().last().unwrap_or(' ');
        let (str, proposal_topic) = match "NEG".find(last_chr) {
            None => (str, ProposalTopicBehaviour::NetworkEconomics),
            Some(x) => (
                &str[0..str.len() - 1],
                match x {
                    0 => ProposalTopicBehaviour::NetworkEconomics,
                    1 => ProposalTopicBehaviour::ExchangeRate,
                    // Must be 2, but using _ for a complete match.
                    _ => ProposalTopicBehaviour::Governance,
                },
            ),
        };
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
            proposal_topic,
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
pub struct NNS {
    pub fixture: NNSFixture,
    pub governance: Governance,
    pub(crate) initial_state: Option<NNSState>,
}

impl NNS {
    /// Increases the time by the given amount.
    pub fn advance_time_by(&mut self, delta_seconds: u64) -> &mut Self {
        self.fixture
            .nns_state
            .try_lock()
            .unwrap()
            .environment
            .advance_time_by(delta_seconds);
        self
    }

    pub fn capture_state(&mut self) -> &mut Self {
        self.initial_state = Some(self.get_state());
        self
    }

    pub(crate) fn get_state(&self) -> NNSState {
        NNSState {
            now: self.now(),
            accounts: self
                .fixture
                .nns_state
                .try_lock()
                .unwrap()
                .ledger
                .accounts
                .clone(),
            governance_proto: self.governance.clone_proto(),
            latest_gc_num_proposals: self.governance.latest_gc_num_proposals,
        }
    }

    pub fn run_periodic_tasks(&mut self) -> &mut Self {
        self.governance.run_periodic_tasks().now_or_never();
        self
    }

    /// Issues a manage_neuron command to register a vote
    fn register_vote(
        &mut self,
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
        self.governance
            .manage_neuron(&caller, &manage_neuron)
            .now_or_never()
            .unwrap()
    }

    /// Issues a manage_neuron command to register a vote, and asserts that it
    /// worked.
    pub fn register_vote_assert_success(
        &mut self,
        caller: PrincipalId,
        neuron_id: NeuronId,
        pid: ProposalId,
        vote: Vote,
    ) {
        let result = self.register_vote(caller, neuron_id, pid, vote);
        assert_eq!(
            result,
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::RegisterVote(
                    manage_neuron_response::RegisterVoteResponse {}
                ))
            }
        );
    }

    /// Creates a proposal from the specified proposer, and register the
    /// specified votes.
    ///
    /// This function assumes that:
    /// - neuron of id `i` has for controller `principal(i)`
    pub fn propose_with_action(
        &mut self,
        prop: &ProposalNeuronBehavior,
        summary: String,
        action: proposal::Action,
    ) -> ProposalId {
        // Submit proposal
        self.governance
            .make_proposal(
                &NeuronId { id: prop.proposer },
                &principal(prop.proposer),
                &Proposal {
                    title: Some("A Reasonable Title".to_string()),
                    summary,
                    action: Some(action),
                    ..Default::default()
                },
            )
            .unwrap()
    }

    pub fn propose_and_vote(
        &mut self,
        behavior: impl Into<ProposalNeuronBehavior>,
        summary: String,
    ) -> ProposalId {
        behavior.into().propose_and_vote(self, summary)
    }

    pub fn merge_maturity(
        &mut self,
        id: &NeuronId,
        controller: &PrincipalId,
        percentage_to_merge: u32,
    ) -> Result<MergeMaturityResponse, GovernanceError> {
        let result = self
            .governance
            .manage_neuron(
                controller,
                &ManageNeuron {
                    id: None,
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(*id)),
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

    pub fn merge_neurons(
        &mut self,
        target: &NeuronId,
        controller: &PrincipalId,
        source: &NeuronId,
    ) -> Result<(), GovernanceError> {
        self.governance
            .merge_neurons(
                target,
                controller,
                &Merge {
                    source_neuron_id: Some(*source),
                },
            )
            .now_or_never()
            .unwrap()?;
        Ok(())
    }

    pub fn simulate_merge_neurons(
        &mut self,
        target: &NeuronId,
        controller: &PrincipalId,
        source: &NeuronId,
    ) -> ManageNeuronResponse {
        self.governance.simulate_manage_neuron(
            controller,
            ManageNeuron {
                id: Some(*target),
                neuron_id_or_subaccount: None,
                command: Some(Command::Merge(Merge {
                    source_neuron_id: Some(*source),
                })),
            },
        )
    }

    pub fn get_neuron(&self, ident: &NeuronId) -> Neuron {
        self.governance
            .neuron_store
            .with_neuron(ident, |n| Neuron::from(n.clone()))
            .unwrap()
    }

    pub fn get_account_balance(&self, account: AccountIdentifier) -> u64 {
        self.account_balance(account)
            .now_or_never()
            .unwrap()
            .unwrap()
            .get_e8s()
    }

    pub fn get_neuron_account_id(&self, id: u64) -> AccountIdentifier {
        LedgerBuilder::neuron_account_id(&self.get_neuron(&NeuronId { id }))
    }

    pub fn get_neuron_stake(&self, neuron: &Neuron) -> u64 {
        self.get_account_balance(LedgerBuilder::neuron_account_id(neuron))
    }

    pub fn push_mocked_canister_reply(&mut self, call: impl Into<CanisterCallReply>) {
        self.fixture
            .nns_state
            .try_lock()
            .unwrap()
            .environment
            .push_mocked_canister_reply(call)
    }
}

#[async_trait]
impl IcpLedger for NNS {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to_account: AccountIdentifier,
        arg: u64,
    ) -> Result<u64, NervousSystemError> {
        self.fixture
            .transfer_funds(amount_e8s, fee_e8s, from_subaccount, to_account, arg)
            .await
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        self.fixture.total_supply().await
    }

    async fn account_balance(
        &self,
        account: AccountIdentifier,
    ) -> Result<Tokens, NervousSystemError> {
        self.fixture.account_balance(account).await
    }

    fn canister_id(&self) -> CanisterId {
        self.fixture.canister_id()
    }
}

#[async_trait]
impl Environment for NNS {
    fn now(&self) -> u64 {
        self.fixture.now()
    }

    fn random_u64(&mut self) -> u64 {
        self.fixture.random_u64()
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        self.fixture.random_byte_array()
    }

    fn execute_nns_function(
        &self,
        proposal_id: u64,
        update: &ExecuteNnsFunction,
    ) -> Result<(), GovernanceError> {
        self.fixture.execute_nns_function(proposal_id, update)
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        self.fixture.heap_growth_potential()
    }

    async fn call_canister_method(
        &self,
        _target: CanisterId,
        _method_name: &str,
        _request: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        unimplemented!();
    }
}

pub type LedgerTransform = Box<dyn FnOnce(Box<dyn IcpLedger>) -> Box<dyn IcpLedger>>;
pub type EnvironmentTransform = Box<dyn FnOnce(Box<dyn Environment>) -> Box<dyn Environment>>;

/// The NNSBuilder permits the declarative construction of an NNS fixture. All
/// of the methods concern setting or querying what this initial state will
/// be. Therefore, `get_account_balance` on a builder object will only tell
/// you what the account will be once the NNS fixture is created, which is
/// different from calling `get_account_balance` on the resulting fixture,
/// even though it will initially be the same amount.
pub struct NNSBuilder {
    ledger_builder: LedgerBuilder,
    environment_builder: EnvironmentBuilder,
    governance: GovernanceProto,
    ledger_transforms: Vec<LedgerTransform>,
    environment_transforms: Vec<EnvironmentTransform>,
}

impl Default for NNSBuilder {
    fn default() -> Self {
        NNSBuilder {
            ledger_builder: LedgerBuilder::default(),
            environment_builder: Default::default(),
            governance: GovernanceProtoBuilder::new().build(),
            ledger_transforms: Vec::default(),
            environment_transforms: Vec::default(),
        }
        .set_start_time(DEFAULT_TEST_START_TIMESTAMP_SECONDS)
    }
}

impl NNSBuilder {
    pub fn new() -> Self {
        NNSBuilder::default()
    }

    pub fn create(self) -> NNS {
        let fixture = NNSFixture::new(NNSFixtureState {
            ledger: self.ledger_builder.create(),
            environment: self.environment_builder.create(),
        });
        let cmc: Box<dyn CMC> = Box::new(fixture.clone());
        let mut ledger: Box<dyn IcpLedger> = Box::new(fixture.clone());
        for t in self.ledger_transforms {
            ledger = t(ledger);
        }
        let mut environment: Box<dyn Environment> = Box::new(fixture.clone());
        for t in self.environment_transforms {
            environment = t(environment);
        }
        let mut nns = NNS {
            fixture: fixture.clone(),
            governance: Governance::new(self.governance, environment, ledger, cmc),
            initial_state: None,
        };
        nns.capture_state();
        nns
    }

    pub fn set_start_time(mut self, seconds: u64) -> Self {
        self.environment_builder.set_start_time(seconds);
        self
    }

    pub fn push_mock_reply(mut self, canister_call_reply: CanisterCallReply) -> Self {
        self.environment_builder
            .push_mock_reply(canister_call_reply);
        self
    }

    pub fn set_economics(mut self, econ: NetworkEconomics) -> Self {
        self.governance.economics = Some(econ);
        self
    }

    pub fn set_wait_for_quiet_threshold_seconds(mut self, seconds: u64) -> Self {
        self.governance.wait_for_quiet_threshold_seconds = seconds;
        self
    }

    /// At the moment the functionality of this operation is not used by any
    /// tests.
    pub fn set_block_height(self, _height: u64) -> Self {
        self
    }

    pub fn with_supply(mut self, amount: u64) -> Self {
        self.ledger_builder
            .add_account(LedgerBuilder::minting_account(), amount);
        self
    }

    pub fn add_account_for(mut self, ident: PrincipalId, amount: u64) -> Self {
        self.ledger_builder
            .add_account(AccountIdentifier::new(ident, None), amount);
        self
    }

    pub fn add_neuron(mut self, neuron: NeuronBuilder) -> Self {
        if let Some(owner) = neuron.owner {
            self.ledger_builder
                .try_add_account(AccountIdentifier::new(owner, None), 0);
        }
        self.governance.neurons.insert(
            neuron.ident,
            neuron.create(
                self.environment_builder.environment_fixture_state.now,
                &mut self.ledger_builder,
            ),
        );
        self
    }

    pub fn add_neurons(self, neurons: impl IntoIterator<Item = (Neuron, u64)>) -> Self {
        neurons.into_iter().fold(self, |b, (neuron, id)| {
            b.add_neuron(
                NeuronBuilder::from(neuron)
                    .set_ident(id)
                    .set_owner(principal(id)),
            )
        })
    }

    #[allow(dead_code)]
    pub fn get_neuron(&self, ident: u64) -> Option<&Neuron> {
        self.governance.neurons.get(&ident)
    }

    /// Transform the ledger just before it's built, e.g., to allow blocking on
    /// its calls for interleaving tests. Multiple transformations can be
    /// chained; they are applied in the order in which they were added.
    pub fn add_ledger_transform(mut self, transform: LedgerTransform) -> Self {
        self.ledger_transforms.push(transform);
        self
    }

    pub fn add_environment_transform(mut self, transform: EnvironmentTransform) -> Self {
        self.environment_transforms.push(transform);
        self
    }

    pub fn add_proposal(mut self, proposal_data: ProposalData) -> Self {
        self.governance
            .proposals
            .insert(proposal_data.id.unwrap().id, proposal_data);
        self
    }
}

#[macro_export]
macro_rules! assert_changes {
    ($nns:expr, $expected:expr) => {{
        let new_state = $nns.get_state();
        comparable::pretty_assert_changes!(
            $nns.initial_state
                .as_ref()
                .expect("initial_state was never set"),
            &new_state,
            $expected,
        );
        $nns.initial_state = Some(new_state);
    }};
}

#[macro_export]
macro_rules! prop_assert_changes {
    ($nns:expr, $expected:expr) => {{
        let new_state = $nns.get_state();
        comparable::prop_pretty_assert_changes!(
            $nns.initial_state
                .as_ref()
                .expect("initial_state was never set"),
            &new_state,
            $expected,
        );
        $nns.initial_state = Some(new_state);
    }};
}
