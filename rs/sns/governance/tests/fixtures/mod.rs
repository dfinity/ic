use async_trait::async_trait;
use futures::future::FutureExt;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::{ledger::Ledger, NervousSystemError};
use ic_sns_governance::governance::{
    governance_minting_account, neuron_account_id, Governance, TimeWarp, ValidGovernanceProto,
};
use ic_sns_governance::pb::v1::manage_neuron::MergeMaturity;
use ic_sns_governance::pb::v1::manage_neuron_response::MergeMaturityResponse;
use ic_sns_governance::pb::v1::neuron::{DissolveState, Followees};
use ic_sns_governance::pb::v1::Governance as GovernanceProto;
use ic_sns_governance::pb::v1::{
    get_neuron_response, manage_neuron, manage_neuron_response, proposal, GetNeuron,
    GovernanceError, ManageNeuron, ManageNeuronResponse, Motion, NervousSystemParameters, Neuron,
    NeuronId, NeuronPermission, NeuronPermissionType, Proposal, ProposalId, Vote,
};
use ic_sns_governance::types::{native_action_ids, Environment, HeapGrowthPotential};
use ledger_canister::{AccountIdentifier, Subaccount, Tokens};
use rand::rngs::StdRng;
use rand_core::{RngCore, SeedableRng};
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::sync::Arc;
use std::sync::Mutex;

const DEFAULT_TEST_START_TIMESTAMP_SECONDS: u64 = 999_111_000_u64;

type LedgerMap = BTreeMap<AccountIdentifier, u64>;

/// Constructs a test principal id from an NeuronId.
/// Convenience functions to make creating neurons more concise.
pub fn principal(neuron_id: &NeuronId) -> PrincipalId {
    let first_byte = neuron_id.id.get(0).unwrap();
    PrincipalId::try_from(format!("SID{}", first_byte).as_bytes().to_vec()).unwrap()
}

pub fn get_proposal_submission_principal(neuron: &Neuron) -> Result<PrincipalId, String> {
    for neuron_permission in &neuron.permissions {
        if neuron_permission
            .permission_type
            .contains(&(NeuronPermissionType::SubmitProposal as i32))
        {
            return Ok(neuron_permission.principal.unwrap());
        }
    }

    Err(format!(
        "Neuron {} has no permissions with NeuronPermissionType::MakeProposal",
        neuron.id.as_ref().unwrap()
    ))
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
#[derive(Default)]
pub struct LedgerFixture {
    accounts: LedgerMap,
}

impl LedgerFixture {
    pub fn get_supply(&self) -> Tokens {
        Tokens::from_e8s(self.accounts.iter().map(|(_, y)| y).sum())
    }
}

#[derive(Default)]
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

    pub fn account_id(ident: PrincipalId) -> AccountIdentifier {
        AccountIdentifier::new(ident, None)
    }

    pub fn get_account_balance(&self, ident: AccountIdentifier) -> Option<u64> {
        self.ledger_fixture.accounts.get(&ident).copied()
    }
}

/// The NeuronBuilder is used for creating neurons on behalf of the governance
/// canister. The principal id and subaccount identifier are both derived from
/// the neuron id, which is provided by the caller.
pub struct NeuronBuilder {
    id: Option<NeuronId>,
    stake: u64,
    permissions: Vec<NeuronPermission>,
    age_timestamp: Option<u64>,
    created_seconds: Option<u64>,
    maturity: u64,
    neuron_fees: u64,
    dissolve_state: Option<DissolveState>,
    followees: BTreeMap<u64, Followees>,
}

impl From<Neuron> for NeuronBuilder {
    fn from(neuron: Neuron) -> Self {
        NeuronBuilder {
            id: neuron.id,
            stake: neuron.cached_neuron_stake_e8s,
            permissions: vec![],
            age_timestamp: if neuron.aging_since_timestamp_seconds == u64::MAX {
                None
            } else {
                Some(neuron.aging_since_timestamp_seconds)
            },
            created_seconds: Some(neuron.created_timestamp_seconds),
            maturity: neuron.maturity_e8s_equivalent,
            neuron_fees: neuron.neuron_fees_e8s,
            dissolve_state: neuron.dissolve_state,
            followees: neuron.followees,
        }
    }
}

impl NeuronBuilder {
    pub fn new_without_owner(id: NeuronId, stake: u64) -> Self {
        NeuronBuilder {
            id: Some(id),
            stake,
            permissions: vec![],
            age_timestamp: None,
            created_seconds: None,
            maturity: 0,
            neuron_fees: 0,
            dissolve_state: None,
            followees: BTreeMap::new(),
        }
    }

    pub fn new(id: NeuronId, stake: u64, owner: NeuronPermission) -> Self {
        NeuronBuilder {
            id: Some(id),
            stake,
            permissions: vec![owner],
            age_timestamp: None,
            created_seconds: None,
            maturity: 0,
            neuron_fees: 0,
            dissolve_state: None,
            followees: BTreeMap::new(),
        }
    }

    pub fn set_dissolve_delay(mut self, seconds: u64) -> Self {
        self.dissolve_state = Some(DissolveState::DissolveDelaySeconds(seconds));
        self
    }

    pub fn add_neuron_permission(mut self, neuron_permission: NeuronPermission) -> Self {
        self.permissions.push(neuron_permission);
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

    pub fn set_creation_timestamp(mut self, secs: u64) -> Self {
        self.created_seconds = Some(secs);
        self
    }

    pub fn set_aging_since_timestamp(mut self, secs: u64) -> Self {
        self.age_timestamp = Some(secs);
        self
    }

    pub fn start_dissolving(mut self, now: u64) -> Self {
        if let Some(DissolveState::DissolveDelaySeconds(secs)) = self.dissolve_state {
            self.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(now + secs));
        }
        self
    }

    pub fn get_owner(&self) -> Option<PrincipalId> {
        if self.permissions.is_empty() {
            return None;
        }

        self.permissions[0].principal
    }

    pub fn set_dissolve_state(mut self, state: Option<DissolveState>) -> Self {
        self.dissolve_state = state;
        self
    }

    pub fn create(self, now: u64, ledger: &mut LedgerBuilder) -> Neuron {
        if let Some(id) = self.id.as_ref() {
            let subaccount = id.subaccount().unwrap();
            ledger.add_account(neuron_account_id(subaccount), self.stake);
        }

        Neuron {
            id: self.id,
            permissions: self.permissions,
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
            dissolve_state: self.dissolve_state,
            followees: self.followees,
        }
    }

    pub fn add_followees(mut self, function_id: u64, followees: Followees) -> Self {
        self.followees.insert(function_id, followees);
        self
    }
}

pub struct SNSFixtureState {
    now: u64,
    rng: StdRng,
    ledger: LedgerFixture,
}

#[derive(Clone)]
pub struct SNSFixture {
    sns_state: Arc<Mutex<SNSFixtureState>>,
}

impl SNSFixture {
    pub fn new(state: SNSFixtureState) -> Self {
        SNSFixture {
            sns_state: Arc::new(Mutex::new(state)),
        }
    }
}

#[async_trait]
impl Ledger for SNSFixture {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to_account: AccountIdentifier,
        _: u64,
    ) -> Result<u64, NervousSystemError> {
        let from_account = from_subaccount.map_or(governance_minting_account(), neuron_account_id);
        println!(
            "Issuing ledger transfer from account {} (subaccount {}) to account {} amount {} fee {}",
            from_account, from_subaccount.as_ref().map_or_else(||"None".to_string(), ToString::to_string), to_account, amount_e8s, fee_e8s
        );
        let accounts = &mut self.sns_state.try_lock().unwrap().ledger.accounts;

        let _to_e8s = accounts
            .get(&to_account)
            .ok_or_else(|| NervousSystemError::new_with_message("Target account doesn't exist"))?;
        let from_e8s = accounts
            .get_mut(&from_account)
            .ok_or_else(|| NervousSystemError::new_with_message("Source account doesn't exist"))?;

        let requested_e8s = amount_e8s + fee_e8s;

        if *from_e8s < requested_e8s {
            return Err(NervousSystemError::new_with_message(format!(
                "Insufficient funds. Available {} requested {}",
                *from_e8s, requested_e8s
            )));
        }

        *from_e8s -= requested_e8s;

        *accounts.entry(to_account).or_default() += amount_e8s;

        Ok(0)
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        Ok(self.sns_state.try_lock().unwrap().ledger.get_supply())
    }

    async fn account_balance(
        &self,
        account: AccountIdentifier,
    ) -> Result<Tokens, NervousSystemError> {
        let accounts = &mut self.sns_state.try_lock().unwrap().ledger.accounts;
        let account_e8s = accounts.get(&account).unwrap_or(&0);
        Ok(Tokens::from_e8s(*account_e8s))
    }
}

#[async_trait]
impl Environment for SNSFixture {
    fn now(&self) -> u64 {
        self.sns_state.try_lock().unwrap().now
    }

    fn random_u64(&mut self) -> u64 {
        self.sns_state.try_lock().unwrap().rng.next_u64()
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.sns_state
            .try_lock()
            .unwrap()
            .rng
            .fill_bytes(&mut bytes);
        bytes
    }

    async fn call_canister(
        &self,
        _canister_id: CanisterId,
        _method_name: &str,
        _arg: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        unimplemented!("call_canister is unimplemented")
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        HeapGrowthPotential::NoIssue
    }

    fn canister_id(&self) -> CanisterId {
        CanisterId::from_u64(1)
    }
}

/// The SNSState is used to capture all of the salient details of the SNS
/// environment, so that we can compute the "delta", or what changed between
/// actions.
#[derive(Clone, Default)]
#[cfg_attr(feature = "test", derive(comparable::Comparable), compare_default)]
pub struct SNSState {
    now: u64,
    accounts: LedgerMap,
    governance_proto: GovernanceProto,
    // Attributes from `Governance`, which itself is not cloneable
    latest_gc_num_proposals: usize,
}

/// A struct to help setting up tests concisely thanks to a concise format to
/// specifies who proposes something and who votes on that proposal.
pub struct ProposalNeuronBehavior {
    /// Neuron id of the proposer.
    proposer: Neuron,
    /// Map neuron id of voters to their votes.
    votes: BTreeMap<NeuronId, Vote>,
    /// Keep track of proposal actions to use.
    proposal_action: u64,
}

impl ProposalNeuronBehavior {
    /// Creates a proposal from the specified proposer, and register the
    /// specified votes.
    ///
    /// This function assumes that:
    /// - neuron of id `i` has for controller `principal(i)`
    pub async fn propose_and_vote(&self, sns: &mut SNS, summary: String) -> ProposalId {
        // Submit proposal
        let action = match self.proposal_action {
            native_action_ids::MOTION => proposal::Action::Motion(Motion {
                motion_text: format!("summary: {}", summary),
            }),
            _ => panic!("Unsupported proposal_action"),
        };
        let pid = sns
            .governance
            .make_proposal(
                self.proposer.id.as_ref().unwrap(),
                &get_proposal_submission_principal(&self.proposer).unwrap(),
                &Proposal {
                    title: "A Reasonable Title".to_string(),
                    summary,
                    action: Some(action),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // Vote
        for (voter, vote) in &self.votes {
            sns.register_vote_assert_success(principal(voter), voter.clone(), pid, *vote);
        }
        pid
    }
}

#[allow(clippy::upper_case_acronyms)]
pub struct SNS {
    pub fixture: SNSFixture,
    pub governance: Governance,
    pub(crate) initial_state: Option<SNSState>,
}

impl SNS {
    /// Increases the time by the given amount.
    pub fn advance_time_by(&mut self, delta_seconds: u64) -> &mut Self {
        self.fixture.sns_state.lock().unwrap().now += delta_seconds;
        self
    }

    pub fn capture_state(&mut self) -> &mut Self {
        self.initial_state = Some(self.get_state());
        self
    }

    pub(crate) fn get_state(&self) -> SNSState {
        SNSState {
            now: self.now(),
            accounts: self
                .fixture
                .sns_state
                .try_lock()
                .unwrap()
                .ledger
                .accounts
                .clone(),
            governance_proto: self.governance.proto.clone(),
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
            subaccount: neuron_id.subaccount().unwrap().to_vec(),
            command: Some(manage_neuron::Command::RegisterVote(
                manage_neuron::RegisterVote {
                    proposal: Some(pid),
                    vote: vote as i32,
                },
            )),
        };
        self.governance
            .manage_neuron(&manage_neuron, &caller)
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
    pub async fn propose_with_action(
        &mut self,
        prop: &ProposalNeuronBehavior,
        summary: String,
        action: proposal::Action,
    ) -> ProposalId {
        // Submit proposal
        self.governance
            .make_proposal(
                prop.proposer.id.as_ref().unwrap(),
                &get_proposal_submission_principal(&prop.proposer).unwrap(),
                &Proposal {
                    title: "A Reasonable Title".to_string(),
                    summary,
                    action: Some(action),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
    }

    pub async fn propose_and_vote(
        &mut self,
        behavior: impl Into<ProposalNeuronBehavior>,
        summary: String,
    ) -> ProposalId {
        behavior.into().propose_and_vote(self, summary).await
    }

    pub fn merge_maturity(
        &mut self,
        neuron_id: &NeuronId,
        controller: &PrincipalId,
        percentage_to_merge: u32,
    ) -> Result<MergeMaturityResponse, GovernanceError> {
        let result = self
            .governance
            .manage_neuron(
                &ManageNeuron {
                    subaccount: neuron_id.subaccount().unwrap().to_vec(),
                    command: Some(manage_neuron::Command::MergeMaturity(MergeMaturity {
                        percentage_to_merge,
                    })),
                },
                controller,
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

    pub fn get_neuron(&self, neuron_id: &NeuronId) -> Result<Neuron, GovernanceError> {
        let result = self
            .governance
            .get_neuron(GetNeuron {
                neuron_id: Some(neuron_id.clone()),
            })
            .result
            .unwrap();

        match result {
            get_neuron_response::Result::Neuron(neuron) => Ok(neuron),
            get_neuron_response::Result::Error(err) => Err(err),
        }
    }

    pub fn get_account_balance(&self, account: AccountIdentifier) -> u64 {
        self.account_balance(account)
            .now_or_never()
            .unwrap()
            .unwrap()
            .get_e8s()
    }

    pub fn get_neuron_account_id(&self, neuron_id: &NeuronId) -> AccountIdentifier {
        neuron_account_id(neuron_id.subaccount().unwrap())
    }

    pub fn get_neuron_stake(&self, neuron: &Neuron) -> u64 {
        self.get_account_balance(self.get_neuron_account_id(neuron.id.as_ref().unwrap()))
    }
}

#[async_trait]
impl Ledger for SNS {
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
}

#[async_trait]
impl Environment for SNS {
    fn now(&self) -> u64 {
        self.fixture.now()
    }

    fn set_time_warp(&mut self, _new_time_warp: TimeWarp) {
        unimplemented!()
    }

    fn random_u64(&mut self) -> u64 {
        self.fixture.random_u64()
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        self.fixture.random_byte_array()
    }

    async fn call_canister(
        &self,
        canister_id: CanisterId,
        method_name: &str,
        arg: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        self.fixture
            .call_canister(canister_id, method_name, arg)
            .await
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        self.fixture.heap_growth_potential()
    }

    fn canister_id(&self) -> CanisterId {
        self.fixture.canister_id()
    }
}

pub type LedgerTransform = Box<dyn FnOnce(Box<dyn Ledger>) -> Box<dyn Ledger>>;

/// The SNSBuilder permits the declarative construction of an SNS fixture. All
/// of the methods concern setting or querying what this initial state will
/// be. Therefore, `get_account_balance` on a builder object will only tell
/// you what the account will be once the SNS fixture is created, which is
/// different from calling `get_account_balance` on the resulting fixture,
/// even though it will initially be the same amount.
pub struct SNSBuilder {
    start_time: u64,
    ledger_builder: LedgerBuilder,
    governance: GovernanceProto,
    ledger_transforms: Vec<LedgerTransform>,
}

impl Default for SNSBuilder {
    fn default() -> Self {
        SNSBuilder {
            start_time: DEFAULT_TEST_START_TIMESTAMP_SECONDS,
            ledger_builder: LedgerBuilder::default(),
            governance: GovernanceProto {
                ..Default::default()
            },
            ledger_transforms: Vec::default(),
        }
    }
}

impl SNSBuilder {
    pub fn new() -> Self {
        SNSBuilder::default()
    }

    pub fn create(self) -> SNS {
        let fixture = SNSFixture::new(SNSFixtureState {
            now: self.start_time,
            rng: StdRng::seed_from_u64(9539),
            ledger: self.ledger_builder.create(),
        });
        let mut ledger: Box<dyn Ledger> = Box::new(fixture.clone());
        for t in self.ledger_transforms {
            ledger = t(ledger);
        }

        let valid_governance = ValidGovernanceProto::try_from(self.governance).unwrap();
        let mut sns = SNS {
            fixture: fixture.clone(),
            governance: Governance::new(valid_governance, Box::new(fixture), ledger),
            initial_state: None,
        };
        sns.capture_state();
        sns
    }

    pub fn set_start_time(mut self, seconds: u64) -> Self {
        self.start_time = seconds;
        self
    }

    pub fn set_nervous_system_parameters(
        mut self,
        nervous_system_parameters: NervousSystemParameters,
    ) -> Self {
        self.governance.parameters = Some(nervous_system_parameters);
        self
    }

    pub fn set_block_height(self, _height: u64) -> Self {
        self
    }

    pub fn with_supply(mut self, amount: u64) -> Self {
        self.ledger_builder
            .add_account(LedgerBuilder::minting_account(), amount);
        self
    }

    pub fn add_account_for(mut self, principal_id: PrincipalId, amount: u64) -> Self {
        self.ledger_builder
            .add_account(AccountIdentifier::new(principal_id, None), amount);
        self
    }

    pub fn get_account_balance(&self, ident: AccountIdentifier) -> Option<u64> {
        self.ledger_builder.get_account_balance(ident)
    }

    pub fn add_neuron(mut self, neuron: NeuronBuilder) -> Self {
        if let Some(owner) = neuron.get_owner() {
            self.ledger_builder
                .try_add_account(AccountIdentifier::new(owner, None), 0);
        }

        if let Some(ref neuron_id) = neuron.id {
            self.governance.neurons.insert(
                neuron_id.to_string(),
                neuron.create(self.start_time, &mut self.ledger_builder),
            );
        }

        self
    }

    pub fn add_neurons(self, neurons: impl IntoIterator<Item = Neuron>) -> Self {
        neurons
            .into_iter()
            .fold(self, |b, neuron| b.add_neuron(NeuronBuilder::from(neuron)))
    }

    pub fn get_neuron(&self, neuron_id: NeuronId) -> Option<&Neuron> {
        self.governance.neurons.get(&neuron_id.to_string())
    }

    /// Transform the ledger just before it's built, e.g., to allow blocking on
    /// its calls for interleaving tests. Multiple transformations can be
    /// chained; they are applied in the order in which they were added.
    pub fn add_ledger_transform(mut self, transform: LedgerTransform) -> Self {
        self.ledger_transforms.push(transform);
        self
    }
}

#[macro_export]
macro_rules! assert_changes {
    ($sns:expr, $expected:expr) => {{
        let new_state = $sns.get_state();
        comparable::pretty_assert_changes!(
            $sns.initial_state
                .as_ref()
                .expect("initial_state was never set"),
            &new_state,
            $expected,
        );
        $sns.initial_state = Some(new_state);
    }};
}

#[macro_export]
macro_rules! prop_assert_changes {
    ($sns:expr, $expected:expr) => {{
        let new_state = $sns.get_state();
        comparable::prop_pretty_assert_changes!(
            $sns.initial_state
                .as_ref()
                .expect("initial_state was never set"),
            &new_state,
            $expected,
        );
        $sns.initial_state = Some(new_state);
    }};
}
