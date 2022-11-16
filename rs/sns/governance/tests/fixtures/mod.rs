use async_trait::async_trait;
use futures::future::FutureExt;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1::{Account, Subaccount};
use ic_ledger_core::Tokens;
use ic_nervous_system_common::NervousSystemError;
use ic_sns_governance::{
    governance::{Governance, ValidGovernanceProto},
    ledger::ICRC1Ledger,
    pb::v1::{
        get_neuron_response,
        governance::{Mode, SnsMetadata},
        manage_neuron,
        manage_neuron::MergeMaturity,
        manage_neuron_response,
        manage_neuron_response::MergeMaturityResponse,
        neuron::{DissolveState, Followees},
        GetNeuron, Governance as GovernanceProto, GovernanceError, ManageNeuron,
        ManageNeuronResponse, NervousSystemParameters, Neuron, NeuronId, NeuronPermission,
    },
    types::{Environment, HeapGrowthPotential},
};
use maplit::btreemap;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::{
    collections::BTreeMap,
    convert::TryFrom,
    sync::{Arc, Mutex},
};

const DEFAULT_TEST_START_TIMESTAMP_SECONDS: u64 = 999_111_000_u64;

/// Constructs a neuron id from a principal_id and memo. This is a
/// convenient helper method in tests.
pub fn neuron_id(principal_id: PrincipalId, memo: u64) -> NeuronId {
    NeuronId::from(
        ic_nervous_system_common::ledger::compute_neuron_staking_subaccount_bytes(
            principal_id,
            memo,
        ),
    )
}

/// The LedgerFixture allows for independent testing of Ledger functionality.
#[derive(Clone)]
pub struct LedgerFixture {
    ledger_fixture_state: Arc<Mutex<LedgerFixtureState>>,
}

impl LedgerFixture {
    pub fn new(state: LedgerFixtureState) -> Self {
        LedgerFixture {
            ledger_fixture_state: Arc::new(Mutex::new(state)),
        }
    }
}

#[async_trait]
impl ICRC1Ledger for LedgerFixture {
    async fn transfer_funds(
        &self,
        amount_e8s: u64,
        fee_e8s: u64,
        from_subaccount: Option<Subaccount>,
        to: Account,
        _memo: u64,
    ) -> Result<u64, NervousSystemError> {
        let ledger_fixture_state = &mut self.ledger_fixture_state.try_lock().unwrap();

        let self_canister_id = ledger_fixture_state.self_canister_id;
        let from_account = Account {
            owner: self_canister_id.get(),
            subaccount: from_subaccount,
        };

        println!(
            "Issuing ledger transfer from account {} (subaccount {}) to account {} amount {} fee {}",
            from_account,
            from_subaccount.as_ref().map_or_else(||"None".to_string(), |a| format!("{:?}", a)),
            to,
            amount_e8s,
            fee_e8s
        );

        let _to_e8s = ledger_fixture_state
            .accounts
            .get(&to)
            .ok_or_else(|| NervousSystemError::new_with_message("Target account doesn't exist"))?;
        let from_e8s = ledger_fixture_state
            .accounts
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

        *ledger_fixture_state.accounts.entry(to).or_default() += amount_e8s;

        ledger_fixture_state.block_height += 1;

        Ok(ledger_fixture_state.block_height)
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        let accounts = &mut self.ledger_fixture_state.try_lock().unwrap().accounts;

        Ok(Tokens::from_e8s(accounts.iter().map(|(_, y)| y).sum()))
    }

    async fn account_balance(&self, account: Account) -> Result<Tokens, NervousSystemError> {
        let accounts = &mut self.ledger_fixture_state.try_lock().unwrap().accounts;
        let account_e8s = accounts.get(&account).unwrap_or(&0);
        Ok(Tokens::from_e8s(*account_e8s))
    }

    fn canister_id(&self) -> CanisterId {
        self.ledger_fixture_state
            .try_lock()
            .unwrap()
            .target_canister_id
    }
}

/// The LedgerFixtureState captures the state of a given LedgerFixture instance.
/// This state is used to inspect properly issued ledger calls from Governance.
pub struct LedgerFixtureState {
    accounts: BTreeMap<Account, u64>,
    self_canister_id: CanisterId,
    target_canister_id: CanisterId,
    block_height: u64,
}

/// The builder for the LedgerFixture. This allows for setting up the state
/// of the LedgerFixture before its instantiated.
pub struct LedgerFixtureBuilder {
    accounts: BTreeMap<Account, u64>,
    self_canister_id: CanisterId,
    target_canister_id: CanisterId,
    block_height: u64,
}

impl LedgerFixtureBuilder {
    pub fn new(self_canister_id: CanisterId, target_canister_id: CanisterId) -> Self {
        LedgerFixtureBuilder {
            accounts: btreemap! {},
            self_canister_id,
            target_canister_id,
            block_height: 0,
        }
    }

    pub fn create(self) -> LedgerFixture {
        LedgerFixture::new(LedgerFixtureState {
            accounts: self.accounts,
            self_canister_id: self.self_canister_id,
            target_canister_id: self.target_canister_id,
            block_height: self.block_height,
        })
    }

    pub fn add_account(&mut self, ident: Account, amount: u64) -> &mut Self {
        self.accounts.insert(ident, amount);
        self
    }

    pub fn try_add_account(&mut self, ident: Account, amount: u64) -> &mut Self {
        self.accounts.entry(ident).or_insert(amount);
        self
    }

    pub fn account_id(ident: PrincipalId) -> Account {
        Account {
            owner: ident,
            subaccount: None,
        }
    }

    pub fn get_account_balance(&self, ident: Account) -> Option<u64> {
        self.accounts.get(&ident).copied()
    }
}

/// The NeuronBuilder is used for creating neurons on behalf of the governance
/// canister. The principal id and subaccount identifier are both derived from
/// the neuron id, which is provided by the caller.
pub struct NeuronBuilder {
    id: Option<NeuronId>,
    stake_e8s: u64,
    permissions: Vec<NeuronPermission>,
    age_timestamp: Option<u64>,
    created_seconds: Option<u64>,
    maturity: u64,
    neuron_fees: u64,
    dissolve_state: Option<DissolveState>,
    followees: BTreeMap<u64, Followees>,
    voting_power_percentage_multiplier: u64,
}

impl From<Neuron> for NeuronBuilder {
    fn from(neuron: Neuron) -> Self {
        NeuronBuilder {
            id: neuron.id,
            stake_e8s: neuron.cached_neuron_stake_e8s,
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
            voting_power_percentage_multiplier: neuron.voting_power_percentage_multiplier,
        }
    }
}

impl NeuronBuilder {
    pub fn new_without_owner(id: NeuronId, stake: u64) -> Self {
        NeuronBuilder {
            id: Some(id),
            stake_e8s: stake,
            permissions: vec![],
            age_timestamp: None,
            created_seconds: None,
            maturity: 0,
            neuron_fees: 0,
            dissolve_state: None,
            followees: BTreeMap::new(),
            voting_power_percentage_multiplier: 100,
        }
    }

    pub fn new(id: NeuronId, stake_e8s: u64, owner: NeuronPermission) -> Self {
        NeuronBuilder {
            id: Some(id),
            stake_e8s,
            permissions: vec![owner],
            age_timestamp: None,
            created_seconds: None,
            maturity: 0,
            neuron_fees: 0,
            dissolve_state: None,
            followees: BTreeMap::new(),
            voting_power_percentage_multiplier: 100,
        }
    }

    pub fn create(self, now: u64, ledger: &mut LedgerFixtureBuilder) -> Neuron {
        if let Some(id) = self.id.as_ref() {
            let subaccount = id.subaccount().unwrap();
            let neuron_account = Account {
                owner: ledger.self_canister_id.get(),
                subaccount: Some(subaccount),
            };
            ledger.add_account(neuron_account, self.stake_e8s);
        }

        Neuron {
            id: self.id,
            permissions: self.permissions,
            cached_neuron_stake_e8s: self.stake_e8s,
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
            voting_power_percentage_multiplier: self.voting_power_percentage_multiplier,
            source_nns_neuron_id: None,
            staked_maturity_e8s_equivalent: None,
            auto_stake_maturity: None,
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

    pub fn set_voting_power_percentage_multiplier(
        mut self,
        voting_power_percentage_multiplier: u64,
    ) -> Self {
        self.voting_power_percentage_multiplier = voting_power_percentage_multiplier;
        self
    }

    pub fn add_followees(mut self, function_id: u64, followees: Followees) -> Self {
        self.followees.insert(function_id, followees);
        self
    }
}

/// The EnvironmentFixture allows for independent testing of Environment functionality.
#[derive(Clone)]
pub struct EnvironmentFixture {
    environment_fixture_state: Arc<Mutex<EnvironmentFixtureState>>,
}

impl EnvironmentFixture {
    pub fn new(state: EnvironmentFixtureState) -> Self {
        EnvironmentFixture {
            environment_fixture_state: Arc::new(Mutex::new(state)),
        }
    }
}

#[async_trait]
impl Environment for EnvironmentFixture {
    fn now(&self) -> u64 {
        self.environment_fixture_state.try_lock().unwrap().now
    }

    fn random_u64(&mut self) -> u64 {
        self.environment_fixture_state
            .try_lock()
            .unwrap()
            .rng
            .next_u64()
    }

    fn random_byte_array(&mut self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.environment_fixture_state
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
        self.environment_fixture_state
            .try_lock()
            .unwrap()
            .canister_id
    }
}

/// The EnvironmentFixtureState captures the state of a given EnvironmentFixture instance.
/// This state is used to respond to environment calls from Governance in a deterministic way.
pub struct EnvironmentFixtureState {
    now: u64,
    rng: StdRng,
    canister_id: CanisterId,
}

/// The GovernanceState is used to capture all of the salient details of the Governance
/// canister, so that we can compute the "delta", or what changed between
/// actions.
#[derive(Clone, Default, comparable::Comparable, Debug)]
#[compare_default]
pub struct GovernanceState {
    pub now: u64,
    pub sns_accounts: BTreeMap<Account, u64>,
    pub icp_accounts: BTreeMap<Account, u64>,
    pub governance_proto: GovernanceProto,
    // Attributes from `Governance`, which itself is not cloneable
    pub latest_gc_num_proposals: usize,
}

/// The GovernanceCanisterFixture is the root in the fixture hierarchy. It owns all fixtures
/// and ultimately the Governance struct under test. The GovernanceCanisterFixture provides
/// many helper methods for common calls, but allows for tests to operate directly on the
/// low level fixtures if needed.
pub struct GovernanceCanisterFixture {
    pub environment_fixture: EnvironmentFixture,
    pub icp_ledger_fixture: LedgerFixture,
    pub sns_ledger_fixture: LedgerFixture,
    pub governance: Governance,
    pub(crate) initial_state: Option<GovernanceState>,
}

impl GovernanceCanisterFixture {
    /// Increases the time by the given amount.
    pub fn advance_time_by(&mut self, delta_seconds: u64) -> &mut Self {
        self.environment_fixture
            .environment_fixture_state
            .lock()
            .unwrap()
            .now += delta_seconds;
        self
    }

    pub fn capture_state(&mut self) -> &mut Self {
        self.initial_state = Some(self.get_state());
        self
    }

    pub fn get_state(&self) -> GovernanceState {
        GovernanceState {
            now: self
                .environment_fixture
                .environment_fixture_state
                .try_lock()
                .unwrap()
                .now,
            sns_accounts: self
                .sns_ledger_fixture
                .ledger_fixture_state
                .try_lock()
                .unwrap()
                .accounts
                .clone(),
            icp_accounts: self
                .icp_ledger_fixture
                .ledger_fixture_state
                .try_lock()
                .unwrap()
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

    pub fn get_neuron(&self, neuron_id: &NeuronId) -> Neuron {
        let result = self
            .governance
            .get_neuron(GetNeuron {
                neuron_id: Some(neuron_id.clone()),
            })
            .result
            .unwrap();

        match result {
            get_neuron_response::Result::Neuron(neuron) => neuron,
            get_neuron_response::Result::Error(err) => panic!("Expected Neuron to exist: {}", err),
        }
    }

    pub fn get_account_balance(&self, account: &Account, target_ledger: TargetLedger) -> u64 {
        let ledger_fixture = match target_ledger {
            TargetLedger::Icp => &self.icp_ledger_fixture,
            TargetLedger::Sns => &self.sns_ledger_fixture,
        };
        ledger_fixture
            .account_balance(account.clone())
            .now_or_never()
            .unwrap()
            .unwrap()
            .get_e8s()
    }

    pub fn get_neuron_account_id(&self, neuron_id: &NeuronId) -> Account {
        self.governance
            .neuron_account_id(neuron_id.subaccount().unwrap())
    }

    pub async fn get_neuron_stake_e8s(&self, neuron: &Neuron) -> u64 {
        self.sns_ledger_fixture
            .account_balance(self.get_neuron_account_id(neuron.id.as_ref().unwrap()))
            .await
            .unwrap()
            .get_e8s()
    }

    pub fn manage_neuron(
        &mut self,
        target_neuron: &NeuronId,
        manage_neuron_command: manage_neuron::Command,
        caller: &PrincipalId,
    ) -> ManageNeuronResponse {
        self.governance
            .manage_neuron(
                &ManageNeuron {
                    subaccount: target_neuron.clone().id,
                    command: Some(manage_neuron_command),
                },
                caller,
            )
            .now_or_never()
            .unwrap()
    }

    pub fn now(&self) -> u64 {
        self.environment_fixture.now()
    }

    pub fn get_nervous_system_parameters(&self) -> &NervousSystemParameters {
        self.governance.proto.parameters.as_ref().unwrap()
    }
}

pub type LedgerTransform = Box<dyn FnOnce(Box<dyn ICRC1Ledger>) -> Box<dyn ICRC1Ledger>>;

/// The GovernanceCanisterFixtureBuilder permits the declarative construction
/// of an GovernanceCanisterFixture. All of the methods concern setting or
/// querying what this initial state will be. Therefore, `get_account_balance`
/// on a builder object will only tell you what the account will be once
/// the GovernanceCanisterFixture is created, which is different from calling
/// `get_account_balance` on the resulting fixture, even though it will
/// initially be the same amount.
pub struct GovernanceCanisterFixtureBuilder {
    start_time: u64,
    governance_canister_id: CanisterId,
    governance: GovernanceProto,
    /// Transform the SNS ledger just before it's built, e.g., to allow blocking on
    /// its calls for interleaving tests. Multiple transformations can be
    /// chained; they are applied in the order in which they were added.
    sns_ledger_transforms: Vec<LedgerTransform>,
    /// Transform the ICP ledger just before it's built, e.g., to allow blocking on
    /// its calls for interleaving tests. Multiple transformations can be
    /// chained; they are applied in the order in which they were added.
    icp_ledger_transforms: Vec<LedgerTransform>,
    sns_ledger_builder: LedgerFixtureBuilder,
    icp_ledger_builder: LedgerFixtureBuilder,
}

impl Default for GovernanceCanisterFixtureBuilder {
    fn default() -> Self {
        let (
            governance_canister_id,
            root_canister_id,
            sns_ledger_canister_id,
            icp_ledger_canister_id,
            swap_canister_id,
        ) = (
            CanisterId::from_u64(0),
            CanisterId::from_u64(1),
            CanisterId::from_u64(2),
            CanisterId::from_u64(3),
            CanisterId::from_u64(4),
        );

        GovernanceCanisterFixtureBuilder {
            start_time: DEFAULT_TEST_START_TIMESTAMP_SECONDS,
            governance: GovernanceProto {
                root_canister_id: Some(root_canister_id.get()),
                ledger_canister_id: Some(sns_ledger_canister_id.get()),
                swap_canister_id: Some(swap_canister_id.get()),
                mode: Mode::Normal as i32,
                sns_metadata: Some(SnsMetadata::with_default_values_for_testing()),
                parameters: Some(NervousSystemParameters::with_default_values()),
                ..Default::default()
            },
            sns_ledger_transforms: Vec::default(),
            icp_ledger_transforms: Vec::default(),
            governance_canister_id,
            sns_ledger_builder: LedgerFixtureBuilder::new(
                governance_canister_id,
                sns_ledger_canister_id,
            ),
            icp_ledger_builder: LedgerFixtureBuilder::new(
                governance_canister_id,
                icp_ledger_canister_id,
            ),
        }
    }
}

/// Enum representing the different ledgers that the GovernanceCanisterFixture can query or update.
pub enum TargetLedger {
    Icp,
    Sns,
}

impl GovernanceCanisterFixtureBuilder {
    pub fn new() -> Self {
        GovernanceCanisterFixtureBuilder::default()
    }

    pub fn create(self) -> GovernanceCanisterFixture {
        let environment_fixture = EnvironmentFixture::new(EnvironmentFixtureState {
            now: self.start_time,
            rng: StdRng::seed_from_u64(9539),
            canister_id: self.governance_canister_id,
        });

        let sns_ledger_fixture = self.sns_ledger_builder.create();
        let mut sns_ledger: Box<dyn ICRC1Ledger> = Box::new(sns_ledger_fixture.clone());
        for t in self.sns_ledger_transforms {
            sns_ledger = t(sns_ledger);
        }

        let icp_ledger_fixture = self.icp_ledger_builder.create();
        let mut icp_ledger: Box<dyn ICRC1Ledger> = Box::new(icp_ledger_fixture.clone());
        for t in self.icp_ledger_transforms {
            icp_ledger = t(icp_ledger);
        }

        let valid_governance = ValidGovernanceProto::try_from(self.governance).unwrap();
        let mut governance = GovernanceCanisterFixture {
            environment_fixture: environment_fixture.clone(),
            icp_ledger_fixture,
            sns_ledger_fixture,
            governance: Governance::new(
                valid_governance,
                Box::new(environment_fixture),
                sns_ledger,
                icp_ledger,
            ),
            initial_state: None,
        };
        governance.capture_state();
        governance
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

    pub fn add_account_for(
        mut self,
        principal_id: PrincipalId,
        amount: u64,
        target_ledger: TargetLedger,
    ) -> Self {
        self.ledger_builder_from_target_mut(target_ledger)
            .add_account(
                Account {
                    owner: principal_id,
                    subaccount: None,
                },
                amount,
            );
        self
    }

    pub fn get_account_balance(&self, ident: Account, target_ledger: TargetLedger) -> Option<u64> {
        self.ledger_builder_from_target(target_ledger)
            .get_account_balance(ident)
    }

    pub fn add_neuron(mut self, neuron: NeuronBuilder) -> Self {
        if let Some(owner) = neuron.get_owner() {
            self.sns_ledger_builder.try_add_account(
                Account {
                    owner,
                    subaccount: None,
                },
                0,
            );
        }

        if let Some(ref neuron_id) = neuron.id {
            self.governance.neurons.insert(
                neuron_id.to_string(),
                neuron.create(self.start_time, &mut self.sns_ledger_builder),
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
    pub fn add_ledger_transform(
        mut self,
        transform: LedgerTransform,
        target_ledger: TargetLedger,
    ) -> Self {
        match target_ledger {
            TargetLedger::Icp => self.icp_ledger_transforms.push(transform),
            TargetLedger::Sns => self.sns_ledger_transforms.push(transform),
        };
        self
    }

    pub fn ledger_builder_from_target(&self, target_ledger: TargetLedger) -> &LedgerFixtureBuilder {
        match target_ledger {
            TargetLedger::Icp => &self.icp_ledger_builder,
            TargetLedger::Sns => &self.sns_ledger_builder,
        }
    }

    pub fn ledger_builder_from_target_mut(
        &mut self,
        target_ledger: TargetLedger,
    ) -> &mut LedgerFixtureBuilder {
        match target_ledger {
            TargetLedger::Icp => &mut self.icp_ledger_builder,
            TargetLedger::Sns => &mut self.sns_ledger_builder,
        }
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
