#![allow(dead_code)]
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::TryFrom;
use std::fmt;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::SystemTime;

use crossbeam::channel::{bounded, Receiver as CBReceiver, Sender as CBSender};
use ic_nns_governance::pb::v1::manage_neuron::NeuronIdOrSubaccount;
use rand::distributions::Distribution;
use rand::distributions::WeightedIndex;
use rand::rngs::StdRng;
use rand::Rng;
use rand_core::{RngCore, SeedableRng};
use randomkit::Sample;
use statrs::function::erf::erfc;
use tokio::time::{timeout_at, Instant};

use canister_test::Canister;
use dfn_candid::candid_one;
use dfn_protobuf::protobuf;
use ic_base_types::PrincipalId;
use ic_canister_client::Sender;
use ic_crypto_sha::Sha256;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_nns_governance::pb::v1::{
    manage_neuron::disburse::Amount, manage_neuron::Command, manage_neuron::Disburse,
    neuron::DissolveState, GovernanceError, ManageNeuron, ManageNeuronResponse, NetworkEconomics,
    Neuron as NeuronProto,
};
use ic_nns_test_utils::itest_helpers::{
    local_test_on_nns_subnet, NnsCanisters, NnsInitPayloadsBuilder,
};
use ledger_canister::{
    AccountBalanceArgs, AccountIdentifier, BlockHeight, LedgerCanisterInitPayload, Memo,
    NotifyCanisterArgs, SendArgs, Subaccount, Tokens, DEFAULT_TRANSFER_FEE,
};

/// A user that owns/controls Accounts and/or Neurons.
#[derive(Clone)]
struct User {
    /// The id of the user.
    id: u64,
    /// The sender to be used in all remote operations.
    sender: Sender,
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("principal", &self.sender.get_principal_id())
            .finish()
    }
}

impl PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.sender.get_principal_id() == other.sender.get_principal_id()
    }
}

/// An account in the ledger.
#[derive(Clone, Debug, PartialEq)]
struct Account {
    /// The id of the account, for fuzzing purposes.
    id: u64,
    /// The (optional) subaccount.
    subaccount: Option<Subaccount>,
    /// The user that is the owner of the account.
    owner: User,
    /// The expected balance, in ICPTs.
    balance: Tokens,
}

impl From<Account> for AccountIdentifier {
    fn from(val: Account) -> Self {
        AccountIdentifier::new(val.owner.sender.get_principal_id(), val.subaccount)
    }
}

/// A neuron in the governance canister.
#[derive(Clone, Debug, PartialEq)]
struct Neuron {
    /// The id of the neuron.
    id: u64,
    /// The id the neuron in the governance canister if
    /// is has already been created.
    id_in_governance: Option<u64>,
    /// The nonce to use in the neuron's creation.
    nonce: u64,
    /// The user that is the owner of the neuron.
    owner: User,
    /// The expected stake of the Neuron, in ICPTs.
    balance: Tokens,
}

impl Neuron {
    fn subaccount(&self) -> Subaccount {
        Subaccount({
            let mut state = Sha256::new();
            state.write(&[0x0c]);
            state.write(b"neuron-stake");
            state.write(self.owner.sender.get_principal_id().as_slice());
            state.write(&self.nonce.to_be_bytes());
            state.finish()
        })
    }
}

impl From<Neuron> for NeuronProto {
    fn from(neuron: Neuron) -> NeuronProto {
        NeuronProto {
            id: neuron.id_in_governance.map(|id| NeuronId { id }),
            controller: Some(neuron.owner.sender.get_principal_id()),
            cached_neuron_stake_e8s: neuron.balance.get_e8s(),
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(0)),
            created_timestamp_seconds: 1,
            aging_since_timestamp_seconds: 1,
            account: neuron.subaccount().into(),
            not_for_profit: false,
            ..Default::default()
        }
    }
}

impl From<Neuron> for AccountIdentifier {
    fn from(neuron: Neuron) -> AccountIdentifier {
        let subaccount = Subaccount::try_from(
            &{
                let mut state = Sha256::new();
                state.write(&[0x0c]);
                state.write(b"neuron-stake");
                state.write(neuron.owner.sender.get_principal_id().as_slice());
                state.write(&neuron.nonce.to_be_bytes());
                state.finish()
            }[..],
        )
        .expect("Couldn't build subaccount from hash.");
        AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(subaccount))
    }
}

/// The current fuzz state. This state is expected to match
/// the state of the NNS.
#[derive(Clone, Debug, PartialEq)]
struct FuzzState {
    /// Save the initial state so that we can output the initial state
    /// and the sequence of operations, when we find a problem.
    initial_accounts: BTreeMap<u64, Account>,
    initial_neurons: BTreeMap<u64, Neuron>,
    /// All the ledger accounts expected to exist. Accounts with
    /// 0 balance are possible.
    accounts: BTreeMap<u64, Account>,
    /// All the neurons that are expected to exist. All neurons
    /// have at least the minimum stake.
    neurons: BTreeMap<u64, Neuron>,
    /// List of neuron ids that are reserved for governance
    /// Other neurons follow these neurons and these neurons
    /// are not selected for random disburse operations.
    governance_neurons: BTreeSet<u64>,
}

impl FuzzState {
    fn new(accounts: BTreeMap<u64, Account>, neurons: BTreeMap<u64, Neuron>) -> Self {
        Self {
            initial_accounts: accounts.clone(),
            initial_neurons: neurons.clone(),
            accounts,
            neurons,
            governance_neurons: BTreeSet::new(),
        }
    }

    /// Applies an operation to the local state.
    fn apply(&mut self, operation: &Operation) {
        match operation {
            Operation::LedgerTransfer {
                id: _,
                source,
                destination,
                amount,
            } => {
                let source_account = self.accounts.get_mut(&source.id).unwrap();
                source_account.balance =
                    ((source_account.balance - *amount).unwrap() - DEFAULT_TRANSFER_FEE).unwrap();
                let destination_account = self.accounts.get_mut(&destination.id).unwrap();
                destination_account.balance = (destination_account.balance + *amount).unwrap();
            }
            Operation::NeuronStake {
                id: _,
                source,
                destination,
                amount,
            } => {
                let source_account = self.accounts.get_mut(&source.id).unwrap();
                source_account.balance =
                    ((source_account.balance - *amount).unwrap() - DEFAULT_TRANSFER_FEE).unwrap();
                let destination_neuron = self.neurons.get_mut(&destination.id).unwrap();
                destination_neuron.balance = (destination_neuron.balance + *amount).unwrap();
            }
            Operation::NeuronDisburse {
                id: _,
                source,
                destination,
                amount,
            } => {
                let source_neuron = self.neurons.get_mut(&source.id).unwrap();
                let amount = if let Some(amount) = amount {
                    source_neuron.balance = ((source_neuron.balance - *amount).unwrap()
                        - DEFAULT_TRANSFER_FEE)
                        .unwrap();
                    *amount
                } else {
                    let amount = source_neuron.balance;
                    source_neuron.balance = Tokens::from_tokens(0).unwrap();
                    amount
                };
                let destination_account = self.accounts.get_mut(&destination.id).unwrap();
                destination_account.balance = (destination_account.balance + amount).unwrap();
            }
            _ => unimplemented!(),
        }
    }

    /// Chooses a random staked Neuron (i.e. a neuron we can call NeuronDisburse
    /// on).
    fn random_staked_neuron(&self, rng: &mut StdRng) -> Option<Neuron> {
        let staked_neurons = self
            .neurons
            .values()
            .filter(|n| n.id_in_governance.is_some())
            .collect::<Vec<&Neuron>>();
        let len = staked_neurons.len();
        if len > 0 {
            return Some((*staked_neurons.get(rng.gen_range(0, len)).unwrap()).clone());
        }
        None
    }

    /// Chooses a random unstaked neuron (i.e. a neuron we can call NeuronStake
    /// on).
    fn random_unstaked_neuron(&self, rng: &mut StdRng) -> Option<Neuron> {
        let unstaked_neurons = self
            .neurons
            .values()
            .filter(|n| n.id_in_governance.is_none())
            .collect::<Vec<&Neuron>>();
        let len = unstaked_neurons.len();
        if len > 0 {
            return Some((*unstaked_neurons.get(rng.gen_range(0, len)).unwrap()).clone());
        }
        None
    }

    /// Chooses a random account.
    fn random_account(&self, rng: &mut StdRng) -> Option<Account> {
        let len = self.accounts.len();
        if len > 0 {
            return Some(
                self.accounts
                    .values()
                    .nth(rng.gen_range(0, len))
                    .unwrap()
                    .clone(),
            );
        }
        None
    }

    /// Chooses a random account from a specific user.
    fn random_account_from(&self, rng: &mut StdRng, owner: &User) -> Option<Account> {
        let accounts = self
            .accounts
            .values()
            .filter(|a| &a.owner == owner)
            .collect::<Vec<&Account>>();
        let len = accounts.len();
        if len > 0 {
            return Some((*accounts.get(rng.gen_range(0, len)).unwrap()).clone());
        }
        None
    }

    /// Chooses a random account different than 'other'.
    fn random_account_different_than(&self, rng: &mut StdRng, other: &Account) -> Option<Account> {
        if !self.accounts.values().any(|a| a != other) {
            return None;
        }
        loop {
            let account = self.random_account(rng)?;
            if account == *other {
                continue;
            }
            return Some(account);
        }
    }
}

/// The total possible set of operations.
/// Different fuzz drivers might allow only subsets
/// of these.
#[derive(Clone, Debug)]
enum Operation {
    /// A ledger transfer from an existing source account to
    /// an existing destination account.
    LedgerTransfer {
        id: u64,
        source: Account,
        destination: Account,
        amount: Tokens,
    },
    /// A stake operation from an existing account to a new
    /// neuron.
    NeuronStake {
        id: u64,
        source: Account,
        destination: Neuron,
        amount: Tokens,
    },
    /// A disburse operation from a neuron, to one of the users
    /// accounts.
    NeuronDisburse {
        id: u64,
        source: Neuron,
        destination: Account,
        amount: Option<Tokens>,
    },
    /// Verifies the balance of a single account or of a single
    /// neuron.
    VerifyOne {
        id: u64,
        account: Option<Account>,
        neuron: Option<Neuron>,
    },
    /// Gets the balance of a single account.
    GetAccountBalance { id: u64, account: Account },
}

impl Operation {
    /// Returns the id of the operation.
    fn id(&self) -> u64 {
        match self {
            Operation::LedgerTransfer {
                id,
                source: _,
                destination: _,
                amount: _,
            } => *id,
            Operation::NeuronStake {
                id,
                source: _,
                destination: _,
                amount: _,
            } => *id,
            Operation::NeuronDisburse {
                id,
                source: _,
                destination: _,
                amount: _,
            } => *id,
            Operation::VerifyOne {
                id,
                account: _,
                neuron: _,
            } => *id,
            Operation::GetAccountBalance { id, account: _ } => *id,
        }
    }

    /// Returns the ids of the neurons/accounts involved.
    fn data_dependendencies(&self) -> Vec<u64> {
        match self {
            Operation::LedgerTransfer {
                id: _,
                source,
                destination,
                amount: _,
            } => vec![source.id, destination.id],
            Operation::NeuronStake {
                id: _,
                source,
                destination,
                amount: _,
            } => vec![source.id, destination.id],
            Operation::NeuronDisburse {
                id: _,
                source,
                destination,
                amount: _,
            } => vec![source.id, destination.id],
            Operation::VerifyOne {
                id: _,
                account,
                neuron,
            } => {
                if account.is_some() {
                    vec![account.as_ref().unwrap().id]
                } else {
                    vec![neuron.as_ref().unwrap().id]
                }
            }
            Operation::GetAccountBalance { id: _, account } => vec![account.id],
        }
    }
}

impl Ord for Operation {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id().cmp(&other.id())
    }
}

impl PartialOrd for Operation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Operation {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Eq for Operation {}

/// Results for each kind of operation. The engine will check that
/// these match the expected ones.
#[derive(Clone, Debug)]
enum OperationResult {
    LedgerTransfer {
        id: u64,
        result: Result<BlockHeight, String>,
    },
    VerifyOne {
        id: u64,
        result: Result<(), String>,
    },
    NeuronStake {
        id: u64,
        neuron_id: u64,
        result: Result<NeuronId, String>,
    },
    NeuronDisburse {
        id: u64,
        result: Result<ManageNeuronResponse, String>,
    },
    GetAccountBalance {
        id: u64,
        result: Result<Tokens, String>,
    },
}

/// Params for the fuzz test.
#[derive(Clone, Debug)]
struct FuzzParams {
    /// The network economics the NNS will be initialized with.
    network_economics: NetworkEconomics,
    /// The rng seed to use. Will use the current time if not set and
    /// print it so that a run can be replicated.
    rng_seed: Option<u64>,
    /// The number of users that will own ledger accounts/neurons.
    initial_num_users: u64,
    /// The number of ledger accounts to start with.
    initial_num_ledger_accounts: u64,
    /// We split the number of neurons in staked and unstaked because
    /// we want to keep the total possible amount of neurons constant.
    /// The number of staked neurons to start with.
    initial_num_staked_neurons: u64,
    /// The number of unstaked neurons to start with.
    initial_num_unstaked_neurons: u64,
    /// The total number of e8s to distribute across all ledger
    /// acounts and neurons.
    total_e8s_to_distribute: u64,
    /// Number of operations to perform in total.
    total_num_ops: u64,
    /// Number of batches to divide the total operations in.
    num_batches: u64,
    /// Weighted probabilies of generating each of the operation types.
    /// E.g. vec![(0, 1.0), (3, 2.0)] will generate only operations 0
    /// (ledger transfers) and 3 (verify one) in a 2:1 ratio.
    ops_to_generate: Vec<(usize, f64)>,
}

/// The maximum amount of time any single canister call can take.
const MAX_OP_DURATION: Duration = Duration::from_secs(30);

/// A generator of fuzz operations.
///
/// The generator is created with some initial state, which the driver
/// will make sure matches the initial state of the target NNS.
///
/// The generator is deterministic both in the generation and execution
/// of operations. If a seed is not passed as an initial parameter, one
/// is generated and printed so that the same run can be replicated in
/// case of failure.
#[derive(Clone, Debug)]
struct FuzzGenerator {
    params: FuzzParams,
    state: FuzzState,
    rng: StdRng,
    weighted_index: WeightedIndex<f64>,
    next_op_id: u64,
}

impl FuzzGenerator {
    /// Creates a new fuzz generator with some initial state.
    fn new(params: FuzzParams) -> Self {
        let seed = params.rng_seed.unwrap_or(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        );
        // Print the seed in case we need to replicate one run
        println!("Fuzz generator using seed: {}", seed);
        let mut rng = StdRng::seed_from_u64(seed);
        let state = Self::generate_initial_state(&mut rng, seed, &params);
        Self {
            params: params.clone(),
            state,
            rng,
            weighted_index: WeightedIndex::new(
                params
                    .ops_to_generate
                    .iter()
                    .map(|(_, weight)| *weight)
                    .collect::<Vec<f64>>()
                    .as_slice(),
            )
            .expect("Couldn't build weighted index"),
            next_op_id: 0,
        }
    }

    fn generate_initial_state(mut rng: &mut StdRng, seed: u64, params: &FuzzParams) -> FuzzState {
        // Generate the initial users.
        let mut users = Vec::new();
        for id in 0..params.initial_num_users {
            let keypair = { ed25519_dalek::Keypair::generate(&mut rng) };
            users.push(User {
                id,
                sender: Sender::from_keypair(&keypair),
            });
        }
        // Cycling iterator to pick users for accounts/neurons.
        let mut users_iter = users.iter().cycle();

        // Splits the total of e8s to distribute into individual amounts for each of
        // the accounts/neurons to generate, according to a multinomial distribution.
        let total_accounts = params.initial_num_ledger_accounts + params.initial_num_staked_neurons;
        let low_sigma = -3f64;
        let high_sigma = 3f64;
        let step_size = 1f64 / ((total_accounts as f64) - 1f64);
        let mut z_values = Vec::new();
        for i in 0..total_accounts {
            z_values.push(low_sigma * (1f64 - i as f64 * step_size) * high_sigma);
        }
        let mut p = Vec::new();
        for (i, _val) in z_values.iter().enumerate() {
            if i == 0 {
                let erfcval = 0.5 * erfc(-z_values[i] / 2f64.sqrt());
                p.push(erfcval);
            } else if i == z_values.len() - 1 {
                let erfcval = p[0];
                p.push(erfcval);
            } else {
                let erfcval1 = 0.5 * erfc(-z_values[i] / 2f64.sqrt());
                let erfcval2 = 0.5 * erfc(-z_values[i - 1] / 2f64.sqrt());
                let erfcval = erfcval1 - erfcval2;
                p.push(erfcval);
            }
        }
        let mut dist_rng = randomkit::Rng::from_seed(seed as u32);
        let distribution =
            randomkit::dist::Multinomial::new(params.total_e8s_to_distribute as isize, p).unwrap();
        let mut values = distribution.sample(&mut dist_rng);

        // Create the initial staked neurons by sampling from the distribution above.
        // We sample from the range in the distribution that has the minimum neuron
        // stake.
        let mut range_begin = 0;
        for (idx, value) in values.iter().enumerate() {
            if (*value) as u64 >= params.network_economics.neuron_minimum_stake_e8s {
                range_begin = idx;
                break;
            }
        }
        assert_ne!(range_begin, 0);
        assert!(values.len() - range_begin > params.initial_num_staked_neurons as usize);
        let mut neurons = BTreeMap::new();
        for id in 0..params.initial_num_staked_neurons {
            let idx = rng.gen_range(range_begin, values.len());
            let value = values.remove(idx);
            let owner = users_iter.next().unwrap().clone();
            neurons.insert(
                id,
                Neuron {
                    id,
                    nonce: rng.next_u64(),
                    id_in_governance: Some(id),
                    owner: owner.clone(),
                    balance: Tokens::from_e8s(value as u64),
                },
            );
        }

        let total_neurons = params.initial_num_staked_neurons + params.initial_num_unstaked_neurons;
        for id in params.initial_num_staked_neurons..total_neurons {
            let owner = users_iter.next().unwrap().clone();
            neurons.insert(
                id,
                Neuron {
                    id,
                    nonce: rng.next_u64(),
                    id_in_governance: None,
                    owner: owner.clone(),
                    balance: Tokens::from_e8s(0),
                },
            );
        }

        assert_eq!(values.len(), params.initial_num_ledger_accounts as usize);
        let mut users_with_main_accounts = BTreeSet::new();
        // Create the initial accounts from the distribution above.
        let mut accounts = BTreeMap::new();
        for id in total_neurons..(total_neurons + params.initial_num_ledger_accounts) {
            let idx = rng.gen_range(0, values.len());
            let value = values.remove(idx);
            let owner = users_iter.next().unwrap().clone();
            let has_main_account = users_with_main_accounts.contains(&owner.id);
            let use_subaccount = rng.gen_bool(1.0 / 2.0);
            let mut subaccount = None;
            if use_subaccount || has_main_account {
                let mut sa = [0u8; 32];
                rng.fill_bytes(&mut sa);
                subaccount = Some(
                    Subaccount::try_from(
                        &{
                            let mut state = Sha256::new();
                            state.write(&sa);
                            state.finish()
                        }[..],
                    )
                    .expect("Couldn't build subaccount from hash"),
                );
            }
            if subaccount == None {
                users_with_main_accounts.insert(owner.id);
            }
            accounts.insert(
                id,
                Account {
                    id,
                    subaccount,
                    owner: owner.clone(),
                    balance: Tokens::from_e8s(value as u64),
                },
            );
        }

        FuzzState::new(accounts, neurons)
    }

    fn choose_random_op_idx(&mut self) -> usize {
        let choice = self.weighted_index.sample(&mut self.rng);
        self.params.ops_to_generate[choice].0
    }

    fn generate_random_ledger_transfer(&mut self) -> Option<Operation> {
        let id = self.next_op_id;
        let source = self.state.random_account(&mut self.rng)?;
        if source.balance.get_e8s() < DEFAULT_TRANSFER_FEE.get_e8s() {
            return None;
        }
        let destination = self
            .state
            .random_account_different_than(&mut self.rng, &source)?;
        let amount = Tokens::from_e8s(
            self.rng
                .gen_range(0, source.balance.get_e8s() - DEFAULT_TRANSFER_FEE.get_e8s()),
        );
        let operation = Operation::LedgerTransfer {
            id,
            source,
            destination,
            amount,
        };
        self.state.apply(&operation);
        Some(operation)
    }

    fn generate_random_neuron_stake(&mut self) -> Option<Operation> {
        let id = self.next_op_id;
        let destination = self.state.random_unstaked_neuron(&mut self.rng)?;
        let source = self
            .state
            .random_account_from(&mut self.rng, &destination.owner)?;
        if source.balance.get_e8s() < self.params.network_economics.neuron_minimum_stake_e8s {
            return None;
        }
        let amount = Tokens::from_e8s(self.rng.gen_range(
            self.params.network_economics.neuron_minimum_stake_e8s,
            source.balance.get_e8s(),
        ));
        let operation = Operation::NeuronStake {
            id,
            source,
            destination,
            amount,
        };
        self.state.apply(&operation);
        Some(operation)
    }

    fn generate_random_neuron_disburse(&mut self) -> Option<Operation> {
        let id = self.next_op_id;
        let source = self.state.random_staked_neuron(&mut self.rng)?;
        let destination = self.state.random_account(&mut self.rng)?;
        if source.balance.get_e8s() < DEFAULT_TRANSFER_FEE.get_e8s() {
            return None;
        }
        let amount = match self.rng.gen_bool(1.0 / 2.0) {
            true => Some(Tokens::from_e8s(self.rng.gen_range(
                0,
                source.balance.get_e8s() - DEFAULT_TRANSFER_FEE.get_e8s(),
            ))),
            false => None,
        };
        let operation = Operation::NeuronDisburse {
            id,
            source,
            destination,
            amount,
        };
        self.state.apply(&operation);
        Some(operation)
    }

    fn generate_random_verify_one(&mut self) -> Option<Operation> {
        let id = self.next_op_id;
        let verify_account = self.rng.gen_bool(1.0 / 2.0);
        if !self.state.accounts.is_empty() && (self.state.neurons.is_empty() || verify_account) {
            self.state
                .random_account(&mut self.rng)
                .map(|account| Operation::VerifyOne {
                    id,
                    account: Some(account),
                    neuron: None,
                })
        } else if !self.state.neurons.is_empty()
            && (self.state.accounts.is_empty() || !verify_account)
        {
            self.state
                .random_staked_neuron(&mut self.rng)
                .map(|neuron| Operation::VerifyOne {
                    id,
                    account: None,
                    neuron: Some(neuron),
                })
        } else {
            None
        }
    }

    // Generates a sequence of valid operations, based on the
    // current state.
    fn generate_valid_sequence(&mut self, size: usize) -> Vec<Operation> {
        let mut operations = Vec::new();
        while operations.len() < size {
            let operation = match self.choose_random_op_idx() {
                0 => self.generate_random_ledger_transfer(),
                1 => self.generate_random_neuron_stake(),
                2 => self.generate_random_neuron_disburse(),
                3 => self.generate_random_verify_one(),
                _ => panic!("Unsupposed operation idx."),
            };
            if let Some(operation) = operation {
                operations.push(operation);
                self.next_op_id += 1;
            }
        }
        operations
    }
}

/// A driver for a fuzz test. Different implementations might have different
/// targets, such as local struct, a real NNS on a local replica, or an NNS
/// deployed to a testnet.
trait FuzzDriver {
    fn initialize(&mut self, state: &FuzzState);
    /// Executes the sequence of operations, applying it to an implementation
    /// of the NNS and to the fuzz state.
    fn execute_operations(&mut self, operations: Vec<Operation>);
    /// Collects and verifies the results of the executed operations.
    fn collect_results(&mut self, len: usize) -> Vec<OperationResult>;
    /// Stops the driver.
    fn stop(&mut self);
}

/// The fuzz engine that uses the generator to create operations and the driver
/// to apply them. Finally it verifies that the results match the expected ones.
struct FuzzEngine {
    params: FuzzParams,
    generator: FuzzGenerator,
    driver: Box<dyn FuzzDriver>,
    operations: Vec<Operation>,
    results: Vec<OperationResult>,
}

impl FuzzEngine {
    fn new(params: FuzzParams, driver: Box<dyn FuzzDriver>) -> Self {
        Self {
            params: params.clone(),
            generator: FuzzGenerator::new(params),
            driver,
            operations: Vec::new(),
            results: Vec::new(),
        }
    }

    fn init(&mut self) {
        self.driver.initialize(&self.generator.state);
    }

    /// Verify the results (and potentially update some internal state with the
    /// state from the NNS).
    fn verify_results(&mut self, op_results: &[OperationResult]) {
        for op_result in op_results {
            match op_result {
                OperationResult::LedgerTransfer { id, result } => {
                    if result.is_err() {
                        // A ledger transfer failed. Get the balance of that
                        // account before panicking with the failure.
                        let balance_op = Operation::GetAccountBalance {
                            id: 0,
                            account: self.generator.state.accounts.get(id).unwrap().clone(),
                        };

                        self.driver.execute_operations(vec![balance_op]);
                        let balance_res = self.driver.collect_results(1)[0].clone();

                        panic!(
                            "Test failed on ledger transfer operation {} with error: {}.\
                             Account balance: {:?}\
                             Test started with params: {:?}\
                             Initial accounts: {:#?}\
                             \nOperations: {:#?}\nResults: {:#?}",
                            id,
                            result.as_ref().unwrap_err(),
                            balance_res,
                            self.params,
                            self.generator.state.initial_accounts,
                            self.operations,
                            self.results
                        );
                    }
                }
                OperationResult::NeuronStake {
                    id,
                    neuron_id,
                    result,
                } => {
                    if result.is_err() {
                        panic!(
                            "Test failed on neuron stake operation {} with error: {}.\
                             Test started with params: {:?}\
                             Initial accounts: {:#?}\
                             \nOperations: {:#?}\nResults: {:#?}",
                            id,
                            result.as_ref().unwrap_err(),
                            self.params,
                            self.generator.state.initial_accounts,
                            self.operations,
                            self.results
                        );
                    } else {
                        let neuron_id_in_governance = result.as_ref().unwrap();
                        self.generator
                            .state
                            .neurons
                            .get_mut(neuron_id)
                            .unwrap()
                            .id_in_governance = Some(neuron_id_in_governance.id);
                    }
                }
                OperationResult::NeuronDisburse { id, result } => {
                    if result.is_err() {
                        panic!(
                            "Test failed on neuron disburse operation {} with error: {}.\
                             Test started with params: {:?}\
                             Initial accounts: {:#?}\
                             \nOperations: {:#?}\nResults: {:#?}",
                            id,
                            result.as_ref().unwrap_err(),
                            self.params,
                            self.generator.state.initial_accounts,
                            self.operations,
                            self.results
                        );
                    }
                }
                OperationResult::VerifyOne { id, result } => {
                    if result.is_err() {
                        panic!(
                            "Test failed on verify one operation {} with error: {}.\
                             Test started with params: {:?}\
                             Initial accounts: {:#?}\
                             \nOperations: {:#?}\nResults: {:#?}",
                            id,
                            result.as_ref().unwrap_err(),
                            self.params,
                            self.generator.state.initial_accounts,
                            self.operations,
                            self.results
                        );
                    }
                }
                _ => unimplemented!(),
            }
        }
    }

    /// Run the fuzz test.
    fn run(&mut self) {
        let mut executed_ops = 0;
        let ops_per_batch = self.params.total_num_ops / self.params.num_batches;
        while executed_ops < self.params.total_num_ops {
            let operations = self
                .generator
                .generate_valid_sequence(ops_per_batch as usize);
            let num_ops = operations.len();
            self.operations.append(&mut operations.clone());
            self.driver.execute_operations(operations);
            let mut results = self.driver.collect_results(num_ops);
            self.verify_results(&results);
            self.results.append(&mut results);
            executed_ops += num_ops as u64;
        }
        self.driver.stop();
    }
}

/// An implementation of a fuzz driver that executes the operations against
/// a local version of the nns.
struct LocalNnsFuzzDriver {
    params: FuzzParams,
    operation_sender: Option<CBSender<Operation>>,
    results_receiver: Option<CBReceiver<OperationResult>>,
    // A handle to thread that creates the nns canisters.
    sender_thread: Option<JoinHandle<()>>,
}

impl LocalNnsFuzzDriver {
    /// Splits operations in parallizable groups by running a naive connected
    /// components algorithm.
    ///
    /// Operations that have data depencies are not parallelizable, so end up
    /// being grouped together. An operation has a data dependeny on another
    /// operation it it interacts with the same account or neuron.
    fn split_parallelizable_operations(operations: &[Operation]) -> Vec<Vec<Operation>> {
        // Build an adjancency list of data items
        let mut adj = BTreeMap::new();
        for operation in operations {
            for it0 in operation.data_dependendencies() {
                let list = adj.entry(it0).or_insert_with(BTreeSet::new);
                for it1 in operation.data_dependendencies() {
                    if it1 != it0 {
                        list.insert(it1);
                    }
                }
            }
        }

        // Do depth first search in the data items and group them together.
        fn dfs(
            key: u64,
            adj: &BTreeMap<u64, BTreeSet<u64>>,
            visited: &mut BTreeSet<u64>,
            component: &mut BTreeSet<u64>,
        ) {
            visited.insert(key);
            component.insert(key);
            for value in adj.get(&key).unwrap() {
                if !visited.contains(value) {
                    dfs(*value, adj, visited, component);
                }
            }
        }

        // Go through the adjancency list to find the connected components
        let mut components = Vec::new();
        let mut visited = BTreeSet::new();
        for key in adj.keys() {
            if !visited.contains(key) {
                let mut component = BTreeSet::new();
                dfs(*key, &adj, &mut visited, &mut component);
                components.push(component);
            }
        }

        // Now, for each component get back the operations that involve it.
        let mut final_components = Vec::new();
        for component in components {
            let mut final_component = BTreeSet::new();
            for operation in operations {
                for data_item in operation.data_dependendencies() {
                    if component.contains(&data_item) {
                        final_component.insert(operation);
                    }
                }
            }
            final_components.push(
                final_component
                    .iter()
                    .cloned()
                    .cloned()
                    .collect::<Vec<Operation>>(),
            );
        }

        final_components
    }

    async fn handle_ledger_transfer(
        id: u64,
        source: Account,
        destination: Account,
        amount: Tokens,
        ledger: &Canister<'_>,
    ) -> OperationResult {
        let result: Result<BlockHeight, String> = timeout_at(
            Instant::now() + MAX_OP_DURATION,
            ledger.update_from_sender(
                "send_pb",
                protobuf,
                SendArgs {
                    memo: Memo(0),
                    amount,
                    fee: DEFAULT_TRANSFER_FEE,
                    from_subaccount: source.subaccount,
                    to: destination.clone().into(),
                    created_at_time: None,
                },
                &source.owner.sender,
            ),
        )
        .await
        .unwrap_or_else(|_| Err(format!("Operation {} (transfer) timed out.", id)));
        OperationResult::LedgerTransfer { id, result }
    }

    async fn handle_neuron_stake(
        id: u64,
        source: Account,
        destination: Neuron,
        amount: Tokens,
        ledger: &Canister<'_>,
    ) -> OperationResult {
        assert_eq!(source.owner, destination.owner);
        let result: Result<BlockHeight, String> = timeout_at(
            Instant::now() + MAX_OP_DURATION,
            ledger.update_from_sender(
                "send_pb",
                protobuf,
                SendArgs {
                    memo: Memo(destination.nonce),
                    amount,
                    fee: DEFAULT_TRANSFER_FEE,
                    from_subaccount: source.subaccount,
                    to: AccountIdentifier::new(
                        PrincipalId::from(GOVERNANCE_CANISTER_ID),
                        Some(destination.subaccount()),
                    ),
                    created_at_time: None,
                },
                &source.owner.sender,
            ),
        )
        .await
        .unwrap_or_else(|_| Err(format!("Operation {} (stake) timed out.", id)));
        if result.is_err() {
            return OperationResult::NeuronStake {
                id,
                neuron_id: destination.id,
                result: Err(result.unwrap_err()),
            };
        }
        let result: Result<NeuronId, String> = timeout_at(
            Instant::now() + MAX_OP_DURATION,
            ledger.update_from_sender(
                "notify_pb",
                protobuf,
                NotifyCanisterArgs {
                    block_height: result.unwrap(),
                    max_fee: DEFAULT_TRANSFER_FEE,
                    from_subaccount: source.subaccount,
                    to_canister: GOVERNANCE_CANISTER_ID,
                    to_subaccount: Some(destination.subaccount()),
                },
                &source.owner.sender,
            ),
        )
        .await
        .unwrap_or_else(|_| Err(format!("Operation {} (notify) timed out.", id)));

        OperationResult::NeuronStake {
            id,
            neuron_id: destination.id,
            result,
        }
    }

    async fn handle_neuron_disburse(
        id: u64,
        source: Neuron,
        destination: Account,
        amount: Option<Tokens>,
        governance: &Canister<'_>,
    ) -> OperationResult {
        let amount = amount.map(|a| Amount { e8s: a.get_e8s() });
        let result: Result<ManageNeuronResponse, String> = timeout_at(
            Instant::now() + MAX_OP_DURATION,
            governance.update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                        id: source.id_in_governance.unwrap(),
                    })),
                    id: None,
                    command: Some(Command::Disburse(Disburse {
                        amount,
                        to_account: Some(
                            AccountIdentifier::new(
                                destination.owner.sender.get_principal_id(),
                                destination.subaccount,
                            )
                            .into(),
                        ),
                    })),
                },
                &source.owner.sender,
            ),
        )
        .await
        .unwrap_or_else(|_| Err(format!("Operation {} (disburse) timed out.", id)));
        OperationResult::NeuronDisburse { id, result }
    }

    async fn handle_verify_one(
        id: u64,
        account: Option<Account>,
        neuron: Option<Neuron>,
        ledger: &Canister<'_>,
        governance: &Canister<'_>,
    ) -> OperationResult {
        if let Some(account) = account {
            let result: Result<Tokens, String> = timeout_at(
                Instant::now() + MAX_OP_DURATION,
                ledger.query_from_sender(
                    "account_balance_pb",
                    protobuf,
                    AccountBalanceArgs {
                        account: account.clone().into(),
                    },
                    &account.owner.sender,
                ),
            )
            .await
            .unwrap_or_else(|_| Err(format!("Operation {} (get balance) timed out.", id)));
            if let Ok(balance) = result {
                if balance == account.balance {
                    OperationResult::VerifyOne { id, result: Ok(()) }
                } else {
                    OperationResult::VerifyOne {
                        id,
                        result: Err(format!(
                            "Balance of account: {:?} didn't match. Got: {:?}",
                            account, balance
                        )),
                    }
                }
            } else {
                OperationResult::VerifyOne {
                    id,
                    result: Err(result.unwrap_err()),
                }
            }
        } else {
            let neuron = neuron.expect("Expected a neuron");
            let result: Result<Result<NeuronProto, GovernanceError>, String> = timeout_at(
                Instant::now() + MAX_OP_DURATION,
                governance.query_from_sender(
                    "get_full_neuron",
                    candid_one,
                    neuron
                        .id_in_governance
                        .expect("Neuron to verify must have a gov id"),
                    &neuron.owner.sender,
                ),
            )
            .await
            .unwrap_or_else(|_| Err(format!("Operation {} (get balance) timed out.", id)));
            if let Ok(inner) = result.clone() {
                if let Ok(neuron_proto) = inner {
                    let balance = Tokens::from_e8s(neuron_proto.cached_neuron_stake_e8s);
                    if balance == neuron.balance {
                        OperationResult::VerifyOne { id, result: Ok(()) }
                    } else {
                        OperationResult::VerifyOne {
                            id,
                            result: Err(format!(
                                "Balance of neuron: {:?} didn't match. Got: {:?}",
                                account, balance
                            )),
                        }
                    }
                } else {
                    OperationResult::VerifyOne {
                        id,
                        result: Err(format!("Governance error: {:?}", inner.unwrap_err())),
                    }
                }
            } else {
                OperationResult::VerifyOne {
                    id,
                    result: Err(result.unwrap_err()),
                }
            }
        }
    }

    async fn handle_get_account_balance(
        id: u64,
        account: Account,
        ledger: &Canister<'_>,
    ) -> OperationResult {
        let result: Result<Tokens, String> = ledger
            .query_from_sender(
                "account_balance_pb",
                protobuf,
                AccountBalanceArgs {
                    account: account.clone().into(),
                },
                &account.owner.sender,
            )
            .await;
        OperationResult::GetAccountBalance { id, result }
    }

    async fn handle_operation(
        operation: Operation,
        canisters: Arc<NnsCanisters<'_>>,
    ) -> OperationResult {
        match operation {
            Operation::LedgerTransfer {
                id,
                source,
                destination,
                amount,
            } => {
                Self::handle_ledger_transfer(id, source, destination, amount, &canisters.ledger)
                    .await
            }
            Operation::NeuronStake {
                id,
                source,
                destination,
                amount,
            } => {
                Self::handle_neuron_stake(id, source, destination, amount, &canisters.ledger).await
            }
            Operation::NeuronDisburse {
                id,
                source,
                destination,
                amount,
            } => {
                Self::handle_neuron_disburse(id, source, destination, amount, &canisters.governance)
                    .await
            }
            Operation::VerifyOne {
                id,
                account,
                neuron,
            } => {
                Self::handle_verify_one(
                    id,
                    account,
                    neuron,
                    &canisters.ledger,
                    &canisters.governance,
                )
                .await
            }
            Operation::GetAccountBalance { id, account } => {
                Self::handle_get_account_balance(id, account, &canisters.ledger).await
            }
        }
    }
}

impl FuzzDriver for LocalNnsFuzzDriver {
    /// Starts a local replica runtime and installs the nns canisters.
    /// The runtime is kept alive for the duration of the test.
    fn initialize(&mut self, state: &FuzzState) {
        println!("Initializing LocalNnsFuzzDriver");
        let ops_per_batch = (self.params.total_num_ops / self.params.num_batches) as usize;
        let (ops_sender, ops_receiver) = bounded(ops_per_batch);
        let (results_sender, results_receiver) = bounded(ops_per_batch);
        self.operation_sender = Some(ops_sender);
        self.results_receiver = Some(results_receiver);

        let state = state.clone();
        let economics = self.params.network_economics.clone();
        self.sender_thread = Some(thread::spawn(move || {
            local_test_on_nns_subnet(move |runtime| async move {
                println!("Initializing the NNS.");
                let mut governance = GovernanceCanisterInitPayloadBuilder::new().proto;

                governance.economics = Some(economics);
                // Note that we're introducing some indeterminism by allowing the ledger
                // to receive a list of accounts that is different each time (since it
                // uses a HashMap). Something to dig into if we see indet problems.
                let mut ledger_init_state = HashMap::new();
                for account in state.accounts.values() {
                    ledger_init_state.insert(account.clone().into(), account.balance);
                }

                for neuron in state
                    .neurons
                    .values()
                    .filter(|n| n.id_in_governance.is_some())
                {
                    governance
                        .neurons
                        .insert(neuron.id_in_governance.unwrap(), neuron.clone().into());
                }

                let ledger_init_args = LedgerCanisterInitPayload::builder()
                    .minting_account(GOVERNANCE_CANISTER_ID.into())
                    .initial_values(ledger_init_state)
                    .build()
                    .unwrap();

                let nns_init_payload = NnsInitPayloadsBuilder::new()
                    .with_governance_proto(governance)
                    .with_ledger_init_state(ledger_init_args)
                    .build();

                // Get a static reference to the runtime that we can pass to operation execution
                // threads below.
                let runtime = Box::new(runtime);
                let runtime: &'static canister_test::Runtime = Box::leak(runtime);

                // Surroung the canisters struct in Arc so that we can pass it to operation
                // execution threads below.
                let nns_canisters = Arc::new(NnsCanisters::set_up(runtime, nns_init_payload).await);
                println!("NNS initialized. Starting to send operations.");

                let mut operations = Vec::new();
                while let Ok(operation) = ops_receiver.recv() {
                    operations.push(operation);
                    if operations.len() < ops_per_batch {
                        continue;
                    }

                    let mut join_handles = Vec::new();
                    for operation_group in Self::split_parallelizable_operations(&operations) {
                        let nns_canisters_handle = nns_canisters.clone();
                        join_handles.push(tokio::runtime::Handle::current().spawn(async move {
                            let mut results = Vec::new();
                            for operation in operation_group {
                                println!(
                                    "Thread: {:?} Executing operation: {:?}",
                                    thread::current().id(),
                                    operation
                                );
                                results.push(
                                    Self::handle_operation(operation, nns_canisters_handle.clone())
                                        .await,
                                )
                            }
                            results
                        }));
                    }

                    println!("Waiting for latest batch to complete.");
                    // Wait on all the ops before proceeding.
                    let result_groups = futures::future::join_all(join_handles.into_iter()).await;
                    for result_group in result_groups {
                        match result_group {
                            Ok(results) => {
                                for result in results {
                                    results_sender
                                        .send(result)
                                        .expect("Can't send result, channel closed.");
                                }
                            }
                            Err(join_error) => {
                                // If we had an error, return, which will cause the results
                                // receiver to fail.
                                return Err(format!(
                                    "Error waiting on a results operation: {:?}",
                                    join_error
                                ));
                            }
                        }
                    }

                    operations.clear();
                }
                println!("All operations sent. Execution complete.");
                runtime.stop();
                Ok(())
            });
        }));
    }

    fn execute_operations(&mut self, operations: Vec<Operation>) {
        assert!(self.operation_sender.is_some());
        for operation in operations {
            self.operation_sender
                .as_ref()
                .unwrap()
                .send(operation)
                .expect("Error sending operation to be executed");
        }
    }

    fn collect_results(&mut self, len: usize) -> Vec<OperationResult> {
        assert!(self.results_receiver.is_some());
        let mut results = Vec::new();
        while let Ok(op_result) = self.results_receiver.as_ref().unwrap().recv() {
            results.push(op_result.clone());
            if results.len() >= len {
                break;
            }
        }
        results
    }

    fn stop(&mut self) {
        // Dropping the sender causes the channel to close.
        self.operation_sender = None;
        if self.sender_thread.is_some() {
            self.sender_thread.take().map(JoinHandle::join);
        }
    }
}

impl LocalNnsFuzzDriver {
    fn new(params: FuzzParams) -> Self {
        Self {
            params,
            operation_sender: None,
            results_receiver: None,
            sender_thread: None,
        }
    }
}

#[test]
fn test_fuzz_generator_initial_state() {
    let gen = FuzzGenerator::new(FuzzParams {
        network_economics: NetworkEconomics::with_default_values(),
        rng_seed: Some(0),
        initial_num_users: 10,
        initial_num_ledger_accounts: 100,
        initial_num_staked_neurons: 10,
        initial_num_unstaked_neurons: 10,
        total_e8s_to_distribute: 500_000_000 * 100_000_000,
        total_num_ops: 0,
        num_batches: 0,
        ops_to_generate: vec![(0, 1.0), (1, 1.0), (2, 1.0), (3, 1.0)],
    });

    assert_eq!(gen.state.accounts.len(), 100);
    assert_eq!(gen.state.neurons.len(), 20);

    let mut total_e8s = 0;
    for neuron in gen.state.neurons.values() {
        total_e8s += neuron.balance.get_e8s();
    }
    for account in gen.state.accounts.values() {
        total_e8s += account.balance.get_e8s();
    }
    assert_eq!(total_e8s, gen.params.total_e8s_to_distribute);

    // Test that if we generate the fuzz gen as above with the same random
    // seed we get the same fuzz state.
    let gen2 = FuzzGenerator::new(FuzzParams {
        network_economics: NetworkEconomics::with_default_values(),
        rng_seed: Some(0),
        initial_num_users: 10,
        initial_num_ledger_accounts: 100,
        initial_num_staked_neurons: 10,
        initial_num_unstaked_neurons: 10,
        total_e8s_to_distribute: 500_000_000 * 100_000_000,
        total_num_ops: 0,
        num_batches: 0,
        ops_to_generate: vec![(0, 1.0), (1, 1.0), (2, 1.0), (3, 1.0)],
    });

    assert_eq!(gen.state, gen2.state);

    // But if we generate with a new seed, we get a different fuzz state.
    let gen2 = FuzzGenerator::new(FuzzParams {
        network_economics: NetworkEconomics::with_default_values(),
        rng_seed: Some(1),
        initial_num_users: 10,
        initial_num_ledger_accounts: 100,
        initial_num_staked_neurons: 10,
        initial_num_unstaked_neurons: 10,
        total_e8s_to_distribute: 500_000_000 * 100_000_000,
        total_num_ops: 0,
        num_batches: 0,
        ops_to_generate: vec![(0, 1.0), (1, 1.0), (2, 1.0), (3, 1.0)],
    });

    assert_ne!(gen.state, gen2.state);
}

// Tests ledger transfers in isolation.
#[test]
fn test_ledger_transfers() {
    let params = FuzzParams {
        network_economics: NetworkEconomics::with_default_values(),
        rng_seed: None,
        initial_num_users: 10,
        initial_num_ledger_accounts: 100,
        initial_num_staked_neurons: 0,
        initial_num_unstaked_neurons: 0,
        total_e8s_to_distribute: 500_000_000 * 100_000_000,
        total_num_ops: 100,
        num_batches: 5,
        ops_to_generate: vec![(0, 1.0), (3, 1.0)],
    };
    let mut engine = FuzzEngine::new(params.clone(), Box::new(LocalNnsFuzzDriver::new(params)));

    engine.init();
    engine.run();
}

// Tests neuron stake/disburse in isolation.
// TODO(NNS1-901) remove the ignore. Still some (test-only) stuff to address.
#[test]
#[ignore]
fn test_neurons() {
    let params = FuzzParams {
        network_economics: NetworkEconomics::with_default_values(),
        rng_seed: None,
        initial_num_users: 10,
        initial_num_ledger_accounts: 100,
        initial_num_staked_neurons: 100,
        initial_num_unstaked_neurons: 100,
        total_e8s_to_distribute: 500_000_000 * 100_000_000,
        total_num_ops: 100,
        num_batches: 5,
        ops_to_generate: vec![(1, 1.0), (2, 1.0), (3, 1.0)],
    };
    let mut engine = FuzzEngine::new(params.clone(), Box::new(LocalNnsFuzzDriver::new(params)));

    engine.init();
    engine.run();
}
