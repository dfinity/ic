use async_trait::async_trait;
use candid::Encode;
use futures::future::FutureExt;
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_common::types::UpdateIcpXdrConversionRatePayload;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::{
    governance::{Environment, Governance, Ledger},
    pb::v1::{
        governance_error::ErrorType, manage_neuron, manage_neuron::NeuronIdOrSubaccount,
        manage_neuron_response, proposal, ExecuteNnsFunction, GovernanceError, ManageNeuron,
        Motion, NetworkEconomics, Neuron, NnsFunction, Proposal, Vote,
    },
};
use ledger_canister::{AccountIdentifier, Tokens};
use rand::rngs::StdRng;
use rand_core::{RngCore, SeedableRng};
use std::collections::hash_map::Entry;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::sync::Arc;
use std::sync::Mutex;

use ic_nns_governance::governance::HeapGrowthPotential;
use ic_nns_governance::pb::v1::ManageNeuronResponse;
use ledger_canister::Subaccount;

const DEFAULT_TEST_START_TIMESTAMP_SECONDS: u64 = 999_111_000_u64;

#[derive(Clone, Debug)]
pub struct FakeAccount {
    pub id: AccountIdentifier,
    pub amount_e8s: u64,
}

type LedgerMap = HashMap<AccountIdentifier, u64>;

/// The state required for fake implementations of `Environment` and
/// `Ledger`.
pub struct FakeState {
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
pub struct FakeDriver {
    pub state: Arc<Mutex<FakeState>>,
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

    pub fn with_supply(self, supply: Tokens) -> FakeDriver {
        {
            let old_supply = self.get_supply();
            let accounts = &mut self.state.lock().unwrap().accounts;
            let minting = accounts.entry(FakeDriver::minting_account()).or_default();
            assert!(old_supply >= Tokens::from_e8s(*minting));
            let old_in_use = (old_supply - Tokens::from_e8s(*minting)).unwrap();
            assert!(supply >= old_in_use);
            *minting = (supply - old_in_use).unwrap().get_e8s();
        }
        self
    }

    pub fn get_supply(&self) -> Tokens {
        Tokens::from_e8s(
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
    pub fn now(&self) -> u64 {
        self.state.lock().unwrap().now
    }

    pub fn create_account_with_funds(&mut self, to: AccountIdentifier, amount_e8s: u64) {
        let accounts = &mut self.state.try_lock().unwrap().accounts;
        match accounts.entry(to) {
            Entry::Occupied(_) => panic!("Account exists"),
            Entry::Vacant(v) => {
                v.insert(amount_e8s);
            }
        }
    }

    pub fn add_funds_to_account(&mut self, to: AccountIdentifier, amount_e8s: u64) {
        let accounts = &mut self.state.try_lock().unwrap().accounts;
        match accounts.entry(to) {
            Entry::Vacant(_) => panic!("Account doesn't exist"),
            Entry::Occupied(mut o) => {
                *o.get_mut() += amount_e8s;
            }
        }
    }

    pub fn assert_account_contains(&self, account: &AccountIdentifier, amount_e8s: u64) {
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

    pub fn assert_num_neuron_accounts_exist(&self, num_accounts: usize) {
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

        *accounts.entry(to_account).or_default() += amount_e8s;

        Ok(0)
    }

    async fn total_supply(&self) -> Result<Tokens, GovernanceError> {
        Ok(self.get_supply())
    }

    async fn account_balance(&self, account: AccountIdentifier) -> Result<Tokens, GovernanceError> {
        let accounts = &mut self.state.try_lock().unwrap().accounts;
        let account_e8s = accounts.get(&account).unwrap_or(&0);
        Ok(Tokens::from_e8s(*account_e8s))
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
        bytes
    }

    fn execute_nns_function(
        &self,
        _proposal_id: u64,
        _update: &ExecuteNnsFunction,
    ) -> Result<(), GovernanceError> {
        Ok(())
        //panic!("unexpected call")
    }

    fn heap_growth_potential(&self) -> HeapGrowthPotential {
        HeapGrowthPotential::NoIssue
    }
}

/// Constructs a test principal id from an integer.
/// Convenience functions to make creating neurons more concise.
pub fn principal(i: u64) -> PrincipalId {
    PrincipalId::try_from(format!("SID{}", i).as_bytes().to_vec()).unwrap()
}

/// Issues a manage_neuron command to register a vote
pub fn register_vote(
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
pub fn register_vote_assert_success(
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
    pub fn propose_and_vote(&self, gov: &mut Governance, summary: String) -> ProposalId {
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
                    })
                    .unwrap(),
                })
            }
        };
        let pid = gov
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
    /// Format: <neuron_behaviour>* <proposal_topic>?
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
        let chr = if str.is_empty() {
            ' '
        } else {
            str.chars().last().unwrap()
        };
        let (str, proposal_topic) = match "NEG".find(chr) {
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
