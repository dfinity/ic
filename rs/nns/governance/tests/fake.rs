use async_trait::async_trait;
use candid::{Decode, Encode};
use cycles_minting_canister::{IcpXdrConversionRate, IcpXdrConversionRateCertifiedResponse};
use futures::future::FutureExt;
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::tokens::CheckedSub;
use ic_nervous_system_canisters::cmc::CMC;
use ic_nervous_system_canisters::ledger::IcpLedger;
use ic_nervous_system_common::NervousSystemError;
use ic_nervous_system_timers::test::{advance_time_for_timers, set_time_for_timers};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID,
    NODE_REWARDS_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance::{
    governance::{Environment, Governance, HeapGrowthPotential, RngError},
    pb::v1::{
        ExecuteNnsFunction, GovernanceError, ManageNeuron, Motion, NetworkEconomics, Proposal,
        Vote, manage_neuron, manage_neuron::NeuronIdOrSubaccount, proposal,
    },
};
use ic_nns_governance_api::Neuron;
use ic_nns_governance_api::{ManageNeuronResponse, manage_neuron_response};
use ic_sns_root::{GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse};
use ic_sns_swap::pb::v1 as sns_swap_pb;
use ic_sns_wasm::pb::v1::{DeployedSns, ListDeployedSnsesRequest, ListDeployedSnsesResponse};
use icp_ledger::{AccountIdentifier, Subaccount, Tokens};
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};
use lazy_static::lazy_static;
use maplit::btreemap;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{
    collections::{BTreeMap, HashMap, hash_map::Entry},
    convert::{TryFrom, TryInto},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_TEST_START_TIMESTAMP_SECONDS: u64 = 999_111_000_u64;
pub const NODE_PROVIDER_REWARD: u64 = 10_000;

use ic_nns_governance::governance::RandomnessGenerator;
#[cfg(feature = "tla")]
use ic_nns_governance::governance::tla::{
    self, Destination, TLA_INSTRUMENTATION_STATE, ToTla, account_to_tla, tla_function,
};
use ic_nns_governance::{tla_log_request, tla_log_response};
use ic_node_rewards_canister_api::RewardsCalculationAlgorithmVersion;
use ic_node_rewards_canister_api::monthly_rewards::GetNodeProvidersMonthlyXdrRewardsResponse;
use ic_node_rewards_canister_api::providers_rewards::{
    GetNodeProvidersRewardsResponse, NodeProvidersRewards,
};

lazy_static! {
    pub(crate) static ref SNS_ROOT_CANISTER_ID: PrincipalId = PrincipalId::new_user_test_id(213599);
    pub(crate) static ref SNS_GOVERNANCE_CANISTER_ID: PrincipalId =
        PrincipalId::new_user_test_id(127565);
    pub(crate) static ref SNS_LEDGER_CANISTER_ID: PrincipalId =
        PrincipalId::new_user_test_id(315611);
    pub(crate) static ref SNS_LEDGER_ARCHIVE_CANISTER_ID: PrincipalId =
        PrincipalId::new_user_test_id(864704);
    pub(crate) static ref SNS_LEDGER_INDEX_CANISTER_ID: PrincipalId =
        PrincipalId::new_user_test_id(450226);
    pub(crate) static ref TARGET_SWAP_CANISTER_ID: PrincipalId =
        PrincipalId::new_user_test_id(129844);
    pub(crate) static ref DAPP_CANISTER_ID: PrincipalId = PrincipalId::new_user_test_id(504845);
    pub(crate) static ref DEVELOPER_PRINCIPAL_ID: PrincipalId =
        PrincipalId::new_user_test_id(739631);
}

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
    pub rng: ChaCha20Rng,
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
            rng: ChaCha20Rng::seed_from_u64(9539),
            accounts: HashMap::new(),
        }
    }
}

/// A struct that produces a fake environment where time can be
/// advanced, and ledger accounts manipulated.
pub struct FakeDriver {
    pub state: Arc<Mutex<FakeState>>,
    pub error_on_next_ledger_call: Arc<Mutex<Option<NervousSystemError>>>,
}

/// Create a default mock driver.
impl Default for FakeDriver {
    fn default() -> Self {
        let ret = Self {
            state: Arc::new(Mutex::new(Default::default())),
            error_on_next_ledger_call: Arc::new(Mutex::new(None)),
        };
        set_time_for_timers(std::time::Duration::from_secs(
            ret.state.try_lock().unwrap().now,
        ));
        ret
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
        set_time_for_timers(std::time::Duration::from_secs(timestamp));
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
            let old_in_use = old_supply.checked_sub(&Tokens::from_e8s(*minting)).unwrap();
            assert!(supply >= old_in_use);
            *minting = supply.checked_sub(&old_in_use).unwrap().get_e8s();
        }
        self
    }

    pub fn get_supply(&self) -> Tokens {
        Tokens::from_e8s(self.state.lock().unwrap().accounts.values().sum())
    }

    /// Increases the time by the given amount.
    pub fn advance_time_by(&mut self, delta_seconds: u64) {
        advance_time_for_timers(std::time::Duration::from_secs(delta_seconds));
        self.state.lock().unwrap().now += delta_seconds;
    }

    /// Constructs an `Environment` that interacts with this driver.
    pub fn get_fake_env(&self) -> Arc<dyn Environment> {
        Arc::new(FakeDriver {
            state: Arc::clone(&self.state),
            error_on_next_ledger_call: Arc::clone(&self.error_on_next_ledger_call),
        })
    }

    /// Constructs a `Ledger` that interacts with this driver.
    pub fn get_fake_ledger(&self) -> Arc<dyn IcpLedger> {
        Arc::new(FakeDriver {
            state: Arc::clone(&self.state),
            error_on_next_ledger_call: Arc::clone(&self.error_on_next_ledger_call),
        })
    }

    pub fn get_fake_cmc(&self) -> Arc<dyn CMC> {
        Arc::new(FakeDriver {
            state: Arc::clone(&self.state),
            error_on_next_ledger_call: Arc::clone(&self.error_on_next_ledger_call),
        })
    }

    pub fn get_fake_randomness_generator(&self) -> Box<dyn RandomnessGenerator> {
        Box::new(FakeDriver {
            state: Arc::clone(&self.state),
            error_on_next_ledger_call: Arc::clone(&self.error_on_next_ledger_call),
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

    pub fn fail_next_ledger_call(&self) {
        self.error_on_next_ledger_call
            .lock()
            .unwrap()
            .replace(NervousSystemError::new());
    }
}

#[async_trait]
impl IcpLedger for FakeDriver {
    #[cfg_attr(feature = "tla", tla_function(force_async_fn = true))]
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

        let from_account = AccountIdentifier::new(
            ic_base_types::PrincipalId::from(GOVERNANCE_CANISTER_ID),
            from_subaccount,
        );
        println!(
            "Issuing ledger transfer from account {} (subaccount {}) to account {} amount {} fee {}",
            from_account,
            from_subaccount
                .as_ref()
                .map_or_else(|| "None".to_string(), ToString::to_string),
            to_account,
            amount_e8s,
            fee_e8s
        );
        tla_log_request!(
            "WaitForTransfer",
            Destination::new("ledger"),
            "Transfer",
            tla::TlaValue::Record(BTreeMap::from([
                ("amount".to_string(), amount_e8s.to_tla_value()),
                ("fee".to_string(), fee_e8s.to_tla_value()),
                ("from".to_string(), account_to_tla(from_account)),
                ("to".to_string(), account_to_tla(to_account)),
            ]))
        );

        if let Some(err) = self.error_on_next_ledger_call.lock().unwrap().take() {
            println!(
                "Failing the ledger transfer because we were instructed to fail the next ledger call"
            );
            tla_log_response!(
                Destination::new("ledger"),
                tla::TlaValue::Variant {
                    tag: "Fail".to_string(),
                    value: Box::new(tla::TlaValue::Constant("UNIT".to_string()))
                }
            );
            return Err(err);
        }

        let accounts = &mut self.state.try_lock().unwrap().accounts;

        let from_e8s = accounts
            .get_mut(&from_account)
            .ok_or_else(|| NervousSystemError::new_with_message("Source account doesn't exist"))?;

        let requested_e8s = amount_e8s + fee_e8s;

        if !is_minting_operation {
            if *from_e8s < requested_e8s {
                tla_log_response!(
                    Destination::new("ledger"),
                    tla::TlaValue::Variant {
                        tag: "Fail".to_string(),
                        value: Box::new(tla::TlaValue::Constant("UNIT".to_string()))
                    }
                );
                return Err(NervousSystemError::new_with_message(format!(
                    "Insufficient funds. Available {} requested {}",
                    *from_e8s, requested_e8s
                )));
            }
            *from_e8s -= requested_e8s;
        }

        *accounts.entry(to_account).or_default() += amount_e8s;
        tla_log_response!(
            Destination::new("ledger"),
            tla::TlaValue::Variant {
                tag: "TransferOk".to_string(),
                value: Box::new(tla::TlaValue::Constant("UNIT".to_string()))
            }
        );

        Ok(0)
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        if let Some(err) = self.error_on_next_ledger_call.lock().unwrap().take() {
            return Err(err);
        }

        Ok(self.get_supply())
    }

    async fn account_balance(
        &self,
        account: AccountIdentifier,
    ) -> Result<Tokens, NervousSystemError> {
        tla_log_request!(
            "WaitForBalanceQuery",
            Destination::new("ledger"),
            "AccountBalance",
            tla::TlaValue::Record(BTreeMap::from([(
                "account".to_string(),
                account_to_tla(account)
            )]))
        );

        if let Some(err) = self.error_on_next_ledger_call.lock().unwrap().take() {
            tla_log_response!(
                Destination::new("ledger"),
                tla::TlaValue::Variant {
                    tag: "Fail".to_string(),
                    value: Box::new(tla::TlaValue::Constant("UNIT".to_string())),
                }
            );
            return Err(err);
        }

        let accounts = &mut self.state.try_lock().unwrap().accounts;

        let account_e8s = accounts.get(&account).unwrap_or(&0);
        tla_log_response!(
            Destination::new("ledger"),
            tla::TlaValue::Variant {
                tag: "BalanceQueryOk".to_string(),
                value: Box::new(account_e8s.to_tla_value()),
            }
        );
        Ok(Tokens::from_e8s(*account_e8s))
    }

    fn canister_id(&self) -> CanisterId {
        LEDGER_CANISTER_ID
    }

    async fn icrc2_approve(
        &self,
        _spender: icrc_ledger_types::icrc1::account::Account,
        _amount: u64,
        _expires_at: Option<u64>,
        _fee: u64,
        _from_subaccount: Option<icrc_ledger_types::icrc1::account::Subaccount>,
        _expected_allowance: Option<u64>,
    ) -> Result<candid::Nat, NervousSystemError> {
        Err(NervousSystemError {
            error_message: "Not Implemented".to_string(),
        })
    }

    async fn icrc3_get_blocks(
        &self,
        _args: Vec<GetBlocksRequest>,
    ) -> Result<GetBlocksResult, NervousSystemError> {
        Err(NervousSystemError {
            error_message: "Not Implemented".to_string(),
        })
    }
}

#[async_trait]
impl CMC for FakeDriver {
    async fn neuron_maturity_modulation(&self) -> Result<i32, String> {
        Ok(100)
    }
}

impl RandomnessGenerator for FakeDriver {
    fn random_u64(&mut self) -> Result<u64, RngError> {
        Ok(self.state.try_lock().unwrap().rng.next_u64())
    }

    fn random_byte_array(&mut self) -> Result<[u8; 32], RngError> {
        let mut bytes = [0u8; 32];
        self.state.try_lock().unwrap().rng.fill_bytes(&mut bytes);
        Ok(bytes)
    }

    fn seed_rng(&mut self, seed: [u8; 32]) {
        self.state.try_lock().unwrap().rng = ChaCha20Rng::from_seed(seed);
    }

    fn get_rng_seed(&self) -> Option<[u8; 32]> {
        Some(self.state.try_lock().unwrap().rng.get_seed())
    }
}

#[async_trait]
impl Environment for FakeDriver {
    fn now(&self) -> u64 {
        self.state.try_lock().unwrap().now
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

    async fn call_canister_method(
        &self,
        target: CanisterId,
        method_name: &str,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, (Option<i32>, String)> {
        if method_name == "list_deployed_snses" {
            assert_eq!(target, SNS_WASM_CANISTER_ID);

            let request = Decode!(&request, ListDeployedSnsesRequest).unwrap();
            assert_eq!(request, ListDeployedSnsesRequest {});

            return Ok(Encode!(&ListDeployedSnsesResponse {
                instances: vec![DeployedSns {
                    swap_canister_id: Some(*TARGET_SWAP_CANISTER_ID),
                    // Not realistic, but sufficient for test(s) that use this.
                    ..Default::default()
                }],
            })
            .unwrap());
        }

        if method_name == "get_state" {
            assert_eq!(PrincipalId::from(target), *TARGET_SWAP_CANISTER_ID);

            let request = Decode!(&request, sns_swap_pb::GetStateRequest).unwrap();
            assert_eq!(request, sns_swap_pb::GetStateRequest {});

            return Ok(Encode!(&sns_swap_pb::GetStateResponse {
                swap: Some(sns_swap_pb::Swap {
                    init: Some(sns_swap_pb::Init {
                        nns_governance_canister_id: GOVERNANCE_CANISTER_ID.to_string(),
                        sns_governance_canister_id: SNS_GOVERNANCE_CANISTER_ID.to_string(),
                        sns_ledger_canister_id: SNS_LEDGER_CANISTER_ID.to_string(),
                        icp_ledger_canister_id: LEDGER_CANISTER_ID.to_string(),
                        sns_root_canister_id: SNS_ROOT_CANISTER_ID.to_string(),

                        fallback_controller_principal_ids: vec![DEVELOPER_PRINCIPAL_ID.to_string()],

                        // Similar to NNS, but different.
                        transaction_fee_e8s: Some(12_345),
                        neuron_minimum_stake_e8s: Some(123_456_789),
                        confirmation_text: None,
                        restricted_countries: None,

                        min_participants: None, // TODO[NNS1-2339]
                        min_icp_e8s: None,      // TODO[NNS1-2339]
                        max_icp_e8s: None,      // TODO[NNS1-2339]
                        min_direct_participation_icp_e8s: None, // TODO[NNS1-2339]
                        max_direct_participation_icp_e8s: None, // TODO[NNS1-2339]
                        min_participant_icp_e8s: None, // TODO[NNS1-2339]
                        max_participant_icp_e8s: None, // TODO[NNS1-2339]
                        swap_start_timestamp_seconds: None, // TODO[NNS1-2339]
                        swap_due_timestamp_seconds: None, // TODO[NNS1-2339]
                        sns_token_e8s: None,    // TODO[NNS1-2339]
                        neuron_basket_construction_parameters: None, // TODO[NNS1-2339]
                        nns_proposal_id: None,  // TODO[NNS1-2339]
                        should_auto_finalize: Some(true),
                        neurons_fund_participation_constraints: None,
                        neurons_fund_participation: None,
                    }),
                    ..Default::default() // Not realistic, but sufficient for tests.
                }),
                ..Default::default() // Ditto previous comment.
            })
            .unwrap());
        }

        if method_name == "get_sns_canisters_summary" {
            assert_eq!(PrincipalId::from(target), *SNS_ROOT_CANISTER_ID);

            let request = Decode!(&request, GetSnsCanistersSummaryRequest).unwrap();
            assert_eq!(
                request,
                GetSnsCanistersSummaryRequest {
                    update_canister_list: None
                }
            );

            return Ok(Encode!(&GetSnsCanistersSummaryResponse {
                root: Some(ic_sns_root::CanisterSummary {
                    canister_id: Some(*SNS_ROOT_CANISTER_ID),
                    status: None,
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
            .unwrap());
        }

        if method_name == "get_node_providers_monthly_xdr_rewards" {
            assert_eq!(PrincipalId::from(target), NODE_REWARDS_CANISTER_ID.get());

            return Ok(Encode!(&GetNodeProvidersMonthlyXdrRewardsResponse {
                rewards: Some(
                    ic_node_rewards_canister_api::monthly_rewards::NodeProvidersMonthlyXdrRewards {
                        rewards: btreemap! {
                            PrincipalId::new_user_test_id(1).0 => NODE_PROVIDER_REWARD,
                        },
                        registry_version: Some(5)
                    }
                ),
                error: None
            })
            .unwrap());
        }

        if method_name == "get_node_providers_rewards" {
            assert_eq!(PrincipalId::from(target), NODE_REWARDS_CANISTER_ID.get());

            let response: GetNodeProvidersRewardsResponse = Ok(NodeProvidersRewards {
                rewards_xdr_permyriad: btreemap! {
                    PrincipalId::new_user_test_id(1).0 => NODE_PROVIDER_REWARD,
                },
                algorithm_version: RewardsCalculationAlgorithmVersion::default(),
            });

            return Ok(Encode!(&response).unwrap());
        }

        if method_name == "get_average_icp_xdr_conversion_rate" {
            assert_eq!(PrincipalId::from(target), CYCLES_MINTING_CANISTER_ID.get());

            return Ok(Encode!(&IcpXdrConversionRateCertifiedResponse {
                data: IcpXdrConversionRate {
                    timestamp_seconds: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    xdr_permyriad_per_icp: 1 // Below the minimum exchange rate limit
                },
                hash_tree: vec![],
                certificate: vec![],
            })
            .unwrap());
        }

        if method_name == "raw_rand" {
            let mut bytes = [0u8; 32];
            self.state.try_lock().unwrap().rng.fill_bytes(&mut bytes);
            return Ok(Encode!(&bytes).unwrap());
        }

        println!(
            "WARNING: Unexpected canister call:\n\
             ..target = {}\n\
             ..method_name = {}\n\
             ..request.len() = {}",
            target,
            method_name,
            request.len(),
        );

        Ok(vec![])
    }
}

/// Constructs a test principal id from an integer.
/// Convenience functions to make creating neurons more concise.
pub fn principal(i: u64) -> PrincipalId {
    PrincipalId::try_from(format!("SID{i}").as_bytes().to_vec()).unwrap()
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
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum ProposalTopicBehavior {
    Governance,
    NetworkEconomics,
}

/// A struct to help setting up tests concisely thanks to a concise format to
/// specifies who proposes something and who votes on that proposal.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct ProposalNeuronBehavior {
    /// Neuron id of the proposer.
    pub proposer: u64,
    /// Map neuron id of voters to their votes.
    pub votes: BTreeMap<u64, Vote>,
    /// Keep track of proposal topic to use.
    pub proposal_topic: ProposalTopicBehavior,
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
            ProposalTopicBehavior::Governance => proposal::Action::Motion(Motion {
                motion_text: format!("summary: {summary}"),
            }),
            ProposalTopicBehavior::NetworkEconomics => {
                proposal::Action::ManageNetworkEconomics(NetworkEconomics {
                    ..Default::default()
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
            .now_or_never()
            .unwrap()
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
    /// neuron_behaviour: each subsequent character corresponds to the
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
    /// "--yP-nyG" means:
    ///
    /// neuron 3 proposes, neurons 2 and 6 votes yes, neuron 5 votes
    /// no, neurons 0, 1, and 4 do not vote; the proposal topic is
    /// Governance.
    fn from(str: &str) -> ProposalNeuronBehavior {
        // Look at the last letter to figure out if it specifies a proposal type.
        let chr = if str.is_empty() {
            ' '
        } else {
            str.chars().last().unwrap()
        };
        let (str, proposal_topic) = match "NG".find(chr) {
            None => (str, ProposalTopicBehavior::NetworkEconomics),
            Some(x) => (
                &str[0..str.len() - 1],
                match x {
                    0 => ProposalTopicBehavior::NetworkEconomics,
                    // Must be 1, but using _ for a complete match.
                    _ => ProposalTopicBehavior::Governance,
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
