use crate::SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES;
use candid::types::number::Nat;
use canister_test::{local_test_with_config_e, Canister, CanisterIdRecord, Project, Runtime, Wasm};
use dfn_candid::{candid_one, CandidOne};
use ic_canister_client_sender::Sender;
use ic_config::subnet_config::SubnetConfig;
use ic_config::Config;
use ic_crypto_sha::Sha256;
use ic_icrc1::{endpoints::TransferArg, Account, Subaccount};
use ic_icrc1_ledger::InitArgs as LedgerInitArgs;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::Tokens;
use ic_nervous_system_root::{CanisterStatusResult, CanisterStatusType};
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID as NNS_GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID,
};
use ic_sns_governance::{
    governance::TimeWarp,
    init::GovernanceCanisterInitPayloadBuilder,
    pb::v1::{
        get_neuron_response, get_proposal_response,
        manage_neuron::{
            claim_or_refresh::{By, MemoAndController},
            configure::Operation,
            disburse::Amount,
            AddNeuronPermissions, ClaimOrRefresh, Command, Configure, Disburse, Follow,
            IncreaseDissolveDelay, RegisterVote, RemoveNeuronPermissions, Split, StartDissolving,
        },
        manage_neuron_response::Command as CommandResponse,
        proposal::Action,
        Account as AccountProto, GetNeuron, GetNeuronResponse, GetProposal, GetProposalResponse,
        Governance, GovernanceError, ListNervousSystemFunctionsResponse, ListNeurons,
        ListNeuronsResponse, ListProposals, ListProposalsResponse, ManageNeuron,
        ManageNeuronResponse, Motion, NervousSystemParameters, Neuron, NeuronId,
        NeuronPermissionList, Proposal, ProposalData, ProposalId, RewardEvent,
        Subaccount as SubaccountProto, Vote,
    },
    types::DEFAULT_TRANSFER_FEE,
};
use ic_sns_init::SnsCanisterInitPayloads;
use ic_sns_root::{
    pb::v1::{RegisterDappCanisterRequest, RegisterDappCanisterResponse, SnsRootCanister},
    GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse,
};
use ic_sns_swap::pb::v1::Init as SwapInit;
use ic_types::{CanisterId, PrincipalId};
use maplit::btreemap;
use on_wire::IntoWire;
use std::future::Future;
use std::path::Path;
use std::thread;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};

/// Constant nonce to use when generating the subaccount. Using a constant nonce
/// allows the testing environment to calculate what a given subaccount will
/// be before it's created.
pub const NONCE: u64 = 12345_u64;

/// Constant that defines the time in tenths of a second to wait for a test
pub const TIME_FOR_HEARTBEAT: u64 = 200;

/// Packages commonly used test data into a single struct.
#[derive(Clone)]
pub struct UserInfo {
    pub subaccount: Subaccount,
    pub neuron_id: NeuronId,
    pub sender: Sender,
}

impl UserInfo {
    /// The subaccount and NeuronId can be calculated ahead of time given a Sender.
    /// Note: Even though this methods calculates the NeuronId, the Neuron will still
    /// need to be staked and claimed for it to exist in the SNS.
    pub fn new(sender: Sender) -> Self {
        let subaccount = {
            let mut state = Sha256::new();
            state.write(&[0x0c]);
            state.write(b"neuron-stake");
            state.write(sender.get_principal_id().as_slice());
            state.write(&NONCE.to_be_bytes());
            state.finish()
        };

        let neuron_id = NeuronId {
            id: subaccount.to_vec(),
        };

        UserInfo {
            subaccount,
            neuron_id,
            sender,
        }
    }
}

/// Builder to help create the initial payloads for the SNS canisters in tests.
pub struct SnsTestsInitPayloadBuilder {
    pub governance: GovernanceCanisterInitPayloadBuilder,
    pub ledger: LedgerInitArgs,
    pub root: SnsRootCanister,
    pub swap: SwapInit,
}

#[allow(clippy::new_without_default)]
impl SnsTestsInitPayloadBuilder {
    pub fn new() -> SnsTestsInitPayloadBuilder {
        let ledger = LedgerInitArgs {
            // minting_account will be set when the Governance canister ID is allocated
            minting_account: Account {
                owner: PrincipalId::default(),
                subaccount: None,
            },
            initial_balances: vec![],
            archive_options: ArchiveOptions {
                trigger_threshold: 2000,
                num_blocks_to_archive: 1000,
                // 1 GB, which gives us 3 GB space when upgrading
                node_max_memory_size_bytes: Some(1024 * 1024 * 1024),
                // 128kb
                max_message_size_bytes: Some(128 * 1024),
                // controller_id will be set when the Root canister ID is allocated
                controller_id: CanisterId::from_u64(0).into(),
                cycles_for_archive_creation: Some(0),
            },
            transfer_fee: DEFAULT_TRANSFER_FEE.get_e8s(),
            token_symbol: "TKX".to_string(),
            token_name: "Token Example".to_string(),
            metadata: vec![],
        };

        SnsTestsInitPayloadBuilder {
            root: SnsRootCanister::default(),
            governance: GovernanceCanisterInitPayloadBuilder::new(),
            ledger,
            swap: SwapInit::default(),
        }
    }

    pub fn with_ledger_init_state(&mut self, state: LedgerInitArgs) -> &mut Self {
        self.ledger = state;
        self
    }

    pub fn with_ledger_account(&mut self, account: Account, icpts: Tokens) -> &mut Self {
        self.ledger
            .initial_balances
            .push((account, icpts.get_e8s()));
        self
    }

    pub fn with_ledger_accounts(&mut self, accounts: Vec<Account>, tokens: Tokens) -> &mut Self {
        for account in accounts {
            self.ledger
                .initial_balances
                .push((account, tokens.get_e8s()));
        }
        self
    }

    pub fn with_governance_init_payload(
        &mut self,
        governance_init_payload_builder: GovernanceCanisterInitPayloadBuilder,
    ) -> &mut Self {
        self.governance = governance_init_payload_builder;
        self
    }

    pub fn with_nervous_system_parameters(&mut self, params: NervousSystemParameters) -> &mut Self {
        self.governance.with_parameters(params);
        self
    }

    pub fn with_initial_neurons(&mut self, neurons: Vec<Neuron>) -> &mut Self {
        let mut neuron_map = btreemap! {};
        for neuron in neurons {
            neuron_map.insert(neuron.id.as_ref().unwrap().to_string(), neuron);
        }
        self.governance.with_neurons(neuron_map);
        self
    }

    pub fn build(&mut self) -> SnsCanisterInitPayloads {
        SnsCanisterInitPayloads {
            governance: self.governance.build(),
            ledger: self.ledger.clone(),
            root: self.root.clone(),
            swap: self.swap.clone(),
        }
    }
}

pub fn populate_canister_ids(
    root_canister_id: CanisterId,
    governance_canister_id: CanisterId,
    ledger_canister_id: CanisterId,
    swap_canister_id: CanisterId,
    sns_canister_init_payloads: &mut SnsCanisterInitPayloads,
) {
    let root_canister_id = Some(PrincipalId::from(root_canister_id));
    let governance_canister_id = Some(PrincipalId::from(governance_canister_id));
    let ledger_canister_id = Some(PrincipalId::from(ledger_canister_id));
    let swap_canister_id = Some(PrincipalId::from(swap_canister_id));

    // Root.
    {
        let root = &mut sns_canister_init_payloads.root;
        if root.governance_canister_id.is_none() {
            root.governance_canister_id = governance_canister_id;
        }
        if root.ledger_canister_id.is_none() {
            root.ledger_canister_id = ledger_canister_id;
        }
        if root.swap_canister_id.is_none() {
            root.swap_canister_id = swap_canister_id;
        }
    }

    // Governance canister_init args.
    {
        let governance = &mut sns_canister_init_payloads.governance;
        governance.ledger_canister_id = ledger_canister_id;
        governance.root_canister_id = root_canister_id;
        governance.swap_canister_id = swap_canister_id;
    }

    // Ledger
    {
        let ledger = &mut sns_canister_init_payloads.ledger;
        ledger.minting_account = Account {
            owner: governance_canister_id.unwrap(),
            subaccount: None,
        };
        ledger.archive_options.controller_id = root_canister_id.unwrap();
    }

    // Swap
    {
        let swap = &mut sns_canister_init_payloads.swap;
        swap.sns_root_canister_id = root_canister_id.unwrap().to_string();
        swap.sns_governance_canister_id = governance_canister_id.unwrap().to_string();
        swap.sns_ledger_canister_id = ledger_canister_id.unwrap().to_string();

        swap.nns_governance_canister_id = NNS_GOVERNANCE_CANISTER_ID.to_string();
        swap.icp_ledger_canister_id = ICP_LEDGER_CANISTER_ID.to_string();
    }
}

/// All the SNS canisters
#[derive(Clone)]
pub struct SnsCanisters<'a> {
    pub root: Canister<'a>,
    pub governance: Canister<'a>,
    pub ledger: Canister<'a>,
    pub swap: Canister<'a>,
}

impl SnsCanisters<'_> {
    /// Creates and installs all of the SNS canisters
    pub async fn set_up(
        runtime: &'_ Runtime,
        mut init_payloads: SnsCanisterInitPayloads,
    ) -> SnsCanisters<'_> {
        let since_start_secs = {
            let s = SystemTime::now();
            move || (SystemTime::now().duration_since(s).unwrap()).as_secs_f32()
        };

        let mut root = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Couldn't create Root canister");

        let mut governance = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Couldn't create Governance canister");

        let mut ledger = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Couldn't create Ledger canister");

        let mut swap = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Couldn't create Ledger canister");

        let root_canister_id = root.canister_id();
        let governance_canister_id = governance.canister_id();
        let ledger_canister_id = ledger.canister_id();
        let swap_canister_id = swap.canister_id();

        populate_canister_ids(
            root_canister_id,
            governance_canister_id,
            ledger_canister_id,
            swap_canister_id,
            &mut init_payloads,
        );

        assert!(!init_payloads.ledger.initial_balances.iter().any(|(a, _)| a
            == &Account {
                owner: governance_canister_id.get(),
                subaccount: None
            }));

        // Set initial neurons
        for n in init_payloads.governance.neurons.values() {
            let sub = n
                .subaccount()
                .unwrap_or_else(|e| panic!("Couldn't calculate subaccount from neuron: {}", e));
            let aid = Account {
                owner: governance_canister_id.get(),
                subaccount: Some(sub),
            };
            init_payloads
                .ledger
                .initial_balances
                .push((aid, n.cached_neuron_stake_e8s));
        }

        // Install canisters
        futures::join!(
            install_governance_canister(&mut governance, init_payloads.governance.clone()),
            install_ledger_canister(&mut ledger, init_payloads.ledger),
            install_root_canister(&mut root, init_payloads.root),
            install_swap_canister(&mut swap, init_payloads.swap),
        );

        eprintln!("SNS canisters installed after {:.1} s", since_start_secs());

        // We can set all the controllers at once. Several -- or all -- may go
        // into the same block, this makes setup faster.
        futures::try_join!(
            root.set_controller_with_retries(governance_canister_id.get()),
            governance.set_controller_with_retries(root_canister_id.get()),
            ledger.set_controller_with_retries(root_canister_id.get()),
            // Swap Canister is controlled by NNS Root and Swap itself. For the integration tests
            // add the swap canister as its own controller, and leave the Runtime in control
            // as well for some amount of control
            swap.add_controller(swap_canister_id.get()),
        )
        .unwrap();

        eprintln!("SNS canisters set up after {:.1} s", since_start_secs());

        SnsCanisters {
            root,
            governance,
            ledger,
            swap,
        }
    }

    /// Make a Governance proposal
    pub async fn make_proposal(
        &self,
        sender: &Sender,
        subaccount: &Subaccount,
        proposal: Proposal,
    ) -> Result<ProposalId, GovernanceError> {
        let manage_neuron_response: ManageNeuronResponse = self
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::MakeProposal(proposal)),
                },
                sender,
            )
            .await
            .expect("Error calling manage_neuron");

        match manage_neuron_response.command.unwrap() {
            CommandResponse::Error(e) => Err(e),
            CommandResponse::MakeProposal(make_proposal_response) => {
                Ok(make_proposal_response.proposal_id.unwrap())
            }
            _ => panic!("Unexpected MakeProposal response"),
        }
    }

    /// Get a proposal
    pub async fn get_proposal(&self, proposal_id: ProposalId) -> ProposalData {
        let get_proposal_response: GetProposalResponse = self
            .governance
            .query_(
                "get_proposal",
                candid_one,
                GetProposal {
                    proposal_id: Some(proposal_id),
                },
            )
            .await
            .expect("Error calling get_proposal");

        match get_proposal_response
            .result
            .expect("Empty get_proposal_response")
        {
            get_proposal_response::Result::Error(e) => {
                panic!("get_proposal error: {}", e);
            }
            get_proposal_response::Result::Proposal(proposal) => proposal,
        }
    }

    /// Get a neuron
    pub async fn get_neuron(&self, neuron_id: &NeuronId) -> Neuron {
        let get_neuron_response: GetNeuronResponse = self
            .governance
            .query_(
                "get_neuron",
                candid_one,
                GetNeuron {
                    neuron_id: Some(neuron_id.clone()),
                },
            )
            .await
            .expect("Error calling get_neuron");

        match get_neuron_response
            .result
            .expect("Empty get_neuron_response")
        {
            get_neuron_response::Result::Error(e) => {
                panic!("get_neuron error: {}", e)
            }
            get_neuron_response::Result::Neuron(neuron) => neuron,
        }
    }

    /// Stake a neuron in the given SNS.
    ///
    /// Assumes `sender` has an account on the Ledger containing at least 100 tokens.
    pub async fn stake_and_claim_neuron(
        &self,
        sender: &Sender,
        dissolve_delay: Option<u32>,
    ) -> NeuronId {
        self.stake_and_claim_neuron_with_tokens(sender, dissolve_delay, 100)
            .await
    }

    /// Stake a neuron in the given SNS.
    ///
    /// Assumes `sender` has an account on the Ledger containing at least `token_amount` tokens.
    pub async fn stake_and_claim_neuron_with_tokens(
        &self,
        sender: &Sender,
        dissolve_delay: Option<u32>,
        token_amount: u64,
    ) -> NeuronId {
        // Stake a neuron by transferring to a subaccount of the neurons
        // canister and claiming the neuron on the governance canister..
        let to_subaccount = {
            let mut state = Sha256::new();
            state.write(&[0x0c]);
            state.write(b"neuron-stake");
            state.write(sender.get_principal_id().as_slice());
            state.write(&NONCE.to_be_bytes());
            state.finish()
        };

        self.stake_neuron_account(sender, &to_subaccount, token_amount)
            .await;

        // Claim the neuron on the governance canister.
        let claim_response: ManageNeuronResponse = self
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: to_subaccount.to_vec(),
                    command: Some(Command::ClaimOrRefresh(ClaimOrRefresh {
                        by: Some(By::MemoAndController(MemoAndController {
                            memo: NONCE,
                            controller: None,
                        })),
                    })),
                },
                sender,
            )
            .await
            .expect("Error calling the manage_neuron API.");

        let neuron_id = match claim_response.command.unwrap() {
            CommandResponse::ClaimOrRefresh(response) => {
                println!(
                    "User {} successfully claimed neuron",
                    sender.get_principal_id()
                );

                response.refreshed_neuron_id.unwrap()
            }
            CommandResponse::Error(error) => panic!(
                "Unexpected error when claiming neuron for user {}: {}",
                sender.get_principal_id(),
                error
            ),
            _ => panic!(
                "Unexpected command response when claiming neuron for user {}.",
                sender.get_principal_id()
            ),
        };

        // Increase dissolve delay
        if let Some(dissolve_delay) = dissolve_delay {
            self.increase_dissolve_delay(sender, &to_subaccount, dissolve_delay)
                .await;
        }

        neuron_id
    }

    pub async fn list_nervous_system_functions(&self) -> ListNervousSystemFunctionsResponse {
        self.governance
            .query_("list_nervous_system_functions", candid_one, ())
            .await
            .expect("Error calling list_nervous_system_functions")
    }

    pub async fn stake_neuron_account(
        &self,
        sender: &Sender,
        to_subaccount: &Subaccount,
        token_amount: u64,
    ) -> u64 {
        // Stake the neuron.
        let stake = Tokens::from_tokens(token_amount).unwrap();
        let block_height = crate::icrc1::transfer(
            &self.ledger,
            sender,
            TransferArg {
                amount: Nat::from(stake.get_e8s()),
                fee: Some(Nat::from(DEFAULT_TRANSFER_FEE.get_e8s())),
                from_subaccount: None,
                to: Account {
                    owner: PrincipalId::from(self.governance.canister_id()),
                    subaccount: Some(*to_subaccount),
                },
                memo: None,
                created_at_time: Some(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64,
                ),
            },
        )
        .await
        .expect("Couldn't send funds.");
        block_height
    }

    pub async fn increase_dissolve_delay(
        &self,
        sender: &Sender,
        subaccount: &Subaccount,
        dissolve_delay: u32,
    ) {
        let increase_response: ManageNeuronResponse = self
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::Configure(Configure {
                        operation: Some(Operation::IncreaseDissolveDelay(IncreaseDissolveDelay {
                            additional_dissolve_delay_seconds: dissolve_delay,
                        })),
                    })),
                },
                sender,
            )
            .await
            .expect("Error calling the manage_neuron API.");

        match increase_response.command.unwrap() {
            CommandResponse::Configure(_) => (),
            CommandResponse::Error(error) => panic!(
                "Unexpected error when increasing dissolve delay for user {}: {}",
                sender.get_principal_id(),
                error
            ),
            _ => panic!(
                "Unexpected command response when increasing dissolve delay for user {}.",
                sender.get_principal_id()
            ),
        };
    }

    pub async fn start_dissolving(
        &self,
        sender: &Sender,
        subaccount: &Subaccount,
    ) -> ManageNeuronResponse {
        self.send_manage_neuron(
            sender,
            ManageNeuron {
                subaccount: subaccount.to_vec(),
                command: Some(Command::Configure(Configure {
                    operation: Some(Operation::StartDissolving(StartDissolving {})),
                })),
            },
        )
        .await
    }

    pub async fn vote(
        &self,
        sender: &Sender,
        subaccount: &Subaccount,
        proposal_id: ProposalId,
        accept: bool,
    ) -> ManageNeuronResponse {
        let vote = if accept { Vote::Yes } else { Vote::No } as i32;

        self.send_manage_neuron(
            sender,
            ManageNeuron {
                subaccount: subaccount.to_vec(),
                command: Some(Command::RegisterVote(RegisterVote {
                    proposal: Some(proposal_id),
                    vote,
                })),
            },
        )
        .await
    }

    pub async fn follow(
        &self,
        sender: &Sender,
        subaccount: &Subaccount,
        followees: Vec<NeuronId>,
        function_id: u64,
    ) -> ManageNeuronResponse {
        self.send_manage_neuron(
            sender,
            ManageNeuron {
                subaccount: subaccount.to_vec(),
                command: Some(Command::Follow(Follow {
                    function_id,
                    followees,
                })),
            },
        )
        .await
    }

    pub async fn disburse_neuron(
        &self,
        sender: &Sender,
        subaccount: &Subaccount,
        amount_e8s: Option<u64>,
        to_account: Option<Account>,
    ) -> ManageNeuronResponse {
        let amount = amount_e8s.map(|e8s| Amount { e8s });

        let to_account: Option<AccountProto> =
            to_account.map(|Account { owner, subaccount }| AccountProto {
                owner: Some(owner),
                subaccount: subaccount.map(|s| SubaccountProto {
                    subaccount: s.to_vec(),
                }),
            });

        self.send_manage_neuron(
            sender,
            ManageNeuron {
                subaccount: subaccount.to_vec(),
                command: Some(Command::Disburse(Disburse { amount, to_account })),
            },
        )
        .await
    }

    pub async fn split_neuron(
        &self,
        sender: &Sender,
        subaccount: &Subaccount,
        amount_e8s: u64,
        memo: u64,
    ) -> ManageNeuronResponse {
        self.send_manage_neuron(
            sender,
            ManageNeuron {
                subaccount: subaccount.to_vec(),
                command: Some(Command::Split(Split { amount_e8s, memo })),
            },
        )
        .await
    }

    /// Frequently tests will call the `ManageNeuron::Split` command knowing it will fail.
    /// This method will call the API and parse the error response in a useful way. Use
    /// this method when intentionally expecting a failure.
    pub async fn split_neuron_with_failure(
        &self,
        sender: &Sender,
        subaccount: &Subaccount,
        amount_e8s: u64,
        memo: u64,
    ) -> GovernanceError {
        let split_response = self
            .split_neuron(sender, subaccount, amount_e8s, memo)
            .await;

        match split_response.command.unwrap() {
            CommandResponse::Split(_) => {
                panic!("Splitting a neuron should have produced a GovernanceError")
            }
            CommandResponse::Error(error) => error,
            _ => panic!("Unexpected command response when Calling ManageNeuron::Split"),
        }
    }

    pub async fn get_user_account_balance(&self, sender: &Sender) -> Tokens {
        crate::icrc1::balance_of(
            &self.ledger,
            Account {
                owner: sender.get_principal_id(),
                subaccount: None,
            },
        )
        .await
        .map(Tokens::from_e8s)
        .expect("Error calling the Ledger's get_account_balancer")
    }

    pub async fn list_neurons(&self, sender: &Sender) -> Vec<Neuron> {
        self.list_neurons_(sender, 100, None).await
    }

    pub async fn list_neurons_(
        &self,
        sender: &Sender,
        limit: u32,
        of_principal: Option<PrincipalId>,
    ) -> Vec<Neuron> {
        let list_neuron_response: ListNeuronsResponse = self
            .governance
            .query_from_sender(
                "list_neurons",
                candid_one,
                ListNeurons {
                    limit,
                    start_page_at: None,
                    of_principal,
                },
                sender,
            )
            .await
            .expect("Error calling the list_neurons API");

        list_neuron_response.neurons
    }

    pub async fn list_proposals(&self, sender: &Sender) -> Vec<ProposalData> {
        self.list_proposals_(sender, 100).await
    }

    pub async fn list_proposals_(&self, sender: &Sender, limit: u32) -> Vec<ProposalData> {
        let list_proposal_response: ListProposalsResponse = self
            .governance
            .query_from_sender(
                "list_proposals",
                candid_one,
                ListProposals {
                    limit,
                    ..Default::default()
                },
                sender,
            )
            .await
            .expect("Error calling the list_proposals API");

        list_proposal_response.proposals
    }

    pub async fn get_nervous_system_parameters(&self) -> NervousSystemParameters {
        self.governance
            .query_("get_nervous_system_parameters", candid_one, ())
            .await
            .expect("Error calling the get_nervous_system_parameters API")
    }

    /// Earn maturity for the given NeuronId. NOTE: This method is only usable
    /// if there is a single neuron created in the SNS as it relies on
    /// submitting proposals that automatically pass via majority voting. It will
    /// also advance time using TimeWarp which is only available in non-production
    /// builds of the SNS.
    pub async fn earn_maturity(&self, neuron_id: &NeuronId, sender: &Sender) -> Result<(), String> {
        if self.list_neurons(sender).await.len() != 1 {
            panic!("earn_maturity cannot be invoked with more than one neuron in the SNS");
        }

        // Make and immediately vote on a proposal so that the neuron earns some rewards aka maturity.
        let proposal = Proposal {
            title: "A proposal that should pass unanimously".into(),
            action: Some(Action::Motion(Motion {
                motion_text: "GIMMIE MATURITY".into(),
            })),
            ..Default::default()
        };

        let subaccount = neuron_id
            .subaccount()
            .expect("Error creating the subaccount");

        // Submit a motion proposal. It should then be executed because the
        // submitter has a majority stake and submitting also votes automatically.
        let proposal_id = self
            .make_proposal(sender, &subaccount, proposal)
            .await
            .unwrap();

        let initial_voting_period_seconds = self
            .get_nervous_system_parameters()
            .await
            .initial_voting_period_seconds
            .unwrap();

        // Advance time to have the proposal be eligible for rewards
        let delta_s = (initial_voting_period_seconds + 1) as i64;
        self.set_time_warp(delta_s).await?;

        let mut proposal = self.get_proposal(proposal_id).await;

        // Wait for a canister heartbeat to allow this proposal to be rewarded
        let start = Instant::now();
        let waiting_for_minutes = || {
            let d = Instant::now() - start;

            d.as_secs_f64() / 60.0
        };
        while proposal.reward_event_round == 0 {
            const TIME_OUT_MINUTES: f64 = 10.0;
            assert!(
                waiting_for_minutes() < TIME_OUT_MINUTES,
                "Rewards did not show up after {} minutes.",
                TIME_OUT_MINUTES
            );

            std::thread::sleep(std::time::Duration::from_millis(100));
            proposal = self.get_proposal(proposal_id).await;
        }

        Ok(())
    }

    pub async fn set_time_warp(&self, delta_s: i64) -> Result<(), String> {
        self.governance
            .update_("set_time_warp", candid_one, TimeWarp { delta_s })
            .await
    }

    pub async fn add_neuron_permissions(
        &self,
        sender: &Sender,
        subaccount: &Subaccount,
        principal_to_add: Option<PrincipalId>,
        permissions: Vec<i32>,
    ) {
        let add_neuron_permissions = AddNeuronPermissions {
            principal_id: principal_to_add,
            permissions_to_add: Some(NeuronPermissionList { permissions }),
        };

        let manage_neuron_response: ManageNeuronResponse = self
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::AddNeuronPermissions(add_neuron_permissions)),
                },
                sender,
            )
            .await
            .expect("Error calling manage_neuron");

        match manage_neuron_response.command.unwrap() {
            CommandResponse::AddNeuronPermission(_) => (),
            response => panic!("Unexpected response from manage_neuron: {:?}", response),
        };
    }

    pub async fn remove_neuron_permissions(
        &self,
        sender: &Sender,
        subaccount: &Subaccount,
        principal_to_remove: &PrincipalId,
        permissions: Vec<i32>,
    ) {
        let remove_neuron_permissions = RemoveNeuronPermissions {
            principal_id: Some(*principal_to_remove),
            permissions_to_remove: Some(NeuronPermissionList { permissions }),
        };

        let manage_neuron_response: ManageNeuronResponse = self
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::RemoveNeuronPermissions(remove_neuron_permissions)),
                },
                sender,
            )
            .await
            .expect("Error calling manage_neuron");

        match manage_neuron_response.command.unwrap() {
            CommandResponse::RemoveNeuronPermission(_) => (),
            response => panic!("Unexpected response from manage_neuron: {:?}", response),
        };
    }

    pub async fn manage_nervous_system_parameters(
        &self,
        sender: &Sender,
        subaccount: &Subaccount,
        nervous_system_parameters: NervousSystemParameters,
    ) -> Result<ProposalId, GovernanceError> {
        let proposal = Proposal {
            title: "ManageNervousSystemParameters proposal".into(),
            action: Some(Action::ManageNervousSystemParameters(
                nervous_system_parameters,
            )),
            ..Default::default()
        };

        self.make_proposal(sender, subaccount, proposal).await
    }

    pub async fn get_latest_reward_event(&self) -> RewardEvent {
        self.governance
            .query_("get_latest_reward_event", candid_one, ())
            .await
            .expect("Error calling get_latest_reward_event")
    }

    /// Await a RewardEvent to be created.
    pub async fn await_reward_event(&self, last_round: u64) -> RewardEvent {
        for _ in 0..TIME_FOR_HEARTBEAT {
            let reward_event = self.get_latest_reward_event().await;

            if reward_event.round > last_round {
                return reward_event;
            }
            sleep(Duration::from_millis(100));
        }

        panic!("There was no RewardEvent greater than {:?}", last_round)
    }

    /// Await a Proposal being rewarded via it's reward_event_round field.
    pub async fn await_proposal_rewarding(&self, proposal_id: ProposalId) -> u64 {
        for _ in 0..TIME_FOR_HEARTBEAT {
            let proposal = self.get_proposal(proposal_id).await;

            if proposal.reward_event_round != 0 {
                return proposal.reward_event_round;
            }
            sleep(Duration::from_millis(100));
        }
        panic!("Proposal {:?} was not rewarded", proposal_id);
    }

    /// Get an SNS canister status from Root
    pub async fn canister_status(&self, canister_id: CanisterId) -> CanisterStatusResult {
        self.root
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_id),
            )
            .await
            .unwrap()
    }

    /// Await an SNS canister completing an upgrade. This method should be called after the
    /// execution of an upgrade proposal.
    pub async fn await_canister_upgrade(&self, canister_id: CanisterId) {
        for _ in 0..25 {
            let status = self.canister_status(canister_id).await;
            // Stop waiting once the canister has reached the Running state.
            if status.status == CanisterStatusType::Running {
                return;
            }

            sleep(Duration::from_millis(100));
        }
        panic!(
            "Canister {} didn't reach the running state after upgrading",
            canister_id
        )
    }

    /// Get the summary of the SNS from root
    pub async fn get_sns_canisters_summary(
        &self,
        update_canister_list: Option<bool>,
    ) -> GetSnsCanistersSummaryResponse {
        self.root
            .update_(
                "get_sns_canisters_summary",
                candid_one,
                GetSnsCanistersSummaryRequest {
                    update_canister_list,
                },
            )
            .await
            .expect("Error calling the get_sns_canisters_summary API")
    }

    async fn send_manage_neuron(
        &self,
        sender: &Sender,
        manage_neuron: ManageNeuron,
    ) -> ManageNeuronResponse {
        self.governance
            .update_from_sender("manage_neuron", candid_one, manage_neuron, sender)
            .await
            .expect("Error calling the manage_neuron")
    }

    pub async fn register_dapp_canister(
        &self,
        canister_id: CanisterId,
    ) -> RegisterDappCanisterResponse {
        self.root
            .update_(
                "register_dapp_canister",
                candid_one,
                RegisterDappCanisterRequest {
                    canister_id: Some(canister_id.get()),
                },
            )
            .await
            .expect("Call to register_dapp_canister failed")
    }
}

/// Installs a rust canister with the provided memory allocation.
pub async fn install_rust_canister_with_memory_allocation(
    canister: &mut Canister<'_>,
    relative_path_from_rs: impl AsRef<Path>,
    binary_name: impl AsRef<str>,
    cargo_features: &[&str],
    canister_init_payload: Option<Vec<u8>>,
    memory_allocation: u64, // in bytes
) {
    // Some ugly code to allow copying AsRef<Path> and features (an array slice) into new thread
    // neither of these implement Send or have a way to clone the whole structure's data
    let path_string = relative_path_from_rs.as_ref().to_str().unwrap().to_owned();
    let binary_name_ = binary_name.as_ref().to_string();
    let features = cargo_features
        .iter()
        .map(|s| s.to_string())
        .collect::<Box<[String]>>();

    // Wrapping call to cargo_bin_* to avoid blocking current thread
    let wasm: Wasm = tokio::runtime::Handle::current()
        .spawn_blocking(move || {
            println!(
                "Compiling Wasm for {} in task on thread: {:?}",
                binary_name_,
                thread::current().id()
            );
            // Second half of moving data had to be done in-thread to avoid lifetime/ownership issues
            let features = features.iter().map(|s| s.as_str()).collect::<Box<[&str]>>();
            let path = Path::new(&path_string);
            Project::cargo_bin_maybe_use_path_relative_to_rs(path, &binary_name_, &features)
        })
        .await
        .unwrap();

    println!("Done compiling the wasm for {}", binary_name.as_ref());

    wasm.install_with_retries_onto_canister(
        canister,
        canister_init_payload,
        Some(memory_allocation),
    )
    .await
    .unwrap_or_else(|e| panic!("Could not install {} due to {}", binary_name.as_ref(), e));
    println!(
        "Installed {} with {}",
        canister.canister_id(),
        binary_name.as_ref()
    );
}

/// Runs a local test on the sns subnetwork, so that the canister will be
/// assigned the same ids as in prod.
pub fn local_test_on_sns_subnet<Fut, Out, F>(run: F) -> Out
where
    Fut: Future<Output = Result<Out, String>>,
    F: FnOnce(Runtime) -> Fut + 'static,
{
    let (config, _tmpdir) = Config::temp_config();
    local_test_with_config_e(config, SubnetConfig::default_system_subnet(), run)
}

/// Compiles the governance canister, builds it's initial payload and installs
/// it
pub async fn install_governance_canister(canister: &mut Canister<'_>, init_payload: Governance) {
    install_rust_canister_with_memory_allocation(
        canister,
        "sns/governance",
        "sns-governance-canister",
        &[],
        Some(CandidOne(init_payload).into_bytes().unwrap()),
        SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES,
    )
    .await;
}

/// Creates and installs the governance canister.
pub async fn set_up_governance_canister(
    runtime: &'_ Runtime,
    init_payload: Governance,
) -> Canister<'_> {
    let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
    install_governance_canister(&mut canister, init_payload).await;
    canister
}

/// Compiles the ledger canister, builds it's initial payload and installs it
pub async fn install_ledger_canister<'runtime, 'a>(
    canister: &mut Canister<'runtime>,
    args: LedgerInitArgs,
) {
    install_rust_canister_with_memory_allocation(
        canister,
        "rosetta-api/icrc1/ledger",
        "ic-icrc1-ledger",
        &[],
        Some(CandidOne(args).into_bytes().unwrap()),
        SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES,
    )
    .await
}

/// Creates and installs the ledger canister.
pub async fn set_up_ledger_canister(runtime: &'_ Runtime, args: LedgerInitArgs) -> Canister<'_> {
    let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
    install_ledger_canister(&mut canister, args).await;
    canister
}

/// Builds the root canister wasm binary, serializes canister_init args for it, and installs it.
pub async fn install_root_canister(canister: &mut Canister<'_>, args: SnsRootCanister) {
    install_rust_canister_with_memory_allocation(
        canister,
        "sns/root",
        "sns-root-canister",
        &[],
        Some(CandidOne(args).into_bytes().unwrap()),
        SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES,
    )
    .await
}

/// Creates and installs the root canister.
pub async fn set_up_root_canister(runtime: &'_ Runtime, args: SnsRootCanister) -> Canister<'_> {
    let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
    install_root_canister(&mut canister, args).await;
    canister
}

/// Builds the swap canister wasm binary, serializes canister_init args for it, and installs it.
pub async fn install_swap_canister(canister: &mut Canister<'_>, args: SwapInit) {
    install_rust_canister_with_memory_allocation(
        canister,
        "sns/swap",
        "sns-swap-canister",
        &[],
        Some(CandidOne(args).into_bytes().unwrap()),
        SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES,
    )
    .await
}

/// Creates and installs the swap canister.
pub async fn set_up_swap_canister(runtime: &'_ Runtime, args: SwapInit) -> Canister<'_> {
    let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
    install_swap_canister(&mut canister, args).await;
    canister
}
