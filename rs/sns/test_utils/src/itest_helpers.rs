use canister_test::{local_test_with_config_e, Canister, Project, Runtime};
use dfn_candid::{candid_one, CandidOne};
use futures::future::join_all;
use ic_config::subnet_config::SubnetConfig;
use ic_config::Config;
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance::pb::v1::manage_neuron_response::Command as CommandResponse;
use ic_sns_governance::pb::v1::{
    get_neuron_response, get_proposal_response,
    manage_neuron::{
        claim_or_refresh::{By, MemoAndController},
        configure::Operation,
        ClaimOrRefresh, Command, Configure, IncreaseDissolveDelay, RegisterVote,
    },
    GetNeuron, GetNeuronResponse, GetProposal, GetProposalResponse, Governance, GovernanceError,
    ManageNeuron, ManageNeuronResponse, NervousSystemParameters, Neuron, NeuronId, Proposal,
    ProposalData, ProposalId, Vote,
};
use ledger_canister as ledger;
use ledger_canister::{
    AccountIdentifier, LedgerCanisterInitPayload, Memo, SendArgs, Subaccount, Tokens,
    DEFAULT_TRANSFER_FEE,
};
use on_wire::IntoWire;
use prost::Message;
use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::{
    memory_allocation_of, ALL_SNS_CANISTER_IDS, NUM_SNS_CANISTERS, TEST_GOVERNANCE_CANISTER_ID,
    TEST_LEDGER_CANISTER_ID, TEST_ROOT_CANISTER_ID,
};
use dfn_protobuf::protobuf;
use ic_canister_client::Sender;
use ic_crypto_sha::Sha256;
use ic_types::PrincipalId;

/// All the SNS canisters
#[derive(Clone)]
pub struct SnsCanisters<'a> {
    pub root: Canister<'a>,
    pub governance: Canister<'a>,
    pub ledger: Canister<'a>,
}

/// Payloads for all the canisters
#[derive(Clone)]
pub struct SnsInitPayloads {
    pub governance: Governance,
    pub ledger: LedgerCanisterInitPayload,
}

/// Builder to help create the initial payloads for the SNS canisters.
pub struct SnsInitPayloadsBuilder {
    pub governance: GovernanceCanisterInitPayloadBuilder,
    pub ledger: LedgerCanisterInitPayload,
}

#[allow(clippy::new_without_default)]
impl SnsInitPayloadsBuilder {
    pub fn new() -> SnsInitPayloadsBuilder {
        SnsInitPayloadsBuilder {
            governance: GovernanceCanisterInitPayloadBuilder::new(),
            ledger: LedgerCanisterInitPayload {
                minting_account: TEST_GOVERNANCE_CANISTER_ID.get().into(),
                initial_values: HashMap::new(),
                archive_options: Some(ledger::ArchiveOptions {
                    trigger_threshold: 2000,
                    num_blocks_to_archive: 1000,
                    // 1 GB, which gives us 3 GB space when upgrading
                    node_max_memory_size_bytes: Some(1024 * 1024 * 1024),
                    // 128kb
                    max_message_size_bytes: Some(128 * 1024),
                    controller_id: TEST_ROOT_CANISTER_ID,
                    cycles_for_archive_creation: Some(0),
                }),
                max_message_size_bytes: Some(128 * 1024),
                // 24 hour transaction window
                transaction_window: Some(Duration::from_secs(24 * 60 * 60)),
                send_whitelist: ALL_SNS_CANISTER_IDS.iter().map(|&x| *x).collect(),
                transfer_fee: Some(DEFAULT_TRANSFER_FEE),
                token_symbol: None,
                token_name: None,
            },
        }
    }

    pub fn with_ledger_init_state(&mut self, state: LedgerCanisterInitPayload) -> &mut Self {
        self.ledger = state;
        self
    }

    pub fn with_ledger_account(&mut self, account: AccountIdentifier, icpts: Tokens) -> &mut Self {
        self.ledger.initial_values.insert(account, icpts);
        self
    }

    pub fn with_ledger_accounts(
        &mut self,
        accounts: Vec<AccountIdentifier>,
        icpts: Tokens,
    ) -> &mut Self {
        for account in accounts {
            self.ledger.initial_values.insert(account, icpts);
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

    pub fn with_governance_proto(&mut self, proto: Governance) -> &mut Self {
        self.governance.with_governance_proto(proto);
        self
    }

    pub fn with_nervous_system_parameters(&mut self, params: NervousSystemParameters) -> &mut Self {
        self.governance.proto.parameters = Some(params);
        self
    }

    pub fn build(&mut self) -> SnsInitPayloads {
        assert!(self
            .ledger
            .initial_values
            .get(&TEST_GOVERNANCE_CANISTER_ID.get().into())
            .is_none());

        for n in self.governance.proto.neurons.values() {
            let sub = n
                .subaccount()
                .unwrap_or_else(|e| panic!("Couldn't calculate subaccount from neuron: {}", e));
            let aid = ledger::AccountIdentifier::new(TEST_GOVERNANCE_CANISTER_ID.get(), Some(sub));
            let previous_value = self
                .ledger
                .initial_values
                .insert(aid, Tokens::from_e8s(n.cached_neuron_stake_e8s));

            assert_eq!(previous_value, None);
        }

        self.governance
            .with_ledger_canister_id(TEST_LEDGER_CANISTER_ID);

        SnsInitPayloads {
            governance: self.governance.build(),
            ledger: self.ledger.clone(),
        }
    }
}

impl SnsCanisters<'_> {
    /// Creates and installs all of the SNS canisters
    pub async fn set_up(runtime: &'_ Runtime, init_payloads: SnsInitPayloads) -> SnsCanisters<'_> {
        let since_start_secs = {
            let s = SystemTime::now();
            move || (SystemTime::now().duration_since(s).unwrap()).as_secs_f32()
        };

        // First, create as many canisters as we need. Ordering does not matter, we just
        // need enough canisters, and them we'll grab them in the order we want.
        let maybe_canisters: Result<Vec<Canister<'_>>, String> = join_all(
            (0..NUM_SNS_CANISTERS).map(|_| runtime.create_canister_max_cycles_with_retries()),
        )
        .await
        .into_iter()
        .collect();

        maybe_canisters.unwrap_or_else(|e| panic!("At least one canister creation failed: {}", e));
        eprintln!("SNS canisters created after {:.1} s", since_start_secs());

        let root = Canister::new(runtime, TEST_ROOT_CANISTER_ID);
        let mut governance = Canister::new(runtime, TEST_GOVERNANCE_CANISTER_ID);
        let mut ledger = Canister::new(runtime, TEST_LEDGER_CANISTER_ID);

        // Install canisters
        futures::join!(
            install_governance_canister(&mut governance, init_payloads.governance.clone()),
            install_ledger_canister(&mut ledger, init_payloads.ledger),
        );

        eprintln!("SNS canisters installed after {:.1} s", since_start_secs());

        // We can set all the controllers at once. Several -- or all -- may go
        // into the same block, this makes setup faster.
        futures::try_join!(
            governance.set_controller_with_retries(TEST_ROOT_CANISTER_ID.get()),
            ledger.set_controller_with_retries(TEST_ROOT_CANISTER_ID.get()),
        )
        .unwrap();

        eprintln!("SNS canisters set up after {:.1} s", since_start_secs());

        SnsCanisters {
            root,
            governance,
            ledger,
        }
    }

    pub fn all_canisters(&self) -> [&Canister<'_>; NUM_SNS_CANISTERS] {
        [&self.root, &self.governance, &self.ledger]
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
    pub async fn get_neuron(&self, neuron_id: NeuronId) -> Neuron {
        let get_neuron_response: GetNeuronResponse = self
            .governance
            .query_(
                "get_neuron",
                candid_one,
                GetNeuron {
                    neuron_id: Some(neuron_id),
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
    /// Assumes `user` has an account on the Ledger containing at least 100 tokens.
    pub async fn stake_and_claim_neuron(
        &self,
        user: &Sender,
        dissolve_delay: Option<u32>,
    ) -> NeuronId {
        // Stake a neuron by transferring to a subaccount of the neurons
        // canister and claiming the neuron on the governance canister..
        let nonce = 12345u64;
        let to_subaccount = Subaccount({
            let mut state = Sha256::new();
            state.write(&[0x0c]);
            state.write(b"neuron-stake");
            state.write(user.get_principal_id().as_slice());
            state.write(&nonce.to_be_bytes());
            state.finish()
        });

        // Stake the neuron.
        let stake = Tokens::from_tokens(100).unwrap();
        let _block_height: u64 = self
            .ledger
            .update_from_sender(
                "send_pb",
                protobuf,
                SendArgs {
                    memo: Memo(nonce),
                    amount: stake,
                    fee: DEFAULT_TRANSFER_FEE,
                    from_subaccount: None,
                    to: AccountIdentifier::new(
                        PrincipalId::from(TEST_GOVERNANCE_CANISTER_ID),
                        Some(to_subaccount),
                    ),
                    created_at_time: None,
                },
                user,
            )
            .await
            .expect("Couldn't send funds.");

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
                            memo: nonce,
                            controller: None,
                        })),
                    })),
                },
                user,
            )
            .await
            .expect("Error calling the manage_neuron api.");

        let neuron_id = match claim_response.command.unwrap() {
            CommandResponse::ClaimOrRefresh(response) => {
                println!(
                    "User {} successfully claimed neuron",
                    user.get_principal_id()
                );

                response.refreshed_neuron_id.unwrap()
            }
            CommandResponse::Error(error) => panic!(
                "Unexpected error when claiming neuron for user {}: {}",
                user.get_principal_id(),
                error
            ),
            _ => panic!(
                "Unexpected command response when claiming neuron for user {}.",
                user.get_principal_id()
            ),
        };

        // Increase dissolve delay
        if let Some(dissolve_delay) = dissolve_delay {
            let increase_response: ManageNeuronResponse = self
                .governance
                .update_from_sender(
                    "manage_neuron",
                    candid_one,
                    ManageNeuron {
                        subaccount: to_subaccount.to_vec(),
                        command: Some(Command::Configure(Configure {
                            operation: Some(Operation::IncreaseDissolveDelay(
                                IncreaseDissolveDelay {
                                    additional_dissolve_delay_seconds: dissolve_delay,
                                },
                            )),
                        })),
                    },
                    user,
                )
                .await
                .expect("Error calling the manage_neuron api.");

            match increase_response.command.unwrap() {
                CommandResponse::Configure(_) => (),
                CommandResponse::Error(error) => panic!(
                    "Unexpected error when increasing dissolve delay for user {}: {}",
                    user.get_principal_id(),
                    error
                ),
                _ => panic!(
                    "Unexpected command response when increasing dissolve delay for user {}.",
                    user.get_principal_id()
                ),
            };
        }

        neuron_id
    }

    pub async fn vote(
        &self,
        user: &Sender,
        subaccount: &Subaccount,
        proposal_id: ProposalId,
        accept: bool,
    ) -> ManageNeuronResponse {
        let vote = if accept { Vote::Yes } else { Vote::No } as i32;

        let response: ManageNeuronResponse = self
            .governance
            .update_from_sender(
                "manage_neuron",
                candid_one,
                ManageNeuron {
                    subaccount: subaccount.to_vec(),
                    command: Some(Command::RegisterVote(RegisterVote {
                        proposal: Some(proposal_id),
                        vote,
                    })),
                },
                user,
            )
            .await
            .expect("Vote request failed");

        response
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
    let wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
        relative_path_from_rs,
        binary_name.as_ref(),
        cargo_features,
    );

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

/// Install a rust canister bytecode in a subnet.
pub async fn install_rust_canister(
    canister: &mut Canister<'_>,
    relative_path_from_rs: impl AsRef<Path>,
    binary_name: impl AsRef<str>,
    cargo_features: &[&str],
    canister_init_payload: Option<Vec<u8>>,
) {
    install_rust_canister_with_memory_allocation(
        canister,
        relative_path_from_rs,
        binary_name,
        cargo_features,
        canister_init_payload,
        memory_allocation_of(canister.canister_id()),
    )
    .await
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
    let mut serialized = Vec::new();
    init_payload
        .encode(&mut serialized)
        .expect("Couldn't serialize init payload.");
    install_rust_canister(
        canister,
        "sns/governance",
        "sns-governance-canister",
        &[],
        Some(serialized),
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
    args: LedgerCanisterInitPayload,
) {
    install_rust_canister(
        canister,
        "rosetta-api/ledger_canister",
        "ledger-canister",
        &["notify-method"],
        Some(CandidOne(args).into_bytes().unwrap()),
    )
    .await
}

/// Creates and installs the ledger canister.
pub async fn set_up_ledger_canister<'runtime, 'a>(
    runtime: &'runtime Runtime,
    args: LedgerCanisterInitPayload,
) -> Canister<'runtime> {
    let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
    install_ledger_canister(&mut canister, args).await;
    canister
}
