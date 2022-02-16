//! Utilities to help build the initial state of the IC, to deploy it, to
//! initialize it, and to upgrade it, for tests.

use crate::{
    governance::{
        get_pending_proposals, submit_external_update_proposal,
        submit_external_update_proposal_binary, wait_for_final_state,
    },
    ids::TEST_NEURON_1_ID,
    registry::invariant_compliant_mutation,
};

use std::{
    convert::TryInto,
    future::Future,
    path::Path,
    time::{Duration, SystemTime},
};

use futures::future::join_all;
use prost::Message;

use candid::Encode;
use canister_test::{
    local_test_with_config_e, local_test_with_config_with_mutations, Canister, Project, Runtime,
    Wasm,
};
use cycles_minting_canister::CyclesCanisterInitPayload;
use dfn_candid::{candid_one, CandidOne};
use ic_base_types::{CanisterId, CanisterInstallMode};
use ic_canister_client::Sender;
use ic_config::{subnet_config::SubnetConfig, Config};
use ic_nns_common::{
    init::{LifelineCanisterInitPayload, LifelineCanisterInitPayloadBuilder},
    types::NeuronId,
};
use ic_nns_constants::ids::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nns_constants::*;
use ic_nns_governance::{
    init::GovernanceCanisterInitPayloadBuilder,
    pb::v1::{Governance, NnsFunction, ProposalStatus},
};
use ic_nns_gtc::{init::GenesisTokenCanisterInitPayloadBuilder, pb::v1::Gtc};
use ic_nns_gtc_accounts::{ECT_ACCOUNTS, SEED_ROUND_ACCOUNTS};
use ic_nns_handler_root::{
    common::{
        CanisterIdRecord, CanisterStatusResult, CanisterStatusType::Running,
        ChangeNnsCanisterProposalPayload,
    },
    init::{RootCanisterInitPayload, RootCanisterInitPayloadBuilder},
};
use ic_registry_transport::pb::v1::{RegistryAtomicMutateRequest, RegistryMutation};
use ic_test_utilities::universal_canister::{
    call_args, wasm as universal_canister_argument_builder, UNIVERSAL_CANISTER_WASM,
};
use ic_utils::byte_slice_fmt::truncate_and_format;
use ledger::{LedgerCanisterInitPayload, Subaccount, Tokens, DEFAULT_TRANSFER_FEE};
use ledger_canister as ledger;
use ledger_canister::AccountIdentifier;
use lifeline::LIFELINE_CANISTER_WASM;
use on_wire::{bytes, IntoWire};
use registry_canister::init::{RegistryCanisterInitPayload, RegistryCanisterInitPayloadBuilder};

/// All the NNS canisters that exist at genesis.
#[derive(Clone)]
pub struct NnsCanisters<'a> {
    // Canisters here are listed in creation order.
    pub registry: Canister<'a>,
    pub governance: Canister<'a>,
    pub ledger: Canister<'a>,
    pub root: Canister<'a>,
    pub cycles_minting: Canister<'a>,
    pub lifeline: Canister<'a>,
    pub genesis_token: Canister<'a>,
    pub identity: Canister<'a>,
    pub nns_ui: Canister<'a>,
}

/// Payloads for all the canisters that exist at genesis.
#[derive(Clone)]
pub struct NnsInitPayloads {
    pub registry: RegistryCanisterInitPayload,
    pub governance: Governance,
    pub ledger: LedgerCanisterInitPayload,
    pub root: RootCanisterInitPayload,
    pub cycles_minting: CyclesCanisterInitPayload,
    pub lifeline: LifelineCanisterInitPayload,
    pub genesis_token: Gtc,
}

/// Builder to help create the intial payloads for the NNS canisters.
pub struct NnsInitPayloadsBuilder {
    pub registry: RegistryCanisterInitPayloadBuilder,
    pub governance: GovernanceCanisterInitPayloadBuilder,
    pub ledger: LedgerCanisterInitPayload,
    pub root: RootCanisterInitPayloadBuilder,
    pub cycles_minting: CyclesCanisterInitPayload,
    pub lifeline: LifelineCanisterInitPayloadBuilder,
    pub genesis_token: GenesisTokenCanisterInitPayloadBuilder,
}

#[allow(clippy::new_without_default)]
impl NnsInitPayloadsBuilder {
    pub fn new() -> NnsInitPayloadsBuilder {
        NnsInitPayloadsBuilder {
            registry: RegistryCanisterInitPayloadBuilder::new(),
            governance: GovernanceCanisterInitPayloadBuilder::new(),
            ledger: LedgerCanisterInitPayload::builder()
                .minting_account(GOVERNANCE_CANISTER_ID.get().into())
                .archive_options(ledger::ArchiveOptions {
                    trigger_threshold: 2000,
                    num_blocks_to_archive: 1000,
                    // 1 GB, which gives us 3 GB space when upgrading
                    node_max_memory_size_bytes: Some(1024 * 1024 * 1024),
                    // 128kb
                    max_message_size_bytes: Some(128 * 1024),
                    controller_id: ROOT_CANISTER_ID,
                })
                .max_message_size_bytes(128 * 1024)
                // 24 hour transaction window
                .transaction_window(Duration::from_secs(24 * 60 * 60))
                .send_whitelist(ALL_NNS_CANISTER_IDS.iter().map(|&x| *x).collect())
                .transfer_fee(DEFAULT_TRANSFER_FEE)
                .build()
                .unwrap(),
            root: RootCanisterInitPayloadBuilder::new(),
            cycles_minting: CyclesCanisterInitPayload {
                ledger_canister_id: LEDGER_CANISTER_ID,
                governance_canister_id: GOVERNANCE_CANISTER_ID,
                minting_account_id: Some(GOVERNANCE_CANISTER_ID.get().into()),
            },
            lifeline: LifelineCanisterInitPayloadBuilder::new(),
            genesis_token: GenesisTokenCanisterInitPayloadBuilder::new(),
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

    pub fn with_neurons_from_csv_file(&mut self, csv_file: &Path) -> &mut Self {
        self.governance.add_all_neurons_from_csv_file(csv_file);
        self
    }

    pub fn with_test_neurons(&mut self) -> &mut Self {
        self.governance.with_test_neurons();
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

    pub fn with_initial_mutations(
        &mut self,
        mutate_reqs: Vec<RegistryAtomicMutateRequest>,
    ) -> &mut Self {
        for req in mutate_reqs.into_iter() {
            self.registry.push_init_mutate_request(req);
        }
        self
    }

    pub fn with_initial_invariant_compliant_mutations(&mut self) -> &mut Self {
        self.registry
            .push_init_mutate_request(RegistryAtomicMutateRequest {
                mutations: invariant_compliant_mutation(),
                preconditions: vec![],
            });
        self
    }

    /// Create GTC neurons and add them to the GTC and Governance canisters'
    /// initial payloads
    pub fn with_gtc_neurons(&mut self) -> &mut Self {
        self.genesis_token.add_sr_neurons(SEED_ROUND_ACCOUNTS);
        self.genesis_token.add_ect_neurons(ECT_ACCOUNTS);

        let gtc_neurons = self
            .genesis_token
            .get_gtc_neurons()
            .into_iter()
            .map(|mut neuron| {
                neuron.followees = self.governance.proto.default_followees.clone();
                neuron
            })
            .collect();

        self.governance.add_gtc_neurons(gtc_neurons);
        self
    }

    pub fn build(&mut self) -> NnsInitPayloads {
        assert!(self
            .ledger
            .initial_values
            .get(&GOVERNANCE_CANISTER_ID.get().into())
            .is_none());

        for n in self.governance.proto.neurons.values() {
            let sub = Subaccount(n.account.as_slice().try_into().unwrap_or_else(|e| {
                panic!(
                    "Subaccounts should be exactly 32 bytes in length. Got {} for neuron {}. {}",
                    truncate_and_format(n.account.as_slice(), 80),
                    n.id.as_ref()
                        .unwrap_or_else(|| panic!("Couldn't get id of neuron: {:?}", n))
                        .id,
                    e
                )
            }));
            let aid = ledger::AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(sub));
            let previous_value = self
                .ledger
                .initial_values
                .insert(aid, Tokens::from_e8s(n.cached_neuron_stake_e8s));

            assert_eq!(previous_value, None);
        }

        NnsInitPayloads {
            registry: self.registry.build(),
            governance: self.governance.build(),
            ledger: self.ledger.clone(),
            root: self.root.build(),
            cycles_minting: self.cycles_minting.clone(),
            lifeline: self.lifeline.build(),
            genesis_token: self.genesis_token.build(),
        }
    }
}

impl NnsCanisters<'_> {
    /// Creates and installs all of the NNS canisters that are scheduled to
    /// exist at genesis, and sets the controller on each canister.
    pub async fn set_up(runtime: &'_ Runtime, init_payloads: NnsInitPayloads) -> NnsCanisters<'_> {
        let since_start_secs = {
            let s = SystemTime::now();
            move || (SystemTime::now().duration_since(s).unwrap()).as_secs_f32()
        };

        // First, create as many canisters as we need. Ordering does not matter, we just
        // need enough canisters, and them we'll grab them in the order we want.
        let maybe_canisters: Result<Vec<Canister<'_>>, String> = join_all(
            (0..NUM_NNS_CANISTERS).map(|_| runtime.create_canister_max_cycles_with_retries()),
        )
        .await
        .into_iter()
        .collect();

        maybe_canisters.unwrap_or_else(|e| panic!("At least one canister creation failed: {}", e));
        eprintln!("NNS canisters created after {:.1} s", since_start_secs());

        let mut registry = Canister::new(runtime, REGISTRY_CANISTER_ID);
        let mut governance = Canister::new(runtime, GOVERNANCE_CANISTER_ID);
        let mut ledger = Canister::new(runtime, LEDGER_CANISTER_ID);
        let mut root = Canister::new(runtime, ROOT_CANISTER_ID);
        let mut cycles_minting = Canister::new(runtime, CYCLES_MINTING_CANISTER_ID);
        let mut lifeline = Canister::new(runtime, LIFELINE_CANISTER_ID);
        let mut genesis_token = Canister::new(runtime, GENESIS_TOKEN_CANISTER_ID);
        let identity = Canister::new(runtime, IDENTITY_CANISTER_ID);
        let nns_ui = Canister::new(runtime, NNS_UI_CANISTER_ID);

        // Install canisters
        futures::join!(
            install_registry_canister(&mut registry, init_payloads.registry.clone()),
            install_governance_canister(&mut governance, init_payloads.governance.clone()),
            install_ledger_canister(&mut ledger, init_payloads.ledger),
            install_root_canister(&mut root, init_payloads.root.clone()),
            install_cycles_minting_canister(
                &mut cycles_minting,
                init_payloads.cycles_minting.clone()
            ),
            install_lifeline_canister(&mut lifeline, init_payloads.lifeline.clone()),
            install_genesis_token_canister(&mut genesis_token, init_payloads.genesis_token.clone()),
        );

        eprintln!("NNS canisters installed after {:.1} s", since_start_secs());

        // We can set all the controllers at once. Several -- or all -- may go
        // into the same block, this makes setup faster.
        futures::try_join!(
            registry.set_controller_with_retries(ROOT_CANISTER_ID.get()),
            governance.set_controller_with_retries(ROOT_CANISTER_ID.get()),
            ledger.set_controller_with_retries(ROOT_CANISTER_ID.get()),
            // The root is special! it's controlled by the lifeline
            root.set_controller_with_retries(LIFELINE_CANISTER_ID.get()),
            cycles_minting.set_controller_with_retries(ROOT_CANISTER_ID.get()),
            lifeline.set_controller_with_retries(ROOT_CANISTER_ID.get()),
            genesis_token.set_controller_with_retries(ROOT_CANISTER_ID.get()),
            identity.set_controller_with_retries(ROOT_CANISTER_ID.get()),
            nns_ui.set_controller_with_retries(ROOT_CANISTER_ID.get()),
        )
        .unwrap();

        eprintln!("NNS canisters set up after {:.1} s", since_start_secs());

        NnsCanisters {
            registry,
            governance,
            ledger,
            root,
            cycles_minting,
            lifeline,
            genesis_token,
            identity,
            nns_ui,
        }
    }

    pub fn all_canisters(&self) -> [&Canister<'_>; NUM_NNS_CANISTERS] {
        [
            &self.registry,
            &self.governance,
            &self.ledger,
            &self.root,
            &self.cycles_minting,
            &self.lifeline,
            &self.genesis_token,
            &self.identity,
            &self.nns_ui,
        ]
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

/// Compiles the governance canister, builds it's initial payload and installs
/// it
pub async fn install_governance_canister(canister: &mut Canister<'_>, init_payload: Governance) {
    let mut serialized = Vec::new();
    init_payload
        .encode(&mut serialized)
        .expect("Couldn't serialize init payload.");
    install_rust_canister(
        canister,
        "nns/governance",
        "governance-canister",
        &["test"],
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

/// Compiles the registry canister, builds it's initial payload and installs it
pub async fn install_registry_canister(
    canister: &mut Canister<'_>,
    init_payload: RegistryCanisterInitPayload,
) {
    let encoded = Encode!(&init_payload).unwrap();
    install_rust_canister(
        canister,
        "registry/canister",
        "registry-canister",
        &[],
        Some(encoded),
    )
    .await;
}

/// Creates and installs the registry canister.
pub async fn set_up_registry_canister(
    runtime: &'_ Runtime,
    init_payload: RegistryCanisterInitPayload,
) -> Canister<'_> {
    let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
    install_registry_canister(&mut canister, init_payload).await;
    canister
}

/// Compiles the GTC canister, builds it's initial payload and installs it
pub async fn install_genesis_token_canister(canister: &mut Canister<'_>, init_payload: Gtc) {
    let mut serialized = Vec::new();
    init_payload
        .encode(&mut serialized)
        .expect("Couldn't serialize init payload.");

    install_rust_canister(
        canister,
        "nns/gtc",
        "genesis-token-canister",
        &[],
        Some(serialized),
    )
    .await
}

/// Creates and installs the GTC canister.
pub async fn set_up_genesis_token_canister(
    runtime: &'_ Runtime,
    init_payload: Gtc,
) -> Canister<'_> {
    let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
    install_genesis_token_canister(&mut canister, init_payload).await;
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

/// Compiles the root canister, builds it's initial payload and installs it
pub async fn install_root_canister(
    canister: &mut Canister<'_>,
    init_payload: RootCanisterInitPayload,
) {
    let encoded = Encode!(&init_payload).unwrap();
    install_rust_canister(
        canister,
        "nns/handlers/root",
        "root-canister",
        &[],
        Some(encoded),
    )
    .await;
}

/// Creates and installs the root canister.
pub async fn set_up_root_canister(
    runtime: &'_ Runtime,
    init_payload: RootCanisterInitPayload,
) -> Canister<'_> {
    let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
    install_root_canister(&mut canister, init_payload).await;
    canister
}

/// Compiles the cycles minting canister, builds it's initial payload and
/// installs it
pub async fn install_cycles_minting_canister(
    canister: &mut Canister<'_>,
    init_payload: CyclesCanisterInitPayload,
) {
    install_rust_canister(
        canister,
        "nns/cmc",
        "cycles-minting-canister",
        &[],
        Some(CandidOne(init_payload).into_bytes().unwrap()),
    )
    .await;
}

/// Creates and installs the cycles minting canister.
pub async fn set_up_cycles_minting_canister(
    runtime: &'_ Runtime,
    init_payload: CyclesCanisterInitPayload,
) -> Canister<'_> {
    let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
    install_cycles_minting_canister(&mut canister, init_payload).await;
    canister
}

/// Compiles the lifeline canister, builds it's initial payload and installs it
pub async fn install_lifeline_canister(
    canister: &mut Canister<'_>,
    _init_payload: LifelineCanisterInitPayload,
) {
    // Use the env var if we have one, otherwise use the embedded binary.
    Wasm::from_location_specified_by_env_var("lifeline", &[])
        .unwrap_or_else(|| Wasm::from_bytes(LIFELINE_CANISTER_WASM))
        .install_with_retries_onto_canister(
            canister,
            None,
            Some(memory_allocation_of(canister.canister_id())),
        )
        .await
        .unwrap();
    println!(
        "Installed {} with the lifeline handler",
        canister.canister_id(),
    );
}

/// Creates and installs the lifeline canister.
pub async fn set_up_lifeline_canister(
    runtime: &'_ Runtime,
    init_payload: LifelineCanisterInitPayload,
) -> Canister<'_> {
    let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
    install_lifeline_canister(&mut canister, init_payload).await;
    canister
}

/// Compiles the universal canister, builds it's initial payload and installs it
pub async fn set_up_universal_canister(runtime: &'_ Runtime) -> Canister<'_> {
    let mut canister = runtime
        .create_canister_max_cycles_with_retries()
        .await
        .unwrap();
    Wasm::from_bytes(UNIVERSAL_CANISTER_WASM)
        .install_with_retries_onto_canister(&mut canister, None, None)
        .await
        .unwrap();
    println!(
        "Installed {} with the universal canister",
        canister.canister_id(),
    );
    canister
}

/// Runs a local test on the nns subnetwork, so that the canister will be
/// assigned the same ids as in prod.
pub fn local_test_on_nns_subnet<Fut, Out, F>(run: F) -> Out
where
    Fut: Future<Output = Result<Out, String>>,
    F: FnOnce(Runtime) -> Fut + 'static,
{
    let (config, _tmpdir) = Config::temp_config();
    local_test_with_config_e(config, SubnetConfig::default_system_subnet(), run)
}

/// Runs a local test on the nns subnetwork, so that the canister will be
/// assigned the same ids as in prod.
///
/// Accepts Registry mutations to apply to the faked Registry of the underlying
/// IC. This allows one to apply the same mutations to a Registry canister
/// deployed on the supplied `Runtime` and the faked Registry that is used by
/// the `Runtime` itself.
pub fn local_test_on_nns_subnet_with_mutations<Fut, Out, F>(
    mutations: Vec<RegistryMutation>,
    run: F,
) -> Out
where
    Fut: Future<Output = Result<Out, String>>,
    F: FnOnce(Runtime) -> Fut + 'static,
{
    let (config, _tmpdir) = Config::temp_config();
    local_test_with_config_with_mutations(config, mutations, run)
        .expect("local_test_with_config_with_mutations failed")
}

/// Encapsulates different test scenarios, with diferent upgrade modes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum UpgradeTestingScenario {
    Never,
    Always,
}

/// Depending on the testing scenario, upgrade the canister to itself, or do
/// nothing.
///
/// The canister must be controllable by the anonymous user.
pub async fn maybe_upgrade_to_self(canister: &mut Canister<'_>, scenario: UpgradeTestingScenario) {
    if UpgradeTestingScenario::Always == scenario {
        canister.upgrade_to_self_binary(Vec::new()).await.unwrap()
    }
}

/// Appends a few inert bytes to the provided Wasm. Results in a functionally
/// identical binary.
pub fn append_inert(wasm: Option<&Wasm>) -> Wasm {
    let mut wasm = wasm.unwrap().clone().bytes();
    // This sequence of bytes encodes an empty wasm custom section
    // named "a". It is harmless to suffix any wasm with it, even multiple
    // times.
    wasm.append(&mut vec![0, 2, 1, 97]);
    Wasm::from_bytes(wasm)
}

/// Upgrades the root canister via a proposal.
pub async fn upgrade_root_canister_by_proposal(
    governance: &Canister<'_>,
    lifeline: &Canister<'_>,
    wasm: Wasm,
) {
    let wasm = wasm.bytes();
    let new_module_hash = &ic_crypto_sha::Sha256::hash(&wasm);

    let proposal_id = submit_external_update_proposal_binary(
        governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::NnsRootUpgrade,
        Encode!(&wasm, &Vec::<u8>::new(), &false).expect(
            "Could not candid-serialize the argument tuple for the NnsRootUpgrade proposal.",
        ),
        "Upgrade Root Canister".to_string(),
        "<proposal created by upgrade_root_canister_by_proposal>".to_string(),
    )
    .await;

    assert_eq!(
        wait_for_final_state(governance, proposal_id).await.status(),
        ProposalStatus::Executed
    );

    let pending_proposals = get_pending_proposals(governance).await;
    assert_eq!(pending_proposals.len(), 0);

    loop {
        let status: CanisterStatusResult = lifeline
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(ROOT_CANISTER_ID),
            )
            .await
            .unwrap();
        if status.module_hash.unwrap().as_slice() == new_module_hash && status.status == Running {
            break;
        }
    }
}

/// Perform a change on a canister by upgrading it or
/// reinstalling entirely, depending on the `how` argument.
/// Argument `wasm` is ensured to have a different
/// hash relative to the current binary.
/// In argument `arg` additional arguments can be provided
/// that serve as input to the upgrade hook or as init arguments
/// to the fresh installation.
///
/// This is an internal method.
async fn change_nns_canister_by_proposal(
    how: CanisterInstallMode,
    canister_id: CanisterId,
    governance: &Canister<'_>,
    root: &Canister<'_>,
    stop_before_installing: bool,
    wasm: Wasm,
    arg: Option<Vec<u8>>,
) {
    let wasm = wasm.bytes();
    let new_module_hash = &ic_crypto_sha::Sha256::hash(&wasm);

    let status: CanisterStatusResult = root
        .update_(
            "canister_status",
            candid_one,
            CanisterIdRecord::from(canister_id),
        )
        .await
        .unwrap();
    let old_module_hash = status.module_hash.unwrap();
    assert_ne!(old_module_hash.as_slice(), new_module_hash, "change_nns_canister_by_proposal: both module hashes prev, cur are the same {:?}, but they should be different for upgrade", old_module_hash);

    let proposal_payload =
        ChangeNnsCanisterProposalPayload::new(stop_before_installing, how, canister_id)
            .with_wasm(wasm);
    let proposal_payload = if let Some(arg) = arg {
        proposal_payload.with_arg(arg)
    } else {
        proposal_payload
    };

    // Submitting a proposal also implicitly records a vote from the proposer,
    // which with TEST_NEURON_1 is enough to trigger execution.
    submit_external_update_proposal(
        governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::NnsCanisterUpgrade,
        proposal_payload,
        "Upgrade NNS Canister".to_string(),
        "<proposal created by change_nns_canister_by_proposal>".to_string(),
    )
    .await;

    // Wait 'till the hash matches and the canister is running again.
    loop {
        let status: CanisterStatusResult = root
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(canister_id),
            )
            .await
            .unwrap();
        if status.module_hash.unwrap().as_slice() == new_module_hash && status.status == Running {
            break;
        }
    }
}

/// Upgrade the given root-controlled canister to the specified Wasm module.
/// This should only be called in NNS integration tests, where the NNS
/// canisters have their expected IDs.
///
/// This goes through MANY rounds of consensus, so expect it to be slow!
///
/// WARNING: this calls `execute_eligible_proposals` on the governance canister,
/// so it may have side effects!
pub async fn upgrade_nns_canister_by_proposal(
    canister: &Canister<'_>,
    governance: &Canister<'_>,
    root: &Canister<'_>,
    stop_before_installing: bool,
    wasm: Wasm,
) {
    change_nns_canister_by_proposal(
        CanisterInstallMode::Upgrade,
        canister.canister_id(),
        governance,
        root,
        stop_before_installing,
        wasm,
        None,
    )
    .await
}

/// Upgrades an nns canister via proposal, with an argument.
pub async fn upgrade_nns_canister_with_arg_by_proposal(
    canister: &Canister<'_>,
    governance: &Canister<'_>,
    root: &Canister<'_>,
    wasm: Wasm,
    arg: Vec<u8>,
) {
    change_nns_canister_by_proposal(
        CanisterInstallMode::Upgrade,
        canister.canister_id(),
        governance,
        root,
        false,
        wasm,
        Some(arg),
    )
    .await
}

/// Propose and execute the fresh reinstallation of the canister. Wasm
/// and initialisation arguments can be specified.
/// This should only be called in NNS integration tests, where the NNS
/// canisters have their expected IDs.
///
/// WARNING: this calls `execute_eligible_proposals` on the governance canister,
/// so it may have side effects!
pub async fn reinstall_nns_canister_by_proposal(
    canister: &Canister<'_>,
    governance: &Canister<'_>,
    root: &Canister<'_>,
    wasm: Wasm,
    arg: Vec<u8>,
) {
    change_nns_canister_by_proposal(
        CanisterInstallMode::Reinstall,
        canister.canister_id(),
        governance,
        root,
        true,
        append_inert(Some(&wasm)),
        Some(arg),
    )
    .await
}

/// Depending on the testing scenario, upgrade the given root-controlled
/// canister to itself, or do nothing. This should only be called in NNS
/// integration tests, where the NNS canisters have their expected IDs.
///
/// This goes through MANY rounds of consensus, so expect it to be slow!
///
/// WARNING: this calls `execute_eligible_proposals` on the Proposals canister,
/// so it may have side effects!
pub async fn maybe_upgrade_root_controlled_canister_to_self(
    // nns_canisters is NOT passed by reference because of the canister to upgrade,
    // for which we have a mutable borrow.
    nns_canisters: NnsCanisters<'_>,
    canister: &mut Canister<'_>,
    stop_before_installing: bool,
    scenario: UpgradeTestingScenario,
) {
    if UpgradeTestingScenario::Always != scenario {
        return;
    }

    // Copy the wasm of the canister to upgrade. We'll need it to upgrade back to
    // it. To observe that the upgrade happens, we need to make the binary different
    // post-upgrade.
    let wasm = append_inert(Some(canister.wasm().unwrap()));
    let wasm_clone = wasm.clone().bytes();
    upgrade_nns_canister_by_proposal(
        canister,
        &nns_canisters.governance,
        &nns_canisters.root,
        stop_before_installing,
        wasm,
    )
    .await;
    canister.set_wasm(wasm_clone);
}

const UNIVERSAL_CANISTER_YEAH_RESPONSE: &[u8] = b"It worked";
const UNIVERSAL_CANISTER_NOPE_RESPONSE: &[u8] = b"It failed";

/// Makes the `sender` call the given method of the
/// `receiver` handler. It is assumed that `sender` is a universal
/// canister.
///
/// Return true if the handler replied, and false if it rejected.
pub async fn forward_call_via_universal_canister(
    sender: &Canister<'_>,
    receiver: &Canister<'_>,
    method: &str,
    payload: Vec<u8>,
) -> bool {
    let universal_canister_payload = universal_canister_argument_builder()
        .call_simple(
            receiver.canister_id(),
            method,
            call_args()
                // "other_side" means "the call argument". There's a reason...
                .other_side(payload)
                .on_reply(
                    universal_canister_argument_builder()
                        .reply_data(UNIVERSAL_CANISTER_YEAH_RESPONSE),
                )
                .on_reject(
                    universal_canister_argument_builder()
                        .reply_data(UNIVERSAL_CANISTER_NOPE_RESPONSE),
                ),
        )
        .build();
    match sender
        .update_("update", bytes, universal_canister_payload)
        .await
        .unwrap()
        .as_slice()
    {
        UNIVERSAL_CANISTER_YEAH_RESPONSE => true,
        UNIVERSAL_CANISTER_NOPE_RESPONSE => false,
        other => panic!(
            "Unexpected response from the universal canister: {:?}",
            other
        ),
    }
}

/// Makes the `sender` call the given method of the
/// `receiver` handler. It is assumed that `sender` is a universal
/// canister.
///
/// Return the response bytes if the receiver replied, and reject message if the
/// call failed.
pub async fn try_call_via_universal_canister(
    sender: &Canister<'_>,
    receiver: &Canister<'_>,
    method: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let universal_canister_payload = universal_canister_argument_builder()
        .call_simple(
            receiver.canister_id(),
            method,
            call_args()
                .other_side(payload)
                .on_reply(
                    universal_canister_argument_builder()
                        .message_payload()
                        .reply_data_append()
                        .reply(),
                )
                .on_reject(
                    universal_canister_argument_builder()
                        .reject_message()
                        .reject(),
                ),
        )
        .build();
    sender
        .update_("update", bytes, universal_canister_payload)
        .await
}
