//! Utilities to help build the initial state of the IC, to deploy it, to
//! initialize it, and to upgrade it, for tests.

use crate::{
    common::NnsInitPayloads,
    governance::{submit_external_update_proposal, wait_for_final_state},
    state_test_helpers::state_machine_builder_for_nns_tests,
};
use candid::Encode;
use canister_test::{
    local_test_with_config_e, local_test_with_config_with_mutations_on_system_subnet, Canister,
    Project, Runtime, Wasm,
};
use cycles_minting_canister::CyclesCanisterInitPayload;
use dfn_candid::{candid_one, CandidOne};
use futures::{future::join_all, FutureExt};
use ic_base_types::CanisterId;
use ic_canister_client_sender::Sender;
use ic_config::Config;
use ic_management_canister_types::CanisterInstallMode;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{CanisterStatusResult, CanisterStatusType},
};
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_common::{
    init::LifelineCanisterInitPayload,
    types::{NeuronId, ProposalId},
};
use ic_nns_constants::*;
use ic_nns_governance_api::{
    pb::v1::{Governance, NnsFunction, ProposalStatus},
    test_api::TimeWarp,
};
use ic_nns_gtc::pb::v1::Gtc;
use ic_nns_handler_root::init::RootCanisterInitPayload;
use ic_registry_transport::pb::v1::RegistryMutation;
use ic_sns_wasm::{init::SnsWasmCanisterInitPayload, pb::v1::AddWasmRequest};
use ic_test_utilities::universal_canister::{
    call_args, wasm as universal_canister_argument_builder, UNIVERSAL_CANISTER_WASM,
};
use ic_types::Cycles;
use icp_ledger as ledger;
use ledger::LedgerCanisterInitPayload;
use lifeline::LIFELINE_CANISTER_WASM;
use on_wire::{bytes, IntoWire};
use prost::Message;
use registry_canister::init::RegistryCanisterInitPayload;
use std::{future::Future, path::Path, thread, time::SystemTime};

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
    pub sns_wasms: Canister<'a>,
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

        // TODO (after deploying SNS-WASMs to mainnet) update ALL_NNS_CANISTER_IDS to the resulting
        // SNS-WASMs canister and delete following line. We avoid that so the canister ID is not added
        // to a whitelist before it is deployed.  But we need one more canister for our tests.
        runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Failed creating last canister");

        let mut registry = Canister::new(runtime, REGISTRY_CANISTER_ID);
        let mut governance = Canister::new(runtime, GOVERNANCE_CANISTER_ID);
        let mut ledger = Canister::new(runtime, LEDGER_CANISTER_ID);
        let mut root = Canister::new(runtime, ROOT_CANISTER_ID);
        let mut cycles_minting = Canister::new(runtime, CYCLES_MINTING_CANISTER_ID);
        let mut lifeline = Canister::new(runtime, LIFELINE_CANISTER_ID);
        let mut genesis_token = Canister::new(runtime, GENESIS_TOKEN_CANISTER_ID);
        let identity = Canister::new(runtime, IDENTITY_CANISTER_ID);
        let nns_ui = Canister::new(runtime, NNS_UI_CANISTER_ID);
        let mut sns_wasms = Canister::new(runtime, SNS_WASM_CANISTER_ID);

        // Install all the canisters
        // Registry and Governance need to first or the process hangs,
        // Ledger is just added as to avoid Governance spamming the logs.
        futures::join!(
            install_registry_canister(&mut registry, init_payloads.registry.clone()),
            install_governance_canister(&mut governance, init_payloads.governance.clone()),
            install_ledger_canister(&mut ledger, init_payloads.ledger.clone()),
        );
        futures::join!(
            install_root_canister(&mut root, init_payloads.root.clone()),
            install_cycles_minting_canister(
                &mut cycles_minting,
                init_payloads.cycles_minting.clone()
            ),
            install_lifeline_canister(&mut lifeline, init_payloads.lifeline.clone()),
            install_genesis_token_canister(&mut genesis_token, init_payloads.genesis_token.clone()),
            install_sns_wasm_canister(&mut sns_wasms, init_payloads.sns_wasms.clone())
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
            sns_wasms.set_controller_with_retries(ROOT_CANISTER_ID.get()),
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
            sns_wasms,
        }
    }

    /// Creates and installs all of the NNS canisters at the right ids that are scheduled to
    /// exist at genesis, and sets the controller on each canister.
    pub async fn set_up_at_ids(
        runtime: &'_ Runtime,
        init_payloads: NnsInitPayloads,
    ) -> NnsCanisters<'_> {
        let since_start_secs = {
            let s = SystemTime::now();
            move || (SystemTime::now().duration_since(s).unwrap()).as_secs_f32()
        };

        // Let's create the canisters at the desired IDs
        let mut registry = runtime
            .create_canister_at_id_max_cycles_with_retries(REGISTRY_CANISTER_ID.get())
            .await
            .unwrap();
        let mut governance = runtime
            .create_canister_at_id_max_cycles_with_retries(GOVERNANCE_CANISTER_ID.get())
            .await
            .unwrap();
        let mut ledger = runtime
            .create_canister_at_id_max_cycles_with_retries(LEDGER_CANISTER_ID.get())
            .await
            .unwrap();
        let mut root = runtime
            .create_canister_at_id_max_cycles_with_retries(ROOT_CANISTER_ID.get())
            .await
            .unwrap();
        let mut cycles_minting = runtime
            .create_canister_at_id_max_cycles_with_retries(CYCLES_MINTING_CANISTER_ID.get())
            .await
            .unwrap();
        let mut lifeline = runtime
            .create_canister_at_id_max_cycles_with_retries(LIFELINE_CANISTER_ID.get())
            .await
            .unwrap();
        let mut genesis_token = runtime
            .create_canister_at_id_max_cycles_with_retries(GENESIS_TOKEN_CANISTER_ID.get())
            .await
            .unwrap();
        let identity = runtime
            .create_canister_at_id_max_cycles_with_retries(IDENTITY_CANISTER_ID.get())
            .await
            .unwrap();
        let nns_ui = runtime
            .create_canister_at_id_max_cycles_with_retries(NNS_UI_CANISTER_ID.get())
            .await
            .unwrap();
        let mut sns_wasms = runtime
            .create_canister_at_id_max_cycles_with_retries(SNS_WASM_CANISTER_ID.get())
            .await
            .unwrap();

        // Install all the canisters
        // Registry and Governance need to first or the process hangs,
        // Ledger is just added as to avoid Governance spamming the logs.
        futures::join!(
            install_registry_canister(&mut registry, init_payloads.registry.clone()),
            install_governance_canister(&mut governance, init_payloads.governance.clone()),
            install_ledger_canister(&mut ledger, init_payloads.ledger.clone()),
        );
        // nns_ui and identity do not need to be installed for this test,
        // because their init payload is not available in our tests.
        futures::join!(
            install_root_canister(&mut root, init_payloads.root.clone()),
            install_cycles_minting_canister(
                &mut cycles_minting,
                init_payloads.cycles_minting.clone()
            ),
            install_lifeline_canister(&mut lifeline, init_payloads.lifeline.clone()),
            install_genesis_token_canister(&mut genesis_token, init_payloads.genesis_token.clone()),
            install_sns_wasm_canister(&mut sns_wasms, init_payloads.sns_wasms.clone())
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
            sns_wasms.set_controller_with_retries(ROOT_CANISTER_ID.get()),
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
            sns_wasms,
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
            &self.sns_wasms,
        ]
    }

    pub async fn set_time_warp(&self, delta_s: i64) -> Result<(), String> {
        self.governance
            .update_("set_time_warp", candid_one, TimeWarp { delta_s })
            .await
    }

    /// Add an SNS WASM via NNS proposal
    pub async fn add_wasm(&self, payload: AddWasmRequest) {
        let proposal_id: ProposalId = submit_external_update_proposal(
            &self.governance,
            Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
            NeuronId(TEST_NEURON_1_ID),
            NnsFunction::AddSnsWasm,
            payload,
            "add_wasm".to_string(),
            "".to_string(),
        )
        .await;

        // Wait for the proposal to be accepted and executed.
        assert_eq!(
            wait_for_final_state(&self.governance, proposal_id)
                .await
                .status(),
            ProposalStatus::Executed
        );
    }
}

/// Installs a rust canister with the provided memory allocation.
async fn install_rust_canister_with_memory_allocation(
    canister: &mut Canister<'_>,
    binary_name: impl AsRef<str>,
    cargo_features: &[&str],
    canister_init_payload: Option<Vec<u8>>,
    memory_allocation: u64, // in bytes
) {
    // Some ugly code to allow copying AsRef<Path> and features (an array slice) into new thread
    // neither of these implement Send or have a way to clone the whole structure's data
    let binary_name_ = binary_name.as_ref().to_string();
    let features = cargo_features
        .iter()
        .map(|s| s.to_string())
        .collect::<Box<[String]>>();

    let wasm: Wasm = match canister.runtime() {
        Runtime::Remote(_) | Runtime::Local(_) => {
            tokio::runtime::Handle::current()
                .spawn_blocking(move || {
                    println!(
                        "Compiling Wasm for {} in task on thread: {:?}",
                        binary_name_,
                        thread::current().id()
                    );
                    // Second half of moving data had to be done in-thread to avoid lifetime/ownership issues
                    let features = features.iter().map(|s| s.as_str()).collect::<Box<[&str]>>();
                    Project::cargo_bin_maybe_from_env(&binary_name_, &features)
                })
                .await
                .unwrap()
        }
        Runtime::StateMachine(_) => {
            let features = features.iter().map(|s| s.as_str()).collect::<Box<[&str]>>();
            Project::cargo_bin_maybe_from_env(&binary_name_, &features)
        }
    };

    println!("Done compiling the wasm for {}", binary_name.as_ref());

    if canister.is_runtime_local() {
        wasm.install_onto_canister(
            canister,
            CanisterInstallMode::Reinstall,
            canister_init_payload,
            Some(memory_allocation),
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Could not install {} via local runtime due to {}",
                binary_name.as_ref(),
                e
            )
        });
    } else {
        wasm.install_with_retries_onto_canister(
            canister,
            canister_init_payload,
            Some(memory_allocation),
        )
        .await
        .unwrap_or_else(|e| {
            panic!(
                "Could not install {} via remote runtime due to {}",
                binary_name.as_ref(),
                e
            )
        });
    };
    println!(
        "Installed {} with {}",
        canister.canister_id(),
        binary_name.as_ref()
    );
}

/// Installs a rust canister with the provided memory allocation
/// from the specified path to the WASM code.
async fn install_rust_canister_with_memory_allocation_from_path<P: AsRef<Path>>(
    canister: &mut Canister<'_>,
    path_to_wasm: P,
    canister_init_payload: Option<Vec<u8>>,
    memory_allocation: u64, // in bytes
) {
    let wasm: Wasm = Wasm::from_file(path_to_wasm.as_ref());
    wasm.install_with_retries_onto_canister(
        canister,
        canister_init_payload,
        Some(memory_allocation),
    )
    .await
    .unwrap_or_else(|e| panic!("Could not install {:?} due to {}", path_to_wasm.as_ref(), e));
    println!(
        "Installed {} with {:?}",
        canister.canister_id(),
        path_to_wasm.as_ref(),
    );
}

/// Install a rust canister bytecode in a subnet.
pub async fn install_rust_canister(
    canister: &mut Canister<'_>,
    binary_name: impl AsRef<str>,
    cargo_features: &[&str],
    canister_init_payload: Option<Vec<u8>>,
) {
    install_rust_canister_with_memory_allocation(
        canister,
        binary_name,
        cargo_features,
        canister_init_payload,
        memory_allocation_of(canister.canister_id()),
    )
    .await
}

/// Install a rust canister bytecode in a subnet
/// from a specified path to the WASM code.
pub async fn install_rust_canister_from_path<P: AsRef<Path>>(
    canister: &mut Canister<'_>,
    path_to_wasm: P,
    canister_init_payload: Option<Vec<u8>>,
) {
    install_rust_canister_with_memory_allocation_from_path(
        canister,
        path_to_wasm,
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
    install_rust_canister(canister, "governance-canister", &["test"], Some(serialized)).await;
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
    install_rust_canister(canister, "registry-canister", &[], Some(encoded)).await;
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

    install_rust_canister(canister, "genesis-token-canister", &[], Some(serialized)).await
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
        "ledger-canister",
        &["notify-method"],
        Some(CandidOne(args).into_bytes().unwrap()),
    )
    .await
}

/// Creates and installs the ledger canister.
pub async fn set_up_ledger_canister(
    runtime: &Runtime,
    args: LedgerCanisterInitPayload,
) -> Canister {
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
    install_rust_canister(canister, "root-canister", &[], Some(encoded)).await;
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
    init_payload: Option<CyclesCanisterInitPayload>,
) {
    install_rust_canister(
        canister,
        "cycles-minting-canister",
        &[],
        Some(CandidOne(init_payload).into_bytes().unwrap()),
    )
    .await;
}

/// Creates and installs the cycles minting canister.
pub async fn set_up_cycles_minting_canister(
    runtime: &'_ Runtime,
    init_payload: Option<CyclesCanisterInitPayload>,
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
    Wasm::from_location_specified_by_env_var("lifeline_canister", &[])
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
    install_universal_canister(&mut canister).await;
    canister
}

/// Installs universal canister with specified cycle count
pub async fn set_up_universal_canister_with_cycles(
    runtime: &'_ Runtime,
    cycles: u128,
) -> Canister<'_> {
    let mut canister = runtime.create_canister(Some(cycles)).await.unwrap();
    install_universal_canister(&mut canister).await;
    canister
}

async fn install_universal_canister(canister: &mut Canister<'_>) {
    Wasm::from_bytes(UNIVERSAL_CANISTER_WASM)
        .install_with_retries_onto_canister(canister, None, None)
        .await
        .unwrap();
    println!(
        "Installed {} with the universal canister",
        canister.canister_id(),
    );
}

/// Compiles the sns_wasm canister, builds it's initial payload and installs it
pub async fn install_sns_wasm_canister(
    canister: &mut Canister<'_>,
    init_payload: SnsWasmCanisterInitPayload,
) {
    let encoded = Encode!(&init_payload).unwrap();
    install_rust_canister(canister, "sns-wasm-canister", &[], Some(encoded)).await;
}

/// Creates and installs the sns_wasm canister.
///
/// Use None for `cycles` to get max_cycles of normal NNS canisters when not testing cycle-dependent
/// code (such as ensuring cycles are received and passed to created SNS canisters)
pub async fn set_up_sns_wasm_canister(
    runtime: &'_ Runtime,
    init_payload: SnsWasmCanisterInitPayload,
    cycles: Option<u128>, // None -> max_cycles
) -> Canister<'_> {
    let mut canister = runtime.create_canister(cycles).await.unwrap();
    install_sns_wasm_canister(&mut canister, init_payload).await;
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
    local_test_with_config_e(config, run)
}

/// Runs a test in a StateMachine in a way that is (mostly) compatible with local_test_on_nns_subnet
pub fn state_machine_test_on_nns_subnet<Fut, Out, F>(run: F) -> Out
where
    Fut: Future<Output = Result<Out, String>>,
    F: FnOnce(Runtime) -> Fut + 'static,
{
    let state_machine = state_machine_builder_for_nns_tests().build();
    // This is for easy conversion from existing tests, but nothing is actually async.
    run(Runtime::StateMachine(state_machine))
        .now_or_never()
        .expect("Async call did not return from now_or_never")
        .expect("state_machine_test_on_nns_subnet failed.")
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
    local_test_with_config_with_mutations_on_system_subnet(config, mutations, run)
        .expect("local_test_with_config_with_mutations_on_system_subnet failed")
}

/// Encapsulates different test scenarios, with different upgrade modes.
#[derive(Copy, Clone, Eq, PartialEq)]
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

fn is_gzipped_blob(blob: &[u8]) -> bool {
    (blob.len() > 4)
        // Has magic bytes.
        && (blob[0..2] == [0x1F, 0x8B])
}

/// Bumps the gzip timestamp of the provided gzipped Wasm.
/// Results in a functionally identical binary.
pub fn bump_gzip_timestamp(wasm: &Wasm) -> Wasm {
    // wasm is gzipped and the subslice [4..8]
    // is the little endian representation of a timestamp
    // so we just increment that timestamp
    let mut new_wasm = wasm.clone().bytes();
    assert!(is_gzipped_blob(&new_wasm));
    let t = u32::from_le_bytes(new_wasm[4..8].try_into().unwrap());
    new_wasm[4..8].copy_from_slice(&(t + 1).to_le_bytes());
    Wasm::from_bytes(new_wasm)
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
    let new_module_hash = &ic_crypto_sha2::Sha256::hash(&wasm);

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

    let change_canister_request =
        ChangeCanisterRequest::new(stop_before_installing, how, canister_id)
            .with_memory_allocation(memory_allocation_of(canister_id))
            .with_wasm(wasm);
    let change_canister_request = if let Some(arg) = arg {
        change_canister_request.with_arg(arg)
    } else {
        change_canister_request
    };

    // Submitting a proposal also implicitly records a vote from the proposer,
    // which with TEST_NEURON_1 is enough to trigger execution.
    submit_external_update_proposal(
        governance,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::NnsCanisterUpgrade,
        change_canister_request,
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
        if status.module_hash.unwrap().as_slice() == new_module_hash
            && status.status == CanisterStatusType::Running
        {
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
        bump_gzip_timestamp(&wasm),
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
/// WARNING: this calls `execute_eligible_proposals` on the governance canister,
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
    let wasm = bump_gzip_timestamp(canister.wasm().unwrap());
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

pub async fn try_call_with_cycles_via_universal_canister(
    sender: &Canister<'_>,
    receiver: &Canister<'_>,
    method: &str,
    payload: Vec<u8>,
    cycles: u128,
) -> Result<Vec<u8>, String> {
    let universal_canister_payload = universal_canister_argument_builder()
        .call_with_cycles(
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
            Cycles::from(cycles),
        )
        .build();
    sender
        .update_("update", bytes, universal_canister_payload)
        .await
}
