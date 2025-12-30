//! Utilities to help build the initial state of the IC, to deploy it, to
//! initialize it, and to upgrade it, for tests.

use crate::{
    common::NnsInitPayloads,
    governance::{submit_external_update_proposal, wait_for_final_state},
    state_test_helpers::state_machine_builder_for_nns_tests,
};
use candid::{CandidType, Encode, Principal};
use canister_test::{
    Canister, Project, Runtime, Wasm, local_test_with_config_e,
    local_test_with_config_with_mutations_on_system_subnet,
};
use cycles_minting_canister::CyclesCanisterInitPayload;
use dfn_candid::{CandidOne, candid_one};
use futures::{FutureExt, executor::block_on, future::join_all};
use ic_canister_client_sender::Sender;
use ic_config::Config;
use ic_management_canister_types_private::CanisterInstallMode;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nns_common::{
    init::LifelineCanisterInitPayload,
    types::{NeuronId, ProposalId},
};
use ic_nns_constants::*;
use ic_nns_governance_api::{Governance, NnsFunction, ProposalStatus, test_api::TimeWarp};
use ic_nns_gtc::pb::v1::Gtc;
use ic_nns_handler_root::init::RootCanisterInitPayload;
use ic_registry_transport::pb::v1::RegistryMutation;
use ic_sns_wasm::{init::SnsWasmCanisterInitPayload, pb::v1::AddWasmRequest};
use ic_test_utilities::universal_canister::{
    UNIVERSAL_CANISTER_WASM, call_args, wasm as universal_canister_argument_builder,
};
use ic_types::Cycles;
use ic_xrc_types::{Asset, AssetClass, ExchangeRateMetadata};
use icp_ledger as ledger;
use ledger::LedgerCanisterInitPayload;
use lifeline::LIFELINE_CANISTER_WASM;
use on_wire::{IntoWire, bytes};
use prost::Message;
use registry_canister::init::RegistryCanisterInitPayload;
use serde::Deserialize;
use std::{future::Future, path::Path, thread, time::SystemTime};
use xrc_mock::{ExchangeRate, XrcMockInitPayload};

/// All the NNS canisters that are use in tests, but not all canisters
/// on NNS mainnet (there are 4 ledger archives, for example and a ledger index that aren't tested
/// using this struct)
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
    pub migration: Canister<'a>,

    // Optional canisters.
    pub subnet_rental: Option<Canister<'a>>,
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

        maybe_canisters.unwrap_or_else(|e| panic!("At least one canister creation failed: {e}"));
        eprintln!("NNS canisters created after {:.1} s", since_start_secs());

        // TODO (after deploying SNS-WASMs to mainnet) update ALL_NNS_CANISTER_IDS to the resulting
        // SNS-WASMs canister and delete following line. We avoid that so the canister ID is not added
        // to a whitelist before it is deployed.  But we need one more canister for our tests.
        runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Failed creating last canister");

        // Create canisters.

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
        let mut subnet_rental = Canister::new(runtime, SUBNET_RENTAL_CANISTER_ID);
        let mut migration = Canister::new(runtime, MIGRATION_CANISTER_ID);

        // Install code into canisters (pass init argument/payload).
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
            install_sns_wasm_canister(&mut sns_wasms, init_payloads.sns_wasms.clone()),
            async {
                if let Some(()) = init_payloads.subnet_rental {
                    install_subnet_rental_canister(&mut subnet_rental).await;
                }
            },
            install_migration_canister(&mut migration),
        );

        eprintln!("NNS canisters installed after {:.1} s", since_start_secs());

        // Set controller(s) of canisters.

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
            subnet_rental.set_controller_with_retries(ROOT_CANISTER_ID.get()),
            migration.set_controller_with_retries(ROOT_CANISTER_ID.get()),
        )
        .unwrap();

        eprintln!("NNS canisters set up after {:.1} s", since_start_secs());

        // Finally, bundle canisters.
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
            subnet_rental: init_payloads.subnet_rental.map(|()| subnet_rental),
            migration,
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
        let mut migration = runtime
            .create_canister_at_id_max_cycles_with_retries(MIGRATION_CANISTER_ID.get())
            .await
            .unwrap();

        let mut subnet_rental = init_payloads.subnet_rental.as_ref().map(|_not_used| {
            block_on(async {
                runtime
                    .create_canister_at_id_max_cycles_with_retries(SUBNET_RENTAL_CANISTER_ID.get())
                    .await
                    .unwrap()
            })
        });

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
            install_sns_wasm_canister(&mut sns_wasms, init_payloads.sns_wasms.clone()),
            async {
                if let Some(subnet_rental) = subnet_rental.as_mut() {
                    install_subnet_rental_canister(subnet_rental).await;
                }
            },
            install_migration_canister(&mut migration),
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
            async {
                if let Some(subnet_rental) = subnet_rental.as_mut() {
                    subnet_rental
                        .set_controller_with_retries(ROOT_CANISTER_ID.get())
                        .await
                } else {
                    Ok(())
                }
            },
            migration.set_controller_with_retries(ROOT_CANISTER_ID.get()),
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
            subnet_rental,
            migration,
        }
    }

    pub fn all_canisters(&self) -> [&Canister<'_>; 10] {
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
                .status,
            ProposalStatus::Executed as i32
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

/// Runtime must be built from a node belonging to a subnet that can host
/// EXCHANGE_RATE_CANISTER_ID.
///
/// Warning: This assumes that canisters with ID smaller than that of the
/// Exchange Rate canister have all already been created.
pub async fn create_and_install_mock_exchange_rate_canister(
    runtime: &'_ Runtime,
    price_of_icp_in_xdr_cents: u64,
) {
    // Step 1: Create the canister.

    // Create canisters in a loop until we hit EXCHANGE_RATE_CANISTER_ID. Yes,
    // this is a hack. You might think that
    // runtime.create_canister_with_specified_id(...) would get the desired
    // effect (more straightforwardly), but trying to create an Exchange Rate
    // canister that way results in
    //
    //     The `specified_id` uf6dk-hyaaa-aaaaq-qaaaq-cai is invalid because it belongs to the canister allocation ranges of the test environment.
    //
    // This is because of the way that the routing table is set up in system
    // tests. If we wanted to get rid of this hack, we would have to change how
    // the routing table is set up in system tests:
    // https://github.com/dfinity/ic/pull/6053#discussion_r2329340517
    //
    // The "Warning" in the triple slash comments of this function is because of
    // this hack.
    let mut found = false;
    for _ in 0..100 {
        let canister = runtime.create_canister(Some(0)).await.unwrap();
        if canister.canister_id() == EXCHANGE_RATE_CANISTER_ID {
            found = true;
            break;
        }
    }
    assert!(found);

    // Step 2: Install code into the canister.

    // Step 2.1: Construct init payload/argument.
    let exchange_rate = ExchangeRate {
        // The additional 7 zeros because `decimal` is set to 9 a little bit
        // later, in metadata.
        rate: 10_u64.pow(7) * price_of_icp_in_xdr_cents,

        base_asset: Some(Asset {
            symbol: "ICP".to_string(),
            class: AssetClass::Cryptocurrency,
        }),
        quote_asset: Some(Asset {
            symbol: "CXDR".to_string(),
            class: AssetClass::FiatCurrency,
        }),

        // I believe these are realistic compared to what would be seen in
        // production. FWIW, these same values are used in other tests.
        metadata: Some(ExchangeRateMetadata {
            decimals: 9,
            base_asset_num_queried_sources: 7,
            base_asset_num_received_rates: 5,
            quote_asset_num_queried_sources: 10,
            quote_asset_num_received_rates: 4,
            standard_deviation: 0,
            forex_timestamp: None,
        }),
    };
    let init_payload = XrcMockInitPayload {
        response: xrc_mock::Response::ExchangeRate(exchange_rate),
    };

    // Step 2.2: Actually install the WASM, and pass init_payload to it.
    let mut mock_exchange_rate_canister = Canister::new(runtime, EXCHANGE_RATE_CANISTER_ID);
    install_mock_exchange_rate_canister(&mut mock_exchange_rate_canister, init_payload).await;
}

/// Compiles the governance canister, builds it's initial payload and installs
/// it
pub async fn install_governance_canister(canister: &mut Canister<'_>, init_payload: Governance) {
    let serialized = Encode!(&init_payload).expect("Couldn't serialize init payload.");
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
    install_rust_canister(canister, "registry-canister", &["test"], Some(encoded)).await;
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
pub async fn install_ledger_canister(canister: &mut Canister<'_>, args: LedgerCanisterInitPayload) {
    install_rust_canister(
        canister,
        "ledger-canister",
        &[],
        Some(CandidOne(args).into_bytes().unwrap()),
    )
    .await
}

/// Creates and installs the ledger canister.
pub async fn set_up_ledger_canister(
    runtime: &Runtime,
    args: LedgerCanisterInitPayload,
) -> Canister<'_> {
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
    Wasm::from_bytes(UNIVERSAL_CANISTER_WASM.to_vec())
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

pub async fn install_node_rewards_canister(canister: &mut Canister<'_>) {
    install_rust_canister(canister, "node-rewards-canister", &[], None).await;
}

pub async fn install_mock_exchange_rate_canister(
    canister: &mut Canister<'_>,
    init_payload: XrcMockInitPayload,
) {
    let init_payload = Encode!(&init_payload).unwrap();
    install_rust_canister(canister, "xrc_mock", &[], Some(init_payload)).await;
}

pub async fn install_subnet_rental_canister(canister: &mut Canister<'_>) {
    install_rust_canister(canister, "subnet-rental-canister", &[], None).await;
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

/// Compiles the migration canister and installs it.
pub async fn install_migration_canister(canister: &mut Canister<'_>) {
    #[derive(CandidType, Deserialize, Default)]
    struct MigrationCanisterInitArgs {
        allowlist: Option<Vec<Principal>>,
    }
    install_rust_canister(
        canister,
        "migration-canister",
        &[],
        Some(Encode!(&MigrationCanisterInitArgs::default()).unwrap()),
    )
    .await;
}

/// Creates and installs the migration canister.
pub async fn set_up_migration_canister(runtime: &'_ Runtime) -> Canister<'_> {
    let mut canister = runtime.create_canister_with_max_cycles().await.unwrap();
    install_migration_canister(&mut canister).await;
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
        other => panic!("Unexpected response from the universal canister: {other:?}"),
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
