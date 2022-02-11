use canister_test::{local_test_with_config_e, Canister, Project, Runtime};
use dfn_candid::CandidOne;
use futures::future::join_all;
use ic_config::subnet_config::SubnetConfig;
use ic_config::Config;
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance::pb::v1::Governance;
use ledger_canister as ledger;
use ledger_canister::{AccountIdentifier, LedgerCanisterInitPayload, Tokens, DEFAULT_TRANSFER_FEE};
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
                }),
                max_message_size_bytes: Some(128 * 1024),
                // 24 hour transaction window
                transaction_window: Some(Duration::from_secs(24 * 60 * 60)),
                send_whitelist: ALL_SNS_CANISTER_IDS.iter().map(|&x| *x).collect(),
                transfer_fee: Some(DEFAULT_TRANSFER_FEE),
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
}

/// Installs a rust canister with the provided memory allocation.
pub async fn install_rust_canister_with_memory_allocation(
    mut canister: &mut Canister<'_>,
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
        &mut canister,
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
