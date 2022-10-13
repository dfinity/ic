use crate::registry::invariant_compliant_mutation;
use canister_test::{Project, Wasm};
use core::{
    option::Option::{None, Some},
    time::Duration,
};
use cycles_minting_canister::CyclesCanisterInitPayload;
use ic_base_types::{PrincipalId, SubnetId};
use ic_nns_common::init::{LifelineCanisterInitPayload, LifelineCanisterInitPayloadBuilder};
use ic_nns_constants::{
    ALL_NNS_CANISTER_IDS, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID, ROOT_CANISTER_ID,
};
use ic_nns_governance::{init::GovernanceCanisterInitPayloadBuilder, pb::v1::Governance};
use ic_nns_gtc::{init::GenesisTokenCanisterInitPayloadBuilder, pb::v1::Gtc};
use ic_nns_gtc_accounts::{ECT_ACCOUNTS, SEED_ROUND_ACCOUNTS};
use ic_nns_handler_root::init::{RootCanisterInitPayload, RootCanisterInitPayloadBuilder};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_sns_wasm::init::{SnsWasmCanisterInitPayload, SnsWasmCanisterInitPayloadBuilder};
use ic_utils::byte_slice_fmt::truncate_and_format;
use ledger_canister::{
    self as ledger,
    account_identifier::{AccountIdentifier, Subaccount},
    LedgerCanisterInitPayload, Tokens, DEFAULT_TRANSFER_FEE,
};
use lifeline::LIFELINE_CANISTER_WASM;
use registry_canister::init::{RegistryCanisterInitPayload, RegistryCanisterInitPayloadBuilder};
use std::convert::TryInto;
use std::path::Path;

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
    pub sns_wasms: SnsWasmCanisterInitPayload,
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
    pub sns_wasms: SnsWasmCanisterInitPayloadBuilder,
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
                    controller_id: ROOT_CANISTER_ID.into(),
                    cycles_for_archive_creation: Some(0),
                    max_transactions_per_response: None,
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
                last_purged_notification: Some(1),
            },
            lifeline: LifelineCanisterInitPayloadBuilder::new(),
            genesis_token: GenesisTokenCanisterInitPayloadBuilder::new(),
            sns_wasms: SnsWasmCanisterInitPayloadBuilder::new(),
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
        accounts: Vec<(AccountIdentifier, Tokens)>,
    ) -> &mut Self {
        for (account, icpts) in accounts {
            self.with_ledger_account(account, icpts);
        }
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

    pub fn with_sns_dedicated_subnets(&mut self, sns_subnets: Vec<SubnetId>) -> &mut Self {
        self.sns_wasms.with_sns_subnet_ids(sns_subnets);
        self
    }

    pub fn with_sns_wasm_access_controls(&mut self, access_controls_enabled: bool) -> &mut Self {
        self.sns_wasms
            .with_access_controls_enabled(access_controls_enabled);
        self
    }

    pub fn with_sns_wasm_allowed_principals(
        &mut self,
        allowed_principals: Vec<PrincipalId>,
    ) -> &mut Self {
        self.sns_wasms.with_allowed_principals(allowed_principals);
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
            sns_wasms: self.sns_wasms.build(),
        }
    }
}

/// Build Wasm for NNS Governance canister
pub fn build_governance_wasm() -> Wasm {
    let features = ["test"];
    Project::cargo_bin_maybe_from_env("governance-canister", &features)
}
/// Build Wasm for NNS Root canister
pub fn build_root_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("root-canister", &features)
}
/// Build Wasm for NNS Registry canister
pub fn build_registry_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("registry-canister", &features)
}
/// Build Wasm for NNS Ledger canister
pub fn build_ledger_wasm() -> Wasm {
    let features = ["notify-method"];
    Project::cargo_bin_maybe_from_env("ledger-canister", &features)
}
/// Build Wasm for NNS CMC
pub fn build_cmc_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("cycles-minting-canister", &features)
}
/// Build Wasm for NNS Lifeline canister
pub fn build_lifeline_wasm() -> Wasm {
    Wasm::from_location_specified_by_env_var("lifeline", &[])
        .unwrap_or_else(|| Wasm::from_bytes(LIFELINE_CANISTER_WASM))
}
/// Build Wasm for NNS Genesis Token canister
pub fn build_genesis_token_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("genesis-token-canister", &features)
}
/// Build Wasm for NNS SnsWasm canister
pub fn build_sns_wasms_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("sns-wasm-canister", &features)
}
