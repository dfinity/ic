use crate::{
    gtc_helpers::GenesisTokenCanisterInitPayloadBuilder, registry::invariant_compliant_mutation,
    subnet_rental::SubnetRentalCanisterInitPayloadBuilder,
};
use canister_test::{Project, Wasm};
use core::option::Option::{None, Some};
use cycles_minting_canister::CyclesCanisterInitPayload;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_nns_common::init::{LifelineCanisterInitPayload, LifelineCanisterInitPayloadBuilder};
use ic_nns_constants::{
    ALL_NNS_CANISTER_IDS, CYCLES_LEDGER_CANISTER_ID, GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID,
};
use ic_nns_governance_api::{Governance, NetworkEconomics, Neuron};
use ic_nns_governance_init::GovernanceCanisterInitPayloadBuilder;
use ic_nns_gtc::pb::v1::Gtc;
use ic_nns_gtc_accounts::{ECT_ACCOUNTS, SEED_ROUND_ACCOUNTS};
use ic_nns_handler_root::init::{RootCanisterInitPayload, RootCanisterInitPayloadBuilder};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use ic_sns_wasm::init::{SnsWasmCanisterInitPayload, SnsWasmCanisterInitPayloadBuilder};
use ic_utils::byte_slice_fmt::truncate_and_format;
use icp_ledger::{
    self as ledger, LedgerCanisterInitPayload, LedgerCanisterInitPayloadBuilder, Tokens,
    account_identifier::{AccountIdentifier, Subaccount},
};
use lifeline::LIFELINE_CANISTER_WASM;
use registry_canister::init::{RegistryCanisterInitPayload, RegistryCanisterInitPayloadBuilder};
use std::{convert::TryInto, path::Path};

/// Payloads for all the canisters that exist at genesis.
#[derive(Clone, Debug)]
pub struct NnsInitPayloads {
    pub registry: RegistryCanisterInitPayload,
    pub governance: Governance,
    pub ledger: LedgerCanisterInitPayload,
    pub root: RootCanisterInitPayload,
    pub cycles_minting: Option<CyclesCanisterInitPayload>,
    pub lifeline: LifelineCanisterInitPayload,
    pub genesis_token: Gtc,
    pub sns_wasms: SnsWasmCanisterInitPayload,
    pub index: ic_icp_index::InitArg,

    // Optional canister(s). Unlike others above, these are of type
    // Option<${CANISTER}InitPayload>. When an optional canister is enabled,
    // these fields contain Some (otherwise, they contain None).
    pub subnet_rental: Option<()>,
}

/// Builder to help create the initial payloads for the NNS canisters.
pub struct NnsInitPayloadsBuilder {
    pub registry: RegistryCanisterInitPayloadBuilder,
    pub governance: GovernanceCanisterInitPayloadBuilder,
    pub ledger: LedgerCanisterInitPayload,
    pub root: RootCanisterInitPayloadBuilder,
    pub cycles_minting: Option<CyclesCanisterInitPayload>,
    pub lifeline: LifelineCanisterInitPayloadBuilder,
    pub genesis_token: GenesisTokenCanisterInitPayloadBuilder,
    pub sns_wasms: SnsWasmCanisterInitPayloadBuilder,
    pub index: ic_icp_index::InitArg,
    pub subnet_rental: SubnetRentalCanisterInitPayloadBuilder,
}

#[allow(clippy::new_without_default)]
impl NnsInitPayloadsBuilder {
    pub fn new() -> NnsInitPayloadsBuilder {
        NnsInitPayloadsBuilder {
            registry: RegistryCanisterInitPayloadBuilder::new(),
            governance: GovernanceCanisterInitPayloadBuilder::new(),
            ledger: LedgerCanisterInitPayloadBuilder::new_with_mainnet_settings()
                .send_whitelist(ALL_NNS_CANISTER_IDS.iter().map(|&x| *x).collect())
                .build()
                .unwrap(),
            root: RootCanisterInitPayloadBuilder::new(),
            cycles_minting: Some(CyclesCanisterInitPayload {
                ledger_canister_id: Some(LEDGER_CANISTER_ID),
                governance_canister_id: Some(GOVERNANCE_CANISTER_ID),
                exchange_rate_canister: None,
                minting_account_id: Some(GOVERNANCE_CANISTER_ID.get().into()),
                last_purged_notification: None,
                cycles_ledger_canister_id: Some(CYCLES_LEDGER_CANISTER_ID),
            }),
            lifeline: LifelineCanisterInitPayloadBuilder::new(),
            genesis_token: GenesisTokenCanisterInitPayloadBuilder::new(),
            sns_wasms: SnsWasmCanisterInitPayloadBuilder::new(),
            index: ic_icp_index::InitArg {
                ledger_id: LEDGER_CANISTER_ID.get().into(),
            },
            subnet_rental: SubnetRentalCanisterInitPayloadBuilder::new(),
        }
    }

    pub fn with_ledger_init_state(&mut self, state: LedgerCanisterInitPayload) -> &mut Self {
        self.ledger = state;
        self
    }

    pub fn with_ledger_account(&mut self, account: AccountIdentifier, icpts: Tokens) -> &mut Self {
        self.ledger
            .init_args()
            .unwrap()
            .initial_values
            .insert(account, icpts);
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

    pub fn with_test_neurons_fund_neurons(
        &mut self,
        maturity_equivalent_icp_e8s: u64,
    ) -> &mut Self {
        self.governance
            .with_test_neurons_fund_neurons(maturity_equivalent_icp_e8s);
        self
    }

    pub fn with_test_neurons_fund_neurons_with_hotkeys(
        &mut self,
        hotkeys: Vec<PrincipalId>,
        maturity_equivalent_icp_e8s: u64,
    ) -> &mut Self {
        self.governance
            .with_test_neurons_fund_neurons_with_hotkeys(hotkeys, maturity_equivalent_icp_e8s);
        self
    }

    pub fn with_additional_neurons(&mut self, neurons: Vec<Neuron>) -> &mut Self {
        self.governance.with_additional_neurons(neurons);
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
                mutations: invariant_compliant_mutation(0),
                preconditions: vec![],
            });
        self
    }

    /// Create GTC neurons and add them to the GTC and Governance canisters'
    /// initial payloads
    pub fn with_gtc_neurons(&mut self) -> &mut Self {
        self.genesis_token.add_sr_neurons(SEED_ROUND_ACCOUNTS);
        self.genesis_token.add_ect_neurons(ECT_ACCOUNTS);

        let default_followees = &self.governance.proto.default_followees;

        let gtc_neurons = self
            .genesis_token
            .get_gtc_neurons()
            .into_iter()
            .map(|mut neuron| {
                neuron.followees.clone_from(default_followees);
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

    pub fn with_exchange_rate_canister(
        &mut self,
        exchange_rate_canister_id: CanisterId,
    ) -> &mut Self {
        if let Some(init_payload) = self.cycles_minting.as_mut() {
            init_payload.exchange_rate_canister = Some(
                cycles_minting_canister::ExchangeRateCanister::Set(exchange_rate_canister_id),
            );
        }

        self
    }

    pub fn with_network_economics(&mut self, network_economics: NetworkEconomics) -> &mut Self {
        self.governance.with_network_economics(network_economics);
        self
    }

    pub fn with_subnet_rental_canister(&mut self) -> &mut Self {
        self.subnet_rental.enable();
        self
    }

    pub fn build(&mut self) -> NnsInitPayloads {
        assert!(
            !self
                .ledger
                .init_args()
                .unwrap()
                .initial_values
                .contains_key(&GOVERNANCE_CANISTER_ID.get().into())
        );
        for n in self.governance.proto.neurons.values() {
            let sub = Subaccount(n.account.as_slice().try_into().unwrap_or_else(|e| {
                panic!(
                    "Subaccounts should be exactly 32 bytes in length. Got {} for neuron {}. {}",
                    truncate_and_format(n.account.as_slice(), 80),
                    n.id.as_ref()
                        .unwrap_or_else(|| panic!("Couldn't get id of neuron: {n:?}"))
                        .id,
                    e
                )
            }));
            let aid = ledger::AccountIdentifier::new(GOVERNANCE_CANISTER_ID.get(), Some(sub));
            let previous_value = self
                .ledger
                .init_args()
                .unwrap()
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
            index: self.index.clone(),
            subnet_rental: self.subnet_rental.build(),
        }
    }
}

fn is_gzipped_blob(blob: &[u8]) -> bool {
    (blob.len() > 4)
        // Has magic bytes.
        && (blob[0..2] == [0x1F, 0x8B])
}

pub fn modify_wasm_bytes(wasm_bytes: &[u8], modify_with: u32) -> Vec<u8> {
    // wasm_bytes are gzipped and the subslice [4..8]
    // is the little endian representation of a timestamp
    // so we just increment that timestamp
    assert!(is_gzipped_blob(wasm_bytes));
    let mut new_wasm_bytes = wasm_bytes.to_vec();
    let t = u32::from_le_bytes(new_wasm_bytes[4..8].try_into().unwrap());
    new_wasm_bytes[4..8].copy_from_slice(&(t + modify_with + 1).to_le_bytes());
    new_wasm_bytes
}

// NOTE, keep the functions for building wasms in the same order as the constants in
// rs/nns/constants/src/lib.rs.  Only the first ledger archive is represented in the ordering.

// REGISTRY

/// Build Wasm for NNS Registry canister
pub fn build_registry_wasm_with_features(features: &[&str]) -> Wasm {
    Project::cargo_bin_maybe_from_env("registry-canister", features)
}

/// Build Wasm for NNS Registry canister
pub fn build_registry_wasm() -> Wasm {
    build_registry_wasm_with_features(&[])
}

/// Build Wasm for NNS Registry canister
pub fn build_test_registry_wasm() -> Wasm {
    build_registry_wasm_with_features(&["test"])
}

/// Build mainnet Wasm for NNS Registry canister
pub fn build_mainnet_registry_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("mainnet-registry-canister", &features)
}

// GOVERNANCE

/// Build Wasm for NNS Governance canister
pub fn build_governance_wasm_with_features(features: &[&str]) -> Wasm {
    Project::cargo_bin_maybe_from_env("governance-canister", features)
}

/// Build Wasm for NNS Governance canister
pub fn build_test_governance_wasm() -> Wasm {
    let features = ["test"];
    build_governance_wasm_with_features(&features)
}

/// Build Wasm for NNS Governance canister with no features
pub fn build_governance_wasm() -> Wasm {
    let features = [];
    build_governance_wasm_with_features(&features)
}

/// Build mainnet Wasm for NNS Governance Canister
pub fn build_mainnet_governance_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("mainnet-governance-canister", &features)
}

// LEDGER

/// Build Wasm for NNS Ledger canister
pub fn build_ledger_wasm() -> Wasm {
    Project::cargo_bin_maybe_from_env("ledger-canister", &[])
}

/// Build mainnet Wasm for NNS Ledger Canister
pub fn build_mainnet_ledger_wasm() -> Wasm {
    Project::cargo_bin_maybe_from_env("mainnet-icp-ledger-canister", &[])
}

// ROOT

/// Build Wasm for NNS Root canister
pub fn build_root_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("root-canister", &features)
}

/// Build mainnet Wasm for NNS Root Canister
pub fn build_mainnet_root_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("mainnet-root-canister", &features)
}

// CYCLES-MINTING

/// Build Wasm for NNS CMC
pub fn build_cmc_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("cycles-minting-canister", &features)
}
/// Build mainnet Wasm for NNS CMC
pub fn build_mainnet_cmc_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("mainnet-cycles-minting-canister", &features)
}

// LIFELINE

/// Build Wasm for NNS Lifeline canister
pub fn build_lifeline_wasm() -> Wasm {
    Wasm::from_location_specified_by_env_var("lifeline_canister", &[])
        .unwrap_or_else(|| Wasm::from_bytes(LIFELINE_CANISTER_WASM))
}

/// Build mainnet Wasm for NNS Lifeline canister
pub fn build_mainnet_lifeline_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("mainnet-lifeline-canister", &features)
}

// GENESIS TOKEN

/// Build Wasm for NNS Genesis Token canister
pub fn build_genesis_token_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("genesis-token-canister", &features)
}

// IDENTITY (not used in tests yet)

// NNS UI (not used in tests yet)

// LEDGER ARCHIVE (not used in tests yet)

// SNS WASM

/// Build Wasm for NNS SnsWasm canister
pub fn build_sns_wasms_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("sns-wasm-canister", &features)
}

/// Build mainnet Wasm for NNS SnsWasm canister
pub fn build_mainnet_sns_wasms_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("mainnet-sns-wasm-canister", &features)
}

// LEDGER INDEX

/// Build Wasm for Index canister for the ICP Ledger
pub fn build_index_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("ic-icp-index", &features)
}

/// Build mainnet Wasm for Index canister for the ICP Ledger
pub fn build_mainnet_index_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("mainnet-ic-icp-index-canister", &features)
}

// SUBNET RENTAL (not used in tests yet)

// NODE REWARDS CANISTER

/// Build Wasm for NNS Node Rewards canister
pub fn build_node_rewards_wasm() -> Wasm {
    let features = [];
    Project::cargo_bin_maybe_from_env("node-rewards-canister", &features)
}

pub fn build_node_rewards_test_wasm() -> Wasm {
    let features = ["test"];
    Project::cargo_bin_maybe_from_env("node-rewards-canister", &features)
}

/// Build mainnet Wasm for NNS Node Rewards canister
pub fn build_mainnet_node_rewards_wasm() -> Wasm {
    panic!(
        "NRC has not yet been released to mainnet.  Please update this function when it is.\
        Additionally, tests using NNS canisters will need to build this canister when testing \
        node provider rewards.  See sync-with-released-nervous-system-wasms/src/main.rs"
    );
    // let features = [];
    // Project::cargo_bin_maybe_from_env("mainnet-node-rewards-canister", &features)
}
