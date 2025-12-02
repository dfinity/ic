use candid::{Decode, Encode, Nat, Principal};
use canister_test::Wasm;
use futures::{StreamExt, stream};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_interfaces_registry::{RegistryDataProvider, ZERO_REGISTRY_VERSION};
use ic_ledger_core::Tokens;
use ic_management_canister_types::CanisterSettings;
use ic_nervous_system_agent::{
    ProgressNetwork,
    helpers::nns as nns_agent_helpers,
    pocketic_impl::{PocketIcAgent, PocketIcCallError},
    sns::Sns,
};
use ic_nervous_system_common::{E8, ONE_DAY_SECONDS};
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL};
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use ic_nns_constants::{
    self, ALL_NNS_CANISTER_IDS, CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID, LEDGER_INDEX_CANISTER_ID, LIFELINE_CANISTER_ID, REGISTRY_CANISTER_ID,
    ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_nns_governance_api::{
    CreateServiceNervousSystem, GetNeuronsFundAuditInfoResponse, InstallCodeRequest, ListNeurons,
    ListNeuronsResponse, MakeProposalRequest, ManageNeuronCommandRequest, ManageNeuronResponse,
    NetworkEconomics, Neuron, ProposalActionRequest, ProposalInfo,
    install_code::CanisterInstallMode,
};
use ic_nns_test_utils::{
    common::{
        NnsInitPayloadsBuilder, build_cmc_wasm, build_governance_wasm, build_index_wasm,
        build_ledger_wasm, build_lifeline_wasm, build_mainnet_cmc_wasm,
        build_mainnet_governance_wasm, build_mainnet_index_wasm, build_mainnet_ledger_wasm,
        build_mainnet_lifeline_wasm, build_mainnet_registry_wasm, build_mainnet_root_wasm,
        build_mainnet_sns_wasms_wasm, build_registry_wasm, build_root_wasm, build_sns_wasms_wasm,
        build_test_governance_wasm, build_test_registry_wasm,
    },
    sns_wasm::{
        build_archive_sns_wasm, build_governance_sns_wasm, build_governance_test_sns_wasm,
        build_index_ng_sns_wasm, build_ledger_sns_wasm, build_mainnet_archive_sns_wasm,
        build_mainnet_governance_sns_wasm, build_mainnet_index_ng_sns_wasm,
        build_mainnet_ledger_sns_wasm, build_mainnet_root_sns_wasm, build_mainnet_swap_sns_wasm,
        build_root_sns_wasm, build_swap_sns_wasm, ensure_sns_wasm_gzipped,
    },
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_transport::pb::v1::{
    RegistryAtomicMutateRequest, RegistryMutation, registry_mutation,
};
use ic_sns_governance_api::pb::v1::{
    self as sns_pb, AdvanceTargetVersionResponse, governance::Version,
};
use ic_sns_init::SnsCanisterInitPayloads;
use ic_sns_swap::pb::v1::{
    ErrorRefundIcpResponse, FinalizeSwapResponse, GetAutoFinalizationStatusResponse,
    GetBuyerStateResponse, GetDerivedStateResponse, GetInitResponse, GetLifecycleResponse,
    Lifecycle, NewSaleTicketResponse, RefreshBuyerTokensResponse,
};
use ic_sns_test_utils::itest_helpers::populate_canister_ids;
use ic_sns_wasm::pb::v1::{GetDeployedSnsByProposalIdResponse, SnsCanisterType, SnsWasm};
use icp_ledger::AccountIdentifier;
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{TransferArg, TransferError},
};
use itertools::{EitherOrBoth, Itertools};
use maplit::btreemap;
use pocket_ic::{PocketIcBuilder, RejectResponse, nonblocking::PocketIc};
use rust_decimal::prelude::ToPrimitive;
use std::{collections::BTreeMap, fmt::Write, path::Path, time::Duration};

pub const STARTING_CYCLES_PER_CANISTER: u128 = 2_000_000_000_000_000;

/// How frequently the canister should attempt to refresh the cached_upgrade_steps
pub(crate) const UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS: u64 = 60 * 60; // 1 hour

pub fn fmt_bytes(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, x| {
        let _ = write!(output, "{x:02x}");
        output
    })
}

pub fn extract_sns_canister_version(
    sns_version: Version,
    sns_canister_type: SnsCanisterType,
) -> Vec<u8> {
    match sns_canister_type {
        SnsCanisterType::Root => sns_version.root_wasm_hash,
        SnsCanisterType::Governance => sns_version.governance_wasm_hash,
        SnsCanisterType::Ledger => sns_version.ledger_wasm_hash,
        SnsCanisterType::Swap => sns_version.swap_wasm_hash,
        SnsCanisterType::Archive => sns_version.archive_wasm_hash,
        SnsCanisterType::Index => sns_version.index_wasm_hash,
        SnsCanisterType::Unspecified => {
            panic!("Unspecified canister type to upgrade.");
        }
    }
}

/// Creates a new PocketIc instance with NNS and SNS and application subnet
pub async fn pocket_ic_for_sns_tests_with_mainnet_versions() -> (PocketIc, SnsWasms) {
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_sns_subnet()
        .build_async()
        .await;

    // Install the (mainnet) NNS canisters.
    {
        let mut nns_installer = NnsInstaller::default();
        nns_installer.with_mainnet_nns_canister_versions();
        nns_installer.install(&pocket_ic).await;
    }

    // Publish (mainnet) SNS Wasms to SNS-W.
    let initial_sns_version = {
        let with_mainnet_sns_canisters = true;
        let deployed_sns_starting_info =
            add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
                .await
                .unwrap();
        deployed_sns_starting_info
            .into_iter()
            .map(|(canister_type, (_, wasm))| (canister_type, wasm))
            .collect::<BTreeMap<_, _>>()
    };

    (pocket_ic, initial_sns_version)
}

pub async fn install_canister(
    pocket_ic: &PocketIc,
    name: &str,
    canister_id: CanisterId,
    arg: Vec<u8>,
    wasm: Wasm,
    controller: Option<PrincipalId>,
) {
    install_canister_with_controllers(
        pocket_ic,
        name,
        canister_id,
        arg,
        wasm,
        controller.into_iter().collect(),
    )
    .await
}

pub async fn install_canister_with_controllers(
    pocket_ic: &PocketIc,
    name: &str,
    canister_id: CanisterId,
    arg: Vec<u8>,
    wasm: Wasm,
    controllers: Vec<PrincipalId>,
) {
    let controllers = controllers.into_iter().map(|c| c.0).collect::<Vec<_>>();
    let controller_principal = controllers.first().cloned();
    let memory_allocation = if ALL_NNS_CANISTER_IDS.contains(&&canister_id) {
        let memory_allocation_bytes = ic_nns_constants::memory_allocation_of(canister_id);
        Some(Nat::from(memory_allocation_bytes))
    } else {
        None
    };
    let settings = Some(CanisterSettings {
        memory_allocation,
        controllers: Some(controllers),
        ..Default::default()
    });
    let canister_id = pocket_ic
        .create_canister_with_id(controller_principal, settings, canister_id.into())
        .await
        .unwrap();
    pocket_ic
        .add_cycles(canister_id, STARTING_CYCLES_PER_CANISTER)
        .await;
    pocket_ic
        .install_canister(canister_id, wasm.bytes(), arg, controller_principal)
        .await;
    let subnet_id = pocket_ic.get_subnet(canister_id).await.unwrap();
    println!("Installed the {name} canister ({canister_id}) onto {subnet_id:?}");
}

pub async fn install_canister_on_subnet(
    pocket_ic: &PocketIc,
    subnet_id: Principal,
    arg: Vec<u8>,
    wasm: Option<Wasm>,
    controllers: Vec<PrincipalId>,
) -> CanisterId {
    let controllers = controllers.into_iter().map(|c| c.0).collect::<Vec<_>>();
    let controller_principal = controllers.first().cloned();
    let settings = Some(CanisterSettings {
        controllers: Some(controllers),
        ..Default::default()
    });
    let canister_id = pocket_ic
        .create_canister_on_subnet(None, settings, subnet_id)
        .await;
    pocket_ic
        .add_cycles(canister_id, STARTING_CYCLES_PER_CANISTER)
        .await;
    if let Some(wasm) = wasm {
        pocket_ic
            .install_canister(canister_id, wasm.bytes(), arg, controller_principal)
            .await;
    }
    CanisterId::unchecked_from_principal(canister_id.into())
}

/// A builder for adding SNS WASW modules to SNS-W canister.
#[derive(Default)]
pub struct SnsWasmCanistersInstaller {
    pub mainnet_sns_canister_versions: Option<bool>,
    pub neuron_id: Option<NeuronId>,
    pub principal_id: Option<PrincipalId>,
}

impl SnsWasmCanistersInstaller {
    /// Requests the mainnet Wasm versions for all NNS canisters being installed.
    pub fn with_mainnet_sns_canister_versions(&mut self) -> &mut Self {
        self.mainnet_sns_canister_versions = Some(true);
        self
    }

    /// Requests tip-of-this-branch Wasm versions for all NNS canisters being installed.
    pub fn with_current_sns_canister_versions(&mut self) -> &mut Self {
        self.mainnet_sns_canister_versions = Some(false);
        self
    }

    /// Specifies the ID of the neuron which will be used to create NNS proposals and
    /// principal ID that is able to submit proposals on behalf of the provided neuron.
    /// If the neuron is not specified with this method, `TEST_NEURON_1_ID` will be used
    pub fn with_nns_neuron(&mut self, neuron_id: NeuronId, principal_id: PrincipalId) -> &mut Self {
        self.neuron_id = Some(neuron_id);
        self.principal_id = Some(principal_id);
        self
    }

    /// Adds an SNS canister WASM module to the SNS-W canister via NNS proposal.
    /// If the neuron ID wasn't specified with `the with_nns_neuron` method,
    /// it uses `TEST_NEURON_1_ID` as the NNS neuron ID to submit the proposal.
    pub async fn add_wasm_via_nns_proposal(
        &self,
        pocket_ic: &PocketIc,
        wasm: SnsWasm,
    ) -> Result<ProposalInfo, String> {
        let neuron_id = self.neuron_id.unwrap_or(NeuronId {
            id: TEST_NEURON_1_ID,
        });
        let principal_id = self.principal_id.unwrap_or(*TEST_NEURON_1_OWNER_PRINCIPAL);
        let agent = PocketIcAgent::new(pocket_ic, principal_id);
        nns_agent_helpers::add_wasm_via_nns_proposal(&agent, neuron_id, wasm).await
    }

    /// Adds SNS canister WASM modules to the SNS-W canister via NNS proposals.
    /// If the neuron ID wasn't specified with the 'with_nns_neuron' method,
    /// it uses `TEST_NEURON_1_ID`` as the NNS neuron ID to submit the proposal.
    /// This method either uses mainnet or tip-of-the-branch SNS canisters.
    /// based on whether `with_mainnet_sns_canister_versions` or `with_current_sns_canister_versions`
    /// method was called.
    pub async fn add_wasms_to_sns_wasm(
        &self,
        pocket_ic: &PocketIc,
    ) -> Result<DeployedSnsStartingInfo, String> {
        let with_mainnet_sns_canisters = self.mainnet_sns_canister_versions.expect(
            "Please explicitly request either mainnet or tip-of-the-branch SNS canisters version.",
        );
        let (root_wasm, governance_wasm, swap_wasm, index_wasm, ledger_wasm, archive_wasm) =
            if with_mainnet_sns_canisters {
                (
                    ensure_sns_wasm_gzipped(build_mainnet_root_sns_wasm()),
                    ensure_sns_wasm_gzipped(build_mainnet_governance_sns_wasm()),
                    ensure_sns_wasm_gzipped(build_mainnet_swap_sns_wasm()),
                    ensure_sns_wasm_gzipped(build_mainnet_index_ng_sns_wasm()),
                    ensure_sns_wasm_gzipped(build_mainnet_ledger_sns_wasm()),
                    ensure_sns_wasm_gzipped(build_mainnet_archive_sns_wasm()),
                )
            } else {
                (
                    ensure_sns_wasm_gzipped(build_root_sns_wasm()),
                    ensure_sns_wasm_gzipped(build_governance_test_sns_wasm()),
                    ensure_sns_wasm_gzipped(build_swap_sns_wasm()),
                    ensure_sns_wasm_gzipped(build_index_ng_sns_wasm()),
                    ensure_sns_wasm_gzipped(build_ledger_sns_wasm()),
                    ensure_sns_wasm_gzipped(build_archive_sns_wasm()),
                )
            };

        let root_proposal_info = self
            .add_wasm_via_nns_proposal(pocket_ic, root_wasm.clone())
            .await?;
        let gov_proposal_info = self
            .add_wasm_via_nns_proposal(pocket_ic, governance_wasm.clone())
            .await?;
        let swap_proposal_info = self
            .add_wasm_via_nns_proposal(pocket_ic, swap_wasm.clone())
            .await?;

        let index_proposal_info = self
            .add_wasm_via_nns_proposal(pocket_ic, index_wasm.clone())
            .await?;
        let ledger_proposal_info = self
            .add_wasm_via_nns_proposal(pocket_ic, ledger_wasm.clone())
            .await?;
        let archive_proposal_info = self
            .add_wasm_via_nns_proposal(pocket_ic, archive_wasm.clone())
            .await?;

        Ok(btreemap! {
            // Governance suite
            SnsCanisterType::Swap => (swap_proposal_info, swap_wasm),
            SnsCanisterType::Root => (root_proposal_info, root_wasm),
            SnsCanisterType::Governance => (gov_proposal_info, governance_wasm),

            // Ledger suite
            SnsCanisterType::Index => (index_proposal_info, index_wasm),
            SnsCanisterType::Ledger => (ledger_proposal_info, ledger_wasm),
            SnsCanisterType::Archive => (archive_proposal_info, archive_wasm),
        })
    }
}

pub async fn add_wasm_via_nns_proposal(
    pocket_ic: &PocketIc,
    wasm: SnsWasm,
) -> Result<ProposalInfo, String> {
    SnsWasmCanistersInstaller::default()
        .add_wasm_via_nns_proposal(pocket_ic, wasm)
        .await
}

pub async fn propose_to_set_network_economics_and_wait(
    pocket_ic: &PocketIc,
    network_economics: NetworkEconomics,
) -> Result<ProposalInfo, String> {
    let proposal = MakeProposalRequest {
        title: Some("Set NetworkEconomics.neurons_fund_economics {}".to_string()),
        summary: "summary".to_string(),
        url: "".to_string(),
        action: Some(ProposalActionRequest::ManageNetworkEconomics(
            network_economics,
        )),
    };
    nns::governance::propose_and_wait(pocket_ic, proposal).await
}

pub type DeployedSnsStartingInfo = BTreeMap<SnsCanisterType, (ProposalInfo, SnsWasm)>;
pub type SnsWasms = BTreeMap<SnsCanisterType, SnsWasm>;

pub fn hash_sns_wasms(wasms: &SnsWasms) -> Version {
    Version {
        root_wasm_hash: wasms[&SnsCanisterType::Root].sha256_hash().to_vec(),
        governance_wasm_hash: wasms[&SnsCanisterType::Governance].sha256_hash().to_vec(),
        ledger_wasm_hash: wasms[&SnsCanisterType::Ledger].sha256_hash().to_vec(),
        swap_wasm_hash: wasms[&SnsCanisterType::Swap].sha256_hash().to_vec(),
        archive_wasm_hash: wasms[&SnsCanisterType::Archive].sha256_hash().to_vec(),
        index_wasm_hash: wasms[&SnsCanisterType::Index].sha256_hash().to_vec(),
    }
}

pub async fn add_wasms_to_sns_wasm(
    pocket_ic: &PocketIc,
    with_mainnet_sns_canisters: bool,
) -> Result<DeployedSnsStartingInfo, String> {
    let mut sns_wasm_canister_installer = SnsWasmCanistersInstaller::default();

    if with_mainnet_sns_canisters {
        sns_wasm_canister_installer.with_mainnet_sns_canister_versions();
    } else {
        sns_wasm_canister_installer.with_current_sns_canister_versions();
    }

    sns_wasm_canister_installer
        .add_wasms_to_sns_wasm(pocket_ic)
        .await
}

/// A builder for fine-tuning and installing the NNS canister suite in PocketIc.
#[derive(Default)]
pub struct NnsInstaller {
    mainnet_nns_canister_versions: Option<bool>,
    neurons_fund_hotkeys: Option<Vec<PrincipalId>>,
    custom_registry_mutations: Option<Vec<RegistryAtomicMutateRequest>>,
    initial_balances: Vec<(AccountIdentifier, Tokens)>,
    with_cycles_minting_canister: bool,
    with_cycles_ledger: bool,
    with_index_canister: bool,
    with_test_governance_canister: bool,
    with_test_registry_canister: bool,
    neurons: Option<Vec<Neuron>>,
}

impl NnsInstaller {
    /// Requests the mainnet Wasm versions for all NNS canisters being installed.
    pub fn with_mainnet_nns_canister_versions(&mut self) -> &mut Self {
        self.mainnet_nns_canister_versions = Some(true);
        self
    }

    /// Requests tip-of-this-branch Wasm versions for all NNS canisters being installed.
    pub fn with_current_nns_canister_versions(&mut self) -> &mut Self {
        self.mainnet_nns_canister_versions = Some(false);
        self
    }

    /// Requests that the NNS Governance is initialized with a Neurons' Fund neuron with hotkeys
    /// taken from `neurons_fund_hotkeys`. Hotkeys are principals that can control the neuron
    /// in various ways, but generally less powerful than the neuron controller.
    /// Mutually exclusive with `with_neurons`.
    pub fn with_neurons_fund_hotkeys(
        &mut self,
        neurons_fund_hotkeys: Vec<PrincipalId>,
    ) -> &mut Self {
        self.neurons_fund_hotkeys = Some(neurons_fund_hotkeys);
        self
    }

    /// Requests that the NNS Registry is initialized with `custom_registry_mutations`.
    ///
    /// The custom mutations must result in an invariant-compliant Registry state.
    ///
    /// Without this specification, default initial Registry mutations will be used, which are
    /// guaranteed to be compliant.
    pub fn with_custom_registry_mutations(
        &mut self,
        custom_registry_mutations: Vec<RegistryAtomicMutateRequest>,
    ) -> &mut Self {
        self.custom_registry_mutations = Some(custom_registry_mutations);
        self
    }

    /// Requests `initial_balances` as a Vec of `(test_user_icp_ledger_account,
    /// test_user_icp_ledger_initial_balance)` pairs, representing some initial ICP balances.
    pub fn with_ledger_balances(
        &mut self,
        initial_balances: Vec<(AccountIdentifier, Tokens)>,
    ) -> &mut Self {
        self.initial_balances = initial_balances;
        self
    }

    pub fn with_cycles_minting_canister(&mut self) -> &mut Self {
        self.with_cycles_minting_canister = true;
        self
    }

    pub fn with_cycles_ledger(&mut self) -> &mut Self {
        self.with_cycles_ledger = true;
        self
    }

    pub fn with_index_canister(&mut self) -> &mut Self {
        self.with_index_canister = true;
        self
    }

    pub fn with_test_governance_canister(&mut self) -> &mut Self {
        self.with_test_governance_canister = true;
        self
    }

    pub fn with_test_registry_canister(&mut self) -> &mut Self {
        self.with_test_registry_canister = true;
        self
    }

    /// Requests the NNS Governance to be initialized with the following neurons.
    /// Mutually exclusive with `with_neurons_fund_hotkeys`.
    pub fn with_neurons(&mut self, neurons: Vec<Neuron>) -> &mut Self {
        self.neurons = Some(neurons);
        self
    }

    /// Installs the NNS canister suite.
    ///
    /// Ensures that there is a whale neuron with `TEST_NEURON_1_ID`.
    ///
    /// Requires that the PocketIC instance has an NNS and an SNS subnet.
    ///
    /// Returns the list of `controller_principal_id`s of pre-configured NNS neurons.
    pub async fn install(self, pocket_ic: &PocketIc) -> Vec<PrincipalId> {
        let with_mainnet_canister_versions = self
            .mainnet_nns_canister_versions
            .expect("Please explicitly request either mainnet or tip-of-the-branch NNS version.");

        assert!(
            !(with_mainnet_canister_versions && self.with_test_governance_canister),
            "The test version of the governance canister cannot be used with mainnet versions of the NNS canisters"
        );

        let topology = pocket_ic.topology().await;

        let sns_subnet_id = topology.get_sns().expect("No SNS subnet found");
        let sns_subnet_id = SubnetId::from(PrincipalId::from(sns_subnet_id));

        let mut nns_init_payload_builder = NnsInitPayloadsBuilder::new();

        if let Some(custom_registry_mutations) = self.custom_registry_mutations {
            nns_init_payload_builder.with_initial_mutations(custom_registry_mutations);
        } else {
            nns_init_payload_builder.with_initial_invariant_compliant_mutations();
        }

        assert!(
            !(self.neurons.is_some() && self.neurons_fund_hotkeys.is_some()),
            "'with_neurons' and 'with_neurons_fund_hotkeys' methods are mutually exclusive."
        );
        let maturity_equivalent_icp_e8s = 1_500_000 * E8;

        if let Some(neurons) = self.neurons {
            nns_init_payload_builder.with_additional_neurons(neurons);
        } else {
            nns_init_payload_builder.with_test_neurons_fund_neurons_with_hotkeys(
                self.neurons_fund_hotkeys.unwrap_or_default(),
                maturity_equivalent_icp_e8s,
            );
        }
        nns_init_payload_builder
            .with_sns_dedicated_subnets(vec![sns_subnet_id])
            .with_sns_wasm_access_controls(true);

        for (test_user_icp_ledger_account, test_user_icp_ledger_initial_balance) in
            self.initial_balances
        {
            nns_init_payload_builder.with_ledger_account(
                test_user_icp_ledger_account,
                test_user_icp_ledger_initial_balance,
            );
        }

        let nns_init_payload = nns_init_payload_builder.build();

        let (governance_wasm, ledger_wasm, root_wasm, lifeline_wasm, sns_wasm_wasm, registry_wasm) =
            if with_mainnet_canister_versions {
                (
                    build_mainnet_governance_wasm(),
                    build_mainnet_ledger_wasm(),
                    build_mainnet_root_wasm(),
                    build_mainnet_lifeline_wasm(),
                    build_mainnet_sns_wasms_wasm(),
                    build_mainnet_registry_wasm(),
                )
            } else {
                (
                    if self.with_test_governance_canister {
                        build_test_governance_wasm()
                    } else {
                        build_governance_wasm()
                    },
                    build_ledger_wasm(),
                    build_root_wasm(),
                    build_lifeline_wasm(),
                    build_sns_wasms_wasm(),
                    if self.with_test_registry_canister {
                        build_test_registry_wasm()
                    } else {
                        build_registry_wasm()
                    },
                )
            };

        install_canister(
            pocket_ic,
            "ICP Ledger",
            LEDGER_CANISTER_ID,
            Encode!(&nns_init_payload.ledger).unwrap(),
            ledger_wasm,
            Some(ROOT_CANISTER_ID.get()),
        )
        .await;
        install_canister(
            pocket_ic,
            "NNS Root",
            ROOT_CANISTER_ID,
            Encode!(&nns_init_payload.root).unwrap(),
            root_wasm,
            Some(LIFELINE_CANISTER_ID.get()),
        )
        .await;
        install_canister(
            pocket_ic,
            "NNS Governance",
            GOVERNANCE_CANISTER_ID,
            Encode!(&nns_init_payload.governance).unwrap(),
            governance_wasm,
            Some(ROOT_CANISTER_ID.get()),
        )
        .await;
        install_canister(
            pocket_ic,
            "Lifeline",
            LIFELINE_CANISTER_ID,
            Encode!(&nns_init_payload.lifeline).unwrap(),
            lifeline_wasm,
            Some(ROOT_CANISTER_ID.get()),
        )
        .await;
        install_canister(
            pocket_ic,
            "NNS SNS-W",
            SNS_WASM_CANISTER_ID,
            Encode!(&nns_init_payload.sns_wasms).unwrap(),
            sns_wasm_wasm,
            Some(ROOT_CANISTER_ID.get()),
        )
        .await;
        install_canister(
            pocket_ic,
            "Registry",
            REGISTRY_CANISTER_ID,
            Encode!(&nns_init_payload.registry).unwrap(),
            registry_wasm,
            Some(ROOT_CANISTER_ID.get()),
        )
        .await;

        if self.with_cycles_minting_canister {
            let cycles_minting_wasm = if with_mainnet_canister_versions {
                build_mainnet_cmc_wasm()
            } else {
                build_cmc_wasm()
            };
            install_canister(
                pocket_ic,
                "Cycles Minting",
                CYCLES_MINTING_CANISTER_ID,
                Encode!(&nns_init_payload.cycles_minting).unwrap(),
                cycles_minting_wasm,
                Some(ROOT_CANISTER_ID.get()),
            )
            .await;

            // Authorize canister creation on application subnets.
            let application_subnets = pocket_ic
                .topology()
                .await
                .get_app_subnets()
                .into_iter()
                .map(|id| SubnetId::from(PrincipalId::from(id)))
                .collect();
            nns::cmc::set_authorized_subnetwork_list(
                pocket_ic,
                GOVERNANCE_CANISTER_ID.get(),
                None,
                application_subnets,
            )
            .await;
        }

        if self.with_cycles_ledger {
            cycles_ledger::install(pocket_ic).await;
        }

        if self.with_index_canister {
            let ledger_index_wasm = if with_mainnet_canister_versions {
                build_mainnet_index_wasm()
            } else {
                build_index_wasm()
            };
            install_canister(
                pocket_ic,
                "Index",
                LEDGER_INDEX_CANISTER_ID,
                Encode!(&nns_init_payload.index).unwrap(),
                ledger_index_wasm,
                Some(ROOT_CANISTER_ID.get()),
            )
            .await;
        }

        nns_init_payload
            .governance
            .neurons
            .values()
            .map(|neuron| neuron.controller.unwrap())
            .collect()
    }
}

pub fn load_registry_mutations<P: AsRef<Path>>(path: P) -> RegistryAtomicMutateRequest {
    let registry_data_provider = ProtoRegistryDataProvider::load_from_file(path.as_ref());
    let updates = registry_data_provider
        .get_updates_since(ZERO_REGISTRY_VERSION)
        .unwrap();

    let mutations = updates
        .into_iter()
        .map(|update| {
            let mut mutation = RegistryMutation::default();

            let typ = if update.value.is_none() {
                registry_mutation::Type::Delete
            } else {
                registry_mutation::Type::Insert
            };
            mutation.set_mutation_type(typ);
            mutation.key = update.key.as_bytes().to_vec();
            mutation.value = update.value.unwrap_or_default();
            mutation
        })
        .collect::<Vec<_>>();

    RegistryAtomicMutateRequest {
        mutations,
        ..Default::default()
    }
}

pub mod cycles_ledger {
    use super::{install_canister, nns};
    use candid::{CandidType, Encode, Principal};
    use canister_test::Wasm;
    use cycles_minting_canister::{MEMO_MINT_CYCLES, NotifyMintCyclesSuccess};
    use ic_base_types::PrincipalId;
    use ic_nns_constants::{
        CYCLES_LEDGER_CANISTER_ID, CYCLES_MINTING_CANISTER_ID, ROOT_CANISTER_ID,
    };
    use icp_ledger::{
        AccountIdentifier, DEFAULT_TRANSFER_FEE, Tokens, TransferArgs,
        account_identifier::Subaccount,
    };
    use pocket_ic::nonblocking::PocketIc;

    #[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType)]
    struct CyclesLedgerInitArgs {
        pub index_id: Option<Principal>,
        pub max_blocks_per_request: u64,
    }

    /// Argument taken by the Cycles Ledger canister.
    ///
    /// See (https://github.com/dfinity/cycles-ledger/tree/main/cycles-ledger
    ///
    /// ```candid
    /// (variant {
    ///     Init = record {
    ///         index_id : opt principal;
    ///         max_blocks_per_request : nat64;
    ///     }
    /// })
    /// ```
    #[derive(Clone, Eq, PartialEq, Hash, Debug, CandidType)]
    enum CyclesLedgerArgs {
        Init(CyclesLedgerInitArgs),
    }

    pub async fn install(pocket_ic: &PocketIc) {
        let features = &[];
        let cycles_ledger_wasm =
            Wasm::from_location_specified_by_env_var("cycles_ledger", features).unwrap();

        let arg = Encode!(&CyclesLedgerArgs::Init(CyclesLedgerInitArgs {
            index_id: None,
            max_blocks_per_request: 1000,
        }))
        .unwrap();

        install_canister(
            pocket_ic,
            "Cycles Ledger",
            CYCLES_LEDGER_CANISTER_ID,
            arg,
            cycles_ledger_wasm,
            Some(ROOT_CANISTER_ID.get()),
        )
        .await;
    }

    pub async fn mint_icp_and_convert_to_cycles(
        pocket_ic: &PocketIc,
        beneficiary: PrincipalId,
        amount: Tokens,
    ) {
        nns::ledger::mint_icp(
            pocket_ic,
            AccountIdentifier::new(beneficiary, None),
            amount.saturating_add(DEFAULT_TRANSFER_FEE),
            None,
        )
        .await;

        let beneficiary_cmc_account = AccountIdentifier::new(
            CYCLES_MINTING_CANISTER_ID.into(),
            Some(Subaccount::from(&beneficiary)),
        );

        let transfer_args = TransferArgs {
            memo: MEMO_MINT_CYCLES,
            amount,
            fee: Tokens::from_e8s(10_000),
            from_subaccount: None,
            to: beneficiary_cmc_account.to_address(),
            created_at_time: None,
        };

        let block_index = nns::ledger::transfer(pocket_ic, beneficiary, transfer_args)
            .await
            .unwrap();

        let NotifyMintCyclesSuccess {
            block_index: _,
            minted: _,
            balance: _,
        } = nns::cmc::notify_mint_cycles(pocket_ic, beneficiary, None, None, block_index).await;
    }
}

#[derive(Copy, Clone, Debug)]
pub struct SnsTestCanisterIds {
    pub root_canister_id: CanisterId,
    pub governance_canister_id: CanisterId,
    pub ledger_canister_id: CanisterId,
    pub swap_canister_id: CanisterId,
    pub index_canister_id: CanisterId,
}

/// Function to allow directly installing and specifying the ids of the canisters
/// which is only useful when we need to test something that is ID-specific
pub async fn install_sns_directly_with_snsw_versions(
    pocket_ic: &PocketIc,
    mut payloads: SnsCanisterInitPayloads,
    sns_canister_ids: Option<SnsTestCanisterIds>,
) -> SnsTestCanisterIds {
    let create_canister = || async move {
        let id = pocket_ic.create_canister().await;
        pocket_ic.add_cycles(id, STARTING_CYCLES_PER_CANISTER).await;
        id
    };
    let create_canister_at_id = |canister_id: CanisterId| async move {
        let id = pocket_ic
            .create_canister_with_id(None, None, canister_id.into())
            .await
            .unwrap();
        pocket_ic
            .add_cycles(canister_id.into(), STARTING_CYCLES_PER_CANISTER)
            .await;
        id
    };
    let install_canister = |canister_id, wasm, payload| async move {
        pocket_ic
            .install_canister(canister_id, wasm, payload, None)
            .await;
    };

    let (
        root_canister_id,
        governance_canister_id,
        ledger_canister_id,
        swap_canister_id,
        index_canister_id,
    ) = if let Some(SnsTestCanisterIds {
        root_canister_id,
        governance_canister_id,
        ledger_canister_id,
        swap_canister_id,
        index_canister_id,
    }) = sns_canister_ids
    {
        (
            create_canister_at_id(root_canister_id).await,
            create_canister_at_id(governance_canister_id).await,
            create_canister_at_id(ledger_canister_id).await,
            create_canister_at_id(swap_canister_id).await,
            create_canister_at_id(index_canister_id).await,
        )
    } else {
        (
            create_canister().await,
            create_canister().await,
            create_canister().await,
            create_canister().await,
            create_canister().await,
        )
    };

    populate_canister_ids(
        root_canister_id.into(),
        governance_canister_id.into(),
        ledger_canister_id.into(),
        swap_canister_id.into(),
        index_canister_id.into(),
        vec![],
        &mut payloads,
    );

    let SnsCanisterInitPayloads {
        mut governance,
        ledger,
        root,
        swap,
        index_ng,
    } = payloads;

    let (
        root_sns_wasm,
        governance_sns_wasm,
        ledger_sns_wasm,
        swap_sns_wasm,
        index_sns_wasm,
        archive_sns_wasm,
    ) = {
        let latest_version = nns::sns_wasm::get_latest_sns_version(pocket_ic).await;
        (
            nns::sns_wasm::get_wasm(pocket_ic, latest_version.root_wasm_hash).await,
            nns::sns_wasm::get_wasm(pocket_ic, latest_version.governance_wasm_hash).await,
            nns::sns_wasm::get_wasm(pocket_ic, latest_version.ledger_wasm_hash).await,
            nns::sns_wasm::get_wasm(pocket_ic, latest_version.swap_wasm_hash).await,
            nns::sns_wasm::get_wasm(pocket_ic, latest_version.index_wasm_hash).await,
            nns::sns_wasm::get_wasm(pocket_ic, latest_version.archive_wasm_hash).await,
        )
    };

    let deployed_version = Version {
        root_wasm_hash: root_sns_wasm.sha256_hash().to_vec(),
        governance_wasm_hash: governance_sns_wasm.sha256_hash().to_vec(),
        ledger_wasm_hash: ledger_sns_wasm.sha256_hash().to_vec(),
        swap_wasm_hash: swap_sns_wasm.sha256_hash().to_vec(),
        archive_wasm_hash: archive_sns_wasm.sha256_hash().to_vec(),
        index_wasm_hash: index_sns_wasm.sha256_hash().to_vec(),
    };

    governance.deployed_version = Some(deployed_version.into());

    install_canister(
        root_canister_id,
        root_sns_wasm.wasm,
        Encode!(&root).unwrap(),
    )
    .await;
    install_canister(
        governance_canister_id,
        governance_sns_wasm.wasm,
        Encode!(&governance).unwrap(),
    )
    .await;
    install_canister(
        ledger_canister_id,
        ledger_sns_wasm.wasm,
        Encode!(&ledger).unwrap(),
    )
    .await;
    install_canister(
        swap_canister_id,
        swap_sns_wasm.wasm,
        Encode!(&swap).unwrap(),
    )
    .await;
    install_canister(
        index_canister_id,
        index_sns_wasm.wasm,
        Encode!(&index_ng.expect("Index payload was None")).unwrap(),
    )
    .await;

    pocket_ic
        .set_controllers(
            root_canister_id,
            Some(Principal::anonymous()),
            vec![governance_canister_id],
        )
        .await
        .expect("could not set controllers");
    pocket_ic
        .set_controllers(
            governance_canister_id,
            Some(Principal::anonymous()),
            vec![root_canister_id],
        )
        .await
        .expect("could not set controllers");
    pocket_ic
        .set_controllers(
            ledger_canister_id,
            Some(Principal::anonymous()),
            vec![root_canister_id],
        )
        .await
        .expect("could not set controllers");
    pocket_ic
        .set_controllers(
            swap_canister_id,
            Some(Principal::anonymous()),
            vec![ROOT_CANISTER_ID.get().0],
        )
        .await
        .expect("could not set controllers");
    pocket_ic
        .set_controllers(
            index_canister_id,
            Some(Principal::anonymous()),
            vec![root_canister_id],
        )
        .await
        .expect("could not set controllers");

    fn convert_canister_id(canister_id: Principal) -> CanisterId {
        CanisterId::unchecked_from_principal(PrincipalId::from(canister_id))
    }

    SnsTestCanisterIds {
        root_canister_id: convert_canister_id(root_canister_id),
        governance_canister_id: convert_canister_id(governance_canister_id),
        ledger_canister_id: convert_canister_id(ledger_canister_id),
        swap_canister_id: convert_canister_id(swap_canister_id),
        index_canister_id: convert_canister_id(index_canister_id),
    }
}

pub async fn upgrade_nns_canister_to_tip_of_master_or_panic(
    pocket_ic: &PocketIc,
    canister_id: CanisterId,
) {
    // What we really want here is `match canister_id { ... }`, but this does not work because
    // `CanisterId` encapsulates `PrincipalId` which has a manual implementation for `PartialEq`,
    // whereas Rust requires constants used in match expressions to **derive** `PartialEq`.
    let (wasm, controller, label) = if canister_id == GOVERNANCE_CANISTER_ID {
        (
            build_governance_wasm(),
            ROOT_CANISTER_ID.get(),
            "NNS Governance",
        )
    } else if canister_id == LEDGER_CANISTER_ID {
        (build_ledger_wasm(), ROOT_CANISTER_ID.get(), "ICP Ledger")
    } else if canister_id == LIFELINE_CANISTER_ID {
        (build_lifeline_wasm(), ROOT_CANISTER_ID.get(), "Lifeline")
    } else if canister_id == ROOT_CANISTER_ID {
        (build_root_wasm(), LIFELINE_CANISTER_ID.get(), "NNS Root")
    } else if canister_id == SNS_WASM_CANISTER_ID {
        (build_sns_wasms_wasm(), ROOT_CANISTER_ID.get(), "SNS-W")
    } else if canister_id == REGISTRY_CANISTER_ID {
        (build_registry_wasm(), ROOT_CANISTER_ID.get(), "Registry")
    } else {
        panic!("ID {canister_id} does not identify a known NNS canister.");
    };

    let expected_hash = wasm.sha256_hash();

    let pre_upgrade_module_hash = pocket_ic
        .canister_status(canister_id.into(), Some(controller.0))
        .await
        .unwrap()
        .module_hash
        .unwrap();

    if pre_upgrade_module_hash == expected_hash.to_vec() {
        println!("The {label} canister is already at the tip of the master branch.");

        return;
    }

    println!("Upgrading {label} to the latest version.");
    let proposal_info = nns::governance::propose_and_wait(
        pocket_ic,
        MakeProposalRequest {
            title: Some(format!("Upgrade {label} to the latest version.")),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(ProposalActionRequest::InstallCode(InstallCodeRequest {
                canister_id: Some(canister_id.get()),
                install_mode: Some(CanisterInstallMode::Upgrade as i32),
                wasm_module: Some(wasm.bytes()),
                arg: Some(vec![]),
                skip_stopping_before_installing: None,
            })),
        },
    )
    .await
    .unwrap();

    // Check 1: The upgrade proposal did not fail.
    assert_eq!(proposal_info.failure_reason, None);

    // Check 2: The upgrade proposal succeeded.
    assert!(proposal_info.executed_timestamp_seconds > 0);

    // We need to wait for a few blocks before the effect takes place. Successful proposals do not
    // yet imply that the upgrade took place.
    for _ in 0..10 {
        pocket_ic.tick().await;
        pocket_ic.advance_time(Duration::from_secs(1)).await;
    }

    // Check 3: WASM module hash must change.
    let post_upgrade_module_hash = pocket_ic
        .canister_status(canister_id.into(), Some(controller.0))
        .await
        .unwrap()
        .module_hash
        .unwrap();
    assert_ne!(
        pre_upgrade_module_hash,
        post_upgrade_module_hash,
        "pre_upgrade_module_hash == post_upgrade_module_hash == {}",
        fmt_bytes(&pre_upgrade_module_hash),
    );
}

pub mod nns {
    use super::*;
    use ic_nervous_system_agent::{helpers::nns as nns_agent_helpers, nns as nns_agent};
    pub mod governance {
        use super::*;

        pub async fn list_neurons(
            pocket_ic: &PocketIc,
            sender: PrincipalId,
        ) -> ListNeuronsResponse {
            nns_agent::governance::list_neurons(
                &PocketIcAgent::new(pocket_ic, sender),
                ListNeurons {
                    neuron_ids: vec![],
                    include_neurons_readable_by_caller: true,
                    include_empty_neurons_readable_by_caller: Some(true),
                    include_public_neurons_in_full_neurons: None,
                    page_number: None,
                    page_size: None,
                    neuron_subaccounts: None,
                },
            )
            .await
            .unwrap()
        }

        /// Manage an NNS neuron, e.g., to make an NNS Governance proposal.
        pub async fn manage_neuron(
            pocket_ic: &PocketIc,
            sender: PrincipalId,
            neuron_id: NeuronId,
            command: ManageNeuronCommandRequest,
        ) -> ManageNeuronResponse {
            nns_agent::governance::manage_neuron(
                &PocketIcAgent::new(pocket_ic, sender),
                neuron_id,
                command,
            )
            .await
            .unwrap()
        }

        pub async fn propose_and_wait(
            pocket_ic: &PocketIc,
            proposal: MakeProposalRequest,
        ) -> Result<ProposalInfo, String> {
            let neuron_id = NeuronId {
                id: TEST_NEURON_1_ID,
            };
            let agent = PocketIcAgent::new(pocket_ic, *TEST_NEURON_1_OWNER_PRINCIPAL);
            nns_agent_helpers::propose_and_wait(&agent, neuron_id, proposal).await
        }

        pub async fn wait_for_proposal_execution(
            pocket_ic: &PocketIc,
            proposal_id: u64,
        ) -> Result<ProposalInfo, String> {
            nns_agent_helpers::wait_for_proposal_execution(
                &PocketIcAgent::new(pocket_ic, Principal::anonymous()),
                ProposalId { id: proposal_id },
            )
            .await
        }

        pub async fn nns_get_proposal_info(
            pocket_ic: &PocketIc,
            proposal_id: ProposalId,
            sender: PrincipalId,
        ) -> Result<ProposalInfo, RejectResponse> {
            nns_agent::governance::get_proposal_info(
                &PocketIcAgent::new(pocket_ic, sender),
                proposal_id,
            )
            .await
            .map(|p| p.unwrap())
            .map_err(|err| match err {
                PocketIcCallError::PocketIc(reject_response) => reject_response,
                err => panic!("Unexpected error when getting proposal info: {err:#?}"),
            })
        }

        pub async fn get_neurons_fund_audit_info(
            pocket_ic: &PocketIc,
            proposal_id: ProposalId,
        ) -> GetNeuronsFundAuditInfoResponse {
            nns_agent::governance::get_neurons_fund_audit_info(pocket_ic, proposal_id)
                .await
                .unwrap()
        }

        pub async fn propose_to_deploy_sns_and_wait(
            pocket_ic: &PocketIc,
            create_service_nervous_system: CreateServiceNervousSystem,
            sns_instance_label: &str,
        ) -> (Sns, ProposalId) {
            let agent = PocketIcAgent::new(pocket_ic, *TEST_NEURON_1_OWNER_PRINCIPAL);
            let test_neuron_1_id = NeuronId {
                id: TEST_NEURON_1_ID,
            };
            nns_agent_helpers::propose_to_deploy_sns_and_wait(
                &agent,
                test_neuron_1_id,
                create_service_nervous_system,
                format!("Create SNS #{sns_instance_label}"),
                "".to_string(),
                "".to_string(),
            )
            .await
            .unwrap()
        }

        pub async fn get_network_economics_parameters(pocket_ic: &PocketIc) -> NetworkEconomics {
            ic_nervous_system_agent::nns::governance::get_network_economics_parameters(pocket_ic)
                .await
                .unwrap()
        }
    }

    pub mod registry {
        use ic_registry_transport::{
            deserialize_get_value_response, pb::v1::HighCapacityRegistryGetValueResponse,
            serialize_get_value_request,
        };
        use registry_canister::mutations::do_swap_node_in_subnet_directly::SwapNodeInSubnetDirectlyPayload;

        use super::*;

        pub async fn swap_node_in_subnet_directly(
            pocket_ic: &PocketIc,
            payload: SwapNodeInSubnetDirectlyPayload,
            sender: PrincipalId,
        ) -> Result<(), RejectResponse> {
            let agent = PocketIcAgent::new(pocket_ic, sender);

            ic_nervous_system_agent::nns::registry::swap_node_in_subnet_directly(&agent, payload)
                .await
                .map_err(|err| match err {
                    PocketIcCallError::PocketIc(reject) => reject,
                    err => {
                        panic!("Unexpected error when performing swap in subnet directly: {err:?}")
                    }
                })
        }

        pub async fn get_value<A: AsRef<str>>(
            pocket_ic: &PocketIc,
            key: A,
            version_opt: Option<u64>,
        ) -> Result<HighCapacityRegistryGetValueResponse, RejectResponse> {
            pocket_ic
                .query_call(
                    REGISTRY_CANISTER_ID.get().0,
                    PrincipalId::new_anonymous().0,
                    "get_value",
                    serialize_get_value_request(key.as_ref().as_bytes().to_vec(), version_opt)
                        .unwrap(),
                )
                .await
                .map(|res| {
                    let response = deserialize_get_value_response(res)
                        .expect("Failed to deserialize get value response");

                    if let Some(err) = response.error {
                        panic!("Received error from registry: {err:?}");
                    }

                    response
                })
        }

        pub async fn apply_mutations_for_test(
            pocket_ic: &PocketIc,
            mutations: &Vec<RegistryMutation>,
        ) -> Result<(), RejectResponse> {
            pocket_ic
                .update_call(
                    REGISTRY_CANISTER_ID.get().0,
                    Principal::anonymous(),
                    "apply_mutations_for_test",
                    candid::Encode!(mutations).unwrap(),
                )
                .await
                .map(|_| ())
        }
    }

    pub mod ledger {
        use super::*;
        use ic_nervous_system_agent::nns::ledger as nns_agent_ledger;
        use icp_ledger::{Memo, TransferArgs};

        pub async fn icrc1_transfer(
            pocket_ic: &PocketIc,
            sender: PrincipalId,
            transfer_arg: TransferArg,
        ) -> Result<Nat, TransferError> {
            nns_agent_ledger::icrc1_transfer(&PocketIcAgent::new(pocket_ic, sender), transfer_arg)
                .await
                .unwrap()
        }

        pub async fn account_balance(pocket_ic: &PocketIc, account: &AccountIdentifier) -> Tokens {
            nns_agent_ledger::account_balance(
                &PocketIcAgent::new(pocket_ic, Principal::from(*TEST_NEURON_1_OWNER_PRINCIPAL)),
                *account,
            )
            .await
            .unwrap()
        }

        pub async fn transfer(
            pocket_ic: &PocketIc,
            sender: PrincipalId,
            args: TransferArgs,
        ) -> Result<u64, icp_ledger::TransferError> {
            nns_agent_ledger::transfer(&PocketIcAgent::new(pocket_ic, sender), args)
                .await
                .unwrap()
        }

        // Test method to mint ICP to a principal
        pub async fn mint_icp(
            pocket_ic: &PocketIc,
            destination: AccountIdentifier,
            amount: Tokens,
            memo: Option<Memo>,
        ) -> u64 {
            let governance_canister_agent = PocketIcAgent::new(pocket_ic, GOVERNANCE_CANISTER_ID);
            let args = TransferArgs {
                to: destination.to_address(),
                // An overwhelmingly large number, but not so large as to cause serious risk of
                // addition overflow.
                amount,

                // Non-Operative
                // -------------
                fee: Tokens::ZERO, // Because we are minting.
                memo: memo.unwrap_or(Memo(0)),
                from_subaccount: None,
                created_at_time: None,
            };
            nns_agent_ledger::transfer(&governance_canister_agent, args)
                .await
                .unwrap()
                .unwrap()
        }
    }

    pub mod sns_wasm {
        use super::*;
        use ic_nns_test_utils::sns_wasm::create_modified_sns_wasm;
        use ic_sns_wasm::pb::v1::SnsVersion;

        pub async fn get_deployed_sns_by_proposal_id(
            pocket_ic: &PocketIc,
            proposal_id: ProposalId,
        ) -> GetDeployedSnsByProposalIdResponse {
            ic_nervous_system_agent::nns::sns_wasm::get_deployed_sns_by_proposal_id(
                pocket_ic,
                proposal_id,
            )
            .await
            .unwrap()
        }

        /// Get the WASM for a given hash from SNS-W
        pub async fn get_wasm(pocket_ic: &PocketIc, wasm_hash: Vec<u8>) -> SnsWasm {
            ic_nervous_system_agent::nns::sns_wasm::get_wasm(pocket_ic, wasm_hash)
                .await
                .map(|response| response.wasm.expect("No wasm found for hash provided"))
                .unwrap()
        }

        /// Get the latest version of SNS from SNS-W
        pub async fn get_latest_sns_version(pocket_ic: &PocketIc) -> Version {
            let response = ic_nervous_system_agent::nns::sns_wasm::list_upgrade_steps(
                pocket_ic, None, None, 0,
            )
            .await
            .unwrap();
            let latest_version = response
                .steps
                .last()
                .cloned()
                .expect("No upgrade steps found")
                .version
                .expect("No version found");

            let SnsVersion {
                root_wasm_hash,
                governance_wasm_hash,
                ledger_wasm_hash,
                swap_wasm_hash,
                archive_wasm_hash,
                index_wasm_hash,
            } = latest_version;

            Version {
                root_wasm_hash,
                governance_wasm_hash,
                ledger_wasm_hash,
                swap_wasm_hash,
                archive_wasm_hash,
                index_wasm_hash,
            }
        }

        /// Modify the WASM for a given canister type and add it to SNS-W.
        /// Returns the new (modified) version that is now at the tip of SNS-W.
        pub async fn modify_and_add_wasm(
            pocket_ic: &PocketIc,
            mut version: SnsWasms,
            canister_type: SnsCanisterType,
            nonce: u32,
        ) -> SnsWasms {
            let wasm = version.get(&canister_type).unwrap();
            let wasm = create_modified_sns_wasm(wasm, Some(nonce));
            add_wasm_via_nns_proposal(pocket_ic, wasm.clone())
                .await
                .unwrap();
            version.insert(canister_type, wasm);
            version
        }

        /// Modify the WASM for a given canister type and add it to SNS-W.
        /// Returns the new (modified) version that is now at the tip of SNS-W.
        pub async fn modify_and_add_master_wasm(
            pocket_ic: &PocketIc,
            mut version: SnsWasms,
            canister_type: SnsCanisterType,
            nonce: u32,
        ) -> SnsWasms {
            let wasm = match canister_type {
                SnsCanisterType::Root => build_root_sns_wasm(),
                SnsCanisterType::Governance => build_governance_sns_wasm(),
                SnsCanisterType::Ledger => build_ledger_sns_wasm(),
                SnsCanisterType::Swap => build_swap_sns_wasm(),
                SnsCanisterType::Index => build_index_ng_sns_wasm(),
                SnsCanisterType::Unspecified => {
                    panic!("Where did you get this canister type from?")
                }
                SnsCanisterType::Archive => build_archive_sns_wasm(),
            };
            let wasm = create_modified_sns_wasm(&wasm, Some(nonce));
            add_wasm_via_nns_proposal(pocket_ic, wasm.clone())
                .await
                .unwrap();
            version.insert(canister_type, wasm);
            version
        }
    }

    pub mod cmc {
        use super::*;
        use cycles_minting_canister::NotifyMintCyclesSuccess;
        use icrc_ledger_types::icrc1::account::Subaccount;

        pub async fn set_authorized_subnetwork_list(
            pocket_ic: &PocketIc,
            sender: PrincipalId,
            who: Option<PrincipalId>,
            subnets: Vec<SubnetId>,
        ) {
            ic_nervous_system_agent::nns::cmc::set_authorized_subnetwork_list(
                &PocketIcAgent::new(pocket_ic, sender),
                who,
                subnets,
            )
            .await
            .unwrap()
        }

        pub async fn notify_mint_cycles(
            pocket_ic: &PocketIc,
            sender: PrincipalId,
            deposit_memo: Option<Vec<u8>>,
            to_subaccount: Option<Subaccount>,
            block_index: u64,
        ) -> NotifyMintCyclesSuccess {
            ic_nervous_system_agent::nns::cmc::notify_mint_cycles(
                &PocketIcAgent::new(pocket_ic, sender),
                block_index,
                to_subaccount,
                deposit_memo,
            )
            .await
            .unwrap()
            .unwrap()
        }
    }
}

pub mod sns {
    use super::*;
    use ic_nervous_system_agent::{helpers::sns as sns_agent_helpers, sns::root::SnsCanisters};

    #[derive(Clone, Debug, PartialEq)]
    pub enum SnsUpgradeError {
        CanisterVersionMismatch {
            canister_type: SnsCanisterType,
            canister_version_from_sns_pov: Vec<u8>,
            canister_version_from_ic00_pov: Vec<u8>,
            is_pre_upgrade: bool,
        },
        TargetCanisterVersionUnchanged {
            pre_upgrade_canister_version: Vec<u8>,
            post_upgrade_canister_version: Vec<u8>,
        },
    }

    pub async fn try_upgrade_sns_to_next_version(
        pocket_ic: &PocketIc,
        sns: &Sns,
        expected_type_to_change: SnsCanisterType,
    ) -> Result<(), SnsUpgradeError> {
        // Ensure that we are working with knowledge of the latest archive canisters (if there are any).
        let sns = {
            let response = sns.root.list_sns_canisters(pocket_ic).await.unwrap();
            SnsCanisters::try_from(response).unwrap().sns
        };

        let (canister_id, controller_id) = match expected_type_to_change {
            SnsCanisterType::Root => (sns.root.canister_id, sns.governance.canister_id),
            SnsCanisterType::Governance => (sns.governance.canister_id, sns.root.canister_id),
            SnsCanisterType::Ledger => (sns.ledger.canister_id, sns.root.canister_id),
            SnsCanisterType::Swap => (sns.swap.canister_id, sns.root.canister_id),
            SnsCanisterType::Archive => {
                let archive = sns.archive.last().expect(
                    "Testing Archive canister upgrade requires some Archive canisters \
                        to be created for this SNS.",
                );
                (archive.canister_id, sns.root.canister_id)
            }
            SnsCanisterType::Index => (sns.index.canister_id, sns.root.canister_id),
            SnsCanisterType::Unspecified => {
                panic!("Unspecified canister type to upgrade.");
            }
        };

        let pre_upgrade_version = sns.governance.version(pocket_ic).await;
        let pre_upgrade_version = pre_upgrade_version.unwrap().deployed_version.unwrap();

        // Check that we get the same version from the management canister and from the SNS.
        let pre_upgrade_canister_version = {
            let canister_version_from_sns_pov =
                extract_sns_canister_version(pre_upgrade_version.clone(), expected_type_to_change);
            let canister_version_from_ic00_pov = pocket_ic
                .canister_status(canister_id.into(), Some(controller_id.into()))
                .await
                .unwrap()
                .module_hash
                .unwrap();
            if canister_version_from_sns_pov != canister_version_from_ic00_pov {
                return Err(SnsUpgradeError::CanisterVersionMismatch {
                    canister_type: expected_type_to_change,
                    canister_version_from_sns_pov,
                    canister_version_from_ic00_pov,
                    is_pre_upgrade: true,
                });
            }
            canister_version_from_sns_pov
        };

        governance::propose_to_upgrade_sns_to_next_version_and_wait(
            pocket_ic,
            sns.governance.canister_id,
        )
        .await;

        for _ in 0..20 {
            pocket_ic.progress(Duration::from_secs(10)).await;
        }

        let post_upgrade_version = sns.governance.version(pocket_ic).await;
        let post_upgrade_version = post_upgrade_version.unwrap().deployed_version.unwrap();

        // Check that we get the same version from the management canister and from the SNS.
        let post_upgrade_canister_version = {
            let canister_version_from_sns_pov =
                extract_sns_canister_version(post_upgrade_version, expected_type_to_change);
            let canister_version_from_ic00_pov = pocket_ic
                .canister_status(canister_id.into(), Some(controller_id.into()))
                .await
                .unwrap()
                .module_hash
                .unwrap();
            if canister_version_from_sns_pov != canister_version_from_ic00_pov {
                println!("pre_upgrade_canister_version = {pre_upgrade_canister_version:?}");
                return Err(SnsUpgradeError::CanisterVersionMismatch {
                    canister_type: expected_type_to_change,
                    canister_version_from_sns_pov,
                    canister_version_from_ic00_pov,
                    is_pre_upgrade: false,
                });
            }
            canister_version_from_sns_pov
        };

        if pre_upgrade_canister_version == post_upgrade_canister_version {
            return Err(SnsUpgradeError::TargetCanisterVersionUnchanged {
                pre_upgrade_canister_version,
                post_upgrade_canister_version,
            });
        }

        Ok(())
    }

    pub async fn upgrade_sns_to_next_version_and_assert_change(
        pocket_ic: &PocketIc,
        sns: &Sns,
        expected_type_to_change: SnsCanisterType,
    ) {
        try_upgrade_sns_to_next_version(pocket_ic, sns, expected_type_to_change)
            .await
            .unwrap_or_else(|err| panic!("Upgrading {expected_type_to_change:?} failed: {err:#?}"));
    }

    pub mod governance {
        use super::*;
        use assert_matches::assert_matches;
        use ic_crypto_sha2::Sha256;
        use ic_nervous_system_agent::{
            helpers::sns::SnsProposalError, sns::governance::GovernanceCanister,
        };
        use ic_sns_governance_api::pb::v1::{
            GetUpgradeJournalRequest, Neuron, get_neuron_response,
            neuron::DissolveState,
            upgrade_journal_entry::{self, Event},
        };
        use sns_pb::UpgradeSnsControlledCanister;

        pub const EXPECTED_UPGRADE_DURATION_MAX_SECONDS: u64 = 1000;
        pub const EXPECTED_UPGRADE_STEPS_REFRESH_MAX_SECONDS: u64 =
            UPGRADE_STEPS_INTERVAL_REFRESH_BACKOFF_SECONDS + 10;

        pub fn redact_human_readable(event: Event) -> Event {
            match event {
                Event::UpgradeOutcome(upgrade_outcome) => {
                    Event::UpgradeOutcome(upgrade_journal_entry::UpgradeOutcome {
                        human_readable: None,
                        ..upgrade_outcome
                    })
                }
                Event::UpgradeStepsReset(upgrade_steps_reset) => {
                    Event::UpgradeStepsReset(upgrade_journal_entry::UpgradeStepsReset {
                        human_readable: None,
                        ..upgrade_steps_reset
                    })
                }
                Event::TargetVersionReset(target_version_reset) => {
                    Event::TargetVersionReset(upgrade_journal_entry::TargetVersionReset {
                        human_readable: None,
                        ..target_version_reset
                    })
                }
                event => event,
            }
        }

        /// Manage an SNS neuron, e.g., to make an SNS Governance proposal.
        async fn manage_neuron(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            // subaccount: &[u8],
            neuron_id: sns_pb::NeuronId,
            command: sns_pb::manage_neuron::Command,
        ) -> sns_pb::ManageNeuronResponse {
            let agent = PocketIcAgent::new(pocket_ic, sender);
            let sns_governance_canister = GovernanceCanister::new(canister_id);
            sns_governance_canister
                .manage_neuron(&agent, neuron_id, command)
                .await
                .unwrap()
        }

        pub async fn start_dissolving_neuron(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            neuron_id: sns_pb::NeuronId,
        ) -> sns_pb::ManageNeuronResponse {
            let command =
                sns_pb::manage_neuron::Command::Configure(sns_pb::manage_neuron::Configure {
                    operation: Some(
                        sns_pb::manage_neuron::configure::Operation::StartDissolving(
                            sns_pb::manage_neuron::StartDissolving {},
                        ),
                    ),
                });
            manage_neuron(pocket_ic, canister_id, sender, neuron_id, command).await
        }

        pub async fn propose_and_wait(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            neuron_id: sns_pb::NeuronId,
            proposal: sns_pb::Proposal,
        ) -> Result<sns_pb::ProposalData, SnsProposalError> {
            let agent = PocketIcAgent::new(pocket_ic, sender);
            let sns_governance_canister = GovernanceCanister::new(canister_id);
            sns_agent_helpers::propose_and_wait(
                &agent,
                neuron_id,
                sns_governance_canister,
                proposal,
            )
            .await
        }

        /// This function assumes that the proposal submission succeeded (and panics otherwise).
        pub async fn wait_for_proposal_execution(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            proposal_id: sns_pb::ProposalId,
        ) -> Result<sns_pb::ProposalData, SnsProposalError> {
            let canister = GovernanceCanister::new(canister_id);
            sns_agent_helpers::wait_for_proposal_execution(pocket_ic, canister, proposal_id).await
        }

        pub async fn get_proposal(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            proposal_id: sns_pb::ProposalId,
            sender: PrincipalId,
        ) -> Result<sns_pb::GetProposalResponse, RejectResponse> {
            let agent = PocketIcAgent::new(pocket_ic, sender);
            let canister = GovernanceCanister::new(canister_id);
            canister
                .get_proposal(&agent, proposal_id)
                .await
                .map_err(|err| match err {
                    PocketIcCallError::PocketIc(reject_response) => reject_response,
                    err => panic!("Unexpected error when getting proposal info: {err:#?}"),
                })
        }

        pub async fn list_neurons(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
        ) -> sns_pb::ListNeuronsResponse {
            GovernanceCanister::new(canister_id)
                .list_neurons(pocket_ic, sns_pb::ListNeurons::default())
                .await
                .unwrap()
        }

        pub fn dissolve_delay_seconds(neuron: &Neuron, now_seconds: u64) -> u64 {
            match neuron.dissolve_state {
                Some(DissolveState::DissolveDelaySeconds(d)) => d,
                Some(DissolveState::WhenDissolvedTimestampSeconds(ts)) => {
                    ts.saturating_sub(now_seconds)
                }
                None => 0,
            }
        }

        /// Searches for the ID and controller principal of an SNS neuron that can submit proposals,
        /// i.e., a neuron whose `dissolve_delay_seconds` is greater that or equal 6 months.
        pub async fn find_neuron_with_majority_voting_power(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
        ) -> Option<(sns_pb::NeuronId, PrincipalId)> {
            let sns_neurons = list_neurons(pocket_ic, canister_id).await.neurons;
            sns_neurons
                .iter()
                .find(|neuron| {
                    dissolve_delay_seconds(neuron, neuron.created_timestamp_seconds)
                        >= 6 * 30 * ONE_DAY_SECONDS
                })
                .map(|sns_neuron| {
                    (
                        sns_neuron.id.clone().unwrap(),
                        sns_neuron.permissions.last().unwrap().principal.unwrap(),
                    )
                })
        }

        /// Returns the neuron ID of the first neuron that is distinct from `neuron_id` or `None`.
        pub async fn find_another_neuron(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            neuron_id: sns_pb::NeuronId,
        ) -> Option<sns_pb::NeuronId> {
            let sns_neurons = list_neurons(pocket_ic, canister_id).await.neurons;
            sns_neurons
                .into_iter()
                .filter_map(|Neuron { id, .. }| {
                    let this_neuron_id = id.unwrap();

                    if this_neuron_id != neuron_id {
                        return Some(this_neuron_id);
                    }

                    None
                })
                .next()
        }

        /// This function is a wrapper around `GovernanceCanister::get_nervous_system_parameters`, kept here for convenience.
        pub async fn get_nervous_system_parameters(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
        ) -> sns_pb::NervousSystemParameters {
            GovernanceCanister { canister_id }
                .get_nervous_system_parameters(pocket_ic)
                .await
                .unwrap()
        }

        pub async fn propose_to_advance_sns_target_version(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
        ) -> Result<sns_pb::ProposalData, String> {
            // Get an ID of an SNS neuron that can submit proposals. We rely on the fact that this
            // neuron either holds the majority of the voting power or the follow graph is set up
            // s.t. when this neuron submits a proposal, that proposal gets through without the need
            // for any voting.
            let (sns_neuron_id, sns_neuron_principal_id) =
                sns::governance::find_neuron_with_majority_voting_power(
                    pocket_ic,
                    sns_governance_canister_id,
                )
                .await
                .expect("cannot find SNS neuron with dissolve delay over 6 months.");

            sns::governance::propose_and_wait(
                pocket_ic,
                sns_governance_canister_id,
                sns_neuron_principal_id,
                sns_neuron_id.clone(),
                sns_pb::Proposal {
                    title: "Advance SNS target version.".to_string(),
                    summary: "".to_string(),
                    url: "".to_string(),
                    action: Some(sns_pb::proposal::Action::AdvanceSnsTargetVersion(
                        sns_pb::AdvanceSnsTargetVersion { new_target: None },
                    )),
                },
            )
            .await
            .map_err(|err| format!("{err:?}"))
        }

        /// Tries to assign the `automatically_advance_target_version` flag in the SNS specified
        /// by `sns_governance_canister_id`.
        ///
        /// Works by using a super powerful neuron to make a proposal. This assumes that such
        /// a neuron exists. Then, this waits for the proposal to execute successfully
        /// before returning.
        pub async fn set_automatically_advance_target_version_flag(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
            automatically_advance_target_version: bool,
        ) -> Result<sns_pb::ProposalData, String> {
            // Get an ID of an SNS neuron that can submit proposals. We rely on the fact that this
            // neuron either holds the majority of the voting power or the follow graph is set up
            // s.t. when this neuron submits a proposal, that proposal gets through without the need
            // for any voting.
            let (sns_neuron_id, sns_neuron_principal_id) =
                sns::governance::find_neuron_with_majority_voting_power(
                    pocket_ic,
                    sns_governance_canister_id,
                )
                .await
                .expect("cannot find SNS neuron with dissolve delay over 6 months.");

            sns::governance::propose_and_wait(
                pocket_ic,
                sns_governance_canister_id,
                sns_neuron_principal_id,
                sns_neuron_id.clone(),
                sns_pb::Proposal {
                    title: format!(
                        "Set automatically_advance_target_version to {automatically_advance_target_version}.",
                    ),
                    summary: "".to_string(),
                    url: "".to_string(),
                    action: Some(sns_pb::proposal::Action::ManageNervousSystemParameters(
                        sns_pb::NervousSystemParameters {
                            automatically_advance_target_version: Some(
                                automatically_advance_target_version,
                            ),
                            ..Default::default()
                        },
                    )),
                },
            )
            .await
            .map_err(|err| format!("{err:?}"))
        }

        // Upgrade; one canister at a time.
        pub async fn propose_to_upgrade_sns_to_next_version_and_wait(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
        ) {
            // Get an ID of an SNS neuron that can submit proposals. We rely on the fact that this
            // neuron either holds the majority of the voting power or the follow graph is set up
            // s.t. when this neuron submits a proposal, that proposal gets through without the need
            // for any voting.
            let (sns_neuron_id, sns_neuron_principal_id) =
                find_neuron_with_majority_voting_power(pocket_ic, sns_governance_canister_id)
                    .await
                    .expect("cannot find SNS neuron with dissolve delay over 6 months.");

            let proposal_data = propose_and_wait(
                pocket_ic,
                sns_governance_canister_id,
                sns_neuron_principal_id,
                sns_neuron_id.clone(),
                sns_pb::Proposal {
                    title: "Upgrade to the next SNS version.".to_string(),
                    summary: "".to_string(),
                    url: "".to_string(),
                    action: Some(sns_pb::proposal::Action::UpgradeSnsToNextVersion(
                        sns_pb::UpgradeSnsToNextVersion {},
                    )),
                },
            )
            .await
            .unwrap();

            // Check 1: The upgrade proposal did not fail.
            assert_eq!(proposal_data.failure_reason, None);

            // Check 2: The upgrade proposal succeeded.
            assert!(proposal_data.executed_timestamp_seconds > 0);
        }

        pub async fn propose_to_upgrade_sns_controlled_canister_and_wait(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
            upgrade: UpgradeSnsControlledCanister,
        ) {
            // Get an ID of an SNS neuron that can submit proposals. We rely on the fact that this
            // neuron either holds the majority of the voting power or the follow graph is set up
            // s.t. when this neuron submits a proposal, that proposal gets through without the need
            // for any voting.
            let (sns_neuron_id, sns_neuron_principal_id) =
                find_neuron_with_majority_voting_power(pocket_ic, sns_governance_canister_id)
                    .await
                    .expect("cannot find SNS neuron with dissolve delay over 6 months.");

            let proposal_data = propose_and_wait(
                pocket_ic,
                sns_governance_canister_id,
                sns_neuron_principal_id,
                sns_neuron_id.clone(),
                sns_pb::Proposal {
                    title: "Upgrade SNS controlled canister.".to_string(),
                    summary: "".to_string(),
                    url: "".to_string(),
                    action: Some(sns_pb::proposal::Action::UpgradeSnsControlledCanister(
                        upgrade,
                    )),
                },
            )
            .await
            .unwrap();

            // Check 1: The upgrade proposal did not fail.
            assert_eq!(proposal_data.failure_reason, None);

            // Check 2: The upgrade proposal succeeded.
            assert!(proposal_data.executed_timestamp_seconds > 0);
        }

        /// Get the neuron with the given ID from the SNS Governance canister.
        #[allow(dead_code)]
        async fn get_neuron(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
            neuron_id: sns_pb::NeuronId,
        ) -> Result<sns_pb::Neuron, sns_pb::GovernanceError> {
            let canister = GovernanceCanister::new(sns_governance_canister_id);
            let response = canister.get_neuron(pocket_ic, neuron_id).await.unwrap();
            match response.result.expect("No result in response") {
                get_neuron_response::Result::Error(e) => Err(e),
                get_neuron_response::Result::Neuron(neuron) => Ok(neuron),
            }
        }

        pub fn new_sns_neuron_id(principal: PrincipalId, nonce: u64) -> sns_pb::NeuronId {
            let subaccount = {
                let mut state = Sha256::new();
                state.write(&[0x0c]);
                state.write(b"neuron-stake");
                state.write(principal.as_slice());
                state.write(&nonce.to_be_bytes());
                state.finish()
            };

            sns_pb::NeuronId {
                id: subaccount.to_vec(),
            }
        }

        pub async fn try_get_upgrade_journal(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
        ) -> std::result::Result<sns_pb::GetUpgradeJournalResponse, PocketIcCallError> {
            let canister = GovernanceCanister::new(sns_governance_canister_id);
            canister
                .get_upgrade_journal(pocket_ic, GetUpgradeJournalRequest::default())
                .await
        }

        pub async fn get_upgrade_journal(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
        ) -> sns_pb::GetUpgradeJournalResponse {
            try_get_upgrade_journal(pocket_ic, canister_id)
                .await
                .unwrap()
        }

        pub async fn advance_target_version(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
            target_version: Version,
        ) -> AdvanceTargetVersionResponse {
            let canister = GovernanceCanister::new(sns_governance_canister_id);
            canister
                .advance_target_version(pocket_ic, target_version)
                .await
                .unwrap()
        }

        /// Verifies that the upgrade journal has the expected entries.
        pub async fn assert_upgrade_journal(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
            expected_entries: &[sns_pb::upgrade_journal_entry::Event],
        ) {
            let response =
                sns::governance::get_upgrade_journal(pocket_ic, sns_governance_canister_id).await;

            let journal_entries = assert_matches!(
                response,
                sns_pb::GetUpgradeJournalResponse {
                    upgrade_journal: Some(sns_pb::UpgradeJournal {
                        entries,
                        ..
                    }),
                    ..
                } => entries
            );

            for (index, either_or_both) in journal_entries
                .iter()
                .zip_longest(expected_entries.iter())
                .enumerate()
            {
                let (actual, expected) = match either_or_both {
                    EitherOrBoth::Both(actual, expected) => (actual, expected),
                    EitherOrBoth::Left(actual) => {
                        panic!("Observed an unexpected journal entry at index {index}: {actual:?}")
                    }
                    EitherOrBoth::Right(expected) => {
                        panic!("Did not observe an expected entry at index {index}: {expected:?}")
                    }
                };
                assert!(actual.timestamp_seconds.is_some());
                assert_eq!(
                    &actual.event.clone().map(redact_human_readable),
                    &Some(redact_human_readable(expected.clone())),
                    "Upgrade journal entry at index {index} does not match"
                );
            }
        }

        pub async fn set_following(
            pocket_ic: &PocketIc,
            sns_governance_canister_id: PrincipalId,
            sender: PrincipalId,
            neuron_id: sns_pb::NeuronId,
            set_following: sns_pb::manage_neuron::SetFollowing,
        ) -> Result<sns_pb::ManageNeuronResponse, RejectResponse> {
            let agent = PocketIcAgent::new(pocket_ic, sender);
            let sns_governance_canister = GovernanceCanister::new(sns_governance_canister_id);
            sns_governance_canister
                .set_following(&agent, neuron_id, set_following)
                .await
                .map_err(|err| match err {
                    PocketIcCallError::PocketIc(reject_response) => reject_response,
                    err => panic!("Unexpected error when setting following: {err:#?}"),
                })
        }
    }

    pub mod index_ng {
        use candid::{CandidType, Deserialize};

        use ic_icrc1_index_ng::GetBlocksResponse;
        use icrc_ledger_types::{icrc1::transfer::BlockIndex, icrc3::blocks::GetBlocksRequest};

        use super::*;

        /// Copied from rs/ledger_suite/icrc1/index-ng/src/lib.rs
        #[derive(Eq, PartialEq, Debug, CandidType, Deserialize)]
        pub struct Status {
            pub num_blocks_synced: BlockIndex,
        }

        pub async fn ledger_id(pocket_ic: &PocketIc, canister_id: PrincipalId) -> PrincipalId {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "ledger_id",
                    Encode!().unwrap(),
                )
                .await
                .unwrap();
            Decode!(&result, PrincipalId).unwrap()
        }

        pub async fn status(pocket_ic: &PocketIc, canister_id: PrincipalId) -> Status {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "status",
                    Encode!().unwrap(),
                )
                .await
                .unwrap();
            Decode!(&result, Status).unwrap()
        }

        pub async fn get_blocks<I>(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            start: I,
            length: I,
        ) -> GetBlocksResponse
        where
            I: Into<Nat>,
        {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "get_blocks",
                    Encode!(&GetBlocksRequest {
                        start: start.into(),
                        length: length.into(),
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
            Decode!(&result, GetBlocksResponse).unwrap()
        }

        // Retrieves blocks from the Ledger and the Archives.
        pub async fn get_all_blocks(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            start: u64,
            length: u64,
        ) -> GetBlocksResponse {
            let res = get_blocks(pocket_ic, canister_id, 0_u64, 0_u64).await;
            let length = length.min(res.chain_length);
            let mut blocks: Vec<_> = vec![];
            let mut curr_start = start;
            while length > blocks.len() as u64 {
                let new_blocks = get_blocks(
                    pocket_ic,
                    canister_id,
                    curr_start,
                    length - (curr_start - start),
                )
                .await
                .blocks;
                assert!(!new_blocks.is_empty());
                curr_start += new_blocks.len() as u64;
                blocks.extend(new_blocks);
            }
            GetBlocksResponse { blocks, ..res }
        }
    }

    pub mod ledger {
        use std::collections::BTreeSet;

        use ic_sns_root::ArchiveInfo;
        use icrc_ledger_types::{
            icrc2::{
                allowance::{Allowance, AllowanceArgs},
                approve::{ApproveArgs, ApproveError},
                transfer_from::{TransferFromArgs, TransferFromError},
            },
            icrc3::blocks::{GetBlocksRequest, GetBlocksResponse},
        };

        use super::*;

        pub async fn icrc1_total_supply(pocket_ic: &PocketIc, canister_id: PrincipalId) -> Nat {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "icrc1_total_supply",
                    Encode!().unwrap(),
                )
                .await
                .unwrap();
            Decode!(&result, Nat).unwrap()
        }

        pub async fn icrc1_balance_of(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            account: Account,
        ) -> Nat {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "icrc1_balance_of",
                    Encode!(&account).unwrap(),
                )
                .await
                .unwrap();
            Decode!(&result, Nat).unwrap()
        }

        pub async fn icrc1_transfer_request(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            transfer_arg: TransferArg,
        ) -> pocket_ic::common::rest::RawMessageId {
            pocket_ic
                .submit_call(
                    canister_id.into(),
                    Principal::from(sender),
                    "icrc1_transfer",
                    Encode!(&transfer_arg).unwrap(),
                )
                .await
                .unwrap()
        }

        pub async fn icrc1_transfer(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            transfer_arg: TransferArg,
        ) -> Result<Nat, TransferError> {
            let call_id =
                icrc1_transfer_request(pocket_ic, canister_id, sender, transfer_arg).await;
            let result = pocket_ic.await_call(call_id).await.unwrap();
            Decode!(&result, Result<Nat, TransferError>).unwrap()
        }

        pub async fn get_blocks<I>(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            start: I,
            length: I,
        ) -> GetBlocksResponse
        where
            I: Into<Nat>,
        {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "get_blocks",
                    Encode!(&GetBlocksRequest {
                        start: start.into(),
                        length: length.into(),
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
            Decode!(&result, GetBlocksResponse).unwrap()
        }

        // Retrieves blocks from the Ledger and the Archives.
        pub async fn get_all_blocks(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            start: u64,
            length: u64,
        ) -> GetBlocksResponse {
            let res = get_blocks(pocket_ic, canister_id, start, length).await;
            let mut blocks = vec![];
            for archived in &res.archived_blocks {
                let archive_canister_id =
                    archived.callback.canister_id.as_ref().try_into().unwrap();
                // Archives paginate their results. We need to fetch all the blocks and
                // therefore we loop until all of them have been fetched.
                let mut curr_start = archived.start.clone();
                while curr_start < archived.length {
                    let block_range = archive::get_blocks(
                        pocket_ic,
                        archive_canister_id,
                        curr_start.clone(),
                        archived.length.clone() - (curr_start.clone() - archived.start.clone()),
                    )
                    .await;
                    assert!(!block_range.blocks.is_empty());
                    curr_start += block_range.blocks.len();
                    blocks.extend(block_range.blocks);
                }
            }
            blocks.extend(res.blocks);
            GetBlocksResponse { blocks, ..res }
        }

        pub async fn check_blocks_or_panic(
            pocket_ic: &PocketIc,
            sns_ledger_canister_id: PrincipalId,
        ) {
            let all_blocks: BTreeSet<_> =
                get_all_blocks(pocket_ic, sns_ledger_canister_id, 0, u64::MAX)
                    .await
                    .blocks
                    .into_iter()
                    .collect();
            let non_archived_blocks: BTreeSet<_> = {
                let response = get_blocks(pocket_ic, sns_ledger_canister_id, 0, u64::MAX).await;
                response.blocks.into_iter().collect()
            };
            assert!(non_archived_blocks.is_subset(&all_blocks));
            assert!(
                !all_blocks.is_empty(),
                "There should be some blocks.\n\
                all_blocks = {all_blocks:?}\n\
                non_archived_blocks = {non_archived_blocks:?}"
            );
            assert!(
                !non_archived_blocks.is_empty(),
                "Some blocks should not be archived.\n\
                all_blocks = {all_blocks:?}\n\
                non_archived_blocks = {non_archived_blocks:?}"
            );
            assert!(
                non_archived_blocks.len() < all_blocks.len(),
                "Some blocks should be archived.\n\
                all_blocks = {all_blocks:?}\n\
                non_archived_blocks = {non_archived_blocks:?}"
            );
        }

        pub async fn archives(pocket_ic: &PocketIc, canister_id: PrincipalId) -> Vec<ArchiveInfo> {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "archives",
                    Encode!().unwrap(),
                )
                .await
                .unwrap();
            Decode!(&result, Vec<ArchiveInfo>).unwrap()
        }

        pub async fn icrc2_approve(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            arg: ApproveArgs,
        ) -> Result<Nat, ApproveError> {
            let result = pocket_ic
                .update_call(
                    canister_id.into(),
                    Principal::from(sender),
                    "icrc2_approve",
                    Encode!(&arg).unwrap(),
                )
                .await
                .unwrap();
            Decode!(&result, Result<Nat, ApproveError>).unwrap()
        }

        pub async fn icrc2_allowance(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            arg: AllowanceArgs,
        ) -> Allowance {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::from(sender),
                    "icrc2_allowance",
                    Encode!(&arg).unwrap(),
                )
                .await
                .unwrap();
            Decode!(&result, Allowance).unwrap()
        }

        pub async fn icrc2_transfer_from(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            sender: PrincipalId,
            arg: TransferFromArgs,
        ) -> Result<Nat, TransferFromError> {
            let result = pocket_ic
                .update_call(
                    canister_id.into(),
                    Principal::from(sender),
                    "icrc2_transfer_from",
                    Encode!(&arg).unwrap(),
                )
                .await
                .unwrap();
            Decode!(&result, Result<Nat, TransferFromError>).unwrap()
        }
    }

    pub mod archive {
        use icrc_ledger_types::icrc3::{blocks::BlockRange, transactions::GetTransactionsRequest};

        use super::*;

        pub async fn get_blocks<I>(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
            start: I,
            length: I,
        ) -> BlockRange
        where
            I: Into<Nat>,
        {
            let result = pocket_ic
                .query_call(
                    canister_id.into(),
                    Principal::anonymous(),
                    "get_blocks",
                    Encode!(&GetTransactionsRequest {
                        start: start.into(),
                        length: length.into(),
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
            Decode!(&result, BlockRange).unwrap()
        }
    }

    // Try to spawn one Archive canister by creating a bunch of ICRC1 minting transactions.
    //
    // Panics is this cannot be accomplished.
    //
    // Returns the principal ID of the first Archive canister.
    pub async fn ensure_archive_canister_is_spawned_or_panic(
        pocket_ic: &PocketIc,
        sns_governance_canister_id: PrincipalId,
        sns_ledger_canister_id: PrincipalId,
    ) -> PrincipalId {
        // We assume that this number of transactions are needed,
        // which currently cannot be configured via proposals and is thus hard coded.
        const NUM_TRANSACTIONS_NEEDED_TO_SPAWN_FIRST_ARCHIVE: u64 = 2000;

        // Generate a bunch of SNS token transactions.
        // Sending all the requests, then awaiting all the responses, is much faster than sending each request in
        // serial.
        let transfer_requests = stream::iter(0..NUM_TRANSACTIONS_NEEDED_TO_SPAWN_FIRST_ARCHIVE)
            .map(|i| {
                async move {
                    let user_principal_id = PrincipalId::new_user_test_id(i);
                    let direct_participant_swap_account = Account {
                        owner: user_principal_id.0,
                        subaccount: None,
                    };
                    ledger::icrc1_transfer_request(
                        pocket_ic,
                        sns_ledger_canister_id,
                        sns_governance_canister_id,
                        TransferArg {
                            from_subaccount: None,
                            to: direct_participant_swap_account,
                            fee: None,
                            created_at_time: None,
                            memo: None,
                            amount: Nat::from(100_000_u64), // mint an arbitrary amount of SNS tokens
                        },
                    )
                    .await
                }
            })
            .buffer_unordered(100)
            .collect::<Vec<_>>()
            .await;
        let _transfer_responses = stream::iter(transfer_requests)
            .map(|call_id| async move { pocket_ic.await_call(call_id).await.unwrap() })
            .buffer_unordered(100)
            .collect::<Vec<_>>()
            .await;

        let mut archives = ledger::archives(pocket_ic, sns_ledger_canister_id).await;

        let Some(archive) = archives.pop() else {
            panic!("Failed to spawn an Archive canister.")
        };

        PrincipalId::from(archive.canister_id)
    }

    pub mod root {
        use super::*;
        use ic_sns_root::{GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse};

        pub async fn get_sns_canisters_summary(
            pocket_ic: &PocketIc,
            sns_root_canister_id: PrincipalId,
        ) -> GetSnsCanistersSummaryResponse {
            let result = pocket_ic
                .update_call(
                    sns_root_canister_id.into(),
                    Principal::anonymous(),
                    "get_sns_canisters_summary",
                    Encode!(&GetSnsCanistersSummaryRequest {
                        update_canister_list: Some(false),
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
            Decode!(&result, GetSnsCanistersSummaryResponse).unwrap()
        }
    }

    // Helper function that progress the blockchain until either the index canister has synced all
    // the blocks up to the last one in the ledger or enough attempts passed and therefore it fails.
    pub async fn wait_until_ledger_and_index_sync_is_completed(
        pocket_ic: &PocketIc,
        ledger_canister_id: PrincipalId,
        index_canister_id: PrincipalId,
    ) {
        const MAX_ATTEMPTS: u8 = 100; // No reason for this number.
        let mut num_blocks_synced = u64::MAX;
        let mut chain_length = u64::MAX;
        for _i in 0..MAX_ATTEMPTS {
            pocket_ic.progress(Duration::from_secs(1)).await;
            num_blocks_synced = index_ng::status(pocket_ic, index_canister_id)
                .await
                .num_blocks_synced
                .0
                .to_u64()
                .unwrap();
            chain_length = ledger::get_blocks(pocket_ic, ledger_canister_id, 0_u64, 1_u64)
                .await
                .chain_length;
            if num_blocks_synced == chain_length {
                return;
            }
        }
        panic!(
            "The index canister was unable to sync all the blocks with the ledger. Number of \
            blocks synced {num_blocks_synced} but the Ledger chain length is {chain_length}.\n",
        );
    }

    // Assert that the index canister contains the same blocks as the ledger.
    pub async fn assert_ledger_index_parity(
        pocket_ic: &PocketIc,
        ledger_canister_id: PrincipalId,
        index_canister_id: PrincipalId,
    ) {
        use ic_icrc1::{Block, blocks::generic_block_to_encoded_block};
        use ic_icrc1_tokens_u64::U64;
        use ic_ledger_core::block::BlockType;
        use icrc_ledger_types::icrc::generic_value::Value;

        let ledger_blocks = ledger::get_all_blocks(pocket_ic, ledger_canister_id, 0, u64::MAX)
            .await
            .blocks;
        let index_blocks = index_ng::get_all_blocks(pocket_ic, index_canister_id, 0, u64::MAX)
            .await
            .blocks;
        assert_eq!(ledger_blocks.len(), index_blocks.len());

        fn convert_to_std_format(x: Value) -> Value {
            match x {
                Value::Int(x) => {
                    assert!(x >= 0, "cannot conver negative value {x:?} to Nat64");
                    Value::Nat(x.0.to_biguint().unwrap().into())
                }
                Value::Nat64(x) => Value::Nat(x.into()),
                Value::Map(map) => Value::Map(
                    map.into_iter()
                        .map(|(key, value)| {
                            let value = convert_to_std_format(value);
                            (key, value)
                        })
                        .collect(),
                ),
                Value::Array(array) => {
                    Value::Array(array.into_iter().map(convert_to_std_format).collect())
                }
                _ => x,
            }
        }

        for idx in 0..ledger_blocks.len() {
            let generic_block_ledger = ledger_blocks[idx].clone();
            let generic_block_index = index_blocks[idx].clone();

            // TODO: Remove this conversion after the next ICRC1 Ledger upgrade.
            let generic_block_ledger = convert_to_std_format(generic_block_ledger);
            let generic_block_index = convert_to_std_format(generic_block_index);

            let encoded_block_ledger =
                generic_block_to_encoded_block(generic_block_ledger.clone()).unwrap();
            let encoded_block_index =
                generic_block_to_encoded_block(generic_block_index.clone()).unwrap();
            let block_ledger = Block::<U64>::decode(encoded_block_ledger.clone()).unwrap();
            let block_index = Block::<U64>::decode(encoded_block_index.clone()).unwrap();

            assert_eq!(
                generic_block_ledger, generic_block_index,
                "block_index: {idx}"
            );
            assert_eq!(generic_block_ledger, generic_block_index);
            assert_eq!(encoded_block_ledger, encoded_block_index);
            assert_eq!(block_ledger, block_index);
        }
    }

    pub mod swap {
        use super::*;
        use ic_nervous_system_agent::sns::swap::SwapCanister;
        use ic_nns_governance_api::create_service_nervous_system::SwapParameters;
        use ic_sns_swap::pb::v1::{GetOpenTicketResponse, SnsNeuronRecipe};
        use icp_ledger::DEFAULT_TRANSFER_FEE;

        pub async fn get_init(pocket_ic: &PocketIc, canister_id: PrincipalId) -> GetInitResponse {
            let canister = SwapCanister::new(canister_id);
            canister.get_init(pocket_ic).await.unwrap()
        }

        pub async fn list_sns_neuron_recipes(
            pocket_ic: &PocketIc,
            canister_id: PrincipalId,
        ) -> Vec<SnsNeuronRecipe> {
            let canister = SwapCanister::new(canister_id);
            canister
                .list_all_sns_neuron_recipes(pocket_ic)
                .await
                .unwrap()
        }

        pub async fn new_sale_ticket(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
            buyer: PrincipalId,
            amount_icp_e8s: u64,
        ) -> Result<NewSaleTicketResponse, String> {
            let agent = PocketIcAgent::new(pocket_ic, buyer);
            let canister = SwapCanister::new(swap_canister_id);
            canister
                .new_sale_ticket(&agent, amount_icp_e8s, None)
                .await
                .map_err(|err| err.to_string())
        }

        pub async fn refresh_buyer_tokens(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
            buyer: PrincipalId,
            confirmation_text: Option<String>,
        ) -> Result<RefreshBuyerTokensResponse, String> {
            let agent = PocketIcAgent::new(pocket_ic, buyer);
            let canister = SwapCanister::new(swap_canister_id);
            canister
                .refresh_buyer_tokens(&agent, buyer, confirmation_text)
                .await
                .map_err(|err| err.to_string())
        }

        pub async fn get_buyer_state(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
            buyer: PrincipalId,
        ) -> Result<GetBuyerStateResponse, String> {
            let canister = SwapCanister::new(swap_canister_id);
            canister
                .get_buyer_state(pocket_ic, buyer)
                .await
                .map_err(|err| err.to_string())
        }

        pub async fn get_open_ticket(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
            buyer: PrincipalId,
        ) -> Result<GetOpenTicketResponse, String> {
            let agent = PocketIcAgent::new(pocket_ic, buyer);
            let canister = SwapCanister::new(swap_canister_id);
            canister
                .get_open_ticket(&agent)
                .await
                .map_err(|err| err.to_string())
        }

        pub async fn error_refund_icp(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
            source_principal_id: PrincipalId,
        ) -> ErrorRefundIcpResponse {
            let canister = SwapCanister::new(swap_canister_id);
            canister
                .error_refund_icp(pocket_ic, source_principal_id)
                .await
                .unwrap()
        }

        pub async fn get_derived_state(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
        ) -> GetDerivedStateResponse {
            let canister = SwapCanister::new(swap_canister_id);
            canister.get_derived_state(pocket_ic).await.unwrap()
        }

        pub async fn get_lifecycle(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
        ) -> GetLifecycleResponse {
            let canister = SwapCanister::new(swap_canister_id);
            canister.get_lifecycle(pocket_ic).await.unwrap()
        }

        pub async fn await_swap_lifecycle(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
            expected_lifecycle: Lifecycle,
        ) -> Result<(), String> {
            let canister = SwapCanister::new(swap_canister_id);
            sns_agent_helpers::await_swap_lifecycle(pocket_ic, canister, expected_lifecycle, false)
                .await
        }

        /// Returns:
        /// * `Ok(None)` if any of the top-level fields of this `auto_finalization_status` are unset, i.e.:
        ///   `has_auto_finalize_been_attempted`, `is_auto_finalize_enabled`,
        ///   or `auto_finalize_swap_response`.
        /// * `Err` if `auto_finalize_swap_response` contains any errors.
        /// * `Ok(Some(response))` -- otherwise.
        pub fn validate_auto_finalization_status(
            auto_finalization_status: &GetAutoFinalizationStatusResponse,
        ) -> Result<Option<&FinalizeSwapResponse>, String> {
            if auto_finalization_status
                .has_auto_finalize_been_attempted
                .is_none()
                || auto_finalization_status.is_auto_finalize_enabled.is_none()
            {
                return Ok(None);
            }
            let Some(ref auto_finalize_swap_response) =
                auto_finalization_status.auto_finalize_swap_response
            else {
                return Ok(None);
            };
            if let Some(ref error_message) = auto_finalize_swap_response.error_message {
                // If auto_finalization_status contains an error, we return that error.
                return Err(error_message.clone());
            }
            Ok(Some(auto_finalize_swap_response))
        }

        /// Returns:
        /// * `Ok(true)` if auto-finalization completed, reaching `Lifecycle::Committed`.
        /// * `Ok(false)` if auto-finalization is still happening (or swap lifecycle reached a final state
        ///   other than Committed), i.e., one of the following conditions holds:
        ///     1. Any of the top-level fields of this `auto_finalization_status` are unset:
        ///        `has_auto_finalize_been_attempted`, `is_auto_finalize_enabled`,
        ///        or `auto_finalize_swap_response`.
        ///     2. `auto_finalize_swap_response` does not match the expected pattern for a *committed* SNS
        ///        Swap's `auto_finalize_swap_response`. In particular:
        ///        - `set_dapp_controllers_call_result` must be `Some`
        ///        - `sweep_sns_result` must be `Some`.
        /// * `Err` if `auto_finalize_swap_response` contains any errors.
        pub fn is_auto_finalization_status_committed_or_err(
            auto_finalization_status: &GetAutoFinalizationStatusResponse,
        ) -> Result<bool, String> {
            let Some(auto_finalize_swap_response) =
                validate_auto_finalization_status(auto_finalization_status)?
            else {
                return Ok(false);
            };
            // Otherwise, either `auto_finalization_status` matches the expected structure of it does not
            // indicate that the swap has been committed yet.
            Ok(matches!(
                auto_finalize_swap_response,
                FinalizeSwapResponse {
                    sweep_icp_result: Some(_),
                    create_sns_neuron_recipes_result: Some(_),
                    settle_neurons_fund_participation_result: Some(_),
                    sweep_sns_result: Some(_),
                    claim_neuron_result: Some(_),
                    set_mode_call_result: Some(_),
                    set_dapp_controllers_call_result: Some(_),
                    settle_community_fund_participation_result: None,
                    error_message: None,
                }
            ))
        }

        /// Returns:
        /// * `Ok(true)` if auto-finalization completed, reaching `Lifecycle::Aborted`.
        /// * `Ok(false)` if auto-finalization is still happening (or swap lifecycle reached a final state
        ///   other than Aborted), i.e., one of the following conditions holds:
        ///     1. Any of the top-level fields of this `auto_finalization_status` are unset:
        ///        `has_auto_finalize_been_attempted`, `is_auto_finalize_enabled`,
        ///        or `auto_finalize_swap_response`.
        ///     2. `auto_finalize_swap_response` does not match the expected pattern for an *aborted* SNS
        ///        Swap's `auto_finalize_swap_response`. In particular:
        ///        - `set_dapp_controllers_call_result` must be `Some`,
        ///        - `sweep_sns_result` must be `None`.
        /// * `Err` if `auto_finalize_swap_response` contains any errors.
        pub fn is_auto_finalization_status_aborted_or_err(
            auto_finalization_status: &GetAutoFinalizationStatusResponse,
        ) -> Result<bool, String> {
            let Some(auto_finalize_swap_response) =
                validate_auto_finalization_status(auto_finalization_status)?
            else {
                return Ok(false);
            };
            // Otherwise, either `auto_finalization_status` matches the expected structure of it does not
            // indicate that the swap has been aborted yet.
            Ok(matches!(
                auto_finalize_swap_response,
                FinalizeSwapResponse {
                    sweep_icp_result: Some(_),
                    set_dapp_controllers_call_result: Some(_),
                    settle_neurons_fund_participation_result: Some(_),
                    create_sns_neuron_recipes_result: None,
                    sweep_sns_result: None,
                    claim_neuron_result: None,
                    set_mode_call_result: None,
                    settle_community_fund_participation_result: None,
                    error_message: None,
                }
            ))
        }

        pub async fn finalize_swap(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
        ) -> FinalizeSwapResponse {
            let canister = SwapCanister::new(swap_canister_id);
            canister.finalize_swap(pocket_ic).await.unwrap()
        }

        pub async fn get_auto_finalization_status(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
        ) -> GetAutoFinalizationStatusResponse {
            let canister = SwapCanister::new(swap_canister_id);
            canister
                .get_auto_finalization_status(pocket_ic)
                .await
                .unwrap()
        }

        /// Subset of `Lifecycle` indicating terminal statuses.
        #[derive(Copy, Clone, Eq, PartialEq, Debug)]
        pub enum SwapFinalizationStatus {
            Aborted,
            Committed,
        }

        pub async fn await_swap_finalization_status(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
            status: SwapFinalizationStatus,
        ) -> Result<GetAutoFinalizationStatusResponse, String> {
            let mut last_auto_finalization_status = None;
            for _attempt_count in 1..=1000 {
                pocket_ic.progress(Duration::from_secs(1)).await;
                let auto_finalization_status =
                    get_auto_finalization_status(pocket_ic, swap_canister_id).await;
                match status {
                    SwapFinalizationStatus::Aborted => {
                        if is_auto_finalization_status_aborted_or_err(&auto_finalization_status)? {
                            return Ok(auto_finalization_status);
                        }
                    }
                    SwapFinalizationStatus::Committed => {
                        if is_auto_finalization_status_committed_or_err(&auto_finalization_status)?
                        {
                            return Ok(auto_finalization_status);
                        }
                    }
                }
                last_auto_finalization_status = Some(auto_finalization_status);
            }
            Err(format!(
                "Looks like the expected SNS auto-finalization status of {status:?} is never going to be reached: {last_auto_finalization_status:#?}",
            ))
        }

        pub async fn participate_in_swap(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
            direct_participant: PrincipalId,
            amount_icp_excluding_fees: Tokens,
        ) {
            let agent = PocketIcAgent::new(pocket_ic, direct_participant);
            let canister = SwapCanister::new(swap_canister_id);
            sns_agent_helpers::participate_in_swap(
                &agent,
                canister,
                amount_icp_excluding_fees,
                None,
            )
            .await
            .unwrap()
        }

        /// Generates the amount of individual ICP direct participations needed to complete the swap
        /// by fulfiling the minimum number of participants and the maximum amount of direct
        /// participation.
        ///
        /// 'remaining_minimum_participants' is the number of participants that are needed to complete the swap.
        /// 'remaining_maximum_direct_participation_icp' is the cumulative amount of ICP that is needed to
        /// complete the swap.
        pub fn remaining_swap_participations(
            remaining_minimum_participants: u64,
            remaining_maximum_direct_participation_icp: Tokens,
        ) -> Vec<Tokens> {
            let icp_needed_to_immediately_close_e8s =
                remaining_maximum_direct_participation_icp.get_e8s();
            let per_participant_amount_e8s =
                icp_needed_to_immediately_close_e8s / remaining_minimum_participants;
            let remainder = icp_needed_to_immediately_close_e8s % remaining_minimum_participants;
            (0..remaining_minimum_participants)
                .map(|i| {
                    let amount = per_participant_amount_e8s + if i == 0 { remainder } else { 0 };
                    Tokens::from_e8s(amount)
                })
                .collect()
        }

        pub async fn smoke_test_participate_and_finalize(
            pocket_ic: &PocketIc,
            swap_canister_id: PrincipalId,
            swap_parameters: SwapParameters,
        ) {
            for (i, amount) in remaining_swap_participations(
                swap_parameters.minimum_participants.unwrap(),
                Tokens::from_e8s(
                    swap_parameters
                        .maximum_direct_participation_icp
                        .unwrap()
                        .e8s
                        .unwrap(),
                ),
            )
            .iter()
            .enumerate()
            {
                let participant_id = PrincipalId::new_user_test_id(1000 + i as u64);
                nns::ledger::mint_icp(
                    pocket_ic,
                    AccountIdentifier::new(participant_id, None),
                    amount.saturating_add(DEFAULT_TRANSFER_FEE),
                    None,
                )
                .await;
                participate_in_swap(
                    pocket_ic,
                    swap_canister_id,
                    PrincipalId::new_user_test_id(1000 + i as u64),
                    *amount,
                )
                .await;
            }

            await_swap_finalization_status(
                pocket_ic,
                swap_canister_id,
                SwapFinalizationStatus::Committed,
            )
            .await
            .unwrap();
        }
    }
}

pub mod universal_canister {
    use ic_test_utilities::universal_canister::wasm;

    use super::*;

    pub fn init_payload(additional_pages: u32) -> Vec<u8> {
        wasm().stable_grow(additional_pages).build()
    }

    pub async fn stable_write(
        pocket_ic: &PocketIc,
        universal_canister_id: PrincipalId,
        offset: u32,
        data: &[u8],
    ) -> Result<(), String> {
        let payload = wasm().stable_write(offset, data).reply().build();

        pocket_ic
            .update_call(
                universal_canister_id.into(),
                Principal::anonymous(),
                "update",
                payload,
            )
            .await
            .map_err(|err| err.to_string())
            .map(|_| ())
    }

    pub fn stable_read_payload(offset: u32, size: u32) -> Vec<u8> {
        wasm()
            .stable_read(offset, size)
            .reply_data_append()
            .reply()
            .build()
    }

    pub async fn stable_read(
        pocket_ic: &PocketIc,
        universal_canister_id: PrincipalId,
        offset: u32,
        size: u32,
    ) -> Result<Vec<u8>, String> {
        pocket_ic
            .query_call(
                universal_canister_id.into(),
                Principal::anonymous(),
                "query",
                stable_read_payload(offset, size),
            )
            .await
            .map_err(|err| err.to_string())
    }
}
