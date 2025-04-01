use candid::{CandidType, Encode};
use canister_test::Wasm;
use futures::future::join_all;
use ic_base_types::PrincipalId;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{
    add_wasms_to_sns_wasm, install_canister_with_controllers, NnsInstaller,
};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, IDENTITY_CANISTER_ID, LEDGER_CANISTER_ID,
    LEDGER_INDEX_CANISTER_ID, NNS_UI_CANISTER_ID, ROOT_CANISTER_ID, SNS_AGGREGATOR_CANISTER_ID,
    SNS_WASM_CANISTER_ID,
};
use ic_registry_transport::pb::v1::RegistryAtomicMutateRequest;
use icp_ledger::{AccountIdentifier, Tokens};
use pocket_ic::nonblocking::PocketIc;

use crate::utils::{check_canister_installed, ALL_SNS_TESTING_CANISTER_IDS};

async fn validate_subnet_setup(pocket_ic: &PocketIc) {
    let topology = pocket_ic.topology().await;
    let _nns_subnet_id = topology.get_nns().expect("NNS subnet not found");
    let _sns_subnet_id = topology.get_nns().expect("SNS subnet not found");
    let _ii_subnet_id = topology.get_ii().expect("II subnet not found");
    let app_subnet_ids = topology.get_app_subnets();
    assert!(!app_subnet_ids.is_empty(), "No application subnets found");
}

pub async fn bootstrap_nns(
    pocket_ic: &PocketIc,
    initial_mutations: Vec<RegistryAtomicMutateRequest>,
    ledger_balances: Vec<(AccountIdentifier, Tokens)>,
    neuron_hotkeys: Vec<PrincipalId>,
) {
    // Ensure that all required subnets are present before proceeding to install NNS canisters
    // At the moment this check doesn't make a lot of sense since we are always creating the new PocketIC instance
    // with all the required subnets. However, in the future, we might want to be able to check externally provided
    // networks.
    validate_subnet_setup(pocket_ic).await;
    // Check if all NNS canisters are already installed
    let canisters_installed = join_all(
        ALL_SNS_TESTING_CANISTER_IDS
            .iter()
            .map(|canister_id| async { check_canister_installed(pocket_ic, canister_id).await }),
    )
    .await;

    if !canisters_installed.iter().any(|installed| *installed) {
        // TODO @rvem: at some point in the future we might want to use
        // non-default 'neurons_fund_hotkeys' to provide
        // neuron hotkeys for user-provided identities.
        let mut nns_installer = NnsInstaller::default();
        nns_installer.with_current_nns_canister_versions();
        nns_installer.with_test_governance_canister();
        nns_installer.with_cycles_minting_canister();
        nns_installer.with_cycles_ledger();
        nns_installer.with_index_canister();
        nns_installer.with_custom_registry_mutations(initial_mutations);
        nns_installer.with_ledger_balances(ledger_balances);
        nns_installer.with_neurons_fund_hotkeys(neuron_hotkeys);
        nns_installer.install(pocket_ic).await;
        add_wasms_to_sns_wasm(pocket_ic, false).await.unwrap();
    } else if !canisters_installed.iter().all(|exists| *exists) {
        panic!("Some NNS canisters are missing, we cannot fix this automatically at the moment");
    }

    install_frontend_nns_canisters(pocket_ic).await;
}

#[derive(CandidType)]
struct SnsAggregatorPayload {
    pub update_interval_ms: u64,
    pub fast_interval_ms: u64,
}

#[derive(CandidType)]
struct NnsDappPayload {
    args: Vec<(String, String)>,
}

async fn install_frontend_nns_canisters(pocket_ic: &PocketIc) {
    let features = &[];

    let sns_aggregator_wasm =
        Wasm::from_location_specified_by_env_var("sns_aggregator", features).unwrap();
    let nns_dapp_wasm = Wasm::from_location_specified_by_env_var("nns_dapp", features).unwrap();
    let internet_identity_wasm =
        Wasm::from_location_specified_by_env_var("internet_identity", features).unwrap();

    if !check_canister_installed(pocket_ic, &SNS_AGGREGATOR_CANISTER_ID).await {
        // Refresh every second so that the NNS dapp is as up-to-date as possible
        let sns_aggregator_payload = SnsAggregatorPayload {
            update_interval_ms: 1000,
            fast_interval_ms: 100,
        };

        install_canister_with_controllers(
            pocket_ic,
            "sns_aggregator",
            SNS_AGGREGATOR_CANISTER_ID,
            Encode!(&sns_aggregator_payload).unwrap(),
            sns_aggregator_wasm,
            vec![ROOT_CANISTER_ID.get(), SNS_WASM_CANISTER_ID.get()],
        )
        .await;
    }

    if !check_canister_installed(pocket_ic, &IDENTITY_CANISTER_ID).await {
        let internet_identity_payload: Option<()> = None;

        install_canister_with_controllers(
            pocket_ic,
            "internet-identity",
            IDENTITY_CANISTER_ID,
            Encode!(&internet_identity_payload).unwrap(),
            internet_identity_wasm,
            vec![ROOT_CANISTER_ID.get()],
        )
        .await;
    }

    if !check_canister_installed(pocket_ic, &NNS_UI_CANISTER_ID).await {
        // TODO @rvem: perhaps, we may start using configurable endpoint for the IC http interface
        // which should be considered in NNS dapp configuration.
        let endpoint = "localhost:8080";
        let nns_dapp_payload = NnsDappPayload {
            args: vec![
                ("API_HOST".to_string(), format!("http://{}", endpoint)),
                (
                    "CYCLES_MINTING_CANISTER_ID".to_string(),
                    CYCLES_MINTING_CANISTER_ID.get().to_string(),
                ),
                ("DFX_NETWORK".to_string(), "local".to_string()),
                (
                    "FEATURE_FLAGS".to_string(),
                    "{\"ENABLE_CKBTC\":false,\"ENABLE_CKTESTBTC\":false}".to_string(),
                ),
                ("FETCH_ROOT_KEY".to_string(), "true".to_string()),
                (
                    "GOVERNANCE_CANISTER_ID".to_string(),
                    GOVERNANCE_CANISTER_ID.get().to_string(),
                ),
                ("HOST".to_string(), format!("http://{}", endpoint)),
                (
                    "IDENTITY_SERVICE_URL".to_string(),
                    format!("http://{}.{}", IDENTITY_CANISTER_ID.get(), endpoint),
                ),
                (
                    "LEDGER_CANISTER_ID".to_string(),
                    LEDGER_CANISTER_ID.get().to_string(),
                ),
                (
                    "OWN_CANISTER_ID".to_string(),
                    NNS_UI_CANISTER_ID.get().to_string(),
                ),
                (
                    "ROBOTS".to_string(),
                    "<meta name=\"robots\" content=\"noindex, nofollow\" />".to_string(),
                ),
                (
                    "SNS_AGGREGATOR_URL".to_string(),
                    format!("http://{}.{}", SNS_AGGREGATOR_CANISTER_ID.get(), endpoint),
                ),
                ("STATIC_HOST".to_string(), format!("http://{}", endpoint)),
                (
                    "WASM_CANISTER_ID".to_string(),
                    SNS_WASM_CANISTER_ID.get().to_string(),
                ),
                (
                    "INDEX_CANISTER_ID".to_string(),
                    LEDGER_INDEX_CANISTER_ID.get().to_string(),
                ),
            ],
        };
        install_canister_with_controllers(
            pocket_ic,
            "nns-dapp",
            NNS_UI_CANISTER_ID,
            Encode!(&nns_dapp_payload).unwrap(),
            nns_dapp_wasm,
            vec![ROOT_CANISTER_ID.get()],
        )
        .await;
    };
}
