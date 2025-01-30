use candid::{CandidType, Encode};
use canister_test::Wasm;
use ic_base_types::CanisterId;
use ic_management_canister_types::CanisterInstallMode;
use ic_nervous_system_agent::sns::Sns;
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::nns::governance::propose_to_deploy_sns_and_wait,
    pocket_ic_helpers::sns::{
        governance::{
            propose_to_upgrade_sns_controlled_canister_and_wait,
            EXPECTED_UPGRADE_DURATION_MAX_SECONDS,
        },
        swap::{await_swap_lifecycle, smoke_test_participate_and_finalize},
    },
    pocket_ic_helpers::{
        add_wasms_to_sns_wasm, await_with_timeout,
        install_canister_on_subnet, install_canister_with_controllers,
        NnsInstaller,
    },
};
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, GOVERNANCE_CANISTER_ID, IDENTITY_CANISTER_ID, LEDGER_CANISTER_ID,
    LEDGER_INDEX_CANISTER_ID, NNS_UI_CANISTER_ID, ROOT_CANISTER_ID, SNS_AGGREGATOR_CANISTER_ID,
    SNS_WASM_CANISTER_ID,
};
use ic_sns_governance_api::pb::v1::UpgradeSnsControlledCanister;
use ic_sns_swap::pb::v1::Lifecycle;
use pocket_ic::{management_canister::CanisterStatusResultStatus, nonblocking::PocketIc};

pub async fn bootstrap_nns(pocket_ic: &PocketIc) {
    // TODO @rvem: at some point in the future we might want to use
    // non-default 'initial_balances' as well as 'neurons_fund_hotkeys' to provide
    // tokens and neuron hotkeys for user-provided indentities.
    let mut nns_installer = NnsInstaller::default();
    nns_installer.with_current_nns_canister_versions();
    nns_installer.with_cycles_minting_canister();
    nns_installer.with_index_canister();
    nns_installer.install(pocket_ic).await;

    install_frontend_nns_canisters(pocket_ic).await;
    add_wasms_to_sns_wasm(pocket_ic, false).await.unwrap();
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
}

// TODO @rvem: I don't like the fact that this struct definition is copy-pasted from 'canister/canister.rs'.
// We should extract it into a separate crate and reuse in both canister and this crates.
#[derive(CandidType)]
pub struct TestCanisterInitArgs {
    pub greeting: Option<String>,
}

pub async fn install_test_canister(pocket_ic: &PocketIc, args: TestCanisterInitArgs) -> CanisterId {
    let topology = pocket_ic.topology().await;
    let application_subnet_ids = topology.get_app_subnets();
    let application_subnet_id = application_subnet_ids
        .first()
        .expect("No Application subnet found");
    let features = &[];
    let test_canister_wasm =
        Wasm::from_location_specified_by_env_var("sns_testing_canister", features).unwrap();
    install_canister_on_subnet(
        pocket_ic,
        *application_subnet_id,
        Encode!(&args).unwrap(),
        Some(test_canister_wasm),
        vec![ROOT_CANISTER_ID.get()],
    )
    .await
}

pub async fn create_sns(
    pocket_ic: &PocketIc,
    dapp_canister_ids: Vec<CanisterId>,
) -> (Sns, ProposalId) {
    let sns_proposal_id = "1";
    let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
        .neurons_fund_participation(true)
        .with_dapp_canisters(dapp_canister_ids)
        .build();
    let swap_parameters = create_service_nervous_system
        .swap_parameters
        .clone()
        .unwrap();
    let (sns, proposal_id) =
        propose_to_deploy_sns_and_wait(pocket_ic, create_service_nervous_system, sns_proposal_id)
            .await;
    await_swap_lifecycle(pocket_ic, sns.swap.canister_id, Lifecycle::Open)
        .await
        .expect("Expecting the swap to be open after creation");
    smoke_test_participate_and_finalize(pocket_ic, sns.swap.canister_id, swap_parameters).await;
    await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Committed)
        .await
        .expect("Expecting the swap to be commited after creation and swap completion");
    (sns, proposal_id)
}

pub async fn upgrade_sns_controlled_test_canister(
    pocket_ic: &PocketIc,
    sns: Sns,
    canister_id: CanisterId,
    upgrade_arg: TestCanisterInitArgs,
) {
    // For now, we're using the same wasm module, but different init arguments used in 'post_upgrade' hook.
    let features = &[];
    let test_canister_wasm =
        Wasm::from_location_specified_by_env_var("sns_testing_canister", features).unwrap();
    propose_to_upgrade_sns_controlled_canister_and_wait(
        pocket_ic,
        sns.governance.canister_id,
        UpgradeSnsControlledCanister {
            canister_id: Some(canister_id.get()),
            new_canister_wasm: test_canister_wasm.bytes(),
            canister_upgrade_arg: Some(Encode!(&upgrade_arg).unwrap()),
            mode: Some(CanisterInstallMode::Upgrade as i32),
            chunked_canister_wasm: None,
        },
    )
    .await;
    // Wait for the canister to become available
    await_with_timeout(
        pocket_ic,
        0..EXPECTED_UPGRADE_DURATION_MAX_SECONDS,
        |pocket_ic| async {
            let canister_status = pocket_ic
                .canister_status(canister_id.into(), Some(sns.root.canister_id.into()))
                .await;
            canister_status
                .expect("Canister status is unavailable")
                .status as u32
        },
        &(CanisterStatusResultStatus::Running as u32),
    )
    .await
    .expect("Test canister failed to get into the 'Running' state after upgrade");
}
