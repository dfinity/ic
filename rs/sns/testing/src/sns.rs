use candid::{CandidType, Encode};
use canister_test::Wasm;
use ic_base_types::CanisterId;
use ic_management_canister_types::CanisterStatusType as CanisterStatusResultStatus;
use ic_management_canister_types_private::CanisterInstallMode;
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
    pocket_ic_helpers::{await_with_timeout, install_canister_on_subnet},
};
use ic_nns_common::pb::v1::ProposalId;
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_sns_governance_api::pb::v1::UpgradeSnsControlledCanister;
use ic_sns_swap::pb::v1::Lifecycle;
use pocket_ic::nonblocking::PocketIc;

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
    assert_eq!(
        swap_parameters.start_time, None,
        "Expecting the swap start time to be None to start the swap immediately"
    );
    let (sns, proposal_id) =
        propose_to_deploy_sns_and_wait(pocket_ic, create_service_nervous_system, sns_proposal_id)
            .await;
    await_swap_lifecycle(pocket_ic, sns.swap.canister_id, Lifecycle::Open)
        .await
        .expect("Expecting the swap to be open after creation");
    smoke_test_participate_and_finalize(pocket_ic, sns.swap.canister_id, swap_parameters).await;
    await_swap_lifecycle(pocket_ic, sns.swap.canister_id, Lifecycle::Committed)
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
