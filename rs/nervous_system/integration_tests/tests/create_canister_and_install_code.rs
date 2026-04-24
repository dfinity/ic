use candid::Principal;
use ic_base_types::PrincipalId;
use ic_crypto_sha2::Sha256;
use ic_nervous_system_common_test_utils::wasm_helpers::SMALLEST_VALID_WASM_BYTES;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{NnsInstaller, nns};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_governance_api::{
    CreateCanisterAndInstallCodeRequest, MakeProposalRequest, ProposalActionRequest,
    SuccessfulProposalExecutionValue, WasmModule,
};
use pocket_ic::PocketIcBuilder;

/// Verifies that a CreateCanisterAndInstallCode proposal can be submitted,
/// adopted, and executed, and that the new canister appears on the target
/// subnet with the expected WASM module installed and the expected controller.
#[tokio::test]
async fn test_create_canister_and_install_code() {
    // Step 1: Prepare the world.

    // Step 1.1: Set up PocketIC with NNS + SNS (required by NnsInstaller) +
    // system subnet.
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        // Even though this test has nothing to do with SNS, we do this, because
        // NnsInstaller panics without an SNS subnet.
        .with_sns_subnet()
        .with_system_subnet()
        .build_async()
        .await;

    // Step 1.2: Install NNS canisters with the test governance canister
    // (which has the CreateCanisterAndInstallCode feature flag enabled).
    {
        let mut nns_installer = NnsInstaller::default();
        nns_installer.with_current_nns_canister_versions();
        nns_installer.with_test_governance_canister();
        nns_installer.install(&pocket_ic).await;
    }

    // Step 2: Call the code under test.

    // Step 2.1: Get the system subnet ID to use as host_subnet_id.
    let topology = pocket_ic.topology().await;
    let nns_subnet_id = PrincipalId::from(topology.get_nns().unwrap());
    let system_subnets = topology.get_system_subnets();
    let host_subnet_id = PrincipalId::from(*system_subnets.first().unwrap());
    // Sanity check: we want to exercise canister creation on a non-NNS subnet.
    assert_ne!(host_subnet_id, nns_subnet_id);

    // Step 2.2: Prepare the WASM and compute its expected hash.
    let wasm_module_bytes = SMALLEST_VALID_WASM_BYTES;
    let expected_module_hash = Sha256::hash(wasm_module_bytes).to_vec();

    // Step 2.3: Execute proposal.
    let proposal_info = nns::governance::propose_and_wait(
        &pocket_ic,
        MakeProposalRequest {
            title: Some("Create canister and install code".to_string()),
            summary: "Integration test".to_string(),
            url: "".to_string(),
            action: Some(ProposalActionRequest::CreateCanisterAndInstallCode(
                CreateCanisterAndInstallCodeRequest {
                    host_subnet_id: Some(host_subnet_id),
                    canister_settings: None,
                    wasm_module: Some(WasmModule::Inlined(wasm_module_bytes.to_vec())),
                    install_arg: None,
                },
            )),
        },
    )
    .await
    .unwrap();

    // Step 3: Verify results.

    // Step 3.1: Inspect timestamp fields.
    assert_eq!(
        proposal_info.failure_reason, None,
        "Proposal failed: {:?}",
        proposal_info.failure_reason
    );
    assert!(
        proposal_info.executed_timestamp_seconds > 0,
        "Proposal was not executed"
    );

    // Step 3.2: Get the canister ID from proposal's success_value.
    let canister_id: PrincipalId = match proposal_info.success_value {
        Some(SuccessfulProposalExecutionValue::CreateCanisterAndInstallCode(ok)) => {
            ok.canister_id.unwrap()
        }
        wrong => panic!(
            "Expected CreateCanisterAndInstallCode success_value, got: {:?}",
            wrong
        ),
    };

    // Step 3.3: Verify the canister lives on the expected subnet.
    let canister_subnet = pocket_ic
        .get_subnet(Principal::from(canister_id))
        .await
        .unwrap();
    assert_eq!(
        PrincipalId::from(canister_subnet),
        host_subnet_id,
        "Canister is on the wrong subnet"
    );

    // Step 3.4: Verify the canister has specified code.
    let root_principal = Principal::from(PrincipalId::from(ROOT_CANISTER_ID));
    let status = pocket_ic
        .canister_status(Principal::from(canister_id), Some(root_principal))
        .await
        .unwrap();

    assert_eq!(
        status.module_hash,
        Some(expected_module_hash),
        "WASM module hash mismatch"
    );

    // Step 3.5: Verify that root controls the created canister.
    assert!(
        status.settings.controllers.contains(&root_principal),
        "Root should be a controller. Controllers: {:?}",
        status.settings.controllers,
    );
}
