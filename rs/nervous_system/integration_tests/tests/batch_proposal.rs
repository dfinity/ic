use candid::Principal;
use ic_base_types::PrincipalId;
use ic_crypto_sha2::Sha256;
use ic_nervous_system_common_test_utils::wasm_helpers::SMALLEST_VALID_WASM_BYTES;
use ic_nervous_system_integration_tests::pocket_ic_helpers::{NnsInstaller, nns};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_governance_api::{
    BatchRequest, CreateCanisterAndInstallCodeRequest, MakeProposalRequest, ProposalActionRequest,
    SuccessfulProposalExecutionValue, WasmModule,
};
use pocket_ic::PocketIcBuilder;

/// Verifies that a Batch proposal containing two CreateCanisterAndInstallCode
/// sub-actions is executed successfully and that each sub-action produces a
/// distinct canister ID with the expected WASM installed.
#[tokio::test]
async fn test_batch_of_two_create_canister_and_install_code_proposals() {
    // Step 1: Prepare the world.

    // Step 1.1: Boot up an IC.
    let pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        // Required by NnsInstaller, but otherwise, not actually used.
        .with_sns_subnet()
        .build_async()
        .await;

    // Step 1.2: Install NNS.
    let mut nns_installer = NnsInstaller::default();
    nns_installer.with_current_nns_canister_versions();
    // Required to enable the Batch proposal feature flag.
    nns_installer.with_test_governance_canister();
    nns_installer.install(&pocket_ic).await;

    // Step 2: Call the code under test.

    // Step 2.1: Gather ingredients for proposal.

    // The subnet where the canisters will be created.
    let topology = pocket_ic.topology().await;
    let host_subnet_id = PrincipalId::from(topology.get_nns().unwrap());

    // Code that will be installed into the new canisters.
    let wasm_a: Vec<u8> = SMALLEST_VALID_WASM_BYTES.to_vec();
    let wasm_b: Vec<u8> = {
        let mut w = wasm_a.clone();
        // Append a valid custom section (id=0, size=2, name_len=0, data=[0x42]).
        w.extend_from_slice(&[0x00, 0x02, 0x00, 0x42]);
        w
    };
    // Used later for verification.
    let hashes = [
        Sha256::hash(&wasm_a).to_vec(),
        Sha256::hash(&wasm_b).to_vec(),
    ];

    // Step 2.2: Assemble the kernel of the proposal, the Batch itself.
    let actions = [wasm_a, wasm_b]
        .into_iter()
        .map(|wasm: Vec<u8>| -> ProposalActionRequest {
            let result = CreateCanisterAndInstallCodeRequest {
                host_subnet_id: Some(host_subnet_id),
                wasm_module: Some(WasmModule::Inlined(wasm)),
                canister_settings: None,
                install_arg: None,
            };

            ProposalActionRequest::CreateCanisterAndInstallCode(result)
        })
        .collect();
    let batch = BatchRequest {
        actions: Some(actions),
    };

    // Step 2.3: Execute the proposal.
    let proposal_info = nns::governance::propose_and_wait(
        &pocket_ic,
        MakeProposalRequest {
            title: Some("Create two canisters (using Batch)".to_string()),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(ProposalActionRequest::Batch(batch)),
        },
    )
    .await
    .unwrap();

    // Step 3: Verify results.

    // Step 3.1: Proposal executed successfully.
    assert!(
        proposal_info.executed_timestamp_seconds > 0,
        "{:#?}",
        proposal_info,
    );
    assert_eq!(proposal_info.failure_reason, None, "{:#?}", proposal_info,);

    // Step 3.2: New canister IDs (in success_value).
    let batch_ok = match proposal_info.success_value {
        Some(SuccessfulProposalExecutionValue::Batch(ok)) => ok,
        wrong => panic!("Expected Batch success_value, got: {wrong:#?}"),
    };
    assert_eq!(batch_ok.sub_results.len(), 2, "{batch_ok:#?}");
    let new_canister_ids = batch_ok
        .sub_results
        .into_iter()
        .map(|sub_result| {
            // Unwrap sub_result.
            let sub_result = match sub_result.unwrap() {
                SuccessfulProposalExecutionValue::CreateCanisterAndInstallCode(ok) => ok,
                wrong => {
                    panic!("Sub-result 0: expected CreateCanisterAndInstallCode, got {wrong:#?}")
                }
            };

            sub_result.canister_id.unwrap()
        })
        .collect::<Vec<_>>();
    let canister_id_a = new_canister_ids[0];
    let canister_id_b = new_canister_ids[1];
    assert_ne!(
        canister_id_a, canister_id_b,
        "Both sub-actions must produce distinct canister IDs"
    );

    // Step 3.3: Canisters created in specified subnet.
    for (i, canister_id) in new_canister_ids.iter().enumerate() {
        let canister_subnet = pocket_ic
            .get_subnet(Principal::from(*canister_id))
            .await
            .unwrap();

        assert_eq!(PrincipalId::from(canister_subnet), host_subnet_id, "{i}");
    }

    // Step 3.4: Each canister has the expected WASM installed.
    for (i, (canister_id, expected_module_hash)) in
        new_canister_ids.iter().zip(hashes.iter()).enumerate()
    {
        // Observe module hash.
        let controller = Principal::from(PrincipalId::from(ROOT_CANISTER_ID));
        let observed_module_hash = pocket_ic
            .canister_status(Principal::from(*canister_id), Some(controller))
            .await
            .unwrap()
            .module_hash
            .unwrap();

        assert_eq!(observed_module_hash, *expected_module_hash, "{i}");
    }
}
