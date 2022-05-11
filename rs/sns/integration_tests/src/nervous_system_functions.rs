use candid::Encode;
use ic_canister_client::Sender;
use ic_nervous_system_common_test_keys::TEST_USER1_KEYPAIR;
use ic_sns_governance::pb::v1::nervous_system_function::{
    FunctionType, GenericNervousSystemFunction,
};
use ic_sns_governance::pb::v1::proposal::Action;
use ic_sns_governance::pb::v1::{
    ExecuteGenericNervousSystemFunction, NervousSystemFunction, NervousSystemParameters,
    NeuronPermissionList, NeuronPermissionType, Proposal, ProposalDecisionStatus, ProposalId,
};
use ic_sns_governance::types::ONE_YEAR_SECONDS;
use ic_sns_test_utils::itest_helpers::{
    install_rust_canister_with_memory_allocation, local_test_on_sns_subnet, SnsCanisters,
    SnsInitPayloadsBuilder,
};
use ledger_canister::Tokens;

/// Assert the proposal is accepted and executed.
async fn assert_proposal_executed(sns_canisters: &SnsCanisters<'_>, proposal_id: ProposalId) {
    let proposal_data = sns_canisters.get_proposal(proposal_id).await;
    assert!(proposal_data.decided_timestamp_seconds > 0);
    assert!(proposal_data.executed_timestamp_seconds > 0);
    assert_eq!(proposal_data.failure_reason, None);
    assert_eq!(proposal_data.failed_timestamp_seconds, 0);
    assert_eq!(
        proposal_data.status(),
        ProposalDecisionStatus::ProposalStatusExecuted
    );
}

/// Tests that you can add a NervousSystemFunction, that it can then validate and execute
/// ExecuteNervousSystemFunction proposals and that, on removal, a deletion marker is left
/// preventing the reuse of ids.
#[test]
fn test_add_remove_and_execute_nervous_system_functions() {
    local_test_on_sns_subnet(|runtime| async move {
        let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            transaction_fee_e8s: Some(100_000),
            reject_cost_e8s: Some(0),
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(user.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(system_params.clone())
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let mut dapp_canister = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .unwrap();

        install_rust_canister_with_memory_allocation(
            &mut dapp_canister,
            "sns/integration_tests",
            "sns-test-dapp-canister",
            &[],
            None,
            1024 * 1024 * 1024, // 1GB
        )
        .await;

        let list_nervous_system_functions_response =
            sns_canisters.list_nervous_system_functions().await;
        // Initially we should have the 6 native functions
        assert_eq!(list_nervous_system_functions_response.functions.len(), 6);

        let neuron_id = sns_canisters
            .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
            .await;

        let subaccount = neuron_id
            .subaccount()
            .expect("Error creating the subaccount");

        let nervous_system_function = NervousSystemFunction {
            id: 1000,
            name: "Call test dapp method".to_string(),
            description: None,
            function_type: Some(FunctionType::GenericNervousSystemFunction(
                GenericNervousSystemFunction {
                    target_canister_id: Some(dapp_canister.canister_id().get()),
                    target_method_name: Some("test_dapp_method".to_string()),
                    validator_canister_id: Some(dapp_canister.canister_id().get()),
                    validator_method_name: Some("test_dapp_method_validate".to_string()),
                },
            )),
        };

        let proposal_payload = Proposal {
            title: "Add new GenericNervousSystemFunction".into(),
            action: Some(Action::AddGenericNervousSystemFunction(
                nervous_system_function.clone(),
            )),
            ..Default::default()
        };

        let proposal_id = sns_canisters
            .make_proposal(&user, &subaccount, proposal_payload)
            .await
            .unwrap();

        assert_proposal_executed(&sns_canisters, proposal_id).await;

        let list_nervous_system_functions_response =
            sns_canisters.list_nervous_system_functions().await;
        // We should now have an extra function, which we just added.
        assert_eq!(list_nervous_system_functions_response.functions.len(), 7);
        assert!(
            list_nervous_system_functions_response
                .functions
                .get(6)
                .as_ref()
                .unwrap()
                == &&nervous_system_function
        );

        let invalid_value = 5i64;
        let proposal_payload = Proposal {
            title: "An invalid ExecuteNervousSystemFunction call".into(),
            action: Some(Action::ExecuteGenericNervousSystemFunction(
                ExecuteGenericNervousSystemFunction {
                    function_id: 1000,
                    payload: Encode!(&invalid_value).unwrap(),
                },
            )),
            ..Default::default()
        };

        let result = sns_canisters
            .make_proposal(&user, &subaccount, proposal_payload)
            .await;

        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .error_message
            .contains("Value < 10. Invalid!"));

        let valid_value = 11i64;

        let proposal_payload = Proposal {
            title: "A valid ExecuteNervousSystemFunction call".into(),
            action: Some(Action::ExecuteGenericNervousSystemFunction(
                ExecuteGenericNervousSystemFunction {
                    function_id: 1000,
                    payload: Encode!(&valid_value).unwrap(),
                },
            )),
            ..Default::default()
        };

        let proposal_id = sns_canisters
            .make_proposal(&user, &subaccount, proposal_payload)
            .await
            .unwrap();

        assert_proposal_executed(&sns_canisters, proposal_id).await;
        let proposal_data = sns_canisters.get_proposal(proposal_id).await;
        assert!(proposal_data.executed_timestamp_seconds > 0);
        assert!(proposal_data.payload_text_rendering.is_some());
        assert!(proposal_data
            .payload_text_rendering
            .unwrap()
            .contains("Value is 11. Valid!"));

        // Now remove the NervousSystemFunction
        let proposal_payload = Proposal {
            title: "Remove ExecuteNervousSystemFunction".into(),
            action: Some(Action::RemoveGenericNervousSystemFunction(1000)),
            ..Default::default()
        };

        let proposal_id = sns_canisters
            .make_proposal(&user, &subaccount, proposal_payload)
            .await
            .unwrap();

        assert_proposal_executed(&sns_canisters, proposal_id).await;

        let proposal_payload = Proposal {
            title: "An invalid ExecuteNervousSystemFunction call".into(),
            action: Some(Action::ExecuteGenericNervousSystemFunction(
                ExecuteGenericNervousSystemFunction {
                    function_id: 1000,
                    payload: Encode!(&valid_value).unwrap(),
                },
            )),
            ..Default::default()
        };

        let result = sns_canisters
            .make_proposal(&user, &subaccount, proposal_payload)
            .await;

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .error_message
            .contains("There is no NervousSystemFunction with id: 1000"));

        let list_nervous_system_functions_response =
            sns_canisters.list_nervous_system_functions().await;
        // Since we removed the function we should go back to only having the native
        // functions listed, and the removed function should appear in the reserved ids.
        assert_eq!(list_nervous_system_functions_response.functions.len(), 6);
        assert_eq!(
            list_nervous_system_functions_response
                .reserved_ids
                .get(0)
                .unwrap(),
            &nervous_system_function.id,
        );

        Ok(())
    });
}
