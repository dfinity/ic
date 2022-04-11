use candid::Encode;
use dfn_candid::candid_one;
use ic_canister_client::Sender;
use ic_nns_test_keys::TEST_USER1_KEYPAIR;
use ic_sns_governance::pb::v1::{
    governance_error::ErrorType, proposal::Action, CallCanisterMethod, NervousSystemParameters,
    NeuronPermissionList, NeuronPermissionType, Proposal,
};
use ic_sns_governance::types::ONE_YEAR_SECONDS;
use ic_sns_test_utils::{
    itest_helpers::{self, local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder},
    SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES,
};
use ledger_canister::Tokens;

#[test]
fn test_call_canister_method_success() {
    local_test_on_sns_subnet(|runtime| {
        async move {
            // Step 1: Prepare

            // Step 1.a: Boot up SNS with one user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let alloc = Tokens::from_tokens(1000).unwrap();

            let system_params = NervousSystemParameters {
                neuron_claimer_permissions: Some(NeuronPermissionList {
                    permissions: NeuronPermissionType::all(),
                }),
                ..NervousSystemParameters::with_default_values()
            };

            let sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user.get_principal_id().into(), alloc)
                .with_nervous_system_parameters(system_params)
                .build();

            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            // Step 1.b: Create a dapp.
            let mut dapp_canister = runtime
                .create_canister_max_cycles_with_retries()
                .await
                .expect("Could not create dapp canister");

            itest_helpers::install_rust_canister_with_memory_allocation(
                &mut dapp_canister,
                "nervous_system/common/test_canister",
                "ic-nervous-system-common-test-canister",
                &[],  // features
                None, // canister_init args
                SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES,
            )
            .await;

            // Step 1.c: Create a neuron.
            let neuron_id = sns_canisters
                .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
                .await;
            let subaccount = neuron_id
                .subaccount()
                .expect("Error creating the subaccount");

            // Step 2: Execute code under test: Propose that we upgrade ledger.

            // Step 2.a: Make the proposal. (This should get executed right
            // away, because the proposing neuron is the only neuron.)
            let proposal = Proposal {
                title: "Set integer to 42".into(),
                action: Some(Action::CallCanisterMethod(CallCanisterMethod {
                    target_canister_id: Some(dapp_canister.canister_id().get()),
                    target_method_name: "set_integer".into(),
                    payload: Encode!(&42).unwrap(),
                })),
                ..Default::default()
            };
            let proposal_id = sns_canisters
                .make_proposal(&user, &subaccount, proposal)
                .await
                .unwrap();

            // Step 3: Inspect result(s).

            // Step 3.a: Assert that the proposal was approved.
            let proposal = sns_canisters.get_proposal(proposal_id).await;
            assert_ne!(
                proposal.decided_timestamp_seconds, 0,
                "proposal: {:?}",
                proposal
            );

            // Step 3.b: Wait until the proposal has been executed.
            let mut executed = false;
            for _ in 0..100 {
                let proposal = sns_canisters.get_proposal(proposal_id).await;
                // Assert that the execution did not fail
                assert_eq!(
                    proposal.failed_timestamp_seconds, 0,
                    "proposal: {:?}",
                    proposal
                );
                assert_eq!(proposal.failure_reason, None, "proposal: {:?}", proposal);

                if proposal.executed_timestamp_seconds > 0 {
                    executed = true;
                    break;
                }
            }
            assert!(executed);

            // Step 3.c: Query the dapp to see the effect of executing the proposal.
            let final_integer: i32 = dapp_canister
                .query_("get_integer", candid_one, ())
                .await
                .unwrap();
            assert_eq!(final_integer, 42);

            Ok(())
        }
    })
}

#[test]
fn test_call_canister_method_fail() {
    local_test_on_sns_subnet(|runtime| {
        async move {
            // Step 1: Prepare

            // Step 1.a: Boot up SNS with one user.
            let user = Sender::from_keypair(&TEST_USER1_KEYPAIR);
            let alloc = Tokens::from_tokens(1000).unwrap();

            let system_params = NervousSystemParameters {
                neuron_claimer_permissions: Some(NeuronPermissionList {
                    permissions: NeuronPermissionType::all(),
                }),
                ..NervousSystemParameters::with_default_values()
            };

            let sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user.get_principal_id().into(), alloc)
                .with_nervous_system_parameters(system_params)
                .build();

            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            // Step 1.b: Create a dapp.
            let mut dapp_canister = runtime
                .create_canister_max_cycles_with_retries()
                .await
                .expect("Could not create dapp canister");

            itest_helpers::install_rust_canister_with_memory_allocation(
                &mut dapp_canister,
                "nervous_system/common/test_canister",
                "ic-nervous-system-common-test-canister",
                &[],  // features
                None, // canister_init args
                SNS_MAX_CANISTER_MEMORY_ALLOCATION_IN_BYTES,
            )
            .await;

            // Step 1.c: Create a neuron.
            let neuron_id = sns_canisters
                .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
                .await;
            let subaccount = neuron_id
                .subaccount()
                .expect("Error creating the subaccount");

            // Step 2: Execute code under test: Propose that we upgrade ledger.

            // Step 2.a: Make the proposal. (This should get executed right
            // away, because the proposing neuron is the only neuron.)
            let proposal = Proposal {
                title: "An Ode to Monty Python".into(),
                action: Some(Action::CallCanisterMethod(CallCanisterMethod {
                    target_canister_id: Some(dapp_canister.canister_id().get()),
                    target_method_name: "explode".into(),
                    payload: Encode!(&"We are the knights who say NI!".to_string()).unwrap(),
                })),
                ..Default::default()
            };
            let proposal_id = sns_canisters
                .make_proposal(&user, &subaccount, proposal)
                .await
                .unwrap();

            // Step 3: Inspect result(s).

            // Step 3.a: Assert that the proposal was approved.
            let proposal = sns_canisters.get_proposal(proposal_id).await;
            assert_ne!(
                proposal.decided_timestamp_seconds, 0,
                "proposal: {:?}",
                proposal
            );

            // Step 3.b: Wait until the proposal has failed to execute.
            let mut done = false;
            for _ in 0..100 {
                let proposal = sns_canisters.get_proposal(proposal_id).await;

                // Assert that the execution did not successfully execute.
                assert_eq!(
                    proposal.executed_timestamp_seconds, 0,
                    "proposal: {:?}",
                    proposal
                );

                if proposal.failed_timestamp_seconds == 0 {
                    continue;
                }

                // Inspect failure_reason.
                let failure_reason = proposal.failure_reason.expect("No failure_reason.");
                assert_eq!(
                    failure_reason.error_type,
                    ErrorType::External as i32,
                    "failure_reason: {:?}",
                    failure_reason
                );
                assert!(
                    failure_reason
                        .error_message
                        .to_lowercase()
                        .contains("panic"),
                    "failure_reason: {:?}",
                    failure_reason
                );
                assert!(
                    failure_reason
                        .error_message
                        .contains("We are the knights who say NI!"),
                    "failure_reason: {:?}",
                    failure_reason
                );

                done = true;
                break;
            }
            assert!(done);

            // Step 3.c: Query the dapp to see that integer remains at its original value.
            let final_integer: i32 = dapp_canister
                .query_("get_integer", candid_one, ())
                .await
                .unwrap();
            assert_eq!(final_integer, 0);

            Ok(())
        }
    })
}
