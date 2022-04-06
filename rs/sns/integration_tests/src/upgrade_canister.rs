use canister_test::Project;
use dfn_candid::candid_one;
use ic_canister_client::Sender;
use ic_nervous_system_root::{CanisterIdRecord, CanisterStatusResult, CanisterStatusType};
use ic_nns_test_keys::TEST_USER1_KEYPAIR;
use ic_sns_governance::pb::v1::{
    governance_error::ErrorType, proposal::Action, NervousSystemParameters, NeuronPermissionList,
    NeuronPermissionType, Proposal, ProposalData, UpgradeSnsControlledCanister,
};
use ic_sns_governance::types::ONE_YEAR_SECONDS;
use ic_sns_test_utils::itest_helpers::{
    local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder,
};
use ledger_canister::Tokens;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};

#[test]
fn test_upgrade_canister_proposal_is_successful() {
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

            // Step 1.b: Create a neuron.
            let neuron_id = sns_canisters
                .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
                .await;
            let subaccount = neuron_id
                .subaccount()
                .expect("Error creating the subaccount");

            // Step 2: Execute code under test: Propose that we upgrade ledger.

            // Step 2.a: Make sure that the proposal will have a discernable
            // effect (verified in Step 3). Specifically, that the wasm will
            // have changed (upon successful execution).
            let status: CanisterStatusResult = sns_canisters
                .root
                .update_(
                    "canister_status",
                    candid_one,
                    CanisterIdRecord::from(sns_canisters.ledger.canister_id()),
                )
                .await
                .unwrap();
            let original_ledger_wasm_hash = status.module_hash.unwrap();

            // Assert that original_ledger_wasm_hash differs from the hash of
            // the wasm that we're about to install.
            let new_ledger_wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
                "rosetta-api/ledger_canister",
                "ledger-canister",
                &[], // features
            )
            .bytes();
            let new_ledger_wasm_hash = &ic_crypto_sha::Sha256::hash(&new_ledger_wasm);
            assert_ne!(new_ledger_wasm_hash[..], original_ledger_wasm_hash[..]);

            // Step 2.b: Make the proposal. (This should get executed right
            // away, because the proposing neuron is the only neuron.)
            let proposal = Proposal {
                title: "Upgrade ledger.".into(),
                action: Some(Action::UpgradeSnsControlledCanister(
                    UpgradeSnsControlledCanister {
                        canister_id: Some(sns_canisters.ledger.canister_id().into()),
                        new_canister_wasm: new_ledger_wasm,
                    },
                )),
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
            assert_ne!(
                proposal.executed_timestamp_seconds, 0,
                "proposal: {:?}",
                proposal
            );
            assert_eq!(
                proposal.failed_timestamp_seconds, 0,
                "proposal: {:?}",
                proposal
            );
            assert_eq!(proposal.failure_reason, None, "proposal: {:?}", proposal);

            // Step 3.b: Wait until new ledger is running.
            let mut attempt_count = 0;
            let status = loop {
                // Query ledger status.
                let status: CanisterStatusResult = sns_canisters
                    .root
                    .update_(
                        "canister_status",
                        candid_one,
                        CanisterIdRecord::from(sns_canisters.ledger.canister_id()),
                    )
                    .await
                    .unwrap();
                attempt_count += 1;

                // Stop waiting once it ledger has reached the Running state.
                if status.status == CanisterStatusType::Running {
                    break status;
                }

                assert!(attempt_count < 25, "status: {:?}", status);
                sleep(Duration::from_millis(100)).await;
            };

            // Step 3.c: Assert that the new wasm hash is new_ledger_wasm_hash.
            assert_eq!(
                status.module_hash.as_ref().unwrap()[..],
                new_ledger_wasm_hash[..],
                "status: {:?}",
                status
            );

            Ok(())
        }
    })
}

#[test]
fn test_upgrade_canister_proposal_execution_fail() {
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

            let mut sns_init_payload = SnsInitPayloadsBuilder::new()
                .with_ledger_account(user.get_principal_id().into(), alloc)
                .with_nervous_system_parameters(system_params)
                .build();

            // Step 1.b: Sabotage: Unlike the previous test, we configure root
            // so that it does not recognize governance as the true governance
            // canister of this SNS. As a result, when governance tries to
            // execute a canister upgrade proposal (in step 2.b), the request
            // from governance to root gets rejected by root.
            sns_init_payload.root.governance_canister_id = Some(user.get_principal_id());

            let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

            // Step 1.c: Create a neuron.
            let neuron_id = sns_canisters
                .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
                .await;
            let subaccount = neuron_id
                .subaccount()
                .expect("Error creating the subaccount");

            // Step 2: Execute code under test: Propose that we upgrade ledger.

            // Step 2.a: Make sure that the proposal will have a discernable
            // effect (verified in Step 3). Specifically, that the wasm will
            // have changed (upon successful execution).
            let status: CanisterStatusResult = sns_canisters
                .root
                .update_(
                    "canister_status",
                    candid_one,
                    CanisterIdRecord::from(sns_canisters.ledger.canister_id()),
                )
                .await
                .unwrap();
            let original_ledger_wasm_hash = status.module_hash.unwrap();

            // Assert that original_ledger_wasm_hash differs from the hash of
            // the wasm that we're about to (attempt to) install.
            let new_ledger_wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
                "rosetta-api/ledger_canister",
                "ledger-canister",
                &[], // features
            )
            .bytes();

            let new_ledger_wasm_hash = &ic_crypto_sha::Sha256::hash(&new_ledger_wasm);
            assert_ne!(new_ledger_wasm_hash[..], original_ledger_wasm_hash[..]);

            // Step 2.b: Make the proposal. (This should get executed right
            // away, because the proposing neuron is the only neuron.)
            let proposal = Proposal {
                title: "Upgrade ledger.".into(),
                action: Some(Action::UpgradeSnsControlledCanister(
                    UpgradeSnsControlledCanister {
                        canister_id: Some(sns_canisters.ledger.canister_id().into()),
                        new_canister_wasm: new_ledger_wasm,
                    },
                )),
                ..Default::default()
            };
            let proposal_id = sns_canisters
                .make_proposal(&user, &subaccount, proposal)
                .await
                .unwrap();

            // Step 3: Inspect result(s).

            // Step 3.a: Assert that the proposal was approved, but did not execute successfully.
            let mut proposal = sns_canisters.get_proposal(proposal_id).await;
            // Clear wasm field to avoid giant debug output.
            match proposal.proposal.as_mut().unwrap().action.as_mut().unwrap() {
                Action::UpgradeSnsControlledCanister(upgrade) => {
                    upgrade.new_canister_wasm = vec![];
                }
                action => panic!(
                    "Proposal action was not UpgradeSnsControlledCanister: {:?}",
                    action
                ),
            };
            fn age_s(t: u64) -> f64 {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs_f64()
                    - (t as f64)
            }
            let decision_age_s = age_s(proposal.decided_timestamp_seconds);
            assert!(
                decision_age_s < 30.0,
                "decision_age_s: {}, proposal: {:?}",
                decision_age_s,
                proposal
            );
            assert_eq!(
                proposal.executed_timestamp_seconds, 0,
                "proposal: {:?}",
                proposal
            );
            let failure_age_s = age_s(proposal.failed_timestamp_seconds);
            assert!(
                failure_age_s < 30.0,
                "failure_age_s: {}, proposal: {:?}",
                failure_age_s,
                proposal
            );
            assert_eq!(
                proposal.failure_reason.as_ref().unwrap().error_type,
                ErrorType::External as i32,
                "proposal: {:?}",
                proposal
            );

            // Step 3.b: Assert that ledger is running the original wasm.
            let status: CanisterStatusResult = sns_canisters
                .root
                .update_(
                    "canister_status",
                    candid_one,
                    CanisterIdRecord::from(sns_canisters.ledger.canister_id()),
                )
                .await
                .unwrap();
            assert_eq!(
                status.status,
                CanisterStatusType::Running,
                "status: {:?}",
                status,
            );
            assert_eq!(
                status.module_hash.as_ref().unwrap()[..],
                original_ledger_wasm_hash[..],
                "status: {:?}",
                status,
            );

            Ok(())
        }
    })
}

/// Similar to test_upgrade_canister_proposal_is_successful, but the upgrade
/// target canister is governance, not ledger.
#[test]
fn test_self_upgrade_canister_proposal() {
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

            // Step 1.b: Create a neuron.
            let neuron_id = sns_canisters
                .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
                .await;
            let subaccount = neuron_id
                .subaccount()
                .expect("Error creating the subaccount");

            // Step 2: Execute code under test: Propose that we upgrade governance.

            // Step 2.a: Make sure that the proposal will have a discernable
            // effect (verified in Step 3). Specifically, that the wasm will
            // have changed (upon successful execution).
            let status: CanisterStatusResult = sns_canisters
                .root
                .update_(
                    "canister_status",
                    candid_one,
                    CanisterIdRecord::from(sns_canisters.governance.canister_id()),
                )
                .await
                .unwrap();
            let original_governance_wasm_hash = status.module_hash.unwrap();

            // Assert that original_governance_wasm_hash differs from the hash of
            // the wasm that we're about to install.
            let new_governance_wasm = add_a_useless_func_to_wasm(
                Project::cargo_bin_maybe_use_path_relative_to_rs(
                    "sns/governance",
                    "sns-governance-canister",
                    &[], // features
                )
                .bytes(),
            );
            let new_governance_wasm_hash = &ic_crypto_sha::Sha256::hash(&new_governance_wasm);
            assert_ne!(
                new_governance_wasm_hash[..],
                original_governance_wasm_hash[..]
            );

            // Step 2.b: Make the proposal. (This should get executed right
            // away, because the proposing neuron is the only neuron.)
            let proposal = Proposal {
                title: "Upgrade governance.".into(),
                action: Some(Action::UpgradeSnsControlledCanister(
                    UpgradeSnsControlledCanister {
                        canister_id: Some(sns_canisters.governance.canister_id().into()),
                        new_canister_wasm: new_governance_wasm,
                    },
                )),
                ..Default::default()
            };
            let proposal_id = sns_canisters
                .make_proposal(&user, &subaccount, proposal)
                .await
                .unwrap();

            // Step 3: Inspect result(s).

            // Step 3.a: Wait until new governance is running. Root explicitly
            // stops governance, and then starts it back up as part of the
            // upgrade process. This is because governance specifies that the
            // target canister (i.e. itself) should be stopped first, and then
            // started again after.
            let mut attempt_count = 0;
            let status = loop {
                // Query governance status from root.
                let status: CanisterStatusResult = sns_canisters
                    .root
                    .update_(
                        "canister_status",
                        candid_one,
                        CanisterIdRecord::from(sns_canisters.governance.canister_id()),
                    )
                    .await
                    .unwrap();
                attempt_count += 1;

                // Stop waiting once it governance has reached the Running state.
                if status.status == CanisterStatusType::Running {
                    break status;
                }

                assert!(attempt_count < 25, "status: {:?}", status);
                sleep(Duration::from_millis(100)).await;
            };

            // Step 3.b: Fetch the proposal from (new) governance, and assert
            // that it was approved, executed, and did not fail.
            let proposal = sns_canisters.get_proposal(proposal_id).await;
            assert_ne!(
                proposal.decided_timestamp_seconds, 0,
                "proposal: {:?}",
                proposal
            );
            assert_ne!(
                proposal.executed_timestamp_seconds, 0,
                "proposal: {:?}",
                proposal
            );
            assert_eq!(
                proposal.failed_timestamp_seconds, 0,
                "proposal: {:?}",
                proposal
            );
            assert_eq!(proposal.failure_reason, None, "proposal: {:?}", proposal);

            // Step 3.c: Assert that the new wasm hash is new_governance_wasm_hash.
            assert_eq!(
                status.module_hash.as_ref().unwrap()[..],
                new_governance_wasm_hash[..],
                "status: {:?}",
                status
            );

            Ok(())
        }
    })
}

#[test]
fn test_upgrade_root_success() {
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

            // Step 1.b: Create a neuron.
            let neuron_id = sns_canisters
                .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
                .await;
            let subaccount = neuron_id
                .subaccount()
                .expect("Error creating the subaccount");

            // Step 2: Execute code under test: Propose that we upgrade root.

            // Step 2.a: Make sure that the proposal will have a discernable
            // effect (verified in Step 3). Specifically, that the wasm will
            // have changed (upon successful execution).
            let original_root_wasm_hash = {
                let status: CanisterStatusResult = sns_canisters
                    .governance
                    .update_("get_root_canister_status", candid_one, ())
                    .await
                    .unwrap();

                assert_eq!(status.status, CanisterStatusType::Running, "{:?}", status);

                status.module_hash.unwrap()
            };
            let new_root_wasm = add_a_useless_func_to_wasm(
                Project::cargo_bin_maybe_use_path_relative_to_rs(
                    "sns/root",
                    "sns-root-canister",
                    &[], // features
                )
                .bytes(),
            );
            let new_root_wasm_hash = &ic_crypto_sha::Sha256::hash(&new_root_wasm);
            assert_ne!(new_root_wasm_hash[..], original_root_wasm_hash[..]);

            // Step 2.b: Make the proposal. (This should get executed right
            // away, because the proposing neuron is the only neuron.)
            let proposal = Proposal {
                title: "Upgrade root.".into(),
                action: Some(Action::UpgradeSnsControlledCanister(
                    UpgradeSnsControlledCanister {
                        canister_id: Some(sns_canisters.root.canister_id().into()),
                        new_canister_wasm: new_root_wasm,
                    },
                )),
                ..Default::default()
            };
            let proposal_id = sns_canisters
                .make_proposal(&user, &subaccount, proposal)
                .await
                .unwrap();

            // Step 3: Inspect result(s).

            // Step 3.a: Assert that the proposal was approved.
            let mut proposal = sns_canisters.get_proposal(proposal_id).await;
            // Clear the wasm field, because printing it would cause lots of spam.
            clear_wasm_from_proposal(&mut proposal);
            assert_ne!(
                proposal.decided_timestamp_seconds, 0,
                "proposal: {:?}",
                proposal
            );

            // Step 3.b: Wait until new root is running.
            let mut attempt_count = 0;
            let status = loop {
                // Query root status.
                let status: CanisterStatusResult = sns_canisters
                    .governance
                    .update_("get_root_canister_status", candid_one, ())
                    .await
                    .unwrap();
                attempt_count += 1;

                // Stop waiting once it root has reached the Running state.
                if status.status == CanisterStatusType::Running {
                    break status;
                }

                assert!(attempt_count < 25, "status: {:?}", status);
                sleep(Duration::from_millis(100)).await;
            };

            // Step 3.c: Assert that the proposal final status is success.
            let mut proposal = sns_canisters.get_proposal(proposal_id).await;
            clear_wasm_from_proposal(&mut proposal);
            assert_eq!(proposal.failure_reason, None, "{:?}", proposal);
            assert!(proposal.executed_timestamp_seconds != 0, "{:?}", proposal);
            assert_eq!(proposal.failed_timestamp_seconds, 0, "{:?}", proposal);

            // Step 3.d: Assert that the new wasm hash is new_root_wasm_hash.
            assert_eq!(
                status.module_hash.as_ref().unwrap()[..],
                new_root_wasm_hash[..],
                "original_root_wasm_hash: {:?}",
                original_root_wasm_hash
            );

            Ok(())
        }
    })
}

fn clear_wasm_from_proposal(proposal: &mut ProposalData) {
    match proposal.proposal.as_mut().unwrap().action.as_mut().unwrap() {
        Action::UpgradeSnsControlledCanister(upgrade) => upgrade.new_canister_wasm = vec![],
        _ => panic!(
            "Not an UpgradeSnsControlledCanister proposal: {:?}",
            proposal
        ),
    }
}

fn add_a_useless_func_to_wasm(wasm: Vec<u8>) -> Vec<u8> {
    let mut wat = wabt::wasm2wat(wasm).unwrap();
    add_a_useless_func_to_wat(&mut wat);
    wabt::wat2wasm(wat).unwrap()
}

/// # Arguments
/// * `wat`: WebAssembly module in text format. Must end with a ")\n".
fn add_a_useless_func_to_wat(wat: &mut String) {
    assert!(wat.ends_with(")\n"));
    wat.truncate(wat.len() - 2);
    wat.push_str(" (func))");
}
