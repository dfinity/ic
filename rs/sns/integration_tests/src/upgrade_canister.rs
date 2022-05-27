use canister_test::{Canister, Project, Runtime, Wasm};
use dfn_candid::candid_one;
use ic_base_types::PrincipalId;
use ic_canister_client::Sender;
use ic_ic00_types::{CanisterInstallMode, CanisterStatusResultV2};
use ic_nervous_system_common_test_keys::{TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR};
use ic_nervous_system_root::{CanisterIdRecord, CanisterStatusResult, CanisterStatusType};
use ic_sns_governance::pb::v1::{
    governance_error::ErrorType, proposal::Action, NervousSystemParameters, NeuronPermissionList,
    NeuronPermissionType, Proposal, ProposalData, UpgradeSnsControlledCanister,
};
use ic_sns_governance::types::ONE_YEAR_SECONDS;
use ic_sns_test_utils::itest_helpers::{
    install_governance_canister, install_ledger_canister, install_root_canister,
    local_test_on_sns_subnet, SnsCanisters, SnsInitPayloadsBuilder, UserInfo,
};
use itertools::Itertools;
use lazy_static::lazy_static;
use ledger_canister::Tokens;
use maplit::btreeset;
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};

// The minimum WASM payload.
lazy_static! {
    pub static ref EMPTY_WASM: Vec<u8> = vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0];
}

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

            let summary: Vec<(String, PrincipalId, CanisterStatusResultV2)> = sns_canisters
                .root
                .update_(
                    "get_sns_canisters_summary",
                    candid_one,
                    Vec::<PrincipalId>::new(), // dapp_canisters
                )
                .await
                .expect("Could not get SNS summary");

            let summary = summary
                .iter()
                .map(|(name, principal_id, _)| (name.clone(), *principal_id))
                .collect::<BTreeSet<_>>();

            assert_eq!(
                summary,
                btreeset! {
                    ("governance".to_string(), sns_canisters.governance.canister_id().get()),
                    ("ledger".to_string(), sns_canisters.ledger.canister_id().get()),
                    ("root".to_string(), sns_canisters.root.canister_id().get())
                }
            );

            Ok(())
        }
    })
}

#[test]
fn governance_mem_test() {
    local_test_on_sns_subnet(|mut runtime| async move {
        println!("Initializing governance mem test canister...");

        if let Runtime::Local(local_runtime) = &mut runtime {
            local_runtime.ingress_time_limit = Duration::from_secs(20 * 60);
        }

        let mut governance = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .unwrap();

        let state_initializer_wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
            "sns/integration_tests",
            "sns-governance-mem-test-canister",
            &[],
        );

        // It's on purpose that we don't want retries here! This test is only about
        // initializing a canister with a very large state. A failure is most
        // likely repeatable, so the test will fail much faster without retries.
        let install = state_initializer_wasm
            .install(&runtime)
            .with_mode(CanisterInstallMode::Install);
        install.install(&mut governance, Vec::new()).await.unwrap();

        // Now let's upgrade to the real governance canister
        let real_wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
            "sns/governance",
            "sns-governance-canister",
            &[],
        );
        governance.set_wasm(real_wasm.bytes());

        // Exercise canister_post_upgrade of the real canister
        governance
            .upgrade_to_self_binary(/* arg passed to post-upgrade: */ Vec::new())
            .await
            .unwrap();

        // Exercise canister_pre_upgrade (and post upgrade again) of the real canister
        governance
            .upgrade_to_self_binary(/* arg passed to post-upgrade: */ Vec::new())
            .await
            .unwrap();

        Ok(())
    });
}

/// This is a regression test: it used to be that, if two upgrades happened in a
/// row, with the stable memory of the second being smaller than for the first,
/// the second upgrade would read too many bytes from stable memory, resulting
/// in a trap in post_upgrade.
#[test]
fn test_upgrade_after_state_shrink() {
    local_test_on_sns_subnet(|runtime| async move {
        // Initialize a User with a unique principal to claim a neuron
        let neuron_claimer = UserInfo::new(Sender::from_keypair(&TEST_USER1_KEYPAIR));
        // Initialize an extra user who's unique principal will be used to shrink the state
        let extra_user = UserInfo::new(Sender::from_keypair(&TEST_USER2_KEYPAIR));
        let alloc = Tokens::from_tokens(1000).unwrap();

        let system_params = NervousSystemParameters {
            neuron_claimer_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            neuron_grantable_permissions: Some(NeuronPermissionList {
                permissions: NeuronPermissionType::all(),
            }),
            ..NervousSystemParameters::with_default_values()
        };

        let sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_ledger_account(neuron_claimer.sender.get_principal_id().into(), alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Stake and claim a neuron using the `neuron_claimer` user
        sns_canisters
            .stake_and_claim_neuron(&neuron_claimer.sender, Some(ONE_YEAR_SECONDS as u32))
            .await;

        // Use the neuron_claimer to add the extra_user's unique principal as a permission to
        // the neuron. This permission is what will shrink the state after the update.
        sns_canisters
            .add_neuron_permissions(
                &neuron_claimer.sender,
                &neuron_claimer.subaccount,
                Some(extra_user.sender.get_principal_id()),
                vec![NeuronPermissionType::Vote as i32],
            )
            .await;

        // Get the WASM of the sns-governance canister to be used in the upgrades
        let governance_wasm = Project::cargo_bin_maybe_use_path_relative_to_rs(
            "sns/governance",
            "sns-governance-canister",
            &[], // features
        )
        .bytes();

        // Create and submit an upgrade proposal to trigger the first "write and read" of
        // stable memory for the governance canister.
        let proposal = Proposal {
            title: "Upgrade governance.".into(),
            action: Some(Action::UpgradeSnsControlledCanister(
                UpgradeSnsControlledCanister {
                    canister_id: Some(sns_canisters.governance.canister_id().into()),
                    new_canister_wasm: governance_wasm,
                },
            )),
            ..Default::default()
        };

        sns_canisters
            .make_proposal(
                &neuron_claimer.sender,
                &neuron_claimer.subaccount,
                proposal.clone(),
            )
            .await
            .unwrap();

        sns_canisters
            .await_canister_upgrade(sns_canisters.governance.canister_id())
            .await;

        // Now that the first upgrade is complete, shrink the state by removing the NeuronPermission
        // granted to the extra_voter user.
        sns_canisters
            .remove_neuron_permissions(
                &neuron_claimer.sender,
                &neuron_claimer.subaccount,
                &extra_user.sender.get_principal_id(),
                vec![NeuronPermissionType::Vote as i32],
            )
            .await;

        // Submit the same upgrade proposal to trigger the second "write and read" of
        // stable memory for the governance canister.
        sns_canisters
            .make_proposal(&neuron_claimer.sender, &neuron_claimer.subaccount, proposal)
            .await
            .unwrap();

        // Await the canister upgrade to complete. If the upgrade completes we know that
        // the canister completed it pre-upgrade and post-upgrade cycle successfully
        sns_canisters
            .await_canister_upgrade(sns_canisters.governance.canister_id())
            .await;

        Ok(())
    });
}

/// Test that SNS canisters can be installed in any order.
#[test]
fn test_install_canisters_in_any_order() {
    local_test_on_sns_subnet(|runtime| async move {
        let mut sns_init_payload = SnsInitPayloadsBuilder::new()
            .with_nervous_system_parameters(NervousSystemParameters::with_default_values())
            .build();

        // Initialize the SNS canisters but do not install any canister code
        let mut root = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Couldn't create Root canister");

        let mut governance = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Couldn't create Governance canister");

        let mut ledger = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Couldn't create Ledger canister");

        let root_canister_id = root.canister_id();
        let governance_canister_id = governance.canister_id();
        let ledger_canister_id = ledger.canister_id();

        // Populate the minimal set of fields for install
        sns_init_payload.governance.ledger_canister_id = Some(ledger_canister_id.into());
        sns_init_payload.governance.root_canister_id = Some(root_canister_id.into());
        sns_init_payload.root.governance_canister_id = Some(governance_canister_id.into());
        sns_init_payload.root.ledger_canister_id = Some(ledger_canister_id.into());

        // Use canister tags to generate all the permutations needed to test random order installs
        let canister_tags = vec!["governance", "ledger", "root"];

        // Generate the permutations
        let permutation_size = canister_tags.len();
        let canister_install_order_permutations =
            canister_tags.into_iter().permutations(permutation_size);

        for canister_install_order in canister_install_order_permutations {
            println!("Testing install order: {:?}", canister_install_order);
            for canister_tag in canister_install_order {
                println!("Starting install of {}", canister_tag);

                // Match the canister tag and wait for the install to complete to guarantee the
                // order
                match canister_tag {
                    "governance" => {
                        install_governance_canister(
                            &mut governance,
                            sns_init_payload.governance.clone(),
                        )
                        .await
                    }
                    "ledger" => {
                        install_ledger_canister(&mut ledger, sns_init_payload.ledger.clone()).await
                    }
                    "root" => install_root_canister(&mut root, sns_init_payload.root.clone()).await,
                    _ => panic!("Unexpected canister tag"),
                };
                println!("Successfully installed {}", canister_tag);
            }

            // After each permutation, reset all the canisters to the empty wasm to
            // test the next install order
            reset_canister_to_empty_wasm(&mut governance).await;
            reset_canister_to_empty_wasm(&mut ledger).await;
            reset_canister_to_empty_wasm(&mut root).await;
        }

        Ok(())
    });
}

async fn reset_canister_to_empty_wasm(canister: &mut Canister<'_>) {
    let wasm: Wasm = Wasm::from_bytes(EMPTY_WASM.clone());
    wasm.install_with_retries_onto_canister(canister, None, None)
        .await
        .unwrap_or_else(|e| panic!("Could not install empty wasm due to {}", e));
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
