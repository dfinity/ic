use candid::Encode;
use canister_test::{Canister, Project, Runtime, Wasm};
use dfn_candid::candid_one;
use dfn_core::bytes;
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_client_sender::Sender;
use ic_ledger_core::Tokens;
use ic_management_canister_types::{CanisterInstallMode, CanisterSettingsArgsBuilder};
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{CanisterStatusResult, CanisterStatusType},
};
use ic_nervous_system_common::ONE_YEAR_SECONDS;
use ic_nervous_system_common_test_keys::{TEST_USER1_KEYPAIR, TEST_USER2_KEYPAIR};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID};
use ic_nns_test_utils::state_test_helpers::{
    create_canister, sns_claim_staked_neuron, sns_make_proposal, sns_stake_neuron,
    sns_wait_for_proposal_execution, update,
};
use ic_protobuf::types::v1::CanisterInstallMode as CanisterInstallModeProto;
use ic_sns_governance::pb::v1::{
    governance_error::ErrorType, proposal::Action, NervousSystemParameters, NeuronId,
    NeuronPermissionList, NeuronPermissionType, Proposal, UpgradeSnsControlledCanister,
};
use ic_sns_test_utils::{
    itest_helpers::{
        install_governance_canister, install_ledger_canister, install_root_canister,
        install_swap_canister, local_test_on_sns_subnet, state_machine_test_on_sns_subnet,
        SnsCanisters, SnsTestsInitPayloadBuilder, UserInfo,
    },
    state_test_helpers::{
        setup_sns_canisters, sns_root_register_dapp_canisters, state_machine_builder_for_sns_tests,
        SnsTestCanisterIds,
    },
};
use ic_state_machine_tests::StateMachine;
use ic_universal_canister::{wasm, UNIVERSAL_CANISTER_WASM};
use itertools::Itertools;
use lazy_static::lazy_static;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::Duration;

// The minimum WASM payload.
lazy_static! {
    pub static ref EMPTY_WASM: Vec<u8> = vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0];
}

// Note: Tests for UpgradeSnsToNextVersion action is in rs/nns/sns-wasm/tests/upgrade_sns_instance.rs

fn setup_sns(
    state_machine: &StateMachine,
) -> (SnsTestCanisterIds, CanisterId, PrincipalId, NeuronId) {
    // Step 1.a: Boot up SNS with one user.
    let user = PrincipalId::new_user_test_id(0);
    let alloc = Tokens::from_tokens(1000).unwrap();

    let system_params = NervousSystemParameters {
        neuron_claimer_permissions: Some(NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        }),
        ..NervousSystemParameters::with_default_values()
    };

    let sns_init_payload = SnsTestsInitPayloadBuilder::new()
        .with_ledger_account(user.0.into(), alloc)
        .with_nervous_system_parameters(system_params)
        .build();

    let canister_ids = setup_sns_canisters(state_machine, sns_init_payload);

    let dapp_canister_id = create_canister(
        state_machine,
        Wasm::from_bytes(EMPTY_WASM.clone()),
        Some(Encode!().unwrap()),
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![canister_ids.root_canister_id.get()])
                .with_memory_allocation(2 << 30)
                .build(),
        ),
    );

    sns_stake_neuron(
        state_machine,
        canister_ids.governance_canister_id,
        canister_ids.ledger_canister_id,
        user,
        Tokens::from_tokens(1).unwrap(),
        1,
    );
    let neuron_id = sns_claim_staked_neuron(
        state_machine,
        canister_ids.governance_canister_id,
        user,
        1,
        Some(ONE_YEAR_SECONDS as u32),
    );

    sns_root_register_dapp_canisters(
        state_machine,
        canister_ids.root_canister_id,
        canister_ids.governance_canister_id,
        vec![dapp_canister_id],
    );

    let new_dapp_wasm = Wasm::from_bytes(UNIVERSAL_CANISTER_WASM).bytes();
    let new_dapp_wasm_hash = &ic_crypto_sha2::Sha256::hash(&new_dapp_wasm);

    let status = state_machine
        .canister_status_as(canister_ids.root_canister_id.get(), dapp_canister_id)
        .unwrap()
        .unwrap();
    assert_eq!(status.memory_allocation(), 2 << 30);
    assert_ne!(status.module_hash().unwrap(), new_dapp_wasm_hash.to_vec());

    (canister_ids, dapp_canister_id, user, neuron_id)
}

#[test]
fn test_upgrade_canister_proposal_is_successful() {
    let state_machine = state_machine_builder_for_sns_tests().build();
    let (canister_ids, dapp_canister_id, user, neuron_id) = setup_sns(&state_machine);

    let new_dapp_wasm = Wasm::from_bytes(UNIVERSAL_CANISTER_WASM).bytes();
    let new_dapp_wasm_hash = &ic_crypto_sha2::Sha256::hash(&new_dapp_wasm);

    // Step 2.b: Make the proposal. (This should get executed right
    // away, because the proposing neuron is the only neuron.)
    let proposal = Proposal {
        title: "Upgrade dapp.".into(),
        action: Some(Action::UpgradeSnsControlledCanister(
            UpgradeSnsControlledCanister {
                canister_id: Some(dapp_canister_id.get()),
                new_canister_wasm: new_dapp_wasm,
                canister_upgrade_arg: Some(wasm().set_global_data(&[42]).build()),
                // mode: None corresponds to CanisterInstallModeProto::Upgrade
                mode: None,
            },
        )),
        ..Default::default()
    };
    let proposal_id = sns_make_proposal(
        &state_machine,
        canister_ids.governance_canister_id,
        user,
        neuron_id,
        proposal,
    )
    .unwrap();

    sns_wait_for_proposal_execution(
        &state_machine,
        canister_ids.governance_canister_id,
        proposal_id,
    );

    for _ in 1..100 {
        state_machine.advance_time(Duration::from_secs(1));
        state_machine.tick();
    }

    let status = state_machine
        .canister_status_as(canister_ids.root_canister_id.get(), dapp_canister_id)
        .unwrap()
        .unwrap();
    // Assert that memory allocation is not changed.
    assert_eq!(status.memory_allocation(), 2 << 30);
    assert_eq!(status.module_hash().unwrap(), new_dapp_wasm_hash.to_vec());

    // Check that arg to post-upgrade method was passed to the new wasm module.
    let result = update(
        &state_machine,
        dapp_canister_id,
        "update",
        wasm().get_global_data().append_and_reply().build(),
    )
    .expect("Couldn't build update args");
    assert_eq!(result, vec![42]);
}

#[test]
fn test_upgrade_canister_proposal_reinstall() {
    local_test_on_sns_subnet(|runtime| async move {
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(user.get_principal_id().0.into(), alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let mut dapp_canister = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Could not create dapp canister");

        let dapp_wasm = Wasm::from_bytes(UNIVERSAL_CANISTER_WASM);

        dapp_wasm
            .install_with_retries_onto_canister(
                &mut dapp_canister,
                Some(wasm().stable_grow(42).build()),
                None,
            )
            .await
            .unwrap();
        // Check that stable memory was grown.
        let res: Vec<u8> = dapp_canister
            .update_(
                "update",
                bytes,
                wasm()
                    .stable_size()
                    .int_to_blob()
                    .append_and_reply()
                    .build(),
            )
            .await
            .unwrap();
        assert_eq!(res, vec![42, 0, 0, 0]);

        dapp_canister
            .set_controller(sns_canisters.root.canister_id().get())
            .await
            .expect("Could not set root as controller of dapp");

        // Step 1.b: Create a neuron.
        let neuron_id = sns_canisters
            .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
            .await;
        let subaccount = neuron_id
            .subaccount()
            .expect("Error creating the subaccount");

        sns_canisters
            .register_dapp_canister(&user, &neuron_id, dapp_canister.canister_id())
            .await;

        // Step 2: Execute code under test: Propose that we upgrade dapp.
        // (This should get executed right away,
        // because the proposing neuron is the only neuron.)
        let new_dapp_wasm = Wasm::from_bytes(UNIVERSAL_CANISTER_WASM).bytes();
        let new_dapp_wasm_hash = &ic_crypto_sha2::Sha256::hash(&new_dapp_wasm);
        let proposal = Proposal {
            title: "Reinstall dapp.".into(),
            action: Some(Action::UpgradeSnsControlledCanister(
                UpgradeSnsControlledCanister {
                    canister_id: Some(dapp_canister.canister_id().get()),
                    new_canister_wasm: new_dapp_wasm,
                    canister_upgrade_arg: Some(wasm().build()),
                    mode: Some(CanisterInstallModeProto::Reinstall.into()),
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
        let proposal = sns_canisters
            .await_proposal_execution_or_failure(&proposal_id)
            .await;

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

        // Step 3.b: Wait until new dapp is running.
        let status = sns_canisters
            .await_canister_upgrade(dapp_canister.canister_id())
            .await;

        // Step 3.c: Assert that the new wasm hash is new_dapp_wasm_hash.
        assert_eq!(
            status.module_hash.as_ref().unwrap()[..],
            new_dapp_wasm_hash[..],
            "status: {:?}",
            status
        );
        // Check that stable memory was erased during reinstall.
        let res: Vec<u8> = dapp_canister
            .update_(
                "update",
                bytes,
                wasm()
                    .stable_size()
                    .int_to_blob()
                    .append_and_reply()
                    .build(),
            )
            .await
            .unwrap();
        assert_eq!(res, vec![0, 0, 0, 0]);

        Ok(())
    })
}

#[test]
fn test_upgrade_canister_proposal_execution_fail() {
    local_test_on_sns_subnet(|runtime| async move {
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

        let mut sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(user.get_principal_id().0.into(), alloc)
            .with_nervous_system_parameters(system_params)
            .build();

        // Step 1.b: Sabotage: Unlike the previous test, we configure root
        // so that it does not recognize governance as the true governance
        // canister of this SNS. As a result, when governance tries to
        // execute a canister upgrade proposal (in step 2.b), the request
        // from governance to root gets rejected by root.
        sns_init_payload.root.governance_canister_id = Some(user.get_principal_id());

        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        let mut dapp_canister = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Could not create dapp canister");

        let dapp_wasm = Wasm::from_bytes(EMPTY_WASM.clone());

        dapp_wasm
            .install_with_retries_onto_canister(&mut dapp_canister, Some(Encode!().unwrap()), None)
            .await
            .unwrap();

        dapp_canister
            .set_controller(sns_canisters.root.canister_id().get())
            .await
            .expect("Could not set root as controller of dapp");

        // Step 1.c: Create a neuron.
        let neuron_id = sns_canisters
            .stake_and_claim_neuron(&user, Some(ONE_YEAR_SECONDS as u32))
            .await;
        let subaccount = neuron_id
            .subaccount()
            .expect("Error creating the subaccount");

        sns_canisters
            .register_dapp_canister(&user, &neuron_id, dapp_canister.canister_id())
            .await;

        // Step 2: Execute code under test: Propose that we upgrade dapp.

        // Step 2.a: Make sure that the proposal will have a discernible
        // effect (verified in Step 3). Specifically, that the wasm will
        // have changed (upon successful execution).
        let status: CanisterStatusResult = sns_canisters
            .root
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(dapp_canister.canister_id()),
            )
            .await
            .unwrap();
        let original_dapp_wasm_hash = status.module_hash.unwrap();

        // Assert that original_dapp_wasm_hash differs from the hash of
        // the wasm that we're about to (attempt to) install.
        let new_dapp_wasm =
            Wasm::from_wat("(module (import \"ic0\" \"msg_reply\" (func $msg_reply)))").bytes();

        let new_dapp_wasm_hash = &ic_crypto_sha2::Sha256::hash(&new_dapp_wasm);
        assert_ne!(new_dapp_wasm_hash[..], original_dapp_wasm_hash[..]);

        // Step 2.b: Make the proposal. (This should get executed right
        // away, because the proposing neuron is the only neuron.)
        let proposal = Proposal {
            title: "Upgrade dapp.".into(),
            action: Some(Action::UpgradeSnsControlledCanister(
                UpgradeSnsControlledCanister {
                    canister_id: Some(dapp_canister.canister_id().get()),
                    new_canister_wasm: new_dapp_wasm,
                    canister_upgrade_arg: None,
                    mode: Some(CanisterInstallModeProto::Upgrade.into()),
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
        // Clear wasm and arg fields to avoid giant debug output.
        match proposal.proposal.as_mut().unwrap().action.as_mut().unwrap() {
            Action::UpgradeSnsControlledCanister(upgrade) => {
                upgrade.new_canister_wasm = vec![];
                upgrade.canister_upgrade_arg = None;
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

        // Step 3.b: Assert that dapp is running the original wasm.
        let status: CanisterStatusResult = sns_canisters
            .root
            .update_(
                "canister_status",
                candid_one,
                CanisterIdRecord::from(dapp_canister.canister_id()),
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
            original_dapp_wasm_hash[..],
            "status: {:?}",
            status,
        );

        Ok(())
    })
}

#[test]
fn test_upgrade_canister_proposal_too_large() {
    let state_machine = state_machine_builder_for_sns_tests().build();
    let (canister_ids, dapp_canister_id, user, neuron_id) = setup_sns(&state_machine);

    let new_dapp_wasm = Wasm::from_bytes(UNIVERSAL_CANISTER_WASM).bytes();

    // Step 2.b: Make the proposal. (This should get executed right
    // away, because the proposing neuron is the only neuron.)
    let proposal = Proposal {
        title: "Upgrade dapp.".into(),
        action: Some(Action::UpgradeSnsControlledCanister(
            UpgradeSnsControlledCanister {
                canister_id: Some(dapp_canister_id.get()),
                new_canister_wasm: new_dapp_wasm,
                canister_upgrade_arg: Some(wasm().set_global_data(&[42; 2_000_000]).build()),
                // mode: None corresponds to CanisterInstallModeProto::Upgrade
                mode: None,
            },
        )),
        ..Default::default()
    };
    let error = sns_make_proposal(
        &state_machine,
        canister_ids.governance_canister_id,
        user,
        neuron_id,
        proposal,
    )
    .unwrap_err();
    assert!(error.error_message.contains("the maximum canister WASM and argument size for UpgradeSnsControlledCanister is 2000000 bytes."));
}

#[test]
fn governance_mem_test() {
    state_machine_test_on_sns_subnet(|runtime| async move {
        println!("Initializing governance mem test canister...");

        let mut runtime = runtime;
        if let Runtime::Local(local_runtime) = &mut runtime {
            local_runtime.ingress_time_limit = Duration::from_secs(20 * 60);
        }

        let mut governance = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .unwrap();

        let state_initializer_wasm =
            Project::cargo_bin_maybe_from_env("sns-governance-mem-test-canister", &[]);

        // It's on purpose that we don't want retries here! This test is only about
        // initializing a canister with a very large state. A failure is most
        // likely repeatable, so the test will fail much faster without retries.
        let install = state_initializer_wasm
            .install(&runtime)
            .with_mode(CanisterInstallMode::Install);
        install.install(&mut governance, Vec::new()).await.unwrap();

        // Now let's upgrade to the real governance canister
        let real_wasm = Project::cargo_bin_maybe_from_env("sns-governance-canister", &[]);
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

        let sns_init_payload = SnsTestsInitPayloadBuilder::new()
            .with_ledger_account(neuron_claimer.sender.get_principal_id().0.into(), alloc)
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
            .add_neuron_permissions_or_panic(
                &neuron_claimer.sender,
                &neuron_claimer.subaccount,
                Some(extra_user.sender.get_principal_id()),
                vec![NeuronPermissionType::Vote as i32],
            )
            .await;

        // Get the WASM of the sns-governance canister to be used in the upgrades
        let governance_wasm = Project::cargo_bin_maybe_from_env("sns-governance-canister", &[]) // features
            .bytes();

        // Create and submit an upgrade proposal to trigger the first "write and read" of
        // stable memory for the governance canister.
        let proposal = Proposal {
            title: "Upgrade governance.".into(),
            action: Some(Action::UpgradeSnsControlledCanister(
                UpgradeSnsControlledCanister {
                    canister_id: Some(sns_canisters.governance.canister_id().into()),
                    new_canister_wasm: governance_wasm,
                    canister_upgrade_arg: None,
                    mode: Some(CanisterInstallModeProto::Upgrade.into()),
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
            .remove_neuron_permissions_or_panic(
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
        let mut sns_init_payload = SnsTestsInitPayloadBuilder::new()
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

        let mut swap = runtime
            .create_canister_max_cycles_with_retries()
            .await
            .expect("Couldn't create Sale canister");

        let root_canister_id = root.canister_id();
        let governance_canister_id = governance.canister_id();
        let ledger_canister_id = ledger.canister_id();
        let swap_canister_id = swap.canister_id();

        // Populate the minimal set of fields for install
        sns_init_payload.governance.ledger_canister_id = Some(ledger_canister_id.into());
        sns_init_payload.governance.root_canister_id = Some(root_canister_id.into());
        sns_init_payload.governance.swap_canister_id = Some(swap_canister_id.into());
        sns_init_payload.root.governance_canister_id = Some(governance_canister_id.into());
        sns_init_payload.root.ledger_canister_id = Some(ledger_canister_id.into());
        sns_init_payload.root.swap_canister_id = Some(swap_canister_id.into());

        sns_init_payload.swap.nns_governance_canister_id = GOVERNANCE_CANISTER_ID.to_string();
        sns_init_payload.swap.sns_governance_canister_id = governance_canister_id.to_string();
        sns_init_payload.swap.sns_ledger_canister_id = ledger_canister_id.to_string();
        sns_init_payload.swap.icp_ledger_canister_id = LEDGER_CANISTER_ID.to_string();
        sns_init_payload.swap.sns_root_canister_id = root_canister_id.to_string();
        sns_init_payload.swap.fallback_controller_principal_ids =
            vec![CanisterId::from_u64(900).get().to_string()];

        // Use canister tags to generate all the permutations needed to test random order installs
        let canister_tags = vec!["governance", "ledger", "root", "swap"];

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
                    "swap" => install_swap_canister(&mut swap, sns_init_payload.swap.clone()).await,
                    _ => panic!("Unexpected canister tag"),
                };
                println!("Successfully installed {}", canister_tag);
            }

            // After each permutation, reset all the canisters to the empty wasm to
            // test the next install order
            reset_canister_to_empty_wasm(&mut governance).await;
            reset_canister_to_empty_wasm(&mut ledger).await;
            reset_canister_to_empty_wasm(&mut root).await;
            reset_canister_to_empty_wasm(&mut swap).await;
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
