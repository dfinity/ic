use candid::{Decode, Encode};
use canister_test::Project;
use dfn_candid::{candid, candid_one};
use ic_base_types::{CanisterId, PrincipalId};
use ic_ledger_core::Tokens;
use ic_management_canister_types::CanisterInstallMode;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{CanisterStatusResult, CanisterStatusType},
};
use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_test_utils::state_test_helpers::{get_controllers, set_controllers, update_with_sender};
use ic_sns_root::{
    pb::v1::SnsRootCanister, GetSnsCanistersSummaryRequest, GetSnsCanistersSummaryResponse,
};
use ic_sns_test_utils::{
    itest_helpers::{
        local_test_on_sns_subnet, set_up_root_canister, SnsCanisters, SnsTestsInitPayloadBuilder,
    },
    state_test_helpers::{
        sns_root_register_dapp_canister, sns_root_register_dapp_canisters,
        state_machine_builder_for_sns_tests, Scenario,
    },
};
use ic_state_machine_tests::StateMachine;
use ic_types::ingress::WasmResult;
use ic_universal_canister::UNIVERSAL_CANISTER_WASM;
use std::{collections::BTreeSet, time::Duration};

#[test]
fn test_get_status() {
    local_test_on_sns_subnet(|runtime| async move {
        // Step 1: Prepare: Create root canister.
        let root = set_up_root_canister(
            &runtime,
            SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(42)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(43)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(44)),
                dapp_canister_ids: vec![],
                archive_canister_ids: vec![],
                latest_ledger_archive_poll_timestamp_seconds: None,
                index_canister_id: Some(PrincipalId::new_user_test_id(45)),
                testflight: false,
                updated_framework_canisters_memory_limit: Some(true),
            },
        )
        .await;

        // To get the status of a canister A from canister B, B must control A.
        // In this case, we only have one canister, root. So we make it play
        // both roles by making it a controller of itself.
        root.set_controller_with_retries(root.canister_id().get())
            .await
            .unwrap();

        // Step 2: Execute: Send canister_status request.
        let response: CanisterStatusResult = root
            .update_(
                "canister_status",
                candid,
                (CanisterIdRecord::from(root.canister_id()),),
            )
            .await
            .unwrap();

        // Step 3: Inspect the response. We're not looking for anything in
        // particular, but since root has replied, it must be in the running
        // state, so we might as well assert that the response reflects this.
        assert_eq!(
            response.status,
            CanisterStatusType::Running,
            "response: {:?}",
            response
        );

        Ok(())
    });
}

#[test]
fn test_get_sns_canisters_summary() {
    local_test_on_sns_subnet(|runtime| async move {
        // Create and setup a basic SNS
        let sns_init_payload = SnsTestsInitPayloadBuilder::new().build();
        let sns_canisters = SnsCanisters::set_up(&runtime, sns_init_payload).await;

        // Get the status of the SNS using get_sns_canisters_summary
        let response = sns_canisters.get_sns_canisters_summary(None).await;

        // Assert that all the canisters returned a canister summary
        assert!(response.root.is_some());
        assert!(response.governance.is_some());
        assert!(response.ledger.is_some());
        assert!(response.swap.is_some());

        // Assert that the canister_ids match what was set up
        assert_eq!(
            response.root_canister_summary().canister_id(),
            sns_canisters.root.canister_id().get()
        );
        assert_eq!(
            response.governance_canister_summary().canister_id(),
            sns_canisters.governance.canister_id().get()
        );
        assert_eq!(
            response.ledger_canister_summary().canister_id(),
            sns_canisters.ledger.canister_id().get()
        );
        assert_eq!(
            response.swap_canister_summary().canister_id(),
            sns_canisters.swap.canister_id().get()
        );

        Ok(())
    });
}

#[test]
fn test_register_dapp_canister() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    let scenario = Scenario::new(&state_machine, Tokens::from_tokens(100).unwrap());
    scenario.init_all_canisters(&state_machine);

    // Get the status of the SNS using get_sns_canisters_summary
    let response =
        root_get_sns_canisters_summary(&scenario, &state_machine, scenario.root_canister_id);

    assert!(response.dapps.is_empty());

    for dapp_canister_id in scenario.dapp_canister_ids.iter() {
        set_controllers(
            &state_machine,
            *TEST_USER1_PRINCIPAL,
            *dapp_canister_id,
            vec![scenario.root_canister_id.into()],
        );
    }

    for dapp_canister_id in scenario.dapp_canister_ids.clone() {
        let _response = sns_root_register_dapp_canister(
            &state_machine,
            scenario.root_canister_id,
            scenario.governance_canister_id,
            dapp_canister_id,
        );
    }

    let response =
        root_get_sns_canisters_summary(&scenario, &state_machine, scenario.root_canister_id);

    assert!(!response.dapps.is_empty());
    assert_eq!(
        response.dapps[0].canister_id(),
        scenario.dapp_canister_ids[0].into()
    );
}

#[test]
fn test_register_dapp_canisters() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    let scenario = Scenario::new(&state_machine, Tokens::from_tokens(100).unwrap());
    scenario.init_all_canisters(&state_machine);

    // Get the status of the SNS using get_sns_canisters_summary
    let response =
        root_get_sns_canisters_summary(&scenario, &state_machine, scenario.root_canister_id);

    assert!(response.dapps.is_empty());

    for dapp_canister_id in scenario.dapp_canister_ids.iter() {
        set_controllers(
            &state_machine,
            *TEST_USER1_PRINCIPAL,
            *dapp_canister_id,
            vec![scenario.root_canister_id.into()],
        );
    }
    let _response = sns_root_register_dapp_canisters(
        &state_machine,
        scenario.root_canister_id,
        scenario.governance_canister_id,
        scenario.dapp_canister_ids.clone(),
    );

    let response =
        root_get_sns_canisters_summary(&scenario, &state_machine, scenario.root_canister_id);

    assert!(!response.dapps.is_empty());
    assert_eq!(
        response.dapps[0].canister_id(),
        scenario.dapp_canister_ids[0].into()
    );
}

#[test]
fn test_register_dapp_canisters_removes_other_controllers() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    let scenario = Scenario::new(&state_machine, Tokens::from_tokens(100).unwrap());
    scenario.init_all_canisters(&state_machine);

    // Get the status of the SNS using get_sns_canisters_summary
    let response =
        root_get_sns_canisters_summary(&scenario, &state_machine, scenario.root_canister_id);

    assert!(response.dapps.is_empty());

    // Make sure all the dapp canisters have at a controller besides the root
    // canister
    let controllers_to_set = vec![scenario.root_canister_id.into(), *TEST_USER1_PRINCIPAL];
    for dapp_canister_id in scenario.dapp_canister_ids.iter() {
        set_controllers(
            &state_machine,
            *TEST_USER1_PRINCIPAL,
            *dapp_canister_id,
            // Make sure TEST_USER1_PRINCIPAL is also a controller
            controllers_to_set.clone(),
        );

        let observed_controllers =
            get_controllers(&state_machine, *TEST_USER1_PRINCIPAL, *dapp_canister_id);
        assert_eq!(
            observed_controllers.into_iter().collect::<BTreeSet<_>>(),
            controllers_to_set.clone().into_iter().collect()
        );
    }
    // Register the dapp canisters
    let _response = sns_root_register_dapp_canisters(
        &state_machine,
        scenario.root_canister_id,
        scenario.governance_canister_id,
        scenario.dapp_canister_ids.clone(),
    );

    let response =
        root_get_sns_canisters_summary(&scenario, &state_machine, scenario.root_canister_id);

    assert!(!response.dapps.is_empty());
    assert_eq!(
        response.dapps[0].canister_id(),
        scenario.dapp_canister_ids[0].into()
    );

    for dapp_canister_id in scenario.dapp_canister_ids.iter() {
        let controllers = get_controllers(
            &state_machine,
            scenario.root_canister_id.into(),
            *dapp_canister_id,
        );
        assert_eq!(controllers, vec![scenario.root_canister_id.into()]);
    }
}

#[test]
fn test_root_restarts_governance_on_stop_canister_timeout() {
    let state_machine = state_machine_builder_for_sns_tests().build();

    let scenario = Scenario::new(&state_machine, Tokens::from_tokens(100).unwrap());
    scenario.init_all_canisters(&state_machine);

    let get_gov_status = || {
        let response =
            root_get_sns_canisters_summary(&scenario, &state_machine, scenario.root_canister_id);

        response.governance.unwrap().status.unwrap().status
    };

    let get_gov_hash = || {
        let response =
            root_get_sns_canisters_summary(&scenario, &state_machine, scenario.root_canister_id);
        response
            .governance
            .unwrap()
            .status
            .unwrap()
            .module_hash
            .unwrap()
    };

    // Uninstall and reinstall so we get our killer feature from the unstoppable canister
    let _: () = update_with_sender(
        &state_machine,
        CanisterId::ic_00(),
        "uninstall_code",
        candid_one,
        CanisterIdRecord::from(scenario.governance_canister_id),
        scenario.root_canister_id.get(),
    )
    .unwrap();

    state_machine
        .install_wasm_in_mode(
            scenario.governance_canister_id,
            CanisterInstallMode::Install,
            Project::cargo_bin_maybe_from_env("unstoppable-canister", &[]).bytes(),
            vec![],
        )
        .unwrap();

    let installed_gov_hash = get_gov_hash();

    state_machine.advance_time(Duration::from_secs(1));
    state_machine.tick();

    assert_eq!(get_gov_status(), CanisterStatusType::Running);

    let wasm_module = UNIVERSAL_CANISTER_WASM.to_vec();

    let proposal = ChangeCanisterRequest {
        stop_before_installing: true,
        mode: CanisterInstallMode::Upgrade,
        canister_id: GOVERNANCE_CANISTER_ID,
        wasm_module,
        arg: vec![],
        compute_allocation: None,
        memory_allocation: None,
    };

    let _: () = update_with_sender(
        &state_machine,
        scenario.root_canister_id,
        "change_canister",
        candid_one,
        proposal,
        scenario.governance_canister_id.get(),
    )
    .expect("Didn't work");

    state_machine.tick();

    // After 60 seconds, canister is still trying to stop...
    state_machine.advance_time(Duration::from_secs(60));
    state_machine.tick();

    assert_eq!(get_gov_status(), CanisterStatusType::Stopping);

    state_machine.advance_time(Duration::from_secs(241));
    state_machine.tick();
    state_machine.tick();

    assert_eq!(get_gov_status(), CanisterStatusType::Running);
    // We assert no upgrade happened.
    assert_eq!(get_gov_hash(), installed_gov_hash)
}

fn root_get_sns_canisters_summary(
    scenario: &Scenario,
    state_machine: &StateMachine,
    root_canister_id: CanisterId,
) -> GetSnsCanistersSummaryResponse {
    let request = GetSnsCanistersSummaryRequest {
        update_canister_list: None,
    };

    let result = state_machine
        .execute_ingress(
            root_canister_id,
            "get_sns_canisters_summary",
            Encode!(&request).unwrap(),
        )
        .unwrap();
    let result = match result {
        WasmResult::Reply(reply) => reply,
        WasmResult::Reject(reject) => {
            panic!(
                "get_sns_canisters_summary was rejected by the swap canister: {:#?}",
                reject
            )
        }
    };
    let response = Decode!(&result, GetSnsCanistersSummaryResponse).unwrap();

    // Assert that all the canisters returned a canister summary
    assert!(response.root.is_some());
    assert!(response.governance.is_some());
    assert!(response.ledger.is_some());
    assert!(response.swap.is_some());

    // Assert that the canister_ids match what was set up
    assert_eq!(
        response.root_canister_summary().canister_id(),
        scenario.root_canister_id.into()
    );
    assert_eq!(
        response.governance_canister_summary().canister_id(),
        scenario.governance_canister_id.into()
    );
    assert_eq!(
        response.ledger_canister_summary().canister_id(),
        scenario.ledger_canister_id.into()
    );
    assert_eq!(
        response.swap_canister_summary().canister_id(),
        scenario.swap_canister_id.into()
    );

    response
}
