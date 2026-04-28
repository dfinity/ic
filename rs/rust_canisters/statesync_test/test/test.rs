use candid::{Decode, Encode};
use canister_test::*;
use ic_management_canister_types_private::CanisterSettingsArgsBuilder;
use ic_state_machine_tests::{ErrorCode, StateMachine};
use statesync_test::CanisterCreationStatus;

fn deploy_state_sync_test_canister(env: &StateMachine) -> CanisterId {
    let features = [];
    let wasm = Project::cargo_bin_maybe_from_env("statesync-test-canister", &features);
    env.install_canister(
        wasm.bytes(),
        vec![],
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_memory_allocation(8 * 1024 * 1024 * 1024)
                .build(),
        ),
    )
    .expect("Failed to install canister")
}

#[test]
fn test_statesync_test_canisters() {
    let env = StateMachine::new();

    let canister_id = deploy_state_sync_test_canister(&env);
    let result = env
        .query(canister_id, "read_state", Encode!(&0_usize).unwrap())
        .unwrap();
    let res = assert_reply(result);
    let val = Decode!(&res, Result<u8, String>).unwrap();
    assert_eq!(
        val,
        Ok(0),
        "Queried first element of state vector, should have been 0, was {res:?}"
    );

    let result = env
        .execute_ingress(canister_id, "change_state", Encode!(&33_u32).unwrap())
        .unwrap();
    let res = assert_reply(result);
    let val = Decode!(&res, Result<u64, String>).unwrap();
    assert_eq!(
        val,
        Ok(1),
        "Changed state for the first time, result should have been 1, was {res:?}"
    );

    let result = env
        .query(canister_id, "read_state", Encode!(&0_usize).unwrap())
        .unwrap();
    let res = assert_reply(result);
    let val = Decode!(&res, Result<u8, String>).unwrap();
    assert_eq!(
        val,
        Ok(42),
        "Queried 0th element of state vector, should be 42 for seed 33, was {:?}",
        res
    );
}

#[test]
fn test_create_and_update_many_canisters() {
    let env = StateMachine::new();

    let seed_canister_id = deploy_state_sync_test_canister(&env);

    // Canister version of a canister created/controlled by the seed canister.
    let canister_version = |canister_id| {
        env.canister_status_query_as(seed_canister_id.into(), canister_id)
            .unwrap()
            .unwrap()
            .version()
    };

    let canister_creation_status = || {
        let result = env
            .query(
                seed_canister_id,
                "canister_creation_status",
                Encode!(&()).unwrap(),
            )
            .unwrap();
        let bytes = assert_reply(result);
        Decode!(&bytes, CanisterCreationStatus).unwrap()
    };

    assert!(matches!(
        canister_creation_status(),
        CanisterCreationStatus::Idle
    ));

    // Kick off canister creation.
    let num_canisters: u64 = 1000;
    let result = env
        .execute_ingress(
            seed_canister_id,
            "create_many_canisters",
            Encode!(&num_canisters).unwrap(),
        )
        .unwrap();
    let _ = assert_reply(result);

    // Trying to create a different number of canisters
    // while canister creation is in progress
    // results in a trap.
    let err = env
        .execute_ingress(
            seed_canister_id,
            "create_many_canisters",
            Encode!(&42_u64).unwrap(),
        )
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert!(err.description().contains(&format!(
        "Canister creation of a different number {num_canisters} of canisters is already in progress!"
    )));

    // Trying to create the same number of canisters
    // succeeds immediately since the call is idempotent.
    let result = env
        .execute_ingress(
            seed_canister_id,
            "create_many_canisters",
            Encode!(&num_canisters).unwrap(),
        )
        .unwrap();
    let _ = assert_reply(result);

    assert!(
        matches!(canister_creation_status(), CanisterCreationStatus::InProgress(n) if n == num_canisters)
    );

    while !matches!(canister_creation_status(), CanisterCreationStatus::Done(_)) {
        env.tick();
    }

    // Trying to create a different number of canisters
    // while canister creation is done
    // results in a trap.
    let err = env
        .execute_ingress(
            seed_canister_id,
            "create_many_canisters",
            Encode!(&42_u64).unwrap(),
        )
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::CanisterCalledTrap);
    assert!(err.description().contains(&format!(
        "Canister creation of a different number {num_canisters} of canisters is already done!"
    )));

    // Trying to create the same number of canisters
    // succeeds immediately since the call is idempotent.
    let result = env
        .execute_ingress(
            seed_canister_id,
            "create_many_canisters",
            Encode!(&num_canisters).unwrap(),
        )
        .unwrap();
    let _ = assert_reply(result);

    assert!(matches!(
        canister_creation_status(),
        CanisterCreationStatus::Done(_)
    ));

    // We created `num_canisters` in addition to the seed canister.
    assert_eq!(env.num_running_canisters(), num_canisters + 1);

    let created_canister_ids: Vec<CanisterId> = match canister_creation_status() {
        CanisterCreationStatus::Done(ids) => ids
            .into_iter()
            .map(|canister_candid_principal| {
                CanisterId::unchecked_from_principal(PrincipalId::from(canister_candid_principal))
            })
            .collect(),
        s => panic!("Expected Done, got {s:?}"),
    };
    assert_eq!(created_canister_ids.len(), num_canisters as usize);

    // Kick off canister state updates for the created canisters.
    // The call returns immediately, but keeps cycling through
    // the created canisters in the background and bumping their
    // freezing threshold so that their canister state keeps changing
    // and, consequently, their canister "version" keeps increasing.
    let result = env
        .execute_ingress(
            seed_canister_id,
            "update_many_canisters",
            Encode!(&()).unwrap(),
        )
        .unwrap();
    let _ = assert_reply(result);

    // Capture the current canister version as the baseline version
    // to check increase against.
    let baseline_versions: Vec<(_, u64)> = created_canister_ids
        .iter()
        .copied()
        .map(|canister_id| (canister_id, canister_version(canister_id)))
        .collect();

    // Execute rounds until the canister version of all created canisters increases
    // by at least 2 w.r.t. the baseline version observed above.
    // This property ensures that the created canisters are indeed being
    // updated repeatedly in the background.
    loop {
        let all_versions_increased =
            baseline_versions
                .iter()
                .copied()
                .all(|(canister_id, baseline_version)| {
                    canister_version(canister_id) >= baseline_version + 2
                });
        if all_versions_increased {
            break;
        }
        env.tick();
    }
}

fn assert_reply(res: WasmResult) -> Vec<u8> {
    match res {
        WasmResult::Reply(res) => res,
        WasmResult::Reject(_) => {
            unreachable!("Unexpected reject, should have been a reply");
        }
    }
}
