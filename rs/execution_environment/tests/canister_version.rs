use ic00::CanisterSettingsArgsBuilder;
use ic_ic00_types::CanisterInstallMode::{Install, Reinstall, Upgrade};
use ic_ic00_types::{
    self as ic00, CanisterIdRecord, CanisterInstallMode, InstallCodeArgs, Method, Payload,
};
use ic_state_machine_tests::StateMachine;
use ic_types::{ingress::WasmResult, CanisterId, Cycles};
use ic_types_test_utils::ids::user_test_id;

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

fn get_canister_version(env: &StateMachine, canister_id: CanisterId) -> u64 {
    env.get_latest_state()
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .canister_version
}

/// Creates, installs, and possibly reinstall/upgrades (depends on `mode`) the canister code
/// compiled from its WAT representation;
/// and checks the canister version after each of these operations
fn test(wat: &str, mode: CanisterInstallMode) {
    let test_canister = wat::parse_str(wat).expect("invalid WAT");

    // set up StateMachine
    let env = StateMachine::new();

    let user_id = user_test_id(7).get();

    // create canister via ingress from user_id
    let wasm_result = env
        .execute_ingress_as(
            user_id,
            ic00::IC_00,
            ic00::Method::ProvisionalCreateCanisterWithCycles,
            ic00::ProvisionalCreateCanisterWithCyclesArgs {
                amount: Some(candid::Nat::from(INITIAL_CYCLES_BALANCE.get())),
                settings: Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![user_id])
                        .build(),
                ),
                specified_id: None,
                sender_canister_version: None,
            }
            .encode(),
        )
        .expect("failed to create canister");
    let canister_id = match wasm_result {
        WasmResult::Reply(bytes) => CanisterIdRecord::decode(&bytes[..])
            .expect("failed to decode canister ID record")
            .get_canister_id(),
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {}", reason),
    };
    // check canister_version
    assert_eq!(get_canister_version(&env, canister_id), 0);

    // install test_canister via ingress from user_id
    env.execute_ingress_as(
        user_id,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(
            Install,
            canister_id,
            test_canister.clone(),
            vec![],
            None,
            None,
            None,
            None,
        )
        .encode(),
    )
    .unwrap();
    // check canister_version
    assert_eq!(get_canister_version(&env, canister_id), 1);

    if mode != CanisterInstallMode::Install {
        // install test_canister via ingress from user_id
        env.execute_ingress_as(
            user_id,
            ic00::IC_00,
            Method::InstallCode,
            InstallCodeArgs::new(
                mode,
                canister_id,
                test_canister,
                vec![],
                None,
                None,
                None,
                None,
            )
            .encode(),
        )
        .unwrap();
        // check canister_version
        assert_eq!(get_canister_version(&env, canister_id), 2);
    }
}

fn canister_wat(b1: bool, b2: bool, b3: bool, b4: bool) -> String {
    let start = "    (start $noop)\n";
    let init = "    (export \"canister_init\" (func $noop))\n";
    let pre = "    (export \"canister_pre_upgrade\" (func $noop))\n";
    let post = "    (export \"canister_post_upgrade\" (func $noop))\n";
    let mut res = r#"(module
    (func $noop
        return)
"#
    .to_string();
    if b1 {
        res.push_str(start);
    }
    if b2 {
        res.push_str(init);
    }
    if b3 {
        res.push_str(pre);
    }
    if b4 {
        res.push_str(post);
    }
    let end = ")\n".to_string();
    res.push_str(&end);
    res
}

#[test]
fn canister_version() {
    for b1 in [false, true] {
        for b2 in [false, true] {
            for b3 in [false, true] {
                for b4 in [false, true] {
                    let test_canister: &str = &canister_wat(b1, b2, b3, b4);
                    test(test_canister, Install);
                    test(test_canister, Reinstall);
                    test(test_canister, Upgrade);
                }
            }
        }
    }
}
