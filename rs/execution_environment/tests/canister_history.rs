use ic00::{
    CanisterSettingsArgsBuilder, CanisterSnapshotResponse, LoadCanisterSnapshotArgs,
    TakeCanisterSnapshotArgs,
};
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_crypto_sha2::Sha256;
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types::CanisterInstallMode::{Install, Reinstall, Upgrade};
use ic_management_canister_types::{
    self as ic00, CanisterChange, CanisterChangeDetails, CanisterChangeOrigin, CanisterIdRecord,
    CanisterInfoRequest, CanisterInfoResponse, CreateCanisterArgs, InstallCodeArgs, Method,
    Payload, UpdateSettingsArgs,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::{
    CanisterHistory, MAX_CANISTER_HISTORY_CHANGES,
};
use ic_state_machine_tests::{PrincipalId, StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_types::{ingress::WasmResult, CanisterId, Cycles};
use ic_types_test_utils::ids::user_test_id;
use ic_universal_canister::{
    call_args, wasm, UNIVERSAL_CANISTER_WASM, UNIVERSAL_CANISTER_WASM_SHA256,
};
use std::time::Duration;
use std::time::UNIX_EPOCH;

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

/// This is a simple test canister that we use in addition to the universal canister
/// to make sure that the canister history stores the module hashes of these two canisters
/// correctly, e.g., when upgrading or reinstalling the canister.
const TEST_CANISTER: &str = "(module)";

fn universal_canister_payload(
    receiver: &PrincipalId,
    method: &str,
    payload: Vec<u8>,
    cycles: Cycles,
) -> Vec<u8> {
    wasm()
        .call_with_cycles(
            receiver,
            method,
            call_args()
                .other_side(payload)
                .on_reject(wasm().reject_message().reject()),
            cycles,
        )
        .build()
}

fn get_canister_history(env: &StateMachine, canister_id: CanisterId) -> CanisterHistory {
    env.get_latest_state()
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .get_canister_history()
        .clone()
}

fn get_canister_info(
    env: &StateMachine,
    ucan: CanisterId,
    canister_id: CanisterId,
    num_requested_changes: Option<u64>,
) -> Result<CanisterInfoResponse, String> {
    let info_request_payload = universal_canister_payload(
        &PrincipalId::default(),
        &Method::CanisterInfo.to_string(),
        CanisterInfoRequest::new(canister_id, num_requested_changes).encode(),
        Cycles::new(0),
    );
    let wasm_result = env
        .execute_ingress(ucan, "update", info_request_payload)
        .unwrap();
    match wasm_result {
        WasmResult::Reply(bytes) => Ok(CanisterInfoResponse::decode(&bytes[..])
            .expect("failed to decode canister_info response")),
        WasmResult::Reject(reason) => Err(reason),
    }
}

/// Returns a StateMachine, the test canister Wasm, and its module hash.
fn test_setup(
    subnet_type: SubnetType,
    now: std::time::SystemTime,
) -> (StateMachine, Vec<u8>, [u8; 32]) {
    // TEST_CANISTER as wasm and its SHA256 hash
    let test_canister = wat::parse_str(TEST_CANISTER).expect("invalid WAT");
    let mut hasher = Sha256::new();
    hasher.write(&test_canister);
    let test_canister_sha256 = hasher.finish();

    // set up StateMachine
    let subnet_config = SubnetConfig::new(subnet_type);
    let env = StateMachine::new_with_config(StateMachineConfig::new(
        subnet_config,
        HypervisorConfig::default(),
    ));

    // set time of StateMachine to current system time
    env.set_time(now);

    (env, test_canister, test_canister_sha256)
}

#[test]
fn canister_history_tracks_create_install_reinstall() {
    let mut now = std::time::SystemTime::now();
    let (env, test_canister, test_canister_sha256) = test_setup(SubnetType::Application, now);

    // declare user IDs
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    // create canister via ingress from user_id1
    let wasm_result = env
        .execute_ingress_as(
            user_id1,
            ic00::IC_00,
            ic00::Method::ProvisionalCreateCanisterWithCycles,
            ic00::ProvisionalCreateCanisterWithCyclesArgs {
                amount: Some(candid::Nat::from(INITIAL_CYCLES_BALANCE.get())),
                settings: Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![user_id1, user_id2])
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
    // check canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![user_id1, user_id2]),
    )];
    let history = get_canister_history(&env, canister_id);
    assert_eq!(
        history.get_total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(
        history
            .get_changes(history.get_total_num_changes() as usize)
            .map(|c| (**c).clone())
            .collect::<Vec<CanisterChange>>(),
        reference_change_entries
    );

    // install test_canister via ingress from user_id2
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id2,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(Install, canister_id, test_canister, vec![], None, None).encode(),
    )
    .unwrap();
    // check canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        1,
        CanisterChangeOrigin::from_user(user_id2),
        CanisterChangeDetails::code_deployment(Install, test_canister_sha256),
    ));
    let history = get_canister_history(&env, canister_id);
    assert_eq!(
        history.get_total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(
        history
            .get_changes(history.get_total_num_changes() as usize)
            .map(|c| (**c).clone())
            .collect::<Vec<CanisterChange>>(),
        reference_change_entries
    );

    // reinstall to universal_canister via ingress from user_id1
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id1,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(
            Reinstall,
            canister_id,
            UNIVERSAL_CANISTER_WASM.into(),
            vec![],
            None,
            None,
        )
        .encode(),
    )
    .unwrap();
    // check canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        2,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::code_deployment(Reinstall, UNIVERSAL_CANISTER_WASM_SHA256),
    ));
    let history = get_canister_history(&env, canister_id);
    assert_eq!(
        history.get_total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(
        history
            .get_changes(history.get_total_num_changes() as usize)
            .map(|c| (**c).clone())
            .collect::<Vec<CanisterChange>>(),
        reference_change_entries
    );
}

#[test]
fn canister_history_tracks_upgrade() {
    let mut now = std::time::SystemTime::now();
    let (env, test_canister, test_canister_sha256) = test_setup(SubnetType::Application, now);

    // declare user IDs
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    // create canister via ingress from user_id1
    let wasm_result = env
        .execute_ingress_as(
            user_id1,
            ic00::IC_00,
            ic00::Method::ProvisionalCreateCanisterWithCycles,
            ic00::ProvisionalCreateCanisterWithCyclesArgs {
                amount: Some(candid::Nat::from(INITIAL_CYCLES_BALANCE.get())),
                settings: Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![user_id1, user_id2])
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
    // update reference canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![user_id1, user_id2]),
    )];

    // install test_canister via ingress from user_id2
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id2,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(Install, canister_id, test_canister, vec![], None, None).encode(),
    )
    .unwrap();
    // update reference canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        1,
        CanisterChangeOrigin::from_user(user_id2),
        CanisterChangeDetails::code_deployment(Install, test_canister_sha256),
    ));

    // upgrade to universal_canister via ingress from user_id1
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id1,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(
            Upgrade,
            canister_id,
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            None,
        )
        .encode(),
    )
    .unwrap();
    // check canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        2,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::code_deployment(Upgrade, UNIVERSAL_CANISTER_WASM_SHA256),
    ));
    let history = get_canister_history(&env, canister_id);
    assert_eq!(
        history.get_total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(
        history
            .get_changes(history.get_total_num_changes() as usize)
            .map(|c| (**c).clone())
            .collect::<Vec<CanisterChange>>(),
        reference_change_entries
    );
}

#[test]
fn canister_history_tracks_uninstall() {
    let mut now = std::time::SystemTime::now();
    let (env, test_canister, test_canister_sha256) = test_setup(SubnetType::Application, now);

    // declare user IDs
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    // create canister via ingress from user_id1
    let wasm_result = env
        .execute_ingress_as(
            user_id1,
            ic00::IC_00,
            ic00::Method::ProvisionalCreateCanisterWithCycles,
            ic00::ProvisionalCreateCanisterWithCyclesArgs {
                amount: Some(candid::Nat::from(INITIAL_CYCLES_BALANCE.get())),
                settings: Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![user_id1, user_id2])
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
    // update reference canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![user_id1, user_id2]),
    )];

    // install test_canister via ingress from user_id2
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id2,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(Install, canister_id, test_canister, vec![], None, None).encode(),
    )
    .unwrap();
    // update reference canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        1,
        CanisterChangeOrigin::from_user(user_id2),
        CanisterChangeDetails::code_deployment(Install, test_canister_sha256),
    ));

    // uninstall code via ingress from user_id1
    now += Duration::from_secs(5);
    env.set_time(now);
    let canister_id_record: CanisterIdRecord = canister_id.into();
    env.execute_ingress_as(
        user_id1,
        ic00::IC_00,
        Method::UninstallCode,
        canister_id_record.encode(),
    )
    .unwrap();
    // check canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        2,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::CanisterCodeUninstall,
    ));
    let history = get_canister_history(&env, canister_id);
    assert_eq!(
        history.get_total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(
        history
            .get_changes(history.get_total_num_changes() as usize)
            .map(|c| (**c).clone())
            .collect::<Vec<CanisterChange>>(),
        reference_change_entries
    );
}

#[test]
fn canister_history_tracks_controllers_change() {
    let mut now = std::time::SystemTime::now();
    let (env, _test_canister, _test_canister_sha256) = test_setup(SubnetType::Application, now);

    // declare user IDs
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    // create canister via ingress from user_id1
    let wasm_result = env
        .execute_ingress_as(
            user_id1,
            ic00::IC_00,
            ic00::Method::ProvisionalCreateCanisterWithCycles,
            ic00::ProvisionalCreateCanisterWithCyclesArgs {
                amount: Some(candid::Nat::from(INITIAL_CYCLES_BALANCE.get())),
                settings: Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![user_id1, user_id2])
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
    // update reference canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![user_id1, user_id2]),
    )];

    for i in 1..MAX_CANISTER_HISTORY_CHANGES + 42 {
        // update controllers via ingress from user_id2 (effectively the same set of controllers, but canister history still updated)
        let new_controllers = vec![user_id1, user_id2];
        now += Duration::from_secs(5);
        env.set_time(now);
        env.execute_ingress_as(
            user_id2,
            ic00::IC_00,
            Method::UpdateSettings,
            UpdateSettingsArgs {
                canister_id: canister_id.into(),
                settings: CanisterSettingsArgsBuilder::new()
                    .with_controllers(new_controllers.clone())
                    .build(),
                sender_canister_version: Some(666), // ignored for ingress messages
            }
            .encode(),
        )
        .unwrap();
        // check canister history
        reference_change_entries.push(CanisterChange::new(
            now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
            i,
            CanisterChangeOrigin::from_user(user_id2),
            CanisterChangeDetails::controllers_change(new_controllers),
        ));
        let history = get_canister_history(&env, canister_id);
        assert_eq!(history.get_total_num_changes(), i + 1);
        while reference_change_entries.len() > (MAX_CANISTER_HISTORY_CHANGES as usize) {
            reference_change_entries.remove(0);
        }
        assert_eq!(
            history
                .get_changes(history.get_total_num_changes() as usize)
                .map(|c| (**c).clone())
                .collect::<Vec<CanisterChange>>(),
            reference_change_entries
        );
    }
}

#[test]
fn canister_history_cleared_if_canister_out_of_cycles() {
    let mut now = std::time::SystemTime::now();
    let subnet_type = SubnetType::Application;
    let (env, test_canister, test_canister_sha256) = test_setup(subnet_type, now);

    // declare user IDs
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    // create canister via ingress from user_id1
    let wasm_result = env
        .execute_ingress_as(
            user_id1,
            ic00::IC_00,
            ic00::Method::ProvisionalCreateCanisterWithCycles,
            ic00::ProvisionalCreateCanisterWithCyclesArgs {
                amount: Some(candid::Nat::from(INITIAL_CYCLES_BALANCE.get())),
                settings: Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![user_id1, user_id2])
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
    // update reference canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![user_id1, user_id2]),
    )];

    // install test_canister via ingress from user_id2
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id2,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(
            Install,
            canister_id,
            test_canister,
            vec![],
            Some(1), // set compute allocation to 1 per cent
            None,
        )
        .encode(),
    )
    .unwrap();
    // update reference canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        1,
        CanisterChangeOrigin::from_user(user_id2),
        CanisterChangeDetails::code_deployment(Install, test_canister_sha256),
    ));

    // drain cycle balance of test_canister to trigger code uninstall from system
    let subnet_config = SubnetConfig::new(subnet_type);
    let compute_percent_allocated_per_second_fee = subnet_config
        .cycles_account_manager_config
        .compute_percent_allocated_per_second_fee;
    let seconds_to_burn_balance = env.cycle_balance(canister_id) as u64
        / compute_percent_allocated_per_second_fee.get() as u64;
    now += Duration::from_secs(seconds_to_burn_balance + 1);
    env.set_time(now);
    env.tick();
    // check canister history
    let total_num_change_entries = reference_change_entries.len();
    reference_change_entries.clear();
    let history = get_canister_history(&env, canister_id);
    assert_eq!(
        history.get_total_num_changes(),
        total_num_change_entries as u64
    );
    assert_eq!(
        history
            .get_changes(history.get_total_num_changes() as usize)
            .map(|c| (**c).clone())
            .collect::<Vec<CanisterChange>>(),
        reference_change_entries
    );
}

#[test]
fn canister_history_tracks_changes_from_canister() {
    let mut now = std::time::SystemTime::now();
    let (env, test_canister, test_canister_sha256) = test_setup(SubnetType::Application, now);

    // declare user IDs
    let anonymous_user = PrincipalId::new_anonymous();
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    // create and install universal_canister
    let ucan = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.into(),
            vec![],
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_controllers(vec![anonymous_user, user_id1, user_id2])
                    .build(),
            ),
            INITIAL_CYCLES_BALANCE * 2_u64,
        )
        .unwrap();

    // create a canister via inter-canister call from ucan
    now += Duration::from_secs(5);
    env.set_time(now);
    let ucan_payload = universal_canister_payload(
        &PrincipalId::default(),
        "create_canister",
        CreateCanisterArgs {
            settings: Some(
                CanisterSettingsArgsBuilder::new()
                    .with_controllers(vec![ucan.into(), user_id1, user_id2])
                    .build(),
            ),
            sender_canister_version: Some(2), // specified sender_canister_version
        }
        .encode(),
        INITIAL_CYCLES_BALANCE,
    );
    let wasm_result = env.execute_ingress(ucan, "update", ucan_payload).unwrap();
    let canister_id = match wasm_result {
        WasmResult::Reply(bytes) => CanisterIdRecord::decode(&bytes[..])
            .expect("failed to decode canister ID record")
            .get_canister_id(),
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {}", reason),
    };
    // check canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 2, // the canister is created in the next round after the ingress message is received
        0,
        CanisterChangeOrigin::from_canister(ucan.into(), Some(2)),
        CanisterChangeDetails::canister_creation(vec![ucan.into(), user_id1, user_id2]),
    )];
    let history = get_canister_history(&env, canister_id);
    assert_eq!(
        history.get_total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(
        history
            .get_changes(history.get_total_num_changes() as usize)
            .map(|c| (**c).clone())
            .collect::<Vec<CanisterChange>>(),
        reference_change_entries
    );

    // install test_canister via inter-canister call from ucan
    now += Duration::from_secs(5);
    env.set_time(now);
    let ucan_payload = universal_canister_payload(
        &PrincipalId::default(),
        "install_code",
        InstallCodeArgs::new(Install, canister_id, test_canister, vec![], None, None).encode(),
        Cycles::new(0),
    );
    env.execute_ingress(ucan, "update", ucan_payload).unwrap();
    // check canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 2, // the canister is installed in the next round after the ingress message is received
        1,
        CanisterChangeOrigin::from_canister(ucan.into(), None),
        CanisterChangeDetails::code_deployment(Install, test_canister_sha256),
    ));
    let history = get_canister_history(&env, canister_id);
    assert_eq!(
        history.get_total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(
        history
            .get_changes(history.get_total_num_changes() as usize)
            .map(|c| (**c).clone())
            .collect::<Vec<CanisterChange>>(),
        reference_change_entries
    );
}

#[test]
fn canister_history_fails_with_incorrect_sender_version() {
    let now = std::time::SystemTime::now();
    let (env, _test_canister, _test_canister_sha256) = test_setup(SubnetType::Application, now);

    // declare user IDs
    let anonymous_user = PrincipalId::new_anonymous();
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    // create and install universal_canister
    let ucan = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.into(),
            vec![],
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_controllers(vec![anonymous_user, user_id1, user_id2])
                    .build(),
            ),
            INITIAL_CYCLES_BALANCE * 2_u64,
        )
        .unwrap();

    // create canister via ingress from user_id1
    let wasm_result = env
        .execute_ingress_as(
            user_id1,
            ic00::IC_00,
            ic00::Method::ProvisionalCreateCanisterWithCycles,
            ic00::ProvisionalCreateCanisterWithCyclesArgs {
                amount: Some(candid::Nat::from(INITIAL_CYCLES_BALANCE.get())),
                settings: Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![ucan.into(), user_id1, user_id2])
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
    // update reference canister history
    let reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 3, // the universal canister is created in 1st round, installed in 2nd round, this canister is created in 3rd round
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![ucan.into(), user_id1, user_id2]),
    )];

    // attach illegal sender_canister_version (call fails and canister history is not updated)
    let ucan_payload = universal_canister_payload(
        &PrincipalId::default(),
        "install_code",
        InstallCodeArgs {
            mode: Install,
            canister_id: canister_id.into(),
            wasm_module: UNIVERSAL_CANISTER_WASM.into(),
            arg: vec![],
            compute_allocation: None,
            memory_allocation: None,
            sender_canister_version: Some(666), // this value of sender_canister_version does not match the actual sender_canister_version
        }
        .encode(),
        Cycles::new(0),
    );
    let wasm_result = env.execute_ingress(ucan, "update", ucan_payload).unwrap();
    // check failure
    match wasm_result {
        WasmResult::Reply(_) => {
            panic!("Sender canister version should not match the actual canister version.")
        }
        WasmResult::Reject(_) => (),
    };
    assert!(env.module_hash(canister_id).is_none());
    // check canister history
    let history = get_canister_history(&env, canister_id);
    assert_eq!(
        history.get_total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(
        history
            .get_changes(history.get_total_num_changes() as usize)
            .map(|c| (**c).clone())
            .collect::<Vec<CanisterChange>>(),
        reference_change_entries
    );
}

#[test]
fn canister_info_retrieval() {
    let mut now = std::time::SystemTime::now();
    let (env, test_canister, test_canister_sha256) = test_setup(SubnetType::Application, now);

    // declare user IDs
    let anonymous_user = PrincipalId::new_anonymous();
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    // create canister via ingress from user_id1
    let wasm_result = env
        .execute_ingress_as(
            user_id1,
            ic00::IC_00,
            ic00::Method::ProvisionalCreateCanisterWithCycles,
            ic00::ProvisionalCreateCanisterWithCyclesArgs {
                amount: Some(candid::Nat::from(INITIAL_CYCLES_BALANCE.get())),
                settings: Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![user_id1, user_id2])
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
    // update reference canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![user_id1, user_id2]),
    )];

    // install test_canister via ingress from user_id2
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id2,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(Install, canister_id, test_canister, vec![], None, None).encode(),
    )
    .unwrap();
    // update reference canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        1,
        CanisterChangeOrigin::from_user(user_id2),
        CanisterChangeDetails::code_deployment(Install, test_canister_sha256),
    ));

    // upgrade to universal_canister via ingress from user_id1
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id1,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(
            Upgrade,
            canister_id,
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            None,
            None,
        )
        .encode(),
    )
    .unwrap();
    // update reference canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        2,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::code_deployment(Upgrade, UNIVERSAL_CANISTER_WASM_SHA256),
    ));

    // create and install universal_canister
    let ucan = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.into(),
            vec![],
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_controllers(vec![anonymous_user, user_id1, user_id2])
                    .build(),
            ),
            INITIAL_CYCLES_BALANCE,
        )
        .unwrap();

    // users cannot retrieve canister information directly via ingress messages
    let res = env.execute_ingress(
        ic00::IC_00,
        Method::CanisterInfo,
        CanisterInfoRequest::new(canister_id, None).encode(),
    );
    assert_eq!(
        res,
        Err(UserError::new(
            ErrorCode::CanisterRejectedMessage,
            "Only canisters can call ic00 method canister_info"
        ))
    );

    // do not specify the number of requested changes
    let canister_info = get_canister_info(&env, ucan, canister_id, None).unwrap();
    assert_eq!(
        canister_info.total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(canister_info.changes(), vec![]);
    assert_eq!(
        canister_info.module_hash(),
        Some(UNIVERSAL_CANISTER_WASM_SHA256.to_vec())
    );
    assert_eq!(canister_info.controllers(), vec![user_id1, user_id2]);

    // retrieve the entire canister history
    let canister_info = get_canister_info(&env, ucan, canister_id, Some(3)).unwrap();
    assert_eq!(
        canister_info.total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(canister_info.changes(), reference_change_entries);
    assert_eq!(
        canister_info.module_hash(),
        Some(UNIVERSAL_CANISTER_WASM_SHA256.to_vec())
    );
    assert_eq!(canister_info.controllers(), vec![user_id1, user_id2]);

    // retrieve a proper suffix of canister history
    let canister_info = get_canister_info(&env, ucan, canister_id, Some(2)).unwrap();
    assert_eq!(
        canister_info.total_num_changes(),
        reference_change_entries.len() as u64
    );
    let history_suffix: Vec<CanisterChange> =
        reference_change_entries.as_slice()[(reference_change_entries.len() - 2)..].to_vec();
    assert_eq!(canister_info.changes(), history_suffix);
    assert_eq!(
        canister_info.module_hash(),
        Some(UNIVERSAL_CANISTER_WASM_SHA256.to_vec())
    );
    assert_eq!(canister_info.controllers(), vec![user_id1, user_id2]);

    // ask for more entries than present in canister history
    let canister_info = get_canister_info(&env, ucan, canister_id, Some(666)).unwrap();
    assert_eq!(
        canister_info.total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(canister_info.changes(), reference_change_entries);
    assert_eq!(
        canister_info.module_hash(),
        Some(UNIVERSAL_CANISTER_WASM_SHA256.to_vec())
    );
    assert_eq!(canister_info.controllers(), vec![user_id1, user_id2]);

    // uninstall code via ingress from user_id2
    now += Duration::from_secs(5);
    env.set_time(now);
    let canister_id_record: CanisterIdRecord = canister_id.into();
    env.execute_ingress_as(
        user_id2,
        ic00::IC_00,
        Method::UninstallCode,
        canister_id_record.encode(),
    )
    .unwrap();
    // update reference canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        18,
        CanisterChangeOrigin::from_user(user_id2),
        CanisterChangeDetails::CanisterCodeUninstall,
    ));

    // retrieve the entire canister history and check module_hash of uninstalled canister
    let canister_info = get_canister_info(&env, ucan, canister_id, Some(4)).unwrap();
    assert_eq!(
        canister_info.total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(canister_info.changes(), reference_change_entries);
    assert_eq!(canister_info.module_hash(), None);
    assert_eq!(canister_info.controllers(), vec![user_id1, user_id2]);
}

#[test]
fn canister_history_load_snapshot_fails_incorrect_sender_version() {
    // Setup:
    let mut now = std::time::SystemTime::now();
    let (_, test_canister, test_canister_sha256) = test_setup(SubnetType::Application, now);

    // Set up StateMachine
    let env = StateMachineBuilder::new()
        .with_canister_snapshots(true)
        .build();
    // Set time of StateMachine to current system time
    env.set_time(now);

    // Declare user IDs
    let anonymous_user = PrincipalId::new_anonymous();
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    // Create and install universal_canister
    let ucan = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.into(),
            vec![],
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_controllers(vec![anonymous_user, user_id1, user_id2])
                    .build(),
            ),
            INITIAL_CYCLES_BALANCE * 2_u64,
        )
        .unwrap();

    // Create a canister via inter-canister call from ucan
    now += Duration::from_secs(5);
    env.set_time(now);
    let ucan_payload = universal_canister_payload(
        &PrincipalId::default(),
        "create_canister",
        CreateCanisterArgs {
            settings: Some(
                CanisterSettingsArgsBuilder::new()
                    .with_controllers(vec![ucan.into(), user_id1, user_id2])
                    .build(),
            ),
            sender_canister_version: Some(2), // specified sender_canister_version
        }
        .encode(),
        INITIAL_CYCLES_BALANCE,
    );
    let wasm_result = env.execute_ingress(ucan, "update", ucan_payload).unwrap();
    let canister_id = match wasm_result {
        WasmResult::Reply(bytes) => CanisterIdRecord::decode(&bytes[..])
            .expect("failed to decode canister ID record")
            .get_canister_id(),
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {}", reason),
    };

    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 2, // the canister is created in the next round after the ingress message is received
        0,
        CanisterChangeOrigin::from_canister(ucan.into(), Some(2)),
        CanisterChangeDetails::canister_creation(vec![ucan.into(), user_id1, user_id2]),
    )];

    now += Duration::from_secs(5);
    env.set_time(now);
    let wasm_result = env
        .execute_ingress_as(
            ucan.into(),
            ic00::IC_00,
            Method::InstallCode,
            InstallCodeArgs::new(Install, canister_id, test_canister, vec![], None, None).encode(),
        )
        .unwrap();
    match wasm_result {
        WasmResult::Reply(_) => {}
        WasmResult::Reject(reason) => panic!("install_code call rejected: {}", reason),
    };
    // Check canister history.
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1,
        1,
        CanisterChangeOrigin::from_user(ucan.into()),
        CanisterChangeDetails::code_deployment(Install, test_canister_sha256),
    ));
    let history = get_canister_history(&env, canister_id);
    assert_eq!(
        history.get_total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(
        history
            .get_changes(history.get_total_num_changes() as usize)
            .map(|c| (**c).clone())
            .collect::<Vec<CanisterChange>>(),
        reference_change_entries
    );

    // Create canister snapshot.
    now += Duration::from_secs(5);
    env.set_time(now);
    let args: TakeCanisterSnapshotArgs = TakeCanisterSnapshotArgs::new(canister_id, None);
    let ucan_payload = universal_canister_payload(
        &PrincipalId::default(),
        "take_canister_snapshot",
        args.encode(),
        Cycles::new(0),
    );
    let wasm_result = env.execute_ingress(ucan, "update", ucan_payload).unwrap();
    let result = match wasm_result {
        WasmResult::Reply(bytes) => {
            CanisterSnapshotResponse::decode(&bytes[..]).expect("failed to decode record")
        }
        WasmResult::Reject(reason) => panic!("take_canister_snapshot call rejected: {}", reason),
    };
    let snapshot_id = result.snapshot_id();

    // Load snapshot on test_canister via inter-canister call from ucan
    now += Duration::from_secs(5);
    env.set_time(now);
    // This value of sender_canister_version does not match the actual sender_canister_version.
    // Attach illegal sender_canister_version (call fails and canister history is not updated).
    let args: LoadCanisterSnapshotArgs =
        LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, Some(444));
    let ucan_payload = universal_canister_payload(
        &PrincipalId::default(),
        "load_canister_snapshot",
        args.encode(),
        Cycles::new(0),
    );
    let wasm_result = env.execute_ingress(ucan, "update", ucan_payload).unwrap();
    // Check failure.
    match wasm_result {
        WasmResult::Reply(_) => {
            panic!("Sender canister version should not match the actual canister version.")
        }
        WasmResult::Reject(_) => (),
    };

    // Check canister history is unchanged.
    let history = get_canister_history(&env, canister_id);
    assert_eq!(
        history.get_total_num_changes(),
        reference_change_entries.len() as u64
    );
    assert_eq!(
        history
            .get_changes(history.get_total_num_changes() as usize)
            .map(|c| (**c).clone())
            .collect::<Vec<CanisterChange>>(),
        reference_change_entries
    );
}
