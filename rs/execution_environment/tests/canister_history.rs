use ic_base_types::{EnvironmentVariables, PrincipalId};
use ic_config::flag_status::FlagStatus;
use ic_config::{execution_environment::Config as HypervisorConfig, subnet_config::SubnetConfig};
use ic_crypto_sha2::Sha256;
use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::CanisterInstallMode::{Install, Reinstall, Upgrade};
use ic_management_canister_types_private::{
    self as ic00, CanisterChange, CanisterChangeDetails, CanisterChangeOrigin, CanisterIdRecord,
    CanisterInfoRequest, CanisterInfoResponse, CreateCanisterArgs, EnvironmentVariable,
    InstallCodeArgs, MAX_CONTROLLERS, Method, Payload, ProvisionalCreateCanisterWithCyclesArgs,
    UpdateSettingsArgs,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::canister_state::system_state::MAX_CANISTER_HISTORY_CHANGES;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_test_utilities_execution_environment::{ExecutionTest, ExecutionTestBuilder, get_reply};
use ic_types::{CanisterId, Cycles, ingress::WasmResult};
use ic_types_test_utils::ids::user_test_id;
use ic_universal_canister::{
    UNIVERSAL_CANISTER_WASM, UNIVERSAL_CANISTER_WASM_SHA256, call_args, wasm,
};
use ic00::{
    CanisterSettingsArgsBuilder, CanisterSnapshotResponse, LoadCanisterSnapshotArgs,
    TakeCanisterSnapshotArgs,
};
use std::collections::BTreeMap;
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

fn canister_id_from_wasm_result(wasm_result: WasmResult) -> CanisterId {
    match wasm_result {
        WasmResult::Reply(bytes) => CanisterIdRecord::decode(&bytes[..])
            .expect("failed to decode canister ID record")
            .get_canister_id(),
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {reason}"),
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
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {reason}"),
    };
    // check canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![user_id1, user_id2], None),
    )];
    let history = env.get_canister_history(canister_id);
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
        InstallCodeArgs::new(Install, canister_id, test_canister, vec![]).encode(),
    )
    .unwrap();
    // check canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        1,
        CanisterChangeOrigin::from_user(user_id2),
        CanisterChangeDetails::code_deployment(Install, test_canister_sha256),
    ));
    let history = env.get_canister_history(canister_id);
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
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
        )
        .encode(),
    )
    .unwrap();
    // check canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        2,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::code_deployment(Reinstall, *UNIVERSAL_CANISTER_WASM_SHA256),
    ));
    let history = env.get_canister_history(canister_id);
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
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {reason}"),
    };
    // update reference canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![user_id1, user_id2], None),
    )];

    // install test_canister via ingress from user_id2
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id2,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(Install, canister_id, test_canister, vec![]).encode(),
    )
    .unwrap();
    // update reference canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
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
        )
        .encode(),
    )
    .unwrap();
    // check canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        2,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::code_deployment(Upgrade, *UNIVERSAL_CANISTER_WASM_SHA256),
    ));
    let history = env.get_canister_history(canister_id);
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
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {reason}"),
    };
    // update reference canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![user_id1, user_id2], None),
    )];

    // install test_canister via ingress from user_id2
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id2,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(Install, canister_id, test_canister, vec![]).encode(),
    )
    .unwrap();
    // update reference canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
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
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        2,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::CanisterCodeUninstall,
    ));
    let history = env.get_canister_history(canister_id);
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

fn canister_history_tracks_controllers_change(environment_variables_flag: FlagStatus) {
    let mut now = std::time::SystemTime::now();
    let env = setup_with_environment_variables_flag(environment_variables_flag);
    env.set_time(now);

    // declare user IDs
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    // create canister via ingress from user_id1
    // overriding controllers with a list containing repeated controllers
    let wasm_result = env
        .execute_ingress_as(
            user_id1,
            ic00::IC_00,
            ic00::Method::ProvisionalCreateCanisterWithCycles,
            ic00::ProvisionalCreateCanisterWithCyclesArgs {
                amount: Some(candid::Nat::from(INITIAL_CYCLES_BALANCE.get())),
                settings: Some(
                    CanisterSettingsArgsBuilder::new()
                        .with_controllers(vec![
                            user_id2, user_id1, user_id2, user_id1, user_id1, user_id2,
                        ])
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
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {reason}"),
    };
    // update reference canister history
    // the list of controllers in the canister history is sorted and contains no duplicates
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![user_id1, user_id2], None),
    )];

    let env_vars = BTreeMap::from([
        ("NODE_ENV".to_string(), "production".to_string()),
        ("LOG_LEVEL".to_string(), "debug".to_string()),
    ]);

    for i in 1..MAX_CANISTER_HISTORY_CHANGES + 42 {
        // update controllers via ingress from user_id2
        // (effectively the same set of controllers provided as a list containing repeated controllers,
        // but canister history still updated)
        let new_controllers = vec![user_id2, user_id1, user_id2, user_id1, user_id1, user_id2];
        now += Duration::from_secs(5);
        env.set_time(now);
        let settings = if i % 2 == 0 {
            CanisterSettingsArgsBuilder::new()
                .with_controllers(new_controllers.clone())
                .with_environment_variables(
                    env_vars
                        .clone()
                        .into_iter()
                        .map(|(k, v)| EnvironmentVariable { name: k, value: v })
                        .collect::<Vec<_>>(),
                )
                .build()
        } else {
            CanisterSettingsArgsBuilder::new()
                .with_controllers(new_controllers.clone())
                .build()
        };
        env.execute_ingress_as(
            user_id2,
            ic00::IC_00,
            Method::UpdateSettings,
            UpdateSettingsArgs {
                canister_id: canister_id.into(),
                settings,
                sender_canister_version: Some(666), // ignored for ingress messages
            }
            .encode(),
        )
        .unwrap();
        // check canister history
        // the list of controllers in the canister history is sorted and contains no duplicates
        reference_change_entries.push(CanisterChange::new(
            now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
            i,
            CanisterChangeOrigin::from_user(user_id2),
            CanisterChangeDetails::controllers_change(vec![user_id1, user_id2]),
        ));
        let history = env.get_canister_history(canister_id);
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
fn canister_history_tracks_controllers_change_as_controllers_change() {
    canister_history_tracks_controllers_change(FlagStatus::Disabled);
    canister_history_tracks_controllers_change(FlagStatus::Enabled);
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
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {reason}"),
    };
    // update reference canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![user_id1, user_id2], None),
    )];

    // install test_canister via ingress from user_id2
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id2,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(Install, canister_id, test_canister, vec![]).encode(),
    )
    .unwrap();
    env.execute_ingress_as(
        user_id2,
        ic00::IC_00,
        Method::UpdateSettings,
        UpdateSettingsArgs {
            canister_id: canister_id.into(),
            settings: CanisterSettingsArgsBuilder::new()
                .with_compute_allocation(1)
                .build(),
            sender_canister_version: None,
        }
        .encode(),
    )
    .unwrap();

    // update reference canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
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
    let history = env.get_canister_history(canister_id);
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
            UNIVERSAL_CANISTER_WASM.to_vec(),
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
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {reason}"),
    };
    // check canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1, // the canister is created in the next round after the ingress message is received
        0,
        CanisterChangeOrigin::from_canister(ucan.into(), Some(2)),
        CanisterChangeDetails::canister_creation(vec![ucan.into(), user_id1, user_id2], None),
    )];
    let history = env.get_canister_history(canister_id);
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
        InstallCodeArgs::new(Install, canister_id, test_canister, vec![]).encode(),
        Cycles::new(0),
    );
    env.execute_ingress(ucan, "update", ucan_payload).unwrap();
    // check canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1, // the canister is installed in the next round after the ingress message is received
        1,
        CanisterChangeOrigin::from_canister(ucan.into(), None),
        CanisterChangeDetails::code_deployment(Install, test_canister_sha256),
    ));
    let history = env.get_canister_history(canister_id);
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
            UNIVERSAL_CANISTER_WASM.to_vec(),
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
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {reason}"),
    };
    // update reference canister history
    let reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 2, // the universal canister is created in 1st round, installed in 2nd round, this canister is created in 3rd round
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![ucan.into(), user_id1, user_id2], None),
    )];

    // attach illegal sender_canister_version (call fails and canister history is not updated)
    let ucan_payload = universal_canister_payload(
        &PrincipalId::default(),
        "install_code",
        InstallCodeArgs {
            mode: Install,
            canister_id: canister_id.into(),
            wasm_module: UNIVERSAL_CANISTER_WASM.to_vec(),
            arg: vec![],
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
    let history = env.get_canister_history(canister_id);
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
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {reason}"),
    };
    // update reference canister history
    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        0,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::canister_creation(vec![user_id1, user_id2], None),
    )];

    // install test_canister via ingress from user_id2
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id2,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(Install, canister_id, test_canister, vec![]).encode(),
    )
    .unwrap();
    // update reference canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
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
        )
        .encode(),
    )
    .unwrap();
    // update reference canister history
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        2,
        CanisterChangeOrigin::from_user(user_id1),
        CanisterChangeDetails::code_deployment(Upgrade, *UNIVERSAL_CANISTER_WASM_SHA256),
    ));

    // create and install universal_canister
    let ucan = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
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
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
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
    let env = StateMachineBuilder::new().build();
    // Set time of StateMachine to current system time
    env.set_time(now);

    // Declare user IDs
    let anonymous_user = PrincipalId::new_anonymous();
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    // Create and install universal_canister
    let ucan = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
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
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {reason}"),
    };

    let mut reference_change_entries: Vec<CanisterChange> = vec![CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1, // the canister is created in the next round after the ingress message is received
        0,
        CanisterChangeOrigin::from_canister(ucan.into(), Some(2)),
        CanisterChangeDetails::canister_creation(vec![ucan.into(), user_id1, user_id2], None),
    )];

    now += Duration::from_secs(5);
    env.set_time(now);
    let wasm_result = env
        .execute_ingress_as(
            ucan.into(),
            ic00::IC_00,
            Method::InstallCode,
            InstallCodeArgs::new(Install, canister_id, test_canister, vec![]).encode(),
        )
        .unwrap();
    match wasm_result {
        WasmResult::Reply(_) => {}
        WasmResult::Reject(reason) => panic!("install_code call rejected: {reason}"),
    };
    // Check canister history.
    reference_change_entries.push(CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        1,
        CanisterChangeOrigin::from_user(ucan.into()),
        CanisterChangeDetails::code_deployment(Install, test_canister_sha256),
    ));
    let history = env.get_canister_history(canister_id);
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
    let args: TakeCanisterSnapshotArgs =
        TakeCanisterSnapshotArgs::new(canister_id, None, None, None);
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
        WasmResult::Reject(reason) => panic!("take_canister_snapshot call rejected: {reason}"),
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
    let history = env.get_canister_history(canister_id);
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

fn setup_with_environment_variables_flag(environment_variables_flag: FlagStatus) -> StateMachine {
    StateMachine::new_with_config(StateMachineConfig::new(
        SubnetConfig::new(SubnetType::Application),
        HypervisorConfig {
            environment_variables: environment_variables_flag,
            ..Default::default()
        },
    ))
}

fn check_environment_variables_for_create_canister_history(
    method: Method,
    payload: Vec<u8>,
    environment_variables_flag: FlagStatus,
    env_vars: &BTreeMap<String, String>,
    user_id1: PrincipalId,
    user_id2: PrincipalId,
) {
    // Set up StateMachine.
    let anonymous_user = PrincipalId::new_anonymous();
    let env = setup_with_environment_variables_flag(environment_variables_flag);

    // Set time of StateMachine to current system time.
    let mut now = std::time::SystemTime::now();
    env.set_time(now);

    // Create and install universal_canister
    let ucan = env
        .install_canister_with_cycles(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            vec![],
            Some(
                CanisterSettingsArgsBuilder::new()
                    .with_controllers(vec![anonymous_user, user_id1, user_id2])
                    .build(),
            ),
            INITIAL_CYCLES_BALANCE * 2_u64,
        )
        .unwrap();

    // Create a canister with environment variables.
    now += Duration::from_secs(5);
    env.set_time(now);
    let ucan_payload = universal_canister_payload(
        &PrincipalId::default(),
        method.to_string().as_str(),
        payload,
        INITIAL_CYCLES_BALANCE,
    );
    let wasm_result = env.execute_ingress(ucan, "update", ucan_payload).unwrap();
    let canister_id = canister_id_from_wasm_result(wasm_result);

    // Expected canister history.
    let reference_change_entries = match environment_variables_flag {
        FlagStatus::Enabled => {
            let env_vars_hash = EnvironmentVariables::new(env_vars.clone()).hash();
            vec![CanisterChange::new(
                now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1, // the canister is created in the next round after the ingress message is received
                0,
                CanisterChangeOrigin::from_canister(ucan.into(), Some(2)),
                CanisterChangeDetails::canister_creation(
                    vec![user_id1, user_id2],
                    Some(env_vars_hash),
                ),
            )]
        }
        FlagStatus::Disabled => {
            vec![CanisterChange::new(
                now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 + 1, // the canister is created in the next round after the ingress message is received
                0,
                CanisterChangeOrigin::from_canister(ucan.into(), Some(2)),
                CanisterChangeDetails::canister_creation(vec![user_id1, user_id2], None),
            )]
        }
    };

    // Verify canister history is updated.
    let history = env.get_canister_history(canister_id);
    assert_eq!(history.get_total_num_changes(), 1);
    let changes = history
        .get_changes(history.get_total_num_changes() as usize)
        .map(|c| (**c).clone())
        .collect::<Vec<CanisterChange>>();
    assert_eq!(changes, reference_change_entries);

    // Verify the environment variables of the canister state.
    let state = env.get_latest_state();
    let canister_state = state.canister_state(&canister_id).unwrap();
    match environment_variables_flag {
        FlagStatus::Enabled => {
            assert_eq!(
                canister_state.system_state.environment_variables,
                EnvironmentVariables::new(env_vars.clone())
            );
        }
        FlagStatus::Disabled => {
            assert_eq!(
                canister_state.system_state.environment_variables,
                EnvironmentVariables::new(BTreeMap::new())
            );
        }
    }
}

#[test]
fn canister_history_tracking_env_vars_update_settings() {
    let user_id = user_test_id(7).get();
    let intial_env_vars = EnvironmentVariables::new(BTreeMap::from([
        ("NODE_ENV".to_string(), "production".to_string()),
        ("LOG_LEVEL".to_string(), "info".to_string()),
    ]));
    let initial_env_vars_hash = intial_env_vars.hash();

    // Set up StateMachine.
    let env = setup_with_environment_variables_flag(FlagStatus::Enabled);
    // Set time of StateMachine to current system time.
    let mut now = std::time::SystemTime::now();
    env.set_time(now);

    let canister_id = env.create_canister_with_cycles(
        None,
        INITIAL_CYCLES_BALANCE,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![user_id])
                .with_environment_variables(
                    intial_env_vars
                        .iter()
                        .map(|(name, value)| EnvironmentVariable {
                            name: name.clone(),
                            value: value.clone(),
                        })
                        .collect::<Vec<_>>(),
                )
                .build(),
        ),
    );

    // Update settings with new environment variables.
    now += Duration::from_secs(5);
    env.set_time(now);
    let env_vars = EnvironmentVariables::new(BTreeMap::from([
        ("NODE_ENV".to_string(), "production".to_string()),
        ("LOG_LEVEL".to_string(), "debug".to_string()),
    ]));

    env.execute_ingress_as(
        user_id,
        ic00::IC_00,
        Method::UpdateSettings,
        UpdateSettingsArgs {
            canister_id: canister_id.into(),
            sender_canister_version: Some(2),
            settings: CanisterSettingsArgsBuilder::new()
                .with_environment_variables(
                    env_vars
                        .iter()
                        .map(|(name, value)| EnvironmentVariable {
                            name: name.clone(),
                            value: value.clone(),
                        })
                        .collect::<Vec<_>>(),
                )
                .build(),
        }
        .encode(),
    )
    .unwrap();

    /*
    // Expected canister history change after update settings.
    let env_vars_hash = env_vars.hash();
    let reference_change = CanisterChange::new(
        now.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64,
        1,
        CanisterChangeOrigin::from_user(user_id),
        CanisterChangeDetails::settings_change(None, Some(env_vars_hash)),
    );
    */

    // Verify canister history is not updated.
    let history = env.get_canister_history(canister_id);
    assert_eq!(history.get_total_num_changes(), 1);
    let changes = history
        .get_changes(history.get_total_num_changes() as usize)
        .map(|c| (**c).clone())
        .collect::<Vec<CanisterChange>>();
    assert_eq!(
        changes[0].details(),
        &CanisterChangeDetails::canister_creation(vec![user_id], Some(initial_env_vars_hash))
    );
    //assert_eq!(changes[1], reference_change);

    // Verify the environment variables of the canister state.
    let state = env.get_latest_state();
    let canister_state = state.canister_state(&canister_id).unwrap();
    assert_eq!(canister_state.system_state.environment_variables, env_vars);
}

#[test]
fn canister_history_no_change_during_update_settings() {
    let user_id = user_test_id(7).get();
    let env = setup_with_environment_variables_flag(FlagStatus::Enabled);
    let canister_id = env.create_canister_with_cycles(
        None,
        INITIAL_CYCLES_BALANCE,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![user_id])
                .build(),
        ),
    );

    let env_vars = BTreeMap::from([
        ("NODE_ENV".to_string(), "production".to_string()),
        ("LOG_LEVEL".to_string(), "info".to_string()),
    ]);

    // Update settings with no controllers changed.
    env.execute_ingress_as(
        user_id,
        ic00::IC_00,
        Method::UpdateSettings,
        UpdateSettingsArgs {
            canister_id: canister_id.into(),
            sender_canister_version: Some(2),
            settings: CanisterSettingsArgsBuilder::new()
                .with_environment_variables(
                    env_vars
                        .clone()
                        .into_iter()
                        .map(|(k, v)| EnvironmentVariable { name: k, value: v })
                        .collect::<Vec<_>>(),
                )
                .build(),
        }
        .encode(),
    )
    .unwrap();

    // Verify canister history contains only the canister creation change.
    let history = env.get_canister_history(canister_id);
    assert_eq!(history.get_total_num_changes(), 1);
    let changes = history
        .get_changes(history.get_total_num_changes() as usize)
        .map(|c| (**c).clone())
        .collect::<Vec<CanisterChange>>();
    assert_eq!(
        changes[0].details(),
        &CanisterChangeDetails::canister_creation(vec![user_id], None)
    );
}

#[test]
fn canister_history_tracking_env_vars_create_canister() {
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    let env_vars = BTreeMap::from([
        ("NODE_ENV".to_string(), "production".to_string()),
        ("LOG_LEVEL".to_string(), "info".to_string()),
    ]);

    let payload = CreateCanisterArgs {
        settings: Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![user_id1, user_id2])
                .with_environment_variables(
                    env_vars
                        .clone()
                        .into_iter()
                        .map(|(k, v)| EnvironmentVariable { name: k, value: v })
                        .collect::<Vec<_>>(),
                )
                .build(),
        ),
        sender_canister_version: Some(2),
    }
    .encode();

    check_environment_variables_for_create_canister_history(
        Method::CreateCanister,
        payload.clone(),
        FlagStatus::Enabled,
        &env_vars,
        user_id1,
        user_id2,
    );

    // TODO(EXC-2071): Delete test when feature flag is removed.
    check_environment_variables_for_create_canister_history(
        Method::CreateCanister,
        payload,
        FlagStatus::Disabled,
        &env_vars,
        user_id1,
        user_id2,
    );
}

#[test]
fn canister_history_tracking_env_vars_provisional_create_canister() {
    let user_id1 = user_test_id(7).get();
    let user_id2 = user_test_id(8).get();

    let env_vars = BTreeMap::from([
        ("NODE_ENV".to_string(), "production".to_string()),
        ("LOG_LEVEL".to_string(), "info".to_string()),
    ]);

    let payload = ProvisionalCreateCanisterWithCyclesArgs {
        amount: Some(candid::Nat::from(INITIAL_CYCLES_BALANCE.get())),
        settings: Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![user_id1, user_id2])
                .with_environment_variables(
                    env_vars
                        .clone()
                        .into_iter()
                        .map(|(k, v)| EnvironmentVariable { name: k, value: v })
                        .collect::<Vec<_>>(),
                )
                .build(),
        ),
        specified_id: None,
        sender_canister_version: Some(2),
    }
    .encode();
    check_environment_variables_for_create_canister_history(
        Method::ProvisionalCreateCanisterWithCycles,
        payload.clone(),
        FlagStatus::Enabled,
        &env_vars,
        user_id1,
        user_id2,
    );

    // TODO(EXC-2071): Delete test when feature flag is removed.
    check_environment_variables_for_create_canister_history(
        Method::ProvisionalCreateCanisterWithCycles,
        payload,
        FlagStatus::Disabled,
        &env_vars,
        user_id1,
        user_id2,
    );
}

#[test]
fn canister_history_tracking_env_vars_update_with_identical_values() {
    let user_id = user_test_id(7).get();
    let env_vars = EnvironmentVariables::new(BTreeMap::from([
        ("NODE_ENV".to_string(), "production".to_string()),
        ("LOG_LEVEL".to_string(), "info".to_string()),
    ]));
    let env_vars_hash = env_vars.hash();
    let env_vars_args = env_vars
        .iter()
        .map(|(name, value)| EnvironmentVariable {
            name: name.clone(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();

    // Set up StateMachine with environment variables tracking enabled.
    let env = setup_with_environment_variables_flag(FlagStatus::Enabled);
    let mut now = std::time::SystemTime::now();
    env.set_time(now);

    // Create canister with initial environment variables.
    let canister_id = env.create_canister_with_cycles(
        None,
        INITIAL_CYCLES_BALANCE,
        Some(
            CanisterSettingsArgsBuilder::new()
                .with_controllers(vec![user_id])
                .with_environment_variables(env_vars_args.clone())
                .build(),
        ),
    );

    // Update settings with the same environment variables.
    now += Duration::from_secs(5);
    env.set_time(now);
    env.execute_ingress_as(
        user_id,
        ic00::IC_00,
        Method::UpdateSettings,
        UpdateSettingsArgs {
            canister_id: canister_id.into(),
            sender_canister_version: Some(2),
            settings: CanisterSettingsArgsBuilder::new()
                .with_environment_variables(env_vars_args)
                .build(),
        }
        .encode(),
    )
    .unwrap();

    // Check canister history: should still only have one entry.
    let history = env.get_canister_history(canister_id);
    assert_eq!(history.get_total_num_changes(), 1);
    let changes = history
        .get_changes(history.get_total_num_changes() as usize)
        .map(|c| (**c).clone())
        .collect::<Vec<CanisterChange>>();

    // First entry: canister creation with env vars.
    assert_eq!(
        changes[0].details(),
        &CanisterChangeDetails::canister_creation(vec![user_id], Some(env_vars_hash))
    );
    /*
    // Second entry: settings change with identical env vars.
    assert_eq!(
        changes[1].details(),
        &CanisterChangeDetails::settings_change(None, Some(env_vars_hash))
    );
    */
    // Also check that the canister's environment variables are as expected.
    let state = env.get_latest_state();
    let canister_state = state.canister_state(&canister_id).unwrap();
    assert_eq!(canister_state.system_state.environment_variables, env_vars);
}

/// Tests that subnet available execution memory matches the canister memory usage
/// after executing the following requests tracked in canister history:
/// - canister creation;
/// - installing/upgrading/reinstalling code;
/// - uninstalling code;
/// - taking canister snapshot;
/// - loading canister snapshot;
/// - changing canister settings (controllers).
///
/// The test also exercises the case of decreasing canister history memory usage
/// after filling canister history with entries of the maximum possible size.
#[test]
fn subnet_available_memory() {
    let mut test = ExecutionTestBuilder::new().build();
    test.set_user_id(user_test_id(0));

    let initial_subnet_available_memory = test.subnet_available_memory();
    let mut current_subnet_available_memory = test.subnet_available_memory();

    let canister_id = test.create_canister_with_default_cycles();

    let mut check_subnet_available_memory = |test: &ExecutionTest, memory_usage_increase: bool| {
        assert_eq!(
            test.subnet_available_memory().get_execution_memory()
                + test.canister_state(canister_id).memory_usage().get() as i64,
            initial_subnet_available_memory.get_execution_memory()
        );
        if memory_usage_increase {
            assert!(
                test.subnet_available_memory().get_execution_memory()
                    < current_subnet_available_memory.get_execution_memory()
            );
        } else {
            assert!(
                test.subnet_available_memory().get_execution_memory()
                    > current_subnet_available_memory.get_execution_memory()
            );
        }
        current_subnet_available_memory = test.subnet_available_memory();
    };

    // memory usage increases after canister creation
    check_subnet_available_memory(&test, true);

    // memory usage increases after installing the universal canister WASM
    test.install_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    check_subnet_available_memory(&test, true);

    // memory usage increases after taking a snapshot
    let take_canister_snapshot_args = TakeCanisterSnapshotArgs::new(canister_id, None, None, None);
    let res = test.subnet_message(
        Method::TakeCanisterSnapshot,
        take_canister_snapshot_args.encode(),
    );
    let snapshot_id = CanisterSnapshotResponse::decode(&get_reply(res))
        .unwrap()
        .id;
    check_subnet_available_memory(&test, true);

    // memory usage increases after upgrading and growing stable memory in post-upgrade
    let grow_payload = wasm().stable_grow(100).build();
    test.upgrade_canister_with_args(
        canister_id,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        grow_payload.clone(),
    )
    .unwrap();
    check_subnet_available_memory(&test, true);

    // memory usage decreases after uninstalling code
    test.uninstall_code(canister_id).unwrap();
    check_subnet_available_memory(&test, false);

    // memory usage increases after reinstalling code and growing stable memory in init
    test.reinstall_canister_with_args(
        canister_id,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        grow_payload.clone(),
    )
    .unwrap();
    check_subnet_available_memory(&test, true);

    // memory usage decreases after loading snapshot since the snapshot was taken with empty stable memory;
    // this way, we also test that `CanisterManager::cycles_and_memory_usage_updates` can handle the case
    // of decreasing memory usage
    let load_canister_snapshot_args = LoadCanisterSnapshotArgs::new(canister_id, snapshot_id, None);
    test.subnet_message(
        Method::LoadCanisterSnapshot,
        load_canister_snapshot_args.encode(),
    )
    .unwrap();
    check_subnet_available_memory(&test, false);

    // memory usage increases after filling canister history with controllers changes
    // setting the maximum number of controllers every time
    for _ in 0..MAX_CANISTER_HISTORY_CHANGES {
        let controllers = (0..MAX_CONTROLLERS)
            .map(|i| user_test_id(i as u64).get())
            .collect();
        test.canister_update_controller(canister_id, controllers)
            .unwrap();
    }
    check_subnet_available_memory(&test, true);

    // memory usage decreases after setting a single controller since
    // canister history is a circular buffer and
    // a change to the maximum number of controllers was just overwriten
    // with a change to a single controller which takes less memory
    test.canister_update_controller(canister_id, vec![test.user_id().get()])
        .unwrap();
    check_subnet_available_memory(&test, false);

    // memory usage decreases after upgrading since
    // canister history is a circular buffer and
    // a change to the maximum number of controllers was just overwriten
    // with a change to upgrade code which takes less memory
    test.upgrade_canister(canister_id, UNIVERSAL_CANISTER_WASM.to_vec())
        .unwrap();
    check_subnet_available_memory(&test, false);
}
