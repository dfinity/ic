use ic_base_types::PrincipalId;
use ic_config::execution_environment;
use ic_config::subnet_config::{SchedulerConfig, SubnetConfig};
use ic_management_canister_types_private::CanisterInstallMode::{Install, Reinstall, Upgrade};
use ic_management_canister_types_private::{
    self as ic00, CanisterIdRecord, CanisterInstallMode, InstallCodeArgs, Method, Payload,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig, UserError};
use ic_types::ingress::{IngressState, IngressStatus};
use ic_types::{CanisterId, Cycles, ingress::WasmResult};
use ic_types_test_utils::ids::user_test_id;
use ic00::CanisterSettingsArgsBuilder;

const INITIAL_CYCLES_BALANCE: Cycles = Cycles::new(100_000_000_000_000);

fn get_canister_version(
    env: &StateMachine,
    canister_id: CanisterId,
    controller: PrincipalId,
) -> u64 {
    let returned_version = env
        .canister_status_as(controller, canister_id)
        .unwrap()
        .unwrap()
        .version();
    let system_version = env
        .get_latest_state()
        .canister_state(&canister_id)
        .unwrap()
        .system_state
        .canister_version;
    assert_eq!(returned_version, system_version);
    system_version
}

/// This function implements the functionality of `StateMachine::execute_ingress_as`
/// and additionally asserts that DTS is used if the parameter `dts` is true.
fn execute_ingress_with_dts(
    env: &StateMachine,
    sender: PrincipalId,
    canister_id: CanisterId,
    method: impl ToString,
    payload: Vec<u8>,
    dts: bool,
) -> Result<WasmResult, UserError> {
    const MAX_TICKS: usize = 100;
    let msg_id = env.send_ingress(sender, canister_id, method, payload);
    for tick in 0..MAX_TICKS {
        match env.ingress_status(&msg_id) {
            IngressStatus::Known {
                state: IngressState::Completed(result),
                ..
            } => {
                assert_eq!(dts, 0 < tick);
                return Ok(result);
            }
            IngressStatus::Known {
                state: IngressState::Failed(error),
                ..
            } => return Err(error),
            _ => {
                env.tick();
            }
        }
    }
    panic!("Did not get answer to ingress {msg_id} after {MAX_TICKS} state machine ticks",)
}

/// Creates, installs, and possibly reinstall/upgrades (depends on `mode`) the canister code
/// compiled from its WAT representation;
/// and checks the canister version after each of these operations
fn test(wat: &str, mode: CanisterInstallMode, dts_install: bool, dts_upgrade: bool) {
    let test_canister = wat::parse_str(wat).expect("invalid WAT");

    let subnet_config = SubnetConfig::new(SubnetType::Application);
    let subnet_config = SubnetConfig {
        scheduler_config: SchedulerConfig {
            max_instructions_per_install_code_slice: 100_000.into(),
            max_instructions_per_slice: 100_000.into(),
            install_code_rate_limit: 1_000_000_000_000_000.into(),
            ..subnet_config.scheduler_config
        },
        ..subnet_config
    };
    let config = StateMachineConfig::new(subnet_config, execution_environment::Config::default());

    // set up StateMachine
    let env = StateMachineBuilder::new()
        .with_config(Some(config))
        .with_subnet_type(SubnetType::Application)
        .build();

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
        WasmResult::Reject(reason) => panic!("create_canister call rejected: {reason}"),
    };
    // check canister_version
    assert_eq!(get_canister_version(&env, canister_id, user_id), 0);

    // install test_canister via ingress from user_id
    execute_ingress_with_dts(
        &env,
        user_id,
        ic00::IC_00,
        Method::InstallCode,
        InstallCodeArgs::new(Install, canister_id, test_canister.clone(), vec![]).encode(),
        dts_install,
    )
    .unwrap();
    // check canister_version
    assert_eq!(get_canister_version(&env, canister_id, user_id), 1);

    if mode != CanisterInstallMode::Install {
        let dts = match mode {
            CanisterInstallMode::Reinstall => dts_install,
            CanisterInstallMode::Upgrade => dts_upgrade,
            CanisterInstallMode::Install => panic!("unreachable"),
        };
        // install test_canister via ingress from user_id
        execute_ingress_with_dts(
            &env,
            user_id,
            ic00::IC_00,
            Method::InstallCode,
            InstallCodeArgs::new(mode, canister_id, test_canister, vec![]).encode(),
            dts,
        )
        .unwrap();
        // check canister_version
        assert_eq!(get_canister_version(&env, canister_id, user_id), 2);
    }
}

fn canister_wat(b1: Option<bool>, b2: Option<bool>, b3: Option<bool>, b4: Option<bool>) -> String {
    let mut res = r#"(module
    (func $noop
      return
    )
    (func $loop
      (local $i i64)
      (loop $my_loop
        ;; add one to $i
        local.get $i
        i64.const 1
        i64.add
        local.set $i
        ;; loop if $i is less than 100_000
        local.get $i
        i64.const 100_000
        i64.lt_s
        br_if $my_loop
      )
    )
"#
    .to_string();
    if let Some(dts) = b1 {
        if dts {
            res.push_str("    (start $loop)\n");
        } else {
            res.push_str("    (start $noop)\n");
        }
    }
    if let Some(dts) = b2 {
        if dts {
            res.push_str("    (export \"canister_init\" (func $loop))\n");
        } else {
            res.push_str("    (export \"canister_init\" (func $noop))\n");
        }
    }
    if let Some(dts) = b3 {
        if dts {
            res.push_str("    (export \"canister_pre_upgrade\" (func $loop))\n");
        } else {
            res.push_str("    (export \"canister_pre_upgrade\" (func $noop))\n");
        }
    }
    if let Some(dts) = b4 {
        if dts {
            res.push_str("    (export \"canister_post_upgrade\" (func $loop))\n");
        } else {
            res.push_str("    (export \"canister_post_upgrade\" (func $noop))\n");
        }
    }
    let end = ")\n".to_string();
    res.push_str(&end);
    res
}

#[test]
fn canister_version() {
    let opts = [None, Some(false), Some(true)];
    for b1 in opts {
        for b2 in opts {
            for b3 in opts {
                for b4 in opts {
                    let test_canister: &str = &canister_wat(b1, b2, b3, b4);
                    let dts_install = b1 == Some(true) || b2 == Some(true);
                    let dts_upgrade = b1 == Some(true) || b3 == Some(true) || b4 == Some(true);
                    test(test_canister, Install, dts_install, dts_upgrade);
                    test(test_canister, Reinstall, dts_install, dts_upgrade);
                    test(test_canister, Upgrade, dts_install, dts_upgrade);
                }
            }
        }
    }
}
