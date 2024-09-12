use ic_base_types::{NumBytes, NumSeconds, PrincipalIdBlobParseError};
use ic_config::{
    embedders::Config as EmbeddersConfig, flag_status::FlagStatus, subnet_config::SchedulerConfig,
};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::RejectCode;
use ic_interfaces::execution_environment::{
    CanisterOutOfCyclesError, ExecutionMode, HypervisorError, HypervisorResult,
    PerformanceCounterType, StableMemoryApi, SubnetAvailableMemory, SystemApi, SystemApiCallId,
    TrapCode,
};
use ic_limits::SMALL_APP_SUBNET_MAX_SIZE;
use ic_logger::replica_logger::no_op_logger;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    canister_state::system_state::OnLowWasmMemoryHookStatus, testing::CanisterQueuesTesting,
    CallOrigin, Memory, NetworkTopology, SystemState,
};
use ic_system_api::{
    sandbox_safe_system_state::SandboxSafeSystemState, ApiType, DefaultOutOfInstructionsHandler,
    SystemApiImpl,
};
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_state::SystemStateBuilder;
use ic_test_utilities_types::{
    ids::{call_context_test_id, canister_test_id, subnet_test_id, user_test_id},
    messages::RequestBuilder,
};
use ic_types::{
    messages::{CallbackId, RejectContext, RequestMetadata, MAX_RESPONSE_COUNT_BYTES, NO_DEADLINE},
    methods::{Callback, WasmClosure},
    time,
    time::UNIX_EPOCH,
    CanisterTimer, CountBytes, Cycles, NumInstructions, PrincipalId, Time,
    MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE,
};
use maplit::btreemap;
use more_asserts::assert_le;
use std::{
    collections::BTreeSet,
    convert::From,
    panic::{catch_unwind, UnwindSafe},
    rc::Rc,
};
use strum::IntoEnumIterator;

mod common;
use common::*;

const INITIAL_CYCLES: Cycles = Cycles::new(1 << 40);

fn get_system_state_with_cycles(cycles_amount: Cycles) -> SystemState {
    SystemState::new_running_for_testing(
        canister_test_id(42),
        user_test_id(24).get(),
        cycles_amount,
        NumSeconds::from(100_000),
    )
}

fn assert_api_supported<T>(res: HypervisorResult<T>) {
    res.unwrap();
}

fn assert_trap_supported<T>(res: HypervisorResult<T>) {
    match res {
        Err(HypervisorError::CalledTrap { .. }) => (),
        _ => panic!("Expected HypervisorError::CalledTrap"),
    }
}

fn assert_api_not_supported<T>(res: HypervisorResult<T>) {
    match res {
        Err(HypervisorError::UserContractViolation { error, .. }) => {
            assert!(error.contains("cannot be executed"), "{}", error)
        }
        Err(HypervisorError::ToolchainContractViolation { error }) => {
            assert!(error.contains("cannot be executed"), "{}", error)
        }
        _ => unreachable!("Expected api to be unsupported."),
    }
}

fn assert_api_availability<T, F>(
    f: F,
    api_type: ApiType,
    system_state: &SystemState,
    cycles_account_manager: CyclesAccountManager,
    api_type_enum: SystemApiCallId,
    context: &str,
) where
    F: Fn(SystemApiImpl) -> HypervisorResult<T>,
{
    #[allow(unused_mut)]
    let mut api = get_system_api(api_type, system_state, cycles_account_manager);
    let res = f(api);
    if is_supported(api_type_enum, context) {
        assert_api_supported(res)
    } else {
        assert_api_not_supported(res)
    }
}

/// This struct is used in the following tests to move a `&mut SystemApiImpl`
/// into a closure executed in `catch_unwind` so that we can assert certain
/// system APIs panic. `SystemApiImpl` may not actually be `UnwindSafe`, but all
/// the panicking APIs should panic immediately without modifying or reading any
/// mutable state of the `SystemApiImpl`. So it's fine to pretend it's
/// `UnwindSafe` for the purposes of this test.
struct ForcedUnwindSafe<T>(T);
impl<T> ForcedUnwindSafe<T> {
    fn inner(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T> UnwindSafe for ForcedUnwindSafe<T> {}

fn assert_stable_apis_panic(mut api: SystemApiImpl) {
    let mut unwind_api = ForcedUnwindSafe(&mut api);
    catch_unwind(move || unwind_api.inner().ic0_stable_size())
        .expect_err("Stable API should panic");
    let mut unwind_api = ForcedUnwindSafe(&mut api);
    catch_unwind(move || unwind_api.inner().ic0_stable_grow(1))
        .expect_err("Stable API should panic");
    let mut unwind_api = ForcedUnwindSafe(&mut api);
    catch_unwind(move || unwind_api.inner().ic0_stable_read(0, 0, 0, &mut []))
        .expect_err("Stable API should panic");
    let mut unwind_api = ForcedUnwindSafe(&mut api);
    catch_unwind(move || unwind_api.inner().ic0_stable_write(0, 0, 0, &[]))
        .expect_err("Stable API should panic");
    let mut unwind_api = ForcedUnwindSafe(&mut api);
    catch_unwind(move || unwind_api.inner().ic0_stable64_size())
        .expect_err("Stable API should panic");
    let mut unwind_api = ForcedUnwindSafe(&mut api);
    catch_unwind(move || unwind_api.inner().ic0_stable64_grow(1))
        .expect_err("Stable API should panic");
    let mut unwind_api = ForcedUnwindSafe(&mut api);
    catch_unwind(move || unwind_api.inner().ic0_stable64_read(0, 0, 0, &mut []))
        .expect_err("Stable API should panic");
    let mut unwind_api = ForcedUnwindSafe(&mut api);
    catch_unwind(move || unwind_api.inner().ic0_stable64_write(0, 0, 0, &[]))
        .expect_err("Stable API should panic");
}

fn check_stable_apis_support(mut api: SystemApiImpl) {
    match EmbeddersConfig::default()
        .feature_flags
        .wasm_native_stable_memory
    {
        FlagStatus::Enabled => assert_stable_apis_panic(api),
        FlagStatus::Disabled => {
            assert_api_supported(api.ic0_stable_size());
            assert_api_supported(api.ic0_stable_grow(1));
            assert_api_supported(api.ic0_stable_read(0, 0, 0, &mut []));
            assert_api_supported(api.ic0_stable_write(0, 0, 0, &[]));
            assert_api_supported(api.ic0_stable64_size());
            assert_api_supported(api.ic0_stable64_grow(1));
            assert_api_supported(api.ic0_stable64_read(0, 0, 0, &mut []));
            assert_api_supported(api.ic0_stable64_write(0, 0, 0, &[]));
        }
    }
}

fn init_api() -> ApiType {
    ApiType::init(UNIX_EPOCH, vec![], user_test_id(1).get())
}

fn update_api() -> ApiType {
    ApiTypeBuilder::build_update_api()
}

fn replicated_query_api() -> ApiType {
    ApiType::replicated_query(UNIX_EPOCH, vec![], user_test_id(1).get())
}

fn non_replicated_query_api() -> ApiType {
    ApiTypeBuilder::build_non_replicated_query_api()
}

fn composite_query_api() -> ApiType {
    ApiTypeBuilder::build_composite_query_api()
}

fn reply_api() -> ApiType {
    ApiTypeBuilder::build_reply_api(Cycles::zero())
}

fn composite_reply_api() -> ApiType {
    ApiTypeBuilder::build_composite_reply_api(Cycles::zero())
}

fn reject_api() -> ApiType {
    ApiTypeBuilder::build_reject_api(RejectContext::new(RejectCode::CanisterReject, "error"))
}

fn composite_reject_api() -> ApiType {
    ApiTypeBuilder::build_composite_reject_api(RejectContext::new(
        RejectCode::CanisterReject,
        "error",
    ))
}

fn pre_upgrade_api() -> ApiType {
    ApiType::pre_upgrade(UNIX_EPOCH, user_test_id(1).get())
}

fn start_api() -> ApiType {
    ApiType::start(UNIX_EPOCH)
}

fn cleanup_api() -> ApiType {
    ApiType::Cleanup {
        caller: PrincipalId::new_anonymous(),
        time: UNIX_EPOCH,
        execution_mode: ExecutionMode::Replicated,
        call_context_instructions_executed: 0.into(),
    }
}

fn composite_cleanup_api() -> ApiType {
    ApiType::Cleanup {
        caller: PrincipalId::new_anonymous(),
        time: UNIX_EPOCH,
        execution_mode: ExecutionMode::NonReplicated,
        call_context_instructions_executed: 0.into(),
    }
}

fn inspect_message_api() -> ApiType {
    ApiType::inspect_message(user_test_id(1).get(), "".to_string(), vec![], UNIX_EPOCH)
}

fn system_task_api() -> ApiType {
    ApiTypeBuilder::build_system_task_api()
}

fn is_supported(api_type: SystemApiCallId, context: &str) -> bool {
    // the following matrix follows the Interface Spec:
    // https://internetcomputer.org/docs/current/references/ic-interface-spec#system-api-imports
    // ic0.mint_cycles is not specified there as it is only available for CMC
    let matrix = btreemap! {
        SystemApiCallId::MsgArgDataSize => vec!["I", "U", "RQ", "NRQ", "CQ", "Ry", "CRy", "F"],
        SystemApiCallId::MsgArgDataCopy => vec!["I", "U", "RQ", "NRQ", "CQ", "Ry", "CRy", "F"],
        SystemApiCallId::MsgCallerSize => vec!["*"],
        SystemApiCallId::MsgCallerCopy => vec!["*"],
        SystemApiCallId::MsgRejectCode => vec!["Ry", "Rt", "CRy", "CRt"],
        SystemApiCallId::MsgRejectMsgSize => vec!["Rt", "CRt"],
        SystemApiCallId::MsgRejectMsgCopy => vec!["Rt", "CRt"],
        SystemApiCallId::MsgReplyDataAppend => vec!["U", "RQ", "NRQ", "CQ", "Ry", "Rt", "CRy", "CRt"],
        SystemApiCallId::MsgReply => vec!["U", "RQ", "NRQ", "CQ", "Ry", "Rt", "CRy", "CRt"],
        SystemApiCallId::MsgReject => vec!["U", "RQ", "NRQ", "CQ", "Ry", "Rt", "CRy", "CRt"],
        SystemApiCallId::MsgDeadline => vec!["U", "RQ", "NRQ", "CQ", "Ry", "Rt", "CRy", "CRt"],
        SystemApiCallId::MsgCyclesAvailable => vec!["U", "Rt", "Ry"],
        SystemApiCallId::MsgCyclesAvailable128 => vec!["U", "Rt", "Ry"],
        SystemApiCallId::MsgCyclesRefunded => vec!["Rt", "Ry"],
        SystemApiCallId::MsgCyclesRefunded128 => vec!["Rt", "Ry"],
        SystemApiCallId::MsgCyclesAccept => vec!["U", "Rt", "Ry"],
        SystemApiCallId::MsgCyclesAccept128 => vec!["U", "Rt", "Ry"],
        SystemApiCallId::CyclesBurn128 => vec!["I", "G", "U", "Ry", "Rt", "C", "T"],
        SystemApiCallId::CanisterSelfSize => vec!["*"],
        SystemApiCallId::CanisterSelfCopy => vec!["*"],
        SystemApiCallId::CanisterCycleBalance => vec!["*"],
        SystemApiCallId::CanisterCycleBalance128 => vec!["*"],
        SystemApiCallId::CanisterStatus => vec!["*"],
        SystemApiCallId::CanisterVersion => vec!["*"],
        SystemApiCallId::MsgMethodNameSize => vec!["F"],
        SystemApiCallId::MsgMethodNameCopy => vec!["F"],
        SystemApiCallId::AcceptMessage => vec!["F"],
        SystemApiCallId::CallNew => vec!["U", "CQ", "Ry", "Rt", "CRy", "CRt", "T"],
        SystemApiCallId::CallOnCleanup => vec!["U", "CQ", "Ry", "Rt", "CRy", "CRt", "T"],
        SystemApiCallId::CallDataAppend => vec!["U", "CQ", "Ry", "Rt", "CRy", "CRt", "T"],
        SystemApiCallId::CallCyclesAdd => vec!["U", "Ry", "Rt", "T"],
        SystemApiCallId::CallCyclesAdd128 => vec!["U", "Ry", "Rt", "T"],
        SystemApiCallId::CallPerform => vec!["U", "CQ", "Ry", "Rt", "CRy", "CRt", "T"],
        SystemApiCallId::CallWithBestEffortResponse => vec!["U", "CQ", "Ry", "Rt", "CRy", "CRt", "T"],
        SystemApiCallId::StableSize => vec!["*", "s"],
        SystemApiCallId::StableGrow => vec!["*", "s"],
        SystemApiCallId::StableWrite => vec!["*", "s"],
        SystemApiCallId::StableRead => vec!["*", "s"],
        SystemApiCallId::Stable64Size => vec!["*", "s"],
        SystemApiCallId::Stable64Grow => vec!["*", "s"],
        SystemApiCallId::Stable64Write => vec!["*", "s"],
        SystemApiCallId::Stable64Read => vec!["*", "s"],
        SystemApiCallId::CertifiedDataSet => vec!["I", "G", "U", "Ry", "Rt", "T"],
        SystemApiCallId::DataCertificatePresent => vec!["*"],
        SystemApiCallId::DataCertificateSize => vec!["NRQ", "CQ"],
        SystemApiCallId::DataCertificateCopy => vec!["NRQ", "CQ"],
        SystemApiCallId::Time => vec!["*"],
        SystemApiCallId::GlobalTimerSet => vec!["I", "G", "U", "Ry", "Rt", "C", "T"],
        SystemApiCallId::PerformanceCounter => vec!["*", "s"],
        SystemApiCallId::IsController => vec!["*", "s"],
        SystemApiCallId::InReplicatedExecution => vec!["*", "s"],
        SystemApiCallId::DebugPrint => vec!["*", "s"],
        SystemApiCallId::Trap => vec!["*", "s"],
        SystemApiCallId::MintCycles => vec!["U", "Ry", "Rt", "T"]
    };
    // the semantics of "*" is to cover all modes except for "s"
    matrix.get(&api_type).unwrap().contains(&context)
        || (context != "s" && matrix.get(&api_type).unwrap().contains(&"*"))
}

fn api_availability_test(
    api_type: ApiType,
    cycles_account_manager: CyclesAccountManager,
    api_type_enum: SystemApiCallId,
    context: &str,
) {
    let system_state = get_system_state();
    match api_type_enum {
        SystemApiCallId::MsgCallerSize => {
            assert_api_availability(
                |api| api.ic0_msg_caller_size(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgCallerCopy => {
            assert_api_availability(
                |api| api.ic0_msg_caller_copy(0, 0, 0, &mut [42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgArgDataSize => {
            assert_api_availability(
                |api| api.ic0_msg_arg_data_size(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgArgDataCopy => {
            assert_api_availability(
                |api| api.ic0_msg_arg_data_copy(0, 0, 0, &mut [42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgMethodNameSize => {
            assert_api_availability(
                |api| api.ic0_msg_method_name_size(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgMethodNameCopy => {
            assert_api_availability(
                |api| api.ic0_msg_method_name_copy(0, 0, 0, &mut [42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::AcceptMessage => {
            assert_api_availability(
                |mut api| api.ic0_accept_message(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgReply => {
            assert_api_availability(
                |mut api| api.ic0_msg_reply(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgReplyDataAppend => {
            assert_api_availability(
                |mut api| api.ic0_msg_reply_data_append(0, 0, &[42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgDeadline => {
            assert_api_availability(
                |api| api.ic0_msg_deadline(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgReject => {
            assert_api_availability(
                |mut api| api.ic0_msg_reject(0, 0, &[42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgRejectCode => {
            assert_api_availability(
                |api| api.ic0_msg_reject_code(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgRejectMsgSize => {
            assert_api_availability(
                |api| api.ic0_msg_reject_msg_size(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgRejectMsgCopy => {
            assert_api_availability(
                |api| api.ic0_msg_reject_msg_copy(0, 0, 0, &mut [42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CanisterSelfSize => {
            assert_api_availability(
                |api| api.ic0_canister_self_size(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CanisterSelfCopy => {
            assert_api_availability(
                |mut api| api.ic0_canister_self_copy(0, 0, 0, &mut [42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::DebugPrint => {
            assert_api_availability(
                |api| api.ic0_debug_print(0, 0, &[42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::Trap => {
            let api = get_system_api(api_type, &system_state, cycles_account_manager);
            assert_trap_supported(api.ic0_trap(0, 0, &[42; 128]));
        }
        SystemApiCallId::CallNew => {
            assert_api_availability(
                |mut api| api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CallDataAppend => {
            assert_api_availability(
                |mut api| {
                    let _ = api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[42; 128]);
                    api.ic0_call_data_append(0, 0, &[42; 128])
                },
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CallWithBestEffortResponse => {
            assert_api_availability(
                |mut api| {
                    let _ = api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[42; 128]);
                    api.ic0_call_with_best_effort_response(0)
                },
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CallOnCleanup => {
            assert_api_availability(
                |mut api| {
                    let _ = api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[42; 128]);
                    api.ic0_call_on_cleanup(0, 0)
                },
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CallCyclesAdd => {
            assert_api_availability(
                |mut api| {
                    let _ = api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[42; 128]);
                    api.ic0_call_cycles_add(0)
                },
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CallCyclesAdd128 => {
            assert_api_availability(
                |mut api| {
                    let _ = api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[42; 128]);
                    api.ic0_call_cycles_add128(Cycles::new(0))
                },
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CallPerform => {
            assert_api_availability(
                |mut api| {
                    let _ = api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[42; 128]);
                    api.ic0_call_perform()
                },
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::Time => {
            assert_api_availability(
                |mut api| api.ic0_time(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CanisterVersion => {
            assert_api_availability(
                |api| api.ic0_canister_version(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::GlobalTimerSet => {
            assert_api_availability(
                |mut api| api.ic0_global_timer_set(time::UNIX_EPOCH),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::PerformanceCounter => {
            assert_api_availability(
                |api| api.ic0_performance_counter(PerformanceCounterType::Instructions(0.into())),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CanisterCycleBalance => {
            assert_api_availability(
                |mut api| api.ic0_canister_cycle_balance(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CanisterCycleBalance128 => {
            assert_api_availability(
                |mut api| api.ic0_canister_cycle_balance128(0, &mut [42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgCyclesAvailable => {
            assert_api_availability(
                |api| api.ic0_msg_cycles_available(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgCyclesAvailable128 => {
            assert_api_availability(
                |api| api.ic0_msg_cycles_available128(0, &mut [42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgCyclesRefunded => {
            assert_api_availability(
                |api| api.ic0_msg_cycles_refunded(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgCyclesRefunded128 => {
            assert_api_availability(
                |api| api.ic0_msg_cycles_refunded128(0, &mut [42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgCyclesAccept => {
            assert_api_availability(
                |mut api| api.ic0_msg_cycles_accept(0),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MsgCyclesAccept128 => {
            assert_api_availability(
                |mut api| api.ic0_msg_cycles_accept128(Cycles::zero(), 0, &mut [42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::DataCertificatePresent => {
            assert_api_availability(
                |api| api.ic0_data_certificate_present(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::DataCertificateSize => {
            assert_api_availability(
                |api| api.ic0_data_certificate_size(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::DataCertificateCopy => {
            assert_api_availability(
                |mut api| api.ic0_data_certificate_copy(0, 0, 0, &mut [42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CertifiedDataSet => {
            assert_api_availability(
                |mut api| api.ic0_certified_data_set(0, 0, &[42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CanisterStatus => {
            assert_api_availability(
                |api| api.ic0_canister_status(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::MintCycles => {
            // ic0.mint_cycles is only supported for CMC which is tested separately
            let mut api = get_system_api(api_type, &system_state, cycles_account_manager);
            assert_api_not_supported(api.ic0_mint_cycles(0));
        }
        SystemApiCallId::IsController => {
            assert_api_availability(
                |api| api.ic0_is_controller(0, 0, &[42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::InReplicatedExecution => {
            assert_api_availability(
                |api| api.ic0_in_replicated_execution(),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        SystemApiCallId::CyclesBurn128 => {
            assert_api_availability(
                |mut api| api.ic0_cycles_burn128(Cycles::zero(), 0, &mut [42; 128]),
                api_type,
                &system_state,
                cycles_account_manager,
                api_type_enum,
                context,
            );
        }
        // stable API is tested separately
        SystemApiCallId::StableGrow
        | SystemApiCallId::StableRead
        | SystemApiCallId::StableSize
        | SystemApiCallId::StableWrite
        | SystemApiCallId::Stable64Grow
        | SystemApiCallId::Stable64Read
        | SystemApiCallId::Stable64Size
        | SystemApiCallId::Stable64Write => {}
        // OutOfInstructions and TryGrowWasmMemory are private
        SystemApiCallId::OutOfInstructions => {}
        SystemApiCallId::TryGrowWasmMemory => {}
    }
}

#[test]
fn system_api_availability() {
    for subnet_type in [
        SubnetType::System,
        SubnetType::Application,
        SubnetType::VerifiedApplication,
    ] {
        for (context, api_type) in [
            ("I", init_api()),
            ("U", update_api()),
            ("RQ", replicated_query_api()),
            ("NRQ", non_replicated_query_api()),
            ("CQ", composite_query_api()),
            ("Ry", reply_api()),
            ("CRy", composite_reply_api()),
            ("Rt", reject_api()),
            ("CRt", composite_reject_api()),
            ("G", pre_upgrade_api()),
            ("s", start_api()),
            ("C", cleanup_api()),
            ("CC", composite_cleanup_api()),
            ("F", inspect_message_api()),
            ("T", system_task_api()),
        ] {
            // check stable API availability
            let system_state = get_system_state();
            let cycles_account_manager = CyclesAccountManagerBuilder::new()
                .with_subnet_type(subnet_type)
                .build();
            let api = get_system_api(api_type.clone(), &system_state, cycles_account_manager);
            check_stable_apis_support(api);

            // check ic0.mint_cycles API availability for CMC
            let cmc_system_state = get_cmc_system_state();
            assert_api_availability(
                |mut api| api.ic0_mint_cycles(0),
                api_type.clone(),
                &cmc_system_state,
                cycles_account_manager,
                SystemApiCallId::MintCycles,
                context,
            );

            // now check all other API availability for non-CMC
            for api_type_enum in SystemApiCallId::iter() {
                api_availability_test(
                    api_type.clone(),
                    cycles_account_manager,
                    api_type_enum,
                    context,
                );
            }
        }
    }
}

#[test]
fn test_discard_cycles_charge_by_new_call() {
    let cycles_amount = Cycles::from(1_000_000_000_000u128);
    let max_num_instructions = NumInstructions::from(1 << 30);
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(max_num_instructions)
        .build();
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &get_system_state_with_cycles(cycles_amount),
        cycles_account_manager,
    );

    // Check ic0_canister_cycle_balance after first ic0_call_new.
    assert_eq!(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]), Ok(()));
    // Check cycles balance.
    assert_eq!(
        Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
        cycles_amount
    );

    // Add cycles to call.
    let amount = Cycles::new(49);
    assert_eq!(api.ic0_call_cycles_add128(amount), Ok(()));
    // Check cycles balance after call_add_cycles.
    assert_eq!(
        Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
        cycles_amount - amount
    );

    // Discard the previous call
    assert_eq!(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]), Ok(()));
    // Check cycles balance -> should be the same as the original as the call was
    // discarded.
    assert_eq!(
        Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
        cycles_amount
    );
}

#[test]
fn test_fail_add_cycles_when_not_enough_balance() {
    let cycles_amount = Cycles::from(1_000_000_000_000u128);
    let max_num_instructions = NumInstructions::from(1 << 30);
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(max_num_instructions)
        .build();
    let system_state = get_system_state_with_cycles(cycles_amount);
    let canister_id = system_state.canister_id();
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        cycles_account_manager,
    );

    // Check ic0_canister_cycle_balance after first ic0_call_new.
    assert_eq!(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]), Ok(()));
    // Check cycles balance.
    assert_eq!(
        Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
        cycles_amount
    );

    // Add cycles to call.
    let amount = cycles_amount + Cycles::new(1);
    assert_eq!(
        api.ic0_call_cycles_add128(amount).unwrap_err(),
        HypervisorError::InsufficientCyclesBalance(CanisterOutOfCyclesError {
            canister_id,
            available: cycles_amount,
            threshold: Cycles::zero(),
            requested: amount,
            reveal_top_up: false,
        })
    );
    //Check cycles balance after call_add_cycles.
    assert_eq!(
        Cycles::from(api.ic0_canister_cycle_balance().unwrap()),
        cycles_amount
    );
}

#[test]
fn test_fail_adding_more_cycles_when_not_enough_balance() {
    let cycles_amount = 1_000_000_000_000;
    let max_num_instructions = NumInstructions::from(1 << 30);
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(max_num_instructions)
        .build();
    let system_state = get_system_state_with_cycles(Cycles::from(cycles_amount));
    let canister_id = system_state.canister_id();
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        cycles_account_manager,
    );

    // Check ic0_canister_cycle_balance after first ic0_call_new.
    assert_eq!(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]), Ok(()));
    // Check cycles balance.
    assert_eq!(
        api.ic0_canister_cycle_balance().unwrap() as u128,
        cycles_amount
    );

    // Add cycles to call.
    let amount = cycles_amount / 2 + 1;
    assert_eq!(api.ic0_call_cycles_add128(amount.into()), Ok(()));
    // Check cycles balance after call_add_cycles.
    assert_eq!(
        api.ic0_canister_cycle_balance().unwrap() as u128,
        cycles_amount - amount
    );

    // Adding more cycles fails because not enough balance left.
    assert_eq!(
        api.ic0_call_cycles_add128(amount.into()).unwrap_err(),
        HypervisorError::InsufficientCyclesBalance(CanisterOutOfCyclesError {
            canister_id,
            available: Cycles::from(cycles_amount - amount),
            threshold: Cycles::zero(),
            requested: Cycles::from(amount),
            reveal_top_up: false,
        })
    );
    // Balance unchanged after the second call_add_cycles.
    assert_eq!(
        api.ic0_canister_cycle_balance().unwrap() as u128,
        cycles_amount - amount
    );
}

#[test]
fn test_canister_balance() {
    let cycles_amount = 100;
    let max_num_instructions = NumInstructions::from(1 << 30);
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(max_num_instructions)
        .build();
    let mut system_state = get_system_state_with_cycles(Cycles::from(cycles_amount));

    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5), NO_DEADLINE),
            Cycles::new(50),
            Time::from_nanos_since_unix_epoch(0),
            RequestMetadata::new(0, UNIX_EPOCH),
        );

    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        cycles_account_manager,
    );

    // Check cycles balance.
    assert_eq!(api.ic0_canister_cycle_balance().unwrap(), cycles_amount);
}

#[test]
fn test_canister_cycle_balance() {
    let cycles_amount = Cycles::from(123456789012345678901234567890u128);
    let max_num_instructions = NumInstructions::from(1 << 30);
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_max_num_instructions(max_num_instructions)
        .build();
    let mut system_state = get_system_state_with_cycles(cycles_amount);

    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5), NO_DEADLINE),
            Cycles::new(50),
            Time::from_nanos_since_unix_epoch(0),
            RequestMetadata::new(0, UNIX_EPOCH),
        );

    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        cycles_account_manager,
    );

    // Check ic0_canister_cycle_balance.
    assert_eq!(
        api.ic0_canister_cycle_balance(),
        Err(HypervisorError::Trapped(
            TrapCode::CyclesAmountTooBigFor64Bit
        ))
    );

    let mut heap = vec![0; 16];
    api.ic0_canister_cycle_balance128(0, &mut heap).unwrap();
    assert_eq!(heap, cycles_amount.get().to_le_bytes());
}

#[test]
fn test_msg_cycles_available_traps() {
    let cycles_amount = Cycles::from(123456789012345678901234567890u128);
    let available_cycles = Cycles::from(789012345678901234567890u128);
    let mut system_state = get_system_state_with_cycles(cycles_amount);
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5), NO_DEADLINE),
            available_cycles,
            Time::from_nanos_since_unix_epoch(0),
            RequestMetadata::new(0, UNIX_EPOCH),
        );

    let api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        cycles_account_manager,
    );

    assert_eq!(
        api.ic0_msg_cycles_available(),
        Err(HypervisorError::Trapped(
            TrapCode::CyclesAmountTooBigFor64Bit
        ))
    );

    let mut heap = vec![0; 16];
    api.ic0_msg_cycles_available128(0, &mut heap).unwrap();
    assert_eq!(heap, available_cycles.get().to_le_bytes());
}

#[test]
fn test_msg_cycles_refunded_traps() {
    let incoming_cycles = Cycles::from(789012345678901234567890u128);
    let cycles_amount = Cycles::from(123456789012345678901234567890u128);
    let system_state = get_system_state_with_cycles(cycles_amount);
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let api = get_system_api(
        ApiTypeBuilder::build_reply_api(incoming_cycles),
        &system_state,
        cycles_account_manager,
    );

    assert_eq!(
        api.ic0_msg_cycles_refunded(),
        Err(HypervisorError::Trapped(
            TrapCode::CyclesAmountTooBigFor64Bit
        ))
    );

    let mut heap = vec![0; 16];
    api.ic0_msg_cycles_refunded128(0, &mut heap).unwrap();
    assert_eq!(heap, incoming_cycles.get().to_le_bytes());
}

#[test]
fn certified_data_set() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let mut system_state = SystemStateBuilder::default().build();
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        cycles_account_manager,
    );
    let heap = vec![10; 33];

    // Setting more than 32 bytes fails.
    assert!(api.ic0_certified_data_set(0, 33, &heap).is_err());

    // Setting out of bounds size fails.
    assert!(api.ic0_certified_data_set(30, 10, &heap).is_err());

    // Copy the certified data into the system state.
    api.ic0_certified_data_set(0, 32, &heap).unwrap();

    let system_state_changes = api.into_system_state_changes();
    system_state_changes
        .apply_changes(
            UNIX_EPOCH,
            &mut system_state,
            &default_network_topology(),
            subnet_test_id(1),
            &no_op_logger(),
        )
        .unwrap();
    assert_eq!(system_state.certified_data, vec![10; 32])
}

#[test]
fn data_certificate_copy() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let system_state = SystemStateBuilder::default().build();
    let mut api = get_system_api(
        ApiType::non_replicated_query(
            UNIX_EPOCH,
            user_test_id(1).get(),
            subnet_test_id(1),
            vec![],
            Some(vec![1, 2, 3, 4, 5, 6]),
            ic_system_api::NonReplicatedQueryKind::Pure,
        ),
        &system_state,
        cycles_account_manager,
    );
    let mut heap = vec![0; 10];

    // Copying with out of bounds offset + size fails.
    assert!(api.ic0_data_certificate_copy(0, 0, 10, &mut heap).is_err());
    assert!(api.ic0_data_certificate_copy(0, 10, 1, &mut heap).is_err());

    // Copying with out of bounds dst + size fails.
    assert!(api.ic0_data_certificate_copy(10, 1, 1, &mut heap).is_err());
    assert!(api.ic0_data_certificate_copy(0, 1, 11, &mut heap).is_err());

    // Copying all the data certificate.
    api.ic0_data_certificate_copy(0, 0, 6, &mut heap).unwrap();
    assert_eq!(heap, vec![1, 2, 3, 4, 5, 6, 0, 0, 0, 0]);

    // Copying part of the data certificate.
    api.ic0_data_certificate_copy(6, 2, 4, &mut heap).unwrap();
    assert_eq!(heap, vec![1, 2, 3, 4, 5, 6, 3, 4, 5, 6]);
}

#[test]
fn canister_status() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();

    let api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &get_system_state_with_cycles(INITIAL_CYCLES),
        cycles_account_manager,
    );
    assert_eq!(api.ic0_canister_status(), Ok(1));

    let stopping_system_state = SystemState::new_stopping_for_testing(
        canister_test_id(42),
        user_test_id(24).get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );
    let api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &stopping_system_state,
        cycles_account_manager,
    );
    assert_eq!(api.ic0_canister_status(), Ok(2));

    let stopped_system_state = SystemState::new_stopped_for_testing(
        canister_test_id(42),
        user_test_id(24).get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    );
    let api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &stopped_system_state,
        cycles_account_manager,
    );
    assert_eq!(api.ic0_canister_status(), Ok(3));
}

/// msg_cycles_accept() can accept all cycles in call context
#[test]
fn msg_cycles_accept_all_cycles_in_call_context() {
    let amount = 50;
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let mut system_state = SystemStateBuilder::default().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5), NO_DEADLINE),
            Cycles::from(amount),
            Time::from_nanos_since_unix_epoch(0),
            RequestMetadata::new(0, UNIX_EPOCH),
        );
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        cycles_account_manager,
    );

    assert_eq!(api.ic0_msg_cycles_accept(amount), Ok(amount));
}

/// msg_cycles_accept() can accept all cycles in call context when more
/// asked for
#[test]
fn msg_cycles_accept_all_cycles_in_call_context_when_more_asked() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let mut system_state = SystemStateBuilder::default().build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5), NO_DEADLINE),
            Cycles::new(40),
            Time::from_nanos_since_unix_epoch(0),
            RequestMetadata::new(0, UNIX_EPOCH),
        );
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        cycles_account_manager,
    );

    assert_eq!(api.ic0_msg_cycles_accept(50), Ok(40));
}

/// If call call_perform() fails because canister does not have enough
/// cycles to send the message, then it does not trap, but returns
/// a transient error reject code.
#[test]
fn call_perform_not_enough_cycles_does_not_trap() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new()
        .with_subnet_type(SubnetType::Application)
        .build();
    // Set initial cycles small enough so that it does not have enough
    // cycles to send xnet messages.
    let initial_cycles = cycles_account_manager.xnet_call_performed_fee(SMALL_APP_SUBNET_MAX_SIZE)
        - Cycles::from(10u128);
    let mut system_state = SystemStateBuilder::new()
        .initial_cycles(initial_cycles)
        .build();
    system_state
        .call_context_manager_mut()
        .unwrap()
        .new_call_context(
            CallOrigin::CanisterUpdate(canister_test_id(33), CallbackId::from(5), NO_DEADLINE),
            Cycles::new(40),
            Time::from_nanos_since_unix_epoch(0),
            RequestMetadata::new(0, UNIX_EPOCH),
        );
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        cycles_account_manager,
    );
    api.ic0_call_new(0, 10, 0, 10, 0, 0, 0, 0, &[0; 1024])
        .unwrap();
    api.ic0_call_cycles_add128(Cycles::new(100)).unwrap();
    let res = api.ic0_call_perform();
    match res {
        Ok(code) => {
            assert_eq!(code, RejectCode::SysTransient as i32);
        }
        _ => panic!(
            "expected to get an InsufficientCyclesInMessageMemoryGrow error, got {:?}",
            res
        ),
    }
    let system_state_changes = api.into_system_state_changes();
    system_state_changes
        .apply_changes(
            UNIX_EPOCH,
            &mut system_state,
            &default_network_topology(),
            subnet_test_id(1),
            &no_op_logger(),
        )
        .unwrap();
    assert_eq!(system_state.balance(), initial_cycles);
    let call_context_manager = system_state.call_context_manager().unwrap();
    assert_eq!(call_context_manager.call_contexts().len(), 1);
    assert_eq!(call_context_manager.callbacks().len(), 0);
}

#[test]
fn growing_wasm_memory_updates_subnet_available_memory() {
    let wasm_page_size = 64 << 10;
    let subnet_available_memory_bytes = 2 * wasm_page_size;
    let subnet_available_memory = SubnetAvailableMemory::new(subnet_available_memory_bytes, 0, 0);
    let wasm_custom_sections_available_memory_before =
        subnet_available_memory.get_wasm_custom_sections_memory();
    let system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let api_type = ApiTypeBuilder::build_update_api();
    let execution_mode = api_type.execution_mode();
    let sandbox_safe_system_state = SandboxSafeSystemState::new(
        &system_state,
        cycles_account_manager,
        &NetworkTopology::default(),
        SchedulerConfig::application_subnet().dirty_page_overhead,
        execution_parameters(execution_mode.clone()).compute_allocation,
        RequestMetadata::new(0, UNIX_EPOCH),
        api_type.caller(),
        api_type.call_context_id(),
    );
    let mut api = SystemApiImpl::new(
        api_type,
        sandbox_safe_system_state,
        CANISTER_CURRENT_MEMORY_USAGE,
        CANISTER_CURRENT_MESSAGE_MEMORY_USAGE,
        execution_parameters(execution_mode),
        subnet_available_memory,
        EmbeddersConfig::default()
            .feature_flags
            .wasm_native_stable_memory,
        EmbeddersConfig::default().feature_flags.canister_backtrace,
        EmbeddersConfig::default().max_sum_exported_function_name_lengths,
        Memory::new_for_testing(),
        Memory::new_for_testing().size,
        Rc::new(DefaultOutOfInstructionsHandler::default()),
        no_op_logger(),
    );

    api.try_grow_wasm_memory(0, 1).unwrap();
    assert_eq!(api.get_allocated_bytes().get() as i64, wasm_page_size);
    assert_eq!(api.get_allocated_message_bytes().get() as i64, 0);
    assert_eq!(
        subnet_available_memory.get_wasm_custom_sections_memory(),
        wasm_custom_sections_available_memory_before
    );

    api.try_grow_wasm_memory(0, 10).unwrap_err();
    assert_eq!(api.get_allocated_bytes().get() as i64, wasm_page_size);
    assert_eq!(api.get_allocated_message_bytes().get() as i64, 0);
    assert_eq!(
        subnet_available_memory.get_wasm_custom_sections_memory(),
        wasm_custom_sections_available_memory_before
    );
}

const GIB: i64 = 1 << 30;

fn helper_test_on_low_wasm_memory(
    wasm_memory_threshold: NumBytes,
    wasm_memory_limit: Option<NumBytes>,
    memory_allocation: Option<NumBytes>,
    grow_memory_size: i64,
    grow_wasm_memory: bool,
    start_status: OnLowWasmMemoryHookStatus,
    expected_status: OnLowWasmMemoryHookStatus,
) {
    let wasm_page_size = 64 << 10;
    let subnet_available_memory_bytes = 20 * GIB;
    let subnet_available_memory = SubnetAvailableMemory::new(subnet_available_memory_bytes, 0, 0);

    let mut state_builder = SystemStateBuilder::default()
        .wasm_memory_threshold(wasm_memory_threshold)
        .wasm_memory_limit(wasm_memory_limit)
        .on_low_wasm_memory_hook_status(start_status.clone())
        .initial_cycles(Cycles::from(10_000_000_000_000_000u128));

    if let Some(memory_allocation) = memory_allocation {
        state_builder = state_builder.memory_allocation(memory_allocation);
    };

    let mut system_state = state_builder.build();

    let api_type = ApiTypeBuilder::build_update_api();
    let mut execution_parameters = execution_parameters(api_type.execution_mode());
    execution_parameters.memory_allocation = system_state.memory_allocation;
    execution_parameters.wasm_memory_limit = system_state.wasm_memory_limit;

    let sandbox_safe_system_state = SandboxSafeSystemState::new(
        &system_state,
        CyclesAccountManagerBuilder::new().build(),
        &NetworkTopology::default(),
        SchedulerConfig::application_subnet().dirty_page_overhead,
        execution_parameters.compute_allocation,
        RequestMetadata::new(0, UNIX_EPOCH),
        api_type.caller(),
        api_type.call_context_id(),
    );

    let mut api = SystemApiImpl::new(
        api_type,
        sandbox_safe_system_state,
        CANISTER_CURRENT_MEMORY_USAGE,
        CANISTER_CURRENT_MESSAGE_MEMORY_USAGE,
        execution_parameters,
        subnet_available_memory,
        EmbeddersConfig::default()
            .feature_flags
            .wasm_native_stable_memory,
        EmbeddersConfig::default().feature_flags.canister_backtrace,
        EmbeddersConfig::default().max_sum_exported_function_name_lengths,
        Memory::new_for_testing(),
        Memory::new_for_testing().size,
        Rc::new(DefaultOutOfInstructionsHandler::default()),
        no_op_logger(),
    );

    let additional_wasm_pages = (grow_memory_size as u64).div_ceil(wasm_page_size as u64);

    if grow_wasm_memory {
        api.try_grow_wasm_memory(0, additional_wasm_pages).unwrap();
    } else {
        api.try_grow_stable_memory(0, additional_wasm_pages, StableMemoryApi::Stable64)
            .unwrap();
    }

    let system_state_changes = api.into_system_state_changes();
    system_state_changes
        .apply_changes(
            UNIX_EPOCH,
            &mut system_state,
            &default_network_topology(),
            subnet_test_id(1),
            &no_op_logger(),
        )
        .unwrap();

    assert_eq!(
        *system_state.get_on_low_wasm_memory_hook_status(),
        expected_status
    );
}

#[test]
fn test_on_low_wasm_memory_grow_wasm_memory_all_status_changes() {
    let wasm_memory_threshold = NumBytes::new(GIB as u64);
    let wasm_memory_limit = Some(NumBytes::new(3 * GIB as u64));
    let memory_allocation = None;
    // `max_allowed_wasm_memory` = `wasm_memory_limit` - `wasm_memory_threshold`
    let max_allowed_wasm_memory = 2 * GIB;
    let grow_wasm_memory = true;

    // Hook condition is not satisfied.
    helper_test_on_low_wasm_memory(
        wasm_memory_threshold,
        wasm_memory_limit,
        memory_allocation,
        max_allowed_wasm_memory,
        grow_wasm_memory,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
    );

    // Hook condition is satisfied.
    helper_test_on_low_wasm_memory(
        wasm_memory_threshold,
        wasm_memory_limit,
        memory_allocation,
        max_allowed_wasm_memory + 1,
        grow_wasm_memory,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
        OnLowWasmMemoryHookStatus::Ready,
    );

    // Hook condition is not satisfied.
    helper_test_on_low_wasm_memory(
        wasm_memory_threshold,
        wasm_memory_limit,
        memory_allocation,
        max_allowed_wasm_memory,
        grow_wasm_memory,
        OnLowWasmMemoryHookStatus::Ready,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
    );

    // Hook condition is satisfied.
    helper_test_on_low_wasm_memory(
        wasm_memory_threshold,
        wasm_memory_limit,
        memory_allocation,
        max_allowed_wasm_memory + 1,
        grow_wasm_memory,
        OnLowWasmMemoryHookStatus::Ready,
        OnLowWasmMemoryHookStatus::Ready,
    );

    // Hook condition is not satisfied.
    helper_test_on_low_wasm_memory(
        wasm_memory_threshold,
        wasm_memory_limit,
        memory_allocation,
        max_allowed_wasm_memory,
        grow_wasm_memory,
        OnLowWasmMemoryHookStatus::Executed,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
    );

    // Hook condition is satisfied.
    helper_test_on_low_wasm_memory(
        wasm_memory_threshold,
        wasm_memory_limit,
        memory_allocation,
        max_allowed_wasm_memory + 1,
        grow_wasm_memory,
        OnLowWasmMemoryHookStatus::Executed,
        OnLowWasmMemoryHookStatus::Executed,
    );
}

#[test]
fn test_on_low_wasm_memory_grow_stable_memory() {
    // When memory_allocation is provided, hook condition can be triggered if:
    // memory_allocation - used_stable_memory - used_wasm_memory < wasm_memory_threshold
    // Hence growing stable memory can trigger hook condition.
    let wasm_memory_threshold = NumBytes::new(GIB as u64);
    let wasm_memory_limit = None;
    let memory_allocation = Some(NumBytes::new(3 * GIB as u64));
    let max_allowed_memory_size = 2 * GIB;
    let grow_wasm_memory = false;

    // Hook condition is not satisfied.
    helper_test_on_low_wasm_memory(
        wasm_memory_threshold,
        wasm_memory_limit,
        memory_allocation,
        max_allowed_memory_size,
        grow_wasm_memory,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
    );

    // Hook condition is satisfied.
    helper_test_on_low_wasm_memory(
        wasm_memory_threshold,
        wasm_memory_limit,
        memory_allocation,
        max_allowed_memory_size + 1,
        grow_wasm_memory,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
        OnLowWasmMemoryHookStatus::Ready,
    );

    // Without `memory_allocation`, hook condition is not satisfied.
    helper_test_on_low_wasm_memory(
        wasm_memory_threshold,
        wasm_memory_limit,
        None,
        max_allowed_memory_size + 1,
        grow_wasm_memory,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
    );
}

#[test]
fn test_on_low_wasm_memory_without_memory_limitn() {
    // When memory limit is not set, the default Wasm memory limit is 4 GIB.
    let wasm_memory_threshold = NumBytes::new(GIB as u64);
    // `max_allowed_wasm_memory` = `wasm_memory_limit` - `wasm_memory_threshold`
    let max_allowed_wasm_memory = 3 * GIB as i64;
    let wasm_memory_limit = None;
    let memory_allocation = None;
    let grow_wasm_memory = true;

    // Hook condition is not satisfied.
    helper_test_on_low_wasm_memory(
        wasm_memory_threshold,
        wasm_memory_limit,
        memory_allocation,
        max_allowed_wasm_memory,
        grow_wasm_memory,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
    );

    // Hook condition is satisfied.
    helper_test_on_low_wasm_memory(
        wasm_memory_threshold,
        wasm_memory_limit,
        memory_allocation,
        max_allowed_wasm_memory + 1,
        grow_wasm_memory,
        OnLowWasmMemoryHookStatus::ConditionNotSatisfied,
        OnLowWasmMemoryHookStatus::Ready,
    );
}

#[test]
fn push_output_request_respects_memory_limits() {
    let subnet_available_memory_bytes = 1 << 30;
    let subnet_available_message_memory_bytes = MAX_RESPONSE_COUNT_BYTES as i64 + 13;

    let subnet_available_memory = SubnetAvailableMemory::new(
        subnet_available_memory_bytes,
        subnet_available_message_memory_bytes,
        0,
    );
    let mut system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let api_type = ApiTypeBuilder::build_update_api();
    let execution_mode = api_type.execution_mode();
    let mut sandbox_safe_system_state = SandboxSafeSystemState::new(
        &system_state,
        cycles_account_manager,
        &NetworkTopology::default(),
        SchedulerConfig::application_subnet().dirty_page_overhead,
        execution_parameters(execution_mode.clone()).compute_allocation,
        RequestMetadata::new(0, UNIX_EPOCH),
        api_type.caller(),
        api_type.call_context_id(),
    );
    let own_canister_id = system_state.canister_id;
    let callback_id = sandbox_safe_system_state
        .register_callback(Callback::new(
            call_context_test_id(0),
            own_canister_id,
            canister_test_id(0),
            Cycles::zero(),
            Cycles::zero(),
            Cycles::zero(),
            WasmClosure::new(0, 0),
            WasmClosure::new(0, 0),
            None,
            NO_DEADLINE,
        ))
        .unwrap();
    let mut api = SystemApiImpl::new(
        api_type,
        sandbox_safe_system_state,
        CANISTER_CURRENT_MEMORY_USAGE,
        CANISTER_CURRENT_MESSAGE_MEMORY_USAGE,
        execution_parameters(execution_mode),
        subnet_available_memory,
        EmbeddersConfig::default()
            .feature_flags
            .wasm_native_stable_memory,
        EmbeddersConfig::default().feature_flags.canister_backtrace,
        EmbeddersConfig::default().max_sum_exported_function_name_lengths,
        Memory::new_for_testing(),
        Memory::new_for_testing().size,
        Rc::new(DefaultOutOfInstructionsHandler::default()),
        no_op_logger(),
    );

    let req = RequestBuilder::default()
        .sender(own_canister_id)
        .sender_reply_callback(callback_id)
        .build();

    // First push succeeds with or without message memory usage accounting, as the
    // initial subnet available memory is `MAX_RESPONSE_COUNT_BYTES + 13`.
    assert_eq!(
        0,
        api.push_output_request(req.clone(), Cycles::zero(), Cycles::zero())
            .unwrap()
    );

    // Nothing is consumed for execution memory.
    assert_eq!(api.get_allocated_bytes().get(), 0);
    // `MAX_RESPONSE_COUNT_BYTES` are consumed for message memory.
    assert_eq!(
        api.get_allocated_message_bytes().get(),
        MAX_RESPONSE_COUNT_BYTES as u64
    );
    assert_eq!(
        CANISTER_CURRENT_MEMORY_USAGE,
        api.get_current_memory_usage()
    );

    // And the second push fails.
    assert_eq!(
        RejectCode::SysTransient as i32,
        api.push_output_request(req, Cycles::zero(), Cycles::zero())
            .unwrap()
    );
    // Without altering memory usage.
    assert_eq!(api.get_allocated_bytes().get(), 0,);
    assert_eq!(
        api.get_allocated_message_bytes().get(),
        MAX_RESPONSE_COUNT_BYTES as u64
    );
    assert_eq!(
        CANISTER_CURRENT_MEMORY_USAGE,
        api.get_current_memory_usage()
    );

    // Ensure that exactly one output request was pushed.
    let system_state_changes = api.into_system_state_changes();
    system_state_changes
        .apply_changes(
            UNIX_EPOCH,
            &mut system_state,
            &default_network_topology(),
            subnet_test_id(1),
            &no_op_logger(),
        )
        .unwrap();
    assert_eq!(1, system_state.queues().output_queues_len());
}

#[test]
fn push_output_request_oversized_request_memory_limits() {
    let subnet_available_memory_bytes = 1 << 30;
    let subnet_available_message_memory_bytes = 3 * MAX_RESPONSE_COUNT_BYTES as i64;

    let subnet_available_memory = SubnetAvailableMemory::new(
        subnet_available_memory_bytes,
        subnet_available_message_memory_bytes,
        0,
    );
    let mut system_state = SystemStateBuilder::default().build();
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let api_type = ApiTypeBuilder::build_update_api();
    let execution_mode = api_type.execution_mode();
    let mut sandbox_safe_system_state = SandboxSafeSystemState::new(
        &system_state,
        cycles_account_manager,
        &NetworkTopology::default(),
        SchedulerConfig::application_subnet().dirty_page_overhead,
        execution_parameters(execution_mode.clone()).compute_allocation,
        RequestMetadata::new(0, UNIX_EPOCH),
        api_type.caller(),
        api_type.call_context_id(),
    );
    let own_canister_id = system_state.canister_id;
    let callback_id = sandbox_safe_system_state
        .register_callback(Callback::new(
            call_context_test_id(0),
            own_canister_id,
            canister_test_id(0),
            Cycles::zero(),
            Cycles::zero(),
            Cycles::zero(),
            WasmClosure::new(0, 0),
            WasmClosure::new(0, 0),
            None,
            NO_DEADLINE,
        ))
        .unwrap();
    let mut api = SystemApiImpl::new(
        api_type,
        sandbox_safe_system_state,
        CANISTER_CURRENT_MEMORY_USAGE,
        CANISTER_CURRENT_MESSAGE_MEMORY_USAGE,
        execution_parameters(execution_mode),
        subnet_available_memory,
        EmbeddersConfig::default()
            .feature_flags
            .wasm_native_stable_memory,
        EmbeddersConfig::default().feature_flags.canister_backtrace,
        EmbeddersConfig::default().max_sum_exported_function_name_lengths,
        Memory::new_for_testing(),
        Memory::new_for_testing().size,
        Rc::new(DefaultOutOfInstructionsHandler::default()),
        no_op_logger(),
    );

    // Oversized payload larger than available memory.
    let req = RequestBuilder::default()
        .sender(own_canister_id)
        .sender_reply_callback(callback_id)
        .method_payload(vec![13; 4 * MAX_RESPONSE_COUNT_BYTES])
        .build();

    // Not enough memory to push the request.
    assert_eq!(
        RejectCode::SysTransient as i32,
        api.push_output_request(req, Cycles::zero(), Cycles::zero())
            .unwrap()
    );

    // Memory usage unchanged.
    assert_eq!(0, api.get_allocated_bytes().get());
    assert_eq!(0, api.get_allocated_message_bytes().get());

    // Slightly smaller, still oversized request.
    let req = RequestBuilder::default()
        .sender(own_canister_id)
        .method_payload(vec![13; 2 * MAX_RESPONSE_COUNT_BYTES])
        .build();
    let req_size_bytes = req.count_bytes();
    assert!(req_size_bytes > MAX_RESPONSE_COUNT_BYTES);

    // Pushing succeeds.
    assert_eq!(
        0,
        api.push_output_request(req, Cycles::zero(), Cycles::zero())
            .unwrap()
    );

    // `req_size_bytes` are consumed.
    assert_eq!(0, api.get_allocated_bytes().get());
    assert_eq!(
        req_size_bytes as u64,
        api.get_allocated_message_bytes().get()
    );
    assert_eq!(
        CANISTER_CURRENT_MEMORY_USAGE,
        api.get_current_memory_usage()
    );

    // Ensure that exactly one output request was pushed.
    let system_state_changes = api.into_system_state_changes();
    system_state_changes
        .apply_changes(
            UNIX_EPOCH,
            &mut system_state,
            &default_network_topology(),
            subnet_test_id(1),
            &no_op_logger(),
        )
        .unwrap();
    assert_eq!(1, system_state.queues().output_queues_len());
}

#[test]
fn ic0_global_timer_set_is_propagated_from_sandbox() {
    let cycles_account_manager = CyclesAccountManagerBuilder::new().build();
    let mut system_state = SystemStateBuilder::default().build();
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        cycles_account_manager,
    );

    assert_eq!(
        api.ic0_global_timer_set(Time::from_nanos_since_unix_epoch(1))
            .unwrap(),
        time::UNIX_EPOCH
    );
    assert_eq!(
        api.ic0_global_timer_set(Time::from_nanos_since_unix_epoch(2))
            .unwrap(),
        Time::from_nanos_since_unix_epoch(1)
    );

    // Propagate system state changes
    assert_eq!(system_state.global_timer, CanisterTimer::Inactive);
    let system_state_changes = api.into_system_state_changes();
    system_state_changes
        .apply_changes(
            UNIX_EPOCH,
            &mut system_state,
            &default_network_topology(),
            subnet_test_id(1),
            &no_op_logger(),
        )
        .unwrap();
    assert_eq!(
        system_state.global_timer,
        CanisterTimer::Active(Time::from_nanos_since_unix_epoch(2))
    );
}

#[test]
fn ic0_is_controller_test() {
    let mut system_state = SystemStateBuilder::default().build();
    system_state.controllers = BTreeSet::from([user_test_id(1).get(), user_test_id(2).get()]);
    let api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        CyclesAccountManagerBuilder::new().build(),
    );
    // Users IDs 1 and 2 are controllers, hence ic0_is_controller should return 1,
    // otherwise, it should return 0.
    for i in 1..5 {
        let controller = user_test_id(i).get();
        assert_eq!(
            api.ic0_is_controller(0, controller.as_slice().len(), controller.as_slice())
                .unwrap(),
            (i <= 2) as u32
        );
    }
}

#[test]
fn ic0_is_controller_invalid_principal_id() {
    let api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &SystemStateBuilder::default().build(),
        CyclesAccountManagerBuilder::new().build(),
    );
    let controller = [0u8; 70];
    assert!(matches!(
        api.ic0_is_controller(0, controller.len(), &controller),
        Err(HypervisorError::InvalidPrincipalId(
            PrincipalIdBlobParseError(..)
        ))
    ));
}

#[test]
fn test_ic0_cycles_burn() {
    let initial_cycles = Cycles::new(5_000_000_000_000);
    let system_state = SystemStateBuilder::default()
        .initial_cycles(initial_cycles)
        .build();

    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &system_state,
        CyclesAccountManagerBuilder::new().build(),
    );

    let removed = Cycles::new(2_000_000_000_000);

    for _ in 0..2 {
        let mut heap = vec![0; 16];
        api.ic0_cycles_burn128(removed, 0, &mut heap).unwrap();
        assert_eq!(removed, Cycles::from(&heap));
    }

    let mut heap = vec![0; 16];
    api.ic0_cycles_burn128(removed, 0, &mut heap).unwrap();
    // The remaining balance is lower than the amount requested to be burned,
    // hence the system will remove as many cycles as it can.
    assert_eq!(Cycles::new(1_000_000_000_000), Cycles::from(&heap));

    let mut heap = vec![0; 16];
    api.ic0_cycles_burn128(removed, 0, &mut heap).unwrap();
    // There are no more cycles that can be burned.
    assert_eq!(Cycles::new(0), Cycles::from(&heap));
}

#[test]
fn test_save_log_message_adds_canister_log_records() {
    let messages: Vec<Vec<_>> = vec![
        b"message #1".to_vec(),
        b"message #2".to_vec(),
        b"message #3".to_vec(),
        vec![1, 2, 3],
        vec![],
    ];
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &SystemStateBuilder::default().build(),
        CyclesAccountManagerBuilder::new().build(),
    );
    let initial_records_number = api.canister_log().records().len();
    // Save several log messages.
    for message in &messages {
        api.save_log_message(0, message.len(), message);
    }
    let records = api.canister_log().records();
    // Expect increased number of log records and the content to match the messages.
    assert_eq!(records.len(), initial_records_number + messages.len());
    for (i, message) in messages.into_iter().enumerate() {
        let record = records[initial_records_number + i].clone();
        assert_eq!(record.content, message);
    }
}

#[test]
fn test_save_log_message_invalid_message_size() {
    let message = b"Hello, world!";
    let invalid_size = message.len() + 1;
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &SystemStateBuilder::default().build(),
        CyclesAccountManagerBuilder::new().build(),
    );
    let initial_records_number = api.canister_log().records().len();
    // Save a log message.
    api.save_log_message(0, invalid_size, message);
    // Expect added log record with an error message.
    let records = api.canister_log().records();
    assert_eq!(records.len(), initial_records_number + 1);
    assert_eq!(
        String::from_utf8(records.back().unwrap().content.clone()).unwrap(),
        "(debug_print message out of memory bounds)"
    );
}

#[test]
fn test_save_log_message_invalid_message_offset() {
    let message = b"Hello, world!";
    let invalid_src = 1;
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &SystemStateBuilder::default().build(),
        CyclesAccountManagerBuilder::new().build(),
    );
    let initial_records_number = api.canister_log().records().len();
    // Save a log message.
    api.save_log_message(invalid_src, message.len(), message);
    // Expect added log record with an error message.
    let records = api.canister_log().records();
    assert_eq!(records.len(), initial_records_number + 1);
    assert_eq!(
        String::from_utf8(records.back().unwrap().content.clone()).unwrap(),
        "(debug_print message out of memory bounds)"
    );
}

#[test]
fn test_save_log_message_trims_long_message() {
    let long_message_size = 2 * MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE;
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &SystemStateBuilder::default().build(),
        CyclesAccountManagerBuilder::new().build(),
    );
    let initial_records_number = api.canister_log().records().len();
    // Save a long log message.
    let bytes = vec![b'x'; long_message_size];
    api.save_log_message(0, bytes.len(), &bytes);
    // Expect added log record with the content trimmed to the allowed size.
    let records = api.canister_log().records();
    assert_eq!(records.len(), initial_records_number + 1);
    assert!(records.back().unwrap().content.len() <= MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE);
}

#[test]
fn test_save_log_message_keeps_total_log_size_limited() {
    let messages_number = 10;
    let long_message_size = 2 * MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE;
    let mut api = get_system_api(
        ApiTypeBuilder::build_update_api(),
        &SystemStateBuilder::default().build(),
        CyclesAccountManagerBuilder::new().build(),
    );
    let initial_records_number = api.canister_log().records().len();
    // Save several long messages.
    for _ in 0..messages_number {
        let bytes = vec![b'x'; long_message_size];
        api.save_log_message(0, bytes.len(), &bytes);
    }
    // Expect only one log record to be kept, staying within the size limit.
    let log = api.canister_log();
    assert_eq!(log.records().len(), initial_records_number + 1);
    assert_le!(log.used_space(), MAX_ALLOWED_CANISTER_LOG_BUFFER_SIZE);
}
