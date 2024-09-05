///
/// System API Calls Complexity Module
///

/// The Fixed System API Overhead (in Instructions)
///
/// The cost of the System API calls is proportional to the work the call performs.
/// The cost consists of two parts: fixed and variable. The fixed part accounts for
/// the overhead of performing the call in WebAssembly. The variable part depends
/// on the parameters of the call (i.e. number of bytes).
///
/// The fixed System API overhead represented in WebAssembly Instructions. This
/// overhead will be added to the total Instructions executed by Canisters, and
/// hence will be later proxied to the computation costs in Cycles as the normal
/// WebAssembly instructions.
///
/// See `EXECUTE_UPDATE.md` for more details.
///
pub mod overhead {
    use ic_types::NumInstructions;
    pub const ACCEPT_MESSAGE: NumInstructions = NumInstructions::new(500);
    pub const CALL_CYCLES_ADD: NumInstructions = NumInstructions::new(500);
    pub const CALL_CYCLES_ADD128: NumInstructions = NumInstructions::new(500);
    pub const CALL_DATA_APPEND: NumInstructions = NumInstructions::new(500);
    pub const CALL_NEW: NumInstructions = NumInstructions::new(1_500);
    pub const CALL_ON_CLEANUP: NumInstructions = NumInstructions::new(500);
    pub const CALL_PERFORM: NumInstructions = NumInstructions::new(5_000);
    pub const CALL_WITH_BEST_EFFORT_RESPONSE: NumInstructions = NumInstructions::new(500);
    pub const CANISTER_CYCLE_BALANCE: NumInstructions = NumInstructions::new(500);
    pub const CANISTER_CYCLE_BALANCE128: NumInstructions = NumInstructions::new(500);
    pub const CANISTER_SELF_COPY: NumInstructions = NumInstructions::new(500);
    pub const CANISTER_SELF_SIZE: NumInstructions = NumInstructions::new(500);
    pub const CANISTER_STATUS: NumInstructions = NumInstructions::new(500);
    pub const CANISTER_VERSION: NumInstructions = NumInstructions::new(500);
    pub const CERTIFIED_DATA_SET: NumInstructions = NumInstructions::new(500);
    pub const CONTROLLER_COPY: NumInstructions = NumInstructions::new(500);
    pub const CONTROLLER_SIZE: NumInstructions = NumInstructions::new(500);
    pub const DATA_CERTIFICATE_COPY: NumInstructions = NumInstructions::new(500);
    pub const DATA_CERTIFICATE_PRESENT: NumInstructions = NumInstructions::new(500);
    pub const DATA_CERTIFICATE_SIZE: NumInstructions = NumInstructions::new(500);
    pub const DEBUG_PRINT: NumInstructions = NumInstructions::new(100);
    pub const GLOBAL_TIMER_SET: NumInstructions = NumInstructions::new(500);
    pub const IS_CONTROLLER: NumInstructions = NumInstructions::new(1_000);
    pub const IN_REPLICATED_EXECUTION: NumInstructions = NumInstructions::new(500);
    pub const MSG_ARG_DATA_COPY: NumInstructions = NumInstructions::new(500);
    pub const MSG_ARG_DATA_SIZE: NumInstructions = NumInstructions::new(500);
    pub const MSG_CALLER_COPY: NumInstructions = NumInstructions::new(500);
    pub const MSG_CALLER_SIZE: NumInstructions = NumInstructions::new(500);
    pub const MSG_CYCLES_ACCEPT: NumInstructions = NumInstructions::new(500);
    pub const MSG_CYCLES_ACCEPT128: NumInstructions = NumInstructions::new(500);
    pub const MSG_CYCLES_AVAILABLE: NumInstructions = NumInstructions::new(500);
    pub const MSG_CYCLES_AVAILABLE128: NumInstructions = NumInstructions::new(500);
    pub const MSG_CYCLES_REFUNDED: NumInstructions = NumInstructions::new(500);
    pub const MSG_CYCLES_REFUNDED128: NumInstructions = NumInstructions::new(500);
    pub const MSG_DEADLINE: NumInstructions = NumInstructions::new(500);
    pub const MSG_METHOD_NAME_COPY: NumInstructions = NumInstructions::new(500);
    pub const MSG_METHOD_NAME_SIZE: NumInstructions = NumInstructions::new(500);
    pub const MSG_REJECT_CODE: NumInstructions = NumInstructions::new(500);
    pub const MSG_REJECT_MSG_COPY: NumInstructions = NumInstructions::new(500);
    pub const MSG_REJECT_MSG_SIZE: NumInstructions = NumInstructions::new(500);
    pub const MSG_REJECT: NumInstructions = NumInstructions::new(500);
    pub const MSG_REPLY_DATA_APPEND: NumInstructions = NumInstructions::new(500);
    pub const MSG_REPLY: NumInstructions = NumInstructions::new(500);
    pub const PERFORMANCE_COUNTER: NumInstructions = NumInstructions::new(200);
    pub const STABLE_GROW: NumInstructions = NumInstructions::new(500);
    pub const STABLE_READ: NumInstructions = NumInstructions::new(20);
    pub const STABLE_SIZE: NumInstructions = NumInstructions::new(20);
    pub const STABLE_WRITE: NumInstructions = NumInstructions::new(20);
    pub const STABLE64_GROW: NumInstructions = NumInstructions::new(500);
    pub const STABLE64_READ: NumInstructions = NumInstructions::new(20);
    pub const STABLE64_SIZE: NumInstructions = NumInstructions::new(20);
    pub const STABLE64_WRITE: NumInstructions = NumInstructions::new(20);
    pub const TIME: NumInstructions = NumInstructions::new(500);
    pub const TRAP: NumInstructions = NumInstructions::new(500);
}

pub mod overhead_native {
    use ic_types::NumInstructions;
    // Both for `stable_grow` and `stable64_grow`.
    pub const STABLE_GROW: NumInstructions = NumInstructions::new(100);
    pub const STABLE_READ: NumInstructions = NumInstructions::new(20);
    pub const STABLE_WRITE: NumInstructions = NumInstructions::new(20);
    pub const STABLE64_READ: NumInstructions = NumInstructions::new(20);
    pub const STABLE64_WRITE: NumInstructions = NumInstructions::new(20);
}
