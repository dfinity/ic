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

    pub const MSG_ARG_DATA_COPY: NumInstructions = NumInstructions::new(20);
    pub const MSG_METHOD_NAME_COPY: NumInstructions = NumInstructions::new(20);
    pub const MSG_REPLY_DATA_APPEND: NumInstructions = NumInstructions::new(20);
    pub const MSG_REJECT: NumInstructions = NumInstructions::new(20);
    pub const MSG_REJECT_MSG_COPY: NumInstructions = NumInstructions::new(20);
    pub const DEBUG_PRINT: NumInstructions = NumInstructions::new(100);
    pub const TRAP: NumInstructions = NumInstructions::new(20);
    pub const CALL_SIMPLE: NumInstructions = NumInstructions::new(20);
    pub const CALL_NEW: NumInstructions = NumInstructions::new(0);
    pub const CALL_DATA_APPEND: NumInstructions = NumInstructions::new(20);
    pub const CALL_PERFORM: NumInstructions = NumInstructions::new(0);
    pub const STABLE_READ: NumInstructions = NumInstructions::new(20);
    pub const STABLE_WRITE: NumInstructions = NumInstructions::new(20);
    pub const STABLE64_READ: NumInstructions = NumInstructions::new(20);
    pub const STABLE64_WRITE: NumInstructions = NumInstructions::new(20);
    pub const PERFORMANCE_COUNTER: NumInstructions = NumInstructions::new(200);
}

///
/// System API Calls CPU Complexity (in Instructions).
///
/// The complexity is taken into account to fail the message execution or to stop
/// the round. Unlike the System API overhead, for now the complexity is not proxied
/// into Cycles (TODO: EXC-1029: Computation Cost).
///
/// The most complex System API call takes ~1s per 1M calls, so having the 1s target
/// Round Time, the message will fail after 1M the most complex System API calls.
///
/// The CPU complexity is based on the benchmark results (see `SYSTEM_API.md`).
/// For example, in the `SYSTEM_API.md` 1M of `ic0_call_new()` calls in a tight loop
/// execute for 251ms. So a single system call roughly takes `251ms/1M = 251ns`
/// Basically, the number from the table in milliseconds per 1M calls roughly equals
/// nanoseconds per single call listed below.
///
pub mod cpu {
    use ic_types::NumInstructions;

    const fn from_nanos(nanos: u64) -> NumInstructions {
        // At the moment, the instructions per message limit is 5B.
        // The goal is to have round time to be <= 1s.
        // For this to happen, count how much each system API call should cost (in Instructions)
        // based on the time they de-facto execute (in ns):
        //
        // CPU complexity in Instructions = 5B instructions per message / 1B nanos in second * nanos
        const B: u64 = 1_000_000_000;
        const MAX_INSTRUCTIONS_PER_MESSAGE: u64 = 5 * B;
        const NANOS_IN_SEC: u64 = B;

        NumInstructions::new(MAX_INSTRUCTIONS_PER_MESSAGE * nanos / NANOS_IN_SEC)
    }

    // Note: the complexity should be in general between 30ns and 1_000ns, as lower
    // number no need to be counted, and higher numbers won't allow 1M calls to happen.
    // All the values are conservatively rounded up to take into account the locality
    // of the benchmarks and to tolerate future small fluctuations of the results.
    pub const MSG_REJECT_MSG_COPY: NumInstructions = from_nanos(90);
    pub const MSG_CYCLES_REFUNDED128: NumInstructions = from_nanos(50);
    pub const MSG_METHOD_NAME_COPY: NumInstructions = from_nanos(80);
    pub const DATA_CERTIFICATE_COPY: NumInstructions = from_nanos(60);
    pub const MSG_CALLER_COPY: NumInstructions = from_nanos(60);
    pub const MSG_ARG_DATA_COPY: NumInstructions = from_nanos(80);
    pub const MSG_REPLY_DATA_APPEND: NumInstructions = from_nanos(70);
    pub const MSG_REJECT: NumInstructions = from_nanos(20);
    pub const CANISTER_SELF_COPY: NumInstructions = from_nanos(60);
    pub const CONTROLLER_COPY: NumInstructions = from_nanos(60);
    pub const DEBUG_PRINT: NumInstructions = from_nanos(30);
    pub const TRAP: NumInstructions = from_nanos(1_000);
    pub const CALL_SIMPLE: NumInstructions = from_nanos(1_000);
    pub const CALL_NEW: NumInstructions = from_nanos(260);
    // The `SYSTEM_API.md` captures `call_new+ic0_call_data_append()`
    pub const CALL_DATA_APPEND: NumInstructions = from_nanos(360 - 260);
    pub const CALL_PERFORM: NumInstructions = from_nanos(1_000);
    // For the `stable_*` calls we need to make sure we can do at least 50M calls
    // (i.e. inefficient 1-byte reads), so the complexity should not exceed 1_000 / 50 = 20ns
    pub const STABLE_GROW: NumInstructions = from_nanos(20); // should be 60
    pub const STABLE_READ: NumInstructions = from_nanos(20); // should be 90
    pub const STABLE_WRITE: NumInstructions = from_nanos(20); // should be 100
    pub const STABLE64_GROW: NumInstructions = from_nanos(20); // should be 60
    pub const STABLE64_READ: NumInstructions = from_nanos(20); // should be 100
    pub const STABLE64_WRITE: NumInstructions = from_nanos(20); // should be 110
    pub const CANISTER_CYCLES_BALANCE128: NumInstructions = from_nanos(50);
    pub const MSG_CYCLES_AVAILABLE128: NumInstructions = from_nanos(60);
    pub const MSG_CYCLES_ACCEPT128: NumInstructions = from_nanos(80);
    pub const CERTIFIED_DATA_SET: NumInstructions = from_nanos(70);
    pub const PERFORMANCE_COUNTER: NumInstructions = from_nanos(50);
}
