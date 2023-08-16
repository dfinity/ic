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

    pub mod old {
        use ic_types::NumInstructions;
        pub const ACCEPT_MESSAGE: NumInstructions = NumInstructions::new(0);
        pub const CALL_CYCLES_ADD: NumInstructions = NumInstructions::new(0);
        pub const CALL_CYCLES_ADD128: NumInstructions = NumInstructions::new(0);
        pub const CALL_DATA_APPEND: NumInstructions = NumInstructions::new(20);
        pub const CALL_NEW: NumInstructions = NumInstructions::new(0);
        pub const CALL_ON_CLEANUP: NumInstructions = NumInstructions::new(0);
        pub const CALL_PERFORM: NumInstructions = NumInstructions::new(0);
        pub const CANISTER_CYCLE_BALANCE: NumInstructions = NumInstructions::new(0);
        pub const CANISTER_CYCLE_BALANCE128: NumInstructions = NumInstructions::new(0);
        pub const CANISTER_SELF_COPY: NumInstructions = NumInstructions::new(0);
        pub const CANISTER_SELF_SIZE: NumInstructions = NumInstructions::new(0);
        pub const CANISTER_STATUS: NumInstructions = NumInstructions::new(0);
        pub const CANISTER_VERSION: NumInstructions = NumInstructions::new(0);
        pub const CERTIFIED_DATA_SET: NumInstructions = NumInstructions::new(0);
        pub const DATA_CERTIFICATE_COPY: NumInstructions = NumInstructions::new(0);
        pub const DATA_CERTIFICATE_PRESENT: NumInstructions = NumInstructions::new(0);
        pub const DATA_CERTIFICATE_SIZE: NumInstructions = NumInstructions::new(0);
        pub const DEBUG_PRINT: NumInstructions = NumInstructions::new(100);
        pub const GLOBAL_TIMER_SET: NumInstructions = NumInstructions::new(0);
        pub const IS_CONTROLLER: NumInstructions = NumInstructions::new(1_000);
        pub const MSG_ARG_DATA_COPY: NumInstructions = NumInstructions::new(20);
        pub const MSG_ARG_DATA_SIZE: NumInstructions = NumInstructions::new(0);
        pub const MSG_CALLER_COPY: NumInstructions = NumInstructions::new(0);
        pub const MSG_CALLER_SIZE: NumInstructions = NumInstructions::new(0);
        pub const MSG_CYCLES_ACCEPT: NumInstructions = NumInstructions::new(0);
        pub const MSG_CYCLES_ACCEPT128: NumInstructions = NumInstructions::new(0);
        pub const MSG_CYCLES_AVAILABLE: NumInstructions = NumInstructions::new(0);
        pub const MSG_CYCLES_AVAILABLE128: NumInstructions = NumInstructions::new(0);
        pub const MSG_CYCLES_REFUNDED: NumInstructions = NumInstructions::new(0);
        pub const MSG_CYCLES_REFUNDED128: NumInstructions = NumInstructions::new(0);
        pub const MSG_METHOD_NAME_COPY: NumInstructions = NumInstructions::new(20);
        pub const MSG_METHOD_NAME_SIZE: NumInstructions = NumInstructions::new(0);
        pub const MSG_REJECT_CODE: NumInstructions = NumInstructions::new(0);
        pub const MSG_REJECT_MSG_COPY: NumInstructions = NumInstructions::new(20);
        pub const MSG_REJECT_MSG_SIZE: NumInstructions = NumInstructions::new(0);
        pub const MSG_REJECT: NumInstructions = NumInstructions::new(20);
        pub const MSG_REPLY_DATA_APPEND: NumInstructions = NumInstructions::new(20);
        pub const MSG_REPLY: NumInstructions = NumInstructions::new(0);
        pub const PERFORMANCE_COUNTER: NumInstructions = NumInstructions::new(200);
        pub const STABLE_GROW: NumInstructions = NumInstructions::new(0);
        pub const STABLE_READ: NumInstructions = NumInstructions::new(20);
        pub const STABLE_SIZE: NumInstructions = NumInstructions::new(0);
        pub const STABLE_WRITE: NumInstructions = NumInstructions::new(20);
        pub const STABLE64_GROW: NumInstructions = NumInstructions::new(0);
        pub const STABLE64_READ: NumInstructions = NumInstructions::new(20);
        pub const STABLE64_SIZE: NumInstructions = NumInstructions::new(0);
        pub const STABLE64_WRITE: NumInstructions = NumInstructions::new(20);
        pub const TIME: NumInstructions = NumInstructions::new(0);
        pub const TRAP: NumInstructions = NumInstructions::new(20);
    }

    pub mod new {
        use ic_types::NumInstructions;
        pub const ACCEPT_MESSAGE: NumInstructions = NumInstructions::new(500);
        pub const CALL_CYCLES_ADD: NumInstructions = NumInstructions::new(500);
        pub const CALL_CYCLES_ADD128: NumInstructions = NumInstructions::new(500);
        pub const CALL_DATA_APPEND: NumInstructions = NumInstructions::new(500);
        pub const CALL_NEW: NumInstructions = NumInstructions::new(1_500);
        pub const CALL_ON_CLEANUP: NumInstructions = NumInstructions::new(500);
        pub const CALL_PERFORM: NumInstructions = NumInstructions::new(5_000);
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
}

pub mod overhead_native {
    pub mod old {
        use ic_types::NumInstructions;
        // Both for `stable_grow` and `stable64_grow`.
        pub const STABLE_GROW: NumInstructions = NumInstructions::new(0);
        pub const STABLE_READ: NumInstructions = NumInstructions::new(20);
        pub const STABLE_WRITE: NumInstructions = NumInstructions::new(20);
        pub const STABLE64_READ: NumInstructions = NumInstructions::new(20);
        pub const STABLE64_WRITE: NumInstructions = NumInstructions::new(20);
    }
    pub mod new {
        use ic_types::NumInstructions;
        // Both for `stable_grow` and `stable64_grow`.
        pub const STABLE_GROW: NumInstructions = NumInstructions::new(100);
        pub const STABLE_READ: NumInstructions = NumInstructions::new(20);
        pub const STABLE_WRITE: NumInstructions = NumInstructions::new(20);
        pub const STABLE64_READ: NumInstructions = NumInstructions::new(20);
        pub const STABLE64_WRITE: NumInstructions = NumInstructions::new(20);
    }
}

///
/// System API Calls CPU Complexity (in Instructions).
///
/// The complexity is taken into account to fail the message execution or to stop
/// the round. Unlike the System API overhead, for now the complexity is not proxied
/// into Cycles.
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
    use ic_types::CpuComplexity;

    const fn from_nanos(nanos: i64) -> CpuComplexity {
        // At the moment, the instructions per message limit is 5B.
        // The goal is to have round time to be <= 1s.
        // For this to happen, count how much each system API call should cost (in Instructions)
        // based on the time they de-facto execute (in ns):
        //
        // CPU complexity in Instructions = 5B instructions per message / 1B nanos in second * nanos
        const B: i64 = 1_000_000_000;
        const MAX_INSTRUCTIONS_PER_MESSAGE: i64 = 5 * B;
        const NANOS_IN_SEC: i64 = B;

        CpuComplexity::new(MAX_INSTRUCTIONS_PER_MESSAGE * nanos / NANOS_IN_SEC)
    }

    // Note: the complexity should be in general between 30ns and 1_000ns, as lower
    // number no need to be counted, and higher numbers won't allow 1M calls to happen.
    // All the values are conservatively rounded up to take into account the locality
    // of the benchmarks and to tolerate future small fluctuations of the results.
    pub const ACCEPT_MESSAGE: CpuComplexity = from_nanos(20);
    pub const CALL_CYCLES_ADD: CpuComplexity = from_nanos(20);
    pub const CALL_CYCLES_ADD128: CpuComplexity = from_nanos(20);
    // The `SYSTEM_API.md` captures `call_new+ic0_call_data_append()`
    pub const CALL_DATA_APPEND: CpuComplexity = from_nanos(360 - 260);
    pub const CALL_NEW: CpuComplexity = from_nanos(260);
    pub const CALL_ON_CLEANUP: CpuComplexity = from_nanos(20);
    pub const CALL_PERFORM: CpuComplexity = from_nanos(1_000);
    pub const CANISTER_CYCLE_BALANCE: CpuComplexity = from_nanos(50);
    pub const CANISTER_CYCLE_BALANCE128: CpuComplexity = from_nanos(50);
    pub const CANISTER_SELF_COPY: CpuComplexity = from_nanos(60);
    pub const CANISTER_SELF_SIZE: CpuComplexity = from_nanos(20);
    pub const CANISTER_STATUS: CpuComplexity = from_nanos(20);
    pub const CANISTER_VERSION: CpuComplexity = from_nanos(20);
    pub const CERTIFIED_DATA_SET: CpuComplexity = from_nanos(70);
    pub const CONTROLLER_COPY: CpuComplexity = from_nanos(60);
    pub const CONTROLLER_SIZE: CpuComplexity = from_nanos(20);
    pub const DATA_CERTIFICATE_COPY: CpuComplexity = from_nanos(60);
    pub const DATA_CERTIFICATE_PRESENT: CpuComplexity = from_nanos(20);
    pub const DATA_CERTIFICATE_SIZE: CpuComplexity = from_nanos(20);
    pub const DEBUG_PRINT: CpuComplexity = from_nanos(30);
    pub const GLOBAL_TIMER_SET: CpuComplexity = from_nanos(20);
    pub const IS_CONTROLLER: CpuComplexity = from_nanos(200);
    pub const MSG_ARG_DATA_COPY: CpuComplexity = from_nanos(80);
    pub const MSG_ARG_DATA_SIZE: CpuComplexity = from_nanos(20);
    pub const MSG_CALLER_COPY: CpuComplexity = from_nanos(60);
    pub const MSG_CALLER_SIZE: CpuComplexity = from_nanos(20);
    pub const MSG_CYCLES_ACCEPT: CpuComplexity = from_nanos(80);
    pub const MSG_CYCLES_ACCEPT128: CpuComplexity = from_nanos(80);
    pub const MSG_CYCLES_AVAILABLE: CpuComplexity = from_nanos(60);
    pub const MSG_CYCLES_AVAILABLE128: CpuComplexity = from_nanos(60);
    pub const MSG_CYCLES_REFUNDED: CpuComplexity = from_nanos(50);
    pub const MSG_CYCLES_REFUNDED128: CpuComplexity = from_nanos(50);
    pub const MSG_METHOD_NAME_COPY: CpuComplexity = from_nanos(80);
    pub const MSG_METHOD_NAME_SIZE: CpuComplexity = from_nanos(20);
    pub const MSG_REJECT_CODE: CpuComplexity = from_nanos(20);
    pub const MSG_REJECT_MSG_COPY: CpuComplexity = from_nanos(90);
    pub const MSG_REJECT_MSG_SIZE: CpuComplexity = from_nanos(20);
    pub const MSG_REJECT: CpuComplexity = from_nanos(20);
    pub const MSG_REPLY_DATA_APPEND: CpuComplexity = from_nanos(70);
    pub const MSG_REPLY: CpuComplexity = from_nanos(20);
    pub const PERFORMANCE_COUNTER: CpuComplexity = from_nanos(50);
    // For the `stable_*` calls we need to make sure we can do at least 50M calls
    // (i.e. inefficient 1-byte reads), so the complexity should not exceed 1_000 / 50 = 20ns
    pub const STABLE_GROW: CpuComplexity = from_nanos(20); // should be 60
    pub const STABLE_READ: CpuComplexity = from_nanos(20); // should be 90
    pub const STABLE_SIZE: CpuComplexity = from_nanos(20);
    pub const STABLE_WRITE: CpuComplexity = from_nanos(20); // should be 100
    pub const STABLE64_GROW: CpuComplexity = from_nanos(20); // should be 60
    pub const STABLE64_READ: CpuComplexity = from_nanos(20); // should be 100
    pub const STABLE64_SIZE: CpuComplexity = from_nanos(20);
    pub const STABLE64_WRITE: CpuComplexity = from_nanos(20); // should be 110
    pub const TIME: CpuComplexity = from_nanos(20);
    pub const TRAP: CpuComplexity = from_nanos(1_000);
}

pub mod system_api {
    // Select between the system api complexity overhead constants based on the metering type.
    // Takes as parameter a constant name and the metering type.
    macro_rules! complexity_overhead {
        ($name:ident, $metering_type:expr) => {
            match $metering_type {
                MeteringType::Old => system_api_complexity::overhead::old::$name,
                MeteringType::New => system_api_complexity::overhead::new::$name,
                MeteringType::None => system_api_complexity::overhead::old::$name,
            }
        };
    }

    // Select between the system api complexity for native stable memory constants based on the metering type.
    // Takes as parameter a constant name and the metering type.
    macro_rules! complexity_overhead_native {
        ($name:ident, $metering_type:expr) => {
            match $metering_type {
                MeteringType::Old => system_api_complexity::overhead_native::old::$name,
                MeteringType::New => system_api_complexity::overhead_native::new::$name,
                MeteringType::None => system_api_complexity::overhead_native::old::$name,
            }
        };
    }

    pub(crate) use complexity_overhead;
    pub(crate) use complexity_overhead_native;
}
