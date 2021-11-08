use ic_types::NumInstructions;

/// Fixed charge for System AIP calls overhead (in Instructions).
/// See `EXECUTE_UPDATE.md` for more details.

// Benchmark results: +386 for 1B, -7K for 8KiB
pub const MSG_ARG_DATA_COPY: NumInstructions = NumInstructions::new(20);
// Not part of the update API
pub const MSG_METHOD_NAME_COPY: NumInstructions = NumInstructions::new(20);
// Benchmark results: +394 for 1B
pub const MSG_REPLY_DATA_APPEND: NumInstructions = NumInstructions::new(20);
// Benchmark results: OK
pub const MSG_REJECT: NumInstructions = NumInstructions::new(0);
// Not part of the update API
pub const MSG_REJECT_MSG_COPY: NumInstructions = NumInstructions::new(0);
// Not tested
pub const DEBUG_PRINT: NumInstructions = NumInstructions::new(0);
// Not tested
pub const TRAP: NumInstructions = NumInstructions::new(0);
// call_* API was not tested
pub const CALL_SIMPLE: NumInstructions = NumInstructions::new(0);
// call_* API was not tested
pub const CALL_DATA_APPEND: NumInstructions = NumInstructions::new(0);
// Benchmark results: +442 for 1B, -7K for 8KiB
pub const STABLE_READ: NumInstructions = NumInstructions::new(20);
// Benchmark results: +477 for 1B, -7K for 8KiB
pub const STABLE_WRITE: NumInstructions = NumInstructions::new(20);
// Benchmark results: +460 for 1B, -7K for 8KiB
pub const STABLE64_READ: NumInstructions = NumInstructions::new(20);
// Benchmark results: +463 for 1B, -7K for 8KiB
pub const STABLE64_WRITE: NumInstructions = NumInstructions::new(20);
