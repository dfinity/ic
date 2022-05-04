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
}
