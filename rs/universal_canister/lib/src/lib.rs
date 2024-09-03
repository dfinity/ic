//! The Universal Canister (UC) is a canister built in Rust, compiled to Wasm,
//! and serves as a canister that can be used for a multitude of tests.
//!
//! Payloads to UC can execute any arbitrary sequence of system methods, making
//! it possible to test different canister behaviors without having to write up
//! custom Wat files.

pub mod management;

use hex_literal::hex;
use ic_types::Cycles;
use universal_canister::Ops;
/// The binary of the universal canister as compiled from
/// `rs/universal_canister/impl`.
///
/// For steps on how to produce it, please see the README in
/// `rs/universal_canister`.
pub const UNIVERSAL_CANISTER_WASM: &[u8] = include_bytes!("universal-canister.wasm.gz");
pub const UNIVERSAL_CANISTER_WASM_SHA256: [u8; 32] =
    hex!("65b035adf05770b69d68be0a5bec39df4d2ac5fc1dccb8397766120270159e6b");

/// A succinct shortcut for creating a `PayloadBuilder`, which is used to encode
/// instructions to be executed by the UC.
///
/// Note that a `PayloadBuilder` isn't really building Wasm as the name
/// of the shortcut here suggests, but we call it `wasm()` since it gives
/// a close enough indicator of what `PayloadBuilder` accomplishes without
/// getting into the details of how it accomplishes it.
///
/// Example usage:
/// ```no_run
/// # use ic_universal_canister::wasm;
/// // Instruct the UC to reply with the bytes encoding "Hello"
/// let bytes = wasm().reply_data(b"Hello").build();
/// ```
pub fn wasm() -> PayloadBuilder {
    PayloadBuilder::default()
}

/// A shortcut for a `CallArgs::default()`
pub fn call_args() -> CallArgs {
    CallArgs::default()
}

/// A builder class for building payloads for the universal canister.
///
/// Payloads for the UC encode `Ops` representing what instructions to
/// execute.
#[derive(Default)]
pub struct PayloadBuilder(Vec<u8>);

impl PayloadBuilder {
    pub fn push_int(mut self, int: u32) -> Self {
        self.0.push(Ops::PushInt as u8);
        self.0.extend_from_slice(&int.to_le_bytes());
        self
    }

    pub fn push_int64(mut self, int: u64) -> Self {
        self.0.push(Ops::PushInt64 as u8);
        self.0.extend_from_slice(&int.to_le_bytes());
        self
    }

    pub fn reply_data(mut self, data: &[u8]) -> Self {
        self = self.push_bytes(data);
        self = self.reply_data_append();
        self.reply()
    }

    pub fn reply_int(mut self) -> Self {
        self = self.int_to_blob();
        self = self.reply_data_append();
        self.reply()
    }

    pub fn reply_int64(mut self) -> Self {
        self = self.int64_to_blob();
        self = self.reply_data_append();
        self.reply()
    }

    pub fn reply_data_append(mut self) -> Self {
        self.0.push(Ops::ReplyDataAppend as u8);
        self
    }

    /// Pop a blob from the stack and append it to the global data on the heap.
    /// NOTE: This does _not_ correspond to a Wasm global.
    pub fn append_to_global_data(mut self) -> Self {
        self.0.push(Ops::AppendGlobal as u8);
        self
    }

    pub fn append_and_reply(mut self) -> Self {
        self = self.reply_data_append();
        self.reply()
    }

    pub fn int_to_blob(mut self) -> Self {
        self.0.push(Ops::IntToBlob as u8);
        self
    }

    pub fn int64_to_blob(mut self) -> Self {
        self.0.push(Ops::Int64ToBlob as u8);
        self
    }

    pub fn blob_length(mut self) -> Self {
        self.0.push(Ops::BlobLength as u8);
        self
    }

    pub fn reply(mut self) -> Self {
        self.0.push(Ops::Reply as u8);
        self
    }

    pub fn stable_size(mut self) -> Self {
        self.0.push(Ops::StableSize as u8);
        self
    }

    pub fn stable64_size(mut self) -> Self {
        self.0.push(Ops::StableSize64 as u8);
        self
    }

    pub fn push_bytes(mut self, data: &[u8]) -> Self {
        self.0.push(Ops::PushBytes as u8);
        self.0.extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.0.extend_from_slice(data);
        self
    }

    pub fn push_equal_bytes(mut self, byte: u32, length: u32) -> Self {
        self = self.push_int(byte);
        self = self.push_int(length);
        self.0.push(Ops::PushEqualBytes as u8);
        self
    }

    pub fn concat(mut self) -> Self {
        self.0.push(Ops::Concat as u8);
        self
    }

    pub fn stable_grow(mut self, additional_pages: u32) -> Self {
        self = self.push_int(additional_pages);
        self.0.push(Ops::StableGrow as u8);
        self
    }

    pub fn stable64_grow(mut self, additional_pages: u64) -> Self {
        self = self.push_int64(additional_pages);
        self.0.push(Ops::StableGrow64 as u8);
        self
    }

    pub fn stable_read(mut self, offset: u32, size: u32) -> Self {
        self = self.push_int(offset);
        self = self.push_int(size);
        self.0.push(Ops::StableRead as u8);
        self
    }

    pub fn stable64_read(mut self, offset: u64, size: u64) -> Self {
        self = self.push_int64(offset);
        self = self.push_int64(size);
        self.0.push(Ops::StableRead64 as u8);
        self
    }

    pub fn stable_write(mut self, offset: u32, data: &[u8]) -> Self {
        self = self.push_int(offset);
        self = self.push_bytes(data);
        self.0.push(Ops::StableWrite as u8);
        self
    }

    /// Write a blob of `data` into the stable memory at the specified `offset`.
    ///
    /// The `offset` integer is expected to be on the stack first, followed by the
    /// blob `data` to write.
    pub fn stable_write_offset_blob(mut self) -> Self {
        self.0.push(Ops::StableWrite as u8);
        self
    }

    pub fn stable64_write(mut self, offset: u64, data: &[u8]) -> Self {
        self = self.push_int64(offset);
        self = self.push_bytes(data);
        self.0.push(Ops::StableWrite64 as u8);
        self
    }

    pub fn stable64_fill(mut self, offset: u64, data: u64, length: u64) -> Self {
        self = self.push_int64(offset);
        self = self.push_int64(data);
        self = self.push_int64(length);
        self.0.push(Ops::StableFill64 as u8);
        self
    }

    pub fn stable_fill(mut self, offset: u32, data: u32, length: u32) -> Self {
        self = self.push_int(offset);
        self = self.push_int(data);
        self = self.push_int(length);
        self.0.push(Ops::StableFill as u8);
        self
    }

    pub fn set_heartbeat<P: AsRef<[u8]>>(mut self, payload: P) -> Self {
        self = self.push_bytes(payload.as_ref());
        self.0.push(Ops::SetHeartbeat as u8);
        self
    }

    pub fn set_global_timer_method<P: AsRef<[u8]>>(mut self, payload: P) -> Self {
        self = self.push_bytes(payload.as_ref());
        self.0.push(Ops::SetGlobalTimerMethod as u8);
        self
    }

    pub fn api_global_timer_set(mut self, timestamp: u64) -> Self {
        self = self.push_int64(timestamp);
        self.0.push(Ops::ApiGlobalTimerSet as u8);
        self
    }

    pub fn canister_version(mut self) -> Self {
        self.0.push(Ops::CanisterVersion as u8);
        self
    }

    pub fn set_inspect_message<P: AsRef<[u8]>>(mut self, payload: P) -> Self {
        self = self.push_bytes(payload.as_ref());
        self.0.push(Ops::SetInspectMessage as u8);
        self
    }

    pub fn set_pre_upgrade<P: AsRef<[u8]>>(mut self, payload: P) -> Self {
        self = self.push_bytes(payload.as_ref());
        self.0.push(Ops::SetPreUpgrade as u8);
        self
    }

    /// A query from a UC to another UC.
    pub fn inter_query<P: AsRef<[u8]>>(self, callee: P, call_args: CallArgs) -> Self {
        self.call_simple(callee, "query", call_args)
    }

    /// A composite query from a UC to another UC.
    pub fn composite_query<P: AsRef<[u8]>>(self, callee: P, call_args: CallArgs) -> Self {
        self.call_simple(callee, "composite_query", call_args)
    }

    /// An update from a UC to another UC.
    pub fn inter_update<P: AsRef<[u8]>>(self, callee: P, call_args: CallArgs) -> Self {
        self.call_simple(callee, "update", call_args)
    }

    pub fn call_simple<P: AsRef<[u8]>, S: ToString>(
        mut self,
        callee: P,
        method: S,
        call_args: CallArgs,
    ) -> Self {
        self = self.call_helper(callee, method, call_args, None, None);
        self
    }

    pub fn call_with_cycles<P: AsRef<[u8]>, S: ToString>(
        mut self,
        callee: P,
        method: S,
        call_args: CallArgs,
        cycles: Cycles,
    ) -> Self {
        self = self.call_helper(callee, method, call_args, Some(cycles), None);
        self
    }

    pub fn call_simple_with_cycles_and_best_effort_response<P: AsRef<[u8]>, S: ToString>(
        mut self,
        callee: P,
        method: S,
        call_args: CallArgs,
        cycles: Cycles,
        timeout_seconds: u32,
    ) -> Self {
        self = self.call_helper(
            callee,
            method,
            call_args,
            Some(cycles),
            Some(timeout_seconds),
        );
        self
    }

    pub fn call_new<P: AsRef<[u8]>, S: ToString>(
        mut self,
        callee: P,
        method: S,
        call_args: CallArgs,
    ) -> Self {
        self = self.push_bytes(callee.as_ref());
        self = self.push_bytes(method.to_string().as_bytes());
        self = self.push_bytes(call_args.on_reply.as_slice());
        self = self.push_bytes(call_args.on_reject.as_slice());
        self.0.push(Ops::CallNew as u8);
        self
    }

    pub fn call_with_best_effort_response(mut self, timeout_seconds: u32) -> Self {
        self = self.push_int(timeout_seconds);
        self.0.push(Ops::CallWithBestEffortResponse as u8);
        self
    }

    pub fn call_perform(mut self) -> Self {
        self.0.push(Ops::CallPerform as u8);
        self
    }

    fn call_helper<P: AsRef<[u8]>, S: ToString>(
        mut self,
        callee: P,
        method: S,
        call_args: CallArgs,
        cycles: Option<Cycles>,
        timeout_secounds: Option<u32>,
    ) -> Self {
        self = self.push_bytes(callee.as_ref());
        self = self.push_bytes(method.to_string().as_bytes());
        self = self.push_bytes(call_args.on_reply.as_slice());
        self = self.push_bytes(call_args.on_reject.as_slice());
        self.0.push(Ops::CallNew as u8);
        self.0.extend_from_slice(call_args.other_side.as_slice());
        self.0.push(Ops::CallDataAppend as u8);
        if let Some(on_cleanup) = call_args.on_cleanup {
            self = self.push_bytes(on_cleanup.as_slice());
            self.0.push(Ops::CallOnCleanup as u8);
        }
        if let Some(cycles) = cycles {
            let (high_amount, low_amount) = cycles.into_parts();
            self = self.push_int64(high_amount);
            self = self.push_int64(low_amount);
            self.0.push(Ops::CallCyclesAdd128 as u8);
        }
        if let Some(timeout) = timeout_secounds {
            self = self.push_int(timeout);
            self.0.push(Ops::CallWithBestEffortResponse as u8);
        }
        self.0.push(Ops::CallPerform as u8);
        self
    }

    pub fn call_cycles_add128(mut self, high_amount: u64, low_amount: u64) -> Self {
        self = self.push_int64(high_amount);
        self = self.push_int64(low_amount);
        self.0.push(Ops::CallCyclesAdd128 as u8);
        self
    }

    pub fn call_cycles_add128_up_to(mut self, high_amount: u64, low_amount: u64) -> Self {
        self = self.push_int64(high_amount);
        self = self.push_int64(low_amount);
        self.0.push(Ops::CallCyclesAdd128UpTo as u8);
        self
    }

    pub fn call_cycles_add(mut self, amount: u64) -> Self {
        self = self.push_int64(amount);
        self.0.push(Ops::CallCyclesAdd as u8);
        self
    }

    pub fn message_payload(mut self) -> Self {
        self.0.push(Ops::MessagePayload as u8);
        self
    }

    pub fn reject_message(mut self) -> Self {
        self.0.push(Ops::RejectMessage as u8);
        self
    }

    pub fn reject_code(mut self) -> Self {
        self.0.push(Ops::RejectCode as u8);
        self
    }

    pub fn reject(mut self) -> Self {
        self.0.push(Ops::Reject as u8);
        self
    }

    pub fn noop(mut self) -> Self {
        self.0.push(Ops::Noop as u8);
        self
    }

    pub fn caller(mut self) -> Self {
        self.0.push(Ops::Caller as u8);
        self
    }

    pub fn self_(mut self) -> Self {
        self.0.push(Ops::Self_ as u8);
        self
    }

    /// Store data (in a global variable) on the heap.
    /// NOTE: This does _not_ correspond to a Wasm global.
    pub fn set_global_data(mut self, data: &[u8]) -> Self {
        self = self.push_bytes(data);
        self.0.push(Ops::SetGlobal as u8);
        self
    }

    /// Store the current stack data (in a global variable) on the heap.
    /// NOTE: This does _not_ correspond to a Wasm global.
    pub fn set_global_data_from_stack(mut self) -> Self {
        self.0.push(Ops::SetGlobal as u8);
        self
    }

    /// Succintly encode the following code:
    /// `self.push_bytes(&wasm().push_bytes(&vec![42; length as usize]).blob_length().reply_int().build())`
    /// The code pushes a payload to be executed by a callee onto the caller's stack.
    /// The payload pushes a blob of a provided length onto the callee's stack and replies with its length to the caller.
    /// Such a payload is useful in tests exercising inter-canister call size limits
    /// since its encoding passed to the caller is succinct, but when interpreted by the caller,
    /// it expands to an inter-canister call argument for the callee of an arbitrary size.
    pub fn push_bytes_wasm_push_bytes_and_reply(mut self, length: u32) -> Self {
        self = self.push_bytes(&[Ops::PushBytes as u8]);
        self = self.push_bytes(&length.to_le_bytes()).concat();
        self = self.push_equal_bytes(42, length).concat();
        self.push_bytes(&wasm().blob_length().reply_int().build())
            .concat()
    }

    /// Get data (stored in a global variable) from the heap.
    /// NOTE: This does _not_ correspond to a Wasm global.
    pub fn get_global_data(mut self) -> Self {
        self.0.push(Ops::GetGlobal as u8);
        self
    }

    /// Increases heap-allocated global u64 counter.
    pub fn inc_global_counter(mut self) -> Self {
        self.0.push(Ops::IncGlobalCounter as u8);
        self
    }

    /// Gets the heap-allocated global u64 counter.
    pub fn get_global_counter(mut self) -> Self {
        self.0.push(Ops::GetGlobalCounter as u8);
        self
    }

    /// Pushes the performance counter of the specified type on top of the stack.
    pub fn performance_counter(mut self, _type: u32) -> Self {
        self = self.push_int(_type);
        self.0.push(Ops::GetPerformanceCounter as u8);
        self
    }

    pub fn debug_print(mut self, msg: &[u8]) -> Self {
        self = self.push_bytes(msg);
        self.0.push(Ops::DebugPrint as u8);
        self
    }

    pub fn trap_with_blob(mut self, data: &[u8]) -> Self {
        self = self.push_bytes(data);
        self.0.push(Ops::Trap as u8);
        self
    }

    pub fn trap(self) -> Self {
        self.trap_with_blob(&[]) // No data provided for trap.
    }

    pub fn accept_message(mut self) -> Self {
        self.0.push(Ops::AcceptMessage as u8);
        self
    }

    pub fn trap_if_eq<P: AsRef<[u8]>>(mut self, data: P, error_message: &str) -> Self {
        self = self.push_bytes(data.as_ref());
        self = self.push_bytes(error_message.as_bytes());
        self.0.push(Ops::TrapIfEq as u8);
        self
    }

    pub fn accept_cycles(mut self, cycles: Cycles) -> Self {
        let (amount_high, amount_low) = cycles.into_parts();
        self = self.push_int64(amount_high);
        self = self.push_int64(amount_low);
        self.0.push(Ops::AcceptCycles128 as u8);
        self
    }

    pub fn cycles_burn128(mut self, amount: Cycles) -> Self {
        let (amount_high, amount_low) = amount.into_parts();
        self = self.push_int64(amount_high);
        self = self.push_int64(amount_low);
        self.0.push(Ops::CyclesBurn128 as u8);
        self
    }

    pub fn call<C: Into<Call>>(mut self, call: C) -> Self {
        let call = call.into();
        let call_args = call.get_call_args();
        let (cycles_high, cycles_low) = call.cycles;
        self = self.call_with_cycles(
            call.callee,
            call.method,
            call_args,
            Cycles::from_parts(cycles_high, cycles_low),
        );
        self
    }

    /// Pushes the size of the argument data onto the stack.
    pub fn msg_arg_data_size(mut self) -> Self {
        self.0.push(Ops::MsgArgDataSize as u8);
        self
    }

    /// Pushes a blob of the given size filled with the argument data bytes starting
    /// from the given offset.
    pub fn msg_arg_data_copy(mut self, offset: u32, size: u32) -> Self {
        self = self.push_int(offset);
        self = self.push_int(size);
        self.0.push(Ops::MsgArgDataCopy as u8);
        self
    }

    /// Pushes the size of the caller data onto the stack.
    pub fn msg_caller_size(mut self) -> Self {
        self.0.push(Ops::MsgCallerSize as u8);
        self
    }

    /// Pushes the deadline of the message onto the stack.
    pub fn msg_deadline(mut self) -> Self {
        self.0.push(Ops::MsgDeadline as u8);
        self
    }

    /// Pushes a blob of the given size filled with the caller data bytes starting
    /// from the given offset.
    pub fn msg_caller_copy(mut self, offset: u32, size: u32) -> Self {
        self = self.push_int(offset);
        self = self.push_int(size);
        self.0.push(Ops::MsgCallerCopy as u8);
        self
    }

    /// Pushes the size of the reject message onto the stack.
    pub fn msg_reject_msg_size(mut self) -> Self {
        self.0.push(Ops::MsgRejectMsgSize as u8);
        self
    }

    /// Pushes a blob of the given size filled with the reject message bytes starting
    /// from the given offset.
    pub fn msg_reject_msg_copy(mut self, offset: u32, size: u32) -> Self {
        self = self.push_int(offset);
        self = self.push_int(size);
        self.0.push(Ops::MsgRejectMsgCopy as u8);
        self
    }

    pub fn msg_cycles_available(mut self) -> Self {
        self.0.push(Ops::CyclesAvailable as u8);
        self
    }

    pub fn msg_cycles_available128(mut self) -> Self {
        self.0.push(Ops::CyclesAvailable128 as u8);
        self
    }

    pub fn msg_cycles_refunded(mut self) -> Self {
        self.0.push(Ops::CyclesRefunded as u8);
        self
    }

    pub fn msg_cycles_refunded128(mut self) -> Self {
        self.0.push(Ops::CyclesRefunded128 as u8);
        self
    }

    pub fn msg_cycles_accept(mut self, max_amount: i64) -> Self {
        self = self.push_int64(max_amount as u64);
        self.0.push(Ops::AcceptCycles as u8);
        self
    }

    pub fn msg_cycles_accept128(mut self, max_amount_height: i64, max_amount_low: i64) -> Self {
        self = self.push_int64(max_amount_height as u64);
        self = self.push_int64(max_amount_low as u64);
        self.0.push(Ops::AcceptCycles128 as u8);
        self
    }

    pub fn certified_data_set(mut self, data: &[u8]) -> Self {
        self = self.push_bytes(data);
        self.0.push(Ops::CertifiedDataSet as u8);
        self
    }

    pub fn data_certificate(mut self) -> Self {
        self.0.push(Ops::DataCertificate as u8);
        self
    }

    /// Loops until the instruction counter is at least the specified amount.
    pub fn instruction_counter_is_at_least(mut self, amount: u64) -> Self {
        self = self.push_int64(amount);
        self.0.push(Ops::InstructionCounterIsAtLeast as u8);
        self
    }

    pub fn is_controller(mut self, data: &[u8]) -> Self {
        self = self.push_bytes(data);
        self.0.push(Ops::IsController as u8);
        self
    }

    pub fn in_replicated_execution(mut self) -> Self {
        self.0.push(Ops::InReplicatedExecution as u8);
        self
    }

    /// Push `int64` with current time. The time is given as nanoseconds since 1970-01-01.
    pub fn time(mut self) -> Self {
        self.0.push(Ops::Time as u8);
        self
    }

    /// Push `int64` with canister cycles balance.
    pub fn cycles_balance(mut self) -> Self {
        self.0.push(Ops::CyclesBalance as u8);
        self
    }

    /// Push `blob` with canister cycles balance.
    pub fn cycles_balance128(mut self) -> Self {
        self.0.push(Ops::CyclesBalance128 as u8);
        self
    }

    /// Allocates heap memory until the memory size is at least the specified amount in bytes.
    pub fn memory_size_is_at_least(mut self, amount: u64) -> Self {
        self = self.push_int64(amount);
        self.0.push(Ops::MemorySizeIsAtLeast as u8);
        self
    }

    pub fn build(self) -> Vec<u8> {
        self.0
    }
}

pub struct Call {
    callee: Vec<u8>,
    method: String,
    args: CallArgs,
    cycles: (u64, u64),
}

impl CallInterface for Call {
    fn call(&mut self) -> &mut Call {
        self
    }
}

impl Call {
    fn new<P: AsRef<[u8]>, S: Into<String>>(callee: P, method: S) -> Self {
        let mut callee_vec = Vec::new();
        callee_vec.extend_from_slice(callee.as_ref());
        Self {
            callee: callee_vec,
            method: method.into(),
            args: CallArgs::default(),
            cycles: (0, 0),
        }
    }

    fn get_call_args(&self) -> CallArgs {
        self.args.clone()
    }
}

pub trait CallInterface {
    fn call(&mut self) -> &mut Call;

    fn cycles(mut self, cycles: (u64, u64)) -> Self
    where
        Self: std::marker::Sized,
    {
        self.call().cycles = cycles;
        self
    }

    fn with_payload<V: Into<Vec<u8>>>(mut self, payload: V) -> Self
    where
        Self: std::marker::Sized,
    {
        self.call().args.other_side = PayloadBuilder::default()
            .push_bytes(&payload.into())
            .build();
        self
    }

    fn on_reply<V: Into<Vec<u8>>>(mut self, on_reply: V) -> Self
    where
        Self: std::marker::Sized,
    {
        self.call().args.on_reply = on_reply.into();
        self
    }

    fn on_reject<V: Into<Vec<u8>>>(mut self, on_reject: V) -> Self
    where
        Self: std::marker::Sized,
    {
        self.call().args.on_reject = on_reject.into();
        self
    }

    fn on_cleanup<V: Into<Vec<u8>>>(mut self, on_cleanup: V) -> Self
    where
        Self: std::marker::Sized,
    {
        self.call().args.on_cleanup = Some(on_cleanup.into());
        self
    }
}

impl From<Vec<u8>> for PayloadBuilder {
    fn from(payload: Vec<u8>) -> Self {
        Self(payload)
    }
}

impl AsRef<[u8]> for PayloadBuilder {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<PayloadBuilder> for Vec<u8> {
    fn from(pb: PayloadBuilder) -> Self {
        pb.build()
    }
}

/// Arguments to be passed into `call_new`.
#[derive(Clone)]
pub struct CallArgs {
    /// Instructions to be exected by the caller upon reply.
    on_reply: Vec<u8>,
    /// Instructions to be exected by the caller upon reject.
    on_reject: Vec<u8>,
    /// Instructions to be exected by the caller to produce the payload to be executed by the callee.
    other_side: Vec<u8>,
    /// Instructions to be exected by the caller upon cleanup.
    on_cleanup: Option<Vec<u8>>,
}

impl Default for CallArgs {
    fn default() -> Self {
        Self {
            on_reply: Self::default_on_reply(),
            on_reject: Self::default_on_reject(),
            other_side: Self::default_other_side(),
            on_cleanup: None,
        }
    }
}

impl CallArgs {
    pub fn on_reply<C: Into<Vec<u8>>>(mut self, callback: C) -> Self {
        self.on_reply = callback.into();
        self
    }

    pub fn on_reject<C: Into<Vec<u8>>>(mut self, callback: C) -> Self {
        self.on_reject = callback.into();
        self
    }

    pub fn on_cleanup<C: Into<Vec<u8>>>(mut self, callback: C) -> Self {
        self.on_cleanup = Some(callback.into());
        self
    }

    // Computes instructions to be exected by the caller to produce the provided payload to be executed by the callee.
    pub fn other_side<C: Into<Vec<u8>>>(mut self, callback: C) -> Self {
        self.other_side = PayloadBuilder::default()
            .push_bytes(&callback.into())
            .build();
        self
    }

    // Stores provided instructions to be exected by the caller to produce the payload to be executed by the callee.
    pub fn eval_other_side<C: Into<Vec<u8>>>(mut self, ops_bytes: C) -> Self {
        self.other_side = ops_bytes.into();
        self
    }

    // The default on_reply callback.
    // Replies to the caller of the caller with whatever arguments passed to it.
    fn default_on_reply() -> Vec<u8> {
        PayloadBuilder::default()
            .message_payload()
            .reply_data_append()
            .reply()
            .build()
    }

    // The default on_reject callback.
    // Replies to the caller of the caller with the reject code.
    fn default_on_reject() -> Vec<u8> {
        PayloadBuilder::default()
            .reject_code()
            .int_to_blob()
            .reject()
            .build()
    }

    // Computes instructions to be executed by the caller to produce the default payload to be executed by the callee.
    // The default payload is to reply with a message stating who the callee and the caller is.
    fn default_other_side() -> Vec<u8> {
        let callback = PayloadBuilder::default()
            .push_bytes(b"Hello ")
            .reply_data_append()
            .caller()
            .reply_data_append()
            .push_bytes(b" this is ")
            .reply_data_append()
            .self_()
            .reply_data_append()
            .reply()
            .build();
        PayloadBuilder::default().push_bytes(&callback).build()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn check_hardcoded_sha256_is_up_to_date() {
        assert_eq!(
            UNIVERSAL_CANISTER_WASM_SHA256,
            ic_crypto_sha2::Sha256::hash(UNIVERSAL_CANISTER_WASM)
        );
    }

    #[test]
    fn try_from_macro_works() {
        assert_eq!(Ops::GetGlobalCounter, Ops::try_from(65).unwrap());
    }
}
