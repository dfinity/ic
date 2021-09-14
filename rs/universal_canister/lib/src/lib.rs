//! The Universal Canister (UC) is a canister built in Rust, compiled to Wasm,
//! and serves as a canister that can be used for a multitude of tests.
//!
//! Payloads to UC can execute any arbitrary sequence of system methods, making
//! it possible to test different canister behaviors without having to write up
//! custom Wat files.

pub mod management;

use hex_literal::hex;

/// The binary of the universal canister as compiled from
/// `rs/universal_canister/impl`.
///
/// For steps on how to produce it, please see the README in
/// `rs/universal_canister`.
pub const UNIVERSAL_CANISTER_WASM: &[u8] = include_bytes!("universal_canister.wasm");
pub const UNIVERSAL_CANISTER_WASM_SHA256: [u8; 32] =
    hex!("8115659b4d5242654f4ce4ebf4e4acf6928df430707afadffcd94772c9cbd2fe");

/// Operands used in encoding UC payloads.
enum Ops {
    Noop = 0,
    PushInt = 2,
    PushBytes = 3,
    ReplyDataAppend = 4,
    Reply = 5,
    Self_ = 6,
    Reject = 7,
    Caller = 8,
    RejectMessage = 10,
    RejectCode = 11,
    IntToBlob = 12,
    MessagePayload = 13,
    StableSize = 15,
    StableGrow = 16,
    StableRead = 17,
    StableWrite = 18,
    DebugPrint = 19,
    Trap = 20,
    SetGlobal = 21,
    GetGlobal = 22,
    SetPreUpgrade = 24,
    AcceptCycles = 30,
    PushInt64 = 31,
    CallNew = 32,
    CallDataAppend = 33,
    CallCyclesAdd = 34,
    CallPerform = 35,
    SetHeartbeat = 40,
    AcceptMessage = 41,
    SetInspectMessage = 42,
    TrapIfEq = 43,
    CallOnCleanup = 44,
    StableFill = 45,
}

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

    pub fn reply_data_append(mut self) -> Self {
        self.0.push(Ops::ReplyDataAppend as u8);
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

    pub fn reply(mut self) -> Self {
        self.0.push(Ops::Reply as u8);
        self
    }

    pub fn stable_size(mut self) -> Self {
        self.0.push(Ops::StableSize as u8);
        self
    }

    pub fn push_bytes(mut self, data: &[u8]) -> Self {
        self.0.push(Ops::PushBytes as u8);
        self.0.extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.0.extend_from_slice(data);
        self
    }

    pub fn stable_grow(mut self, additional_pages: u32) -> Self {
        self = self.push_int(additional_pages);
        self.0.push(Ops::StableGrow as u8);
        self
    }

    pub fn stable_read(mut self, offset: u32, size: u32) -> Self {
        self = self.push_int(offset);
        self = self.push_int(size);
        self.0.push(Ops::StableRead as u8);
        self
    }

    pub fn stable_write(mut self, offset: u32, data: &[u8]) -> Self {
        self = self.push_int(offset);
        self = self.push_bytes(data);
        self.0.push(Ops::StableWrite as u8);
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
        self = self.call_helper(callee, method, call_args, None);
        self
    }

    pub fn call_with_cycles<P: AsRef<[u8]>, S: ToString>(
        mut self,
        callee: P,
        method: S,
        call_args: CallArgs,
        num_cycles: u64,
    ) -> Self {
        self = self.call_helper(callee, method, call_args, Some(num_cycles));
        self
    }

    fn call_helper<P: AsRef<[u8]>, S: ToString>(
        mut self,
        callee: P,
        method: S,
        call_args: CallArgs,
        num_cycles: Option<u64>,
    ) -> Self {
        self = self.push_bytes(callee.as_ref());
        self = self.push_bytes(method.to_string().as_bytes());
        self = self.push_bytes(call_args.on_reply.as_slice());
        self = self.push_bytes(call_args.on_reject.as_slice());
        self.0.push(Ops::CallNew as u8);
        self = self.push_bytes(call_args.other_side.as_slice());
        self.0.push(Ops::CallDataAppend as u8);
        if let Some(on_cleanup) = call_args.on_cleanup {
            self = self.push_bytes(on_cleanup.as_slice());
            self.0.push(Ops::CallOnCleanup as u8);
        }
        if let Some(num_cycles) = num_cycles {
            self = self.push_int64(num_cycles);
            self.0.push(Ops::CallCyclesAdd as u8);
        }
        self.0.push(Ops::CallPerform as u8);
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

    /// Get data (stored in a global variable) from the heap.
    /// NOTE: This does _not_ correspond to a Wasm global.
    pub fn get_global_data(mut self) -> Self {
        self.0.push(Ops::GetGlobal as u8);
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

    pub fn accept_cycles(mut self, num_cycles: u64) -> Self {
        self = self.push_int64(num_cycles);
        self.0.push(Ops::AcceptCycles as u8);
        self
    }

    pub fn call<C: Into<Call>>(mut self, call: C) -> Self {
        let call = call.into();
        let call_args = call.get_call_args();
        self = self.call_with_cycles(call.callee, call.method, call_args, call.cycles);
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
    cycles: u64,
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
            cycles: 0,
        }
    }

    fn get_call_args(&self) -> CallArgs {
        self.args.clone()
    }
}

pub trait CallInterface {
    fn call(&mut self) -> &mut Call;

    fn cycles(mut self, cycles: u64) -> Self
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
        self.call().args.other_side = payload.into();
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
        &self.0.as_slice()
    }
}

impl From<PayloadBuilder> for Vec<u8> {
    fn from(pb: PayloadBuilder) -> Self {
        pb.build()
    }
}

/// Arguments to be passed into `call_simple` or `call_with_funds`.
#[derive(Clone)]
pub struct CallArgs {
    pub on_reply: Vec<u8>,
    pub on_reject: Vec<u8>,
    pub other_side: Vec<u8>,
    pub on_cleanup: Option<Vec<u8>>,
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

    pub fn other_side<C: Into<Vec<u8>>>(mut self, callback: C) -> Self {
        self.other_side = callback.into();
        self
    }

    // The default on_reply callback.
    // Replies to the caller with whatever arguments passed to it.
    fn default_on_reply() -> Vec<u8> {
        PayloadBuilder::default()
            .message_payload()
            .reply_data_append()
            .reply()
            .build()
    }

    // The default on_reject callback.
    // Replies to the caller with the reject code.
    fn default_on_reject() -> Vec<u8> {
        PayloadBuilder::default()
            .reject_code()
            .int_to_blob()
            .reject()
            .build()
    }

    // The default payload to be executed by the callee.
    // Replies with a message stating who the callee and the caller is.
    fn default_other_side() -> Vec<u8> {
        PayloadBuilder::default()
            .push_bytes(b"Hello ")
            .reply_data_append()
            .caller()
            .reply_data_append()
            .push_bytes(b" this is ")
            .reply_data_append()
            .self_()
            .reply_data_append()
            .reply()
            .build()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn check_hardcoded_sha256_is_up_to_date() {
        assert_eq!(
            UNIVERSAL_CANISTER_WASM_SHA256,
            ic_crypto_sha::Sha256::hash(UNIVERSAL_CANISTER_WASM)
        );
    }
}
