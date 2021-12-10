// NOTE: We should try to reuse dfn_core::api here.
// use `wee_alloc` as the global allocator.
extern crate wee_alloc;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc<'_> = wee_alloc::WeeAlloc::INIT;

mod ic0 {
    #[link(wasm_import_module = "ic0")]
    extern "C" {
        pub fn accept_message() -> ();
        pub fn canister_self_copy(dst: u32, offset: u32, size: u32) -> ();
        pub fn canister_self_size() -> u32;
        pub fn canister_status() -> u32;
        pub fn debug_print(offset: u32, size: u32) -> ();
        pub fn msg_arg_data_copy(dst: u32, offset: u32, size: u32) -> ();
        pub fn msg_arg_data_size() -> u32;
        pub fn msg_caller_copy(dst: u32, offset: u32, size: u32) -> ();
        pub fn msg_caller_size() -> u32;
        pub fn msg_reject(src: u32, size: u32) -> ();
        pub fn msg_reject_code() -> u32;
        pub fn msg_reject_msg_copy(dst: u32, offset: u32, size: u32) -> ();
        pub fn msg_reject_msg_size() -> u32;
        pub fn msg_reply() -> ();
        pub fn msg_reply_data_append(offset: u32, size: u32) -> ();
        pub fn msg_cycles_available() -> u64;
        pub fn msg_cycles_available128(dst: u32) -> ();
        pub fn msg_cycles_refunded() -> u64;
        pub fn msg_cycles_refunded128(dst: u32) -> ();
        pub fn msg_cycles_accept(max_amount: u64) -> u64;
        pub fn msg_cycles_accept128(max_amount_high: u64, max_amount_low: u64, dst: u32) -> ();
        pub fn canister_cycle_balance() -> u64;
        pub fn canister_cycle_balance128(dst: u32) -> ();
        pub fn trap(offset: u32, size: u32) -> !;
        pub fn call_new(
            callee_src: u32,
            callee_size: u32,
            name_src: u32,
            name_size: u32,
            reply_fun: u32,
            reply_env: u32,
            reject_fun: u32,
            reject_env: u32,
        ) -> ();
        pub fn call_on_cleanup(fun: u32, env: u32) -> ();
        pub fn call_data_append(src: u32, size: u32) -> ();
        pub fn call_cycles_add(amount: u64) -> ();
        pub fn call_cycles_add128(amount_high: u64, amount_low: u64) -> ();
        pub fn call_perform() -> u32;
        pub fn stable_size() -> u32;
        pub fn stable_grow(additional_pages: u32) -> u32;
        pub fn stable_read(dst: u32, offset: u32, size: u32) -> ();
        pub fn stable_write(offset: u32, src: u32, size: u32) -> ();
        pub fn stable64_size() -> u64;
        pub fn stable64_grow(additional_pages: u64) -> u64;
        pub fn stable64_read(dst: u64, offset: u64, size: u64) -> ();
        pub fn stable64_write(offset: u64, src: u64, size: u64) -> ();
        pub fn certified_data_set(src: u32, size: u32) -> ();
        pub fn data_certificate_present() -> u32;
        pub fn data_certificate_size() -> u32;
        pub fn data_certificate_copy(dst: u32, offset: u32, size: u32) -> ();

        pub fn time() -> u64;
    }
}

// Convenience wrappers around the DFINITY System API

const CYCLES_SIZE: usize = 16;

pub fn accept_message() {
    unsafe { ic0::accept_message() }
}

pub fn call_new(
    callee: &[u8],
    method: &[u8],
    reply_fun: fn(u32) -> (),
    reply_env: u32,
    reject_fun: fn(u32) -> (),
    reject_env: u32,
) {
    unsafe {
        ic0::call_new(
            callee.as_ptr() as u32,
            callee.len() as u32,
            method.as_ptr() as u32,
            method.len() as u32,
            reply_fun as u32,
            reply_env as u32,
            reject_fun as u32,
            reject_env as u32,
        )
    }
}

pub fn call_on_cleanup(fun: fn(u32) -> (), env: u32) {
    unsafe { ic0::call_on_cleanup(fun as u32, env as u32) }
}

pub fn call_data_append(payload: &[u8]) {
    unsafe {
        ic0::call_data_append(payload.as_ptr() as u32, payload.len() as u32);
    }
}

pub fn call_cycles_add(amount: u64) {
    unsafe {
        ic0::call_cycles_add(amount);
    }
}

pub fn call_cycles_add128(amount_high: u64, amount_low: u64) {
    unsafe {
        ic0::call_cycles_add128(amount_high, amount_low);
    }
}

pub fn call_perform() -> u32 {
    unsafe { ic0::call_perform() }
}

/// Returns the argument extracted from the message payload.
pub fn arg_data() -> Vec<u8> {
    let len: u32 = unsafe { ic0::msg_arg_data_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::msg_arg_data_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    bytes
}

/// Returns the caller of the current call.
pub fn caller() -> Vec<u8> {
    let len: u32 = unsafe { ic0::msg_caller_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::msg_caller_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    bytes
}

/// Returns the canister id as a blob.
pub fn id() -> Vec<u8> {
    let len: u32 = unsafe { ic0::canister_self_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::canister_self_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    bytes
}

pub fn status() -> u32 {
    unsafe { ic0::canister_status() }
}

/// Returns the rejection message.
pub fn reject_message() -> Vec<u8> {
    let len: u32 = unsafe { ic0::msg_reject_msg_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::msg_reject_msg_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    bytes
}

pub fn reply_data_append(payload: &[u8]) {
    unsafe {
        ic0::msg_reply_data_append(payload.as_ptr() as u32, payload.len() as u32);
    }
}

pub fn reply() {
    unsafe {
        ic0::msg_reply();
    }
}

/// Rejects the current call with the given message.
pub fn reject(err_message: &[u8]) {
    unsafe {
        ic0::msg_reject(err_message.as_ptr() as u32, err_message.len() as u32);
    }
}

pub fn reject_code() -> u32 {
    unsafe { ic0::msg_reject_code() }
}

pub fn cycles_available() -> u64 {
    unsafe { ic0::msg_cycles_available() }
}

pub fn cycles_available128() -> Vec<u8> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    unsafe { ic0::msg_cycles_available128(bytes.as_mut_ptr() as u32) }
    bytes
}

pub fn cycles_refunded() -> u64 {
    unsafe { ic0::msg_cycles_refunded() }
}

pub fn cycles_refunded128() -> Vec<u8> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    unsafe { ic0::msg_cycles_refunded128(bytes.as_mut_ptr() as u32) }
    bytes
}

pub fn accept(amount: u64) -> u64 {
    unsafe { ic0::msg_cycles_accept(amount) }
}

pub fn accept128(amount_high: u64, amount_low: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    unsafe { ic0::msg_cycles_accept128(amount_high, amount_low, bytes.as_mut_ptr() as u32) }
    bytes
}

pub fn balance() -> u64 {
    unsafe { ic0::canister_cycle_balance() }
}

pub fn balance128() -> Vec<u8> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    unsafe { ic0::canister_cycle_balance128(bytes.as_mut_ptr() as u32) }
    bytes
}

pub fn stable_size() -> u32 {
    unsafe { ic0::stable_size() }
}

pub fn stable64_size() -> u64 {
    unsafe { ic0::stable64_size() }
}

pub fn stable_grow(additional_pages: u32) -> u32 {
    unsafe { ic0::stable_grow(additional_pages) }
}

pub fn stable64_grow(additional_pages: u64) -> u64 {
    unsafe { ic0::stable64_grow(additional_pages) }
}

pub fn stable_read(offset: u32, size: u32) -> Vec<u8> {
    let mut bytes = vec![0; size as usize];
    unsafe {
        ic0::stable_read(bytes.as_mut_ptr() as u32, offset, size);
    }
    bytes
}

pub fn stable64_read(offset: u64, size: u64) -> Vec<u8> {
    let mut bytes = vec![0; size as usize];
    unsafe {
        ic0::stable64_read(bytes.as_mut_ptr() as u64, offset, size);
    }
    bytes
}

pub fn stable_write(offset: u32, data: &[u8]) {
    unsafe {
        ic0::stable_write(offset, data.as_ptr() as u32, data.len() as u32);
    }
}

pub fn stable64_write(offset: u64, data: &[u8]) {
    unsafe {
        ic0::stable64_write(offset, data.as_ptr() as u64, data.len() as u64);
    }
}

pub fn certified_data_set(data: &[u8]) {
    unsafe {
        ic0::certified_data_set(data.as_ptr() as u32, data.len() as u32);
    }
}

pub fn data_certificate_present() -> u32 {
    unsafe { ic0::data_certificate_present() }
}

pub fn data_certificate() -> Vec<u8> {
    let len: u32 = unsafe { ic0::data_certificate_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::data_certificate_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    bytes
}

pub fn time() -> u64 {
    unsafe { ic0::time() }
}

/// Prints the given message.
pub fn print(data: &[u8]) {
    unsafe {
        ic0::debug_print(data.as_ptr() as u32, data.len() as u32);
    }
}

pub fn bad_print() {
    unsafe {
        ic0::debug_print(u32::max_value() - 2, 1);
        ic0::debug_print(u32::max_value() - 2, 3);
    }
}

/// Traps with the given message.
pub fn trap_with_blob(data: &[u8]) -> ! {
    unsafe {
        ic0::trap(data.as_ptr() as u32, data.len() as u32);
    }
}
pub fn trap_with(message: &str) -> ! {
    unsafe {
        ic0::trap(message.as_ptr() as u32, message.len() as u32);
    }
}

use std::panic;
pub fn set_panic_hook() {
    panic::set_hook(Box::new(|i| {
        let s = i.to_string();
        trap_with(&s);
    }));
}
