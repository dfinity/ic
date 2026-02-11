// NOTE: We should try to reuse dfn_core::api here.

#[allow(clippy::unused_unit)]
mod ic0 {
    #[link(wasm_import_module = "ic0")]
    unsafe extern "C" {
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
        pub fn msg_method_name_copy(dst: u32, offset: u32, size: u32) -> ();
        pub fn msg_method_name_size() -> u32;
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
        pub fn canister_liquid_cycle_balance128(dst: u32) -> ();
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
        pub fn call_with_best_effort_response(timeout_seconds: u32) -> ();
        pub fn msg_deadline() -> u64;
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
        pub fn root_key_size() -> u32;
        pub fn root_key_copy(dst: u32, offset: u32, size: u32) -> ();
        pub fn certified_data_set(src: u32, size: u32) -> ();
        pub fn data_certificate_present() -> u32;
        pub fn data_certificate_size() -> u32;
        pub fn data_certificate_copy(dst: u32, offset: u32, size: u32) -> ();

        pub fn time() -> u64;
        pub fn performance_counter(counter_type: u32) -> u64;
        pub fn global_timer_set(timestamp: u64) -> u64;
        pub fn canister_version() -> u64;

        pub fn mint_cycles128(amount_high: u64, amount_low: u64, dst: u32) -> ();

        pub fn is_controller(src: u32, size: u32) -> u32;
        pub fn in_replicated_execution() -> u32;

        pub fn cycles_burn128(amount_high: u64, amount_low: u64, dst: u32) -> ();

        pub fn cost_call(method_name_size: u64, payload_size: u64, dst: u32) -> ();
        pub fn cost_create_canister(dst: u32) -> ();
        pub fn cost_http_request(request_size: u64, max_res_bytes: u64, dst: u32) -> ();
        pub fn cost_http_request_v2(params_src: u32, params_size: u32, dst: u32) -> ();
        pub fn cost_sign_with_ecdsa(src: u32, size: u32, ecdsa_curve: u32, dst: u32) -> u32;
        pub fn cost_sign_with_schnorr(src: u32, size: u32, algorithm: u32, dst: u32) -> u32;
        pub fn cost_vetkd_derive_key(src: u32, size: u32, vetkd_curve: u32, dst: u32) -> u32;

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
        #[allow(clippy::fn_to_numeric_cast_with_truncation)]
        ic0::call_new(
            callee.as_ptr() as u32,
            callee.len() as u32,
            method.as_ptr() as u32,
            method.len() as u32,
            reply_fun as u32,
            reply_env,
            reject_fun as u32,
            reject_env,
        )
    }
}

pub fn call_on_cleanup(fun: fn(u32) -> (), env: u32) {
    #[allow(clippy::fn_to_numeric_cast_with_truncation)]
    unsafe {
        ic0::call_on_cleanup(fun as u32, env)
    }
}

pub fn call_data_append(payload: &[u8]) {
    unsafe {
        ic0::call_data_append(payload.as_ptr() as u32, payload.len() as u32);
    }
}

pub fn call_with_best_effort_response(timeout_seconds: u32) {
    unsafe {
        ic0::call_with_best_effort_response(timeout_seconds);
    }
}

pub fn msg_deadline() -> u64 {
    unsafe { ic0::msg_deadline() }
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

/// Returns the size of the argument data in bytes.
pub fn msg_arg_data_size() -> u32 {
    unsafe { ic0::msg_arg_data_size() }
}

/// Returns a buffer of the given size that is filled with the argument data
/// bytes starting from the given offset.
pub fn msg_arg_data_copy(offset: u32, size: u32) -> Vec<u8> {
    let mut bytes = vec![0; size as usize];
    unsafe {
        ic0::msg_arg_data_copy(bytes.as_mut_ptr() as u32, offset, size);
    }
    bytes
}

/// Returns the argument extracted from the message payload.
pub fn arg_data() -> Vec<u8> {
    msg_arg_data_copy(0, msg_arg_data_size())
}

/// Returns the size of the caller in bytes.
pub fn msg_caller_size() -> u32 {
    unsafe { ic0::msg_caller_size() }
}

/// Returns a buffer of the given size that is filled with the caller bytes
/// starting from the given offset.
pub fn msg_caller_copy(offset: u32, size: u32) -> Vec<u8> {
    let mut bytes = vec![0; size as usize];
    unsafe {
        ic0::msg_caller_copy(bytes.as_mut_ptr() as u32, offset, size);
    }
    bytes
}

/// Returns the caller of the current call.
pub fn caller() -> Vec<u8> {
    msg_caller_copy(0, msg_caller_size())
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

/// Returns the size of the reject message in bytes.
pub fn msg_reject_msg_size() -> u32 {
    unsafe { ic0::msg_reject_msg_size() }
}

/// Returns a buffer of the given size that is filled with the reject message
/// bytes starting from the given offset.
pub fn msg_reject_msg_copy(offset: u32, size: u32) -> Vec<u8> {
    let mut bytes = vec![0; size as usize];
    unsafe {
        ic0::msg_reject_msg_copy(bytes.as_mut_ptr() as u32, offset, size);
    }
    bytes
}

/// Returns the rejection message.
pub fn reject_message() -> Vec<u8> {
    msg_reject_msg_copy(0, msg_reject_msg_size())
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

pub fn liquid_balance128() -> Vec<u8> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    unsafe { ic0::canister_liquid_cycle_balance128(bytes.as_mut_ptr() as u32) }
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

pub fn root_key_size() -> u32 {
    unsafe { ic0::root_key_size() }
}

pub fn root_key_copy(offset: u32, size: u32) -> Vec<u8> {
    let mut bytes = vec![0; size as usize];
    unsafe {
        ic0::root_key_copy(bytes.as_mut_ptr() as u32, offset, size);
    }
    bytes
}

/// Returns the root key.
pub fn root_key() -> Vec<u8> {
    root_key_copy(0, root_key_size())
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

pub fn performance_counter(counter_type: u32) -> u64 {
    unsafe { ic0::performance_counter(counter_type) }
}

pub fn method_name() -> Vec<u8> {
    let len: u32 = unsafe { ic0::msg_method_name_size() };
    let mut bytes = vec![0; len as usize];
    unsafe {
        ic0::msg_method_name_copy(bytes.as_mut_ptr() as u32, 0, len);
    }
    bytes
}

pub fn global_timer_set(timestamp: u64) -> u64 {
    unsafe { ic0::global_timer_set(timestamp) }
}

pub fn canister_version() -> u64 {
    unsafe { ic0::canister_version() }
}

/// Prints the given message.
pub fn print(data: &[u8]) {
    unsafe {
        ic0::debug_print(data.as_ptr() as u32, data.len() as u32);
    }
}

pub fn bad_print() {
    unsafe {
        ic0::debug_print(u32::MAX - 2, 1);
        ic0::debug_print(u32::MAX - 2, 3);
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

/// Mint cycles (only works on CMC).
pub fn mint_cycles128(amount_high: u64, amount_low: u64) -> Vec<u8> {
    let mut result_bytes = vec![0u8; CYCLES_SIZE];
    unsafe { ic0::mint_cycles128(amount_high, amount_low, result_bytes.as_mut_ptr() as u32) }
    result_bytes
}

pub fn is_controller(data: &[u8]) -> u32 {
    unsafe { ic0::is_controller(data.as_ptr() as u32, data.len() as u32) }
}

pub fn in_replicated_execution() -> u32 {
    unsafe { ic0::in_replicated_execution() }
}

/// Burn cycles.
pub fn cycles_burn128(amount_high: u64, amount_low: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    unsafe { ic0::cycles_burn128(amount_high, amount_low, bytes.as_mut_ptr() as u32) }
    bytes
}

pub fn cost_call(method_name_size: u64, payload_size: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    unsafe {
        ic0::cost_call(method_name_size, payload_size, bytes.as_mut_ptr() as u32);
    }
    bytes
}
pub fn cost_create_canister() -> Vec<u8> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    unsafe {
        ic0::cost_create_canister(bytes.as_mut_ptr() as u32);
    }
    bytes
}
pub fn cost_http_request(request_size: u64, max_res_bytes: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    unsafe {
        ic0::cost_http_request(request_size, max_res_bytes, bytes.as_mut_ptr() as u32);
    }
    bytes
}
pub fn cost_http_request_v2(data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    unsafe {
        ic0::cost_http_request_v2(
            data.as_ptr() as u32,
            data.len() as u32,
            bytes.as_mut_ptr() as u32,
        );
    }
    bytes
}
pub fn cost_sign_with_ecdsa(data: &[u8], ecdsa_curve: u32) -> Result<Vec<u8>, u32> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    let result = unsafe {
        ic0::cost_sign_with_ecdsa(
            data.as_ptr() as u32,
            data.len() as u32,
            ecdsa_curve,
            bytes.as_mut_ptr() as u32,
        )
    };
    if result == 0 { Ok(bytes) } else { Err(result) }
}
pub fn cost_sign_with_schnorr(data: &[u8], algorithm: u32) -> Result<Vec<u8>, u32> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    let result = unsafe {
        ic0::cost_sign_with_schnorr(
            data.as_ptr() as u32,
            data.len() as u32,
            algorithm,
            bytes.as_mut_ptr() as u32,
        )
    };
    if result == 0 { Ok(bytes) } else { Err(result) }
}
pub fn cost_vetkd_derive_key(data: &[u8], vetkd_curve: u32) -> Result<Vec<u8>, u32> {
    let mut bytes = vec![0u8; CYCLES_SIZE];
    let result = unsafe {
        ic0::cost_vetkd_derive_key(
            data.as_ptr() as u32,
            data.len() as u32,
            vetkd_curve,
            bytes.as_mut_ptr() as u32,
        )
    };
    if result == 0 { Ok(bytes) } else { Err(result) }
}

use std::panic;

pub fn set_panic_hook() {
    panic::set_hook(Box::new(|i| {
        let s = i.to_string();
        trap_with(&s);
    }));
}
