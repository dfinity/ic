//! Bindings to the [Internet Computer system API](https://internetcomputer.org/docs/current/references/ic-interface-spec#system-api-imports).
//!
//! The raw bindings can be found in the [`sys`] module. The functions in the crate root provide slightly higher-level
//! bindings in terms of slices instead of pointers/lengths, accurately typed pointers, etc., but otherwise does not adapt
//! the API. Where this is all that is needed for the functions to be safe, they are marked as safe, but function pointers
//! cannot be made safe and as such `call_new` is still unsafe.
//!
//! Any function `ic0.foo` that would write to a user buffer has two versions, `foo` which takes `&mut [u8]` and
//! `foo_uninit` which takes `&mut [MaybeUninit<u8>]`.

#![warn(
    elided_lifetimes_in_paths,
    missing_debug_implementations,
    unsafe_op_in_unsafe_fn,
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc
)]

use std::mem::MaybeUninit;

pub mod sys;

#[inline]
pub fn msg_arg_data_size() -> usize {
    // SAFETY: ic0.msg_arg_data_size is always safe to call
    unsafe { sys::msg_arg_data_size() }
}

#[inline]
pub fn msg_arg_data_copy(dst: &mut [u8], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.msg_arg_data_copy
    // The offset parameter does not affect safety
    unsafe { sys::msg_arg_data_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

/// # Safety
///
/// This function will fully initialize `dst` (or trap if it cannot).
#[inline]
pub fn msg_arg_data_copy_uninit(dst: &mut [MaybeUninit<u8>], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.msg_arg_data_copy
    // The offset parameter does not affect safety
    unsafe { sys::msg_arg_data_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

#[inline]
pub fn msg_caller_size() -> usize {
    // SAFETY: ic0.msg_caller_size is always safe to call
    unsafe { sys::msg_caller_size() }
}

#[inline]
pub fn msg_caller_copy(dst: &mut [u8], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.msg_caller_copy
    // The offset parameter does not affect safety
    unsafe { sys::msg_caller_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

/// # Safety
///
/// This function will fully initialize `dst` (or trap if it cannot).
#[inline]
pub fn msg_caller_copy_uninit(dst: &mut [MaybeUninit<u8>], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.msg_caller_copy
    // The offset parameter does not affect safety
    unsafe { sys::msg_caller_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

#[inline]
pub fn msg_reject_code() -> u32 {
    // SAFETY: ic0.msg_reject_code is always safe to call
    unsafe { sys::msg_reject_code() }
}

#[inline]
pub fn msg_reject_msg_size() -> usize {
    // SAFETY: ic0.msg_reject_msg_size is always safe to call
    unsafe { sys::msg_reject_msg_size() }
}

#[inline]
pub fn msg_reject_msg_copy(dst: &mut [u8], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.msg_reject_msg_copy
    // The offset parameter does not affect safety
    unsafe { sys::msg_reject_msg_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

/// # Safety
///
/// This function will fully initialize `dst` (or trap if it cannot).
#[inline]
pub fn msg_reject_msg_copy_uninit(dst: &mut [MaybeUninit<u8>], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.msg_reject_msg_copy
    // The offset parameter does not affect safety
    unsafe { sys::msg_reject_msg_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

#[inline]
pub fn msg_deadline() -> u64 {
    // SAFETY: ic0.msg_deadline is always safe to call
    unsafe { sys::msg_deadline() }
}

#[inline]
pub fn msg_reply_data_append(data: &[u8]) {
    // SAFETY: data is a readable sequence of bytes and therefore safe to pass as ptr and len to ic0.msg_reply_data_append
    unsafe { sys::msg_reply_data_append(data.as_ptr() as usize, data.len()) }
}

#[inline]
pub fn msg_reply() {
    // SAFETY: ic0.msg_reply is always safe to call
    unsafe { sys::msg_reply() }
}

#[inline]
pub fn msg_reject(message: &[u8]) {
    // SAFETY: message is a readable sequence of bytes and therefore safe to pass as ptr and len to ic0.msg_reject
    unsafe { sys::msg_reject(message.as_ptr() as usize, message.len()) }
}

#[inline]
pub fn msg_cycles_available128() -> u128 {
    let mut dst_bytes = [0_u8; 16];
    // SAFETY: dst_bytes is a writable sequence of 16 bytes and therefore safe to pass as ptr to ic0.msg_cycles_available128
    unsafe {
        sys::msg_cycles_available128(dst_bytes.as_mut_ptr() as usize);
    }
    u128::from_le_bytes(dst_bytes)
}

#[inline]
pub fn msg_cycles_refunded128() -> u128 {
    let mut dst_bytes = [0_u8; 16];
    // SAFETY: dst_bytes is a writable sequence of 16 bytes and therefore safe to pass as ptr to ic0.msg_cycles_refunded128
    unsafe {
        sys::msg_cycles_refunded128(dst_bytes.as_mut_ptr() as usize);
    }
    u128::from_le_bytes(dst_bytes)
}

#[inline]
pub fn msg_cycles_accept128(max: u128) -> u128 {
    let (high, low) = to_high_low(max);
    let mut dst_bytes = [0_u8; 16];
    // SAFETY: dst_bytes is a writable sequence of 16 bytes and therefore safe to pass as ptr to ic0.msg_cycles_accept128
    // The max_amount_high and max_amount_low parameters do not affect safety
    unsafe {
        sys::msg_cycles_accept128(high, low, dst_bytes.as_mut_ptr() as usize);
    }
    u128::from_le_bytes(dst_bytes)
}

#[inline]
pub fn cycles_burn128(amount: u128) -> u128 {
    let (high, low) = to_high_low(amount);
    let mut dst_bytes = [0_u8; 16];
    // SAFETY: dst_bytes is a writable sequence of 16 bytes and therefore safe to pass to ic0.cycles_burn128
    // The amount_high and amount_low parameters do not affect safety
    unsafe {
        sys::cycles_burn128(high, low, dst_bytes.as_mut_ptr() as usize);
    }
    u128::from_le_bytes(dst_bytes)
}

#[inline]
pub fn canister_self_size() -> usize {
    // SAFETY: ic0.canister_self_size is always safe to call
    unsafe { sys::canister_self_size() }
}

#[inline]
pub fn canister_self_copy(dst: &mut [u8], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass to ic0.canister_self_copy
    // The offset parameter does not affect safety
    unsafe { sys::canister_self_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

#[inline]
pub fn canister_cycle_balance128() -> u128 {
    let mut dst_bytes = [0_u8; 16];
    // SAFETY: dst_bytes is a writable sequence of 16 bytes and therefore safe to pass to ic0.canister_cycle_balance128
    unsafe {
        sys::canister_cycle_balance128(dst_bytes.as_mut_ptr() as usize);
    }
    u128::from_le_bytes(dst_bytes)
}

#[inline]
pub fn canister_liquid_cycle_balance128() -> u128 {
    let mut dst_bytes = [0_u8; 16];
    // SAFETY: dst_bytes is a writable sequence of 16 bytes and therefore safe to pass to ic0.canister_liquid_cycle_balance128
    unsafe {
        sys::canister_liquid_cycle_balance128(dst_bytes.as_mut_ptr() as usize);
    }
    u128::from_le_bytes(dst_bytes)
}

#[inline]
pub fn canister_status() -> u32 {
    // SAFETY: ic0.canister_status is always safe to call.
    unsafe { sys::canister_status() }
}

#[inline]
pub fn canister_version() -> u64 {
    // SAFETY: ic0.canister_version is always safe to call.
    unsafe { sys::canister_version() }
}

#[inline]
pub fn subnet_self_size() -> usize {
    // SAFETY: ic0.subnet_self_size is always safe to call.
    unsafe { sys::subnet_self_size() }
}

#[inline]
pub fn subnet_self_copy(dst: &mut [u8], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.subnet_self_copy
    // The offset parameter does not affect safety
    unsafe { sys::subnet_self_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

/// # Safety
///
/// This function will fully initialize `dst` (or trap if it cannot).
#[inline]
pub fn subnet_self_copy_uninit(dst: &mut [MaybeUninit<u8>], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.subnet_self_copy
    // The offset parameter does not affect safety
    unsafe { sys::subnet_self_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

#[inline]
pub fn msg_method_name_size() -> usize {
    // SAFETY: ic0.msg_method_name_size is always safe to call
    unsafe { sys::msg_method_name_size() }
}

#[inline]
pub fn msg_method_name_copy(dst: &mut [u8], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.msg_method_name_copy
    // The offset parameter does not affect safety
    unsafe { sys::msg_method_name_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

/// # Safety
///
/// This function will fully initialize `dst` (or trap if it cannot).
#[inline]
pub fn msg_method_name_copy_uninit(dst: &mut [MaybeUninit<u8>], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.msg_method_name_copy
    // The offset parameter does not affect safety
    unsafe { sys::msg_method_name_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

#[inline]
pub fn accept_message() {
    // SAFETY: ic0.accept_message is always safe to call
    unsafe { sys::accept_message() }
}

/// # Safety
///
/// - `reply_fn` is required to be safely callable as a canister entrypoint with `reply_env`.
/// - `reject_fn` is required to be safely callable as a canister entrypoint with `reject_env`.
/// - Ownership of `reply_env` and `reject_env` is acquired by this function.
/// - `reply_fn`, if called, will receive ownership of `reply_env`, `reject_env`, and [`cleanup_env`](call_on_cleanup).
/// - `reject_fn`, if called, will receive ownership of `reply_env`, `reject_env`, and [`cleanup_env`](call_on_cleanup).
#[inline]
pub unsafe fn call_new(
    callee: &[u8],
    name: &str,
    reply_fn: unsafe extern "C" fn(env: usize),
    reply_env: usize,
    reject_fn: unsafe extern "C" fn(env: usize),
    reject_env: usize,
) {
    // SAFETY:
    // - callee, being &[u8], is a readable sequence of bytes and therefore safe to pass as ptr and len
    //   as the callee in ic0.call_new
    // - name is a readable string and therefore safe to pass as ptr and len as the name in ic0.call_new
    // - reply_fn is a function with signature (env : usize) -> () and required to be a safe entrypoint if reply_env is used
    //   as the env, and is therefore safe to pass as the reply fn for ic0.call_new if reply_env is passed as the reply env
    // - reply_env is the correct env parameter for reply_fn
    // - reject_fn is a function with signature (env : usize) -> () and required to be a safe entrypoint if reject_env is used
    //   as the env, and is therefore safe to pass as the reject fn for ic0.call_new if reject_env is passed as the reject env
    // - reject_env is the correct env parameter for reject_fn
    unsafe {
        sys::call_new(
            callee.as_ptr() as usize,
            callee.len(),
            name.as_ptr() as usize,
            name.len(),
            reply_fn as usize,
            reply_env,
            reject_fn as usize,
            reject_env,
        );
    }
}

#[inline]
pub fn call_new_oneway(callee: &[u8], name: &str) {
    // SAFETY:
    // - callee, being &[u8], is a readable sequence of bytes and therefore safe to pass as ptr and len
    //   as the callee in ic0.call_new
    // - name is a readable string and therefore safe to pass as ptr and len as the name in ic0.call_new
    // - `usize::MAX` is a function pointer the wasm module cannot possibly contain and is therefore safe to pass as
    //   `reply_fun` and `reject_fun` to ic0.call_new
    // - When the `reply_fun` and `reject_fun` functions do not exist and therefore will never be called, any value
    //   is safe to pass as `reply_env` and `reject_env` to `ic0.call_new`
    //
    // See https://www.joachim-breitner.de/blog/789-Zero-downtime_upgrades_of_Internet_Computer_canisters#one-way-calls for more context.
    unsafe {
        sys::call_new(
            callee.as_ptr() as usize,
            callee.len(),
            name.as_ptr() as usize,
            name.len(),
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
        );
    }
}

/// # Safety
///
/// - `cleanup_fn` is required to be safely callable as a canister entrypoint with `cleanup_env`.
/// - Ownership of `cleanup_env` is acquired by this function.
/// - `cleanup_fn`, if called, will receive ownership of `cleanup_env`, [`reply_env`](call_new), and [`reject_env`](call_new)
#[inline]
pub unsafe fn call_on_cleanup(cleanup_fn: unsafe extern "C" fn(env: usize), cleanup_env: usize) {
    // SAFETY:
    // - cleanup_fn is a function with signature (env : usize) -> () and required to be a safe entrypoint if cleanup_env is used
    //   as the env, and is therefore safe to pass as the fn for ic0.call_on_cleanup if cleanup_env is passed as the env
    // - cleanup_env is the correct env parameter for cleanup_fn
    unsafe {
        sys::call_on_cleanup(cleanup_fn as usize, cleanup_env);
    }
}

#[inline]
pub fn call_data_append(data: &[u8]) {
    // SAFETY: data is a readable sequence of bytes and therefore safe to pass as ptr and len to ic0.call_data_append
    unsafe { sys::call_data_append(data.as_ptr() as usize, data.len()) }
}

#[inline]
pub fn call_with_best_effort_response(timeout_seconds: u32) {
    // SAFETY: ic0.call_with_best_effort_response is always safe to call
    unsafe { sys::call_with_best_effort_response(timeout_seconds) }
}

#[inline]
pub fn call_cycles_add128(amount: u128) {
    let (high, low) = to_high_low(amount);
    // SAFETY: ic0.call_cycles_add128 is always safe to call
    unsafe { sys::call_cycles_add128(high, low) }
}

/// # Safety
///
/// If `call_perform` returns a nonzero value, the ownership of [`reply_env`](call_new), [`reject_env`](call_new), and
/// [`cleanup_env`](call_on_cleanup) is released to the caller.
///
/// If `call_perform` returns 0, then (from the perspective of safety, *not* semantics) exactly one of
/// [`reply_fn`](call_new), [`reject_fn`](call_new), or [`cleanup_fn`](call_on_cleanup) will be called, exactly once.
#[inline]
pub fn call_perform() -> u32 {
    // SAFETY: ic0.call_perform is always safe to call
    unsafe { sys::call_perform() }
}

#[inline]
pub fn stable64_size() -> u64 {
    // SAFETY: ic0.stable64_size is always safe to call
    unsafe { sys::stable64_size() }
}

#[inline]
pub fn stable64_grow(new_pages: u64) -> u64 {
    // SAFETY: ic0.stable64_grow is always safe to call
    unsafe { sys::stable64_grow(new_pages) }
}

#[inline]
pub fn stable64_write(data: &[u8], offset: u64) {
    // SAFETY: data is a readable sequence of bytes and therefore is safe to pass as ptr and len to ic0.stable64_write
    // The offset parameter does not affect safety
    unsafe { sys::stable64_write(offset, data.as_ptr() as usize as u64, data.len() as u64) }
}

#[inline]
pub fn stable64_read(dst: &mut [u8], offset: u64) {
    // SAFETY: dst is a writable sequence of bytes and therefore is safe to pass as ptr and len to ic0.stable64_read
    // The offset parameter does not affect safety
    unsafe { sys::stable64_read(dst.as_mut_ptr() as usize as u64, offset, dst.len() as u64) }
}

/// # Safety
///
/// This function will fully initialize `dst` (or trap if it cannot).
#[inline]
pub fn stable64_read_uninit(dst: &mut [MaybeUninit<u8>], offset: u64) {
    // SAFETY: dst is a writable sequence of bytes and therefore is safe to pass as ptr and len to ic0.stable64_read
    // The offset parameter does not affect safety
    unsafe { sys::stable64_read(dst.as_mut_ptr() as usize as u64, offset, dst.len() as u64) }
}

#[inline]
pub fn root_key_size() -> usize {
    // SAFETY: ic0.root_key_size is always safe to call
    unsafe { sys::root_key_size() }
}

#[inline]
pub fn root_key_copy(dst: &mut [u8], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.root_key_copy
    // The offset parameter does not affect safety
    unsafe { sys::root_key_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

/// # Safety
///
/// This function will fully initialize `dst` (or trap if it cannot).
#[inline]
pub fn root_key_copy_uninit(dst: &mut [MaybeUninit<u8>], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.root_key_copy
    // The offset parameter does not affect safety
    unsafe { sys::root_key_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

#[inline]
pub fn certified_data_set(data: &[u8]) {
    // SAFETY: data is a readable sequence of bytes and therefore safe to pass as ptr and len to ic0.certified_data_set
    unsafe { sys::certified_data_set(data.as_ptr() as usize, data.len()) }
}

#[inline]
pub fn data_certificate_present() -> u32 {
    // SAFETY: ic0.data_certificate_present is always safe to call
    unsafe { sys::data_certificate_present() }
}

#[inline]
pub fn data_certificate_size() -> usize {
    // SAFETY: ic0.data_certificate_size is always safe to call
    unsafe { sys::data_certificate_size() }
}

#[inline]
pub fn data_certificate_copy(dst: &mut [u8], offset: usize) {
    // SAFETY: dst, being &mut [u8], is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.data_certificate_copy
    // The offset parameter does not affect safety
    unsafe { sys::data_certificate_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

/// # Safety
///
/// This function will fully initialize `dst` (or trap if it cannot).
#[inline]
pub fn data_certificate_copy_uninit(dst: &mut [MaybeUninit<u8>], offset: usize) {
    // SAFETY: dst, being &mut [u8], is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.data_certificate_copy
    // The offset parameter does not affect safety
    unsafe { sys::data_certificate_copy(dst.as_mut_ptr() as usize, offset, dst.len()) }
}

#[inline]
pub fn time() -> u64 {
    // SAFETY: ic0.time is always safe to call
    unsafe { sys::time() }
}

#[inline]
pub fn global_timer_set(timestamp: u64) -> u64 {
    // SAFETY: ic0.global_timer_set is always safe to call
    unsafe { sys::global_timer_set(timestamp) }
}

#[inline]
pub fn performance_counter(counter_type: u32) -> u64 {
    // SAFETY: ic0.performance_counter is always safe to call
    unsafe { sys::performance_counter(counter_type) }
}

#[inline]
pub fn is_controller(principal: &[u8]) -> u32 {
    // SAFETY: principal is a readable sequence of bytes and therefore safe to pass as ptr and len to ic0.is_controller
    unsafe { sys::is_controller(principal.as_ptr() as usize, principal.len()) }
}

#[inline]
pub fn in_replicated_execution() -> u32 {
    // SAFETY: ic0.in_replicated_execution is always safe to call
    unsafe { sys::in_replicated_execution() }
}

#[inline]
pub fn cost_call(method_name_size: u64, payload_size: u64) -> u128 {
    let mut dst_bytes = [0_u8; 16];
    // SAFETY: dst_bytes is a writable sequence of 16 bytes and therefore safe to pass as ptr to ic0.cost_call
    // The method_name_size and payload_size parameters do not affect safety
    unsafe {
        sys::cost_call(
            method_name_size,
            payload_size,
            dst_bytes.as_mut_ptr() as usize,
        );
    }
    u128::from_le_bytes(dst_bytes)
}

#[inline]
pub fn cost_create_canister() -> u128 {
    let mut dst_bytes = [0_u8; 16];
    // SAFETY: dst_bytes is a writable sequence of 16 bytes and therefore safe to pass as ptr to ic0.cost_create_canister
    unsafe {
        sys::cost_create_canister(dst_bytes.as_mut_ptr() as usize);
    }
    u128::from_le_bytes(dst_bytes)
}

#[inline]
pub fn cost_http_request(request_size: u64, max_res_bytes: u64) -> u128 {
    let mut dst_bytes = [0_u8; 16];
    // SAFETY: dst_bytes is a writable sequence of 16 bytes and therefore safe to pass as ptr to ic0.cost_http_request
    // The request_size and max_res_bytes parameters do not affect safety
    unsafe {
        sys::cost_http_request(request_size, max_res_bytes, dst_bytes.as_mut_ptr() as usize);
    }
    u128::from_le_bytes(dst_bytes)
}

#[inline]
pub fn cost_sign_with_ecdsa(key_name: &str, ecdsa_curve: u32) -> (u128, u32) {
    let mut dst_bytes = [0_u8; 16];
    // SAFETY:
    // - key_name is a readable string and therefore safe to pass as ptr and len src to ic0.cost_sign_with_ecdsa
    // - dst_bytes is a writable sequence of 16 bytes and therefore safe to pass as ptr dst to ic0.cost_sign_with_ecdsa
    // The ecdsa_curve parameter does not affect safety
    let code = unsafe {
        sys::cost_sign_with_ecdsa(
            key_name.as_ptr() as usize,
            key_name.len(),
            ecdsa_curve,
            dst_bytes.as_mut_ptr() as usize,
        )
    };
    (u128::from_le_bytes(dst_bytes), code)
}

#[inline]
pub fn cost_sign_with_schnorr(key_name: &str, algorithm: u32) -> (u128, u32) {
    let mut dst_bytes = [0_u8; 16];
    // SAFETY:
    // - key_name is a readable string and therefore safe to pass as ptr and len src to ic0.cost_sign_with_schnorr
    // - dst_bytes is a writable sequence of 16 bytes and therefore safe to pass as ptr dst to ic0.cost_sign_with_schnorr
    // The algorithm parameter does not affect safety
    let code = unsafe {
        sys::cost_sign_with_schnorr(
            key_name.as_ptr() as usize,
            key_name.len(),
            algorithm,
            dst_bytes.as_mut_ptr() as usize,
        )
    };
    (u128::from_le_bytes(dst_bytes), code)
}

#[inline]
pub fn cost_vetkd_derive_key(key_name: &str, vetkd_curve: u32) -> (u128, u32) {
    let mut dst_bytes = [0_u8; 16];
    // SAFETY:
    // - key_name is a readable string and therefore safe to pass as ptr and len path to ic0.cost_vetkd_derive_key
    // - dst_bytes is a writable sequence of 16 bytes and therefore safe to pass as ptr dst to ic0.cost_vetkd_derive_key
    // The vetkd_curve parameter does not affect safety
    let code = unsafe {
        sys::cost_vetkd_derive_key(
            key_name.as_ptr() as usize,
            key_name.len(),
            vetkd_curve,
            dst_bytes.as_mut_ptr() as usize,
        )
    };
    (u128::from_le_bytes(dst_bytes), code)
}

#[inline]
pub fn env_var_count() -> usize {
    // SAFETY: ic0.env_var_count is always safe to call
    unsafe { sys::env_var_count() }
}

#[inline]
pub fn env_var_name_size(index: usize) -> usize {
    // SAFETY: ic0.env_var_name_size is always safe to call
    unsafe { sys::env_var_name_size(index) }
}

#[inline]
pub fn env_var_name_copy(index: usize, dst: &mut [u8], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.env_var_name_copy
    unsafe { sys::env_var_name_copy(index, dst.as_mut_ptr() as usize, offset, dst.len()) }
}

/// # Safety
///
/// This function will fully initialize `dst` (or trap if it cannot).
#[inline]
pub fn env_var_name_copy_uninit(index: usize, dst: &mut [MaybeUninit<u8>], offset: usize) {
    // SAFETY: dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.env_var_name_copy
    unsafe { sys::env_var_name_copy(index, dst.as_mut_ptr() as usize, offset, dst.len()) }
}

#[inline]
pub fn env_var_name_exists(name: &str) -> u32 {
    // SAFETY: name is a readable string and therefore safe to pass as ptr and len to ic0.env_var_name_exists
    unsafe { sys::env_var_name_exists(name.as_ptr() as usize, name.len()) }
}

#[inline]
pub fn env_var_value_size(name: &str) -> usize {
    // SAFETY: name is a readable string and therefore safe to pass as ptr and len to ic0.env_var_value_size
    unsafe { sys::env_var_value_size(name.as_ptr() as usize, name.len()) }
}

#[inline]
pub fn env_var_value_copy(name: &str, dst: &mut [u8], offset: usize) {
    // SAFETY:
    // - name is a readable string and therefore safe to pass as ptr and len to ic0.env_var_value_copy
    // - dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.env_var_value_copy
    unsafe {
        sys::env_var_value_copy(
            name.as_ptr() as usize,
            name.len(),
            dst.as_mut_ptr() as usize,
            offset,
            dst.len(),
        )
    }
}

/// # Safety
///
/// This function will fully initialize `dst` (or trap if it cannot).
#[inline]
pub fn env_var_value_copy_uninit(name: &str, dst: &mut [MaybeUninit<u8>], offset: usize) {
    // SAFETY:
    // - name is a readable string and therefore safe to pass as ptr and len to ic0.env_var_value_copy
    // - dst is a writable sequence of bytes and therefore safe to pass as ptr and len to ic0.env_var_value_copy
    unsafe {
        sys::env_var_value_copy(
            name.as_ptr() as usize,
            name.len(),
            dst.as_mut_ptr() as usize,
            offset,
            dst.len(),
        )
    }
}

#[inline]
pub fn debug_print(message: &[u8]) {
    // SAFETY: message is a readable sequence of bytes and therefore safe to pass as ptr and len to ic0.debug_print
    unsafe { sys::debug_print(message.as_ptr() as usize, message.len()) }
}

#[inline]
pub fn trap(message: &[u8]) -> ! {
    // SAFETY: message is a readable sequence of bytes and therefore safe to pass as ptr and len to ic0.trap
    unsafe { sys::trap(message.as_ptr() as usize, message.len()) }
    unreachable!("trap should halt execution immediately")
}

#[inline]
fn to_high_low(x: u128) -> (u64, u64) {
    let high = (x >> 64) as u64;
    let low = (x & u128::from(u64::MAX)) as u64;
    (high, low)
}
