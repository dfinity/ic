//! System API bindings.
//!
//! This module provides Rust ergonomic bindings to the system APIs.
//!
//! Some APIs require more advanced handling and are organized into separate modules:
//! * For the inter-canister calls API, see the [`call`](mod@crate::call) module.
//! * For the stable memory management API, see the .
//!   * The basic bindings are provided in this module including [`stable_size`], [`stable_grow`], [`stable_read`] and [`stable_write`].
//!   * The [`stable`](crate::stable) module provides more advanced functionalities, e.g. support for `std::io` traits.
//!
//! APIs that are only available for `wasm32` are not included.
//! As a result, system APIs with a numeric postfix (indicating the data bit width) are bound to names without the postfix.
//! For example, `ic0::msg_cycles_available128` is bound to [`msg_cycles_available`], while `ic0::msg_cycles_available` has no binding.
//!
//! Functions that provide bindings for a single system API method share the same name as the system API.
//! For example, `ic0::msg_reject_code` is bound to [`msg_reject_code`].
//!
//! Functions that wrap multiple system API methods are named using the common prefix of the wrapped methods.
//! For example, [`msg_arg_data`] wraps both `ic0::msg_arg_data_size` and `ic0::msg_arg_data_copy`.

use candid::Principal;
use std::{convert::TryFrom, num::NonZeroU64};

#[deprecated(
    since = "0.18.0",
    note = "The `api::call` module is deprecated. Individual items within this module have their own deprecation notices with specific migration guidance."
)]
#[doc(hidden)]
pub mod call;
#[deprecated(
    since = "0.18.0",
    note = "The `api::management_canister` module is deprecated. Please use the `management_canister` and `bitcoin_canister` modules at the crate root."
)]
#[doc(hidden)]
pub mod management_canister;
#[deprecated(
    since = "0.18.0",
    note = "The `api::stable` module has been moved to `stable` (crate root)."
)]
#[doc(hidden)]
pub mod stable;

/// Gets the message argument data.
pub fn msg_arg_data() -> Vec<u8> {
    let len = ic0::msg_arg_data_size();
    let mut buf = vec![0u8; len];
    ic0::msg_arg_data_copy(&mut buf, 0);
    buf
}

/// Gets the identity of the caller, which may be a canister id or a user id.
///
/// During canister installation or upgrade, this is the id of the user or canister requesting the installation or upgrade.
/// During a system task (heartbeat or global timer), this is the id of the management canister.
pub fn msg_caller() -> Principal {
    let len = ic0::msg_caller_size();
    let mut buf = vec![0u8; len];
    ic0::msg_caller_copy(&mut buf, 0);
    // Trust that the system always returns a valid principal.
    Principal::try_from(&buf).unwrap()
}

/// Returns the reject code, if the current function is invoked as a reject callback.
pub fn msg_reject_code() -> u32 {
    ic0::msg_reject_code()
}

/// Gets the reject message.
///
/// This function can only be called in the reject callback.
///
/// Traps if:
/// - There is no reject message (i.e. if `reject_code` is 0).
/// - The message is not valid UTF-8.
pub fn msg_reject_msg() -> String {
    let len = ic0::msg_reject_msg_size();
    let mut buf = vec![0u8; len];
    ic0::msg_reject_msg_copy(&mut buf, 0);
    String::from_utf8(buf).expect("reject message is not valid UTF-8")
}

/// Gets the deadline, in nanoseconds since 1970-01-01, after which the caller might stop waiting for a response.
///
/// For calls to update methods with best-effort responses and their callbacks,
/// the deadline is computed based on the time the call was made,
/// and the `timeout_seconds` parameter provided by the caller.
/// In such cases, the deadline value will be converted to `NonZeroU64` and wrapped in `Some`.
/// To get the deadline value as a `u64`, call `get()` on the `NonZeroU64` value.
///
/// ```rust,no_run
/// use ic_cdk::api::msg_deadline;
/// if let Some(deadline) = msg_deadline() {
///     let deadline_value : u64 = deadline.get();
/// }
/// ```
///
/// For other calls (ingress messages and all calls to query and composite query methods,
/// including calls in replicated mode), a `None` is returned.
/// Please note that the raw `msg_deadline` system API returns 0 in such cases.
/// This function is a wrapper around the raw system API that provides more semantic information through the return type.
pub fn msg_deadline() -> Option<NonZeroU64> {
    let nano_seconds = ic0::msg_deadline();
    match nano_seconds {
        0 => None,
        _ => Some(NonZeroU64::new(nano_seconds).unwrap()),
    }
}

/// Replies to the sender with the data.
pub fn msg_reply<T: AsRef<[u8]>>(data: T) {
    let buf = data.as_ref();
    if !buf.is_empty() {
        ic0::msg_reply_data_append(buf);
    }
    ic0::msg_reply();
}

/// Rejects the call with a diagnostic message.
pub fn msg_reject<T: AsRef<str>>(message: T) {
    let message = message.as_ref();
    ic0::msg_reject(message.as_bytes());
}

/// Gets the number of cycles transferred by the caller of the current call, still available in this message.
pub fn msg_cycles_available() -> u128 {
    ic0::msg_cycles_available128()
}

/// Gets the amount of cycles that came back with the response as a refund
///
/// This function can only be used in a callback handler (reply or reject).
/// The refund has already been added to the canister balance automatically.
pub fn msg_cycles_refunded() -> u128 {
    ic0::msg_cycles_refunded128()
}

/// Moves cycles from the call to the canister balance.
///
/// The actual amount moved will be returned.
pub fn msg_cycles_accept(max_amount: u128) -> u128 {
    ic0::msg_cycles_accept128(max_amount)
}

/// Burns cycles from the canister.
///
/// Returns the amount of cycles that were actually burned.
pub fn cycles_burn(amount: u128) -> u128 {
    ic0::cycles_burn128(amount)
}

/// Gets canister's own identity.
pub fn canister_self() -> Principal {
    let len = ic0::canister_self_size();
    let mut buf = vec![0u8; len];
    ic0::canister_self_copy(&mut buf, 0);
    // Trust that the system always returns a valid principal.
    Principal::try_from(&buf).unwrap()
}

/// Gets the current cycle balance of the canister.
pub fn canister_cycle_balance() -> u128 {
    ic0::canister_cycle_balance128()
}

/// Gets the current amount of cycles that is available for spending in calls and execution.
pub fn canister_liquid_cycle_balance() -> u128 {
    ic0::canister_liquid_cycle_balance128()
}

/// Gets the status of the canister.
///
/// The status is one of the following:
/// - 1: Running
/// - 2: Stopping
/// - 3: Stopped
pub fn canister_status() -> CanisterStatusCode {
    ic0::canister_status().into()
}

/// The status of a canister.
///
/// See [Canister status](https://internetcomputer.org/docs/current/references/ic-interface-spec/#system-api-canister-status).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum CanisterStatusCode {
    /// Running.
    Running = 1,
    /// Stopping.
    Stopping = 2,
    /// Stopped.
    Stopped = 3,
    /// A status code that is not recognized by this library.
    Unrecognized(u32),
}

impl From<u32> for CanisterStatusCode {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::Running,
            2 => Self::Stopping,
            3 => Self::Stopped,
            _ => Self::Unrecognized(value),
        }
    }
}

impl From<CanisterStatusCode> for u32 {
    fn from(value: CanisterStatusCode) -> Self {
        match value {
            CanisterStatusCode::Running => 1,
            CanisterStatusCode::Stopping => 2,
            CanisterStatusCode::Stopped => 3,
            CanisterStatusCode::Unrecognized(value) => value,
        }
    }
}

impl PartialEq<u32> for CanisterStatusCode {
    fn eq(&self, other: &u32) -> bool {
        let self_as_u32: u32 = (*self).into();
        self_as_u32 == *other
    }
}

/// Gets the canister version.
///
/// See [Canister version](https://internetcomputer.org/docs/current/references/ic-interface-spec/#system-api-canister-version).
pub fn canister_version() -> u64 {
    ic0::canister_version()
}

/// Gets the ID of the subnet on which the canister is running.
pub fn subnet_self() -> Principal {
    let len = ic0::subnet_self_size();
    let mut buf = vec![0u8; len];
    ic0::subnet_self_copy(&mut buf, 0);
    // Trust that the system always returns a valid principal.
    Principal::try_from(&buf).unwrap()
}

/// Gets the name of the method to be inspected.
///
/// This function is only available in the `canister_inspect_message` context.
///
/// Traps if the method name is not valid UTF-8.
pub fn msg_method_name() -> String {
    let len = ic0::msg_method_name_size();
    let mut buf = vec![0u8; len];
    ic0::msg_method_name_copy(&mut buf, 0);
    String::from_utf8(buf).expect("msg_method_name is not valid UTF-8")
}

/// Accepts the message in `canister_inspect_message`.
///
/// This function is only available in the `canister_inspect_message` context.
/// This function traps if invoked twice.
pub fn accept_message() {
    ic0::accept_message();
}

/// Gets the current size of the stable memory (in WebAssembly pages).
///
/// One WebAssembly page is 64KiB.
pub fn stable_size() -> u64 {
    ic0::stable64_size()
}

/// Attempts to grow the stable memory by `new_pages` many pages containing zeroes.
///
/// One WebAssembly page is 64KiB.
///
/// If successful, returns the previous size of the memory (in pages).
/// Otherwise, returns `u64::MAX`.
pub fn stable_grow(new_pages: u64) -> u64 {
    ic0::stable64_grow(new_pages)
}

/// Writes data to the stable memory location specified by an offset.
///
/// # Warning
/// This will panic if `offset + buf.len()` exceeds the current size of stable memory.
/// Call [`stable_grow`] to request more stable memory if needed.
pub fn stable_write(offset: u64, buf: &[u8]) {
    ic0::stable64_write(buf, offset);
}

/// Reads data from the stable memory location specified by an offset.
///
/// # Warning
/// This will panic if `offset + buf.len()` exceeds the current size of stable memory.
pub fn stable_read(offset: u64, buf: &mut [u8]) {
    ic0::stable64_read(buf, offset);
}

/// Gets the public key (a DER-encoded BLS key) of the root key of this instance of the Internet Computer Protocol.
///
/// # Note
///
/// This traps in non-replicated mode.
pub fn root_key() -> Vec<u8> {
    let len = ic0::root_key_size();
    let mut buf = vec![0u8; len];
    ic0::root_key_copy(&mut buf, 0);
    buf
}

/// Sets the certified data of this canister.
///
/// Canisters can store up to 32 bytes of data that is certified by
/// the system on a regular basis.  One can call [`data_certificate`]
/// function from a query call to get a certificate authenticating the
/// value set by calling this function.
///
/// This function can only be called from the following contexts:
/// - `canister_init`, `canister_pre_upgrade` and `canister_post_upgrade`
///   hooks.
/// - `canister_update` calls.
/// - reply or reject callbacks.
///
/// # Panics
///
/// - This function traps if `data.len() > 32`.
/// - This function traps if it's called from an illegal context
///   (e.g., from a query call).
pub fn certified_data_set<T: AsRef<[u8]>>(data: T) {
    let buf = data.as_ref();
    ic0::certified_data_set(buf);
}

/// When called from a query call, returns the data certificate authenticating
/// certified data set by this canister.
///
/// Returns `None` if called not from a query call.
pub fn data_certificate() -> Option<Vec<u8>> {
    if ic0::data_certificate_present() == 0 {
        return None;
    }
    let n = ic0::data_certificate_size();
    let mut buf = vec![0u8; n];
    ic0::data_certificate_copy(&mut buf, 0);
    Some(buf)
}

/// Gets current timestamp, in nanoseconds since the epoch (1970-01-01)
pub fn time() -> u64 {
    ic0::time()
}

/// Sets global timer.
///
/// The canister can set a global timer to make the system
/// schedule a call to the exported `canister_global_timer`
/// Wasm method after the specified time.
/// The time must be provided as nanoseconds since 1970-01-01.
///
/// The function returns the previous value of the timer.
/// If no timer is set before invoking the function, then the function returns zero.
///
/// Passing zero as an argument to the function deactivates the timer and thus
/// prevents the system from scheduling calls to the canister's `canister_global_timer` Wasm method.
pub fn global_timer_set(timestamp: u64) -> u64 {
    ic0::global_timer_set(timestamp)
}

/// Gets the value of specified performance counter.
///
/// See [`PerformanceCounterType`] for available counter types.
#[inline]
pub fn performance_counter(counter_type: impl Into<PerformanceCounterType>) -> u64 {
    let counter_type: u32 = counter_type.into().into();
    ic0::performance_counter(counter_type)
}

/// The type of performance counter.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
pub enum PerformanceCounterType {
    /// Current execution instruction counter.
    ///
    /// The number of WebAssembly instructions the canister has executed
    /// since the beginning of the current Message execution.
    InstructionCounter,
    /// Call context instruction counter
    ///
    /// The number of WebAssembly instructions the canister has executed
    /// within the call context of the current Message execution
    /// since Call context creation.
    /// The counter monotonically increases across all message executions
    /// in the call context until the corresponding call context is removed.
    CallContextInstructionCounter,
    /// A performance counter type that is not recognized by this library.
    Unrecognized(u32),
}

impl From<u32> for PerformanceCounterType {
    fn from(value: u32) -> Self {
        match value {
            0 => Self::InstructionCounter,
            1 => Self::CallContextInstructionCounter,
            _ => Self::Unrecognized(value),
        }
    }
}

impl From<PerformanceCounterType> for u32 {
    fn from(value: PerformanceCounterType) -> Self {
        match value {
            PerformanceCounterType::InstructionCounter => 0,
            PerformanceCounterType::CallContextInstructionCounter => 1,
            PerformanceCounterType::Unrecognized(value) => value,
        }
    }
}

impl PartialEq<u32> for PerformanceCounterType {
    fn eq(&self, other: &u32) -> bool {
        let self_as_u32: u32 = (*self).into();
        self_as_u32 == *other
    }
}

/// Returns the number of instructions that the canister executed since the last [entry
/// point](https://internetcomputer.org/docs/current/references/ic-interface-spec/#entry-points).
#[inline]
pub fn instruction_counter() -> u64 {
    performance_counter(0)
}

/// Returns the number of WebAssembly instructions the canister has executed
/// within the call context of the current Message execution since
/// Call context creation.
///
/// The counter monotonically increases across all message executions
/// in the call context until the corresponding call context is removed.
#[inline]
pub fn call_context_instruction_counter() -> u64 {
    performance_counter(1)
}

/// Determines if a Principal is a controller of the canister.
pub fn is_controller(principal: &Principal) -> bool {
    let slice = principal.as_slice();
    match ic0::is_controller(slice) {
        0 => false,
        1 => true,
        n => panic!("unexpected return value from is_controller: {n}"),
    }
}

/// Checks if in replicated execution.
///
/// The canister can check whether it is currently running in replicated or non replicated execution.
pub fn in_replicated_execution() -> bool {
    match ic0::in_replicated_execution() {
        0 => false,
        1 => true,
        n => panic!("unexpected return value from in_replicated_execution: {n}"),
    }
}

/// Gets the amount of cycles that a canister needs to be above the freezing threshold in order to successfully make an inter-canister call.
pub fn cost_call(method_name_size: u64, payload_size: u64) -> u128 {
    ic0::cost_call(method_name_size, payload_size)
}

/// Gets the cycle cost of the Management canister method [`creating_canister`](https://internetcomputer.org/docs/references/ic-interface-spec#ic-create_canister).
///
/// # Note
///
/// [`create_canister`](crate::management_canister::create_canister) and
/// [`create_canister_with_extra_cycles`](crate::management_canister::create_canister_with_extra_cycles)
/// invoke this function inside and attach the required cycles to the call.
pub fn cost_create_canister() -> u128 {
    ic0::cost_create_canister()
}

/// Gets the cycle cost of the Management canister method [`http_request`](https://internetcomputer.org/docs/references/ic-interface-spec#ic-http_request).
///
/// # Note
///
/// [`http_request`](crate::management_canister::http_request) and [`http_request_with_closure`](crate::management_canister::http_request_with_closure)
/// invoke this function inside and attach the required cycles to the call.
pub fn cost_http_request(request_size: u64, max_res_bytes: u64) -> u128 {
    ic0::cost_http_request(request_size, max_res_bytes)
}

/// The error type for [`cost_sign_with_ecdsa`] and [`cost_sign_with_schnorr`].
#[derive(thiserror::Error, Debug, Clone)]
pub enum SignCostError {
    /// The ECDSA/vetKD curve or Schnorr algorithm is invalid.
    #[error("invalid curve or algorithm")]
    InvalidCurveOrAlgorithm,

    /// The key name is invalid for the provided curve or algorithm.
    #[error("invalid key name")]
    InvalidKeyName,
    /// Unrecognized error.
    ///
    /// This error is returned when the System API returns an unrecognized error code.
    /// Please report to ic-cdk maintainers.
    #[error("unrecognized error: {0}")]
    UnrecognizedError(u32),
}

/// Helper function to handle the result of a signature cost function.
fn sign_cost_result(dst: u128, code: u32) -> Result<u128, SignCostError> {
    match code {
        0 => Ok(dst),
        1 => Err(SignCostError::InvalidCurveOrAlgorithm),
        2 => Err(SignCostError::InvalidKeyName),
        _ => Err(SignCostError::UnrecognizedError(code)),
    }
}

/// Gets the cycle cost of the Management canister method [`sign_with_ecdsa`](https://internetcomputer.org/docs/references/ic-interface-spec#ic-sign_with_ecdsa).
///
/// # Note
///
/// Alternatively, [`management_canister::cost_sign_with_ecdsa`](crate::management_canister::cost_sign_with_ecdsa) provides a higher-level API that wraps this function.
///
/// # Errors
///
/// This function will return an error if the `key_name` or the `ecdsa_curve` is invalid.
/// The error type [`SignCostError`] provides more information about the reason of the error.
pub fn cost_sign_with_ecdsa<T: AsRef<str>>(
    key_name: T,
    ecdsa_curve: u32,
) -> Result<u128, SignCostError> {
    let key_name = key_name.as_ref();
    let (cost, code) = ic0::cost_sign_with_ecdsa(key_name, ecdsa_curve);
    sign_cost_result(cost, code)
}

/// Gets the cycle cost of the Management canister method [`sign_with_schnorr`](https://internetcomputer.org/docs/references/ic-interface-spec#ic-sign_with_schnorr).
///
/// # Note
///
/// Alternatively, [`management_canister::cost_sign_with_schnorr`](crate::management_canister::cost_sign_with_schnorr) provides a higher-level API that wraps this function.
///
/// # Errors
///
/// This function will return an error if the `key_name` or the `algorithm` is invalid.
/// The error type [`SignCostError`] provides more information about the reason of the error.
pub fn cost_sign_with_schnorr<T: AsRef<str>>(
    key_name: T,
    algorithm: u32,
) -> Result<u128, SignCostError> {
    let key_name = key_name.as_ref();
    let (dst, code) = ic0::cost_sign_with_schnorr(key_name, algorithm);
    sign_cost_result(dst, code)
}

/// Gets the cycle cost of the Management canister method [`vetkd_derive_key`](https://github.com/dfinity/portal/pull/3763).
///
/// Later, the description will be available in [the interface spec](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-vetkd_derive_key).
///
/// # Note
///
/// Alternatively, [`management_canister::cost_vetkd_derive_key`](crate::management_canister::cost_vetkd_derive_key) provides a higher-level API that wraps this function.
///
/// # Errors
///
/// This function will return an error if the `key_name` or the `vetkd_curve` is invalid.
/// The error type [`SignCostError`] provides more information about the reason of the error.
pub fn cost_vetkd_derive_key<T: AsRef<str>>(
    key_name: T,
    vetkd_curve: u32,
) -> Result<u128, SignCostError> {
    let key_name = key_name.as_ref();
    let (cost, code) = ic0::cost_vetkd_derive_key(key_name, vetkd_curve);
    sign_cost_result(cost, code)
}

/// Gets the number of environment variables available in the canister.
pub fn env_var_count() -> usize {
    ic0::env_var_count()
}

/// Gets the size of the name of the environment variable at the given index.
///
/// # Panics
///
/// This function traps if:
/// - The index is out of bounds (>= than value provided by [`env_var_count`])
/// - The name is not valid UTF-8.
pub fn env_var_name(index: usize) -> String {
    let len = ic0::env_var_name_size(index);
    let mut buf = vec![0u8; len];
    ic0::env_var_name_copy(index, &mut buf, 0);
    String::from_utf8(buf).expect("env_var_name is not valid UTF-8")
}

/// Checks if the environment variable with the given name exists.
///
/// # Panics
///
/// This function traps if the length of `name` exceeds `MAX_ENV_VAR_NAME_LENGTH`.
pub fn env_var_name_exists<T: AsRef<str>>(name: T) -> bool {
    match ic0::env_var_name_exists(name.as_ref()) {
        0 => false,
        1 => true,
        n => panic!("unexpected return value from env_var_name_exists: {n}"),
    }
}

/// Gets the value of the environment variable with the given name.
///
/// It's recommended to use [`env_var_name_exists`] to check if the variable exists before calling this function.
///
/// # Panics
///
/// This function traps if:
/// - The length of `name` exceeds `MAX_ENV_VAR_NAME_LENGTH`.
/// - The name does not match any existing environment variable.
/// - The value is not valid UTF-8.
pub fn env_var_value<T: AsRef<str>>(name: T) -> String {
    let name = name.as_ref();
    let len = ic0::env_var_value_size(name);
    let mut buf = vec![0u8; len];
    ic0::env_var_value_copy(name, &mut buf, 0);
    String::from_utf8(buf).expect("env_var_value is not valid UTF-8")
}

/// Emits textual trace messages.
///
/// On the "real" network, these do not do anything.
///
/// When executing in an environment that supports debugging, this copies out the data
/// and logs, prints or stores it in an environment-appropriate way.
pub fn debug_print<T: AsRef<str>>(data: T) {
    let buf = data.as_ref();
    ic0::debug_print(buf.as_bytes());
}

/// Traps with the given message.
///
/// The environment may copy out the data and log, print or store it in an environment-appropriate way,
/// or include it in system-generated reject messages where appropriate.
pub fn trap<T: AsRef<str>>(data: T) -> ! {
    let buf = data.as_ref();
    ic0::trap(buf.as_bytes());
}

// # Deprecated API bindings
//
// The following functions are deprecated and will be removed in the future.
// They are kept here for compatibility with existing code.

/// Prints the given message.
#[deprecated(since = "0.18.0", note = "Use `debug_print` instead")]
#[doc(hidden)]
pub fn print<S: std::convert::AsRef<str>>(s: S) {
    let s = s.as_ref();
    ic0::debug_print(s.as_bytes());
}

/// Returns the caller of the current call.
#[deprecated(since = "0.18.0", note = "Use `msg_caller` instead")]
#[doc(hidden)]
pub fn caller() -> Principal {
    let len = ic0::msg_caller_size();
    let mut bytes = vec![0u8; len];
    ic0::msg_caller_copy(&mut bytes, 0);
    Principal::try_from(&bytes).unwrap()
}

/// Returns the canister id as a blob.
#[deprecated(since = "0.18.0", note = "Use `canister_self` instead")]
#[doc(hidden)]
pub fn id() -> Principal {
    let len = ic0::canister_self_size();
    let mut bytes = vec![0u8; len];
    ic0::canister_self_copy(&mut bytes, 0);
    Principal::try_from(&bytes).unwrap()
}

/// Gets the amount of funds available in the canister.
///
/// # Panic
///
/// When the cycle balance is greater than `u64::MAX`, this function will panic.
/// As this function is deprecated, it is recommended to use [`canister_cycle_balance`].
#[deprecated(since = "0.18.0", note = "Use `canister_cycle_balance` instead")]
#[doc(hidden)]
pub fn canister_balance() -> u64 {
    // ic0 no longer provides `ic0.canister_cycle_balance` which returns a u64,
    // so we use the u128 version and convert it to u64.
    // When the cycle balance is greater than `u64::MAX`, `ic0.canister_cycle_balance` also panics.
    canister_cycle_balance()
        .try_into()
        .expect("the cycle balance is greater than u64::MAX, please use canister_cycle_balance which returns u128")
}

/// Gets the amount of funds available in the canister.
#[deprecated(since = "0.18.0", note = "Use `canister_cycle_balance` instead")]
#[doc(hidden)]
pub fn canister_balance128() -> u128 {
    canister_cycle_balance()
}

/// Sets the certified data of this canister.
///
/// Canisters can store up to 32 bytes of data that is certified by
/// the system on a regular basis.  One can call [`data_certificate`]
/// function from a query call to get a certificate authenticating the
/// value set by calling this function.
///
/// This function can only be called from the following contexts:
/// - `canister_init`, `canister_pre_upgrade` and `canister_post_upgrade`
///   hooks.
/// - `canister_update` calls.
/// - reply or reject callbacks.
///
/// # Panics
///
/// - This function traps if `data.len() > 32`.
/// - This function traps if it's called from an illegal context
///   (e.g., from a query call).
#[deprecated(since = "0.18.0", note = "Use `certified_data_set` instead")]
#[doc(hidden)]
pub fn set_certified_data(data: &[u8]) {
    ic0::certified_data_set(data);
}

/// Sets global timer.
///
/// The canister can set a global timer to make the system
/// schedule a call to the exported `canister_global_timer`
/// Wasm method after the specified time.
/// The time must be provided as nanoseconds since 1970-01-01.
///
/// The function returns the previous value of the timer.
/// If no timer is set before invoking the function, then the function returns zero.
///
/// Passing zero as an argument to the function deactivates the timer and thus
/// prevents the system from scheduling calls to the canister's `canister_global_timer` Wasm method.
#[deprecated(since = "0.18.0", note = "Use `global_timer_set` instead")]
#[doc(hidden)]
pub fn set_global_timer(timestamp: u64) -> u64 {
    ic0::global_timer_set(timestamp)
}
