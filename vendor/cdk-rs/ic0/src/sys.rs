// This file is generated from ic0.txt.
// Don't manually modify it.
#[cfg(target_family = "wasm")]
#[link(wasm_import_module = "ic0")]
unsafe extern "C" {
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn msg_arg_data_size() -> usize;
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub fn msg_arg_data_copy(dst: usize, offset: usize, size: usize);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn msg_caller_size() -> usize;
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub fn msg_caller_copy(dst: usize, offset: usize, size: usize);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn msg_reject_code() -> u32;
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn msg_reject_msg_size() -> usize;
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub fn msg_reject_msg_copy(dst: usize, offset: usize, size: usize);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn msg_deadline() -> u64;
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`."]
    pub fn msg_reply_data_append(src: usize, size: usize);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn msg_reply();
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`"]
    pub fn msg_reject(src: usize, size: usize);
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128)"]
    pub fn msg_cycles_available128(dst: usize);
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128)"]
    pub fn msg_cycles_refunded128(dst: usize);
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128). The `max_amount_high` and `max_amount_low` parameters do not affect safety."]
    pub fn msg_cycles_accept128(max_amount_high: u64, max_amount_low: u64, dst: usize);
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128). The `amount_high` and `amount_low` parameters do not affect safety."]
    pub fn cycles_burn128(amount_high: u64, amount_low: u64, dst: usize);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn canister_self_size() -> usize;
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub fn canister_self_copy(dst: usize, offset: usize, size: usize);
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128)"]
    pub fn canister_cycle_balance128(dst: usize);
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128)"]
    pub fn canister_liquid_cycle_balance128(dst: usize);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn canister_status() -> u32;
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn canister_version() -> u64;
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn subnet_self_size() -> usize;
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub fn subnet_self_copy(dst: usize, offset: usize, size: usize);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn msg_method_name_size() -> usize;
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub fn msg_method_name_copy(dst: usize, offset: usize, size: usize);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn accept_message();
    #[doc = "# Safety\n\n- `callee_src` must be a pointer to a readable sequence of bytes with size `callee_size`\n- `name_src` must be a pointer to a readable UTF-8 string with size `name_size`\n- `reply_fun` must be a function pointer with signature (env : usize) -> (), safely callable as an entrypoint with `reply_env`\n- `reject_fun` must be a function pointer with signature (env : usize) -> (), safely callable as an entrypoint with `reject_env`\n- This function takes ownership of `reply_env` and `reject_env`\n- If called, `reply_fun` will take ownership of `reply_env`, `reject_env`, and the `ic0.call_on_cleanup` `env`\n- If called, `reject_fun` will take ownership of `reply_env`, `reject_env`, and the `ic0.call_on_cleanup` `env`"]
    pub fn call_new(
        callee_src: usize,
        callee_size: usize,
        name_src: usize,
        name_size: usize,
        reply_fun: usize,
        reply_env: usize,
        reject_fun: usize,
        reject_env: usize,
    );
    #[doc = "# Safety\n\n- `fun` must be a function pointer with signature (env : usize) -> (), safely callable as an entrypoint with `env`\n- This function takes ownership of `env`\n- If called, `fun` will take ownership of `env`, `reply_env`, and `reject_env`"]
    pub fn call_on_cleanup(fun: usize, env: usize);
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`"]
    pub fn call_data_append(src: usize, size: usize);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn call_with_best_effort_response(timeout_seconds: u32);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn call_cycles_add128(amount_high: u64, amount_low: u64);
    #[doc = "# Safety\n\nAlways safe to call.\n- If this function returns a nonzero value, ownership of `reply_env`, `reject_env`, and the `ic0.call_on_cleanup` `env` is released to the caller\n- If this function returns 0, then (from the perspective of safety, *not* semantics) exactly one of `reply_fun`, `reject_fun`, or the `ic0.call_on_cleanup` `fun` will be called, exactly once."]
    pub fn call_perform() -> u32;
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn stable64_size() -> u64;
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn stable64_grow(new_pages: u64) -> u64;
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub fn stable64_write(offset: u64, src: u64, size: u64);
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub fn stable64_read(dst: u64, offset: u64, size: u64);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn root_key_size() -> usize;
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub fn root_key_copy(dst: usize, offset: usize, size: usize);
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`"]
    pub fn certified_data_set(src: usize, size: usize);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn data_certificate_present() -> u32;
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn data_certificate_size() -> usize;
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub fn data_certificate_copy(dst: usize, offset: usize, size: usize);
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn time() -> u64;
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn global_timer_set(timestamp: u64) -> u64;
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn performance_counter(counter_type: u32) -> u64;
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`"]
    pub fn is_controller(src: usize, size: usize) -> u32;
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn in_replicated_execution() -> u32;
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128). The `method_name_size` and `payload_size` parameters do not affect safety."]
    pub fn cost_call(method_name_size: u64, payload_size: u64, dst: usize);
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128)"]
    pub fn cost_create_canister(dst: usize);
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128). The `request_size` and `max_res_bytes` parameters do not affect safety"]
    pub fn cost_http_request(request_size: u64, max_res_bytes: u64, dst: usize);
    #[doc = "# Safety\n\n- `src` must be a pointer to a readable UTF-8 string with size `size`\n- `dst` must be a pointer to a writable sequence of 16 bytes (LE u128)\n- The `ecdsa_curve` parameter does not affect safety"]
    pub fn cost_sign_with_ecdsa(src: usize, size: usize, ecdsa_curve: u32, dst: usize) -> u32;
    #[doc = "# Safety\n\n- `src` must be a pointer to a readable UTF-8 string with size `size`\n- `dst` must be a pointer to a writable sequence of 16 bytes (LE u128)\n- The `algorithm` parameter does not affect safety"]
    pub fn cost_sign_with_schnorr(src: usize, size: usize, algorithm: u32, dst: usize) -> u32;
    #[doc = "# Safety\n\n- `src` must be a pointer to a readable UTF-8 string with size `size`\n- `dst` must be a pointer to a writable sequence of 16 bytes (LE u128)\n- The `vetkd_curve` parameter does not affect safety"]
    pub fn cost_vetkd_derive_key(src: usize, size: usize, vetkd_curve: u32, dst: usize) -> u32;
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn env_var_count() -> usize;
    #[doc = "# Safety\n\nAlways safe to call"]
    pub fn env_var_name_size(index: usize) -> usize;
    #[doc = "# Safety\n\n- The `index` parameter does not affect safety\n- `dst` must be a pointer to a writable sequence of bytes with size `size`\n- The `offset` parameter does not affect safety"]
    pub fn env_var_name_copy(index: usize, dst: usize, offset: usize, size: usize);
    #[doc = "# Safety\n\n`name_src` must be a pointer to a readable UTF-8 string with size `name_size`"]
    pub fn env_var_name_exists(name_src: usize, name_size: usize) -> u32;
    #[doc = "# Safety\n\n`name_src` must be a pointer to a readable UTF-8 string with size `name_size`"]
    pub fn env_var_value_size(name_src: usize, name_size: usize) -> usize;
    #[doc = "# Safety\n\n- `name_src` must be a pointer to a readable UTF-8 string with size `name_size`\n- `dst` must be a pointer to a writable sequence of bytes with size `size`\n- The `offset` parameter does not affect safety"]
    pub fn env_var_value_copy(
        name_src: usize,
        name_size: usize,
        dst: usize,
        offset: usize,
        size: usize,
    );
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`"]
    pub fn debug_print(src: usize, size: usize);
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`"]
    pub fn trap(src: usize, size: usize);
}

#[cfg(not(target_family = "wasm"))]
#[allow(unused_variables)]
#[allow(clippy::missing_safety_doc)]
#[allow(clippy::too_many_arguments)]
mod non_wasm {
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn msg_arg_data_size() -> usize {
        panic!("msg_arg_data_size should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub unsafe fn msg_arg_data_copy(dst: usize, offset: usize, size: usize) {
        panic!("msg_arg_data_copy should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn msg_caller_size() -> usize {
        panic!("msg_caller_size should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub unsafe fn msg_caller_copy(dst: usize, offset: usize, size: usize) {
        panic!("msg_caller_copy should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn msg_reject_code() -> u32 {
        panic!("msg_reject_code should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn msg_reject_msg_size() -> usize {
        panic!("msg_reject_msg_size should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub unsafe fn msg_reject_msg_copy(dst: usize, offset: usize, size: usize) {
        panic!("msg_reject_msg_copy should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn msg_deadline() -> u64 {
        panic!("msg_deadline should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`."]
    pub unsafe fn msg_reply_data_append(src: usize, size: usize) {
        panic!("msg_reply_data_append should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn msg_reply() {
        panic!("msg_reply should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`"]
    pub unsafe fn msg_reject(src: usize, size: usize) {
        panic!("msg_reject should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128)"]
    pub unsafe fn msg_cycles_available128(dst: usize) {
        panic!("msg_cycles_available128 should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128)"]
    pub unsafe fn msg_cycles_refunded128(dst: usize) {
        panic!("msg_cycles_refunded128 should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128). The `max_amount_high` and `max_amount_low` parameters do not affect safety."]
    pub unsafe fn msg_cycles_accept128(max_amount_high: u64, max_amount_low: u64, dst: usize) {
        panic!("msg_cycles_accept128 should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128). The `amount_high` and `amount_low` parameters do not affect safety."]
    pub unsafe fn cycles_burn128(amount_high: u64, amount_low: u64, dst: usize) {
        panic!("cycles_burn128 should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn canister_self_size() -> usize {
        panic!("canister_self_size should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub unsafe fn canister_self_copy(dst: usize, offset: usize, size: usize) {
        panic!("canister_self_copy should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128)"]
    pub unsafe fn canister_cycle_balance128(dst: usize) {
        panic!("canister_cycle_balance128 should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128)"]
    pub unsafe fn canister_liquid_cycle_balance128(dst: usize) {
        panic!("canister_liquid_cycle_balance128 should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn canister_status() -> u32 {
        panic!("canister_status should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn canister_version() -> u64 {
        panic!("canister_version should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn subnet_self_size() -> usize {
        panic!("subnet_self_size should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub unsafe fn subnet_self_copy(dst: usize, offset: usize, size: usize) {
        panic!("subnet_self_copy should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn msg_method_name_size() -> usize {
        panic!("msg_method_name_size should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub unsafe fn msg_method_name_copy(dst: usize, offset: usize, size: usize) {
        panic!("msg_method_name_copy should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn accept_message() {
        panic!("accept_message should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n- `callee_src` must be a pointer to a readable sequence of bytes with size `callee_size`\n- `name_src` must be a pointer to a readable UTF-8 string with size `name_size`\n- `reply_fun` must be a function pointer with signature (env : usize) -> (), safely callable as an entrypoint with `reply_env`\n- `reject_fun` must be a function pointer with signature (env : usize) -> (), safely callable as an entrypoint with `reject_env`\n- This function takes ownership of `reply_env` and `reject_env`\n- If called, `reply_fun` will take ownership of `reply_env`, `reject_env`, and the `ic0.call_on_cleanup` `env`\n- If called, `reject_fun` will take ownership of `reply_env`, `reject_env`, and the `ic0.call_on_cleanup` `env`"]
    pub unsafe fn call_new(
        callee_src: usize,
        callee_size: usize,
        name_src: usize,
        name_size: usize,
        reply_fun: usize,
        reply_env: usize,
        reject_fun: usize,
        reject_env: usize,
    ) {
        panic!("call_new should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n- `fun` must be a function pointer with signature (env : usize) -> (), safely callable as an entrypoint with `env`\n- This function takes ownership of `env`\n- If called, `fun` will take ownership of `env`, `reply_env`, and `reject_env`"]
    pub unsafe fn call_on_cleanup(fun: usize, env: usize) {
        panic!("call_on_cleanup should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`"]
    pub unsafe fn call_data_append(src: usize, size: usize) {
        panic!("call_data_append should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn call_with_best_effort_response(timeout_seconds: u32) {
        panic!("call_with_best_effort_response should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn call_cycles_add128(amount_high: u64, amount_low: u64) {
        panic!("call_cycles_add128 should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call.\n- If this function returns a nonzero value, ownership of `reply_env`, `reject_env`, and the `ic0.call_on_cleanup` `env` is released to the caller\n- If this function returns 0, then (from the perspective of safety, *not* semantics) exactly one of `reply_fun`, `reject_fun`, or the `ic0.call_on_cleanup` `fun` will be called, exactly once."]
    pub unsafe fn call_perform() -> u32 {
        panic!("call_perform should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn stable64_size() -> u64 {
        panic!("stable64_size should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn stable64_grow(new_pages: u64) -> u64 {
        panic!("stable64_grow should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub unsafe fn stable64_write(offset: u64, src: u64, size: u64) {
        panic!("stable64_write should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub unsafe fn stable64_read(dst: u64, offset: u64, size: u64) {
        panic!("stable64_read should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn root_key_size() -> usize {
        panic!("root_key_size should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub unsafe fn root_key_copy(dst: usize, offset: usize, size: usize) {
        panic!("root_key_copy should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`"]
    pub unsafe fn certified_data_set(src: usize, size: usize) {
        panic!("certified_data_set should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn data_certificate_present() -> u32 {
        panic!("data_certificate_present should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn data_certificate_size() -> usize {
        panic!("data_certificate_size should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of bytes with size `size`. The `offset` parameter does not affect safety."]
    pub unsafe fn data_certificate_copy(dst: usize, offset: usize, size: usize) {
        panic!("data_certificate_copy should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn time() -> u64 {
        panic!("time should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn global_timer_set(timestamp: u64) -> u64 {
        panic!("global_timer_set should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn performance_counter(counter_type: u32) -> u64 {
        panic!("performance_counter should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`"]
    pub unsafe fn is_controller(src: usize, size: usize) -> u32 {
        panic!("is_controller should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn in_replicated_execution() -> u32 {
        panic!("in_replicated_execution should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128). The `method_name_size` and `payload_size` parameters do not affect safety."]
    pub unsafe fn cost_call(method_name_size: u64, payload_size: u64, dst: usize) {
        panic!("cost_call should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128)"]
    pub unsafe fn cost_create_canister(dst: usize) {
        panic!("cost_create_canister should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`dst` must be a pointer to a writable sequence of 16 bytes (LE u128). The `request_size` and `max_res_bytes` parameters do not affect safety"]
    pub unsafe fn cost_http_request(request_size: u64, max_res_bytes: u64, dst: usize) {
        panic!("cost_http_request should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n- `src` must be a pointer to a readable UTF-8 string with size `size`\n- `dst` must be a pointer to a writable sequence of 16 bytes (LE u128)\n- The `ecdsa_curve` parameter does not affect safety"]
    pub unsafe fn cost_sign_with_ecdsa(
        src: usize,
        size: usize,
        ecdsa_curve: u32,
        dst: usize,
    ) -> u32 {
        panic!("cost_sign_with_ecdsa should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n- `src` must be a pointer to a readable UTF-8 string with size `size`\n- `dst` must be a pointer to a writable sequence of 16 bytes (LE u128)\n- The `algorithm` parameter does not affect safety"]
    pub unsafe fn cost_sign_with_schnorr(
        src: usize,
        size: usize,
        algorithm: u32,
        dst: usize,
    ) -> u32 {
        panic!("cost_sign_with_schnorr should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n- `src` must be a pointer to a readable UTF-8 string with size `size`\n- `dst` must be a pointer to a writable sequence of 16 bytes (LE u128)\n- The `vetkd_curve` parameter does not affect safety"]
    pub unsafe fn cost_vetkd_derive_key(
        src: usize,
        size: usize,
        vetkd_curve: u32,
        dst: usize,
    ) -> u32 {
        panic!("cost_vetkd_derive_key should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn env_var_count() -> usize {
        panic!("env_var_count should only be called inside canisters.");
    }
    #[doc = "# Safety\n\nAlways safe to call"]
    pub unsafe fn env_var_name_size(index: usize) -> usize {
        panic!("env_var_name_size should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n- The `index` parameter does not affect safety\n- `dst` must be a pointer to a writable sequence of bytes with size `size`\n- The `offset` parameter does not affect safety"]
    pub unsafe fn env_var_name_copy(index: usize, dst: usize, offset: usize, size: usize) {
        panic!("env_var_name_copy should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`name_src` must be a pointer to a readable UTF-8 string with size `name_size`"]
    pub unsafe fn env_var_name_exists(name_src: usize, name_size: usize) -> u32 {
        panic!("env_var_name_exists should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`name_src` must be a pointer to a readable UTF-8 string with size `name_size`"]
    pub unsafe fn env_var_value_size(name_src: usize, name_size: usize) -> usize {
        panic!("env_var_value_size should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n- `name_src` must be a pointer to a readable UTF-8 string with size `name_size`\n- `dst` must be a pointer to a writable sequence of bytes with size `size`\n- The `offset` parameter does not affect safety"]
    pub unsafe fn env_var_value_copy(
        name_src: usize,
        name_size: usize,
        dst: usize,
        offset: usize,
        size: usize,
    ) {
        panic!("env_var_value_copy should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`"]
    pub unsafe fn debug_print(src: usize, size: usize) {
        panic!("debug_print should only be called inside canisters.");
    }
    #[doc = "# Safety\n\n`src` must be a pointer to a readable sequence of bytes with size `size`"]
    pub unsafe fn trap(src: usize, size: usize) {
        panic!("trap should only be called inside canisters.");
    }
}

#[cfg(not(target_family = "wasm"))]
pub use non_wasm::*;
