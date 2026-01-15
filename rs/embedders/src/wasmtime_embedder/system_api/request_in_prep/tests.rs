use super::*;

#[test]
fn method_names_larger_than_allowed_payload_rejected() {
    let sender = CanisterId::from(1);
    let callee_source = 0;
    let callee_size = 10;
    let heap = vec![0; 1024];
    let method_name_source = 0;
    let method_name_len = 100;
    let callback = WasmClosure::new(0, 0);
    let max_size_remote_subnet = NumBytes::from(10);
    let max_sum_exported_function_name_lengths = 1000;
    RequestInPrep::new(
        sender,
        callee_source,
        callee_size,
        method_name_source,
        method_name_len,
        &heap,
        callback.clone(),
        callback,
        max_size_remote_subnet,
        1,
        max_sum_exported_function_name_lengths,
    )
    .unwrap_err();
}

#[test]
fn method_names_larger_than_max_sum_exported_function_names_rejected() {
    let sender = CanisterId::from(1);
    let callee_source = 0;
    let callee_size = 1;
    let heap = vec![0; 1024];
    let method_name_source = 0;
    let max_sum_exported_function_name_lengths = 1000;
    let method_name_len = max_sum_exported_function_name_lengths + 1;
    let callback = WasmClosure::new(0, 0);
    let max_size_remote_subnet = NumBytes::from(10);
    RequestInPrep::new(
        sender,
        callee_source,
        callee_size,
        method_name_source,
        method_name_len,
        &heap,
        callback.clone(),
        callback,
        max_size_remote_subnet,
        1,
        max_sum_exported_function_name_lengths,
    )
    .unwrap_err();
}

#[test]
fn large_callee_rejected() {
    let sender = CanisterId::from(1);
    let callee_source = 0;
    let callee_size = 100;
    let heap = vec![0; 1024];
    let method_name_source = 0;
    let method_name_len = 1;
    let callback = WasmClosure::new(0, 0);
    let max_size_remote_subnet = NumBytes::from(10);
    let max_sum_exported_function_name_lengths = 1000;
    RequestInPrep::new(
        sender,
        callee_source,
        callee_size,
        method_name_source,
        method_name_len,
        &heap,
        callback.clone(),
        callback,
        max_size_remote_subnet,
        1,
        max_sum_exported_function_name_lengths,
    )
    .unwrap_err();
}

#[test]
fn payloads_larger_than_intra_limit_rejected() {
    let sender = CanisterId::from(1);
    let callee_source = 0;
    let callee_size = 1;
    let heap = vec![0; 1024];
    let method_name_source = 0;
    let method_name_len = 1;
    let callback = WasmClosure::new(0, 0);
    let max_size_remote_subnet = NumBytes::from(10);
    let max_sum_exported_function_name_lengths = 1000;
    let mut req_in_prep = RequestInPrep::new(
        sender,
        callee_source,
        callee_size,
        method_name_source,
        method_name_len,
        &heap,
        callback.clone(),
        callback,
        max_size_remote_subnet,
        1,
        max_sum_exported_function_name_lengths,
    )
    .unwrap();
    req_in_prep
        .extend_method_payload(0, 100, &heap)
        .unwrap_err();
}

fn make_request_in_prep() -> RequestInPrep {
    let sender = CanisterId::from(1);
    let callee_source = 0;
    let callee_size = 1;
    let heap = vec![0; 1024];
    let method_name_source = 0;
    let method_name_len = 1;
    let callback = WasmClosure::new(0, 0);
    let max_size_remote_subnet = NumBytes::from(10);
    let max_sum_exported_function_name_lengths = 1000;
    RequestInPrep::new(
        sender,
        callee_source,
        callee_size,
        method_name_source,
        method_name_len,
        &heap,
        callback.clone(),
        callback,
        max_size_remote_subnet,
        1,
        max_sum_exported_function_name_lengths,
    )
    .unwrap()
}

#[test]
fn test_set_timeout() {
    let mut req_in_prep = make_request_in_prep();
    // No timeout is set.
    assert_eq!(req_in_prep.timeout_seconds, None);
    assert!(!req_in_prep.is_timeout_set());
    // Set timeout.
    req_in_prep.set_timeout(10);
    assert_eq!(req_in_prep.timeout_seconds, Some(10));
    assert!(req_in_prep.is_timeout_set());
}
