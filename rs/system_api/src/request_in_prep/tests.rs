use super::*;

#[test]
fn large_methods_rejected() {
    let sender = CanisterId::from(1);
    let callee_source = 0;
    let callee_size = 10;
    let heap = vec![0; 1024];
    let method_name_source = 0;
    let method_name_len = 100;
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
    )
    .unwrap();
    req_in_prep
        .extend_method_payload(0, 100, &heap)
        .unwrap_err();
}
