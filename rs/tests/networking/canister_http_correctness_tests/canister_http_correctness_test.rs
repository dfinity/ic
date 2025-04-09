use anyhow::Result;
use assert_matches::assert_matches;
use candid::{CandidType, Deserialize};
use canister_http::get_universal_vm_address;
use canister_http_correctness_tests::*;
use ic_agent::agent::{RejectCode, RejectResponse};
use ic_management_canister_types_private::{HttpHeader, HttpMethod};
use ic_system_test_driver::util::block_on;
use ic_system_test_driver::{
    driver::group::{SystemTestGroup, SystemTestSubGroup},
    driver::test_env::TestEnv,
    systest,
};
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::setup)
        .add_sequential(
            SystemTestSubGroup::new()
                .add_test(systest!(test_enforce_https))
                .add_test(systest!(test_transform_function_is_executed))
                .add_test(systest!(test_non_existent_transform_function))
                .add_test(systest!(test_composite_transform_function_is_executed))
                .add_test(systest!(test_no_cycles_attached))
                .add_test(systest!(test_max_possible_request_size))
                .add_test(systest!(test_max_possible_request_size_exceeded))
                .add_test(systest!(
                    test_size_2mb_response_insufficient_cycle_for_rejection_path
                ))
                .add_test(systest!(test_size_4096_max_response_cycle_case_1))
                .add_test(systest!(
                    test_size_4096_max_response_insufficient_cycles_case_2
                ))
                .add_test(systest!(test_max_response_bytes_2_mb_returns_ok))
                .add_test(systest!(test_max_response_bytes_too_large))
                .add_test(systest!(test_transform_that_bloats_on_the_2mb_limit))
                .add_test(systest!(
                    test_transform_that_bloats_response_above_2mb_limit
                ))
                .add_test(systest!(test_post_request))
                .add_test(systest!(
                    test_http_endpoint_response_is_within_limits_with_custom_max_response_bytes
                ))
                .add_test(systest!(
                    test_http_endpoint_response_is_too_large_with_custom_max_response_bytes
                ))
                .add_test(systest!(
                    test_http_endpoint_response_is_within_limits_with_default_max_response_bytes
                ))
                .add_test(systest!(
                    test_http_endpoint_response_is_too_large_with_default_max_response_bytes
                ))
                .add_test(systest!(
                    test_http_endpoint_with_delayed_response_is_rejected
                ))
                .add_test(systest!(test_that_redirects_are_not_followed))
                .add_test(systest!(test_http_calls_to_ic_fails))
                .add_test(systest!(test_invalid_domain_name))
                .add_test(systest!(test_invalid_ip))
                .add_test(systest!(test_get_hello_world_call))
                .add_test(systest!(
                    test_request_header_total_size_within_the_48_kib_limit
                ))
                .add_test(systest!(
                    test_request_header_total_size_over_the_48_kib_limit
                ))
                .add_test(systest!(
                    test_response_header_total_size_within_the_48_kib_limit
                ))
                .add_test(systest!(
                    test_response_header_total_size_over_the_48_kib_limit
                ))
                .add_test(systest!(test_request_header_name_and_value_within_limits))
                .add_test(systest!(test_request_header_name_too_long))
                .add_test(systest!(test_request_header_value_too_long))
                .add_test(systest!(test_response_header_name_within_limit))
                .add_test(systest!(test_response_header_name_over_limit))
                .add_test(systest!(test_response_header_value_within_limit))
                .add_test(systest!(test_response_header_value_over_limit))
                .add_test(systest!(test_post_call))
                .add_test(systest!(test_head_call))
                .add_test(systest!(
                    test_small_maximum_possible_response_size_only_headers
                ))
                .add_test(systest!(
                    test_small_maximum_possible_response_size_exceeded_only_headers
                ))
                .add_test(systest!(test_non_ascii_url_is_rejected))
                .add_test(systest!(test_max_url_length))
                .add_test(systest!(test_max_url_length_exceeded))
                .add_test(systest!(
                    test_reference_transform_function_exposed_by_different_canister
                ))
                .add_test(systest!(test_max_number_of_response_headers))
                .add_test(systest!(test_max_number_of_response_headers_exceeded))
                .add_test(systest!(test_max_number_of_request_headers))
                .add_test(systest!(test_max_number_of_request_headers_exceeded))
                .add_test(systest!(test_check_caller_id_on_transform_function)),
        )
        .execute_from_args()?;

    Ok(())
}

fn test_enforce_https(env: TestEnv) {
    let request = enforce_https(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

fn test_transform_function_is_executed(env: TestEnv) {
    let request = transform_function_is_executed(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    let response = response.expect("Http call should succeed");
    assert_eq!(response.headers.len(), 2, "Headers: {:?}", response.headers);
    assert_eq!(response.headers[0].0, "hello");
    assert_eq!(response.headers[0].1, "bonjour");
    assert_eq!(response.headers[1].0, "caller");
    assert_eq!(response.headers[1].1, "aaaaa-aa");
    assert_eq!(
        response.body.as_str(),
        "transform_context",
        "Transform function did not set the body to the provided context."
    );
    assert_eq!(response.status, 202);
}

fn test_non_existent_transform_function(env: TestEnv) {
    let request = non_existent_transform_function(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterError,
            ..
        })
    );
}

fn test_composite_transform_function_is_executed(env: TestEnv) {
    let request = composite_transform_function_is_executed(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    let response = response.expect("Http call should succeed");
    assert_eq!(response.headers.len(), 2, "Headers: {:?}", response.headers);
    assert_eq!(response.headers[0].0, "hello");
    assert_eq!(response.headers[0].1, "bonjour");
    assert_eq!(response.headers[1].0, "caller");
    assert_eq!(response.headers[1].1, "aaaaa-aa");
}

fn test_no_cycles_attached(env: TestEnv) {
    let request = no_cycles_attached(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_max_possible_request_size(env: TestEnv) {
    let request = max_possible_request_size(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(response, Ok(r) if r.status==200);
}

fn test_max_possible_request_size_exceeded(env: TestEnv) {
    let request = max_possible_request_size_exceeded(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_size_2mb_response_insufficient_cycle_for_rejection_path(env: TestEnv) {
    let request = size_2mb_response_insufficient_cycles_for_rejection_path(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(async move { submit_outcall(&handlers, request).await });
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_size_4096_max_response_cycle_case_1(env: TestEnv) {
    let request = size_4096_max_response_cycle_case_1(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(response, Ok(r) if r.status==200);
}

fn test_size_4096_max_response_insufficient_cycles_case_2(env: TestEnv) {
    let request = size_4096_max_response_insufficient_cycles_case_2(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(async move { submit_outcall(&handlers, request).await });
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_max_response_bytes_2_mb_returns_ok(env: TestEnv) {
    let request = max_response_bytes_2_mb_returns_ok(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(response, Ok(r) if r.status==200);
}

fn test_max_response_bytes_too_large(env: TestEnv) {
    let request = max_response_bytes_too_large(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_transform_that_bloats_on_the_2mb_limit(env: TestEnv) {
    let request = transform_that_bloats_on_the_2mb_limit(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(response, Ok(r) if r.status==200);
}

fn test_transform_that_bloats_response_above_2mb_limit(env: TestEnv) {
    let request = transform_that_bloats_response_above_2mb_limit(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

fn test_post_request(env: TestEnv) {
    let request = post_request(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(response, Ok(r) if r.body.contains("satoshi"));
}

fn test_http_endpoint_response_is_within_limits_with_custom_max_response_bytes(env: TestEnv) {
    let request = http_endpoint_response_is_within_limits_with_custom_max_response_bytes(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    let response = response.expect("Http call should succeed");
    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
}

fn test_http_endpoint_response_is_too_large_with_custom_max_response_bytes(env: TestEnv) {
    let request = http_endpoint_response_is_too_large_with_custom_max_response_bytes(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

fn test_http_endpoint_response_is_within_limits_with_default_max_response_bytes(env: TestEnv) {
    let request = http_endpoint_response_is_within_limits_with_default_max_response_bytes(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    let response = response.expect("Http call should succeed");
    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
}

fn test_http_endpoint_response_is_too_large_with_default_max_response_bytes(env: TestEnv) {
    let request = http_endpoint_response_is_too_large_with_default_max_response_bytes(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

fn test_http_endpoint_with_delayed_response_is_rejected(env: TestEnv) {
    let request = http_endpoint_with_delayed_response_is_rejected(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

/// The adapter should not follow HTTP redirects.
fn test_that_redirects_are_not_followed(env: TestEnv) {
    let request = that_redirects_are_not_followed(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(response, Ok(r) if r.status == 303);
}

/// The adapter should reject HTTP calls that are made to other IC replicas' HTTPS endpoints.
fn test_http_calls_to_ic_fails(env: TestEnv) {
    let request = http_calls_to_ic_fails(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));

    let err_response = response.unwrap_err();
    assert_matches!(err_response.reject_code, RejectCode::SysTransient);

    let expected_error_message = "Error(Connect, ConnectError(\"tcp connect error\", Os { code: 111, kind: ConnectionRefused, message: \"Connection refused\" }))";
    assert!(
        err_response.reject_message.contains(expected_error_message),
        "Expected error message to contain, {}, got: {}",
        expected_error_message,
        err_response.reject_message,
    );
}

fn test_invalid_domain_name(env: TestEnv) {
    let request = invalid_domain_name(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysTransient,
            ..
        })
    );
}

fn test_invalid_ip(env: TestEnv) {
    let request = invalid_ip(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysTransient,
            ..
        })
    );
}

/// Test that the response body returned is the same as the requested path.
fn test_get_hello_world_call(env: TestEnv) {
    let expected_body = "hello_world";
    let request = get_hello_world_call(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    let response = response.expect("Http call should succeed");
    assert_matches!(&response, RemoteHttpResponse {body, status: 200, ..} if body == expected_body);
    canister_http_correctness_tests::assert_http_response(&response);
}

fn test_request_header_total_size_within_the_48_kib_limit(env: TestEnv) {
    let request = request_header_total_size_within_the_48_kib_limit(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    let response = response.expect("Http call should succeed");
    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
}

fn test_request_header_total_size_over_the_48_kib_limit(env: TestEnv) {
    let request = request_header_total_size_over_the_48_kib_limit(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_response_header_total_size_within_the_48_kib_limit(env: TestEnv) {
    let request = response_header_total_size_within_the_48_kib_limit(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(&response, Ok(RemoteHttpResponse { status: 200, .. }));

    // Compute exactly the size of the response headers to account also for overhead.
    let total_header_size: usize = response
        .unwrap()
        .headers
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum();

    // Ensure that the successful response contains the expected response headers.
    assert!(
        total_header_size <= 48 * 1024,
        "Total header size ({} bytes) exceeds 48KiB limit",
        total_header_size
    );
}

fn test_response_header_total_size_over_the_48_kib_limit(env: TestEnv) {
    let request = response_header_total_size_over_the_48_kib_limit(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        &response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

fn test_request_header_name_and_value_within_limits(env: TestEnv) {
    let request = request_header_name_and_value_within_limits(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    let response = response.expect("Http call should succeed");
    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
}

fn test_request_header_name_too_long(env: TestEnv) {
    let request = request_header_name_too_long(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_request_header_value_too_long(env: TestEnv) {
    let request = request_header_value_too_long(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_response_header_name_within_limit(env: TestEnv) {
    let request = response_header_name_within_limit(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(&response, Ok(RemoteHttpResponse { status: 200, .. }));
}

fn test_response_header_name_over_limit(env: TestEnv) {
    let request = response_header_name_over_limit(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

fn test_response_header_value_within_limit(env: TestEnv) {
    let request = response_header_value_within_limit(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(&response, Ok(RemoteHttpResponse { status: 200, .. }));
}

fn test_response_header_value_over_limit(env: TestEnv) {
    let request = response_header_value_over_limit(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

fn test_post_call(env: TestEnv) {
    let expected_body = "POST";
    let request = post_call(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request.clone()));
    let response = response.expect("Http call should succeed");
    assert_matches!(&response, RemoteHttpResponse {body, status: 200, ..} if body.contains(expected_body));
    assert_distinct_headers(&response);
    assert_http_json_response(&request.request, &response);
}

/// Send 6666 repeating `x` to /anything endpoint.
/// Use HEAD http method. It only asks for the head, not the body.
/// Set max response size to 666 (order of magnitude smaller)
fn test_head_call(env: TestEnv) {
    let request = head_call(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    let response = response.expect("Http call should succeed");
    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_distinct_headers(&response);
    let header_size = response
        .headers
        .iter()
        .map(|(header, value)| header.len() + value.len())
        .sum::<usize>();
    assert!(header_size <= 666);
    assert!(
        response.body.is_empty(),
        "Head request does not return a body."
    );
}

fn test_small_maximum_possible_response_size_only_headers(env: TestEnv) {
    let request = small_maximum_possible_response_size_only_headers(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    let response = response.expect("Http call should succeed");
    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_http_response(&response);
}

fn test_small_maximum_possible_response_size_exceeded_only_headers(env: TestEnv) {
    let request = small_maximum_possible_response_size_exceeded_only_headers(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

fn test_non_ascii_url_is_rejected(env: TestEnv) {
    let request = non_ascii_url_is_rejected(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

fn test_max_url_length(env: TestEnv) {
    let request = max_url_length(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    let response = response.expect("Http call should succeed");
    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_http_response(&response);
}

fn test_max_url_length_exceeded(env: TestEnv) {
    let request = max_url_length_exceeded(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_reference_transform_function_exposed_by_different_canister(env: TestEnv) {
    let request = reference_transform_function_exposed_by_different_canister(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_max_number_of_response_headers(env: TestEnv) {
    let request = max_number_of_response_headers(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    let response = response.expect("Http call should succeed");
    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    let response_headers = HTTP_HEADERS_MAX_NUMBER - HTTPBIN_OVERHEAD_RESPONSE_HEADERS;
    assert_http_response(&response);
    assert_eq!(
        response.headers.len(),
        HTTP_HEADERS_MAX_NUMBER,
        "Expected {} headers, got {}",
        response_headers,
        response.headers.len()
    );
}

fn test_max_number_of_response_headers_exceeded(env: TestEnv) {
    let request = max_number_of_response_headers_exceeded(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::SysFatal,
            ..
        })
    );
}

fn test_max_number_of_request_headers(env: TestEnv) {
    let request = max_number_of_request_headers(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request.clone()));
    let response = response.expect("Http call should succeed");
    assert_matches!(&response, RemoteHttpResponse { status: 200, .. });
    assert_http_response(&response);
    assert_http_json_response(&request.request, &response);
}

fn test_max_number_of_request_headers_exceeded(env: TestEnv) {
    let webserver_ipv6 = get_universal_vm_address(&env);
    let url = format!("https://[{webserver_ipv6}]:20443/anything");

    let headers = (0..HTTP_HEADERS_MAX_NUMBER + 1)
        .map(|i| HttpHeader {
            name: format!("name{}", i),
            value: format!("value{}", i),
        })
        .collect();

    #[derive(Clone, Debug, CandidType, Deserialize)]
    struct TestRequest {
        url: String,
        headers: Vec<HttpHeader>,
        method: HttpMethod,
    }

    #[derive(Clone, Debug, CandidType, Deserialize)]
    struct TestRemoteHttpRequest {
        pub request: TestRequest,
        pub cycles: u64,
    }

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(
        &handlers,
        TestRemoteHttpRequest {
            request: TestRequest {
                url,
                headers,
                method: HttpMethod::POST,
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(
        response,
        Err(RejectResponse {
            reject_code: RejectCode::CanisterReject,
            ..
        })
    );
}

fn test_check_caller_id_on_transform_function(env: TestEnv) {
    let request = check_caller_id_on_transform_function(&env);

    let handlers = Handlers::new(&env);
    let response = block_on(submit_outcall(&handlers, request));
    let response = response.expect("Http call should succeed");

    // Check caller id injected into header.
    let caller_id = &response
        .headers
        .iter()
        .find(|(name, _)| name.to_lowercase() == "caller")
        .expect("caller header is present after transformation.")
        .1;

    assert_eq!(caller_id, "aaaaa-aa");
}
