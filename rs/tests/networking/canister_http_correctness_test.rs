/* tag::catalog[]
Title:: Test correctness of feature according to spec.

Goal:: Ensure simple HTTP requests can be made from canisters.

Runbook::
0. Instantiate a universal VM with a webserver
1. Instantiate an IC with one application subnet with the HTTP feature enabled.
2. Install NNS canisters
3. Install the proxy canister
4. Make an update call to the proxy canister.

Success::
1. Received http response with status 200.

end::catalog[] */

use anyhow::Result;
use assert_matches::assert_matches;
use canister_http::*;
use canister_test::{Canister, Runtime};
use dfn_candid::candid_one;
use ic_base_types::{CanisterId, NumBytes};
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types::{
    BoundedHttpHeaders, CanisterHttpRequestArgs, HttpHeader, HttpMethod, TransformContext,
    TransformFunc,
};
use ic_system_test_driver::driver::group::SystemTestGroup;
use ic_system_test_driver::driver::group::SystemTestSubGroup;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use ic_test_utilities::cycles_account_manager::CyclesAccountManagerBuilder;
use ic_test_utilities_types::messages::RequestBuilder;
use ic_types::canister_http::{CanisterHttpRequestContext, MAX_CANISTER_HTTP_REQUEST_BYTES};
use ic_types::time::UNIX_EPOCH;
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use serde_json::Value;
use std::{collections::HashSet, convert::TryFrom};

const MAX_REQUEST_BYTES_LIMIT: usize = 2_000_000;

struct Handlers<'a> {
    subnet_size: usize,
    runtime: Runtime,
    env: &'a TestEnv,
}

impl<'a> Handlers<'a> {
    fn new(env: &'a TestEnv) -> Handlers<'a> {
        let subnet_size = get_node_snapshots(env).count();

        let runtime = {
            let mut nodes = get_node_snapshots(env);
            let node = nodes.next().expect("there is no application node");
            get_runtime_from_node(&node)
        };

        Handlers {
            runtime,
            subnet_size,
            env,
        }
    }

    fn proxy_canister(&self) -> Canister<'_> {
        let principal_id = get_proxy_canister_id(self.env);
        let canister_id = CanisterId::unchecked_from_principal(principal_id);
        Canister::new(&self.runtime, canister_id)
    }
}

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(canister_http::setup)
        .add_parallel(
            SystemTestSubGroup::new()
                // .add_test(systest!(test_enforce_https))
                // .add_test(systest!(test_transform_function_is_executed))
                // .add_test(systest!(test_composite_transform_function_is_executed))
                // .add_test(systest!(test_no_cycles_attached))
                .add_test(systest!(test_max_possible_request_size))
                .add_test(systest!(test_max_possible_request_size_exceeded))
                // .add_test(systest!(test_2mb_response_cycle_for_rejection_path))
                // .add_test(systest!(test_4096_max_response_cycle_case_1))
                // .add_test(systest!(test_4096_max_response_cycle_case_2))
                // .add_test(systest!(test_max_response_limit_too_large))
                // .add_test(systest!(
                //     test_transform_that_bloats_response_above_2mb_limit
                // ))
                // .add_test(systest!(test_non_existing_transform_function))
                // .add_test(systest!(test_post_request))
                // .add_test(systest!(test_http_endpoint_response_is_too_large))
                // .add_test(systest!(
                //     test_http_endpoint_with_delayed_response_is_rejected
                // ))
                // .add_test(systest!(test_that_redirects_are_not_followed))
                // .add_test(systest!(test_http_calls_to_ic_fails)),
                .add_test(systest!(test_invalid_domain_name))
                .add_test(systest!(test_invalid_ip))
                .add_test(systest!(test_get_hello_world_call))
                .add_test(systest!(test_post_call))
                .add_test(systest!(test_small_maximum_possible_response_size))
                .add_test(systest!(test_small_maximum_possible_response_size_exceeded))
                .add_test(systest!(test_head_call)),
        )
        .execute_from_args()?;

    Ok(())
}

pub fn test_enforce_https(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("http://[{webserver_ipv6}]:20443"),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Err((RejectionCode::SysFatal, _)));
}

pub fn test_transform_function_is_executed(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443"),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "test_transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    let response = response.expect("Http call should succeed");

    assert_eq!(response.headers.len(), 2, "Headers: {:?}", response.headers);
    assert_eq!(response.headers[0].0, "hello");
    assert_eq!(response.headers[0].1, "bonjour");
    assert_eq!(response.headers[1].0, "caller");
    assert_eq!(response.headers[1].1, "aaaaa-aa");
}

pub fn test_composite_transform_function_is_executed(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443"),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "test_composite_transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    let response = response.expect("Http call should succeed");

    assert_eq!(response.headers.len(), 2, "Headers: {:?}", response.headers);
    assert_eq!(response.headers[0].0, "hello");
    assert_eq!(response.headers[0].1, "bonjour");
    assert_eq!(response.headers[1].0, "caller");
    assert_eq!(response.headers[1].1, "aaaaa-aa");
}

pub fn test_no_cycles_attached(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("http://[{webserver_ipv6}]:20443"),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 0,
        },
    ));

    assert_matches!(response, Err((RejectionCode::CanisterReject, _)));
}

pub fn test_max_possible_request_size(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let headers_list = vec![
        ("name1".to_string(), "value1".to_string()),
        ("name2".to_string(), "value2".to_string()),
    ];

    let header_list_size = headers_list
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum::<usize>();

    let request_headers = headers_list
        .into_iter()
        .map(|(name, value)| HttpHeader { name, value })
        .collect();

    let body = vec![0; MAX_REQUEST_BYTES_LIMIT - header_list_size];

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443/request_size"),
                headers: BoundedHttpHeaders::new(request_headers),
                method: HttpMethod::POST,
                body: Some(body),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Ok(r) if r.status==200);
}

pub fn test_max_possible_request_size_exceeded(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let headers_list = vec![
        ("name1".to_string(), "value1".to_string()),
        ("name2".to_string(), "value2".to_string()),
    ];

    let header_list_size = headers_list
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum::<usize>();

    let request_headers = headers_list
        .into_iter()
        .map(|(name, value)| HttpHeader { name, value })
        .collect();

    let body = vec![0; MAX_REQUEST_BYTES_LIMIT - header_list_size + 1];

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443/request_size"),
                headers: BoundedHttpHeaders::new(request_headers),
                method: HttpMethod::POST,
                body: Some(body),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Err((RejectionCode::CanisterReject, _)));
}

pub fn test_2mb_response_cycle_for_rejection_path(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let request = CanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]:20443"),
        headers: BoundedHttpHeaders::new(vec![]),
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: get_proxy_canister_id(&env).into(),
                method: "transform".to_string(),
            }),
            context: vec![0, 1, 2],
        }),
        max_response_bytes: None,
    };

    let response = block_on(async move {
        submit_outcall(
            &handlers.proxy_canister(),
            RemoteHttpRequest {
                request: request.clone(),
                cycles: expected_cycle_cost(
                    handlers.proxy_canister().canister_id(),
                    request,
                    handlers.subnet_size,
                ) - 1,
            },
        )
        .await
    });

    assert_matches!(response, Err((RejectionCode::CanisterReject, _)));
}

pub fn test_4096_max_response_cycle_case_1(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let request = CanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]:20443"),
        headers: BoundedHttpHeaders::new(vec![]),
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: get_proxy_canister_id(&env).into(),
                method: "transform".to_string(),
            }),
            context: vec![0, 1, 2],
        }),
        max_response_bytes: Some(16384),
    };

    let response = block_on(async move {
        submit_outcall(
            &handlers.proxy_canister(),
            RemoteHttpRequest {
                request: request.clone(),
                cycles: expected_cycle_cost(
                    handlers.proxy_canister().canister_id(),
                    request.clone(),
                    handlers.subnet_size,
                ),
            },
        )
        .await
    });

    assert_matches!(response, Ok(r) if r.status==200);
}

pub fn test_4096_max_response_cycle_case_2(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let request = CanisterHttpRequestArgs {
        url: format!("https://[{webserver_ipv6}]:20443"),
        headers: BoundedHttpHeaders::new(vec![]),
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: get_proxy_canister_id(&env).into(),
                method: "transform".to_string(),
            }),
            context: vec![0, 1, 2],
        }),
        max_response_bytes: Some(16384),
    };

    let response = block_on(async move {
        submit_outcall(
            &handlers.proxy_canister(),
            RemoteHttpRequest {
                request: request.clone(),
                cycles: expected_cycle_cost(
                    handlers.proxy_canister().canister_id(),
                    request.clone(),
                    handlers.subnet_size,
                ) - 1,
            },
        )
        .await
    });
    assert_matches!(response, Err((RejectionCode::CanisterReject, _)));
}

pub fn test_max_response_limit_too_large(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443"),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: Some(4 * 1024 * 1024),
            },
            cycles: 0,
        },
    ));

    assert_matches!(response, Err((RejectionCode::CanisterReject, _)));
}

pub fn test_transform_that_bloats_response_above_2mb_limit(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443"),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "bloat_transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Err((RejectionCode::SysFatal, _)));
}

pub fn test_non_existing_transform_function(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443"),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "idontexist".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Err((RejectionCode::CanisterError, _)))
}

pub fn test_post_request(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443/post"),
                headers: BoundedHttpHeaders::new(vec![HttpHeader {
                    name: "content-type".to_string(),
                    value: "application/x-www-form-urlencoded".to_string(),
                }]),
                method: HttpMethod::POST,
                body: Some("satoshi".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Ok(r) if r.body.contains("satoshi"));
}

pub fn test_http_endpoint_response_is_too_large(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443/bytes/100000"),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: Some(8 * 1024),
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Err((RejectionCode::SysFatal, _)));
}

pub fn test_http_endpoint_with_delayed_response_is_rejected(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443/delay/40"),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Err((RejectionCode::SysFatal, _)));
}

/// The adapter should not follow HTTP redirects.
pub fn test_that_redirects_are_not_followed(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://[{webserver_ipv6}]:20443/redirect/10"),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Ok(r) if r.status == 303);
}

/// The adapter should reject HTTP calls that are made to other IC replicas' HTTPS endpoints.
pub fn test_http_calls_to_ic_fails(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://[{}]:9090", webserver_ipv6),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    let expected_error_message = "Error(Connect, ConnectError(\"tcp connect error\", Os { code: 111, kind: ConnectionRefused, message: \"Connection refused\" }))";
    let err_response = response.clone().unwrap_err();
    assert_matches!(err_response.0, RejectionCode::SysTransient);

    assert!(
        err_response.1.contains(expected_error_message),
        "Expected error message to contain, {}, got: {}",
        expected_error_message,
        err_response.1
    );
}

// ---- BEGIN SPEC COMPLIANCE TESTS ----
fn test_invalid_domain_name(env: TestEnv) {
    let handlers = Handlers::new(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://xwWPqqbNqxxHmLXdguF4DN9xGq22nczV.com"),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Err((RejectionCode::SysTransient, _)));
}

fn test_invalid_ip(env: TestEnv) {
    let handlers = Handlers::new(&env);

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url: format!("https://240.0.0.0"),
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: Some("".as_bytes().to_vec()),
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Err((RejectionCode::SysTransient, _)));
}

/// Test that the response body returned is the same as the requested path.
fn test_get_hello_world_call(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let expected_body = "hello_world";

    let url = format!(
        "https://[{}]:20443/{}/{}",
        webserver_ipv6, "ascii", expected_body
    );

    let max_response_bytes = 666;

    let request = CanisterHttpRequestArgs {
        url,
        headers: BoundedHttpHeaders::new(vec![]),
        method: HttpMethod::GET,
        body: Some("".as_bytes().to_vec()),
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: get_proxy_canister_id(&env).into(),
                method: "transform".to_string(),
            }),
            context: vec![0, 1, 2],
        }),
        max_response_bytes: Some(max_response_bytes),
    };

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: request.clone(),
            cycles: 500_000_000_000,
        },
    ))
    .expect("Request is successful.");

    assert_matches!(&response, RemoteHttpResponse {body, status: 200, ..} if body == expected_body);
    assert_distinct_headers(&response);
}

fn test_post_call(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);
    let expected_body = "POST";

    let url = format!("https://[{}]:20443/{}", webserver_ipv6, "anything");
    let body = Some("hello_world".as_bytes().to_vec());
    let headers = BoundedHttpHeaders::new(vec![
        HttpHeader {
            name: "name1".to_string(),
            value: "value1".to_string(),
        },
        HttpHeader {
            name: "name2".to_string(),
            value: "value2".to_string(),
        },
    ]);
    let max_response_bytes = Some(666);

    let request = CanisterHttpRequestArgs {
        url,
        headers,
        method: HttpMethod::POST,
        body,
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                principal: get_proxy_canister_id(&env).into(),
                method: "transform".to_string(),
            }),
            context: vec![0, 1, 2],
        }),
        max_response_bytes,
    };

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: request.clone(),
            cycles: 500_000_000_000,
        },
    ))
    .expect("Request succeeds.");

    assert_matches!(&response, RemoteHttpResponse {body, status: 200, ..} if body.contains(expected_body));
    assert_distinct_headers(&response);
    assert_http_json_response(&request, &response);
}

fn test_head_call(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!("https://[{}]:20443/{}", webserver_ipv6, "anything");

    let headers_list = vec![
        ("name1".to_string(), "value1".to_string()),
        ("name2".to_string(), "value2".to_string()),
    ];

    let request_headers: Vec<_> = headers_list
        .clone()
        .into_iter()
        .map(|(name, value)| HttpHeader { name, value })
        .collect();

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url,
                headers: BoundedHttpHeaders::new(request_headers),
                method: HttpMethod::HEAD,
                body: None,
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: None,
            },
            cycles: 500_000_000_000,
        },
    ))
    .expect("Request is successful.");

    assert_eq!(response.status, 200);
    assert_matches!(
        response.body,
        body if headers_list.iter().all(|(name, value)| { body.contains(name) && body.contains(value) })
    );
}

fn test_small_maximum_possible_response_size(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!(
        "https://[{}]:20443/{}/{}",
        webserver_ipv6, "ascii", "hello_world"
    );

    // Response headers (size: 158):
    //   date: Jan 1 1970 00:00:00 GMT
    //   content-type: application/octet-stream
    //   content-length: 11
    //   connection: close
    //   access-control-allow-origin: *
    //   access-control-allow-credentials: true

    let header_size = 158;

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url,
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: None,
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: Some(header_size),
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Ok(response) if response.status == 200);
}

fn test_small_maximum_possible_response_size_exceeded(env: TestEnv) {
    let handlers = Handlers::new(&env);
    let webserver_ipv6 = get_universal_vm_address(&env);

    let url = format!(
        "https://[{}]:20443/{}/{}",
        webserver_ipv6, "ascii", "hello_world"
    );

    // Response headers (size: 158):
    //   date: Jan 1 1970 00:00:00 GMT
    //   content-type: application/octet-stream
    //   content-length: 11
    //   connection: close
    //   access-control-allow-origin: *
    //   access-control-allow-credentials: true

    let header_size = 158;

    let response = block_on(submit_outcall(
        &handlers.proxy_canister(),
        RemoteHttpRequest {
            request: CanisterHttpRequestArgs {
                url,
                headers: BoundedHttpHeaders::new(vec![]),
                method: HttpMethod::GET,
                body: None,
                transform: Some(TransformContext {
                    function: TransformFunc(candid::Func {
                        principal: get_proxy_canister_id(&env).into(),
                        method: "transform".to_string(),
                    }),
                    context: vec![0, 1, 2],
                }),
                max_response_bytes: Some(header_size - 1),
            },
            cycles: 500_000_000_000,
        },
    ));

    assert_matches!(response, Err((RejectionCode::SysFatal, _)));
}

// ---- END SPEC COMPLIANCE TESTS -------

/// Case insensitive header names are distinct.
fn assert_distinct_headers(http_response: &RemoteHttpResponse) {
    // let response_body: Value =
    //     serde_json::from_str(&http_response.body).expect("Response body is JSON");

    // let headers: Vec<_> = response_body["headers"]
    //     .as_object()
    //     .expect("Headers are an object")
    //     .iter()
    //     .map(|(name, value)| {
    //         (
    //             name.to_string(),
    //             value
    //                 .as_str()
    //                 .expect("Header value is a string")
    //                 .to_string(),
    //         )
    //     })
    //     .collect();

    let response_header_set: HashSet<String> = http_response
        .headers
        .clone()
        .iter()
        .map(|(name, _)| name.to_lowercase())
        .collect();

    assert_eq!(
        response_header_set.len(),
        http_response.headers.len(),
        "Found duplicate headers: {:?}",
        http_response.headers
    );
}

// TODO: REMOVE THIS FUNCTION. CONTENT-LENGTH HEADER IS NOT USED IN
// HTTP/2.0 AND ABOVE.
/// Assert that content-length header matches the body length, and that the headers are distinct.
// fn assert_http_response(
//     // http_request: &CanisterHttpRequestArgs,
//     http_response: &RemoteHttpResponse,
// ) {
//     assert_distinct_header(http_response);

//     // let response_body: Value =
//     //     serde_json::from_str(&http_response.body).expect("Response body is JSON");

//     // let content_length_header = response_body["headers"]
//     //     .as_object()
//     //     .expect("Headers are an object")
//     //     .iter()
//     //     .map(|(name, value)| {
//     //         (
//     //             name.to_string(),
//     //             value
//     //                 .as_str()
//     //                 .expect("Header value is a string")
//     //                 .to_string(),
//     //         )
//     //     })
//     //     .find(|(name, _)| name.to_lowercase() == "content-length")
//     //     .map(|(_, value)| value.parse::<usize>().expect("Content length is a number"))
//     //     .expect("HTTP response must contain a \"content-length\" header");

//     let content_length_header = http_response
//         .headers
//         .iter()
//         .find(|(name, _)| name.to_lowercase() == "content-length")
//         .map(|(_, value)| value.parse::<usize>())
//         .expect(
//             format!(
//                 "HTTP response contains `content-length` header. Headers: {:?}",
//                 http_response.headers
//             )
//             .as_str(),
//         )
//         .expect("content-length is a number");

//     assert_eq!(
//         content_length_header,
//         http_response.body.len(),
//         "Content length header does not match the body length."
//     );
// }

/// Checks if two sets of headers match according to specific rules:
/// 1. All headers in `outcall_headers` must exist in `http_bin_server_received_headers`
/// 2. All headers in `http_bin_server_received_headers` must exist in `outcall_headers`, unless they are special cases:
/// - "host"
/// - "content-length"
/// - "accept-encoding"
/// - "user-agent" with value "ic/1.0"
/// 3. Request method must match the method in the response.
/// 4. Request body must match the body in the response.
fn assert_http_json_response(
    request: &CanisterHttpRequestArgs,
    http_response: &RemoteHttpResponse,
) {
    let request_headers = request
        .headers
        .get()
        .iter()
        .map(|HttpHeader { name, value }| (name.clone(), value.clone()))
        .collect::<Vec<_>>();

    let response_body: Value =
        serde_json::from_str(&http_response.body).expect("Response body is JSON formatted.");

    let http_bin_server_received_headers: Vec<_> = response_body["headers"]
        .as_object()
        .expect("Headers is an object")
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                value
                    .as_str()
                    .expect("Header value is a string")
                    .to_string(),
            )
        })
        .collect();

    // Rule 1: Check that all left headers exist in right
    let http_bin_server_received_all_outcall_headers = request_headers
        .iter()
        .all(|x| http_bin_server_received_headers.contains(x));

    assert!(
        http_bin_server_received_all_outcall_headers,
        "1. HTTP bin server did not receive all headers specified in the outcall. Specified headers: {:?}, received headers: {:?}",
        request_headers,
        http_bin_server_received_headers
    );

    // Rule 2: Check that all headers received by the server was specified in outcall.
    let http_bin_server_only_received_headers_specified_by_outcall =
        http_bin_server_received_headers
            .iter()
            .filter(|(name, value)| {
                !matches!(
                    (name.as_str(), value.as_str()),
                    ("host", _)
                        | ("content-length", _)
                        | ("accept-encoding", _)
                        | ("user-agent", "ic/1.0")
                )
            })
            .all(|(name, value)| request_headers.contains(&(name.clone(), value.clone())));

    assert!(http_bin_server_only_received_headers_specified_by_outcall,
        "2. Http bin server received headers that were not specified in the outcall. Specified headers: {:?}, received headers: {:?}",
        request_headers,
        http_bin_server_received_headers);

    let request_method = match request.method {
        HttpMethod::GET => "GET",
        HttpMethod::POST => "POST",
        HttpMethod::HEAD => "HEAD",
    };

    assert_eq!(
        request_method,
        response_body["method"].as_str().unwrap(),
        "3. Mismatch in HTTP method."
    );

    let server_received_body = response_body["data"].as_str().unwrap();
    let outcall_sent_body = String::from_utf8(request.body.clone().unwrap_or_default()).unwrap();

    assert_eq!(
        server_received_body, &outcall_sent_body,
        "4. HTTP bin server received body does not match the outcall sent body."
    );
}
type OutcallsResponse = Result<RemoteHttpResponse, (RejectionCode, String)>;

async fn submit_outcall(
    proxy_canister: &Canister<'_>,
    request: RemoteHttpRequest,
) -> OutcallsResponse {
    proxy_canister
        .update_(
            "send_request",
            candid_one::<OutcallsResponse, RemoteHttpRequest>,
            request.clone(),
        )
        .await
        .expect("Request completes.")
}

/// Pricing function of canister http requests.
fn expected_cycle_cost(
    proxy_canister: CanisterId,
    request: CanisterHttpRequestArgs,
    subnet_size: usize,
) -> u64 {
    let cm = CyclesAccountManagerBuilder::new().build();
    let response_size = request
        .max_response_bytes
        .unwrap_or(MAX_CANISTER_HTTP_REQUEST_BYTES);

    let dummy_context = CanisterHttpRequestContext::try_from((
        UNIX_EPOCH,
        &RequestBuilder::default()
            .receiver(CanisterId::from(1))
            .sender(proxy_canister)
            .build(),
        request,
    ))
    .unwrap();
    let req_size = dummy_context.variable_parts_size();
    let cycle_fee = cm.http_request_fee(req_size, Some(NumBytes::from(response_size)), subnet_size);
    cycle_fee.get().try_into().unwrap()
}
