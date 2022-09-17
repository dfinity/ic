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

use crate::canister_http::lib::*;
use crate::driver::{
    test_env::TestEnv,
    test_env_api::{retry_async, RETRY_BACKOFF},
};
use crate::util::block_on;
use anyhow::bail;
use candid;
use canister_test::Canister;
use dfn_candid::candid_one;
use ic_base_types::CanisterId;
use ic_cdk::api::call::RejectionCode;
use ic_ic00_types::{
    CanisterHttpRequestArgs, HttpHeader, HttpMethod, TransformFunc, TransformType,
};
use ic_test_utilities::{mock_time, types::messages::RequestBuilder};
use ic_types::canister_http::CanisterHttpRequestContext;
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use slog::{info, Logger};
use std::convert::TryFrom;
use std::time::Duration;

/// Pricing function of canister http requests.
fn expected_cycle_cost(proxy_canister: CanisterId, request: CanisterHttpRequestArgs) -> u64 {
    let response_size = request.max_response_bytes.unwrap_or(2 * 1024 * 1024);

    let dummy_context = CanisterHttpRequestContext::try_from((
        mock_time(),
        &RequestBuilder::default()
            .receiver(CanisterId::from(1))
            .sender(proxy_canister)
            .build(),
        request,
    ))
    .unwrap();
    let req_size = dummy_context.variable_parts_size().get();

    // 400M is the base fee for a requests
    // 100k is the dynamic factor to represent resource usage
    400_000_000 + (req_size as u64 + response_size) * 100_000
}

pub fn test(env: TestEnv) {
    let logger = env.logger();
    let mut nodes = get_node_snapshots(&env);
    let node = nodes.next().expect("there is no application node");
    let runtime = get_runtime_from_node(&node);
    let proxy_canister = create_proxy_canister(&env, &runtime, &node);
    let webserver_ipv6 = get_universal_vm_address(&env);

    block_on(async {
        let mut test_results = vec![];
        // Test: https enforcement
        test_results.push(
            test_canister_http_property(
                "Enforce HTTPS",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: CanisterHttpRequestArgs {
                        url: format!("http://[{webserver_ipv6}]:20443"),
                        headers: vec![],
                        method: HttpMethod::GET,
                        body: Some("".as_bytes().to_vec()),
                        transform: Some(TransformType::Function(TransformFunc(candid::Func {
                            principal: proxy_canister.canister_id().get().0,
                            method: "transform".to_string(),
                        }))),
                        max_response_bytes: None,
                    },
                    cycles: 500_000_000_000,
                },
                |response| matches!(response, Err((RejectionCode::SysFatal, _))),
            )
            .await,
        );
        // Test: check that transform is actually executed
        test_results.push(
            test_canister_http_property(
                "Check that transform is executed",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: CanisterHttpRequestArgs {
                        url: format!("https://[{webserver_ipv6}]:20443"),
                        headers: vec![],
                        method: HttpMethod::GET,
                        body: Some("".as_bytes().to_vec()),
                        transform: Some(TransformType::Function(TransformFunc(candid::Func {
                            principal: proxy_canister.canister_id().get().0,
                            method: "test_transform".to_string(),
                        }))),
                        max_response_bytes: None,
                    },
                    cycles: 500_000_000_000,
                },
                |response| {
                    let r = response.clone().expect("Http call should suceed");
                    r.headers.len() == 1 && r.headers[0].0 == "hello" && r.headers[0].1 == "bonjour"
                },
            )
            .await,
        );
        // Test: No cycles
        test_results.push(
            test_canister_http_property(
                "No cycles attached",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: CanisterHttpRequestArgs {
                        url: format!("http://[{webserver_ipv6}]:20443"),
                        headers: vec![],
                        method: HttpMethod::GET,
                        body: Some("".as_bytes().to_vec()),
                        transform: Some(TransformType::Function(TransformFunc(candid::Func {
                            principal: proxy_canister.canister_id().get().0,
                            method: "transform".to_string(),
                        }))),
                        max_response_bytes: None,
                    },
                    cycles: 0,
                },
                |response| matches!(response, Err((RejectionCode::CanisterReject, _))),
            )
            .await,
        );
        // Test: Priceing without max_response specified
        // Formula: 400M + (2*response_size_limit + 2*request_size) * 50000
        let request = CanisterHttpRequestArgs {
            url: format!("https://[{webserver_ipv6}]:20443"),
            headers: vec![],
            method: HttpMethod::GET,
            body: Some("".as_bytes().to_vec()),
            transform: Some(TransformType::Function(TransformFunc(candid::Func {
                principal: proxy_canister.canister_id().get().0,
                method: "transform".to_string(),
            }))),
            max_response_bytes: None,
        };
        test_results.push(
            test_canister_http_property(
                "2Mb response cycle test for success path",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: request.clone(),
                    cycles: expected_cycle_cost(proxy_canister.canister_id(), request.clone()),
                },
                |response| matches!(response, Ok(r) if r.status==200),
            )
            .await,
        );
        test_results.push(
            test_canister_http_property(
                "2Mb response cycle test for rejection case",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: request.clone(),
                    cycles: expected_cycle_cost(proxy_canister.canister_id(), request.clone()) - 1,
                },
                |response| matches!(response, Err((RejectionCode::CanisterReject, _))),
            )
            .await,
        );
        // Test: Priceing with max response size specified
        // Formula: 400M + (2*response_size_limit + 2*request_size) * 50000
        let request = CanisterHttpRequestArgs {
            url: format!("https://[{webserver_ipv6}]:20443"),
            headers: vec![],
            method: HttpMethod::GET,
            body: Some("".as_bytes().to_vec()),
            transform: Some(TransformType::Function(TransformFunc(candid::Func {
                principal: proxy_canister.canister_id().get().0,
                method: "transform".to_string(),
            }))),
            max_response_bytes: Some(16384),
        };
        test_results.push(
            test_canister_http_property(
                "4096 max response cycle test 1/2",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: request.clone(),
                    cycles: expected_cycle_cost(proxy_canister.canister_id(), request.clone()),
                },
                |response| matches!(response, Ok(r) if r.status==200),
            )
            .await,
        );
        test_results.push(
            test_canister_http_property(
                "4096 max response cycle test 2/2",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: request.clone(),
                    cycles: expected_cycle_cost(proxy_canister.canister_id(), request.clone()) - 1,
                },
                |response| matches!(response, Err((RejectionCode::CanisterReject, _))),
            )
            .await,
        );
        // Test: Max response limit larger than allowed
        test_results.push(
            test_canister_http_property(
                "Max response limit too large",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: CanisterHttpRequestArgs {
                        url: format!("https://[{webserver_ipv6}]:20443"),
                        headers: vec![],
                        method: HttpMethod::GET,
                        body: Some("".as_bytes().to_vec()),
                        transform: Some(TransformType::Function(TransformFunc(candid::Func {
                            principal: proxy_canister.canister_id().get().0,
                            method: "transform".to_string(),
                        }))),
                        max_response_bytes: Some(4 * 1024 * 1024),
                    },
                    cycles: 0,
                },
                |response| matches!(response, Err((RejectionCode::CanisterReject, _))),
            )
            .await,
        );
        // Test: Use transform that bloats response above 2Mb limit.
        test_results.push(
            test_canister_http_property(
                "Bloat transform function",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: CanisterHttpRequestArgs {
                        url: format!("https://[{webserver_ipv6}]:20443"),
                        headers: vec![],
                        method: HttpMethod::GET,
                        body: Some("".as_bytes().to_vec()),
                        transform: Some(TransformType::Function(TransformFunc(candid::Func {
                            principal: proxy_canister.canister_id().get().0,
                            method: "bloat_transform".to_string(),
                        }))),
                        max_response_bytes: None,
                    },
                    cycles: 500_000_000_000,
                },
                |response| matches!(response, Err((RejectionCode::SysFatal, _))),
            )
            .await,
        );
        // Test: Nonexisting transform.
        test_results.push(
            test_canister_http_property(
                "Non existing transform function",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: CanisterHttpRequestArgs {
                        url: format!("https://[{webserver_ipv6}]:20443"),
                        headers: vec![],
                        method: HttpMethod::GET,
                        body: Some("".as_bytes().to_vec()),
                        transform: Some(TransformType::Function(TransformFunc(candid::Func {
                            principal: proxy_canister.canister_id().get().0,
                            method: "idontexist".to_string(),
                        }))),
                        max_response_bytes: None,
                    },
                    cycles: 500_000_000_000,
                },
                |response| matches!(response, Err((RejectionCode::DestinationInvalid, _))),
            )
            .await,
        );
        // Test: Post request.
        test_results.push(
            test_canister_http_property(
                "POST request",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: CanisterHttpRequestArgs {
                        url: format!("https://[{webserver_ipv6}]:20443/post"),
                        headers: vec![HttpHeader {
                            name: "Content-Type".to_string(),
                            value: "application/x-www-form-urlencoded".to_string(),
                        }],
                        method: HttpMethod::POST,
                        body: Some("satoshi=me".as_bytes().to_vec()),
                        transform: Some(TransformType::Function(TransformFunc(candid::Func {
                            principal: proxy_canister.canister_id().get().0,
                            method: "transform".to_string(),
                        }))),
                        max_response_bytes: None,
                    },
                    cycles: 500_000_000_000,
                },
                |response| matches!(response, Ok(r) if r.body.contains("satoshi")),
            )
            .await,
        );
        // Test: Return response that is too large.
        test_results.push(
            test_canister_http_property(
                "Http endpoint response too large",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: CanisterHttpRequestArgs {
                        url: format!("https://[{webserver_ipv6}]:20443/bytes/100000"),
                        headers: vec![],
                        method: HttpMethod::GET,
                        body: Some("".as_bytes().to_vec()),
                        transform: Some(TransformType::Function(TransformFunc(candid::Func {
                            principal: proxy_canister.canister_id().get().0,
                            method: "transform".to_string(),
                        }))),
                        max_response_bytes: Some(8 * 1024),
                    },
                    cycles: 500_000_000_000,
                },
                |response| matches!(response, Err((RejectionCode::SysFatal, _))),
            )
            .await,
        );
        // Test: Delay response.
        // TODO: This currently traps the proxy canister. Modify proxy canister to return byte response.
        test_results.push(
            test_canister_http_property(
                "Http endpoint with delay",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: CanisterHttpRequestArgs {
                        url: format!("https://[{webserver_ipv6}]:20443/delay/9"),
                        headers: vec![],
                        method: HttpMethod::GET,
                        body: Some("".as_bytes().to_vec()),
                        transform: Some(TransformType::Function(TransformFunc(candid::Func {
                            principal: proxy_canister.canister_id().get().0,
                            method: "transform".to_string(),
                        }))),
                        max_response_bytes: None,
                    },
                    cycles: 500_000_000_000,
                },
                |response| matches!(response, Err((RejectionCode::SysFatal, _))),
            )
            .await,
        );
        // Test: Don't follow redirects.
        test_results.push(
            test_canister_http_property(
                "Http endpoint that does redirects",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: CanisterHttpRequestArgs {
                        url: format!("https://[{webserver_ipv6}]:20443/redirect/10"),
                        headers: vec![],
                        method: HttpMethod::GET,
                        body: Some("".as_bytes().to_vec()),
                        transform: Some(TransformType::Function(TransformFunc(candid::Func {
                            principal: proxy_canister.canister_id().get().0,
                            method: "transform".to_string(),
                        }))),
                        max_response_bytes: None,
                    },
                    cycles: 500_000_000_000,
                },
                |response| matches!(response, Ok(r) if r.body.contains("Redirecting")),
            )
            .await,
        );
        // Test: Drip response. 100 Bytes with 1s between byte
        test_results.push(
            test_canister_http_property(
                "Http endpoint that slowly drips response",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: CanisterHttpRequestArgs {
                        url: format!(
                            "https://[{webserver_ipv6}]:20443/drip?duration=100&numbytes=100"
                        ),
                        headers: vec![],
                        method: HttpMethod::GET,
                        body: Some("".as_bytes().to_vec()),
                        transform: Some(TransformType::Function(TransformFunc(candid::Func {
                            principal: proxy_canister.canister_id().get().0,
                            method: "transform".to_string(),
                        }))),
                        max_response_bytes: None,
                    },
                    cycles: 500_000_000_000,
                },
                |response| matches!(response, Err((RejectionCode::SysFatal, _))),
            )
            .await,
        );
        // Verifies HTTPS call to replica HTTPS service fails
        test_results.push(
            test_canister_http_property(
                "No HTTP calls to IC",
                &logger,
                &proxy_canister,
                RemoteHttpRequest {
                    request: CanisterHttpRequestArgs {
                        url: format!("https://[{}]:9090", node.get_ip_addr()),
                        headers: vec![],
                        method: HttpMethod::GET,
                        body: Some("".as_bytes().to_vec()),
                        transform: Some(TransformType::Function(TransformFunc(candid::Func {
                            principal: proxy_canister.canister_id().get().0,
                            method: "transform".to_string(),
                        }))),
                        max_response_bytes: None,
                    },
                    cycles: 500_000_000_000,
                },
                |response| {
                    let err_response = response.clone().unwrap_err();
                    matches!(err_response.0, RejectionCode::SysTransient)
                        && err_response.1.contains("Connection refused")
                },
            )
            .await,
        );

        // Check tests results
        assert!(
            test_results.iter().all(|&a| a),
            "{} out of {} canister http correctness tests were successful",
            test_results.iter().filter(|&b| *b).count(),
            test_results.len()
        );
    });
}

async fn test_canister_http_property<F>(
    test_name: &str,
    logger: &Logger,
    proxy_canister: &Canister<'_>,
    request: RemoteHttpRequest,
    response_check: F,
) -> bool
where
    F: Fn(&Result<RemoteHttpResponse, (RejectionCode, String)>) -> bool,
{
    info!(logger.clone(), "Running correctness test: {}", test_name);
    let test_result = retry_async(logger, Duration::from_secs(60), RETRY_BACKOFF, || async {
        let res =
            proxy_canister
                .update_(
                    "send_request",
                    candid_one::<
                        Result<RemoteHttpResponse, (RejectionCode, String)>,
                        RemoteHttpRequest,
                    >,
                    request.clone(),
                )
                .await
                .expect("Update call to proxy canister failed");
        if !response_check(&res) {
            bail!("Http request didn't pass check: {:?}", &res);
        }
        Ok(())
    })
    .await;

    match test_result {
        Err(_) => {
            info!(logger.clone(), "Correctness failed: {}", test_name);
            false
        }
        Ok(_) => {
            info!(logger.clone(), "Correctness test succeeded: {}", test_name,);
            true
        }
    }
}
