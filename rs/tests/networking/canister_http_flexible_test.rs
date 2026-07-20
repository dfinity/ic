/* tag::catalog[]
Title:: Flexible HTTP outcalls.

Goal:: Exhaustively exercise the `flexible_http_request` management canister
endpoint on a free subnet (where flexible outcalls fall back to legacy pricing).

Runbook::
0. Instantiate a universal VM with a webserver (httpbin).
1. Instantiate an IC with one application subnet (4 nodes, free cost schedule)
   with the HTTP feature enabled.
2. Install NNS canisters.
3. Install the proxy canister.
4. Make flexible HTTP outcalls through the proxy canister covering:
   - success across replication parameters and HTTP methods,
   - synchronous validation rejections,
   - runtime errors (too many rejects, responses too large),
   - adapter-level per-node failures.

Success::
1. Each scenario returns the expected `FlexibleHttpRequestResult` (or rejection).

end::catalog[] */
#![allow(deprecated)]

use anyhow::{Result, bail};
use candid::{Decode, Principal};
use canister_http::*;
use canister_test::{Canister, Runtime};
use dfn_candid::candid_one;
use ic_cdk::api::call::RejectionCode;
use ic_management_canister_types_private::{
    BoundedHttpHeaders, CanisterHttpResponsePayload, FlexibleCanisterHttpRequestArgs,
    FlexibleHttpGlobalError, FlexibleHttpRequestErr, FlexibleHttpRequestResult, HttpHeader,
    HttpMethod, ReplicationCounts, TransformContext, TransformFunc,
};
use ic_system_test_driver::driver::group::{SystemTestGroup, SystemTestSubGroup};
use ic_system_test_driver::driver::{
    test_env::TestEnv,
    test_env_api::{READY_WAIT_TIMEOUT, RETRY_BACKOFF},
};
use ic_system_test_driver::systest;
use ic_system_test_driver::util::block_on;
use proxy_canister::FlexibleRemoteHttpRequest;
use slog::info;

/// The cycles attached to each flexible outcall. On a free subnet nothing is
/// charged, but the caller must still be able to attach the payment.
const CYCLES: u64 = 500_000_000_000;

/// The application subnet has 4 nodes (see `setup`). With the default
/// replication (`replication: None`) the committee is all `n` nodes,
/// `max_responses = n` and `min_responses = floor(2n/3) + 1`.
const SUBNET_NODES: u32 = 4;
const DEFAULT_MIN_RESPONSES: usize = 3; // floor(2*4/3) + 1
const DEFAULT_MAX_RESPONSES: usize = SUBNET_NODES as usize;

fn main() -> Result<()> {
    SystemTestGroup::new()
        // Flexible outcalls require the pay-as-you-go pricing model, which is
        // still gated. On a free subnet they are available via the legacy
        // pricing fallback, so the test runs on a free-cost-schedule subnet.
        .with_setup(canister_http::setup_with_free_cost_schedule)
        .add_parallel(
            SystemTestSubGroup::new()
                // Success across replication parameters and HTTP methods.
                .add_test(systest!(test_default_replication))
                .add_test(systest!(test_single_request))
                .add_test(systest!(test_all_nodes))
                .add_test(systest!(test_partial_responses))
                .add_test(systest!(test_intermediate_range))
                .add_test(systest!(test_post_with_body))
                .add_test(systest!(test_head_method))
                .add_test(systest!(test_put_with_deterministic_replication))
                .add_test(systest!(test_delete_with_deterministic_replication))
                .add_test(systest!(test_patch_with_deterministic_replication))
                .add_test(systest!(test_redirects_are_not_followed))
                .add_test(systest!(test_redirect_zero_no_content))
                .add_test(systest!(test_nondeterministic_responses))
                // Transform behavior.
                .add_test(systest!(test_transform_appends_context))
                .add_test(systest!(test_transform_sets_status_and_headers))
                .add_test(systest!(test_deterministic_transform_normalizes))
                // Synchronous validation rejections.
                .add_test(systest!(test_reject_total_requests_zero))
                .add_test(systest!(test_reject_total_requests_exceed_nodes))
                .add_test(systest!(test_reject_min_exceeds_max))
                .add_test(systest!(test_reject_max_exceeds_total))
                .add_test(systest!(test_reject_put_requires_deterministic))
                .add_test(systest!(test_reject_delete_non_deterministic))
                .add_test(systest!(test_reject_url_too_long))
                .add_test(systest!(test_reject_invalid_transform_principal))
                .add_test(systest!(test_reject_header_name_too_long))
                .add_test(systest!(test_reject_header_value_too_long))
                // Runtime errors and adapter-level per-node failures.
                .add_test(systest!(test_too_many_rejects_connection_refused))
                .add_test(systest!(test_too_many_rejects_invalid_domain))
                .add_test(systest!(test_too_many_rejects_response_over_node_limit))
                .add_test(systest!(test_too_many_rejects_transform_over_node_limit))
                .add_test(systest!(test_too_many_rejects_composite_transform))
                .add_test(systest!(test_responses_too_large)),
        )
        .execute_from_args()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns a runtime for one of the application-subnet nodes.
fn app_runtime(env: &TestEnv) -> Runtime {
    let node = get_node_snapshots(env)
        .next()
        .expect("there is no application node");
    get_runtime_from_node(&node)
}

/// Returns the proxy canister installed during setup.
fn proxy_canister<'a>(env: &TestEnv, runtime: &'a Runtime) -> Canister<'a> {
    let principal_id = get_proxy_canister_id(env);
    Canister::new(runtime, CanisterId::unchecked_from_principal(principal_id))
}

/// Base flexible request arguments: a `GET` with no headers, body, transform, or
/// explicit replication.
fn get_args(url: String) -> FlexibleCanisterHttpRequestArgs {
    FlexibleCanisterHttpRequestArgs {
        url,
        headers: BoundedHttpHeaders::new(vec![]),
        body: None,
        method: HttpMethod::GET,
        transform: None,
        replication: None,
    }
}

/// Sends a flexible outcall through the proxy canister and returns either the
/// decoded [`FlexibleHttpRequestResult`] (on a handled outcall) or the
/// synchronous rejection (on a validation failure).
async fn send_flexible(
    proxy: &Canister<'_>,
    args: FlexibleCanisterHttpRequestArgs,
    cycles: u64,
) -> Result<FlexibleHttpRequestResult, (RejectionCode, String)> {
    let res = proxy
        .update_(
            "send_flexible_request",
            candid_one::<Result<Vec<u8>, (RejectionCode, String)>, FlexibleRemoteHttpRequest>,
            FlexibleRemoteHttpRequest {
                request: args,
                cycles,
            },
        )
        .await
        .expect("Update call to proxy canister failed");

    res.map(|bytes| {
        candid::Decode!(&bytes, FlexibleHttpRequestResult)
            .expect("Failed to decode FlexibleHttpRequestResult")
    })
}

/// Runs `assert_result` against the outcome of the flexible outcall built by
/// `make_args`, retrying (to absorb transient startup/network flakiness) until
/// the expected outcome is observed or the retry budget is exhausted.
fn run_flexible_test<M, A>(env: TestEnv, description: &str, make_args: M, assert_result: A)
where
    M: Fn(&TestEnv) -> FlexibleCanisterHttpRequestArgs,
    A: Fn(Result<FlexibleHttpRequestResult, (RejectionCode, String)>) -> Result<()>,
{
    let logger = env.logger();
    let runtime = app_runtime(&env);
    let proxy = proxy_canister(&env, &runtime);

    block_on(async {
        ic_system_test_driver::retry_with_msg_async!(
            description.to_string(),
            &logger,
            READY_WAIT_TIMEOUT,
            RETRY_BACKOFF,
            || async {
                let args = make_args(&env);
                let result = send_flexible(&proxy, args, CYCLES).await;
                assert_result(result)
            }
        )
        .await
        .unwrap_or_else(|err| panic!("'{description}' did not reach the expected outcome: {err}"));
    });
}

/// The principal of the proxy canister (the sender of the outcalls), used as the
/// valid transform principal.
fn proxy_principal(env: &TestEnv) -> Principal {
    get_proxy_canister_id(env).0
}

/// Asserts the result is `Ok` with a payload count in `[min, max]` and returns
/// the payloads for further inspection.
fn expect_ok(
    result: Result<FlexibleHttpRequestResult, (RejectionCode, String)>,
    min: usize,
    max: usize,
) -> Result<Vec<CanisterHttpResponsePayload>> {
    match result {
        Ok(FlexibleHttpRequestResult::Ok(payloads)) => {
            if payloads.len() < min || payloads.len() > max {
                bail!(
                    "expected between {min} and {max} response payloads, got {}",
                    payloads.len()
                );
            }
            Ok(payloads)
        }
        other => bail!("expected Ok response payloads, got: {other:?}"),
    }
}

/// Asserts every payload has the given HTTP status.
fn expect_all_status(payloads: &[CanisterHttpResponsePayload], status: u128) -> Result<()> {
    for payload in payloads {
        if payload.status != status {
            bail!(
                "expected status {status} for every payload, got {}",
                payload.status
            );
        }
    }
    Ok(())
}

/// Asserts the result is a synchronous rejection whose message contains
/// `expected_substring`.
fn expect_rejection(
    result: Result<FlexibleHttpRequestResult, (RejectionCode, String)>,
    expected_substring: &str,
) -> Result<()> {
    match result {
        Err((code, message)) => {
            if message.contains(expected_substring) {
                Ok(())
            } else {
                bail!(
                    "rejection message '{message}' (code {code:?}) does not contain '{expected_substring}'"
                )
            }
        }
        other => bail!("expected a synchronous rejection, got: {other:?}"),
    }
}

/// Asserts the result is a runtime `FlexibleHttpRequestResult::Err` with the
/// given global error and a message containing `expected_substring`, and returns
/// the error for further inspection.
fn expect_global_error(
    result: Result<FlexibleHttpRequestResult, (RejectionCode, String)>,
    expected: &FlexibleHttpGlobalError,
    expected_substring: &str,
) -> Result<FlexibleHttpRequestErr> {
    match result {
        Ok(FlexibleHttpRequestResult::Err(err)) => {
            if err.global_error.as_ref() != Some(expected) {
                bail!(
                    "expected global error {expected:?}, got {:?} (message: '{}')",
                    err.global_error,
                    err.message
                );
            }
            if !err.message.contains(expected_substring) {
                bail!(
                    "error message '{}' does not contain '{expected_substring}'",
                    err.message
                );
            }
            Ok(err)
        }
        other => bail!("expected a FlexibleHttpRequestResult::Err, got: {other:?}"),
    }
}

/// Asserts every node in a runtime error carries an error whose message contains
/// `expected_substring`.
fn expect_all_node_errors_contain(
    err: &FlexibleHttpRequestErr,
    expected_substring: &str,
) -> Result<()> {
    if err.node_details.is_empty() {
        bail!("expected per-node error details");
    }
    for detail in &err.node_details {
        match &detail.error {
            Some(node_error) if node_error.message.contains(expected_substring) => {}
            other => bail!("node error {other:?} does not contain '{expected_substring}'"),
        }
    }
    Ok(())
}

fn webserver_base(env: &TestEnv) -> String {
    format!("https://[{}]", get_universal_vm_address(env))
}

// ---------------------------------------------------------------------------
// Success: replication parameters and HTTP methods
// ---------------------------------------------------------------------------

/// Default replication (`None`) returns between `min_responses` and
/// `max_responses` identical payloads for a deterministic endpoint.
fn test_default_replication(env: TestEnv) {
    let logger = env.logger();
    run_flexible_test(
        env,
        "default replication returns min..=max identical payloads",
        |env| get_args(format!("{}/ascii/hello_world", webserver_base(env))),
        move |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 200)?;
            for payload in &payloads {
                if payload.body != b"hello_world".to_vec() {
                    bail!(
                        "unexpected body: {:?}",
                        String::from_utf8_lossy(&payload.body)
                    );
                }
            }
            info!(
                logger,
                "default replication returned {} payloads",
                payloads.len()
            );
            Ok(())
        },
    );
}

/// A committee of a single node returns exactly one payload.
fn test_single_request(env: TestEnv) {
    run_flexible_test(
        env,
        "single-node replication returns exactly one payload",
        |env| {
            let mut args = get_args(format!("{}/ascii/single", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 1,
                min_responses: 1,
                max_responses: 1,
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 1, 1)?;
            expect_all_status(&payloads, 200)?;
            if payloads[0].body != b"single".to_vec() {
                bail!("unexpected body");
            }
            Ok(())
        },
    );
}

/// Requiring all nodes (`min == max == total == n`) returns exactly `n` payloads.
fn test_all_nodes(env: TestEnv) {
    run_flexible_test(
        env,
        "all-nodes replication returns exactly n payloads",
        |env| {
            let mut args = get_args(format!("{}/ascii/all", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: SUBNET_NODES,
                min_responses: SUBNET_NODES,
                max_responses: SUBNET_NODES,
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, SUBNET_NODES as usize, SUBNET_NODES as usize)?;
            expect_all_status(&payloads, 200)?;
            Ok(())
        },
    );
}

/// A partial range (`min < max < total`) returns between `min` and `max` payloads.
fn test_partial_responses(env: TestEnv) {
    run_flexible_test(
        env,
        "partial replication returns min..=max payloads",
        |env| {
            let mut args = get_args(format!("{}/ascii/partial", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 4,
                min_responses: 2,
                max_responses: 3,
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 2, 3)?;
            expect_all_status(&payloads, 200)?;
            Ok(())
        },
    );
}

/// A `POST` with a body succeeds.
fn test_post_with_body(env: TestEnv) {
    run_flexible_test(
        env,
        "POST with a body succeeds",
        |env| {
            let mut args = get_args(format!("{}/post", webserver_base(env)));
            args.method = HttpMethod::POST;
            args.body = Some(b"flexible-body".to_vec());
            args
        },
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 200)?;
            Ok(())
        },
    );
}

/// The transform function is applied to each response (here it appends the
/// context to the body and strips headers).
fn test_transform_appends_context(env: TestEnv) {
    run_flexible_test(
        env,
        "transform is applied to each response",
        |env| {
            let mut args = get_args(format!("{}/ascii/base", webserver_base(env)));
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "transform_with_context".to_string(),
                }),
                context: b"-ctx".to_vec(),
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 200)?;
            for payload in &payloads {
                if payload.body != b"base-ctx".to_vec() {
                    bail!(
                        "expected transformed body 'base-ctx', got {:?}",
                        String::from_utf8_lossy(&payload.body)
                    );
                }
                if !payload.headers.is_empty() {
                    bail!("expected transform to strip headers");
                }
            }
            Ok(())
        },
    );
}

/// `PUT` (like `DELETE`/`PATCH`) is only allowed with deterministic replication
/// (`min == max == total`); this exercises the allowed case.
fn test_put_with_deterministic_replication(env: TestEnv) {
    run_flexible_test(
        env,
        "PUT with deterministic replication succeeds",
        |env| {
            let mut args = get_args(format!("{}/anything", webserver_base(env)));
            args.method = HttpMethod::PUT;
            args.replication = Some(ReplicationCounts {
                total_requests: SUBNET_NODES,
                min_responses: SUBNET_NODES,
                max_responses: SUBNET_NODES,
            });
            // Strip the (non-deterministic) echoed request headers so every node
            // agrees on the response.
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, SUBNET_NODES as usize, SUBNET_NODES as usize)?;
            expect_all_status(&payloads, 200)?;
            Ok(())
        },
    );
}

/// The adapter does not follow redirects: a redirecting endpoint yields a 303.
fn test_redirects_are_not_followed(env: TestEnv) {
    run_flexible_test(
        env,
        "redirects are not followed (status 303)",
        |env| get_args(format!("{}/redirect/10", webserver_base(env))),
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 303)?;
            Ok(())
        },
    );
}

/// Flexible outcalls can aggregate differing responses: a non-deterministic
/// endpoint returns several (possibly different) payloads without diverging.
fn test_nondeterministic_responses(env: TestEnv) {
    run_flexible_test(
        env,
        "non-deterministic responses are aggregated",
        |env| {
            let mut args = get_args(format!("{}/random", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: SUBNET_NODES,
                min_responses: 2,
                max_responses: SUBNET_NODES,
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 2, SUBNET_NODES as usize)?;
            expect_all_status(&payloads, 200)?;
            Ok(())
        },
    );
}

/// An intermediate range (`min < max == total`) returns between `min` and `max`
/// payloads.
fn test_intermediate_range(env: TestEnv) {
    run_flexible_test(
        env,
        "intermediate replication returns min..=max payloads",
        |env| {
            let mut args = get_args(format!("{}/ascii/range", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 4,
                min_responses: 2,
                max_responses: 4,
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 2, 4)?;
            expect_all_status(&payloads, 200)?;
            Ok(())
        },
    );
}

/// A `HEAD` request succeeds. `HEAD` is not restricted to deterministic
/// replication (unlike `PUT`/`DELETE`/`PATCH`).
fn test_head_method(env: TestEnv) {
    run_flexible_test(
        env,
        "HEAD request succeeds",
        |env| {
            let mut args = get_args(format!("{}/anything", webserver_base(env)));
            args.method = HttpMethod::HEAD;
            // Strip the echoed request headers for cross-node agreement.
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 200)?;
            Ok(())
        },
    );
}

/// `DELETE` with deterministic replication (`min == max == total`) succeeds.
fn test_delete_with_deterministic_replication(env: TestEnv) {
    run_flexible_test(
        env,
        "DELETE with deterministic replication succeeds",
        |env| {
            let mut args = get_args(format!("{}/anything", webserver_base(env)));
            args.method = HttpMethod::DELETE;
            args.replication = Some(ReplicationCounts {
                total_requests: 2,
                min_responses: 2,
                max_responses: 2,
            });
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 2, 2)?;
            expect_all_status(&payloads, 200)?;
            Ok(())
        },
    );
}

/// `PATCH` with deterministic replication over a sub-committee succeeds.
fn test_patch_with_deterministic_replication(env: TestEnv) {
    run_flexible_test(
        env,
        "PATCH with deterministic replication succeeds",
        |env| {
            let mut args = get_args(format!("{}/anything", webserver_base(env)));
            args.method = HttpMethod::PATCH;
            args.replication = Some(ReplicationCounts {
                total_requests: 2,
                min_responses: 2,
                max_responses: 2,
            });
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, 2, 2)?;
            expect_all_status(&payloads, 200)?;
            Ok(())
        },
    );
}

/// A `redirect/0` endpoint returns a 204 (No Content) that is not followed.
fn test_redirect_zero_no_content(env: TestEnv) {
    run_flexible_test(
        env,
        "redirect/0 returns 204",
        |env| get_args(format!("{}/redirect/0", webserver_base(env))),
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 204)?;
            Ok(())
        },
    );
}

/// A transform can set the status, headers, and body of every response.
fn test_transform_sets_status_and_headers(env: TestEnv) {
    run_flexible_test(
        env,
        "transform can set status, headers and body",
        |env| {
            let mut args = get_args(format!("{}/ascii/ignored", webserver_base(env)));
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "test_transform".to_string(),
                }),
                context: b"transform_context".to_vec(),
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, DEFAULT_MIN_RESPONSES, DEFAULT_MAX_RESPONSES)?;
            expect_all_status(&payloads, 202)?;
            for payload in &payloads {
                if payload.body != b"transform_context".to_vec() {
                    bail!(
                        "expected transformed body 'transform_context', got {:?}",
                        String::from_utf8_lossy(&payload.body)
                    );
                }
            }
            Ok(())
        },
    );
}

/// A deterministic transform normalizes a non-deterministic endpoint so every
/// node agrees on an identical response.
fn test_deterministic_transform_normalizes(env: TestEnv) {
    run_flexible_test(
        env,
        "a deterministic transform normalizes a non-deterministic endpoint",
        |env| {
            let mut args = get_args(format!("{}/random", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: SUBNET_NODES,
                min_responses: SUBNET_NODES,
                max_responses: SUBNET_NODES,
            });
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "deterministic_transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let payloads = expect_ok(result, SUBNET_NODES as usize, SUBNET_NODES as usize)?;
            expect_all_status(&payloads, 200)?;
            for payload in &payloads {
                if payload.body != b"deterministic".to_vec() {
                    bail!(
                        "expected normalized body 'deterministic', got {:?}",
                        String::from_utf8_lossy(&payload.body)
                    );
                }
            }
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// Synchronous validation rejections
// ---------------------------------------------------------------------------

fn test_reject_total_requests_zero(env: TestEnv) {
    run_flexible_test(
        env,
        "total_requests = 0 is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 0,
                min_responses: 0,
                max_responses: 0,
            });
            args
        },
        |result| expect_rejection(result, "total_requests (0) must be at least 1"),
    );
}

fn test_reject_total_requests_exceed_nodes(env: TestEnv) {
    run_flexible_test(
        env,
        "total_requests > number of nodes is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: SUBNET_NODES + 1,
                min_responses: 1,
                max_responses: 1,
            });
            args
        },
        |result| expect_rejection(result, "must not exceed the number of available nodes (4)"),
    );
}

fn test_reject_min_exceeds_max(env: TestEnv) {
    run_flexible_test(
        env,
        "min_responses > max_responses is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 4,
                min_responses: 3,
                max_responses: 2,
            });
            args
        },
        |result| {
            expect_rejection(
                result,
                "min_responses (3) must not exceed max_responses (2)",
            )
        },
    );
}

fn test_reject_max_exceeds_total(env: TestEnv) {
    run_flexible_test(
        env,
        "max_responses > total_requests is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            args.replication = Some(ReplicationCounts {
                total_requests: 2,
                min_responses: 1,
                max_responses: 3,
            });
            args
        },
        |result| {
            expect_rejection(
                result,
                "max_responses (3) must not exceed total_requests (2)",
            )
        },
    );
}

fn test_reject_put_requires_deterministic(env: TestEnv) {
    run_flexible_test(
        env,
        "PUT with non-deterministic replication is rejected",
        |env| {
            // Default replication has min < total, which is not allowed for PUT.
            let mut args = get_args(format!("{}/anything", webserver_base(env)));
            args.method = HttpMethod::PUT;
            args
        },
        |result| expect_rejection(result, "min_responses = max_responses = total_requests"),
    );
}

fn test_reject_url_too_long(env: TestEnv) {
    run_flexible_test(
        env,
        "an over-long url is rejected",
        |env| {
            // MAX_CANISTER_HTTP_URL_SIZE is 8192.
            let long_path = "a".repeat(8200);
            get_args(format!("{}/ascii/{long_path}", webserver_base(env)))
        },
        |result| expect_rejection(result, "exceeds 8192"),
    );
}

fn test_reject_invalid_transform_principal(env: TestEnv) {
    run_flexible_test(
        env,
        "a transform referencing another principal is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            // The transform must reference the calling (proxy) canister; the
            // management canister principal does not.
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: Principal::management_canister(),
                    method: "transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| expect_rejection(result, "transform principal id expected to be"),
    );
}

/// `DELETE` (like `PUT`/`PATCH`) with explicit but non-equal replication counts
/// is rejected (distinct from the default-replication case).
fn test_reject_delete_non_deterministic(env: TestEnv) {
    run_flexible_test(
        env,
        "DELETE with non-equal replication counts is rejected",
        |env| {
            let mut args = get_args(format!("{}/anything", webserver_base(env)));
            args.method = HttpMethod::DELETE;
            args.replication = Some(ReplicationCounts {
                total_requests: 4,
                min_responses: 3,
                max_responses: 4,
            });
            args
        },
        |result| expect_rejection(result, "min_responses = max_responses = total_requests"),
    );
}

fn test_reject_header_name_too_long(env: TestEnv) {
    run_flexible_test(
        env,
        "an over-long header name is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            // Name of 8193 bytes: the element (8193) is within the candid bound
            // (16384) so it decodes, but exceeds the 8192 header name/value limit.
            args.headers = BoundedHttpHeaders::new(vec![HttpHeader {
                name: "a".repeat(8193),
                value: String::new(),
            }]);
            args
        },
        |result| {
            expect_rejection(
                result,
                "number of bytes to represent some http header name 8193 exceeds 8192",
            )
        },
    );
}

fn test_reject_header_value_too_long(env: TestEnv) {
    run_flexible_test(
        env,
        "an over-long header value is rejected",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            args.headers = BoundedHttpHeaders::new(vec![HttpHeader {
                name: "name".to_string(),
                value: "b".repeat(8193),
            }]);
            args
        },
        |result| {
            expect_rejection(
                result,
                "number of bytes to represent some http header value 8193 exceeds 8192",
            )
        },
    );
}

// ---------------------------------------------------------------------------
// Runtime errors and adapter-level per-node failures
// ---------------------------------------------------------------------------

/// When enough nodes fail to reach the endpoint (here: connection refused on a
/// closed port) `min_responses` cannot be met and the outcall reports
/// `too_many_rejects` with per-node details.
fn test_too_many_rejects_connection_refused(env: TestEnv) {
    run_flexible_test(
        env,
        "connection refused on all nodes yields too_many_rejects",
        |env| {
            // Port 9090 on the webserver is closed => connection refused.
            get_args(format!("https://[{}]:9090", get_universal_vm_address(env)))
        },
        |result| {
            let err = expect_global_error(
                result,
                &FlexibleHttpGlobalError::TooManyRejects(candid::Reserved),
                "Too many rejects",
            )?;
            // Every reject carries per-node details with an error.
            if err.node_details.is_empty() {
                bail!("expected per-node reject details");
            }
            if err.node_details.iter().any(|d| d.error.is_none()) {
                bail!("expected an error for every rejecting node");
            }
            Ok(())
        },
    );
}

/// An unresolvable domain fails at the adapter on every node, again yielding
/// `too_many_rejects`.
fn test_too_many_rejects_invalid_domain(env: TestEnv) {
    run_flexible_test(
        env,
        "an invalid domain yields too_many_rejects",
        |_env| get_args("https://xwWPqqbNqxxHmLXdguF4DN9xGq22nczV.com".to_string()),
        |result| {
            expect_global_error(
                result,
                &FlexibleHttpGlobalError::TooManyRejects(candid::Reserved),
                "Too many rejects",
            )?;
            Ok(())
        },
    );
}

/// When the aggregated responses are too large to fit in a block, the outcall
/// reports `responses_too_large`. Each node returns a ~1 MiB body (below the
/// per-response 2 MiB limit), but `min_responses` (3) of them exceed the 2 MiB
/// payload limit.
fn test_responses_too_large(env: TestEnv) {
    run_flexible_test(
        env,
        "oversized aggregated responses yield responses_too_large",
        |env| get_args(format!("{}/bytes/1000000", webserver_base(env))),
        |result| {
            expect_global_error(
                result,
                &FlexibleHttpGlobalError::ResponsesTooLarge(candid::Reserved),
                "Responses too large",
            )?;
            Ok(())
        },
    );
}

/// A single per-node response that exceeds the 2 MB per-node limit is rejected
/// by the adapter (download limit), so every node rejects and the outcall
/// reports `too_many_rejects`.
fn test_too_many_rejects_response_over_node_limit(env: TestEnv) {
    run_flexible_test(
        env,
        "a per-node response over the 2 MB limit yields too_many_rejects",
        |env| get_args(format!("{}/bytes/2100000", webserver_base(env))),
        |result| {
            let err = expect_global_error(
                result,
                &FlexibleHttpGlobalError::TooManyRejects(candid::Reserved),
                "Too many rejects",
            )?;
            expect_all_node_errors_contain(&err, "exceeds size limit")?;
            Ok(())
        },
    );
}

/// A transform whose output exceeds the 2 MB per-node limit is rejected by the
/// adapter (transform-output limit) on every node, again yielding
/// `too_many_rejects`.
fn test_too_many_rejects_transform_over_node_limit(env: TestEnv) {
    run_flexible_test(
        env,
        "a transform output over the 2 MB limit yields too_many_rejects",
        |env| {
            let mut args = get_args(format!("{}/bytes/16", webserver_base(env)));
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "bloat_transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            let err = expect_global_error(
                result,
                &FlexibleHttpGlobalError::TooManyRejects(candid::Reserved),
                "Too many rejects",
            )?;
            expect_all_node_errors_contain(&err, "Transformed http response exceeds limit")?;
            Ok(())
        },
    );
}

/// A composite query cannot be used as a transform: it fails per node, so every
/// node rejects and the outcall reports `too_many_rejects`.
fn test_too_many_rejects_composite_transform(env: TestEnv) {
    run_flexible_test(
        env,
        "a composite-query transform yields too_many_rejects",
        |env| {
            let mut args = get_args(format!("{}/ascii/x", webserver_base(env)));
            args.transform = Some(TransformContext {
                function: TransformFunc(candid::Func {
                    principal: proxy_principal(env),
                    method: "test_composite_transform".to_string(),
                }),
                context: vec![],
            });
            args
        },
        |result| {
            expect_global_error(
                result,
                &FlexibleHttpGlobalError::TooManyRejects(candid::Reserved),
                "Too many rejects",
            )?;
            Ok(())
        },
    );
}
