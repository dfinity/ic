//! Defines a canister which is used in testing Canister HTTP Calls feature.
//!
//! The canister receives HTTP request through inbound message, decodes the HTTP request
//! and forwards it to targeted service. Canister returns the remote service call response
//! as a canister message to client if the call was successful and agreed by majority nodes,
//! otherwise errors out.
//!
use candid::Principal;
use futures::future::join_all;
use ic_cdk::api::call::RejectionCode;
use ic_cdk::api::time;
use ic_cdk::{caller, spawn};
use ic_cdk_macros::{query, update};
use ic_management_canister_types_private::{
    CanisterHttpResponsePayload, HttpHeader, Payload, TransformArgs,
};
use proxy_canister::{
    RemoteHttpRequest, RemoteHttpResponse, RemoteHttpStressRequest, RemoteHttpStressResponse,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;

thread_local! {
    #[allow(clippy::type_complexity)]
    pub static REMOTE_CALLS: RefCell<HashMap<String, Result<RemoteHttpResponse, (RejectionCode, String)>>>  = RefCell::new(HashMap::new());
}

const MAX_TRANSFORM_SIZE: usize = 2_000_000;

#[update]
async fn send_requests_in_parallel(
    request: RemoteHttpStressRequest,
) -> Result<RemoteHttpStressResponse, (RejectionCode, String)> {
    let start = time();
    if request.count == 0 {
        return Err((
            RejectionCode::CanisterError,
            "Count cannot be 0".to_string(),
        ));
    }

    // This is the maximum size of the queue of canister messages. In our case, it's the highest number of requests we can send in parallel.
    const MAX_CONCURRENCY: usize = 500;

    let mut all_results: Vec<Result<RemoteHttpResponse, (RejectionCode, String)>> = Vec::new();

    let indices: Vec<u64> = (0..request.count).collect();
    for chunk in indices.chunks(MAX_CONCURRENCY) {
        let futures_iter = chunk.iter().map(|_| send_request(request.request.clone()));
        let chunk_results = join_all(futures_iter).await;
        all_results.extend(chunk_results);
    }

    let mut response = None;

    for result in all_results {
        match result {
            Ok(rsp) => response = Some(rsp),
            Err(err) => {
                return Err(err);
            }
        }
    }
    let duration_ns = time() - start;
    Ok(RemoteHttpStressResponse {
        response: response.unwrap(),
        duration: Duration::from_nanos(duration_ns),
    })
}

#[update]
pub async fn start_continuous_requests(
    request: RemoteHttpRequest,
) -> Result<RemoteHttpResponse, (RejectionCode, String)> {
    // This request establishes the session to the target server.
    let _ = send_request(request.clone()).await;

    spawn(async move {
        run_continuous_request_loop(request).await;
    });

    Ok(RemoteHttpResponse::new(
        200,
        vec![],
        "Started non-stop sending.".to_string(),
    ))
}

// TODO: instead of sequentially awaiting on each batch, try to send the next requests anyway, with backoff.
// This should improve the overall qps, as the canister message queue is the bottleneck, and it's not being saturated.
async fn run_continuous_request_loop(request: RemoteHttpRequest) {
    const BATCH_SIZE: usize = 500;
    let futures_iter = (0..BATCH_SIZE).map(|_| send_request(request.clone()));
    let results = join_all(futures_iter).await;

    let mut successes = 0;
    let mut errors = 0;
    for result in results {
        match result {
            Ok(_resp) => {
                successes += 1;
            }
            Err((rejection_code, msg)) => {
                errors += 1;
                println!("Request failed: {:?} - {}", rejection_code, msg);
            }
        }
    }
    println!(
        "Finished batch of {} requests => successes: {}, errors: {}",
        BATCH_SIZE, successes, errors
    );

    spawn(async move {
        run_continuous_request_loop(request).await;
    });
}

#[update]
async fn send_request(
    request: RemoteHttpRequest,
) -> Result<RemoteHttpResponse, (RejectionCode, String)> {
    let RemoteHttpRequest { request, cycles } = request;
    let request_url = request.url.clone();
    println!("send_request making IC call.");
    match ic_cdk::api::call::call_raw(
        Principal::management_canister(),
        "http_request",
        &request.encode(),
        cycles,
    )
    .await
    {
        Ok(raw_response) => {
            println!("send_request returning with success case.");
            let decoded: CanisterHttpResponsePayload = candid::utils::decode_one(&raw_response)
                .expect("Failed to decode CanisterHttpResponsePayload");
            let mut response_headers = vec![];
            for header in decoded.headers {
                response_headers.push((header.name, header.value));
            }
            let response = RemoteHttpResponse::new(
                decoded.status,
                response_headers,
                String::from_utf8_lossy(&decoded.body).to_string(),
            );

            REMOTE_CALLS.with(|results| {
                let mut writer = results.borrow_mut();
                writer
                    .entry(request_url)
                    .or_insert_with(|| Ok(response.clone()));
            });
            Result::Ok(response)
        }
        Err((r, m)) => {
            REMOTE_CALLS.with(|results| {
                let mut writer = results.borrow_mut();
                writer
                    .entry(request.url)
                    .or_insert_with(|| Err((r, m.clone())));
            });
            Err((r, m))
        }
    }
}

#[query]
async fn check_response(
    url: String,
) -> Option<Result<RemoteHttpResponse, (RejectionCode, String)>> {
    println!("check_response being called");
    REMOTE_CALLS.with(|results| {
        let reader = results.borrow();
        println!("Size of dictionary is: {}", reader.len());
        match reader.get(&url) {
            Some(Ok(x)) => Some(Ok(x.clone())),
            Some(Err((r, m))) => Some(Err((*r, m.clone()))),
            None => None,
        }
    })
}

#[query]
fn transform(raw: TransformArgs) -> CanisterHttpResponsePayload {
    let (response, _) = (raw.response, raw.context);
    let mut transformed = response;
    transformed.headers = vec![];
    transformed
}

#[query]
fn deterministic_transform(raw: TransformArgs) -> CanisterHttpResponsePayload {
    let (response, _) = (raw.response, raw.context);
    let mut transformed = response;
    transformed.headers = vec![];
    transformed.body = "deterministic".as_bytes().to_vec();
    transformed
}

#[query]
fn transform_with_context(raw: TransformArgs) -> CanisterHttpResponsePayload {
    let (response, context) = (raw.response, raw.context);
    let mut context = context;
    let mut transformed = response;
    transformed.body.append(&mut context);
    transformed.headers = vec![];
    transformed
}

fn test_transform_(raw: TransformArgs) -> CanisterHttpResponsePayload {
    let (response, context) = (raw.response, raw.context);
    let mut transformed = response;
    transformed.headers = vec![
        HttpHeader {
            name: "hello".to_string(),
            value: "bonjour".to_string(),
        },
        HttpHeader {
            name: "caller".to_string(),
            value: caller().to_string(),
        },
    ];
    transformed.body = context;
    transformed.status = 202;
    transformed
}

#[query]
fn test_transform(raw: TransformArgs) -> CanisterHttpResponsePayload {
    test_transform_(raw)
}

#[query(composite = true)]
fn test_composite_transform(raw: TransformArgs) -> CanisterHttpResponsePayload {
    test_transform_(raw)
}

#[query]
fn bloat_transform(raw: TransformArgs) -> CanisterHttpResponsePayload {
    let (response, _) = (raw.response, raw.context);
    let mut transformed = response;
    transformed.headers = vec![];
    // TODO: size_of<CanisterHttpResponsePayload> = 64, so not exactly sure why 50 does it..
    let overhead = 50;
    // Return response that is bigger than allowed limit.
    // - 50 is small enough, but -49 is too large.
    transformed.body = vec![0; MAX_TRANSFORM_SIZE - overhead + 1];

    transformed
}

#[query]
fn very_large_but_allowed_transform(raw: TransformArgs) -> CanisterHttpResponsePayload {
    let (response, _) = (raw.response, raw.context);
    let mut transformed = response;
    transformed.headers = vec![];
    let overhead = 50;
    // Return response that is exactly equal to the allowed limit.
    transformed.body = vec![0; MAX_TRANSFORM_SIZE - overhead];

    transformed
}

fn main() {}

#[cfg(test)]
mod proxy_canister_test {
    use super::*;
    use ic_management_canister_types_private::HttpHeader;

    #[test]
    fn test_transform() {
        let raw_response = CanisterHttpResponsePayload {
            status: 200,
            body: "homepage".as_bytes().to_vec(),
            headers: vec![HttpHeader {
                name: "date".to_string(),
                value: "Fri, 03 Jun 2022 16:23:43 GMT".to_string(),
            }],
        };
        let sanitized = transform(TransformArgs {
            response: raw_response,
            context: vec![0, 1, 2],
        });
        let sanitized_body = std::str::from_utf8(&sanitized.body).unwrap();
        println!("Sanitized body is: {}", sanitized_body);
        assert!(sanitized.headers.is_empty());
        assert_eq!(sanitized_body, "homepage");
    }

    #[test]
    fn test_transform_with_context() {
        let response = "response";
        let context = "context";
        let raw = TransformArgs {
            response: CanisterHttpResponsePayload {
                status: 200,
                headers: vec![],
                body: response.as_bytes().to_vec(),
            },
            context: context.as_bytes().to_vec(),
        };
        let transformed = transform_with_context(raw);
        assert_eq!(
            response.to_owned() + context,
            String::from_utf8_lossy(&transformed.body).to_string()
        );
    }
}
