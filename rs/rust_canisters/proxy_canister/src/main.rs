//! Defines a canister which is used in testing Canister HTTP Calls feature.
//!
//! The canister receives HTTP request through inbound message, decodes the HTTP request
//! and forwards it to targeted service. Canister returns the remote service call response
//! as a canister message to client if the call was successful and agreed by majority nodes,
//! otherwise errors out.
//!
use candid::{candid_method, Principal};
use ic_cdk::api::call::RejectionCode;
use ic_ic00_types::{CanisterHttpResponsePayload, Payload};
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    #[allow(clippy::type_complexity)]
    pub static REMOTE_CALLS: RefCell<HashMap<String, Result<RemoteHttpResponse, (RejectionCode, String)>>>  = RefCell::new(HashMap::new());
}

#[ic_cdk_macros::update(name = "send_request")]
#[candid_method(update, rename = "send_request")]
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
                decoded.status as u8,
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

#[ic_cdk_macros::query(name = "check_response")]
#[candid_method(query, rename = "check_response")]
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

#[ic_cdk_macros::query(name = "transform")]
#[candid_method(query, rename = "transform")]
fn transform(raw: CanisterHttpResponsePayload) -> CanisterHttpResponsePayload {
    let mut transformed = raw;
    transformed.headers = vec![];
    transformed
}

#[cfg(test)]
mod proxy_canister_test {
    use super::*;
    use ic_ic00_types::HttpHeader;

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
        let sanitized = transform(raw_response);
        let sanitized_body = std::str::from_utf8(&sanitized.body).unwrap();
        println!("Sanitized body is: {}", sanitized_body);
        assert!(sanitized.headers.is_empty());
        assert_eq!(sanitized_body, "homepage");
    }
}

fn main() {}
