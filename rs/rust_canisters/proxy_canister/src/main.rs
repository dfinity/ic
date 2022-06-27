//! Defines a canister which is used in testing Canister HTTP Calls feature.
//!
//! The canister receives HTTP request through inbound message, decodes the HTTP request
//! and forwards it to targeted service. Canister returns the remote service call response
//! as a canister message to client if the call was successful and agreed by majority nodes,
//! otherwise errors out.
//!
use candid::{candid_method, Principal};
use ic_ic00_types::{CanisterHttpRequestArgs, CanisterHttpResponsePayload, HttpHeader, HttpMethod};
use proxy_canister::{RemoteHttpRequest, RemoteHttpResponse};
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    pub static REMOTE_CALLS: RefCell<HashMap<String,RemoteHttpResponse>>  = RefCell::new(HashMap::new());
}

#[ic_cdk_macros::update(name = "send_request")]
#[candid_method(update, rename = "send_request")]
async fn send_request(request: RemoteHttpRequest) -> Result<(), String> {
    let canister_http_headers = request
        .headers
        .into_iter()
        .map(|header| HttpHeader {
            name: header.0,
            value: header.1,
        })
        .collect();
    println!("send_request being called");

    let canister_http_request = CanisterHttpRequestArgs {
        url: request.url.clone(),
        http_method: HttpMethod::GET,
        body: Some(request.body.as_bytes().to_vec()),
        transform_method_name: Some(request.transform),
        headers: canister_http_headers,
        max_response_bytes: Some(1000000),
    };

    println!("send_request encoding CanisterHttpRequestArgs message.");
    let encoded_req = candid::utils::encode_one(&canister_http_request).unwrap();

    println!("send_request making IC call.");
    match ic_cdk::api::call::call_raw(
        Principal::management_canister(),
        "http_request",
        &encoded_req[..],
        0,
    )
    .await
    {
        Ok(raw_response) => {
            println!("send_request returning with success case.");
            let decoded: CanisterHttpResponsePayload = candid::utils::decode_one(&raw_response)
                .map_err(|err| return format!("Decoding raw http response failed: {}", err))?;
            let mut response_headers = vec![];
            for header in decoded.headers {
                response_headers.push((header.name, header.value));
            }
            let response = RemoteHttpResponse::new(
                decoded.status as u8,
                response_headers,
                String::from_utf8(decoded.body).map_err(|err| return format!("Internet Computer cansiter HTTP calls expects request and response be UTF-8 encoded. However, the response content is not UTF-8 compliant. Error: {}", err))?,
            );

            let request_url = request.url.clone();
            REMOTE_CALLS.with(|results| {
                let mut writer = results.borrow_mut();
                writer.entry(request_url).or_insert(response);
            });
            Result::Ok(())
        }
        Err((r, m)) => {
            println!("send_request returning with failure case.");
            let error = format!(
                "Failed to send request to {}. CanisterId: {}, RejectionCode: {:?}, Message: {}",
                &request.url,
                ic_cdk::id(),
                r,
                m
            );
            Err(error)
        }
    }
}

#[ic_cdk_macros::query(name = "check_response")]
#[candid_method(query, rename = "check_response")]
async fn check_response(url: String) -> Result<RemoteHttpResponse, String> {
    println!("check_response being called");
    REMOTE_CALLS.with(|results| {
        let reader = results.borrow();
        println!("Size of dictionary is: {}", reader.len());
        match reader.get(&url) {
            Some(x) => {
                println!("check_response returning with success case.");
                Result::Ok(x.clone())
            }
            _ => {
                println!("check_response returning with failure case.");
                let message = format!("Request to URL {} has not been made.", url);
                println!("{}", message);
                Result::Err(message)
            }
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
