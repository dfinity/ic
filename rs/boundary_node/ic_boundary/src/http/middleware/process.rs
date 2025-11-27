use std::{sync::Arc, time::Duration};

use axum::{Extension, body::Body, extract::Request, middleware::Next, response::IntoResponse};
use bytes::Bytes;
use candid::{Decode, Principal};
use http::header::{CONTENT_TYPE, HeaderValue, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS};
use ic_bn_lib::http::{body::buffer_body, cache::CacheStatus, headers::*};
use ic_bn_lib_common::types::http::Error as HttpError;
use ic_types::messages::Blob;
use serde::{Deserialize, Serialize};

use crate::{
    core::{MAX_REQUEST_BODY_SIZE, decoder_config},
    errors::{ApiError, ErrorCause},
    http::{RequestType, middleware::retry::RetryResult},
    routes::{HttpRequest, RequestContext},
    snapshot::{Node, Subnet},
};

const METHOD_HTTP: &str = "http_request";

const HEADERS_HIDE_HTTP_REQUEST: [&str; 4] =
    ["x-real-ip", "x-forwarded-for", "x-request-id", "user-agent"];

// This is the subset of the request fields
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ICRequestContent {
    sender: Principal,
    canister_id: Option<Principal>,
    method_name: Option<String>,
    nonce: Option<Blob>,
    ingress_expiry: Option<u64>,
    arg: Option<Blob>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ICRequestEnvelope {
    content: ICRequestContent,
}

// Middleware: preprocess the request before handing it over to handlers
pub async fn preprocess_request(
    Extension(request_type): Extension<RequestType>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    // Consume body
    let (parts, body) = request.into_parts();
    let body = buffer_body(body, MAX_REQUEST_BODY_SIZE, Duration::from_secs(60))
        .await
        .map_err(|e| match e {
            HttpError::BodyReadingFailed(v) => ErrorCause::UnableToReadBody(v),
            HttpError::BodyTooBig => ErrorCause::PayloadTooLarge(MAX_REQUEST_BODY_SIZE),
            HttpError::BodyTimedOut => ErrorCause::BodyTimedOut,
            _ => ErrorCause::Other(e.to_string()),
        })?;

    // Parse the request body
    let envelope: ICRequestEnvelope = serde_cbor::from_slice(&body)
        .map_err(|err| ErrorCause::UnableToParseCBOR(err.to_string()))?;
    let content = envelope.content;

    // Check if the request is HTTP and try to parse the arg
    let (arg, http_request) = match (&content.method_name, content.arg) {
        (Some(method), Some(arg)) => {
            if request_type.is_query() && method == METHOD_HTTP {
                let mut req: HttpRequest = Decode!([decoder_config()]; &arg.0, HttpRequest)
                    .map_err(|err| {
                        ErrorCause::UnableToParseHTTPArg(format!(
                            "unable to decode arg as HttpRequest: {err}"
                        ))
                    })?;

                // Remove specific headers
                req.headers
                    .retain(|x| !HEADERS_HIDE_HTTP_REQUEST.contains(&(x.0.as_str())));

                // Drop the arg as it's now redundant
                (None, Some(req))
            } else {
                (Some(arg), None)
            }
        }

        (_, arg) => (arg, None),
    };

    // Construct the context
    let ctx = RequestContext {
        request_type,
        request_size: body.len() as u32,
        sender: Some(content.sender),
        canister_id: content.canister_id,
        method_name: content.method_name,
        ingress_expiry: content.ingress_expiry,
        arg: arg.map(|x| x.0),
        nonce: content.nonce.map(|x| x.0),
        http_request,
    };

    let ctx = Arc::new(ctx);

    // Reconstruct request back from parts
    let mut request = Request::from_parts(parts, Body::from(body));

    // Inject variables into the request
    request.extensions_mut().insert(ctx.clone());

    // Pass request to the next processor
    let mut response = next.run(request).await;

    // Inject context into the response for access by other middleware
    response.extensions_mut().insert(ctx);

    Ok(response)
}

// Middleware: postprocess the response
pub async fn postprocess_response(request: Request, next: Next) -> impl IntoResponse {
    let mut response = next.run(request).await;

    let error_cause = response
        .extensions()
        .get::<ErrorCause>()
        .map(|x| x.to_string())
        .unwrap_or("none".into());

    // Set the correct content-type for all replies if it's not an error
    if error_cause == "none" && response.status().is_success() {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, CONTENT_TYPE_CBOR);
        response
            .headers_mut()
            .insert(X_CONTENT_TYPE_OPTIONS, X_CONTENT_TYPE_OPTIONS_NO_SNIFF);
        response
            .headers_mut()
            .insert(X_FRAME_OPTIONS, X_FRAME_OPTIONS_DENY);
    }

    response.headers_mut().insert(
        X_IC_ERROR_CAUSE,
        HeaderValue::from_maybe_shared(Bytes::from(error_cause)).unwrap(),
    );

    // Add cache status if there's one
    let cache_status = response.extensions().get::<CacheStatus>().cloned();
    if let Some(v) = cache_status {
        response.headers_mut().insert(
            X_IC_CACHE_STATUS,
            HeaderValue::from_maybe_shared(Bytes::from(v.to_string())).unwrap(),
        );

        if let CacheStatus::Bypass(v) = v {
            response.headers_mut().insert(
                X_IC_CACHE_BYPASS_REASON,
                HeaderValue::from_maybe_shared(Bytes::from(v.to_string())).unwrap(),
            );
        }
    }

    if let Some(v) = response.extensions().get::<Arc<Subnet>>().cloned() {
        response.headers_mut().insert(
            X_IC_SUBNET_ID,
            HeaderValue::from_maybe_shared(Bytes::from(v.id.to_string())).unwrap(),
        );
    }

    let node = response.extensions().get::<Arc<Node>>().cloned();
    if let Some(v) = node {
        // Principals and subnet type are always ASCII printable, so unwrap is safe
        response.headers_mut().insert(
            X_IC_NODE_ID,
            HeaderValue::from_maybe_shared(Bytes::from(v.id.to_string())).unwrap(),
        );

        response.headers_mut().insert(
            X_IC_SUBNET_TYPE,
            HeaderValue::from_str(v.subnet_type.as_ref()).unwrap(),
        );
    }

    if let Some(ctx) = response.extensions().get::<Arc<RequestContext>>().cloned() {
        response.headers_mut().insert(
            X_IC_REQUEST_TYPE,
            HeaderValue::from_maybe_shared(Bytes::from(ctx.request_type.to_string())).unwrap(),
        );

        ctx.canister_id.and_then(|v| {
            response.headers_mut().insert(
                X_IC_CANISTER_ID_CBOR,
                HeaderValue::from_maybe_shared(Bytes::from(v.to_string())).unwrap(),
            )
        });

        ctx.sender.and_then(|v| {
            response.headers_mut().insert(
                X_IC_SENDER,
                HeaderValue::from_maybe_shared(Bytes::from(v.to_string())).unwrap(),
            )
        });

        ctx.method_name.as_ref().and_then(|v| {
            response.headers_mut().insert(
                X_IC_METHOD_NAME,
                HeaderValue::from_maybe_shared(Bytes::from(v.clone())).unwrap(),
            )
        });
    }

    let retry_result = response.extensions().get::<RetryResult>().cloned();
    if let Some(v) = retry_result {
        response.headers_mut().insert(
            X_IC_RETRIES,
            HeaderValue::from_maybe_shared(Bytes::from(v.retries.to_string())).unwrap(),
        );
    }

    response
}
