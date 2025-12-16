use std::str::FromStr;

use axum::{
    extract::{MatchedPath, Path, Request},
    middleware::Next,
    response::IntoResponse,
};
use bytes::Bytes;
use candid::Principal;
use http::header::HeaderValue;
use ic_bn_lib::http::headers::*;
use ic_types::{CanisterId, PrincipalId, SubnetId};
use lazy_static::lazy_static;
use regex_lite::Regex;

use crate::{
    errors::{ApiError, ErrorCause},
    http::{
        PATH_CALL_V2, PATH_CALL_V3, PATH_CALL_V4, PATH_QUERY_V2, PATH_QUERY_V3, PATH_READ_STATE_V2,
        PATH_READ_STATE_V3, PATH_SUBNET_READ_STATE_V2, PATH_SUBNET_READ_STATE_V3, RequestType,
    },
};

lazy_static! {
    pub static ref UUID_REGEX: Regex =
        Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap();
}

pub async fn validate_canister_request(
    matched_path: MatchedPath,
    canister_id: Path<String>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    let request_type = match matched_path.as_str() {
        PATH_QUERY_V2 => RequestType::QueryV2,
        PATH_QUERY_V3 => RequestType::QueryV3,
        PATH_CALL_V2 => RequestType::CallV2,
        PATH_CALL_V3 => RequestType::CallV3,
        PATH_CALL_V4 => RequestType::CallV4,
        PATH_READ_STATE_V2 => RequestType::ReadStateV2,
        PATH_READ_STATE_V3 => RequestType::ReadStateV3,
        _ => panic!("unknown path, should never happen"),
    };

    request.extensions_mut().insert(request_type);

    // Decode canister_id from URL
    let canister_id = CanisterId::from_str(&canister_id).map_err(|err| {
        ErrorCause::MalformedRequest(format!("Unable to decode canister_id from URL: {err}"))
    })?;

    request.extensions_mut().insert(canister_id);

    let mut resp = next.run(request).await;
    resp.headers_mut().insert(
        X_IC_CANISTER_ID,
        HeaderValue::from_maybe_shared(Bytes::from(canister_id.to_string())).unwrap(),
    );

    Ok(resp)
}

pub async fn validate_subnet_request(
    matched_path: MatchedPath,
    subnet_id: Path<String>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    let request_type = match matched_path.as_str() {
        PATH_SUBNET_READ_STATE_V2 => RequestType::ReadStateSubnetV2,
        PATH_SUBNET_READ_STATE_V3 => RequestType::ReadStateSubnetV3,
        _ => panic!("unknown path, should never happen"),
    };

    request.extensions_mut().insert(request_type);

    // Decode canister_id from URL
    let principal_id: PrincipalId = Principal::from_text(subnet_id.as_str())
        .map_err(|err| {
            ErrorCause::MalformedRequest(format!("Unable to decode subnet_id from URL: {err}"))
        })?
        .into();
    let subnet_id = SubnetId::from(principal_id);

    request.extensions_mut().insert(subnet_id);

    let resp = next.run(request).await;
    Ok(resp)
}

pub async fn validate_request(request: Request, next: Next) -> Result<impl IntoResponse, ApiError> {
    if let Some(id_header) = request.headers().get(X_REQUEST_ID) {
        let is_valid_id = id_header
            .to_str()
            .map(|id| UUID_REGEX.is_match(id))
            .unwrap_or(false);

        if !is_valid_id {
            #[allow(clippy::borrow_interior_mutable_const)]
            return Err(ErrorCause::MalformedRequest(format!(
                "Unable to parse the request ID in the '{X_REQUEST_ID}': the value is not in UUID format"
            ))
            .into());
        }
    }

    let resp = next.run(request).await;
    Ok(resp)
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Error;
    use axum::{Router, body::Body, middleware, routing::method_routing::get};
    use http::StatusCode;
    use tower::{Service, ServiceBuilder};
    use tower_http::{ServiceBuilderExt, request_id::MakeRequestUuid};

    #[tokio::test]
    async fn test_middleware_validate_canister_request() -> Result<(), Error> {
        let mut app = Router::new().route(PATH_QUERY_V2, get(|| async {})).layer(
            ServiceBuilder::new()
                .layer(middleware::from_fn(validate_request))
                .layer(middleware::from_fn(validate_canister_request))
                .set_x_request_id(MakeRequestUuid)
                .propagate_x_request_id(),
        );

        let url = "http://localhost/api/v2/canister/s6hwe-laaaa-aaaab-qaeba-cai/query";

        // case 1: no 'x-request-id' header, middleware generates one with a random uuid
        let request = Request::builder()
            .method("GET")
            .uri(url)
            .body(Body::from(""))
            .unwrap();
        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let request_id = resp.headers().get(X_REQUEST_ID).unwrap().to_str().unwrap();
        assert!(UUID_REGEX.is_match(request_id));

        // Check if canister id header is correct
        let canister_id = resp
            .headers()
            .get(X_IC_CANISTER_ID)
            .unwrap()
            .to_str()
            .unwrap();

        assert_eq!(canister_id, "s6hwe-laaaa-aaaab-qaeba-cai");

        // case 2: 'x-request-id' header contains a valid uuid, this uuid is not overwritten by middleware
        let request = Request::builder()
            .method("GET")
            .uri(url)
            .header(X_REQUEST_ID, "40a6d613-149e-4bde-8443-33593fd2fd17")
            .body(Body::from(""))
            .unwrap();
        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(X_REQUEST_ID).unwrap(),
            "40a6d613-149e-4bde-8443-33593fd2fd17"
        );

        // case 3: 'x-request-id' header contains an invalid uuid
        #[allow(clippy::borrow_interior_mutable_const)]
        let expected_failure = format!(
            "error: malformed_request\ndetails: Unable to parse the request ID in the '{X_REQUEST_ID}': the value is not in UUID format"
        );

        let request = Request::builder()
            .method("GET")
            .uri(url)
            .header(X_REQUEST_ID, "1")
            .body(Body::from(""))
            .unwrap();
        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let (_, body) = resp.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body, expected_failure);

        // case 4: 'x-request-id' header contains an invalid (not hyphenated) uuid
        let request = Request::builder()
            .method("GET")
            .uri(url)
            .header(X_REQUEST_ID, "40a6d613149e4bde844333593fd2fd17")
            .body(Body::from(""))
            .unwrap();
        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let (_, body) = resp.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body, expected_failure);

        // case 5: 'x-request-id' header is empty
        let request = Request::builder()
            .method("GET")
            .uri(url)
            .header(X_REQUEST_ID, "")
            .body(Body::from(""))
            .unwrap();
        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let (_, body) = resp.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body, expected_failure);

        Ok(())
    }

    #[tokio::test]
    async fn test_middleware_validate_subnet_request() -> Result<(), Error> {
        let mut app = Router::new()
            .route(PATH_SUBNET_READ_STATE_V2, get(|| async {}))
            .layer(
                ServiceBuilder::new()
                    .layer(middleware::from_fn(validate_request))
                    .layer(middleware::from_fn(validate_subnet_request))
                    .set_x_request_id(MakeRequestUuid)
                    .propagate_x_request_id(),
            );

        let url = "http://localhost/api/v2/subnet/s6hwe-laaaa-aaaab-qaeba-cai/read_state";

        // case 1: no 'x-request-id' header, middleware generates one with a random uuid
        let request = Request::builder()
            .method("GET")
            .uri(url)
            .body(Body::from(""))
            .unwrap();
        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let request_id = resp.headers().get(X_REQUEST_ID).unwrap().to_str().unwrap();
        assert!(UUID_REGEX.is_match(request_id));

        // case 2: 'x-request-id' header contains a valid uuid, this uuid is not overwritten by middleware
        let request = Request::builder()
            .method("GET")
            .uri(url)
            .header(X_REQUEST_ID, "40a6d613-149e-4bde-8443-33593fd2fd17")
            .body(Body::from(""))
            .unwrap();
        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(X_REQUEST_ID).unwrap(),
            "40a6d613-149e-4bde-8443-33593fd2fd17"
        );

        // case 3: 'x-request-id' header contains an invalid uuid
        #[allow(clippy::borrow_interior_mutable_const)]
        let expected_failure = format!(
            "error: malformed_request\ndetails: Unable to parse the request ID in the '{X_REQUEST_ID}': the value is not in UUID format"
        );

        let request = Request::builder()
            .method("GET")
            .uri(url)
            .header(X_REQUEST_ID, "1")
            .body(Body::from(""))
            .unwrap();
        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let (_, body) = resp.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body, expected_failure);

        // case 4: 'x-request-id' header contains an invalid (not hyphenated) uuid
        let request = Request::builder()
            .method("GET")
            .uri(url)
            .header(X_REQUEST_ID, "40a6d613149e4bde844333593fd2fd17")
            .body(Body::from(""))
            .unwrap();
        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let (_, body) = resp.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body, expected_failure);

        // case 5: 'x-request-id' header is empty
        let request = Request::builder()
            .method("GET")
            .uri(url)
            .header(X_REQUEST_ID, "")
            .body(Body::from(""))
            .unwrap();
        let resp = app.call(request).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let (_, body) = resp.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!(body, expected_failure);

        Ok(())
    }
}
