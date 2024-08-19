//! Module that deals with requests to /api/v2/canister/.../call

use super::{IngressError, IngressValidator};
use crate::{
    common::{Cbor, WithTimeout},
    HttpError,
};
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, State},
    response::{IntoResponse, Response},
    Router,
};
use http::Request;
use hyper::StatusCode;
use ic_types::{
    messages::{HttpCallContent, HttpRequestEnvelope},
    CanisterId,
};
use serde::Deserialize;
use serde_cbor::value::Value as CBOR;
use std::{collections::BTreeMap, convert::Infallible};
use tower::{util::BoxCloneService, ServiceBuilder};

pub struct CallServiceV2;

impl CallServiceV2 {
    pub(crate) fn route() -> &'static str {
        "/api/:api_version/canister/:effective_canister_id/call"
    }

    pub(crate) fn new_router(call_handler: IngressValidator) -> Router {
        Router::new().route(
            Self::route(),
            axum::routing::post(call_v2)
                .with_state(call_handler)
                .layer(ServiceBuilder::new().layer(DefaultBodyLimit::disable())),
        )
    }

    pub fn new_service(
        call_handler: IngressValidator,
    ) -> BoxCloneService<Request<Body>, Response, Infallible> {
        let router = Self::new_router(call_handler);
        BoxCloneService::new(router.into_service())
    }
}

#[derive(Deserialize)]
struct CallParameters {
    api_version: ApiVersion,
    effective_canister_id: CanisterId,
}

#[derive(Deserialize)]
enum ApiVersion {
    #[serde(rename = "v2")]
    V2,
    #[serde(rename = "v3")]
    V3,
}

/// Handles a call to /api/v2/canister/../call
async fn call_v2(
    axum::extract::Path(CallParameters {
        api_version,
        effective_canister_id,
    }): axum::extract::Path<CallParameters>,
    State(call_handler): State<IngressValidator>,
    WithTimeout(Cbor(request)): WithTimeout<Cbor<HttpRequestEnvelope<HttpCallContent>>>,
) -> Result<StatusCode, Response> {
    call_handler
        .validate_ingress_message(request, effective_canister_id)
        .await
        .map_err(|err| match err {
            IngressError::UserError(user_error) => {
                let mut response_map = BTreeMap::from([
                    (
                        CBOR::Text("error_code".to_string()),
                        CBOR::Text(user_error.code().to_string()),
                    ),
                    (
                        CBOR::Text("reject_message".to_string()),
                        CBOR::Text(user_error.description().to_string()),
                    ),
                    (
                        CBOR::Text("reject_code".to_string()),
                        CBOR::Integer(user_error.reject_code() as i128),
                    ),
                ]);

                if let ApiVersion::V3 = api_version {
                    response_map.insert(
                        CBOR::Text("status".to_string()),
                        CBOR::Text("non_replicated_rejection".to_string()),
                    );
                }
                Cbor(CBOR::Map(response_map)).into_response()
            }
            IngressError::HttpError(HttpError { status, message }) => {
                (status, message).into_response()
            }
        })?
        .try_submit()
        .map_err(|HttpError { status, message }| (status, message).into_response())?;

    Ok(StatusCode::ACCEPTED)
}
