use std::sync::Arc;

use anyhow::{Context, Error};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use http::Method;
use ic_bn_lib::{
    http::cache::{Cache, CacheBuilder},
    prometheus::Registry,
};
use ic_bn_lib_common::{
    traits::{
        Run,
        http::{Bypasser, CustomBypassReason, KeyExtractor},
    },
    types::http::CacheError,
};
use strum::{Display, IntoStaticStr};
use tokio_util::sync::CancellationToken;

use crate::{
    cli,
    errors::{ApiError, ErrorCause},
    routes::RequestContext,
};

#[derive(Debug, Clone)]
struct KeyExtractorContext;

impl KeyExtractor for KeyExtractorContext {
    type Key = Arc<RequestContext>;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, CacheError> {
        let ctx = req
            .extensions()
            .get::<Arc<RequestContext>>()
            .ok_or_else(|| {
                CacheError::ExtractKey("unable to get RequestContext extension".into())
            })?;

        Ok(ctx.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, IntoStaticStr, Display)]
#[strum(serialize_all = "snake_case")]
pub enum BypassReasonIC {
    IncorrectRequestType,
    Nonce,
    NonAnonymous,
}
impl CustomBypassReason for BypassReasonIC {}

/// Decides if we need to bypass caching for the given request
#[derive(Debug, Clone)]
struct BypasserIC {
    cache_non_anonymous: bool,
}

impl Bypasser for BypasserIC {
    type BypassReason = BypassReasonIC;

    fn bypass<T>(&self, req: &Request<T>) -> Result<Option<Self::BypassReason>, CacheError> {
        let ctx = req
            .extensions()
            .get::<Arc<RequestContext>>()
            .ok_or_else(|| {
                CacheError::ExecuteBypasser("unable to get RequestContext extension".into())
            })?;

        Ok(if !ctx.request_type.is_query() {
            // We cache only Query
            Some(BypassReasonIC::IncorrectRequestType)
        } else if ctx.nonce.is_some() {
            // Bypass cache if there's a nonce
            Some(BypassReasonIC::Nonce)
        } else if ctx.is_anonymous() == Some(false) && !self.cache_non_anonymous {
            // Bypass non-anonymous requests if not configured to cache them
            Some(BypassReasonIC::NonAnonymous)
        } else {
            None
        })
    }
}

pub struct CacheState {
    cache: Cache<KeyExtractorContext, BypasserIC>,
}

impl CacheState {
    pub fn new(cli: &cli::Cache, registry: &Registry) -> Result<Self, Error> {
        let bypasser = BypasserIC {
            cache_non_anonymous: cli.cache_non_anonymous,
        };

        let cache = CacheBuilder::new_with_bypasser(KeyExtractorContext, bypasser)
            .cache_size(cli.cache_size.unwrap())
            .max_item_size(cli.cache_max_item_size)
            .ttl(cli.cache_ttl)
            .registry(registry)
            .methods(&[Method::POST])
            .build()
            .context("unable to build Cache")?;

        Ok(Self { cache })
    }

    pub async fn update_metrics(&self) {
        let _ = self.cache.run(CancellationToken::new()).await;
    }
}

// Axum middleware that handles response caching
pub async fn cache_middleware(
    State(state): State<Arc<CacheState>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    let response = state
        .cache
        .process_request(request, next)
        .await
        .map_err(|e| ErrorCause::Other(e.to_string()))?;

    Ok(response)
}

#[cfg(test)]
mod test {
    use super::*;

    use std::{sync::Arc, time::Duration};

    use axum::{
        Extension, Router, body::Body, http::Request, middleware, response::IntoResponse,
        routing::method_routing::post,
    };
    use candid::Principal;
    use http::StatusCode;
    use ic_bn_lib::http::cache::CacheStatus;
    use ic_bn_lib_common::{principal, types::http::CacheBypassReason};
    use tower::Service;

    use crate::{core::ANONYMOUS_PRINCIPAL, http::RequestType};

    const CANISTER_1: &str = "sqjm4-qahae-aq";
    const MAX_RESP_SIZE: usize = 1024;
    const MAX_MEM_SIZE: u64 = 32768;
    const DEFAULT_SIZE: u64 = 8;

    fn gen_request_with_params(
        canister_id: &str,
        request_type: RequestType,
        nonce: bool,
        size: u64,
        ingress_expiry: u64,
        anonymous: bool,
        status_code: StatusCode,
    ) -> Request<Body> {
        let mut req = Request::post("/").body(Body::from("foobar")).unwrap();

        let mut ctx = RequestContext {
            request_type,
            canister_id: Some(Principal::from_text(canister_id).unwrap()),
            sender: Some(if anonymous {
                ANONYMOUS_PRINCIPAL
            } else {
                principal!("f7crg-kabae")
            }),
            method_name: Some("foo".into()),
            ingress_expiry: Some(ingress_expiry),
            arg: Some(vec![1, 2, 3, 4]),
            ..Default::default()
        };

        if nonce {
            ctx.nonce = Some(vec![1, 2, 3, 4]);
        }

        let ctx = Arc::new(ctx);

        req.extensions_mut().insert(ctx);
        req.extensions_mut().insert(size);
        req.extensions_mut().insert(status_code);

        req
    }

    fn gen_request(canister_id: &str, nonce: bool) -> Request<Body> {
        gen_request_with_params(
            canister_id,
            RequestType::QueryV2,
            nonce,
            DEFAULT_SIZE,
            0,
            true,
            StatusCode::OK,
        )
    }

    // Generate a response with a requested size
    async fn handler(
        Extension(size): Extension<u64>,
        Extension(status_code): Extension<StatusCode>,
    ) -> impl IntoResponse {
        (status_code, "a".repeat(size as usize))
    }

    #[tokio::test]
    async fn test_cache() -> Result<(), Error> {
        // Check that we fail if item size >= max size
        let cli = cli::Cache {
            cache_size: Some(MAX_MEM_SIZE),
            cache_max_item_size: MAX_RESP_SIZE,
            cache_ttl: Duration::from_secs(3600),
            cache_non_anonymous: false,
        };

        let cache_state = Arc::new(CacheState::new(&cli, &Registry::new()).unwrap());

        let mut app =
            Router::new()
                .route("/", post(handler))
                .layer(middleware::from_fn_with_state(
                    cache_state,
                    cache_middleware,
                ));

        // Check non-query
        let req = gen_request_with_params(
            CANISTER_1,
            RequestType::CallV2,
            false,
            DEFAULT_SIZE,
            0,
            false,
            StatusCode::OK,
        );
        let res = app.call(req).await.unwrap();
        let cs = res
            .extensions()
            .get::<CacheStatus<BypassReasonIC>>()
            .cloned()
            .unwrap();
        assert_eq!(
            cs,
            CacheStatus::Bypass(CacheBypassReason::Custom(
                BypassReasonIC::IncorrectRequestType
            ))
        );

        // Check non-anonymous
        let req = gen_request_with_params(
            CANISTER_1,
            RequestType::QueryV2,
            false,
            DEFAULT_SIZE,
            0,
            false,
            StatusCode::OK,
        );
        let res = app.call(req).await.unwrap();
        let cs = res
            .extensions()
            .get::<CacheStatus<BypassReasonIC>>()
            .cloned()
            .unwrap();
        assert_eq!(
            cs,
            CacheStatus::Bypass(CacheBypassReason::Custom(BypassReasonIC::NonAnonymous))
        );

        // Check non-2xx
        let req = gen_request_with_params(
            CANISTER_1,
            RequestType::QueryV2,
            false,
            DEFAULT_SIZE,
            0,
            true,
            StatusCode::SERVICE_UNAVAILABLE,
        );
        let res = app.call(req).await.unwrap();
        let cs = res
            .extensions()
            .get::<CacheStatus<BypassReasonIC>>()
            .cloned()
            .unwrap();
        assert_eq!(cs, CacheStatus::Bypass(CacheBypassReason::HTTPError));

        // Check cache hits and misses
        let req = gen_request(CANISTER_1, false);
        let res = app.call(req).await.unwrap();
        let cs = res
            .extensions()
            .get::<CacheStatus<BypassReasonIC>>()
            .cloned()
            .unwrap();
        assert_eq!(cs, CacheStatus::Miss);

        let req = gen_request(CANISTER_1, false);
        let res = app.call(req).await.unwrap();
        let cs = res
            .extensions()
            .get::<CacheStatus<BypassReasonIC>>()
            .cloned()
            .unwrap();
        assert_eq!(cs, CacheStatus::Hit);

        // Check if the body from cache is correct
        let (_, body) = res.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .unwrap()
            .to_vec();
        let body = String::from_utf8_lossy(&body);
        assert_eq!("a".repeat(DEFAULT_SIZE as usize), body);

        // Check with nonce
        let req = gen_request(CANISTER_1, true);
        let res = app.call(req).await.unwrap();
        let cs = res
            .extensions()
            .get::<CacheStatus<BypassReasonIC>>()
            .cloned()
            .unwrap();
        assert_eq!(
            cs,
            CacheStatus::Bypass(CacheBypassReason::Custom(BypassReasonIC::Nonce))
        );

        Ok(())
    }
}
