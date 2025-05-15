use std::sync::Arc;

use anyhow::{Context, Error};
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::IntoResponse,
};
use http::Method;
use ic_bn_lib::{
    http::cache::{
        Bypasser, Cache, CacheBuilder, CustomBypassReason, Error as CacheError, KeyExtractor,
    },
    prometheus::Registry,
    tasks::Run,
    types::RequestType,
};
use strum::{Display, IntoStaticStr};
use tokio_util::sync::CancellationToken;

use crate::{
    cli,
    routes::{ApiError, ErrorCause, RequestContext},
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

#[derive(Debug, Clone)]
/// Decides if we need to bypass caching for the given request
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

        Ok(if ctx.request_type != RequestType::Query {
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
pub mod test;
