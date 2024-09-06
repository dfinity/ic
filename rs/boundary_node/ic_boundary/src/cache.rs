use std::{fmt, sync::Arc, time::Duration};

use anyhow::{anyhow, Error};
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use bytes::Bytes;
use http::header::{HeaderMap, CACHE_CONTROL, CONTENT_LENGTH};
use http::{response, Version};
use moka::future::{Cache as MokaCache, CacheBuilder as MokaCacheBuilder};

use crate::{
    http::{read_streaming_body, AxumResponse},
    routes::{ApiError, ErrorCause, RequestContext},
};

// A list of possible Cache-Control directives that ask us not to cache the response
const SKIP_CACHE_DIRECTIVES: &[&str] = &["no-store", "no-cache", "max-age=0"];

// Reason why the caching was skipped
#[derive(Clone, PartialEq, Debug)]
pub enum CacheBypassReason {
    Nonce,
    NonAnonymous,
    CacheControl,
    SizeUnknown,
    TooBig,
    HTTPError,
}

impl fmt::Display for CacheBypassReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Nonce => write!(f, "nonce"),
            Self::NonAnonymous => write!(f, "non_anonymous"),
            Self::CacheControl => write!(f, "cache_control"),
            Self::SizeUnknown => write!(f, "size_unknown"),
            Self::TooBig => write!(f, "too_big"),
            Self::HTTPError => write!(f, "http_error"),
        }
    }
}

#[derive(Clone, PartialEq, Debug, Default)]
pub enum CacheStatus {
    #[default]
    Disabled,
    Bypass(CacheBypassReason),
    Hit,
    Miss,
}

// Injects itself into a given response to be accessible by middleware
impl CacheStatus {
    fn with_response(self, mut resp: AxumResponse) -> AxumResponse {
        resp.extensions_mut().insert(self);
        resp
    }
}

impl fmt::Display for CacheStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "DISABLED"),
            Self::Bypass(_) => write!(f, "BYPASS"),
            Self::Hit => write!(f, "HIT"),
            Self::Miss => write!(f, "MISS"),
        }
    }
}

#[derive(Clone)]
struct CacheItem {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
}

#[derive(Clone)]
pub struct Cache {
    cache: MokaCache<Arc<RequestContext>, CacheItem>,
    max_item_size: u64,
    cache_non_anonymous: bool,
}

// Estimate rough amount of bytes that cache entry takes in memory
fn weigh_entry(k: &Arc<RequestContext>, v: &CacheItem) -> u32 {
    let mut cost = v.body.len()
        + std::mem::size_of::<CacheItem>()
        + std::mem::size_of::<Arc<RequestContext>>()
        + k.method_name.as_ref().map(|x| x.len()).unwrap_or(0)
        + k.arg.as_ref().map(|x| x.len()).unwrap_or(0)
        + k.nonce.as_ref().map(|x| x.len()).unwrap_or(0)
        + 58; // 2 x Principal

    for (k, v) in v.headers.iter() {
        cost += k.as_str().as_bytes().len();
        cost += v.as_bytes().len();
    }

    cost as u32
}

// Max cost represents the max sum of items' costs that the cache can hold.
// If this is exceeded then some items would be purged.
// We assume that a cache item's cost is a number of bytes it takes in memory.
impl Cache {
    pub fn new(
        cache_size: u64,
        max_item_size: u64,
        ttl: Duration,
        cache_non_anonymous: bool,
    ) -> Result<Self, Error> {
        if max_item_size >= cache_size {
            return Err(anyhow!(
                "Cache item size should be less than whole cache size"
            ));
        }

        let cache = MokaCacheBuilder::new(cache_size)
            .time_to_live(ttl)
            .weigher(weigh_entry)
            .build();

        Ok(Self {
            cache,
            max_item_size,
            cache_non_anonymous,
        })
    }

    // Stores the response components in the cache
    // Response itself cannot be stored since it's not cloneable, so we have to rebuild it
    async fn store(&self, ctx: Arc<RequestContext>, parts: &response::Parts, body: Bytes) {
        let item = CacheItem {
            status: parts.status,
            version: parts.version,
            headers: parts.headers.clone(),
            body,
        };

        // Insert the response into the cache & wait for it to persist there
        self.cache.insert(ctx, item).await;
    }

    // Looks up the request in the cache
    async fn lookup(&self, ctx: &RequestContext) -> Option<AxumResponse> {
        let item = match self.cache.get(ctx).await {
            Some(v) => v,
            None => return None,
        };

        // If an item was found -> construct a response from the cached data
        let mut builder = Response::builder()
            .status(item.status)
            .version(item.version);

        *builder.headers_mut().unwrap() = item.headers;

        Some(
            builder
                .body(axum::body::boxed(Body::from(item.body)))
                .unwrap(),
        )
    }

    pub fn size(&self) -> u64 {
        self.cache.weighted_size()
    }

    pub fn len(&self) -> u64 {
        self.cache.entry_count()
    }

    pub async fn housekeep(&self) {
        self.cache.run_pending_tasks().await;
    }

    // For now stuff below is used only in tests, but belongs here
    #[allow(dead_code)]
    async fn clear(&self) {
        self.cache.invalidate_all();
        self.housekeep().await;
    }
}

// Try to get & parse content-length header
fn extract_content_length(resp: &Response) -> Result<Option<u64>, Error> {
    let size = match resp.headers().get(CONTENT_LENGTH) {
        Some(v) => v.to_str()?.parse::<u64>()?,
        None => return Ok(None),
    };

    Ok(Some(size))
}

// Axum middleware that handles response caching
pub async fn cache_middleware(
    State(cache): State<Arc<Cache>>,
    Extension(ctx): Extension<Arc<RequestContext>>,
    request: Request<Body>,
    next: Next<Body>,
) -> Result<impl IntoResponse, ApiError> {
    let bypass_reason = (|| {
        // Skip cache if there's a nonce
        if ctx.nonce.is_some() {
            return Some(CacheBypassReason::Nonce);
        }

        // Skip non-anonymous requests if not configured to process them
        if Some(false) == ctx.is_anonymous() && !cache.cache_non_anonymous {
            return Some(CacheBypassReason::NonAnonymous);
        }

        // Check if we have a Cache-Control header and if it asks us not to use the cache
        if let Some(v) = request.headers().get(CACHE_CONTROL) {
            if let Ok(hdr) = v.to_str() {
                if SKIP_CACHE_DIRECTIVES.iter().any(|&x| hdr.contains(x)) {
                    return Some(CacheBypassReason::CacheControl);
                }
            }
        }

        None
    })();

    if let Some(v) = bypass_reason {
        return Ok(CacheStatus::Bypass(v).with_response(next.run(request).await));
    }

    // Try to look up the request in the cache
    if let Some(v) = cache.lookup(&ctx).await {
        return Ok(CacheStatus::Hit.with_response(v));
    }

    // If not found - pass the request down the stack
    let response = next.run(request).await;

    // Do not cache non-2xx responses
    if !response.status().is_success() {
        return Ok(CacheStatus::Bypass(CacheBypassReason::HTTPError).with_response(response));
    }

    let content_length = extract_content_length(&response).map_err(|_| {
        ErrorCause::MalformedResponse("Malformed Content-Length header in response".into())
    })?;

    // Do not cache responses that have no known size (probably streaming etc)
    let body_size = match content_length {
        Some(v) => v,
        None => {
            return Ok(CacheStatus::Bypass(CacheBypassReason::SizeUnknown).with_response(response))
        }
    };

    // Do not cache items larger than configured
    if body_size > cache.max_item_size {
        return Ok(CacheStatus::Bypass(CacheBypassReason::TooBig).with_response(response));
    }

    // Buffer entire response body to be able to cache it
    let (parts, body) = response.into_parts();
    let body = read_streaming_body(body, body_size as usize).await?;

    // Insert the response into the cache
    cache.store(ctx, &parts, body.clone()).await;

    // Reconstruct the response from components
    let response = Response::from_parts(parts, axum::body::boxed(Body::from(body)));

    Ok(CacheStatus::Miss.with_response(response))
}

#[cfg(test)]
pub mod test;
