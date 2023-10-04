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
use http::header::{HeaderMap, CACHE_CONTROL, CONTENT_LENGTH};
use http::{response, Version};
use http_body::{combinators::UnsyncBoxBody, Body as HttpBody, LengthLimitError, Limited};
use hyper::body;
use stretto::CacheBuilder;

use crate::routes::{ApiError, ErrorCause, RequestContext};

// Standard response used to pass between middlewares
type AxumResponse = Response<UnsyncBoxBody<bytes::Bytes, axum::Error>>;

// A list of possible Cache-Control directives that ask us not to cache the response
const SKIP_CACHE_DIRECTIVES: &[&str] = &["no-store", "no-cache", "max-age=0"];

// This is calculated from the historical data and needed for estimating Cache counters
const AVG_CACHE_VALUE_SIZE: usize = 800;

// Read the body from the available stream enforcing a size limit
async fn read_streaming_body<H: HttpBody>(
    body_stream: H,
    size_limit: usize,
) -> Result<Vec<u8>, ErrorCause>
where
    <H as HttpBody>::Error: std::error::Error + Send + Sync + 'static,
{
    let limited_body = Limited::new(body_stream, size_limit);

    match body::to_bytes(limited_body).await {
        Ok(data) => Ok(data.to_vec()),

        Err(err) => {
            if err.downcast_ref::<LengthLimitError>().is_some() {
                return Err(ErrorCause::Other("too large response body".into()));
            }

            Err(ErrorCause::Other(format!(
                "unable to read response body: {err}"
            )))
        }
    }
}

// Reason why the caching was skipped
#[derive(Debug, Clone, PartialEq)]
pub enum CacheBypassReason {
    Nonce,
    NonAnonymous,
    CacheControl,
    SizeUnknown,
    TooBig,
}

impl fmt::Display for CacheBypassReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Nonce => write!(f, "nonce"),
            Self::NonAnonymous => write!(f, "non_anonymous"),
            Self::CacheControl => write!(f, "cache_control"),
            Self::SizeUnknown => write!(f, "size_unknown"),
            Self::TooBig => write!(f, "too_big"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub enum CacheStatus {
    #[default]
    Disabled,
    Bypass(CacheBypassReason),
    Hit,
    Miss,
    Error(String), // TODO remove if no errors manifest in prod
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
            Self::Error(_) => write!(f, "ERROR"),
        }
    }
}

struct CacheItem {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Clone)]
pub struct Cache {
    cache: stretto::Cache<RequestContext, CacheItem>,
    max_item_size: usize,
    ttl: Duration,
    cache_non_anonymous: bool,
}

// Max cost represents the max sum of items' costs that the cache can hold.
// If this is exceeded then some items would be purged.
// We assume that a cache item's cost is a number of bytes it takes in memory.
impl Cache {
    pub fn new(
        cache_size: u64,
        max_item_size: usize,
        ttl: Duration,
        cache_non_anonymous: bool,
    ) -> Result<Self, Error> {
        if max_item_size >= cache_size as usize {
            return Err(anyhow!(
                "Cache item size should be less than whole cache size"
            ));
        }

        Ok(Self {
            cache: CacheBuilder::new(
                // That's the recommended way of estimating it
                (cache_size as usize) / AVG_CACHE_VALUE_SIZE * 10,
                cache_size as i64,
            )
            .finalize()
            .unwrap(),

            max_item_size,
            ttl,
            cache_non_anonymous,
        })
    }

    // Stores the response components in the cache
    // Response itself cannot be stored since it's not cloneable, so we have to rebuild it
    fn store(
        &self,
        ctx: RequestContext,
        parts: &response::Parts,
        body: &[u8],
    ) -> Result<(), Error> {
        // Make sure that the vector has the smallest possible memory footprint
        let mut body = body.to_vec();
        body.shrink_to_fit();

        let item = CacheItem {
            status: parts.status,
            version: parts.version,
            headers: parts.headers.clone(),
            body,
        };

        // Estimate the storage cost in bytes
        // This is probably not the exact size that CacheItem would take in memory, but close enough I guess
        let mut cost = item.body.capacity() + std::mem::size_of::<CacheItem>();
        for (k, v) in item.headers.iter() {
            cost += k.as_str().as_bytes().len();
            cost += v.as_bytes().len();
        }

        // Insert the response into the cache & wait for it to persist there
        self.cache
            .try_insert_with_ttl(ctx, item, cost as i64, self.ttl)?;
        self.cache.wait()?;

        Ok(())
    }

    // Looks up the request in the cache
    fn lookup(&self, ctx: &RequestContext) -> Option<AxumResponse> {
        let item = match self.cache.get(ctx) {
            Some(v) => v,
            None => return None,
        };

        let item = item.value();

        // If an item was found -> construct a response from cached data
        let mut builder = Response::builder()
            .status(item.status)
            .version(item.version);

        for (k, v) in item.headers.iter() {
            builder = builder.header(k.clone(), v.clone());
        }

        Some(
            builder
                .body(axum::body::boxed(Body::from(item.body.clone())))
                .unwrap(),
        )
    }

    // For now used only in tests, but belongs here

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.cache.len()
    }

    #[allow(dead_code)]
    fn clear(&self) -> Result<(), Error> {
        self.cache.clear()?;
        self.cache.wait()?;
        Ok(())
    }
}

// Try to get & parse content-length header
fn extract_content_length(resp: &Response) -> Result<Option<usize>, Error> {
    let size = match resp.headers().get(CONTENT_LENGTH) {
        Some(v) => v.to_str()?.parse::<usize>()?,
        None => return Ok(None),
    };

    Ok(Some(size))
}

// Axum middleware that handles response caching
pub async fn cache_middleware(
    State(cache): State<Arc<Cache>>,
    Extension(ctx): Extension<RequestContext>,
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

        // Check if we have a Cache-Control header and if it asks us not to use cache
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
    if let Some(v) = cache.lookup(&ctx) {
        return Ok(CacheStatus::Hit.with_response(v));
    }

    // If not found - pass the request down the stack
    let response = next.run(request).await;

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
    let body = read_streaming_body(body, body_size).await?;

    // Insert the response into the cache
    let cache_status = match cache.store(ctx, &parts, &body) {
        Err(e) => CacheStatus::Error(e.to_string()),
        Ok(_) => CacheStatus::Miss,
    };

    // Reconstruct the response from components
    let response = Response::from_parts(parts, axum::body::boxed(Body::from(body)));

    Ok(cache_status.with_response(response))
}

#[cfg(test)]
pub mod test;
