use std::{
    hash::{Hash, Hasher},
    sync::Arc,
    time::Duration,
};

use axum::{
    body::Body,
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use ic_bn_lib::prometheus::{IntCounter, Registry, register_int_counter_with_registry};
use ic_types::SubnetId;
use moka::sync::Cache;

use crate::{
    errors::{ApiError, ErrorCause},
    routes::RequestContext,
};

#[derive(Clone, Debug)]
struct CacheKey {
    subnet_id: SubnetId,
    paths: Vec<Vec<Vec<u8>>>,
}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.subnet_id.hash(state);
        self.paths.hash(state);
    }
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.subnet_id == other.subnet_id && self.paths == other.paths
    }
}

impl Eq for CacheKey {}

#[derive(Clone)]
struct CachedResponse {
    status: http::StatusCode,
    body: Bytes,
}

pub struct SubnetReadStateCacheState {
    cache: Cache<CacheKey, CachedResponse>,
    pub hits: IntCounter,
    pub misses: IntCounter,
}

impl SubnetReadStateCacheState {
    pub fn new(ttl: Duration, max_entries: u64, registry: &Registry) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_entries)
            .time_to_live(ttl)
            .build();

        let hits = register_int_counter_with_registry!(
            "subnet_read_state_cache_hits_total",
            "Number of cache hits for subnet read_state requests",
            registry
        )
        .unwrap();

        let misses = register_int_counter_with_registry!(
            "subnet_read_state_cache_misses_total",
            "Number of cache misses for subnet read_state requests",
            registry
        )
        .unwrap();

        Self {
            cache,
            hits,
            misses,
        }
    }
}

fn build_cache_key(subnet_id: SubnetId, ctx: &RequestContext) -> Option<CacheKey> {
    let mut paths = ctx.paths.clone()?;
    paths.sort();
    Some(CacheKey { subnet_id, paths })
}

pub async fn subnet_read_state_cache_middleware(
    State(state): State<Arc<SubnetReadStateCacheState>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    let subnet_id = request.extensions().get::<SubnetId>().copied();
    let ctx = request.extensions().get::<Arc<RequestContext>>().cloned();

    let cache_key = subnet_id
        .zip(ctx.as_ref())
        .and_then(|(sid, ctx)| build_cache_key(sid, ctx));

    let cache_key = match cache_key {
        Some(k) => k,
        None => return Ok(next.run(request).await),
    };

    if let Some(cached) = state.cache.get(&cache_key) {
        state.hits.inc();
        return Ok(Response::builder()
            .status(cached.status)
            .body(Body::from(cached.body))
            .unwrap());
    }

    state.misses.inc();

    let response = next.run(request).await;

    if response.status().is_success() {
        let (parts, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024)
            .await
            .map_err(|e| ErrorCause::Other(format!("failed to buffer response body: {e}")))?;

        state.cache.insert(
            cache_key,
            CachedResponse {
                status: parts.status,
                body: body_bytes.clone(),
            },
        );

        Ok(Response::from_parts(parts, Body::from(body_bytes)))
    } else {
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use axum::{Router, body::Body, http::Request, middleware, routing::post};
    use http::StatusCode;
    use ic_types::PrincipalId;
    use tower::Service;

    use crate::{http::RequestType, routes::RequestContext};

    fn make_request(subnet_id: SubnetId, paths: Vec<Vec<Vec<u8>>>) -> Request<Body> {
        let ctx = Arc::new(RequestContext {
            request_type: RequestType::ReadStateSubnetV2,
            paths: Some(paths),
            ..Default::default()
        });

        let mut req = Request::post("/").body(Body::from("body")).unwrap();
        req.extensions_mut().insert(subnet_id);
        req.extensions_mut().insert(ctx);
        req
    }

    async fn dummy_handler() -> impl IntoResponse {
        "response_body"
    }

    fn test_subnet_id(n: u64) -> SubnetId {
        SubnetId::from(PrincipalId::new_subnet_test_id(n))
    }

    #[tokio::test]
    async fn test_cache_hit_and_miss() {
        let registry = Registry::new_custom(None, None).unwrap();
        let state = Arc::new(SubnetReadStateCacheState::new(
            Duration::from_secs(60),
            100,
            &registry,
        ));

        let mut app =
            Router::new()
                .route("/", post(dummy_handler))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    subnet_read_state_cache_middleware,
                ));

        let subnet = test_subnet_id(1);
        let paths = vec![vec![b"time".to_vec()]];

        // First request: cache miss
        let req = make_request(subnet, paths.clone());
        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.misses.get(), 1);
        assert_eq!(state.hits.get(), 0);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "response_body");

        // Second request with same paths: cache hit
        let req = make_request(subnet, paths.clone());
        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.misses.get(), 1);
        assert_eq!(state.hits.get(), 1);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "response_body");
    }

    #[tokio::test]
    async fn test_different_paths_are_separate_entries() {
        let registry = Registry::new_custom(None, None).unwrap();
        let state = Arc::new(SubnetReadStateCacheState::new(
            Duration::from_secs(60),
            100,
            &registry,
        ));

        let mut app =
            Router::new()
                .route("/", post(dummy_handler))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    subnet_read_state_cache_middleware,
                ));

        let subnet = test_subnet_id(1);

        // Request with path A
        let req = make_request(subnet, vec![vec![b"time".to_vec()]]);
        app.call(req).await.unwrap();
        assert_eq!(state.misses.get(), 1);

        // Request with path B: different paths = cache miss
        let req = make_request(subnet, vec![vec![b"subnet".to_vec(), b"pk".to_vec()]]);
        app.call(req).await.unwrap();
        assert_eq!(state.misses.get(), 2);
        assert_eq!(state.hits.get(), 0);
    }

    #[tokio::test]
    async fn test_different_subnets_are_separate_entries() {
        let registry = Registry::new_custom(None, None).unwrap();
        let state = Arc::new(SubnetReadStateCacheState::new(
            Duration::from_secs(60),
            100,
            &registry,
        ));

        let mut app =
            Router::new()
                .route("/", post(dummy_handler))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    subnet_read_state_cache_middleware,
                ));

        let paths = vec![vec![b"time".to_vec()]];

        // Subnet 1
        let req = make_request(test_subnet_id(1), paths.clone());
        app.call(req).await.unwrap();
        assert_eq!(state.misses.get(), 1);

        // Subnet 2: different subnet = cache miss
        let req = make_request(test_subnet_id(2), paths.clone());
        app.call(req).await.unwrap();
        assert_eq!(state.misses.get(), 2);
        assert_eq!(state.hits.get(), 0);
    }

    #[tokio::test]
    async fn test_path_order_does_not_matter() {
        let registry = Registry::new_custom(None, None).unwrap();
        let state = Arc::new(SubnetReadStateCacheState::new(
            Duration::from_secs(60),
            100,
            &registry,
        ));

        let mut app =
            Router::new()
                .route("/", post(dummy_handler))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    subnet_read_state_cache_middleware,
                ));

        let subnet = test_subnet_id(1);

        // Paths in order [A, B]
        let req = make_request(subnet, vec![vec![b"a".to_vec()], vec![b"b".to_vec()]]);
        app.call(req).await.unwrap();
        assert_eq!(state.misses.get(), 1);

        // Same paths in order [B, A]: should be a cache hit due to sorting
        let req = make_request(subnet, vec![vec![b"b".to_vec()], vec![b"a".to_vec()]]);
        app.call(req).await.unwrap();
        assert_eq!(state.hits.get(), 1);
    }

    #[tokio::test]
    async fn test_no_paths_bypasses_cache() {
        let registry = Registry::new_custom(None, None).unwrap();
        let state = Arc::new(SubnetReadStateCacheState::new(
            Duration::from_secs(60),
            100,
            &registry,
        ));

        let mut app =
            Router::new()
                .route("/", post(dummy_handler))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    subnet_read_state_cache_middleware,
                ));

        // Request with no paths in context
        let ctx = Arc::new(RequestContext {
            request_type: RequestType::ReadStateSubnetV2,
            paths: None,
            ..Default::default()
        });

        let mut req = Request::post("/").body(Body::from("body")).unwrap();
        req.extensions_mut().insert(test_subnet_id(1));
        req.extensions_mut().insert(ctx);

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.misses.get(), 0);
        assert_eq!(state.hits.get(), 0);
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let registry = Registry::new_custom(None, None).unwrap();
        let state = Arc::new(SubnetReadStateCacheState::new(
            Duration::from_millis(50),
            100,
            &registry,
        ));

        let mut app =
            Router::new()
                .route("/", post(dummy_handler))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    subnet_read_state_cache_middleware,
                ));

        let subnet = test_subnet_id(1);
        let paths = vec![vec![b"time".to_vec()]];

        // First request: miss
        let req = make_request(subnet, paths.clone());
        app.call(req).await.unwrap();
        assert_eq!(state.misses.get(), 1);

        // Wait for TTL to expire
        tokio::time::sleep(Duration::from_millis(100)).await;

        // After TTL: miss again
        let req = make_request(subnet, paths.clone());
        app.call(req).await.unwrap();
        assert_eq!(state.misses.get(), 2);
    }
}
