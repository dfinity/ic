use std::{mem::size_of, sync::Arc, time::Duration};

use axum::{
    body::{Body, HttpBody},
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use ic_bn_lib::http::calc_headers_size;
use ic_bn_lib::prometheus::{
    IntCounter, IntGauge, Registry, register_int_counter_with_registry,
    register_int_gauge_with_registry,
};
use ic_types::SubnetId;
use moka::sync::Cache;

use crate::{
    errors::{ApiError, buffer_body_to_bytes},
    routes::ReadStatePaths,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CacheKey {
    subnet_id: SubnetId,
    paths: ReadStatePaths,
}

fn weigh_entry(key: &CacheKey, value: &Response<Bytes>) -> u32 {
    let size = size_of::<CacheKey>()
        + key.paths.len()
        + size_of::<Response<Bytes>>()
        + calc_headers_size(value.headers())
        + value.body().len();

    size as u32
}

pub struct SubnetReadStateCacheState {
    cache: Cache<CacheKey, Response<Bytes>>,
    max_item_size: usize,
    body_timeout: Duration,
    hits: IntCounter,
    misses: IntCounter,
    entries: IntGauge,
    memory: IntGauge,
}

impl SubnetReadStateCacheState {
    pub fn new(
        ttl: Duration,
        cache_size: u64,
        max_item_size: usize,
        body_timeout: Duration,
        registry: &Registry,
    ) -> Self {
        let cache = Cache::builder()
            .max_capacity(cache_size)
            .weigher(weigh_entry)
            .time_to_live(ttl)
            .build();

        let hits = register_int_counter_with_registry!(
            "subnet_read_state_cache_hits_total",
            "Number of cache hits for subnet read_state requests",
            registry
        )
        .expect("failed to register subnet read_state cache hits metric");

        let misses = register_int_counter_with_registry!(
            "subnet_read_state_cache_misses_total",
            "Number of cache misses for subnet read_state requests",
            registry
        )
        .expect("failed to register subnet read_state cache misses metric");

        let entries = register_int_gauge_with_registry!(
            "subnet_read_state_cache_entries",
            "Number of entries in the subnet read_state cache",
            registry
        )
        .expect("failed to register subnet read_state cache entries metric");

        let memory = register_int_gauge_with_registry!(
            "subnet_read_state_cache_memory_bytes",
            "Memory usage of the subnet read_state cache in bytes",
            registry
        )
        .expect("failed to register subnet read_state cache memory metric");

        Self {
            cache,
            max_item_size,
            body_timeout,
            hits,
            misses,
            entries,
            memory,
        }
    }

    fn update_gauges(&self) {
        self.entries.set(self.cache.entry_count() as i64);
        self.memory.set(self.cache.weighted_size() as i64);
    }
}

pub async fn subnet_read_state_cache_middleware(
    State(state): State<Arc<SubnetReadStateCacheState>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, ApiError> {
    let subnet_id = request.extensions().get::<SubnetId>().copied();
    let paths = request.extensions_mut().remove::<ReadStatePaths>();

    let (Some(subnet_id), Some(paths)) = (subnet_id, paths) else {
        return Ok(next.run(request).await);
    };

    let cache_key = CacheKey { subnet_id, paths };

    if let Some(cached) = state.cache.get(&cache_key) {
        state.hits.inc();
        state.update_gauges();
        return Ok(cached.map(Body::from));
    }

    state.misses.inc();

    let response = next.run(request).await;

    // Return response as-is if it failed or the advertised body size is too big
    if !response.status().is_success()
        || response.body().size_hint().exact() > Some(state.max_item_size as u64)
    {
        return Ok(response);
    }

    let (parts, body) = response.into_parts();
    let body_bytes = buffer_body_to_bytes(body, state.max_item_size, state.body_timeout).await?;

    let cached = Response::from_parts(parts, body_bytes);
    state.cache.insert(cache_key, cached.clone());
    state.update_gauges();

    Ok(cached.map(Body::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use axum::{Router, body::Body, http::Request, middleware, routing::post};
    use http::StatusCode;
    use ic_bn_lib_common::principal;
    use ic_types::{PrincipalId, messages::Blob};
    use tower::Service;

    use crate::http::middleware::process::should_cache_paths;

    const DEFAULT_TTL: Duration = Duration::from_secs(60);
    const DEFAULT_CACHE_SIZE: u64 = 1024 * 1024;
    const DEFAULT_MAX_ITEM_SIZE: usize = 1024 * 1024;
    const DEFAULT_BODY_TIMEOUT: Duration = Duration::from_secs(10);

    fn make_request(subnet_id: SubnetId, paths: Vec<Vec<Vec<u8>>>) -> Request<Body> {
        let paths = paths
            .iter()
            .map(|x| x.iter().map(|x| Blob(x.clone())).collect())
            .collect::<Vec<_>>();

        let mut req = Request::post("/").body(Body::from("body")).unwrap();
        if should_cache_paths(&paths) {
            req.extensions_mut().insert(ReadStatePaths::from(paths));
        }

        req.extensions_mut().insert(subnet_id);
        req
    }

    async fn dummy_handler() -> impl IntoResponse {
        "response_body"
    }

    fn test_subnet_id(n: u64) -> SubnetId {
        SubnetId::from(PrincipalId::new_subnet_test_id(n))
    }

    fn setup_app(ttl: Duration, cache_size: u64) -> (Router, Arc<SubnetReadStateCacheState>) {
        let registry = Registry::new_custom(None, None).unwrap();
        let state = Arc::new(SubnetReadStateCacheState::new(
            ttl,
            cache_size,
            DEFAULT_MAX_ITEM_SIZE,
            DEFAULT_BODY_TIMEOUT,
            &registry,
        ));
        let app =
            Router::new()
                .route("/", post(dummy_handler))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    subnet_read_state_cache_middleware,
                ));

        (app, state)
    }

    fn cacheable_paths() -> Vec<Vec<Vec<u8>>> {
        let subnet_id = principal!("aaaaa-aa").as_slice().to_vec();

        vec![
            vec![b"canister_ranges".to_vec(), subnet_id.clone()],
            vec![b"subnet".to_vec(), subnet_id],
        ]
    }

    #[tokio::test]
    async fn test_cache_hit_and_miss() {
        let (mut app, state) = setup_app(DEFAULT_TTL, DEFAULT_CACHE_SIZE);

        let subnet = test_subnet_id(1);
        let paths = cacheable_paths();

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
        let subnet_id_1 = test_subnet_id(0).get().as_slice().to_vec();
        let subnet_id_2 = test_subnet_id(1).get().as_slice().to_vec();

        let (mut app, state) = setup_app(DEFAULT_TTL, DEFAULT_CACHE_SIZE);

        let subnet = test_subnet_id(1);

        // Request with canister_ranges for subnet A
        let req = make_request(
            subnet,
            vec![
                vec![b"subnet".to_vec(), subnet_id_1.clone()],
                vec![b"canister_ranges".to_vec(), subnet_id_1],
            ],
        );
        app.call(req).await.unwrap();
        assert_eq!(state.misses.get(), 1);

        // Request with canister_ranges for subnet B: different paths = cache miss
        let req = make_request(
            subnet,
            vec![
                vec![b"subnet".to_vec(), subnet_id_2.clone()],
                vec![b"canister_ranges".to_vec(), subnet_id_2],
            ],
        );

        app.call(req).await.unwrap();
        assert_eq!(state.misses.get(), 2);
        assert_eq!(state.hits.get(), 0);
    }

    #[tokio::test]
    async fn test_different_subnets_are_separate_entries() {
        let (mut app, state) = setup_app(DEFAULT_TTL, DEFAULT_CACHE_SIZE);

        let paths = cacheable_paths();

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
        let (mut app, state) = setup_app(DEFAULT_TTL, DEFAULT_CACHE_SIZE);

        let subnet = test_subnet_id(0);
        let subnet_id_1 = test_subnet_id(0).get().as_slice().to_vec();
        let subnet_id_2 = test_subnet_id(1).get().as_slice().to_vec();

        let path_a = vec![b"canister_ranges".to_vec(), subnet_id_1];
        let path_b = vec![b"subnet".to_vec(), subnet_id_2];

        // Paths in order [A, B]
        let req = make_request(subnet, vec![path_a.clone(), path_b.clone()]);
        app.call(req).await.unwrap();
        assert_eq!(state.misses.get(), 1);

        // Same paths in order [B, A]: should be a cache hit due to sorting
        let req = make_request(subnet, vec![path_b, path_a]);
        app.call(req).await.unwrap();
        assert_eq!(state.hits.get(), 1);
    }

    #[tokio::test]
    async fn test_no_paths_bypasses_cache() {
        let (mut app, state) = setup_app(DEFAULT_TTL, DEFAULT_CACHE_SIZE);

        let mut req = Request::post("/").body(Body::from("body")).unwrap();
        req.extensions_mut().insert(test_subnet_id(1));

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.misses.get(), 0);
        assert_eq!(state.hits.get(), 0);
    }

    #[tokio::test]
    async fn test_non_cacheable_paths_bypass_cache() {
        let (mut app, state) = setup_app(DEFAULT_TTL, DEFAULT_CACHE_SIZE);

        let subnet = test_subnet_id(1);

        // "time" is not a cacheable path pattern
        let req = make_request(subnet, vec![vec![b"time".to_vec()]]);
        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.misses.get(), 0);
        assert_eq!(state.hits.get(), 0);

        // Repeat: still no cache interaction
        let req = make_request(subnet, vec![vec![b"time".to_vec()]]);
        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.misses.get(), 0);
        assert_eq!(state.hits.get(), 0);
    }

    #[tokio::test]
    async fn test_mixed_cacheable_and_non_cacheable_bypasses_cache() {
        let (mut app, state) = setup_app(DEFAULT_TTL, DEFAULT_CACHE_SIZE);

        let subnet = test_subnet_id(1);
        let subnet_id = subnet.get().as_slice().to_vec();

        // Mix of cacheable (canister_ranges) and non-cacheable (time)
        let paths = vec![
            vec![b"canister_ranges".to_vec(), subnet_id],
            vec![b"time".to_vec()],
        ];

        let req = make_request(subnet, paths.clone());
        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.misses.get(), 0);
        assert_eq!(state.hits.get(), 0);
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let (mut app, state) = setup_app(Duration::from_millis(50), DEFAULT_CACHE_SIZE);

        let subnet = test_subnet_id(1);
        let paths = cacheable_paths();

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
