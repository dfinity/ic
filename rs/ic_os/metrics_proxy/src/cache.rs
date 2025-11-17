use crate::metrics::CacheMetrics;
use axum::http;
use axum::response::Response;
use futures_util::FutureExt;
use http::Request;
use http_body_util::BodyExt;
use itertools::Itertools;
use opentelemetry::KeyValue;
use prometheus_parse::{self, Sample};
use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tower::{Layer, Service};

/// Caching primitives used by metrics-proxy.
///
/// This file contains caching primitives for both the code that filters and
/// reduces time resolution of metrics, as well as the code that deals with
/// post-processed HTTP responses from backends.

#[derive(Debug, PartialEq, Eq, Hash)]
struct LabelPair {
    name: String,
    value: String,
}
#[derive(Debug, PartialEq, Eq, Hash)]
struct OrderedLabelSet(Vec<LabelPair>);

/// A comparable struct used to retrieve values from a cache keyed by label names.
impl From<&Sample> for OrderedLabelSet {
    fn from(x: &Sample) -> OrderedLabelSet {
        // We use mut here because the alternative (concat)
        // requires LabelPair to be clonable (less efficient).
        let mut labelset: Vec<LabelPair> = vec![LabelPair {
            name: "__name__".to_string(),
            value: x.metric.to_string(),
        }];
        labelset.extend(
            x.labels
                .iter()
                .map(|m| LabelPair {
                    name: m.0.to_string(),
                    value: m.1.to_string(),
                })
                .collect::<Vec<LabelPair>>(),
        );
        OrderedLabelSet(
            labelset
                .into_iter()
                .sorted_unstable_by_key(|k| k.name.to_string())
                .collect(),
        )
    }
}

struct SampleCacheEntry {
    sample: prometheus_parse::Sample,
    saved_at: Instant,
}

#[derive(Default)]
/// Sample cache store.  Concurrent users of this structure are
/// expected to wrap this in a lock and use it while locked.
/// This structure is otherwise not concurrency-safe.
pub struct SampleCacheStore {
    cache: HashMap<OrderedLabelSet, SampleCacheEntry>,
}

impl SampleCacheStore {
    #[must_use]
    pub fn get(
        &self,
        sample: &prometheus_parse::Sample,
        when: Instant,
        staleness: Duration,
    ) -> Option<Sample> {
        let key = OrderedLabelSet::from(sample);
        let value = self.cache.get(&key);
        match value {
            Some(v) => {
                if let Some(when_minus_staleness) = when.checked_sub(staleness) {
                    if v.saved_at > when_minus_staleness {
                        Some(v.sample.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn put(&mut self, sample: prometheus_parse::Sample, at_: Instant) {
        let cache = &mut self.cache;
        cache.insert(
            OrderedLabelSet::from(&sample),
            SampleCacheEntry {
                sample,
                saved_at: at_,
            },
        );
    }
}

/// The type used by entries in DeadlineCacher-owned hashmaps.
type DeadlineCacherEntry<EntryT> = Arc<RwLock<Option<Arc<EntryT>>>>;

#[derive(Debug, Clone)]
/// Multi-threaded, generic cache for future results.
/// During optimistic caching case, it imposes minimal overhead
/// to perform the bookkeeping overhead that the cache creates.
///
/// The cache is designed to hold the global cache mutex for as
/// little time as possible (e.g. the backend request fetch is done
/// with the global cache lock not held), so that parallel requests
/// to multiple resources can proceed without lock contention.
/// To ensure that parallel requests to the same resource are
/// consolidated into a single backend request, there is an
/// additional lock per resource, which is held for the duration
/// of the backend request, so that when the fetch of the resource
/// is done, all parallel readers of the same resource get served
/// the results of the single request initiated by the first
/// requestor.
pub struct DeadlineCacher<KeyT: 'static, EntryT: Sized + 'static> {
    variants: Arc<Mutex<HashMap<KeyT, DeadlineCacherEntry<EntryT>>>>,
    staleness: Duration,
}

impl<KeyT: Eq + Hash + Clone + Sync + Send, EntryT: Sync + Send> DeadlineCacher<KeyT, EntryT> {
    pub fn new(staleness: Duration) -> Self {
        DeadlineCacher {
            variants: Arc::new(Mutex::new(HashMap::new())),
            staleness,
        }
    }

    /// Get a cached item based on a cache key, or if not cached,
    /// use a future that returns a tuple (T, cached) indicating
    /// if the instance of T should be cached or not.
    ///
    /// Returns a tuple (Arc<Y>, bool) where the boolean indicates
    /// if the result was from cache or not.  This boolean can be
    /// used by the caller to do bookkeeping on cache effectiveness.
    pub async fn get_or_insert_with(
        &self,
        cache_key: KeyT,
        fut: impl Future<Output = (EntryT, bool)>,
    ) -> (Arc<EntryT>, bool) {
        let hashmap = self.variants.clone();

        // Lock the global cache.
        let mut locked_hashmap = hashmap.lock().await;

        // Check the cache for an entry corresponding to a resource.
        if let Some(entry) = locked_hashmap.get(&cache_key) {
            // There is an entry.  Lock it for read first.
            let guard = entry.read().await;
            // The following cached_value will always be Some() for pages that
            // were cacheable in the past.  If the page wasn't cacheable at the
            // last request, this will be None and we will proceed below.
            // The entry guard exists solely so that requests for the same cache
            // key block as the request is proceeding, while enabling us to drop
            // the global cache lock so that other requests hitting a different
            // cache key can proceed in parallel without full contention on the
            // global cache hashmap itself.
            if let Some(cached_value) = guard.clone() {
                // Cache has an entry guard, and entry guard has a value.
                // Return the value directly, and note it was cached.
                return (cached_value, true);
            }
        }

        // We did not find it in the cache (it's not cached)
        // Write the entry guard corresponding to the cache key into the cache,
        // then lock the entry guard and unlock the cache to permit other
        // requests for different cache keys to proceed forward.
        let entry_guard = Arc::new(RwLock::new(None));
        let mut locked_entry_guard = entry_guard.write().await;
        locked_hashmap.insert(cache_key.clone(), entry_guard.clone());
        drop(locked_hashmap);

        // Fetch and cache if the fetcher function returns true
        // as part of its return tuple.  Fetching is accomplished
        // by actually running the future, which is otherwise left
        // unrun and dropped (therefore canceled) if not used.
        let (item3, cache_it) = fut.await;
        let arced = Arc::new(item3);
        if cache_it {
            // Save into cache *only* if cache_it is true.
            // Otherwise leave the empty None guard in place.
            *locked_entry_guard = Some(arced.clone());
        };

        // Now, schedule the asynchronous removal of the cached
        // item from the hashmap.
        let staleness = self.staleness;
        let variants = self.variants.clone();
        tokio::task::spawn(async move {
            tokio::time::sleep(staleness).await;
            let mut write_hashmap = variants.lock().await;
            write_hashmap.remove(&cache_key);
            drop(write_hashmap);
        });

        // Now unlock the entry guard altogether.  Other threads
        // trying to access the same cache key can proceed and
        // immediately get the result that will be returned to
        // them at the beginning of this function (within the context
        // of the read lock of the entry guard).
        drop(locked_entry_guard);

        // Now return the value to the happy requestor that caused
        // the backend fetch to begin with.
        (arced, false)
    }
}

#[derive(Clone)]
// Tower layer for a request/response cache per
// resource and authentication credentials.
pub struct CacheLayer {
    cacher: DeadlineCacher<String, CachedResponse>,
}

impl CacheLayer {
    pub fn new(staleness: Duration) -> Self {
        CacheLayer {
            cacher: DeadlineCacher::new(staleness),
        }
    }
}

impl<S> Layer<S> for CacheLayer {
    type Service = CacheService<S>;

    fn layer(&self, service: S) -> Self::Service {
        CacheService {
            cacher: self.cacher.clone(),
            metrics: CacheMetrics::default(),
            inner: service,
        }
    }
}

#[derive(Debug, Clone)]
/// Concrete implementation of the cache storage for
/// HTTP responses.
struct CachedResponse {
    version: axum::http::Version,
    status: axum::http::StatusCode,
    headers: http::HeaderMap,
    contents: axum::body::Bytes,
}

#[derive(Clone)]
// Tower service implementation, used by CacheLayer, of
// the request/response cache.  It uses the DeadlineCacher
// structure to provide an asynchronous cache that coalesces
// incoming requests designated as cacheable.
pub struct CacheService<S> {
    cacher: DeadlineCacher<String, CachedResponse>,
    metrics: CacheMetrics,
    inner: S,
}

impl<S> Service<Request<axum::body::Body>> for CacheService<S>
where
    S: Service<Request<axum::body::Body>, Response = Response<axum::body::Body>>
        + std::marker::Send
        + 'static,
    S::Error: Into<Box<dyn std::error::Error>>,
    S::Error: std::fmt::Debug,
    S::Error: std::marker::Send,
    <S as Service<http::Request<axum::body::Body>>>::Future: std::marker::Send,
{
    type Error = S::Error;
    type Response = Response<axum::body::Body>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<axum::body::Body>) -> Self::Future {
        let reqversion = request.version();
        let reqheaders = request.headers();
        let frontend_label = format!(
            "{}{}",
            match reqheaders.get("host") {
                Some(host) => host.to_str().unwrap_or("invalid-hostname"),
                None => "no-hostname",
            },
            request.uri()
        );
        let cache_key = format!(
            "{}\n{:?}\n{:?}",
            request.uri(),
            reqheaders.get("Authorization"),
            reqheaders.get("Proxy-Authorization")
        );
        let client_call = self.inner.call(request);
        let cacher = self.cacher.clone();
        let metrics = self.metrics.clone();

        let fut = async move {
            fn badresp(version: axum::http::Version, reason: String) -> (CachedResponse, bool) {
                (
                    CachedResponse {
                        version,
                        status: http::StatusCode::INTERNAL_SERVER_ERROR,
                        headers: http::HeaderMap::new(),
                        contents: reason.into(),
                    },
                    false,
                )
            }
            match client_call.await {
                Err(e) => badresp(
                    reqversion,
                    format!("Proxy error downstream from cacher: {:?}", e).to_string(),
                ),
                Ok(res) => {
                    let (parts, body) = res.into_parts();
                    match body.collect().await {
                        Err(e) => badresp(
                            parts.version,
                            format!("Proxy error fetching body: {:?}", e).to_string(),
                        ),
                        Ok(data) => (
                            CachedResponse {
                                version: parts.version,
                                status: parts.status,
                                headers: parts.headers,
                                contents: data.to_bytes(),
                            },
                            parts.status.is_success(),
                        ),
                    }
                }
            }
        };

        async move {
            let (res, cached) = cacher.get_or_insert_with(cache_key, fut).await;

            // Note the caching status of the returned page.
            match cached {
                true => metrics.http_cache_hits,
                false => metrics.http_cache_misses,
            }
            .add(
                1,
                &[
                    KeyValue::new("http_response_status_code", res.status.as_str().to_string()),
                    KeyValue::new("frontend", frontend_label),
                ],
            );

            // Formulate a response based on the returned page.
            let mut respb = http::response::Response::builder().version(res.version);
            let headers = respb.headers_mut().unwrap();
            headers.extend(res.headers.clone());
            let resp = respb
                .status(res.status)
                .body(axum::body::Body::from(res.contents.clone()))
                .map_err(axum::Error::new)
                .unwrap();
            Ok(resp)
        }
        .boxed()
    }
}
