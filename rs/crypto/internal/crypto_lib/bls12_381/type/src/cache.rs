use crate::G2Affine;
use cached::{Cached, SizedCache};
use parking_lot::Mutex;
use std::sync::LazyLock;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct G2PublicKeyCacheStatistics {
    pub size: usize,
    pub hits: u64,
    pub misses: u64,
}

impl G2PublicKeyCacheStatistics {
    fn new(size: usize, hits: u64, misses: u64) -> Self {
        Self { size, hits, misses }
    }
}

/// A cache for G2 Public Keys
pub(crate) struct G2PublicKeyCache {
    cache: Mutex<SizedCache<[u8; G2Affine::BYTES], G2Affine>>,
}

static GLOBAL_G2PK_CACHE: LazyLock<G2PublicKeyCache> =
    LazyLock::new(|| G2PublicKeyCache::new(G2PublicKeyCache::SIZE_OF_GLOBAL_CACHE));

impl G2PublicKeyCache {
    /// Specify the size of the global cache used for public keys
    pub const SIZE_OF_GLOBAL_CACHE: usize = 1000;

    /// Create a new signature cache with the specified maximum size
    fn new(max_size: usize) -> Self {
        let cache = Mutex::<SizedCache<[u8; G2Affine::BYTES], G2Affine>>::new(
            SizedCache::with_size(max_size),
        );
        Self { cache }
    }

    /// Return a reference to the global signature cache
    pub(crate) fn global() -> &'static Self {
        &GLOBAL_G2PK_CACHE
    }

    /// Check the cache for an already checked G2 public key
    pub(crate) fn get(&self, bytes: &[u8; G2Affine::BYTES]) -> Option<G2Affine> {
        let mut cache = self.cache.lock();
        cache.cache_get(bytes).cloned()
    }

    /// Insert a new G2 public key into the cache
    pub(crate) fn insert(&self, key: G2Affine) {
        let bytes = key.serialize();
        let mut cache = self.cache.lock();
        cache.cache_set(bytes, key);
    }

    /// Return statistics about the cache
    ///
    /// Returns the size of the cache, the number of cache hits, and
    /// the number of cache misses
    pub(crate) fn cache_statistics(&self) -> G2PublicKeyCacheStatistics {
        let cache = self.cache.lock();

        let cache_size = cache.cache_size();
        let hits = cache.cache_hits().unwrap_or(0);
        let misses = cache.cache_misses().unwrap_or(0);

        G2PublicKeyCacheStatistics::new(cache_size, hits, misses)
    }
}
