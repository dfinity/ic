use crate::{G2Affine, G2Prepared};
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
    ///
    /// The logic for this number proceeds as follows:
    ///
    /// - [u8; G2Affine::BYTES] is 96 bytes
    /// - G2Affine is 208 bytes
    /// - ([u8; G2Affine::BYTES], G2Affine) is 304 bytes
    /// - cached's `ListEntry<T>` contains a T plus two usize elements
    /// - Due to structure padding `ListEntry::<([u8; G2Affine::BYTES], G2Affine)>
    ///   is 328 bytes rather than 304+2*8=320
    /// - The other overhead of `SizedCache` is a `hashbrown::RawTable<usize>`,
    ///   which is estimated to consume 9 bytes per element.
    /// - This leads to an estimate of 329 bytes per element, plus some
    ///   fixed overhead.
    ///
    /// The above numbers are for x86-64 and may vary slightly on other machines
    /// due to differing structure layout rules.
    ///
    /// The current size leads to an estimated maximum memory usage of 321 KiB
    pub const SIZE_OF_GLOBAL_CACHE: usize = 1000;

    /// Create a new cache of G2 points with the specified maximum size
    fn new(max_size: usize) -> Self {
        let cache = Mutex::<SizedCache<[u8; G2Affine::BYTES], G2Affine>>::new(
            SizedCache::with_size(max_size),
        );
        Self { cache }
    }

    /// Return a reference to the global cache of G2 points
    pub(crate) fn global() -> &'static Self {
        &GLOBAL_G2PK_CACHE
    }

    /// Check the cache for an already checked G2 public key
    pub(crate) fn get(&self, bytes: &[u8; G2Affine::BYTES]) -> Option<G2Affine> {
        let mut cache = self.cache.lock();
        cache.cache_get(bytes).cloned()
    }

    /// Insert a new G2 public key into the cache
    pub(crate) fn insert(&self, bytes: [u8; G2Affine::BYTES], key: G2Affine) {
        debug_assert_eq!(bytes, key.serialize());
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

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct G2PreparedCacheStatistics {
    pub size: usize,
    pub hits: u64,
    pub misses: u64,
}

impl G2PreparedCacheStatistics {
    fn new(size: usize, hits: u64, misses: u64) -> Self {
        Self { size, hits, misses }
    }
}

/// A cache for G2 Public Keys
pub(crate) struct G2PreparedCache {
    cache: Mutex<SizedCache<[u8; G2Affine::BYTES], G2Prepared>>,
}

static GLOBAL_G2PREP_CACHE: LazyLock<G2PreparedCache> =
    LazyLock::new(|| G2PreparedCache::new(G2PreparedCache::SIZE_OF_GLOBAL_CACHE));

impl G2PreparedCache {
    /// Specify the size of the global cache used for public keys
    ///
    /// This cache is kept small because G2Prepared is quite large,
    /// just under 19 KiB.
    pub const SIZE_OF_GLOBAL_CACHE: usize = 50;

    /// Create a new cache of G2Prepared with the specified maximum size
    fn new(max_size: usize) -> Self {
        let cache = Mutex::<SizedCache<[u8; G2Affine::BYTES], G2Prepared>>::new(
            SizedCache::with_size(max_size),
        );
        Self { cache }
    }

    /// Return a reference to the global G2Prepared cache
    pub(crate) fn global() -> &'static Self {
        &GLOBAL_G2PREP_CACHE
    }

    /// Check the cache for an already prepared G2 element
    pub(crate) fn get(&self, bytes: &[u8; G2Affine::BYTES]) -> Option<G2Prepared> {
        let mut cache = self.cache.lock();
        cache.cache_get(bytes).cloned()
    }

    /// Insert a new G2Prepared into the cache
    pub(crate) fn insert(&self, bytes: [u8; G2Affine::BYTES], prep: G2Prepared) {
        let mut cache = self.cache.lock();
        cache.cache_set(bytes, prep);
    }

    /// Return statistics about the cache
    ///
    /// Returns the size of the cache, the number of cache hits, and
    /// the number of cache misses
    pub(crate) fn cache_statistics(&self) -> G2PreparedCacheStatistics {
        let cache = self.cache.lock();

        let cache_size = cache.cache_size();
        let hits = cache.cache_hits().unwrap_or(0);
        let misses = cache.cache_misses().unwrap_or(0);

        G2PreparedCacheStatistics::new(cache_size, hits, misses)
    }
}
