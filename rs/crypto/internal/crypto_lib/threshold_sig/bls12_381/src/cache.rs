//! Cache for BLS signatures

use ic_utils_mem_lru::LruCacheWithStats;
use std::sync::LazyLock;

#[cfg(test)]
mod tests;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SignatureCacheStatistics {
    pub size: usize,
    pub hits: u64,
    pub misses: u64,
}

impl SignatureCacheStatistics {
    fn new(size: usize, hits: u64, misses: u64) -> Self {
        Self { size, hits, misses }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub(crate) struct SignatureCacheEntry {
    hash: [u8; 32],
}

impl SignatureCacheEntry {
    /// Hash the verification inputs to a short string
    ///
    /// This reduces the amount of memory the cache consumes
    pub(crate) fn new(pk: &[u8; 96], sig: &[u8; 48], msg: &[u8]) -> Self {
        let mut sha256 = ic_crypto_sha2::Sha256::new();
        sha256.write(pk);
        sha256.write(sig);
        sha256.write(msg);
        let hash = sha256.finish();
        Self { hash }
    }
}

/// A cache for BLS signature verification
pub(crate) struct SignatureCache {
    cache: parking_lot::Mutex<LruCacheWithStats<SignatureCacheEntry, ()>>,
}

static GLOBAL_SIGNATURE_CACHE: LazyLock<SignatureCache> =
    LazyLock::new(|| SignatureCache::new(SignatureCache::SIZE_OF_GLOBAL_CACHE));

impl SignatureCache {
    /// Specify the size of the global signature cache
    ///
    /// Each entry stores a 32-byte hash (see [`SignatureCacheEntry`]) plus the
    /// per-entry bookkeeping of the underlying LRU cache (a hash-map slot and
    /// the intrusive linked-list node), on the order of a hundred bytes per
    /// entry. With the currently specified size the cache consumes a few MB of
    /// RAM.
    pub const SIZE_OF_GLOBAL_CACHE: usize = 100000;

    /// Create a new signature cache with the specified maximum size
    fn new(max_size: usize) -> Self {
        let cache = parking_lot::Mutex::<LruCacheWithStats<SignatureCacheEntry, ()>>::new(
            LruCacheWithStats::with_size(max_size),
        );
        Self { cache }
    }

    /// Return a reference to the global signature cache
    pub(crate) fn global() -> &'static Self {
        &GLOBAL_SIGNATURE_CACHE
    }

    /// Check if a cache entry already exists
    ///
    /// Returns true if found, false otherwise
    pub(crate) fn contains(&self, entry: &SignatureCacheEntry) -> bool {
        let mut cache = self.cache.lock();
        cache.get(entry).is_some()
    }

    /// Insert a entry into the signature cache
    ///
    /// # Warning
    /// A signature should only be added to the cache if it has previously
    /// been verified to be valid.
    pub(crate) fn insert(&self, entry: &SignatureCacheEntry) {
        let mut cache = self.cache.lock();
        cache.insert(*entry, ());
    }

    /// Return statistics about the cache
    ///
    /// Returns the size of the cache, the number of cache hits, and
    /// the number of cache misses
    pub(crate) fn cache_statistics(&self) -> SignatureCacheStatistics {
        let cache = self.cache.lock();

        let cache_size = cache.len();
        let hits = cache.hits();
        let misses = cache.misses();

        SignatureCacheStatistics::new(cache_size, hits, misses)
    }
}
