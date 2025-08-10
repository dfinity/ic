//! Cache for BLS signatures

use cached::{Cached, SizedCache};

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
    cache: parking_lot::Mutex<SizedCache<SignatureCacheEntry, ()>>,
}

lazy_static::lazy_static! {
    static ref GLOBAL_SIGNATURE_CACHE: SignatureCache = SignatureCache::new(SignatureCache::SIZE_OF_GLOBAL_CACHE);
}

impl SignatureCache {
    /// Specify the size of the global signature cache
    ///
    /// cached::SizedCache uses approximately 65 bytes of memory
    /// per entry, so with the currently specified size the cache
    /// consumes ~ 6.5 MB of RAM.
    ///
    /// The derivation for 65 bytes is as follows:
    /// - [u8; 32] is 32 bytes
    /// - Option<[u8; 32]> is 33 bytes
    /// - Option<([u8; 32], ())> is also 33 bytes
    /// - cached's `ListEntry<T>` contains a T plus two usize elements
    /// - Due to structure padding `ListEntry<Option<([u8; 32], ())>>` is
    ///   56 bytes rather than 33+2*8=49 bytes. (By using a 31 byte hash
    ///   we could save some substantial amount of cache memory.)
    /// - The other overhead of `SizedCache` is a `hashbrown::RawTable<usize>`,
    ///   which is estimated to consume 9 bytes per element.
    /// - This leads to an estimate of 65 bytes per element, plus some
    ///   fixed overhead.
    pub const SIZE_OF_GLOBAL_CACHE: usize = 100000;

    /// Create a new signature cache with the specified maximum size
    fn new(max_size: usize) -> Self {
        let cache = parking_lot::Mutex::<SizedCache<SignatureCacheEntry, ()>>::new(
            SizedCache::with_size(max_size),
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
        cache.cache_get(entry).is_some()
    }

    /// Insert a entry into the signature cache
    ///
    /// # Warning
    /// A signature should only be added to the cache if it has previously
    /// been verified to be valid.
    pub(crate) fn insert(&self, entry: &SignatureCacheEntry) {
        let mut cache = self.cache.lock();
        cache.cache_set(*entry, ());
    }

    /// Return statistics about the cache
    ///
    /// Returns the size of the cache, the number of cache hits, and
    /// the number of cache misses
    pub(crate) fn cache_statistics(&self) -> SignatureCacheStatistics {
        let cache = self.cache.lock();

        let cache_size = cache.cache_size();
        let hits = cache.cache_hits().unwrap_or(0);
        let misses = cache.cache_misses().unwrap_or(0);

        SignatureCacheStatistics::new(cache_size, hits, misses)
    }
}
