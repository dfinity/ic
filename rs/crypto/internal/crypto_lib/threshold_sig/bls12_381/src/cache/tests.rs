use crate::cache::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::RngCore;

fn random_signature_cache_entry<R: RngCore>(rng: &mut R) -> SignatureCacheEntry {
    let mut pk = [0u8; 96];
    let mut sig = [0u8; 48];
    let mut msg = [0u8; 32];

    rng.fill_bytes(&mut pk);
    rng.fill_bytes(&mut sig);
    rng.fill_bytes(&mut msg);

    SignatureCacheEntry::new(&pk, &sig, &msg)
}

#[test]
fn should_have_signature_cache_behave_like_a_lru_cache() {
    let cache_size = 1000;
    let cache = SignatureCache::new(cache_size);

    let rng = &mut reproducible_rng();

    let mut entries = Vec::with_capacity(cache_size);

    for i in 0..cache_size {
        // in each loop of this test we have one cache miss and then 2 hits
        let expected_stats = SignatureCacheStatistics::new(i, 2 * i as u64, i as u64);

        assert_eq!(cache.cache_statistics(), expected_stats);

        let entry = random_signature_cache_entry(rng);

        // the entry is randomly generated so has not been seen before
        assert!(!cache.contains(&entry));

        cache.insert(&entry);

        // now the entry exists
        // we check the cache twice to exercise the hit vs miss logic better
        assert!(cache.contains(&entry));
        assert!(cache.contains(&entry));

        entries.push(entry);
    }

    let expected_stats =
        SignatureCacheStatistics::new(cache_size, 2 * cache_size as u64, cache_size as u64);
    assert_eq!(cache.cache_statistics(), expected_stats);

    // all of the elements we just added are still in the cache
    for entry in &entries {
        assert!(cache.contains(entry));
    }

    let expected_stats =
        SignatureCacheStatistics::new(cache_size, 3 * cache_size as u64, cache_size as u64);
    assert_eq!(cache.cache_statistics(), expected_stats);

    for i in 0..cache_size {
        let entry = random_signature_cache_entry(rng);

        assert_eq!(cache.cache_statistics().size, cache_size);
        assert!(!cache.contains(&entry));

        cache.insert(&entry);
        assert!(cache.contains(&entry));
        // the cache does not grow at this point
        assert_eq!(cache.cache_statistics().size, cache_size);

        // since the cache is LRU, the first n of the elements we added first are gone now
        for entry in entries.iter().take(i) {
            assert!(!cache.contains(entry));
        }
    }

    // since the cache is LRU, all of the elements we added first are gone now
    for entry in &entries {
        assert!(!cache.contains(entry));
    }
}

#[test]
fn should_have_signature_cache_update_lru_status_after_cache_hit() {
    let cache_size = 3;
    let cache = SignatureCache::new(cache_size);

    let rng = &mut reproducible_rng();

    let entry1 = random_signature_cache_entry(rng);
    let entry2 = random_signature_cache_entry(rng);
    let entry3 = random_signature_cache_entry(rng);
    let entry4 = random_signature_cache_entry(rng);

    cache.insert(&entry1);
    cache.insert(&entry2);
    cache.insert(&entry3);

    assert!(cache.contains(&entry1));
    assert!(cache.contains(&entry2));
    assert!(cache.contains(&entry3));
    assert!(!cache.contains(&entry4));

    cache.insert(&entry4); // bumps 1

    // reverse order of cache hits so 4 is LRU
    assert!(cache.contains(&entry4));
    assert!(cache.contains(&entry3));
    assert!(cache.contains(&entry2));
    assert!(!cache.contains(&entry1));

    cache.insert(&entry1); // bumps 4

    assert!(cache.contains(&entry1));
    assert!(cache.contains(&entry2));
    assert!(cache.contains(&entry3));
    assert!(!cache.contains(&entry4));
}
