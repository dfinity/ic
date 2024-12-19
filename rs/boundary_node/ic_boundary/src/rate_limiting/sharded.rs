use std::{
    hash::Hash,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use dashmap::DashMap;
use ratelimit::Ratelimiter;

use super::generic::create_ratelimiter;

struct Shard {
    limiter: Arc<Ratelimiter>,
    last_access: Instant,
}

// Ratelimiter that creates sub-limiters for each key
pub struct ShardedRatelimiter<K: Hash + Eq + Clone> {
    shards: DashMap<K, Shard>,
    limit: u32,
    dur: Duration,
    ttl: Duration,
    hits: AtomicUsize,
}

impl<K: Hash + Eq + Clone> ShardedRatelimiter<K> {
    pub fn new(limit: u32, dur: Duration, ttl: Duration) -> Self {
        Self {
            shards: DashMap::new(),
            limit,
            dur,
            ttl,
            hits: AtomicUsize::new(0),
        }
    }

    pub fn acquire(&self, key: K, now: Instant) -> bool {
        // Make locking scope narrow, otherwise cleanup will deadlock
        let result = {
            let mut shard = self.shards.entry(key).or_insert_with(|| Shard {
                limiter: Arc::new(create_ratelimiter(self.limit, self.dur)),
                last_access: now,
            });

            shard.last_access = now;
            shard.limiter.try_wait().is_ok()
        };

        // Run cleanup every now and then
        let hits = self.hits.fetch_add(1, Ordering::SeqCst);
        if hits % 10000 == 0 {
            self.cleanup(now);
        }

        result
    }

    fn cleanup(&self, now: Instant) {
        self.shards.retain(|_, v| (now - v.last_access) < self.ttl);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sharded() {
        let s: ShardedRatelimiter<String> =
            ShardedRatelimiter::new(10, Duration::from_secs(1), Duration::from_secs(5));

        // Check 1st shard
        let now = Instant::now();
        for _ in 0..10 {
            assert!(s.acquire("foo".into(), now));
        }
        assert!(!s.acquire("foo".into(), now));

        // Check 2nd shard
        let now = Instant::now();
        for _ in 0..10 {
            assert!(s.acquire("bar".into(), now));
        }
        assert!(!s.acquire("bar".into(), now));

        // Cleanup
        s.cleanup(now + Duration::from_secs(6));

        // Make sure shards were removed and recreated
        let now = Instant::now();
        for _ in 0..10 {
            assert!(s.acquire("foo".into(), now));
        }
        assert!(!s.acquire("foo".into(), now));

        let now = Instant::now();
        for _ in 0..10 {
            assert!(s.acquire("bar".into(), now));
        }
        assert!(!s.acquire("bar".into(), now));
    }
}
