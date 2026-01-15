use std::{hash::Hash, sync::Arc, time::Duration};

use moka::sync::Cache;
use ratelimit::Ratelimiter;

pub fn create_ratelimiter(limit: u32, burst: u32, duration: Duration) -> Ratelimiter {
    Ratelimiter::builder(1, duration.checked_div(limit).unwrap_or(Duration::ZERO))
        .max_tokens(burst as u64)
        .initial_available(burst as u64)
        .build()
        .unwrap()
}

#[derive(Clone)]
struct Shard {
    limiter: Arc<Ratelimiter>,
}

// Ratelimiter that creates sub-limiters for each key
pub struct ShardedRatelimiter<K: Send + Sync + Hash + Eq + Clone + 'static> {
    shards: Cache<K, Shard>,
    limit: u32,
    burst: u32,
    dur: Duration,
}

impl<K: Send + Sync + Hash + Eq + Clone + 'static> ShardedRatelimiter<K> {
    pub fn new(limit: u32, burst: u32, dur: Duration, tti: Duration, max_shards: u64) -> Self {
        let shards = Cache::builder()
            .time_to_idle(tti)
            .max_capacity(max_shards)
            .build();

        Self {
            shards,
            limit,
            burst,
            dur,
        }
    }

    pub fn acquire(&self, key: K) -> bool {
        let shard = self.shards.get_with(key, || Shard {
            limiter: Arc::new(create_ratelimiter(self.limit, self.burst, self.dur)),
        });

        shard.limiter.try_wait().is_ok()
    }

    pub fn shards_count(&self) -> u64 {
        self.shards.run_pending_tasks();
        self.shards.entry_count()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sharded() {
        let s: ShardedRatelimiter<String> =
            ShardedRatelimiter::new(10, 10, Duration::from_secs(1), Duration::from_secs(5), 1000);

        // Check 1st shard works and then blocked
        for _ in 0..10 {
            assert!(s.acquire("foo".into()));
        }
        assert!(!s.acquire("foo".into()));

        // Check 2nd shard works and then blocked
        for _ in 0..10 {
            assert!(s.acquire("bar".into()));
        }
        assert!(!s.acquire("bar".into()));

        // Check 1st still blocked
        for _ in 0..10 {
            assert!(!s.acquire("foo".into()));
        }
    }
}
