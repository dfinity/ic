use num_traits::ops::saturating::SaturatingAdd;
use std::{cmp::Ordering, time::Instant};

use ic_types::{AccumulatedPriority, CanisterId, NumBytes};

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct EvictionCandidate {
    pub id: CanisterId,
    pub last_used: Instant,
    pub rss: NumBytes,
    pub scheduler_priority: AccumulatedPriority,
}

impl Ord for EvictionCandidate {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.scheduler_priority == other.scheduler_priority {
            return self.last_used.cmp(&other.last_used);
        }
        self.scheduler_priority.cmp(&other.scheduler_priority)
    }
}

impl PartialOrd for EvictionCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Evicts the least recently used candidates in order to bring the number of
/// the remaining candidates down to `max_count_threshold`.
///
/// The function also tries to evict candidates that have been idle for a long
/// time (`last_used_threshold`) while keeping the number of the remaining
/// candidates at or above `min_count_threshold`.
///
/// More formally:
/// 1. Sort the candidates in the order of increasing `last_used` field.
/// 2. Let `N` be the total number of candidates.
/// 3. Evict the first `K` candidates such that the number of remaining
///    candidates `N-K` is between the given thresholds:
///    - `min_count_threshold <= N-K <= max_count_threshold`.
///    - if there multiple possible values for `K`, then choose the one that
///      evicts the most candidates with `last_used < last_used_threshold`.
/// 4. Return the evicted candidates.
pub(crate) fn evict(
    mut candidates: Vec<EvictionCandidate>,
    total_rss: NumBytes,
    max_count_threshold: usize,
    last_used_threshold: Instant,
    max_sandboxes_rss: NumBytes,
) -> Vec<EvictionCandidate> {
    candidates.sort_by_key(|x| x.last_used);

    let evict_at_least = candidates.len().saturating_sub(max_count_threshold);

    let mut evicted = vec![];
    let mut evicted_rss = NumBytes::new(0);

    for candidate in candidates.into_iter() {
        if candidate.last_used >= last_used_threshold
            && evicted.len() >= evict_at_least
            && total_rss <= max_sandboxes_rss.saturating_add(&evicted_rss)
        {
            // We have already evicted the minimum required number of candidates
            // and all the remaining candidates were not idle the recent
            // `last_used_threshold` time window. No need to evict more.
            break;
        }
        evicted_rss = evicted_rss.saturating_add(&candidate.rss);
        evicted.push(candidate);
    }

    evicted
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use ic_test_utilities_types::ids::canister_test_id;
    use ic_types::AccumulatedPriority;
    use ic_types::NumBytes;

    use super::{evict, EvictionCandidate};

    #[test]
    fn evict_empty() {
        assert_eq!(evict(vec![], 0.into(), 0, Instant::now(), 0.into()), vec![],);
    }

    #[test]
    fn evict_nothing() {
        let mut candidates = vec![];
        let now = Instant::now();
        for i in 0..10 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now,
                scheduler_priority: AccumulatedPriority::new(0),
                rss: 0.into(),
            });
        }
        assert_eq!(evict(candidates, 0.into(), 10, now, 0.into()), vec![],);
    }

    #[test]
    fn evict_due_to_process_count() {
        let mut candidates = vec![];
        let now = Instant::now();
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now + Duration::from_secs(100 - i),
                rss: 0.into(),
                scheduler_priority: AccumulatedPriority::new(0),
            });
        }
        assert_eq!(
            evict(candidates.clone(), 0.into(), 90, now, 0.into()),
            candidates.into_iter().rev().take(10).collect::<Vec<_>>()
        );
    }

    #[test]
    #[ignore]
    fn evict_due_to_idle_time() {
        let mut candidates = vec![];
        let now = Instant::now();
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now - Duration::from_secs(i),
                rss: 0.into(),
                scheduler_priority: AccumulatedPriority::new(0),
            });
        }
        assert_eq!(
            evict(
                candidates.clone(),
                0.into(),
                100,
                now - Duration::from_secs(50),
                0.into()
            ),
            candidates.into_iter().rev().take(49).collect::<Vec<_>>()
        );
    }

    #[test]
    fn evict_some_due_to_idle_time() {
        let mut candidates = vec![];
        let now = Instant::now();
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now - Duration::from_secs(i + 1) + Duration::from_secs(10),
                rss: 0.into(),
                scheduler_priority: AccumulatedPriority::new(0),
            });
        }
        assert_eq!(
            evict(candidates.clone(), 0.into(), 100, now, 0.into()),
            candidates.into_iter().rev().take(90).collect::<Vec<_>>()
        );
    }

    #[test]
    fn evict_none_due_to_rss() {
        let mut candidates = vec![];
        let now = Instant::now();
        let mut total_rss = NumBytes::new(0);
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now,
                rss: 50.into(),
                scheduler_priority: AccumulatedPriority::new(0),
            });
            total_rss += 50.into();
        }
        assert_eq!(
            evict(candidates.clone(), total_rss, 100, now, total_rss),
            vec![]
        );
    }

    #[test]
    fn evict_some_due_to_rss() {
        let mut candidates = vec![];
        let now = Instant::now();
        let mut total_rss = NumBytes::new(0);
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now,
                rss: 50.into(),
            });
            total_rss += 50.into();
        }
        assert_eq!(
            evict(candidates.clone(), total_rss, 100, now, total_rss / 2),
            candidates.into_iter().take(50).collect::<Vec<_>>()
        );
    }

    #[test]
    fn evict_all_due_to_rss() {
        let mut candidates = vec![];
        let now = Instant::now();
        let mut total_rss = NumBytes::new(0);
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now,
                rss: 50.into(),
            });
            total_rss += 50.into();
        }
        assert_eq!(
            evict(candidates.clone(), total_rss, 100, now, 0.into()),
            candidates
        );
    }

    #[test]
    fn evict_none_due_to_rss() {
        let mut candidates = vec![];
        let now = Instant::now();
        let mut total_rss = NumBytes::new(0);
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now,
                rss: 50.into(),
            });
            total_rss += 50.into();
        }
        assert_eq!(
            evict(candidates.clone(), total_rss, 100, now, total_rss),
            vec![]
        );
    }

    #[test]
    fn evict_some_due_to_rss() {
        let mut candidates = vec![];
        let now = Instant::now();
        let mut total_rss = NumBytes::new(0);
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now,
                rss: 50.into(),
            });
            total_rss += 50.into();
        }
        assert_eq!(
            evict(candidates.clone(), total_rss, 100, now, total_rss / 2),
            candidates.into_iter().take(50).collect::<Vec<_>>()
        );
    }

    #[test]
    fn evict_all_due_to_rss() {
        let mut candidates = vec![];
        let now = Instant::now();
        let mut total_rss = NumBytes::new(0);
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now,
                rss: 50.into(),
            });
            total_rss += 50.into();
        }
        assert_eq!(
            evict(candidates.clone(), total_rss, 100, now, 0.into()),
            candidates
        );
    }

    #[test]
    fn dont_evict_all() {
        let mut candidates = vec![];
        let now = Instant::now();
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now - Duration::from_secs(i + 1),
                rss: 0.into(),
                scheduler_priority: AccumulatedPriority::new(0),
            });
        }
        assert_eq!(
            evict(candidates.clone(), 0.into(), 100, now, 0.into()).len(),
            100
        );
    }
}
