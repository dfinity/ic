use std::{cmp::Ordering, time::Instant};

use ic_types::{AccumulatedPriority, CanisterId};

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct EvictionCandidate {
    pub id: CanisterId,
    pub last_used: Instant,
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
    candidates: Vec<EvictionCandidate>,
    min_count_threshold: usize,
    max_count_threshold: usize,
    last_used_threshold: Instant,
) -> Vec<EvictionCandidate> {
    let (evicted, mut candidates): (_, Vec<_>) = candidates
        .into_iter()
        .partition(|candidate| candidate.last_used < last_used_threshold);

    let evict_at_most = candidates.len().saturating_sub(min_count_threshold);

    if evict_at_most >= evicted.len() {
        return evicted;
    }

    let remain_to_evict = candidates
        .len()
        .saturating_sub(max_count_threshold + evicted.len());

    candidates.sort();

    evicted
        .into_iter()
        .chain(candidates.into_iter().take(remain_to_evict))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use ic_test_utilities_types::ids::canister_test_id;
    use ic_types::AccumulatedPriority;

    use super::{evict, EvictionCandidate};

    #[test]
    fn evict_empty() {
        assert_eq!(evict(vec![], 0, 0, Instant::now()), vec![],);
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
            });
        }
        assert_eq!(evict(candidates, 0, 10, now,), vec![],);
    }

    #[test]
    fn evict_due_to_process_count() {
        let mut candidates = vec![];
        let now = Instant::now();
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now + Duration::from_secs(100 - i),
                scheduler_priority: AccumulatedPriority::new(0),
            });
        }
        assert_eq!(
            evict(candidates.clone(), 0, 90, now,),
            candidates.into_iter().rev().take(10).collect::<Vec<_>>()
        );
    }

    #[test]
    fn evict_due_to_idle_time() {
        let mut candidates = vec![];
        let now = Instant::now();
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now - Duration::from_secs(i),
                scheduler_priority: AccumulatedPriority::new(0),
            });
        }
        assert_eq!(
            evict(candidates.clone(), 0, 100, now - Duration::from_secs(50)),
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
                last_used: now - Duration::from_secs(i + 1),
                scheduler_priority: AccumulatedPriority::new(0),
            });
        }
        assert_eq!(
            evict(candidates.clone(), 10, 100, now),
            candidates.into_iter().rev().take(90).collect::<Vec<_>>()
        );
    }

    #[test]
    fn evict_all() {
        let mut candidates = vec![];
        let now = Instant::now();
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now - Duration::from_secs(i + 1),
                scheduler_priority: AccumulatedPriority::new(0),
            });
        }
        assert_eq!(evict(candidates.clone(), 0, 100, now).len(), 100);
    }
}
