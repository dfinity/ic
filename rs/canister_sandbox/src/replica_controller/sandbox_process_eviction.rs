use std::time::Instant;

use ic_types::CanisterId;

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct EvictionCandidate {
    pub id: CanisterId,
    pub last_used: Instant,
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
    min_count_threshold: usize,
    max_count_threshold: usize,
    last_used_threshold: Instant,
) -> Vec<EvictionCandidate> {
    candidates.sort_by_key(|x| x.last_used);

    let evict_at_least = candidates.len().saturating_sub(max_count_threshold);
    let evict_at_most = candidates.len().saturating_sub(min_count_threshold);

    let mut evicted = vec![];

    for candidate in candidates.into_iter() {
        if evicted.len() >= evict_at_most {
            // Cannot evict anymore because at least `min_count_threshold`
            // should remain not evicted.
            break;
        }
        if candidate.last_used >= last_used_threshold && evicted.len() >= evict_at_least {
            // We have already evicted the minimum required number of candidates
            // and all the remaining candidates were not idle the recent
            // `last_used_threshold` time window. No need to evict more.
            break;
        }
        evicted.push(candidate)
    }

    evicted
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use ic_test_utilities_types::ids::canister_test_id;

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
            });
        }
        assert_eq!(evict(candidates.clone(), 0, 100, now).len(), 100);
    }
}
