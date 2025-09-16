use num_traits::ops::saturating::SaturatingAdd;
use std::time::Instant;

use ic_types::{AccumulatedPriority, CanisterId, NumBytes};

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct EvictionCandidate {
    pub id: CanisterId,
    pub last_used: Instant,
    pub rss: NumBytes,
    pub scheduler_priority: AccumulatedPriority,
}

/// Evicts the candidates with lowest scheduler priority in order to bring the
/// number of the remaining candidates down to `max_count_threshold` and their
/// total RSS down to `max_sandboxes_rss`.
///
/// The function also tries to evict candidates that have been idle for a long
/// time (`last_used_threshold`).
pub(crate) fn evict(
    mut candidates: Vec<EvictionCandidate>,
    total_rss: NumBytes,
    max_count_threshold: usize,
    last_used_threshold: Instant,
    max_sandboxes_rss: NumBytes,
) -> Vec<EvictionCandidate> {
    let evict_at_least: usize = candidates.len().saturating_sub(max_count_threshold);

    let min_scheduler_priority = AccumulatedPriority::new(i64::MIN);

    candidates.sort_by_key(|x| {
        if x.last_used < last_used_threshold {
            // We will first evict `idle` candidates in order of their `last_used` value.
            (0, min_scheduler_priority, x.last_used)
        } else {
            // `Non idle` candidates will be evicted based on the `scheduler_priority` or based
            // on the vale `last_used` in the case multiple candidates have the same priority.
            (1, x.scheduler_priority, x.last_used)
        }
    });

    let mut evicted = vec![];
    let mut evicted_rss = NumBytes::new(0);

    // Evict as many idle candidates as required.
    for candidate in candidates.into_iter() {
        if candidate.last_used >= last_used_threshold
            && evicted.len() >= evict_at_least
            && total_rss <= max_sandboxes_rss.saturating_add(&evicted_rss)
        {
            // We have already evicted the minimum required number of candidates,
            // and all other candidates are non-idle.
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

    use super::{EvictionCandidate, evict};
    use ic_test_utilities_types::ids::canister_test_id;
    use ic_types::AccumulatedPriority;
    use ic_types::NumBytes;
    use rand::Rng;
    use rand::seq::SliceRandom;
    use rand::thread_rng;

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
                rss: 0.into(),
                scheduler_priority: AccumulatedPriority::new(0),
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

        candidates.shuffle(&mut thread_rng());

        assert_eq!(evict(candidates.clone(), 0.into(), 90, now, 0.into()), {
            candidates.sort_by_key(|x| x.last_used);
            candidates.into_iter().take(10).collect::<Vec<_>>()
        });
    }

    #[test]
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

        candidates.shuffle(&mut thread_rng());

        assert_eq!(
            evict(
                candidates.clone(),
                0.into(),
                51,
                now - Duration::from_secs(50),
                0.into()
            ),
            {
                candidates.sort_by_key(|x| x.last_used);
                candidates.into_iter().take(49).collect::<Vec<_>>()
            }
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
        candidates.shuffle(&mut thread_rng());

        assert_eq!(evict(candidates.clone(), 0.into(), 10, now, 0.into()), {
            candidates.sort_by_key(|x| x.last_used);
            candidates.into_iter().take(90).collect::<Vec<_>>()
        });
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

        candidates.shuffle(&mut thread_rng());

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
                scheduler_priority: AccumulatedPriority::new(0),
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
                scheduler_priority: AccumulatedPriority::new(0),
            });
            total_rss += 50.into();
        }
        assert_eq!(
            evict(candidates.clone(), total_rss, 100, now, 0.into()),
            candidates
        );
    }

    #[test]
    fn evict_all_idle_regardless_of_priority() {
        let mut candidates = vec![];
        let now = Instant::now();
        for i in 0..51 {
            let priority = rand::thread_rng().gen_range(0..100);
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now - Duration::from_secs(i + 1),
                rss: 0.into(),
                scheduler_priority: AccumulatedPriority::new(priority),
            });
        }
        for i in 0..49 {
            let priority = rand::thread_rng().gen_range(0..100);
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now + Duration::from_secs(i + 1),
                rss: 0.into(),
                scheduler_priority: AccumulatedPriority::new(priority),
            });
        }
        assert_eq!(evict(candidates.clone(), 0.into(), 100, now, 0.into()), {
            // Since scheduler priority is not important when candidate is idle,
            // we sort only by last_used.
            candidates.sort_by_key(|x| x.last_used);
            candidates.into_iter().take(51).collect::<Vec<_>>()
        });
    }

    #[test]
    fn evict_all_idle() {
        let mut candidates = vec![];
        let now = Instant::now();
        for i in 0..100 {
            let priority = rand::thread_rng().gen_range(0..100);
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now - Duration::from_secs(i + 1),
                rss: 0.into(),
                scheduler_priority: AccumulatedPriority::new(priority),
            });
        }

        candidates.shuffle(&mut thread_rng());

        assert_eq!(evict(candidates.clone(), 0.into(), 50, now, 0.into()), {
            // Since scheduler priority is not important when candidate is idle,
            // we sort only by last_used.
            candidates.sort_by_key(|x| x.last_used);
            candidates
        });
    }

    #[test]
    fn evict_half_due_to_process_count_based_on_scheduler_priorities() {
        let mut candidates = vec![];
        let now = Instant::now();
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now,
                rss: 0.into(),
                scheduler_priority: AccumulatedPriority::new(i.try_into().unwrap()),
            });
        }
        candidates.shuffle(&mut thread_rng());
        assert_eq!(evict(candidates.clone(), 0.into(), 50, now, 0.into()), {
            // Since last_used is the same for all candidates,
            // we sort only by scheduler priority.
            candidates.sort_by_key(|x| x.scheduler_priority);
            candidates.into_iter().take(50).collect::<Vec<_>>()
        });
    }

    #[test]
    fn evict_some_due_to_rss_based_on_priorities() {
        let mut candidates = vec![];
        let now = Instant::now();
        let mut total_rss = NumBytes::new(0);
        for i in 0..100 {
            candidates.push(EvictionCandidate {
                id: canister_test_id(i),
                last_used: now,
                rss: 50.into(),
                scheduler_priority: AccumulatedPriority::new(i.try_into().unwrap()),
            });
            total_rss += 50.into();
        }
        candidates.shuffle(&mut thread_rng());

        assert_eq!(
            evict(candidates.clone(), total_rss, 100, now, total_rss / 2),
            {
                // Since last_used is the same for all candidates,
                // we sort only by scheduler priority.
                candidates.sort_by_key(|x| x.scheduler_priority);
                candidates.into_iter().take(50).collect::<Vec<_>>()
            }
        );
    }

    #[test]
    fn evic_due_to_process_count_based_on_scheduler_priorities_and_last_used() {
        let mut candidates = vec![];
        let now = Instant::now();
        let mut i = 0;
        for priority in [1, 5, 10, 100, 101, 1_000, 1_001, 1_010, 1_100, 2_000] {
            for time_dist in [1, 5, 10, 100, 101, 1_000, 1_001, 1_010, 1_100, 2_000] {
                candidates.push(EvictionCandidate {
                    id: canister_test_id(i),
                    last_used: now - Duration::from_secs(time_dist),
                    rss: 0.into(),
                    scheduler_priority: AccumulatedPriority::new(priority.into()),
                });
                i += 1;
            }
        }
        candidates.shuffle(&mut thread_rng());

        assert_eq!(
            evict(
                candidates.clone(),
                0.into(),
                40,
                now - Duration::from_secs(10_000),
                0.into()
            ),
            {
                candidates.sort_by_key(|x| (x.scheduler_priority, x.last_used));
                candidates.into_iter().take(60).collect::<Vec<_>>()
            }
        );
    }

    #[test]
    fn evic_due_to_rss_based_on_scheduler_priorities_and_last_used() {
        let mut candidates = vec![];
        let now = Instant::now();
        let mut i = 0;
        let mut total_rss = NumBytes::new(0);
        for priority in [1, 5, 10, 100, 101, 1_000, 1_001, 1_010, 1_100, 2_000] {
            for time_dist in [1, 5, 10, 100, 101, 1_000, 1_001, 1_010, 1_100, 2_000] {
                candidates.push(EvictionCandidate {
                    id: canister_test_id(i),
                    last_used: now - Duration::from_secs(time_dist),
                    rss: 50.into(),
                    scheduler_priority: AccumulatedPriority::new(priority.into()),
                });
                i += 1;
                total_rss += 50.into();
            }
        }
        candidates.shuffle(&mut thread_rng());

        assert_eq!(
            evict(
                candidates.clone(),
                total_rss,
                100,
                now - Duration::from_secs(10_000),
                total_rss / 2
            ),
            {
                candidates.sort_by_key(|x| (x.scheduler_priority, x.last_used));
                candidates.into_iter().take(50).collect::<Vec<_>>()
            }
        );
    }
}
