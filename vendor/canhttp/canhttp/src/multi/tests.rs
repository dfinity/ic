use crate::multi::Timestamp;

mod parallel_call {
    use crate::multi::parallel_call;
    use std::convert::Infallible;
    use tower::ServiceBuilder;

    #[tokio::test]
    #[should_panic(expected = "duplicate key")]
    async fn should_panic_when_request_id_not_unique() {
        let adding_service =
            ServiceBuilder::new().service_fn(|(left, right): (u32, u32)| async move {
                Ok::<_, Infallible>(left + right)
            });

        let (_service, _results) =
            parallel_call(adding_service, vec![(0, (2, 3)), (1, (4, 5)), (0, (6, 7))]).await;
    }
}

mod reduce_with_equality {
    use crate::multi::{MultiResults, ReduceWithEquality, ReductionError};

    #[test]
    #[should_panic(expected = "MultiResults is empty")]
    fn should_panic_when_empty() {
        let empty: MultiResults<String, String, String> = MultiResults::default();
        let _panic = empty.reduce(ReduceWithEquality);
    }

    #[test]
    fn should_be_inconsistent_results() {
        fn check_inconsistent_error(results: MultiResults<u8, &str, &str>) {
            let reduced = results.clone().reduce(ReduceWithEquality);
            assert_eq!(reduced, Err(ReductionError::InconsistentResults(results)))
        }

        // different errors
        check_inconsistent_error(MultiResults::from_non_empty_iter(vec![
            (0_u8, Err("reject")),
            (1, Err("transient")),
        ]));
        // different ok results
        check_inconsistent_error(MultiResults::from_non_empty_iter(vec![
            (0_u8, Ok("hello")),
            (1, Ok("world")),
        ]));

        // mix of errors and ok results
        for inconsistent_result in [Ok("different"), Err("offline")] {
            for index in 0..4 {
                let mut results = [Ok("same"), Ok("same"), Ok("same"), Ok("same")];
                results[index] = inconsistent_result;

                let [result_0, result_1, result_2, result_3] = results;

                check_inconsistent_error(MultiResults::from_non_empty_iter(vec![
                    (0_u8, result_0),
                    (1, result_1),
                    (2, result_2),
                    (3, result_3),
                ]));
            }
        }
    }

    #[test]
    fn should_be_consistent_error() {
        fn check_consistent_error(results: MultiResults<u8, &str, &str>, expected_error: &str) {
            let reduced = results.reduce(ReduceWithEquality);
            assert_eq!(
                reduced,
                Err(ReductionError::ConsistentError(expected_error))
            )
        }

        check_consistent_error(
            MultiResults::from_non_empty_iter(vec![(0_u8, Err("error"))]),
            "error",
        );
        check_consistent_error(
            MultiResults::from_non_empty_iter(vec![(0_u8, Err("error")), (1, Err("error"))]),
            "error",
        );
    }

    #[test]
    fn should_be_consistent_result() {
        fn check_consistent_result(results: MultiResults<u8, &str, &str>, expected_result: &str) {
            let reduced = results.reduce(ReduceWithEquality);
            assert_eq!(reduced, Ok(expected_result))
        }

        check_consistent_result(
            MultiResults::from_non_empty_iter(vec![(1, Ok("same"))]),
            "same",
        );
        check_consistent_result(
            MultiResults::from_non_empty_iter(vec![(0_u8, Ok("same")), (1, Ok("same"))]),
            "same",
        );
    }
}

mod reduce_with_threshold {
    use crate::multi::{MultiResults, ReduceWithThreshold, ReductionError};

    #[test]
    fn should_get_consistent_result() {
        fn check_consistent_result(
            results: MultiResults<u8, &str, &str>,
            threshold: u8,
            expected_result: &str,
        ) {
            let reduced = results.reduce(ReduceWithThreshold::new(threshold));
            assert_eq!(reduced, Ok(expected_result));
        }

        // unanimous
        check_consistent_result(
            MultiResults::from_non_empty_iter(vec![
                (0_u8, Ok("same")),
                (1, Ok("same")),
                (2, Ok("same")),
                (3, Ok("same")),
            ]),
            3,
            "same",
        );

        // 3 out-of-4 ok
        for inconsistent_result in [Ok("different"), Err("offline")] {
            for index_inconsistent in 0..4_usize {
                let mut results = [Ok("same"), Ok("same"), Ok("same"), Ok("same")];
                results[index_inconsistent] = inconsistent_result;
                let [result_0, result_1, result_2, result_3] = results;

                check_consistent_result(
                    MultiResults::from_non_empty_iter(vec![
                        (0_u8, result_0),
                        (1, result_1),
                        (2, result_2),
                        (3, result_3),
                    ]),
                    3,
                    "same",
                );
            }
        }
    }

    #[test]
    fn should_get_inconsistent_error() {
        use itertools::Itertools;

        fn check_inconsistent_result(results: MultiResults<u8, &str, &str>, threshold: u8) {
            let reduced = results.clone().reduce(ReduceWithThreshold::new(threshold));
            assert_eq!(reduced, Err(ReductionError::InconsistentResults(results)));
        }

        //not enough results
        check_inconsistent_result(MultiResults::from_non_empty_iter(vec![(0, Ok("same"))]), 2);
        check_inconsistent_result(
            MultiResults::from_non_empty_iter(vec![(0, Ok("same")), (1, Ok("same"))]),
            3,
        );
        check_inconsistent_result(
            MultiResults::from_non_empty_iter(vec![(0, Ok("same")), (1, Err("offline"))]),
            3,
        );

        // 2-out-of-4 ok
        let inconsistent_results = [Ok("different"), Err("offline")];
        for (inconsistent_res_1, inconsistent_res_2) in inconsistent_results
            .clone()
            .iter()
            .cartesian_product(inconsistent_results)
        {
            for indexes in (0..4_usize).permutations(2) {
                let mut results = [Ok("same"), Ok("same"), Ok("same"), Ok("same")];
                results[indexes[0]] = *inconsistent_res_1;
                results[indexes[1]] = inconsistent_res_2;
                let [result_0, result_1, result_2, result_3] = results;

                check_inconsistent_result(
                    MultiResults::from_non_empty_iter(vec![
                        (0_u8, result_0),
                        (1, result_1),
                        (2, result_2),
                        (3, result_3),
                    ]),
                    3,
                );
            }
        }

        // 1-out-of-4 ok
        for ok_index in 0..4_usize {
            let mut results = [
                Err("offline"),
                Err("offline"),
                Err("offline"),
                Err("offline"),
            ];
            results[ok_index] = Ok("same");
            let [result_0, result_1, result_2, result_3] = results;

            check_inconsistent_result(
                MultiResults::from_non_empty_iter(vec![
                    (0_u8, result_0),
                    (1, result_1),
                    (2, result_2),
                    (3, result_3),
                ]),
                3,
            );
        }
    }

    #[test]
    fn should_get_consistent_error() {
        let results: MultiResults<_, &str, _> = MultiResults::from_non_empty_iter(vec![
            (0_u8, Err("offline")),
            (1, Err("offline")),
            (2, Err("offline")),
            (3, Err("offline")),
        ]);

        assert_eq!(
            results.reduce(ReduceWithThreshold::new(3)),
            Err(ReductionError::ConsistentError("offline"))
        )
    }
}

mod timed_size_vec {
    use crate::multi::cache::TimedSizedVec;
    use crate::multi::tests::timestamp;
    use maplit::btreemap;
    use proptest::collection::vec;
    use proptest::prelude::any;
    use proptest::{prop_assert, prop_assert_eq, proptest};
    use std::collections::{BTreeMap, VecDeque};
    use std::num::NonZeroUsize;
    use std::time::Duration;

    #[test]
    fn should_initially_be_empty() {
        let vec: TimedSizedVec<&str> =
            TimedSizedVec::new(Duration::from_secs(60), NonZeroUsize::new(5).unwrap());

        assert_eq!(vec.len(), 0);
        assert_eq!(vec.iter().collect::<Vec<_>>(), vec![]);
    }

    #[test]
    fn should_evict_when_too_many() {
        let mut vec: TimedSizedVec<&str> =
            TimedSizedVec::new(Duration::from_nanos(60), NonZeroUsize::new(5).unwrap());

        for (nanos, value) in ["a", "b", "c", "d", "e"].into_iter().enumerate() {
            let previous = vec.insert_evict(timestamp(nanos as u64), value);
            assert_eq!(previous, BTreeMap::default());
        }

        assert_eq!(
            vec.iter().collect::<Vec<_>>(),
            vec![
                (&timestamp(0), &"a"),
                (&timestamp(1), &"b"),
                (&timestamp(2), &"c"),
                (&timestamp(3), &"d"),
                (&timestamp(4), &"e"),
            ]
        );
        assert_eq!(vec.len(), 5);

        let previous = vec.insert_evict(timestamp(5), "f");
        assert_eq!(previous, btreemap! {timestamp(0) => VecDeque::from(["a"])});
        assert_eq!(
            vec.iter().collect::<Vec<_>>(),
            vec![
                (&timestamp(1), &"b"),
                (&timestamp(2), &"c"),
                (&timestamp(3), &"d"),
                (&timestamp(4), &"e"),
                (&timestamp(5), &"f"),
            ]
        );
        assert_eq!(vec.len(), 5);
    }

    #[test]
    fn should_evict_when_expired() {
        let mut vec: TimedSizedVec<&str> =
            TimedSizedVec::new(Duration::from_nanos(60), NonZeroUsize::new(6).unwrap());

        assert_eq!(vec.insert_evict(timestamp(0), "a"), BTreeMap::default());
        assert_eq!(vec.insert_evict(timestamp(1), "b"), BTreeMap::default());
        assert_eq!(vec.insert_evict(timestamp(1), "c"), BTreeMap::default());
        assert_eq!(vec.insert_evict(timestamp(1), "d"), BTreeMap::default());
        assert_eq!(vec.insert_evict(timestamp(2), "e"), BTreeMap::default());

        assert_eq!(
            vec.iter().collect::<Vec<_>>(),
            vec![
                (&timestamp(0), &"a"),
                (&timestamp(1), &"b"),
                (&timestamp(1), &"c"),
                (&timestamp(1), &"d"),
                (&timestamp(2), &"e"),
            ]
        );
        assert_eq!(vec.len(), 5);

        assert_eq!(vec.insert_evict(timestamp(60), "f"), BTreeMap::default());
        assert_eq!(
            vec.iter().collect::<Vec<_>>(),
            vec![
                (&timestamp(0), &"a"),
                (&timestamp(1), &"b"),
                (&timestamp(1), &"c"),
                (&timestamp(1), &"d"),
                (&timestamp(2), &"e"),
                (&timestamp(60), &"f"),
            ]
        );
        assert_eq!(vec.len(), 6);

        assert_eq!(
            vec.insert_evict(timestamp(61), "g"),
            btreemap! {timestamp(0) => VecDeque::from(["a"])}
        );
        assert_eq!(
            vec.iter().collect::<Vec<_>>(),
            vec![
                (&timestamp(1), &"b"),
                (&timestamp(1), &"c"),
                (&timestamp(1), &"d"),
                (&timestamp(2), &"e"),
                (&timestamp(60), &"f"),
                (&timestamp(61), &"g"),
            ]
        );
        assert_eq!(vec.len(), 6);

        assert_eq!(
            vec.insert_evict(timestamp(62), "h"),
            btreemap! {timestamp(1) => VecDeque::from(["b", "c", "d"])}
        );
        assert_eq!(
            vec.iter().collect::<Vec<_>>(),
            vec![
                (&timestamp(2), &"e"),
                (&timestamp(60), &"f"),
                (&timestamp(61), &"g"),
                (&timestamp(62), &"h"),
            ]
        );
        assert_eq!(vec.len(), 4);
    }

    #[test]
    fn should_have_correct_order_for_values_with_same_timestamp() {
        let mut vec: TimedSizedVec<&str> =
            TimedSizedVec::new(Duration::from_nanos(60), NonZeroUsize::new(5).unwrap());

        assert_eq!(vec.insert_evict(timestamp(0), "a"), BTreeMap::default());
        assert_eq!(vec.insert_evict(timestamp(1), "b"), BTreeMap::default());
        assert_eq!(vec.insert_evict(timestamp(1), "c"), BTreeMap::default());
        assert_eq!(vec.insert_evict(timestamp(1), "d"), BTreeMap::default());
        assert_eq!(vec.insert_evict(timestamp(2), "e"), BTreeMap::default());

        assert_eq!(
            vec.iter().collect::<Vec<_>>(),
            vec![
                (&timestamp(0), &"a"),
                (&timestamp(1), &"b"),
                (&timestamp(1), &"c"),
                (&timestamp(1), &"d"),
                (&timestamp(2), &"e"),
            ]
        );

        assert_eq!(
            vec.insert_evict(timestamp(2), "f"),
            btreemap! {timestamp(0) => VecDeque::from(["a"])}
        );
        assert_eq!(
            vec.iter().collect::<Vec<_>>(),
            vec![
                (&timestamp(1), &"b"),
                (&timestamp(1), &"c"),
                (&timestamp(1), &"d"),
                (&timestamp(2), &"e"),
                (&timestamp(2), &"f"),
            ]
        );

        assert_eq!(
            vec.insert_evict(timestamp(2), "g"),
            btreemap! {timestamp(1) => VecDeque::from(["b"])}
        );
        assert_eq!(
            vec.iter().collect::<Vec<_>>(),
            vec![
                (&timestamp(1), &"c"),
                (&timestamp(1), &"d"),
                (&timestamp(2), &"e"),
                (&timestamp(2), &"f"),
                (&timestamp(2), &"g"),
            ]
        );
    }

    proptest! {
        #[test]
        fn should_have_len_consistent_with_iter(
                expiration in 0..1_000_u64,
                capacity in 1..1_000_usize,
                timestamp_deltas in vec(any::<u64>(), 0..1_000)
        ) {
            let mut vec: TimedSizedVec<()> =
                TimedSizedVec::new(Duration::from_nanos(expiration), NonZeroUsize::new(capacity).unwrap());
            let mut now = 0_u64;
            for delta in timestamp_deltas {
                now = now.saturating_add(delta); //mock sequentially non-decreasing time sequence
                let _ = vec.insert_evict(timestamp(now), ());
            }

            let expected_len = vec.iter().collect::<Vec<_>>().len();
            prop_assert_eq!(vec.len(), expected_len);
            prop_assert!(vec.len() <= vec.capacity().get());
        }
    }
}

mod timed_sized_map {
    use crate::multi::cache::TimedSizedMap;
    use crate::multi::tests::timestamp;
    use crate::multi::TimedSizedVec;
    use itertools::Itertools;
    use maplit::btreemap;
    use std::collections::{BTreeMap, VecDeque};
    use std::num::NonZeroUsize;
    use std::time::Duration;
    use strum::VariantArray;

    #[test]
    fn should_initially_be_empty() {
        let map: TimedSizedMap<Keys, &str> =
            TimedSizedMap::new(Duration::from_nanos(60), NonZeroUsize::new(5).unwrap());
        assert_eq!(map.iter().next(), None);
    }

    #[test]
    fn should_be_stable_when_sorting() {
        let mut map = TimedSizedMap::new(Duration::from_nanos(60), NonZeroUsize::new(5).unwrap());
        for key in Keys::VARIANTS {
            map.insert_evict(timestamp(1), key.clone(), "ok");
        }

        for subset in Keys::VARIANTS.iter().cloned().powerset() {
            assert_eq!(
                map.sort_keys_by(subset.as_slice(), |values| {
                    ascending_num_elements(values)
                })
                .cloned()
                .collect::<Vec<_>>(),
                subset
            );
        }
    }

    #[test]
    fn should_evict_expired() {
        let mut map = TimedSizedMap::new(Duration::from_nanos(60), NonZeroUsize::new(5).unwrap());
        for nanos in 0..3_u64 {
            assert_eq!(
                map.insert_evict(timestamp(nanos), Keys::Key3, "ok"),
                BTreeMap::default()
            );
        }
        for nanos in 3..5_u64 {
            assert_eq!(
                map.insert_evict(timestamp(nanos), Keys::Key1, "ok"),
                BTreeMap::default()
            );
            assert_eq!(
                map.insert_evict(timestamp(nanos), Keys::Key3, "ok"),
                BTreeMap::default()
            );
        }
        assert_eq!(
            map.insert_evict(timestamp(5), Keys::Key1, "ok"),
            BTreeMap::default()
        );
        assert_eq!(
            map.iter().collect::<Vec<_>>(),
            vec![
                (&Keys::Key1, &timestamp(3), &"ok"),
                (&Keys::Key1, &timestamp(4), &"ok"),
                (&Keys::Key1, &timestamp(5), &"ok"),
                (&Keys::Key3, &timestamp(0), &"ok"),
                (&Keys::Key3, &timestamp(1), &"ok"),
                (&Keys::Key3, &timestamp(2), &"ok"),
                (&Keys::Key3, &timestamp(3), &"ok"),
                (&Keys::Key3, &timestamp(4), &"ok"),
            ]
        );
        let map_before = map.clone();
        let now = timestamp(60); //no timestamp expired
        assert_eq!(
            map.evict_expired(&[Keys::Key1, Keys::Key2, Keys::Key3], now),
            BTreeMap::default()
        );
        assert_eq!(map_before, map);

        let now = timestamp(63); //timestamps 0,1,2 expired.
        assert_eq!(
            map.evict_expired(&[Keys::Key1, Keys::Key2, Keys::Key3], now),
            btreemap! {
               &Keys::Key3 => btreemap! {
                    timestamp(0) => VecDeque::from(["ok"]),
                    timestamp(1) => VecDeque::from(["ok"]),
                    timestamp(2) => VecDeque::from(["ok"])
                }
            }
        );
        assert_eq!(
            map.iter().collect::<Vec<_>>(),
            vec![
                (&Keys::Key1, &timestamp(3), &"ok"),
                (&Keys::Key1, &timestamp(4), &"ok"),
                (&Keys::Key1, &timestamp(5), &"ok"),
                (&Keys::Key3, &timestamp(3), &"ok"),
                (&Keys::Key3, &timestamp(4), &"ok"),
            ]
        );
    }

    #[test]
    fn should_evict_expired_entries_while_sorting() {
        let mut map = TimedSizedMap::new(Duration::from_nanos(60), NonZeroUsize::new(5).unwrap());
        for nanos in 0..3_u64 {
            assert_eq!(
                map.insert_evict(timestamp(nanos), Keys::Key3, "ok"),
                BTreeMap::default()
            );
        }
        for nanos in 3..5_u64 {
            assert_eq!(
                map.insert_evict(timestamp(nanos), Keys::Key1, "ok"),
                BTreeMap::default()
            );
            assert_eq!(
                map.insert_evict(timestamp(nanos), Keys::Key3, "ok"),
                BTreeMap::default()
            );
        }
        assert_eq!(
            map.insert_evict(timestamp(5), Keys::Key1, "ok"),
            BTreeMap::default()
        );
        assert_eq!(
            map.iter().collect::<Vec<_>>(),
            vec![
                (&Keys::Key1, &timestamp(3), &"ok"),
                (&Keys::Key1, &timestamp(4), &"ok"),
                (&Keys::Key1, &timestamp(5), &"ok"),
                (&Keys::Key3, &timestamp(0), &"ok"),
                (&Keys::Key3, &timestamp(1), &"ok"),
                (&Keys::Key3, &timestamp(2), &"ok"),
                (&Keys::Key3, &timestamp(3), &"ok"),
                (&Keys::Key3, &timestamp(4), &"ok"),
            ]
        );
        let map_before = map.clone();
        assert_eq!(
            map.sort_keys_by(&[Keys::Key1, Keys::Key2, Keys::Key3], |values| {
                ascending_num_elements(values)
            })
            .collect::<Vec<_>>(),
            vec![&Keys::Key3, &Keys::Key1, &Keys::Key2]
        );
        assert_eq!(map_before, map);

        let now = timestamp(63); //timestamps 0,1,2 expired.
        map.evict_expired(&[Keys::Key1, Keys::Key2, Keys::Key3], now);
        assert_eq!(
            map.sort_keys_by(&[Keys::Key1, Keys::Key2, Keys::Key3], |values| {
                ascending_num_elements(values)
            })
            .collect::<Vec<_>>(),
            vec![&Keys::Key1, &Keys::Key3, &Keys::Key2]
        );
    }

    #[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, VariantArray)]
    enum Keys {
        Key1,
        Key2,
        Key3,
    }

    fn ascending_num_elements<V>(values: Option<&TimedSizedVec<V>>) -> impl Ord {
        std::cmp::Reverse(values.map(|v| v.len()).unwrap_or_default())
    }
}

fn timestamp(nanos: u64) -> Timestamp {
    Timestamp::from_nanos_since_unix_epoch(nanos)
}
