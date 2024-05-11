use ic_agent::agent::http_transport::route_provider::RouteProvider;
use std::collections::HashMap;
use std::{fmt::Debug, hash::Hash, sync::Arc};

pub fn route_n_times(n: usize, f: Arc<impl RouteProvider>) -> Vec<String> {
    (0..n)
        .map(|_| f.route().unwrap().domain().unwrap().to_string())
        .collect()
}

pub fn assert_routed_domains<T>(actual: Vec<T>, expected: Vec<T>, expected_repetitions: usize)
where
    T: AsRef<str> + Eq + Hash + Debug + Ord,
{
    fn build_count_map<T>(items: &[T]) -> HashMap<&T, usize>
    where
        T: Eq + Hash,
    {
        items.iter().fold(HashMap::new(), |mut map, item| {
            *map.entry(item).or_insert(0) += 1;
            map
        })
    }
    let count_actual = build_count_map(&actual);
    let count_expected = build_count_map(&expected);

    let mut keys_actual = count_actual.keys().collect::<Vec<_>>();
    keys_actual.sort();
    let mut keys_expected = count_expected.keys().collect::<Vec<_>>();
    keys_expected.sort();
    // Assert all routed domains are present.
    assert_eq!(keys_actual, keys_expected);

    // Assert the expected repetition count of each routed domain.
    let actual_repetitions = count_actual.values().collect::<Vec<_>>();
    assert!(actual_repetitions
        .iter()
        .all(|&x| x == &expected_repetitions));
}
