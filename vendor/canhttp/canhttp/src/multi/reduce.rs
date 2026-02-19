use crate::multi::MultiResults;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

/// Reduce a [`MultiResults`] into a single [`Result`].
pub trait Reduce<K, V, E> {
    /// Do the reduction.
    fn reduce(&self, results: MultiResults<K, V, E>) -> ReducedResult<K, V, E>;
}

/// Alias for the type returned by [`Reduce`].
pub type ReducedResult<K, V, E> = Result<V, ReductionError<K, V, E>>;

/// Error returned by [`Reduce::reduce`].
#[derive(Debug, PartialEq, Eq)]
pub enum ReductionError<K, V, E> {
    /// The given [`MultiResults`] all show the same error pattern that prevent
    /// them for being reduced to a single value.
    ConsistentError(E),
    /// The given [`MultiResults`] are declared inconsistent with each other
    /// and cannot be reduced to a single value.
    InconsistentResults(MultiResults<K, V, E>),
}

impl<K, V, E> MultiResults<K, V, E> {
    /// Shorthand for calling a given implementation of [`Reduce`].
    pub fn reduce<R: Reduce<K, V, E>>(self, reducer: R) -> ReducedResult<K, V, E> {
        reducer.reduce(self)
    }
}

impl<K, V, E> MultiResults<K, V, E>
where
    E: PartialEq,
{
    fn expect_error(self) -> ReductionError<K, V, E> {
        if all_equal(&self.errors) && self.ok_results.is_empty() {
            return ReductionError::ConsistentError(self.errors.into_values().next().unwrap());
        }
        ReductionError::InconsistentResults(self)
    }
}

impl<K, V, E, T: Reduce<K, V, E>> Reduce<K, V, E> for Box<T> {
    fn reduce(&self, results: MultiResults<K, V, E>) -> ReducedResult<K, V, E> {
        self.as_ref().reduce(results)
    }
}

/// Reduce a [`MultiResults`] by requiring that all elements are ok and all equal to each other.
///
/// # Examples
///
/// ```
/// use canhttp::multi::{MultiResults, ReduceWithEquality, ReduceWithThreshold, ReductionError};
///
/// let results: MultiResults<_, _, ()> = MultiResults::from_non_empty_iter(vec![
///     (0_u8, Ok("same")),
///     (1_u8, Ok("same")),
///     (2_u8, Ok("same"))
/// ]);
/// assert_eq!(
///     results.clone().reduce(ReduceWithEquality),
///     Ok("same")
/// );
///
/// let results = MultiResults::from_non_empty_iter(vec![
///     (0_u8, Ok("same")),
///     (1_u8, Err("unknown")),
///     (2_u8, Ok("same"))
/// ]);
/// assert_eq!(
///     results.clone().reduce(ReduceWithEquality),
///     Err(ReductionError::InconsistentResults(results))
/// );
///
/// let results: MultiResults<_, (), _> = MultiResults::from_non_empty_iter(vec![
///     (0_u8, Err("unknown")),
///     (1_u8, Err("unknown")),
///     (2_u8, Err("unknown")),
/// ]);
/// assert_eq!(
///     results.clone().reduce(ReduceWithEquality),
///     Err(ReductionError::ConsistentError("unknown"))
/// )
/// ```
///
///
///
/// # Panics
///
/// If the results is empty.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReduceWithEquality;

impl<K, V, E> Reduce<K, V, E> for ReduceWithEquality
where
    V: PartialEq,
    E: PartialEq,
{
    fn reduce(&self, results: MultiResults<K, V, E>) -> ReducedResult<K, V, E> {
        assert!(
            !results.is_empty(),
            "ERROR: MultiResults is empty and cannot be reduced"
        );
        if !results.errors.is_empty() {
            return Err(results.expect_error());
        }
        if !all_equal(&results.ok_results) {
            return Err(ReductionError::InconsistentResults(results));
        }
        Ok(results.ok_results.into_values().next().unwrap())
    }
}

/// Reduce a [`MultiResults`] by requiring that at least threshold many `Ok` results are the same.
///
/// # Examples
///
/// ```
/// use canhttp::multi::{MultiResults, ReduceWithThreshold, ReductionError};
///
/// let results = MultiResults::from_non_empty_iter(vec![
///     (0_u8, Ok("same")),
///     (1_u8, Err("unknown")),
///     (2_u8, Ok("same"))
/// ]);
/// assert_eq!(results.reduce(ReduceWithThreshold::new(2)), Ok("same"));
///
/// let results = MultiResults::from_non_empty_iter(vec![
///     (0_u8, Ok("same")),
///     (1_u8, Err("unknown")),
///     (2_u8, Ok("different"))
/// ]);
/// assert_eq!(
///     results.clone().reduce(ReduceWithThreshold::new(2)),
///     Err(ReductionError::InconsistentResults(results))
/// );
///
/// let results: MultiResults<_, (), _> = MultiResults::from_non_empty_iter(vec![
///     (0_u8, Err("unknown")),
///     (1_u8, Err("unknown")),
///     (2_u8, Err("unknown")),
/// ]);
/// assert_eq!(
///     results.clone().reduce(ReduceWithThreshold::new(2)),
///     Err(ReductionError::ConsistentError("unknown"))
/// )
/// ```
///
/// # Panics
///
/// If the results is empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReduceWithThreshold(u8);

impl ReduceWithThreshold {
    /// Instantiate [`ReduceWithThreshold`] with the given threshold.
    ///
    /// # Panics
    ///
    /// If the threshold is 0.
    pub fn new(threshold: u8) -> Self {
        assert!(threshold > 0, "ERROR: min must be greater than 0");
        Self(threshold)
    }
}

impl<K, V, E> Reduce<K, V, E> for ReduceWithThreshold
where
    K: Ord + Clone,
    V: Serialize,
    E: PartialEq,
{
    fn reduce(&self, results: MultiResults<K, V, E>) -> ReducedResult<K, V, E> {
        assert!(
            !results.is_empty(),
            "ERROR: MultiResults is empty and cannot be reduced"
        );
        let min = self.0;
        if results.ok_results.len() < min as usize {
            if !results.errors.is_empty() {
                return Err(results.expect_error());
            }
            return Err(ReductionError::InconsistentResults(results));
        }
        let mut distribution = BTreeMap::new();
        for (key, value) in &results.ok_results {
            let hash = OrdByHash::new(value);
            distribution
                .entry(hash)
                .or_insert_with(BTreeSet::new)
                .insert(key);
        }
        let (_most_frequent_value, mut keys) = distribution
            .into_iter()
            .max_by_key(|(_value, keys)| keys.len())
            .expect("BUG: distribution should be non-empty");
        if keys.len() < min as usize {
            return Err(ReductionError::InconsistentResults(results));
        }
        let key_with_most_frequent_value = keys
            .pop_first()
            .expect("BUG: keys should contain at least min > 0 elements")
            .clone();
        let mut results = results;
        Ok(results
            .ok_results
            .remove(&key_with_most_frequent_value)
            .expect("BUG: missing element"))
    }
}

#[derive(Debug)]
struct OrdByHash<V> {
    hash: [u8; 32],
    marker: PhantomData<V>,
}

impl<V> PartialEq for OrdByHash<V> {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl<V> Eq for OrdByHash<V> {}

impl<V> PartialOrd for OrdByHash<V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<V> Ord for OrdByHash<V> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.hash.cmp(&other.hash)
    }
}

impl<V: Serialize> OrdByHash<V> {
    pub fn new(value: &V) -> Self {
        use sha2::{Digest, Sha256};
        let mut buf = Vec::new();
        ciborium::ser::into_writer(value, &mut buf).expect("failed to serialize type");

        let mut hasher = Sha256::new();
        hasher.update(buf);
        let hash = hasher.finalize().into();
        Self {
            hash,
            marker: PhantomData,
        }
    }
}

fn all_equal<K, T: PartialEq>(map: &BTreeMap<K, T>) -> bool {
    let mut iter = map.values();
    let base_value = iter.next().expect("BUG: map should be non-empty");
    iter.all(|value| value == base_value)
}
