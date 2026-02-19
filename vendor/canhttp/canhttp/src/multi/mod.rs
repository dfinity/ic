//! Make multiple calls in parallel to a [`tower::Service`] and handle their multiple results.
//! See [`parallel_call`].

pub use cache::{TimedSizedMap, TimedSizedVec, Timestamp};
pub use reduce::{Reduce, ReduceWithEquality, ReduceWithThreshold, ReducedResult, ReductionError};

mod cache;
mod reduce;
#[cfg(test)]
mod tests;

use futures_channel::mpsc;
use futures_util::StreamExt;
use std::collections::{btree_map, btree_map::IntoIter as BTreeMapIntoIter, BTreeMap};
use std::fmt::Debug;
use std::iter::FusedIterator;
use tower::{Service, ServiceExt};

/// Process all requests from the given iterator and produce a result for reach request.
///
/// The iterator yields a pair containing:
/// 1. An ID *uniquely* identifying this request.
/// 2. The request itself
///
/// The requests will be sent to the underlying service in parallel and the result for each request
/// can be retrieved by the corresponding request ID.
///
/// # Examples
///
/// ```rust
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::convert::Infallible;
/// use tower::ServiceBuilder;
/// use canhttp::multi::parallel_call;
///
/// let adding_service =
///     ServiceBuilder::new().service_fn(|(left, right): (u32, u32)| async move {
///         Ok::<_, Infallible>(left + right)
///     });
///
/// let (_service, results) =
///     parallel_call(adding_service, vec![(0, (2, 3)), (1, (4, 5))]).await;
///
/// assert_eq!(results.get(&0).unwrap(), Ok(&5_u32));
/// assert_eq!(results.get(&1).unwrap(), Ok(&9_u32));
/// # Ok(())
/// # }
/// ```
///
/// # Panics
///
/// If two requests produced by the iterator have the same request ID.
pub async fn parallel_call<S, I, RequestId, Request, Response, Error>(
    service: S,
    requests: I,
) -> (S, MultiResults<RequestId, Response, Error>)
where
    S: Service<Request, Response = Response, Error = Error>,
    I: IntoIterator<Item = (RequestId, Request)>,
    RequestId: Ord,
{
    let (tx_id, rx_id) = mpsc::unbounded();
    let (tx, rx) = mpsc::unbounded();
    let responses = service.call_all(rx);
    for (id, request) in requests.into_iter() {
        tx_id.unbounded_send(id).expect("BUG: channel closed");
        tx.unbounded_send(request).expect("BUG: channel closed");
    }
    drop(tx_id);
    drop(tx);
    let mut results = MultiResults::default();
    let mut zip = rx_id.zip(responses);
    // Responses arrive in the same order as the requests
    // call_all uses under the hood FuturesOrdered
    while let Some((id, response)) = zip.next().await {
        results.insert_once(id, response);
    }
    let (_, parallel_service) = zip.into_inner();
    (parallel_service.into_inner(), results)
}

/// Aggregates multiple results, where each result is identified by a *unique* key.
///
/// At the implementation level, results are split between [`Ok`] values and [`Err`] values.
/// The main use-case is to use various reduction strategies (see [`Reduce`]) to transform those
/// multiple results into a single one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiResults<K, V, E> {
    ok_results: BTreeMap<K, V>,
    errors: BTreeMap<K, E>,
}

impl<K, V, E> Default for MultiResults<K, V, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V, E> MultiResults<K, V, E> {
    /// Create a new empty [`MultiResults`].
    pub fn new() -> Self {
        Self {
            ok_results: BTreeMap::new(),
            errors: BTreeMap::new(),
        }
    }

    /// Consume the [`MultiResults`] and split it into two maps containing the [`Ok`] results
    /// and the [`Err`] results.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use maplit::btreemap;
    /// use canhttp::multi::MultiResults;
    ///
    /// let results = MultiResults::from_non_empty_iter(vec![
    ///     (0, Ok("yes")),
    ///     (1, Err("wrong")),
    ///     (2, Ok("no"))
    /// ]);
    ///
    /// let (ok, err) = results.into_inner();
    ///
    /// assert_eq!(ok, btreemap! {
    ///     0 => "yes",
    ///     2 => "no",
    /// });
    /// assert_eq!(err, btreemap! {1 => "wrong"});
    /// ```
    pub fn into_inner(self) -> (BTreeMap<K, V>, BTreeMap<K, E>) {
        (self.ok_results, self.errors)
    }

    /// Return a reference to the [`Ok`] results contained in the [`MultiResults`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use maplit::btreemap;
    /// use canhttp::multi::MultiResults;
    ///
    /// let results = MultiResults::from_non_empty_iter(vec![
    ///     (0, Ok("yes")),
    ///     (1, Err("wrong")),
    ///     (2, Ok("no"))
    /// ]);
    ///
    /// let ok = results.ok_results();
    ///
    /// assert_eq!(ok, &btreemap! {
    ///     0 => "yes",
    ///     2 => "no",
    /// });
    /// ```
    pub fn ok_results(&self) -> &BTreeMap<K, V> {
        &self.ok_results
    }

    /// Return the number of results.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use canhttp::multi::MultiResults;
    ///
    /// let results = MultiResults::from_non_empty_iter(vec![
    ///     (0, Ok("yes")),
    ///     (1, Err("wrong")),
    ///     (2, Ok("no"))
    /// ]);
    ///
    /// assert_eq!(results.len(), 3);
    /// ```
    pub fn len(&self) -> usize {
        self.ok_results.len() + self.errors.len()
    }

    /// Return true if and only if there are no results.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use canhttp::multi::MultiResults;
    ///
    /// let mut results = MultiResults::default();
    /// assert!(results.is_empty());
    ///
    /// results.insert_once(1, Ok("yes"));
    /// assert!(!results.is_empty());
    ///
    /// results.insert_once(2, Err("wrong"));
    /// assert!(!results.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.ok_results.is_empty() && self.errors.is_empty()
    }
}

impl<K: Ord, V, E> MultiResults<K, V, E> {
    /// Return a new instance of [`MultiResults`] by inserting
    /// each key-result pair given by the iterator.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use canhttp::multi::MultiResults;
    ///
    /// let results = MultiResults::from_non_empty_iter(vec![
    ///     (0, Ok("yes")),
    ///     (1, Err("wrong")),
    ///     (2, Ok("no"))
    /// ]);
    ///
    /// let mut other_results = MultiResults::default();
    /// other_results.insert_once(0, Ok("yes"));
    /// other_results.insert_once(1, Err("wrong"));
    /// other_results.insert_once(2, Ok("no"));
    ///
    /// assert_eq!(results, other_results);
    /// ```
    ///
    /// # Panics
    ///
    /// If the iterator is empty or a previous result with the same key exist.
    pub fn from_non_empty_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (K, Result<V, E>)>,
    {
        let mut results = MultiResults::default();
        for (key, result) in iter {
            results.insert_once(key, result);
        }
        assert!(!results.is_empty(), "ERROR: MultiResults cannot be empty");
        results
    }

    /// Return a reference to the result identified by the key.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use canhttp::multi::MultiResults;
    ///
    /// let mut results = MultiResults::from_non_empty_iter(vec![
    ///     (0, Ok("yes")),
    ///     (1, Err("wrong")),
    /// ]);
    ///
    /// assert_eq!(results.get(&0), Some(Ok(&"yes")));
    /// assert_eq!(results.get(&1), Some(Err(&"wrong")));
    /// assert_eq!(results.get(&2), None);
    /// ```
    pub fn get(&self, id: &K) -> Option<Result<&V, &E>> {
        self.ok_results
            .get(id)
            .map(Ok)
            .or_else(|| self.errors.get(id).map(Err))
    }

    /// Insert a key-result pair.
    ///
    /// # Examples
    /// ```rust
    /// use canhttp::multi::MultiResults;
    ///
    /// let mut results = MultiResults::default();
    /// results.insert_once(0, Ok("yes"));
    /// assert_eq!(results.is_empty(), false);
    /// assert_eq!(results.get(&0), Some(Ok(&"yes")));
    ///
    /// results.insert_once(1, Err("wrong"));
    /// assert_eq!(results.get(&1), Some(Err(&"wrong")));
    /// ```
    ///
    /// # Panics
    ///
    /// If a previous result with the same key exist.
    pub fn insert_once(&mut self, key: K, result: Result<V, E>) {
        match result {
            Ok(value) => {
                self.insert_once_ok(key, value);
            }
            Err(error) => {
                self.insert_once_err(key, error);
            }
        }
    }

    fn insert_once_ok(&mut self, key: K, value: V) {
        assert!(
            !self.errors.contains_key(&key),
            "ERROR: duplicate key in `errors`"
        );
        assert!(
            self.ok_results.insert(key, value).is_none(),
            "ERROR: duplicate key in `ok_results`"
        );
    }

    fn insert_once_err(&mut self, key: K, error: E) {
        assert!(
            !self.ok_results.contains_key(&key),
            "ERROR: duplicate key in `ok_results`"
        );
        assert!(
            self.errors.insert(key, error).is_none(),
            "ERROR: duplicate key in `errors`"
        );
    }

    /// Add multiple errors to the results.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use canhttp::multi::MultiResults;
    ///
    /// let mut results: MultiResults<_, (), _> = MultiResults::default();
    /// results.add_errors(vec![
    ///     (0, "wrong"),
    ///     (1, "wrong")
    /// ]);
    ///
    /// assert_eq!(results.get(&0), Some(Err(&"wrong")));
    /// assert_eq!(results.get(&1), Some(Err(&"wrong")));
    /// ```
    ///
    /// # Panics
    ///
    /// If a previous result with the same key exist.
    pub fn add_errors<I>(&mut self, errors: I)
    where
        I: IntoIterator<Item = (K, E)>,
    {
        for (key, error) in errors.into_iter() {
            self.insert_once_err(key, error);
        }
    }

    /// A borrowing iterator over the entries of a [`MultiResults`],
    /// where the [`Ok`] results are given first (sorted by key) and then
    /// the [`Err`] results (also sorted by key).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use canhttp::multi::MultiResults;
    ///
    /// let results = MultiResults::from_non_empty_iter(vec![
    ///     (0, Ok("yes")),
    ///     (1, Err("wrong")),
    ///     (2, Ok("no"))
    /// ]);
    ///
    /// let mut iter = results.iter();
    ///
    /// assert_eq!(iter.next(), Some((&0, Ok(&"yes"))));
    /// assert_eq!(iter.next(), Some((&2, Ok(&"no"))));
    /// assert_eq!(iter.next(), Some((&1, Err(&"wrong"))));
    /// assert_eq!(iter.next(), None);
    /// ```
    pub fn iter(&self) -> Iter<'_, K, V, E> {
        Iter {
            ok_results_iter: self.ok_results.iter(),
            errors_iter: self.errors.iter(),
        }
    }
}

/// A borrowing iterator over the entries of a [`MultiResults`],
/// where the [`Ok`] results are given first (sorted by key) and then
/// the [`Err`] results (also sorted by key).
///
/// This `struct` is created by the [`iter`] method on [`MultiResults`].
/// See its documentation for more.
///
/// [`iter`]: MultiResults::iter
pub struct Iter<'a, K, V, E> {
    ok_results_iter: btree_map::Iter<'a, K, V>,
    errors_iter: btree_map::Iter<'a, K, E>,
}

impl<'a, K, V, E> Iterator for Iter<'a, K, V, E> {
    type Item = (&'a K, Result<&'a V, &'a E>);

    fn next(&mut self) -> Option<Self::Item> {
        self.ok_results_iter
            .next()
            .map(|(k, v)| (k, Ok(v)))
            .or_else(|| self.errors_iter.next().map(|(k, e)| (k, Err(e))))
    }
}

impl<'a, K, V, E> FusedIterator for Iter<'a, K, V, E> {}

/// An owning iterator over the entries of a [`MultiResults`],
/// where the [`Ok`] results are given first (sorted by key) and then
/// the [`Err`] results (also sorted by key).
///
/// This `struct` is created by the [`into_iter`] method on [`MultiResults`]
/// (provided by the [`IntoIterator`] trait). See its documentation for more.
///
/// # Examples
///
/// ```rust
/// use canhttp::multi::MultiResults;
///
/// let mut results = MultiResults::from_non_empty_iter(vec![
///     (0, Ok("yes")),
///     (1, Err("wrong")),
///     (2, Ok("no"))
/// ]).into_iter();
///
/// assert_eq!(results.next(), Some((0, Ok("yes"))));
/// assert_eq!(results.next(), Some((2, Ok("no"))));
/// assert_eq!(results.next(), Some((1, Err("wrong"))));
/// assert_eq!(results.next(), None);
///
/// ```
///
/// [`into_iter`]: IntoIterator::into_iter
pub struct IntoIter<K, V, E> {
    ok_results_iter: BTreeMapIntoIter<K, V>,
    errors_iter: BTreeMapIntoIter<K, E>,
}

impl<K, V, E> Iterator for IntoIter<K, V, E> {
    type Item = (K, Result<V, E>);

    fn next(&mut self) -> Option<Self::Item> {
        self.ok_results_iter
            .next()
            .map(|(k, v)| (k, Ok(v)))
            .or_else(|| self.errors_iter.next().map(|(k, e)| (k, Err(e))))
    }
}

impl<K, V, E> FusedIterator for IntoIter<K, V, E> {}

impl<K, V, E> IntoIterator for MultiResults<K, V, E> {
    type Item = (K, Result<V, E>);
    type IntoIter = IntoIter<K, V, E>;

    fn into_iter(self) -> Self::IntoIter {
        Self::IntoIter {
            ok_results_iter: self.ok_results.into_iter(),
            errors_iter: self.errors.into_iter(),
        }
    }
}
