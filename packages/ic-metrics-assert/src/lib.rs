//! Fluent assertions for metrics.

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use async_trait::async_trait;
use candid::{Decode, Encode};
use ic_http_types::{HttpRequest, HttpResponse};
#[cfg(feature = "pocket_ic")]
pub use pocket_ic_query_call::{PocketIcAsyncHttpQuery, PocketIcHttpQuery};
use regex_lite::Regex;
use std::fmt;
use std::fmt::Debug;

/// Provides fluent test assertions for metrics.
///
/// # Examples
///
/// ```rust
/// use ic_metrics_assert::{MetricsAssert, PocketIcHttpQuery};
/// use pocket_ic::PocketIc;
/// use ic_management_canister_types::CanisterId;
///
/// struct Setup {
///     env: PocketIc,
///     canister_id : CanisterId,
/// }
///
/// impl Setup {
///     pub fn check_metrics(self) -> MetricsAssert<Self> {
///         MetricsAssert::from_http_query(self)
///     }
/// }
///
/// impl PocketIcHttpQuery for Setup {
///     fn get_pocket_ic(&self) -> &PocketIc {
///         &self.env
///     }
///
///     fn get_canister_id(&self) -> CanisterId {
///         self.canister_id
///     }
/// }
///
/// fn assert_metrics () {
///     use pocket_ic::PocketIcBuilder;
///     use candid::Principal;
///
///     let env = PocketIcBuilder::new().build();
///     let canister_id = Principal::from_text("7hfb6-caaaa-aaaar-qadga-cai").unwrap();
///     let setup = Setup {env, canister_id};
///
///     setup
///         .check_metrics()
///         .assert_contains_metric_matching("started action \\d+")
///         .assert_contains_metric_matching("completed action 1")
///         .assert_does_not_contain_metric_matching(".*trap.*");
/// }
/// ```
pub struct MetricsAssert<T> {
    actual: T,
    metrics: Vec<String>,
}

impl<T> MetricsAssert<T> {
    /// Initializes an instance of [`MetricsAssert`] by querying the metrics from the `/metrics`
    /// endpoint of a canister via the [`CanisterHttpQuery::http_query`] method.
    pub fn from_http_query<E>(actual: T) -> Self
    where
        T: CanisterHttpQuery<E>,
        E: Debug,
    {
        let metrics =
            decode_metrics_response_or_unwrap(actual.http_query(encoded_metrics_request()));
        Self { actual, metrics }
    }

    /// Initializes an instance of [`MetricsAssert`] by querying the metrics from the `/metrics`
    /// endpoint of a canister via the [`AsyncCanisterHttpQuery::http_query`] method.
    pub async fn from_async_http_query<E>(actual: T) -> Self
    where
        T: AsyncCanisterHttpQuery<E>,
        E: Debug,
    {
        let metrics =
            decode_metrics_response_or_unwrap(actual.http_query(encoded_metrics_request()).await);
        Self { actual, metrics }
    }

    /// Returns the internal instance being tested.
    pub fn into(self) -> T {
        self.actual
    }

    /// Asserts that the metrics contain at least one entry matching the given Regex pattern.
    pub fn assert_contains_metric_matching<P: AsRef<str> + fmt::Display>(self, pattern: P) -> Self {
        assert!(
            !self.find_metrics_matching(pattern.as_ref()).is_empty(),
            "Expected to find metric matching '{}', but none matched in:\n{:?}",
            pattern,
            self.metrics
        );
        self
    }

    /// Asserts that the metrics do not contain any entries matching the given Regex pattern.
    pub fn assert_does_not_contain_metric_matching(self, pattern: &str) -> Self {
        let matches = self.find_metrics_matching(pattern);
        assert!(
            matches.is_empty(),
            "Expected not to find any metric matching '{pattern}', but found the following matches:\n{matches:?}"
        );
        self
    }

    fn find_metrics_matching(&self, pattern: &str) -> Vec<String> {
        let regex = Regex::new(pattern).unwrap_or_else(|_| panic!("Invalid regex: {pattern}"));
        self.metrics
            .iter()
            .filter(|line| regex.is_match(line))
            .cloned()
            .collect()
    }
}

fn encoded_metrics_request() -> Vec<u8> {
    let request = HttpRequest {
        method: "GET".to_string(),
        url: "/metrics".to_string(),
        headers: Default::default(),
        body: Default::default(),
    };
    Encode!(&request).expect("failed to encode HTTP request")
}

fn decode_metrics_response_or_unwrap<E: Debug>(response: Result<Vec<u8>, E>) -> Vec<String> {
    let response = Decode!(&response.expect("failed to retrieve metrics"), HttpResponse)
        .expect("failed to decode HTTP response");
    assert_eq!(response.status_code, 200_u16);
    String::from_utf8_lossy(response.body.as_slice())
        .trim()
        .split('\n')
        .map(|line| line.to_string())
        .collect()
}

/// Trait providing the ability to perform an HTTP request to a canister.
pub trait CanisterHttpQuery<E: Debug> {
    /// Sends a serialized HTTP request to a canister and returns the serialized HTTP response.
    fn http_query(&self, request: Vec<u8>) -> Result<Vec<u8>, E>;
}

/// Trait providing the ability to perform an async HTTP request to a canister.
#[async_trait]
pub trait AsyncCanisterHttpQuery<E: Debug> {
    /// Sends a serialized HTTP request to a canister and returns the serialized HTTP response.
    async fn http_query(&self, request: Vec<u8>) -> Result<Vec<u8>, E>;
}

#[cfg(feature = "pocket_ic")]
mod pocket_ic_query_call {
    use super::*;
    use candid::Principal;
    use ic_management_canister_types::CanisterId;
    use pocket_ic::{PocketIc, RejectResponse, nonblocking};

    /// Provides an implementation of the [`CanisterHttpQuery`] trait in the case where the canister
    /// HTTP requests are made through an instance of [`PocketIc`].
    pub trait PocketIcHttpQuery {
        /// Returns a reference to the instance of [`PocketIc`] through which the HTTP requests are made.
        fn get_pocket_ic(&self) -> &PocketIc;

        /// Returns the ID of the canister to which HTTP requests will be made.
        fn get_canister_id(&self) -> CanisterId;
    }

    impl<T: PocketIcHttpQuery> CanisterHttpQuery<RejectResponse> for T {
        fn http_query(&self, request: Vec<u8>) -> Result<Vec<u8>, RejectResponse> {
            self.get_pocket_ic().query_call(
                self.get_canister_id(),
                Principal::anonymous(),
                "http_request",
                request,
            )
        }
    }

    /// Provides an implementation of the [`AsyncCanisterHttpQuery`] trait in the case where the
    /// canister HTTP requests are made through an instance of [`nonblocking::PocketIc`].
    pub trait PocketIcAsyncHttpQuery {
        /// Returns a reference to the instance of [`nonblocking::PocketIc`] through which the HTTP
        /// requests are made.
        fn get_pocket_ic(&self) -> &nonblocking::PocketIc;

        /// Returns the ID of the canister to which HTTP requests will be made.
        fn get_canister_id(&self) -> CanisterId;
    }

    #[async_trait]
    impl<T: PocketIcAsyncHttpQuery + Send + Sync> AsyncCanisterHttpQuery<RejectResponse> for T {
        async fn http_query(&self, request: Vec<u8>) -> Result<Vec<u8>, RejectResponse> {
            self.get_pocket_ic()
                .query_call(
                    self.get_canister_id(),
                    Principal::anonymous(),
                    "http_request",
                    request,
                )
                .await
        }
    }
}
