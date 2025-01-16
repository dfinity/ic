//! Fluent assertions for metrics.

use candid::{CandidType, Decode, Deserialize, Encode};
use regex::Regex;
use std::fmt::Debug;

pub struct MetricsAssert<T> {
    actual: T,
    metrics: Vec<String>,
}

pub trait CanisterHttpQuery<E: Debug> {
    fn http_get(&self, request: Vec<u8>) -> Result<Vec<u8>, E>;
}

impl<T> MetricsAssert<T> {
    pub fn from_http_query<E>(actual: T) -> Self
    where
        T: CanisterHttpQuery<E>,
        E: Debug,
    {
        let request = http::HttpRequest {
            method: "GET".to_string(),
            url: "/metrics".to_string(),
            headers: Default::default(),
            body: Default::default(),
        };
        let response = Decode!(
            &actual
                .http_get(Encode!(&request).expect("failed to encode HTTP request"))
                .expect("failed to retrieve metrics"),
            http::HttpResponse
        )
        .unwrap();
        assert_eq!(response.status_code, 200_u16);
        let metrics = String::from_utf8_lossy(response.body.as_slice())
            .trim()
            .split('\n')
            .map(|line| line.to_string())
            .collect::<Vec<_>>();
        Self { metrics, actual }
    }

    pub fn actual(self) -> T {
        self.actual
    }

    pub fn assert_contains_metric_matching(self, pattern: &str) -> Self {
        assert!(
            !self.find_metrics_matching(pattern).is_empty(),
            "Expected to find metric matching '{}', but none matched in:\n{:?}",
            pattern,
            self.metrics
        );
        self
    }

    pub fn assert_does_not_contain_metric_matching(self, pattern: &str) -> Self {
        let matches = self.find_metrics_matching(pattern);
        assert!(
            matches.is_empty(),
            "Expected not to find any metric matching '{}', but found the following matches:\n{:?}",
            pattern,
            matches
        );
        self
    }

    fn find_metrics_matching(&self, pattern: &str) -> Vec<String> {
        let regex = Regex::new(pattern).unwrap_or_else(|_| panic!("Invalid regex: {}", pattern));
        self.metrics
            .iter()
            .filter(|line| regex.is_match(line))
            .cloned()
            .collect()
    }
}

#[cfg(feature = "pocket_ic")]
pub use pocket_ic_query_call::PocketIcHttpQuery;

#[cfg(feature = "pocket_ic")]
mod pocket_ic_query_call {
    use super::*;
    use candid::Principal;
    use pocket_ic::{management_canister::CanisterId, PocketIc, UserError, WasmResult};

    pub trait PocketIcHttpQuery {
        fn get_pocket_ic(&self) -> &PocketIc;
        fn get_canister_id(&self) -> CanisterId;
    }

    impl<T: PocketIcHttpQuery> CanisterHttpQuery<UserError> for T {
        fn http_get(&self, request: Vec<u8>) -> Result<Vec<u8>, UserError> {
            self.get_pocket_ic()
                .query_call(
                    self.get_canister_id(),
                    Principal::anonymous(),
                    "http_request",
                    request,
                )
                .map(|result| match result {
                    WasmResult::Reply(bytes) => bytes,
                    WasmResult::Reject(reject) => {
                        panic!("Expected a successful reply, got a reject: {}", reject)
                    }
                })
        }
    }
}

mod http {
    use super::*;
    use serde_bytes::ByteBuf;

    #[derive(Clone, Debug, CandidType, Deserialize)]
    pub struct HttpRequest {
        pub method: String,
        pub url: String,
        pub headers: Vec<(String, String)>,
        pub body: ByteBuf,
    }

    #[derive(Clone, Debug, CandidType, Deserialize)]
    pub struct HttpResponse {
        pub status_code: u16,
        pub headers: Vec<(String, String)>,
        pub body: ByteBuf,
    }
}
