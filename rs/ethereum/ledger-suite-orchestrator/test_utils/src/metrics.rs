use crate::assert_reply;
use candid::{Decode, Encode, Principal};
use ic_cdk::api::management_canister::main::CanisterId;
use pocket_ic::PocketIc;

pub struct MetricsAssert<T> {
    setup: T,
    metrics: Vec<String>,
}

impl<T: AsRef<PocketIc>> MetricsAssert<T> {
    pub fn from_querying_metrics(setup: T, canister_id: CanisterId) -> Self {
        use ic_canisters_http_types::{HttpRequest, HttpResponse};
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/metrics".to_string(),
            headers: Default::default(),
            body: Default::default(),
        };
        let response = Decode!(
            &assert_reply(
                setup
                    .as_ref()
                    .query_call(
                        canister_id,
                        Principal::anonymous(),
                        "http_request",
                        Encode!(&request).expect("failed to encode HTTP request"),
                    )
                    .expect("failed to get metrics")
            ),
            HttpResponse
        )
        .unwrap();
        assert_eq!(response.status_code, 200_u16);
        let metrics = String::from_utf8_lossy(response.body.as_slice())
            .trim()
            .split('\n')
            .map(|line| line.to_string())
            .collect::<Vec<_>>();
        Self { setup, metrics }
    }

    pub fn assert_contains_metric(self, metric: &str) -> T {
        assert!(
            self.metrics.iter().any(|line| line.contains(metric)),
            "Searched metric not found: {} in:\n{:?}",
            metric,
            self.metrics
        );
        self.setup
    }
}
