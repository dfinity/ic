//! Example of a canister using `canhttp` to issue multiple requests in parallel.

use canhttp::http::json::JsonResponseConverter;
use canhttp::http::HttpRequest;
use canhttp::multi::parallel_call;
use canhttp::{
    cycles::{ChargeMyself, CyclesAccountingServiceBuilder},
    http::HttpConversionLayer,
    observability::ObservabilityLayer,
    Client, ConvertServiceBuilder,
};
use ic_cdk::update;
use std::iter;
use tower::{BoxError, Service, ServiceBuilder, ServiceExt};

/// Make parallel HTTP requests.
#[update]
pub async fn make_parallel_http_requests() -> Vec<String> {
    let request = http::Request::get(format!("{}/uuid", httpbin_base_url()))
        .body(vec![])
        .unwrap();

    let mut client = http_client();
    client.ready().await.expect("Client should be ready");

    let (_client, results) = parallel_call(client, iter::repeat_n(request, 5).enumerate()).await;
    let (results, errors) = results.into_inner();
    if !errors.is_empty() {
        panic!(
            "Requests should all succeed but received {} errors: {:?}",
            errors.len(),
            errors
        );
    }

    results
        .into_values()
        .map(|response| {
            assert_eq!(response.status(), http::StatusCode::OK);
            response.body()["uuid"]
                .as_str()
                .expect("Expected UUID in response")
                .to_string()
        })
        .collect()
}

fn http_client(
) -> impl Service<HttpRequest, Response = http::Response<serde_json::Value>, Error = BoxError> {
    ServiceBuilder::new()
        // Print request, response and errors to the console
        .layer(
            ObservabilityLayer::new()
                .on_request(|request: &http::Request<Vec<u8>>| ic_cdk::println!("{request:?}"))
                .on_response(|_, response: &http::Response<serde_json::Value>| {
                    ic_cdk::println!("{response:?}");
                })
                .on_error(|_, error: &BoxError| {
                    ic_cdk::println!("Error {error:?}");
                }),
        )
        // Parse the response as JSON
        .convert_response(JsonResponseConverter::<serde_json::Value>::new())
        // Convert the request and responses to types from the `http` crate
        .layer(HttpConversionLayer)
        // Use cycles from the canister to pay for HTTPs outcalls
        .cycles_accounting(ChargeMyself::default())
        // The actual client
        .service(Client::new_with_box_error())
}

fn httpbin_base_url() -> String {
    option_env!("HTTPBIN_URL")
        .unwrap_or_else(|| "https://httpbin.org")
        .to_string()
}

fn main() {}
