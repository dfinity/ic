//! Example of a canister using `canhttp` to issue HTTP requests.

use canhttp::{
    cycles::{ChargeMyself, CyclesAccountingServiceBuilder},
    http::HttpConversionLayer,
    observability::ObservabilityLayer,
    CanisterReadyLayer, Client, MaxResponseBytesRequestExtension,
};
use http::Request;
use ic_cdk::update;
use tower::{BoxError, Service, ServiceBuilder, ServiceExt};

/// Make an HTTP POST request.
#[update]
pub async fn make_http_post_request() -> String {
    let response = http_client()
        .ready()
        .await
        .expect("Client should be ready")
        .call(request())
        .await
        .expect("Request should succeed");

    assert_eq!(response.status(), http::StatusCode::OK);

    String::from_utf8_lossy(response.body()).to_string()
}

/// Make multiple HTTP POST requests in a loop,
/// ensuring via [`CanisterReadyLayer`] that the loop will stop if the canister is stopped.
#[update]
pub async fn infinite_loop_make_http_post_request() -> String {
    let mut client = ServiceBuilder::new()
        .layer(CanisterReadyLayer)
        .service(http_client());

    loop {
        match client.ready().await {
            Ok(ready) => {
                let response = ready.call(request()).await.expect("Request should succeed");
                assert_eq!(response.status(), http::StatusCode::OK);
            }
            Err(e) => return format!("Not ready: {}", e),
        }
    }
}

fn http_client(
) -> impl Service<http::Request<Vec<u8>>, Response = http::Response<Vec<u8>>, Error = BoxError> {
    ServiceBuilder::new()
        // Print request, response and errors to the console
        .layer(
            ObservabilityLayer::new()
                .on_request(|request: &http::Request<Vec<u8>>| ic_cdk::println!("{request:?}"))
                .on_response(|_, response: &http::Response<Vec<u8>>| {
                    ic_cdk::println!("{response:?}");
                })
                .on_error(|_, error: &BoxError| {
                    ic_cdk::println!("Error {error:?}");
                }),
        )
        // Only deal with types from the http crate.
        .layer(HttpConversionLayer)
        // Use cycles from the canister to pay for HTTPs outcalls
        .cycles_accounting(ChargeMyself::default())
        // The actual client
        .service(Client::new_with_box_error())
}

fn request() -> Request<Vec<u8>> {
    fn httpbin_base_url() -> String {
        option_env!("HTTPBIN_URL")
            .unwrap_or_else(|| "https://httpbin.org")
            .to_string()
    }

    http::Request::post(format!("{}/anything", httpbin_base_url()))
        .max_response_bytes(1_000)
        .header("X-Id", "42")
        .body("Hello, World!".as_bytes().to_vec())
        .unwrap()
}

fn main() {}
