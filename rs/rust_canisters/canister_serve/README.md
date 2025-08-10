# IC Canister Serve

This package provides helpful methods for serving logs and metrics via the http_request endpoint of smart contracts running in the [Internet Computer](https://internetcomputer.org/) (also known as [canisters](https://internetcomputer.org/docs/current/references/glossary/#canister)).

## Usage

This crate builds on top of [ic-canister-log](https://crates.io/crates/ic-canister-log) and 
[ic-metrics-encoder](https://crates.io/crates/ic-metrics-encoder) to make serving metrics and logs easy from
a canister's `http_request` method.  


```rust
use ic_canister_log::{declare_log_buffer, log};
use ic_canister_serve::{serve_logs, serve_metrics};
use ic_cdk::api::management_canister::http_request::{CanisterHttpRequestArgument, HttpResponse};
use ic_metrics_encoder::MetricsEncoder;

// Keep up to 100 last messages.
declare_log_buffer!(name = INFO, capacity = 100);
declare_log_buffer!(name = ERROR, capacity = 100);

fn encode_metrics(w: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> { 
    w.encode_gauge("example_metric_name", 0 as f64, "Example metric description")?;
    Ok(())
}

#[ic_cdk::query]
fn http_request(request: CanisterHttpRequestArgument) -> HttpResponse {
    log!(INFO, "This is an INFO log");
    log!(ERROR, "This is an ERROR log");
    
    let path = match request.url.find('?') {
        None => &request.url[..],
        Some(index) => &request.url[..index],
    };
    
    match path {
        "/metrics" => serve_metrics(encode_metrics),
        "/logs" => serve_logs(request, &INFO, &ERROR),
        _ => HttpResponse {
                status: 404.into(),
                body: "not_found".into(),
                ..Default::default()
            }
   }
}
```

### Example Request

To request the metrics, execute the following curl request:

```shell
$ curl https://example-canister.raw.ic0.app/metrics
```

To request all the logs, execute the following curl request:

```shell
$ curl https://example-canister.raw.ic0.app/logs
```

To request just the INFO logs, execute the following curl request:

```shell
$ curl https://example-canister.raw.ic0.app/logs?severity=Info
```

To request just the ERROR logs, execute the following curl request:

```shell
$ curl https://example-canister.raw.ic0.app/logs?severity=Error
```

To request logs before a certain timestamp, execute the following curl request:
```shell
$ curl https://example-canister.raw.ic0.app/logs?time=1683837947035
```