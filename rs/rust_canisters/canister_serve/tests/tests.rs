#![allow(deprecated)]
use ic_canister_log::{declare_log_buffer, log};
use ic_canister_serve::serve_logs;
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpMethod, HttpResponse,
};
use maplit::hashmap;
use serde_json::json;
use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Debug, serde::Deserialize)]
struct LogsResponseBody {
    entries: Vec<JsonLogEntry>,
}

#[derive(Debug, serde::Deserialize)]
struct JsonLogEntry {
    severity: String,
    timestamp: u128,
    file: String,
    line: u128,
    message: String,
}

const MAX_DELAY_NS: u128 = 1_000_000_000;

#[test]
fn test_serve_logs_no_frills() {
    // Step 1: Prepare the world.
    declare_log_buffer!(name = INFO, capacity = 100);
    declare_log_buffer!(name = ERROR, capacity = 100);

    let before_timestamp_nanoseconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    log!(INFO, "hi");
    log!(ERROR, "YIKES!");
    log!(INFO, "hol' up");
    log!(ERROR, "DA ROOF IS ON FAIYA");

    // Step 2: Call the code under test.
    let http_request = CanisterHttpRequestArgument {
        method: HttpMethod::GET,
        url: "http://example.com/logs".to_string(),
        headers: vec![],
        body: Some(vec![]),
        max_response_bytes: None,
        transform: None,
    };
    let HttpResponse {
        status,
        headers,
        body,
    } = serve_logs(http_request, &INFO, &ERROR);

    // Step 3: Inspect the results.

    // Step 3.1: Inspect header.
    assert_eq!(status, 200_u32);
    assert_eq!(
        headers
            .into_iter()
            .map(|header| (header.name, header.value))
            .collect::<HashMap<String, String>>(),
        hashmap! {
            "Content-Type".to_string() => "application/json".to_string(),
            "Content-Length".to_string() => format!("{}", body.len()),
        },
    );

    // Step 3.2: Inspect (JSON) payload.
    let body = String::from_utf8(body).unwrap();
    let body = serde_json::from_str::<LogsResponseBody>(&body).unwrap();
    assert_eq!(body.entries.len(), 4, "{body:#?}");

    let e0 = &body.entries[0];
    let delay_0_ns = e0.timestamp - before_timestamp_nanoseconds;
    assert_eq!(e0.severity, "Info", "{body:#?}");
    assert!(delay_0_ns < MAX_DELAY_NS, "{body:#?}");
    assert!(
        e0.file.contains("rs/rust_canisters/canister_serve/tests"),
        "{body:#?}"
    );
    assert!(e0.line > 0, "{body:#?}");
    assert_eq!(e0.message, "hi", "{body:#?}");

    let e1 = &body.entries[1];
    let delay_1_ns = e1.timestamp - e0.timestamp;
    assert_eq!(e1.severity, "Error", "{body:#?}");
    assert!(delay_1_ns < MAX_DELAY_NS, "{body:#?}");
    assert!(
        e1.file.contains("rs/rust_canisters/canister_serve/tests"),
        "{body:#?}"
    );
    assert!(e1.line > e0.line, "{body:#?}");
    assert_eq!(e1.message, "YIKES!", "{body:#?}");

    let e2 = &body.entries[2];
    let delay_2_ns = e2.timestamp - e1.timestamp;
    assert_eq!(e2.severity, "Info", "{body:#?}");
    assert!(delay_2_ns < MAX_DELAY_NS, "{body:#?}");
    assert!(
        e2.file.contains("rs/rust_canisters/canister_serve/tests"),
        "{body:#?}"
    );
    assert!(e2.line > e1.line, "{body:#?}");
    assert_eq!(e2.message, "hol' up", "{body:#?}");

    let e3 = &body.entries[3];
    let delay_3_ns = e3.timestamp - e2.timestamp;
    assert_eq!(e3.severity, "Error", "{body:#?}");
    assert!(delay_3_ns < MAX_DELAY_NS, "{body:#?}");
    assert!(
        e3.file.contains("rs/rust_canisters/canister_serve/tests"),
        "{body:#?}"
    );
    assert!(e3.line > e1.line, "{body:#?}");
    assert_eq!(e3.message, "DA ROOF IS ON FAIYA", "{body:#?}");
}

#[test]
fn test_serve_logs_only_errors() {
    // Step 1: Prepare the world.
    declare_log_buffer!(name = INFO, capacity = 100);
    declare_log_buffer!(name = ERROR, capacity = 100);

    let before_timestamp_nanoseconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    log!(INFO, "foo");
    log!(ERROR, "FOO!");
    log!(INFO, "bar");
    log!(ERROR, "BAR!");

    // Step 2: Call the code under test.
    let http_request = CanisterHttpRequestArgument {
        method: HttpMethod::GET,
        url: "http://example.com/logs?severity=Error".to_string(),
        headers: vec![],
        body: Some(vec![]),
        max_response_bytes: None,
        transform: None,
    };

    let HttpResponse {
        status,
        headers,
        body,
    } = serve_logs(http_request, &INFO, &ERROR);

    // Step 3: Inspect the results.

    // Step 3.1: Inspect header.
    assert_eq!(status, 200_u32);
    assert_eq!(
        headers
            .into_iter()
            .map(|header| (header.name, header.value))
            .collect::<HashMap<String, String>>(),
        hashmap! {
            "Content-Type".to_string() => "application/json".to_string(),
            "Content-Length".to_string() => format!("{}", body.len()),
        },
    );

    // Step 3.2: Inspect (JSON) payload.
    let body = String::from_utf8(body).unwrap();
    let body = serde_json::from_str::<LogsResponseBody>(&body).unwrap();
    assert_eq!(body.entries.len(), 2, "{body:#?}");

    let e0 = &body.entries[0];
    let delay_0_ns = e0.timestamp - before_timestamp_nanoseconds;
    assert_eq!(e0.severity, "Error", "{body:#?}");
    assert!(delay_0_ns < MAX_DELAY_NS, "{body:#?}");
    assert!(
        e0.file.contains("rs/rust_canisters/canister_serve/tests"),
        "{body:#?}"
    );
    assert!(e0.line > 0, "{body:#?}");
    assert_eq!(e0.message, "FOO!", "{body:#?}");

    let e1 = &body.entries[1];
    let delay_1_ns = e1.timestamp - e0.timestamp;
    assert_eq!(e1.severity, "Error", "{body:#?}");
    assert!(delay_1_ns < MAX_DELAY_NS, "{body:#?}");
    assert!(
        e1.file.contains("rs/rust_canisters/canister_serve/tests"),
        "{body:#?}"
    );
    assert!(e1.line > e0.line, "{body:#?}");
    assert_eq!(e1.message, "BAR!", "{body:#?}");
}

#[test]
fn test_serve_logs_time_bound() {
    // Step 1: Prepare the world.
    declare_log_buffer!(name = INFO, capacity = 100);
    declare_log_buffer!(name = ERROR, capacity = 100);

    log!(INFO, "before");
    log!(ERROR, "BEFORE!");
    let between_timestamp_nanoseconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    log!(ERROR, "AFTER!");
    log!(INFO, "after");

    // Step 2: Call the code under test.
    let http_request = CanisterHttpRequestArgument {
        method: HttpMethod::GET,
        url: format!("http://example.com/logs?time={between_timestamp_nanoseconds}"),
        headers: vec![],
        body: Some(vec![]),
        max_response_bytes: None,
        transform: None,
    };
    let HttpResponse {
        status,
        headers,
        body,
    } = serve_logs(http_request, &INFO, &ERROR);

    // Step 3: Inspect the results.

    // Step 3.1: Inspect header.
    assert_eq!(status, 200_u32);
    assert_eq!(
        headers
            .into_iter()
            .map(|header| (header.name, header.value))
            .collect::<HashMap<String, String>>(),
        hashmap! {
            "Content-Type".to_string() => "application/json".to_string(),
            "Content-Length".to_string() => format!("{}", body.len()),
        },
    );

    // Step 3.2: Inspect (JSON) payload.
    let body = String::from_utf8(body).unwrap();
    let body = serde_json::from_str::<LogsResponseBody>(&body).unwrap();
    assert_eq!(body.entries.len(), 2, "{body:#?}");

    let e0 = &body.entries[0];
    let delay_0_ns = e0.timestamp - between_timestamp_nanoseconds;
    assert_eq!(e0.severity, "Error", "{body:#?}");
    assert!(delay_0_ns < MAX_DELAY_NS, "{body:#?}");
    assert!(
        e0.file.contains("rs/rust_canisters/canister_serve/tests"),
        "{body:#?}"
    );
    assert!(e0.line > 0, "{body:#?}");
    assert_eq!(e0.message, "AFTER!", "{body:#?}");

    let e1 = &body.entries[1];
    let delay_1_ns = e1.timestamp - e0.timestamp;
    assert_eq!(e1.severity, "Info", "{body:#?}");
    assert!(delay_1_ns < MAX_DELAY_NS, "{body:#?}");
    assert!(
        e1.file.contains("rs/rust_canisters/canister_serve/tests"),
        "{body:#?}"
    );
    assert!(e1.line > e0.line, "{body:#?}");
    assert_eq!(e1.message, "after", "{body:#?}");
}

#[test]
fn test_serve_logs_malformed_request() {
    // Step 1: Prepare the world.
    declare_log_buffer!(name = INFO, capacity = 100);
    declare_log_buffer!(name = ERROR, capacity = 100);

    log!(INFO, "foo");
    log!(ERROR, "BAR!");
    log!(ERROR, "BAZ!");

    // Step 2: Call the code under test.
    let http_request = CanisterHttpRequestArgument {
        method: HttpMethod::GET,
        url: "http://example.com/logs?time=NONSENSE".to_string(),
        headers: vec![],
        body: Some(vec![]),
        max_response_bytes: None,
        transform: None,
    };
    let HttpResponse {
        status,
        headers,
        body,
    } = serve_logs(http_request, &INFO, &ERROR);

    // Step 3: Inspect the results.

    // Step 3.1: Inspect header.
    assert_eq!(status, 400_u32);
    assert_eq!(
        headers
            .into_iter()
            .map(|header| (header.name, header.value))
            .collect::<HashMap<String, String>>(),
        hashmap! {
            "Content-Type".to_string() => "application/json".to_string(),
            "Content-Length".to_string() => format!("{}", body.len()),
        },
    );

    // Step 3.2: Inspect body.
    let body = String::from_utf8(body).unwrap();
    #[derive(Debug, serde::Deserialize)]
    struct ResponseBody {
        error_description: String,
    }
    let ResponseBody { error_description } = serde_json::from_str::<ResponseBody>(&body).unwrap();

    // Step 3.2.1: Stuff that should be in error_description.
    assert!(
        error_description.to_lowercase().contains("invalid"),
        "{}",
        error_description
    );
    assert!(error_description.contains("time"), "{}", error_description);
    assert!(
        error_description.contains("NONSENSE"),
        "{}",
        error_description
    );

    // Step 3.2.2: Stuff that should NOT be in error_description.
    assert!(
        !error_description.to_lowercase().contains("severity"),
        "{}",
        error_description
    );

    // Step 3.2.3: No extraneous keys.
    let body = serde_json::from_str::<serde_json::Value>(&body).unwrap();
    assert_eq!(
        body,
        json!({
            "error_description": error_description,
        }),
    );
}
