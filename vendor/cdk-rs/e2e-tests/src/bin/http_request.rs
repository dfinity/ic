use ic_cdk::management_canister::{
    http_request, http_request_with_closure, transform_context_from_query, HttpHeader, HttpMethod,
    HttpRequestArgs, HttpRequestResult, TransformArgs,
};
use ic_cdk::{query, update};

/// All fields are Some except transform.
#[update]
async fn get_without_transform() {
    let args = HttpRequestArgs {
        url: "https://example.com".to_string(),
        method: HttpMethod::GET,
        headers: vec![HttpHeader {
            name: "request_header_name".to_string(),
            value: "request_header_value".to_string(),
        }],
        body: Some(vec![1]),
        max_response_bytes: Some(100_000),
        transform: None,
        is_replicated: Some(true),
    };

    let res = http_request(&args).await.unwrap();
    assert_eq!(res.status, 200u32);
    assert_eq!(
        res.headers,
        vec![HttpHeader {
            name: "response_header_name".to_string(),
            value: "response_header_value".to_string(),
        }]
    );
    assert_eq!(res.body, vec![42]);
}

/// Method is POST.
#[update]
async fn post() {
    let args = HttpRequestArgs {
        url: "https://example.com".to_string(),
        method: HttpMethod::POST,
        ..Default::default()
    };

    http_request(&args).await.unwrap();
}

/// Method is HEAD.
#[update]
async fn head() {
    let args = HttpRequestArgs {
        url: "https://example.com".to_string(),
        method: HttpMethod::HEAD,
        ..Default::default()
    };

    http_request(&args).await.unwrap();
}

/// The standard way to define a transform function.
///
/// It is a query method that takes a `TransformArgs` and returns an `HttpRequestResult`.
#[query]
fn transform(args: TransformArgs) -> HttpRequestResult {
    let mut body = args.response.body;
    body.push(args.context[0]);
    HttpRequestResult {
        status: args.response.status,
        headers: args.response.headers,
        body,
    }
}

/// Set the transform field with the name of the transform query method.
#[update]
async fn get_with_transform() {
    let args = HttpRequestArgs {
        url: "https://example.com".to_string(),
        method: HttpMethod::GET,
        transform: Some(transform_context_from_query(
            "transform".to_string(),
            vec![42],
        )),
        ..Default::default()
    };

    let res = http_request(&args).await.unwrap();
    assert_eq!(res.status, 200u32);
    assert_eq!(
        res.headers,
        vec![HttpHeader {
            name: "response_header_name".to_string(),
            value: "response_header_value".to_string(),
        }]
    );
    // The first 42 is from the response body, the second 42 is from the transform context.
    assert_eq!(res.body, vec![42, 42]);
}

/// Set the transform field with a closure.
#[update]
async fn get_with_transform_closure() {
    let transform = |args: HttpRequestResult| {
        let mut body = args.body;
        body.push(42);
        HttpRequestResult {
            status: args.status,
            headers: args.headers,
            body,
        }
    };
    let args = HttpRequestArgs {
        url: "https://example.com".to_string(),
        method: HttpMethod::GET,
        transform: None,
        ..Default::default()
    };
    let res = http_request_with_closure(&args, transform).await.unwrap();
    assert_eq!(res.status, 200u32);
    assert_eq!(
        res.headers,
        vec![HttpHeader {
            name: "response_header_name".to_string(),
            value: "response_header_value".to_string(),
        }]
    );
    // The first 42 is from the response body, the second 42 is from the transform closure.
    assert_eq!(res.body, vec![42, 42]);
}

/// Non replicated HTTP request.
#[update]
async fn non_replicated() {
    let args = HttpRequestArgs {
        url: "https://example.com".to_string(),
        method: HttpMethod::GET,
        is_replicated: Some(false),
        ..Default::default()
    };

    http_request(&args).await.unwrap();
}

fn main() {}
