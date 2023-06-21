use std::{
    collections::HashMap,
    net::{Ipv6Addr, SocketAddr},
    str::FromStr,
};

use axum::{
    body::Body,
    extract::Path,
    http::{HeaderMap, Method, Uri},
    http::{HeaderName, StatusCode},
    middleware::map_response,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use axum_server::tls_openssl::OpenSSLConfig;
use axum_server::HttpConfig;
use clap::Parser;
use serde_json::json;
use tokio::time::{sleep, Duration};

const DETERMINISTIC_HEADERS: [(&str, &str); 4] = [
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Credentials", "true"),
    ("Connection", "close"),
    ("Date", "Jan 1 1970 00:00:00 GMT"),
];

/// Returns a normal HTML response
async fn root_handler() -> Html<&'static str> {
    Html(
        "<!DOCTYPE html>
<html lang=\"en\">
<head>
  <title>httpbin</title>
</head>
<body>
  <h1>httpbin</h1>
</body>
</html>",
    )
}

/// Returns a body of size `size`
async fn bytes_or_equal_bytes_handler(Path(size): Path<usize>) -> Vec<u8> {
    "x".repeat(size).as_bytes().to_vec()
}

/// Returns the body specified in the path as the body of the response
async fn ascii_handler(Path(body): Path<String>) -> Vec<u8> {
    body.as_bytes().to_vec()
}

/// Returns the response after a delay of `d` seconds
async fn delay_handler(Path(d): Path<u64>) -> Vec<u8> {
    sleep(Duration::from_secs(d)).await;
    "".as_bytes().to_vec()
}

/// Returns a redirect response based on the number specified in the path
async fn redirect_handler(Path(n): Path<u64>) -> impl IntoResponse {
    if n == 0 {
        return (StatusCode::NO_CONTENT, "".as_bytes().to_vec()).into_response();
    }

    let loc = if n == 1 {
        "/anything".to_string()
    } else {
        format!("/relative-redirect/{}", n - 1)
    };

    Redirect::to(&loc).into_response()
}

/// Builds the response body using the request
async fn anything_handler(method: Method, uri: Uri, headers: HeaderMap, body: String) -> Vec<u8> {
    let host = headers.get("host").unwrap().to_str().unwrap_or("");
    let headers = headers
        .iter()
        .map(|h| (h.0.to_string(), h.1.to_str().unwrap().to_string()))
        .collect::<HashMap<String, String>>();

    let body = json!({
        "method": method.to_string(),
        "headers": headers,
        "data": body,
        "url": format!("https://{}{}", host, uri),
    })
    .to_string();

    body.as_bytes().to_vec()
}

/// Returns the size of the request
async fn request_size_handler(headers: HeaderMap, body: String) -> String {
    let headers_size: usize = headers.iter().map(|h| h.0.as_str().len() + h.1.len()).sum();
    let total_size = headers_size + body.len();
    total_size.to_string()
}

/// Adds `size` headers in the response
async fn many_response_headers_handler(Path(size): Path<usize>) -> (HeaderMap, String) {
    let mut headers = HeaderMap::new();

    for i in 0..size {
        headers.insert(
            HeaderName::from_str(&format!("Name{:?}", i)).unwrap(),
            format!("value{:?}", i).parse().unwrap(),
        );
    }

    (headers, "".to_string())
}

/// Adds a header name of size `size` in the response
async fn long_response_header_name_handler(Path(size): Path<usize>) -> (HeaderMap, String) {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_str(&"x".repeat(size)).unwrap(),
        "value".parse().unwrap(),
    );
    (headers, "".to_string())
}

/// Adds a header value of size `size` in the response
async fn long_response_header_value_handler(Path(size): Path<usize>) -> (HeaderMap, String) {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_str("name").unwrap(),
        "x".repeat(size).parse().unwrap(),
    );
    (headers, "".to_string())
}

/// Makes a response with a total header size of `m`.
/// Each header has a size of 2 * `n` (unless the total size is reached)
async fn large_response_total_header_size_handler(
    Path((n, m)): Path<(usize, usize)>,
) -> impl IntoResponse {
    if n < 8 {
        return Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap();
    }

    let mut builder = Response::builder()
        .header("Content-Type", "text/plain")
        .header("Content-Length", 0);

    let mut total_size: usize = DETERMINISTIC_HEADERS
        .iter()
        .map(|h| h.0.len() + h.1.len())
        .sum::<usize>()
        + builder
            .headers_ref()
            .unwrap()
            .into_iter()
            .map(|h| h.0.as_str().len() + h.1.len())
            .sum::<usize>();

    let mut i = 0;

    while total_size < m {
        let mut name = format!("{:08}{}", i, "x".repeat(n - 8));
        name.truncate(m - total_size);
        total_size += name.len();
        let value = "x".repeat(n.min(m - total_size));
        total_size += value.len();
        builder = builder.header(name, value);
        i += 1;
    }

    builder.body(Body::empty()).unwrap()
}

async fn fallback() -> Redirect {
    Redirect::to("/anything")
}

#[derive(Parser)]
struct Cli {
    /// The port to listen on.
    #[clap(long)]
    port: u16,
    /// The path to cert.pem file.
    #[clap(long)]
    cert_file: std::path::PathBuf,
    /// The path to key.pem file.
    #[clap(long)]
    key_file: std::path::PathBuf,
}

/// The headers must be deterministic because the compliance tests are making use
/// of the total size of the response headers. Setting them here prevents hyper
/// from adding non-deterministic ones.
async fn add_deterministic_headers(res: Response) -> impl IntoResponse {
    (DETERMINISTIC_HEADERS, res)
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    let config = OpenSSLConfig::from_pem_file(args.cert_file, args.key_file)
        .expect("Failed to load TLS config");

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/bytes/:size", get(bytes_or_equal_bytes_handler))
        .route("/equal_bytes/:size", get(bytes_or_equal_bytes_handler))
        .route("/ascii/:body", get(ascii_handler))
        .route("/delay/:d", get(delay_handler))
        .route("/redirect/:n", get(redirect_handler))
        .route("/relative-redirect/:n", get(redirect_handler))
        .route("/post", post(anything_handler))
        .route("/request_size", post(request_size_handler))
        .route(
            "/many_response_headers/:size",
            get(many_response_headers_handler),
        )
        .route(
            "/long_response_header_name/:size",
            get(long_response_header_name_handler),
        )
        .route(
            "/long_response_header_value/:size",
            get(long_response_header_value_handler),
        )
        .route(
            "/anything",
            get(anything_handler)
                .post(anything_handler)
                .head(anything_handler),
        )
        .route(
            "/anything/*key",
            get(anything_handler)
                .post(anything_handler)
                .head(anything_handler),
        )
        .route(
            "/large_response_total_header_size/:n/:m",
            get(large_response_total_header_size_handler),
        )
        .fallback(fallback)
        .layer(map_response(add_deterministic_headers));

    let http_config = HttpConfig::new().http1_only(true).http2_only(false).build();

    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, args.port));

    axum_server::bind_openssl(addr, config)
        .http_config(http_config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
