use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Host, OriginalUri},
    http::{uri::PathAndQuery, Response, Uri},
    response::{IntoResponse, Redirect},
    Extension,
};
use tokio::sync::RwLock;

pub async fn acme_challenge(
    Extension(token): Extension<Arc<RwLock<Option<String>>>>,
) -> impl IntoResponse {
    token.read().await.clone().unwrap_or_default()
}

pub async fn redirect_to_https(
    Host(host): Host,
    OriginalUri(uri): OriginalUri,
) -> impl IntoResponse {
    let fallback_path = PathAndQuery::from_static("/");
    let pq = uri.path_and_query().unwrap_or(&fallback_path).as_str();

    Redirect::permanent(
        &Uri::builder()
            .scheme("https") // redirect to https
            .authority(host) // re-use the same host
            .path_and_query(pq) // re-use the same path and query
            .build()
            .unwrap()
            .to_string(),
    )
}

pub async fn status() -> impl IntoResponse {
    "Hello, World!"
}

pub async fn query() -> impl IntoResponse {
    "Hello, World!"
}

pub async fn call() -> impl IntoResponse {
    "Hello, World!"
}

pub async fn read_state() -> impl IntoResponse {
    "Hello, World!"
}
