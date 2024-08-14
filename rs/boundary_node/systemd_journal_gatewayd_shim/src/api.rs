use std::{collections::HashSet, sync::Arc};

use anyhow::Context;
use axum::{
    body::Body,
    extract::{Query, Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use ic_async_utils::axum::BodyDataStream;
use itertools::{concat, Itertools};
use reqwest::Method;
use url::Url;

use crate::client::HttpClient;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("status {0}: {1}")]
    Custom(StatusCode, String),

    #[error("unauthorized")]
    Unauthorized,

    #[error(transparent)]
    Unspecified(#[from] anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (match self {
            ApiError::Custom(c, b) => (c, b),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            ApiError::Unspecified(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        })
        .into_response()
    }
}

pub(crate) async fn entries(
    State((
        u,  // upstream_url
        us, // units
        c,  // http_client
    )): State<(Url, HashSet<String>, Arc<dyn HttpClient>)>,
    Query(params): Query<Vec<(String, String)>>,
    req: Request<Body>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate request
    let (ps_us, ps_other) =
        params
            .into_iter()
            .fold((vec![], vec![]), |(a, b), (k, v)| match k.as_str() {
                "_SYSTEMD_UNIT" => (concat(vec![a, vec![(k, v)]]), b),
                _ => (a, concat(vec![b, vec![(k, v)]])),
            });

    let mut req_us: Vec<String> = ps_us
        .into_iter()
        .map(|(_, v)| v) // extract unit
        .collect();

    // Default to `us`
    if req_us.is_empty() {
        req_us = us.iter().cloned().collect();
    }

    for u in req_us.iter() {
        if !us.contains(u) {
            return Err(ApiError::Unauthorized);
        }
    }

    // Prepare request
    let mut u = u;

    u.set_query({
        // Concatenate query params
        let ps = concat(vec![
            ps_other,
            req_us
                .into_iter()
                .map(|u| ("_SYSTEMD_UNIT".to_string(), u))
                .collect(),
        ]);

        Some(
            ps.into_iter()
                .map(|(k, v)| format!("{k}={v}"))
                .join("&")
                .as_str(),
        )
    });

    let (parts, body) = req.into_parts();
    let body_stream = BodyDataStream::new(body);

    let mut upstream_req = reqwest::Request::new(Method::GET, u);

    *upstream_req.headers_mut() = parts.headers;
    *upstream_req.body_mut() = Some(reqwest::Body::wrap_stream(body_stream));

    // Send request to upstream
    let resp = c
        .execute(upstream_req)
        .await
        .context("failed to execute request")?;

    if resp.status() != StatusCode::OK {
        return Err(ApiError::Custom(
            resp.status(),
            resp.text()
                .await
                .context("failed to consume response text")?,
        ));
    }

    let mut b = Response::builder();

    // Status
    b = b.status(resp.status());

    // Headers
    *b.headers_mut().context("failed to reference headers")? = resp.headers().clone();

    // Body
    let resp = b
        .body(Body::from_stream(resp.bytes_stream()))
        .context("failed to set response body")?;

    Ok(resp)
}
