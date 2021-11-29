//! From [URL Fields]
//!
//! URL fields provide support for complete or partial URLs, and supports the
//! breaking down into scheme, domain, path, and so on.
//!
//! [URL Fields]: https://www.elastic.co/guide/en/ecs/current/ecs-url.html

use serde::Serialize;
use slog_derive::SerdeValue;

use crate::{Long, SetTo};

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Url {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registered_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_level_domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

impl SetTo<&hyper::Request<hyper::Body>> for Option<Url> {
    fn set(&mut self, request: &hyper::Request<hyper::Body>) {
        let url = self.get_or_insert(Url::default());

        let request_uri = request.uri();

        url.original = Some(request_uri.to_string());
        url.path = Some(request_uri.path().into());
        url.scheme = request_uri.scheme_str().map(|s| s.into());
        url.port = request_uri.port_u16().map(|p| p.into());
        url.query = request_uri.query().map(|s| s.into());

        if let Some(authority) = request_uri.authority() {
            url.domain = Some(authority.host().into());
        }
    }
}
