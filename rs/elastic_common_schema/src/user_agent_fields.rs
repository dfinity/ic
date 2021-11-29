//! From [User Agent Fields].
//!
//! The user_agent fields normally come from a browser request.
//!
//! They often show up in web service logs coming from the parsed user agent
//! string.
//!
//! [User Agent Fields]: https://www.elastic.co/guide/en/ecs/current/ecs-user_agent.html

use serde::Serialize;
use slog_derive::SerdeValue;

use crate::SetTo;

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct UserAgent {
    // TODO: device.name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl SetTo<String> for Option<UserAgent> {
    fn set(&mut self, original: String) {
        let user_agent = self.get_or_insert(UserAgent::default());
        user_agent.original = Some(original);
    }
}

impl SetTo<&hyper::Request<hyper::Body>> for Option<UserAgent> {
    fn set(&mut self, hyper_request: &hyper::Request<hyper::Body>) {
        let user_agent = self.get_or_insert(UserAgent::default());

        user_agent.original = hyper_request
            .headers()
            .get(hyper::header::USER_AGENT)
            .map(|header| header.to_str().unwrap_or("").to_string())
    }
}
