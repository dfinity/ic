//! Elastic Common Schema implementation
//!
//! From [ECS]:
//!
//! > The Elastic Common Schema (ECS) is an open source specification, developed
//! > with support from the Elastic user community. ECS defines a common set of
//! > fields to be used when storing event data in Elasticsearch, such as logs
//! > and metrics.
//! >
//! > ECS specifies field names and Elasticsearch datatypes for each field, and
//! > provides descriptions and example usage. ECS also groups fields into ECS
//! > levels, which are used to signal how much a field is expected to be
//! > present. You can learn more about ECS levels in [Guidelines and Best
//! > Practices]. Finally, ECS also provides a set of naming guidelines for
//! > adding custom fields.
//!
//! This module is an incomplete implementation of (generally) just the ECS
//! fields that ic-fe needs to create structured logs that can easily be
//! ingested in to Elastic with rich support for analysing the data.
//!
//! Caveat lector: This is very much a work-in-progress. I'm not convinced
//! about some of the API decisions. Talk to Nik if you want to use this in
//! one of your tools.
//!
//! # Example, tracking a request/response
//!
//! Suppose you have a web server that receives requests and generates
//! responses. Each request/response pair is a single event.
//!
//! In the request handler:
//!
//! ## Import the library, alias to `ecs`
//!
//! ```
//! use elastic_common_schema as ecs;
//! ```
//!
//! ## Create a new event, and specify its [Kind].
//!
//! ```
//! # use elastic_common_schema as ecs;
//! let mut ev = ecs::Event::new(ecs::Kind::Event);
//! ```
//!
//! The generated event will also have a trace ID and one span associated
//! with the event.
//!
//! ## Start a timer (if you are tracking event durations).
//!
//! ```
//! # use elastic_common_schema as ecs;
//! let mut timer = ecs::Timer::start();
//! ```
//!
//! ## Set the event [Category] and [Type].
//!
//! ```
//! # use elastic_common_schema as ecs;
//! # let mut ev = ecs::Event::new(ecs::Kind::Event);
//! # use crate::elastic_common_schema::SetTo;
//! ev.event.set(ecs::Category::Web);
//! ev.event.set(ecs::Type::Access);
//! ```
//!
//! ## Set event details from the received request.
//!
//! ```
//! # use elastic_common_schema as ecs;
//! # use crate::elastic_common_schema::SetTo;
//! # use std::net::SocketAddr;
//! # let mut ev = ecs::Event::new(ecs::Kind::Event);
//! # let sock_addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
//! # let request = hyper::Request::new(hyper::Body::empty());
//! ev.client.set(sock_addr);     // sock_addr: SocketAddr
//! ev.source.set(sock_addr);
//! ev.http.set(&request);        // request: hyper::Request<Body>
//! ev.url.set(&request);
//! ev.user_agent.set(&request);
//! ```
//!
//! ## Process the request, generate the response
//!
//! Do whatever the code needs to do to generate a response.
//!
//! ## Set event details from the generated response
//!
//! ```
//! # use elastic_common_schema as ecs;
//! # use crate::elastic_common_schema::SetTo;
//! # let mut ev = ecs::Event::new(ecs::Kind::Event);
//! # let response = hyper::Response::new(hyper::Body::empty());
//! ev.http.set(&response);       // response: hyper::Response<Body>
//! ```
//!
//! ## Set whether the event represents a successful result or a failed one
//!
//! ```
//! # use elastic_common_schema as ecs;
//! # use crate::elastic_common_schema::SetTo;
//! # let mut ev = ecs::Event::new(ecs::Kind::Event);
//! ev.event.set(ecs::Outcome::Success);  // or ecs::Outcome::Failure
//! ```
//!
//! ## Finish the timer, add the start, end, and duration to the event
//!
//! ```
//! # use elastic_common_schema as ecs;
//! # use crate::elastic_common_schema::SetTo;
//! # let mut ev = ecs::Event::new(ecs::Kind::Event);
//! # let mut timer = ecs::Timer::start();
//! timer.finish();
//! ev.event.set(&timer);
//! ```
//!
//! ## Log the event
//!
//! ```
//! # use elastic_common_schema as ecs;
//! # use slog::info;
//! # use crate::elastic_common_schema::SetTo;
//! # let mut ev = ecs::Event::new(ecs::Kind::Event);
//! # let log = slog::Logger::root(slog::Discard, slog::o!());
//! info!(log, "Some message"; &ev);
//! ```
//!
//! # Spans
//!
//! An event is automatically associated with a trace and a span.
//!
//! To create a child event from an existing event use `.child()`.
//!
//! ```
//! # use elastic_common_schema as ecs;
//! # let mut ev = ecs::Event::new(ecs::Kind::Event);
//! let mut ev_child = ev.child();
//! ```
//!
//! `ev_child` has the same `Kind` and trace ID as the `ev`, but a different
//! span.
//!
//! Use this if the event involves multiple stages, especially if they involve
//! making requests to other services (web servers, databases, etc).
//!
//! [ECS]: https://www.elastic.co/guide/en/ecs/current/ecs-reference.html
//! [Guidelines and Best Practices]: https://www.elastic.co/guide/en/ecs/current/ecs-guidelines.html
//! [Kind]: https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-kind.html
//! [Category]: https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-category.html
//! [Type]: https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-type.html

pub use chrono::{DateTime, SecondsFormat, Utc};
use slog_derive::SerdeValue;
use trace_fields::{Span, Trace};
use url_fields::Url;
use value::ExtraValues;

use serde::Serialize;

pub mod drain;

mod client_fields;
mod destination_fields;
pub mod error_fields;
mod event_fields;
mod http_fields;
pub mod log_fields;
pub mod process_fields;
mod server_fields;
mod source_fields;
mod trace_fields;
mod url_fields;
mod user_agent_fields;
mod value;

pub use event_fields::Category;
pub use event_fields::Kind;
pub use event_fields::Outcome;
pub use event_fields::Reason;
pub use event_fields::Timer;
pub use event_fields::Type;

pub use value::Value;

// ECS schema references a number of types. These are aliases for those types
// so that the struct definitions are similar to the ECS definitions.
// https://www.elastic.co/guide/en/elasticsearch/reference/7.9/date.html
// and https://www.elastic.co/guide/en/elasticsearch/reference/7.9/mapping-date-format.html#strict-date-time
pub(crate) type Long = i64;
pub type Date = String;
pub type Port = Long;
pub type Duration = Long;

// TODO: Notes on interior builder pattern
//
// Doesn't work for this because you may find yourself wanting to set
// fields down different paths of the tree at the same time.
//
// For example, setting `client` should also set `source`, but the reverse
// is not true.
//
// So any methods that manipulate / set any part of the event all have
// to be implemented on the event, and not on any of the child structs.

/// Represents an [ECS] Event.
///
/// [ECS]: https://www.elastic.co/guide/en/ecs/current/index.html
#[derive(Clone, Default, Debug, Serialize, SerdeValue)]
pub struct Event {
    // Base fields: https://www.elastic.co/guide/en/ecs/current/ecs-base.html
    /// Date/time when the event originated.
    ///
    /// This is the date/time extracted from the event, typically
    /// representing when the event was generated by the source.
    ///
    /// If the event source has no original timestamp, this value is
    /// typically populated by the first time the event was received
    /// by the pipeline.
    ///
    /// Required field for all events.
    #[serde(rename = "@timestamp")]
    pub timestamp: String,

    /// Custom key/value pairs.
    ///
    /// Can be used to add meta information to events. Should not contain
    /// nested objects. All values are stored as keyword.
    ///
    /// Example: docker and k8s labels.
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub labels: Option<Vec<(String, String)>>,

    /// For log events the message field contains the log message, optimized
    /// for viewing in a log viewer.
    ///
    /// For structured logs without an original message field, other fields
    /// can be concatenated to form a human-readable summary of the
    /// event.
    ///
    /// If multiple messages exist, they can be combined into one message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// List of keywords used to tag each event.
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub tags: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<client_fields::Client>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<destination_fields::Destination>,
    pub ecs: Ecs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<error_fields::Error>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<event_fields::Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<http_fields::Http>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<log_fields::Log>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<process_fields::Process>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<server_fields::Server>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<source_fields::Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<user_agent_fields::UserAgent>,
    pub span: trace_fields::Span,
    pub trace: trace_fields::Trace,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<trace_fields::Transaction>,
    pub extra_values: ExtraValues,
}

macro_rules! serialize_field {
    ($self:ident, $field:ident, $record:ident, $serializer:ident) => {
        if let Some($field) = &$self.$field {
            slog::Value::serialize($field, $record, stringify!($field), $serializer)?;
        };
    };
}

/// Convert the event to a set of key/values for logging.
impl slog::KV for &Event {
    // Can't use `slog_derive::KV` due to
    // https://github.com/slog-rs/derive/issues/5#issuecomment-695965603
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        // Skip the timestamp, that's emitted in drain.rs

        // TODO: Labels

        if let Some(message) = &self.message {
            serializer.emit_str("message", message)?;
        }

        serialize_field!(self, client, record, serializer);
        serialize_field!(self, destination, record, serializer);

        slog::Value::serialize(&self.ecs, record, "ecs", serializer)?;

        serialize_field!(self, error, record, serializer);
        serialize_field!(self, event, record, serializer);
        serialize_field!(self, http, record, serializer);
        serialize_field!(self, log, record, serializer);
        serialize_field!(self, process, record, serializer);
        serialize_field!(self, server, record, serializer);
        serialize_field!(self, source, record, serializer);

        slog::Value::serialize(&self.span, record, "span", serializer)?;
        slog::Value::serialize(&self.trace, record, "trace", serializer)?;

        serialize_field!(self, url, record, serializer);
        serialize_field!(self, user_agent, record, serializer);

        // Any extra values are included at the top level, *not* under
        // the `extra_values` key.
        for (key, value) in &self.extra_values.0 {
            slog::Value::serialize(value, record, key, serializer)?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, SerdeValue)]
pub struct Ecs {
    pub version: String,
}

impl Default for Ecs {
    fn default() -> Self {
        Self {
            version: "1.6.0".to_string(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct AutonomousSystem {
    #[serde(skip_serializing_if = "Option::is_none")]
    number: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_name: Option<String>,
}
#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Geo {}

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct User {}

pub trait SetTo<T> {
    fn set(&mut self, item: T);
}

impl Event {
    pub fn new(kind: event_fields::Kind) -> Self {
        Self {
            event: Some(event_fields::Event {
                kind: Some(kind),
                ..Default::default()
            }),
            span: Span::default(),
            trace: Trace::default(),
            ..Default::default()
        }
    }

    // A new event that is part of the same trace, and defaults to having the
    // same `event.kind` value.
    pub fn child(&self) -> Self {
        let event_event = match &self.event {
            Some(event) => event.clone(),
            None => event_fields::Event::default(),
        };

        Self {
            event: Some(event_fields::Event {
                kind: event_event.kind,
                ..Default::default()
            }),
            trace: self.trace.clone(),
            span: Span::default(),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use super::*;
    use anyhow::Result;

    #[test]
    fn json() -> Result<()> {
        let mut event = Event::default();

        let client_ip: IpAddr = "127.0.0.1".parse()?;
        let client_ip2: IpAddr = "127.0.0.2".parse()?;

        event.client.set(client_ip);
        event.client.set(client_ip2);
        event
            .client
            .set("127.0.0.3:8000".parse::<SocketAddr>().unwrap());
        event.client.set(34_i64);

        println!("event: {}", serde_json::to_string(&event)?);

        Ok(())
    }
}
