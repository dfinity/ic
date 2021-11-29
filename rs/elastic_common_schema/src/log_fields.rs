//! From [Log Fields]:
//!
//! Details about the event’s logging mechanism or logging transport.
//!
//! The log.* fields are typically populated with details about the logging
//! mechanism used to create and/or transport the event. For example, syslog
//! details belong under log.syslog.*.
//!
//! The details specific to your event source are typically not logged under
//! log.*, but rather in event.* or in other ECS fields.
//!
//! [Log Fields]: https://www.elastic.co/guide/en/ecs/current/ecs-log.html

use serde::Serialize;
use slog_derive::SerdeValue;

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Log {
    // TODO: file.path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logger: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    // TODO: More fields to go here.
}

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Origin {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<OriginFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct OriginFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}
