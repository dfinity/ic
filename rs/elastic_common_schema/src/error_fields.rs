//! From [Error Fields]:
//!
//! These fields can represent errors of any kind.
//!
//! Use them for errors that happen while fetching events or in cases where the
//! event itself contains an error.
//!
//! [Error Fields]: https://www.elastic.co/guide/en/ecs/current/ecs-error.html

use serde::Serialize;
use slog_derive::SerdeValue;

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Error {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<StackTrace>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub ty: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct StackTrace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}
