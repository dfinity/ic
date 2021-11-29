//! From [Trace Fields]:
//!
//! Distributed tracing makes it possible to analyze performance throughout a
//! microservice architecture all in one view. This is accomplished by tracing
//! all of the requests - from the initial web request in the front-end service
//! - to queries made through multiple back-end services.
//!
//! Also see [Distributed Tracing].
//!
//! [Trace Fields]: https://www.elastic.co/guide/en/ecs/current/ecs-tracing.html
//! [Distributed Tracing]: https://www.elastic.co/guide/en/apm/get-started/current/distributed-tracing.html

use serde::Serialize;
use slog_derive::SerdeValue;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, SerdeValue)]
pub struct Span {
    pub id: String,
}

impl Default for Span {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_hyphenated().to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, SerdeValue)]
pub struct Trace {
    pub id: String,
}

impl Default for Trace {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_hyphenated().to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, SerdeValue)]
pub struct Transaction {
    pub id: Option<String>,
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            id: Some(Uuid::new_v4().to_hyphenated().to_string()),
        }
    }
}
