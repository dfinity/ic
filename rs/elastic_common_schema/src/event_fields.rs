//! From [Event Fields]:
//!
//! The event fields are used for context information about the log or metric
//! event itself.
//!
//! A log is defined as an event containing details of something that happened.
//! Log events must include the time at which the thing happened. Examples of
//! log events include a process starting on a host, a network packet being sent
//! from a source to a destination, or a network connection between a client and
//! a server being initiated or closed. A metric is defined as an event
//! containing one or more numerical measurements and the time at which the
//! measurement was taken. Examples of metric events include memory pressure
//! measured on a host and device temperature. See the event.kind definition in
//! this section for additional details about metric and state events.
//!
//! [Event Fields]: https://www.elastic.co/guide/en/ecs/current/ecs-event.html

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use slog_derive::SerdeValue;

use crate::{Date, Duration, Long, SetTo};

// Categorization hierarchy:
//
// - Kind
// - Category
// - Type
// - Outcome

#[derive(Clone, Debug, Default, Serialize, SerdeValue)]
pub struct Event {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<Vec<Category>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<Date>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<Date>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingested: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<Kind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score_norm: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Long>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<Date>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub ty: Option<Vec<Type>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Clone, Debug, Serialize, SerdeValue)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Events in this category are related to the challenge and response
    /// process in which credentials are supplied and verified to allow the
    /// creation of a session. Common sources for these logs are Windows event
    /// logs and ssh logs. Visualize and analyze events in this category to
    /// look for failed logins, and other authentication-related activity.
    ///
    /// Expected event types for category authentication:
    ///
    /// start, end, info
    Authentication,
    Database,
    Driver,
    File,
    Host,
    Iam,
    IntrusionDetection,
    Malware,
    Network,
    Package,
    /// Use this category of events to visualize and analyze process-specific
    /// information such as lifecycle events or process ancestry.
    ///
    /// Expected event types for category process:
    ///
    /// access, change, end, info, start
    Process,
    /// Relating to web server access. Use this category to create a dashboard
    /// of web server/proxy activity from apache, IIS, nginx web servers, etc.
    /// Note: events from network observers such as Zeek http log may also be
    /// included in this category.
    ///
    /// Expected event types for category web:
    ///
    /// access, error, info
    Web,
}

#[derive(Clone, Debug, Serialize, SerdeValue)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Alert,
    Event,
    Metric,
    State,
    PipelineError,
    Signal,
}

#[derive(Clone, Debug, Serialize, SerdeValue)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Failure,
    Success,
    Unknown,
}

#[derive(Clone, Debug, Serialize, SerdeValue)]
#[serde(rename_all = "snake_case")]
pub enum Type {
    Access,
    Admin,
    Allowed,
    Change,
    Connection,
    Creation,
    Denied,
    End,
    Error,
    Group,
    Info,
    Installation,
    Protocol,
    Start,
    User,
}

impl SetTo<Kind> for Option<Event> {
    fn set(&mut self, kind: Kind) {
        let event = self.get_or_insert(Event::default());
        event.kind = Some(kind);
    }
}

impl SetTo<Category> for Option<Event> {
    fn set(&mut self, extra_category: Category) {
        let event = self.get_or_insert(Event::default());
        let category = event.category.get_or_insert(vec![]);
        category.push(extra_category);
    }
}

impl SetTo<Type> for Option<Event> {
    fn set(&mut self, extra_type: Type) {
        let event = self.get_or_insert(Event::default());
        let ty = event.ty.get_or_insert(vec![]);
        ty.push(extra_type);
    }
}

impl SetTo<Outcome> for Option<Event> {
    fn set(&mut self, outcome: Outcome) {
        let event = self.get_or_insert(Event::default());
        event.outcome = Some(outcome);
    }
}

pub type Reason = String;

impl SetTo<Reason> for Option<Event> {
    fn set(&mut self, reason: Reason) {
        let event = self.get_or_insert(Event::default());
        event.reason = Some(reason);
    }
}

impl SetTo<Duration> for Option<Event> {
    fn set(&mut self, duration: Duration) {
        let event = self.get_or_insert(Event::default());
        event.duration = Some(duration);
    }
}

#[derive(Clone, Debug)]
pub struct Timer {
    start: DateTime<Utc>,
    end: Option<DateTime<Utc>>,
}

impl Timer {
    pub fn start() -> Self {
        Self {
            start: Utc::now(),
            end: None,
        }
    }

    pub fn elapsed(&self) -> chrono::Duration {
        let end = match self.end {
            Some(end) => end,
            None => Utc::now(),
        };

        end - self.start
    }

    pub fn elapsed_nanos(&self) -> i64 {
        self.elapsed()
            .num_nanoseconds()
            .expect("should never overflow")
    }

    pub fn elapsed_secs(&self) -> f64 {
        self.elapsed_nanos() as f64 / 1e9
    }

    pub fn finish(&mut self) {
        self.end = Some(Utc::now())
    }
}

impl SetTo<&Timer> for Option<Event> {
    /// Set the event's start, end, and duration times from the Timer
    fn set(&mut self, timer: &Timer) {
        let event = self.get_or_insert(Event::default());

        let end = timer
            .end
            .expect("set() called on a timer that was not finished");

        // yyyy-MM-dd'T'HH:mm:ss.SSSZ
        // See https://www.elastic.co/guide/en/elasticsearch/reference/7.9/mapping-date-format.html#strict-date-time
        event.start = Some(timer.start.to_rfc3339_opts(SecondsFormat::Millis, true));
        event.end = Some(end.to_rfc3339_opts(SecondsFormat::Millis, true));
        event.duration = Some(timer.elapsed_nanos());
    }
}
