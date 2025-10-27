#![allow(deprecated)]
use by_address::ByAddress;
use ic_canister_log::{GlobalBuffer, LogBuffer, LogEntry};
use ic_cdk::api::management_canister::http_request::{
    CanisterHttpRequestArgument, HttpHeader, HttpResponse,
};
use ic_metrics_encoder::MetricsEncoder;
use maplit::hashmap;
use priority_queue::PriorityQueue;
use std::{
    cmp::Reverse,
    collections::HashMap,
    fmt,
    fmt::{Debug, Display, Formatter},
    mem::size_of,
    str::FromStr,
};

// 1 Mi. Approximately 10^6, 1 million (slightly more).
const MAX_LOGS_RESPONSE_SIZE: usize = 1 << 20;

/// Transforms an `ic_metrics_encoder::MetricsEncoder` into an HttpResponse that can be
/// served via a Canister's `http_request` query method.
///
/// ```
/// use ic_canister_serve::serve_metrics;
/// use ic_cdk::api::management_canister::http_request::{CanisterHttpRequestArgument, HttpResponse};
/// use ic_metrics_encoder::MetricsEncoder;
///
/// fn encode_metrics(w: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
///     w.encode_gauge("example_metric_name", 0 as f64, "Example metric description")?;
///     Ok(())
/// }
///
/// #[ic_cdk::query]
/// fn http_request(request: CanisterHttpRequestArgument) -> HttpResponse {
///     let path = match request.url.find('?') {
///         None => &request.url[..],
///         Some(index) => &request.url[..index],
///     };
///
///     match path {
///         "/metrics" => serve_metrics(encode_metrics),
///         _ => HttpResponse {
///                 status: 404_u32.into(),
///                 body: "not_found".into(),
///                 ..Default::default()
///             }
///     }
/// }
/// ```
pub fn serve_metrics(
    encode_metrics: impl FnOnce(&mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()>,
) -> HttpResponse {
    let mut writer = MetricsEncoder::new(vec![], now() as i64 / 1_000_000);

    match encode_metrics(&mut writer) {
        Ok(()) => {
            let content_body: Vec<u8> = writer.into_inner();
            HttpResponse {
                status: 200_u8.into(),
                headers: vec![
                    HttpHeader {
                        name: "Content-Type".to_string(),
                        value: "text/plain; version=0.0.4".to_string(),
                    },
                    HttpHeader {
                        name: "Content-Length".to_string(),
                        value: content_body.len().to_string(),
                    },
                    HttpHeader {
                        name: "Cache-Control".to_string(),
                        value: "no-store".to_string(),
                    },
                ],
                body: content_body,
            }
        }
        Err(err) => HttpResponse {
            status: 500_u16.into(),
            headers: vec![],
            body: format!("Failed to encode metrics: {err}").into(),
        },
    }
}

/// Given an INFO and ERROR `GlobalBuffer`, render the buffers into a json encoded body of an
/// HttpResponse that can be served via a Canister's `http_request` query method. The method's
/// `CanisterHttpRequestArgument` allows selecting the logs based on severity (INFO/ERROR) and
/// timestamp.
///
/// ```
/// use ic_canister_log::{declare_log_buffer, export, log};
/// use ic_canister_serve::serve_logs;
/// use ic_cdk::api::management_canister::http_request::{CanisterHttpRequestArgument, HttpResponse};
///
/// declare_log_buffer!(name = INFO, capacity = 100);
/// declare_log_buffer!(name = ERROR, capacity = 100);
///
/// #[ic_cdk::query]
/// fn http_request(request: CanisterHttpRequestArgument) -> HttpResponse {
///     log!(INFO, "This is an INFO log");
///     log!(ERROR, "This is an ERROR log");
///
///     let path = match request.url.find('?') {
///         None => &request.url[..],
///         Some(index) => &request.url[..index],
///     };
///
///     match path {
///         "/logs" => serve_logs(request, &INFO, &ERROR),
///         _ => HttpResponse {
///                 status: 404_u32.into(),
///                 body: "not_found".into(),
///                 ..Default::default()
///             }
///     }
/// }
/// ```
pub fn serve_logs(
    request: CanisterHttpRequestArgument,
    info_logs: &'static GlobalBuffer,
    error_logs: &'static GlobalBuffer,
) -> HttpResponse {
    // Convert from generic HTTP request to LogsRequest.
    let request = match LogsRequest::try_from(request) {
        Ok(request) => request,
        Err(message) => {
            let content_body = serde_json::to_string(&hashmap! {"error_description" => message})
                .unwrap_or_default()
                .into_bytes();

            return HttpResponse {
                status: 400_u16.into(),
                headers: vec![
                    HttpHeader {
                        name: "Content-Type".to_string(),
                        value: "application/json".to_string(),
                    },
                    HttpHeader {
                        name: "Content-Length".to_string(),
                        value: content_body.len().to_string(),
                    },
                ],
                body: content_body,
            };
        }
    };

    let body = info_logs.with(|info_logs| {
        let info_logs = info_logs.borrow();
        error_logs.with(|error_logs| {
            let error_logs = error_logs.borrow();

            request.render_json(&info_logs, &error_logs)
        })
    });

    let content_body: Vec<u8> = body.into_bytes();
    HttpResponse {
        status: 200_u8.into(),
        headers: vec![
            HttpHeader {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            },
            HttpHeader {
                name: "Content-Length".to_string(),
                value: content_body.len().to_string(),
            },
        ],
        body: content_body,
    }
}

/// Fields are query parameters. See serve_logs.
///
/// This does two main things:
///
/// 1. Tries to convert from a generic CanisterHttpRequestArgument
///    (via impl From<CanisterHttpRequestArgument>).
///
///2. Renders JSON (via LogsRequest::render_json). Of course, this needs to
///   be fed logs.
struct LogsRequest {
    severity: LogSeverity,
    time: u64,
}

impl LogsRequest {
    /// Returns JSON serialized response body, based on parameters in self.
    ///
    /// This is not entirely straightforward because this needs to do two
    /// things
    ///
    /// a. Merge INFO and ERROR logs (in the future, adding more severity levels
    ///    is would be pretty straightforward).
    ///
    /// b. Implement the filtering specified by the query parameters.
    fn render_json(&self, info_logs: &LogBuffer, error_logs: &LogBuffer) -> String {
        let mut info_logs = LogIter::new(LogSeverity::Info, self.skip_old_log_entries(info_logs));
        let mut error_logs =
            LogIter::new(LogSeverity::Error, self.skip_old_log_entries(error_logs));

        // Select sources. They will be merged later.
        // Prioritize them by the timestamp of their first element.
        let mut sources = PriorityQueue::new();
        {
            let info_priority = info_logs.priority();
            let error_priority = error_logs.priority();
            match self.severity {
                LogSeverity::Info => {
                    sources.push(ByAddress(&mut info_logs), info_priority);
                    sources.push(ByAddress(&mut error_logs), error_priority);
                }
                LogSeverity::Error => {
                    sources.push(ByAddress(&mut error_logs), error_priority);
                }
            }
        }

        // Merge sources by timestamp.
        let mut approximate_total_size = 0;
        let mut interleaved_logs = vec![];
        loop {
            // PriorityQueue::pop removes the element with the highest priority.
            // We prioritize by Reverse(first_log_entry.timestamp). See
            // LogIter::priority. Therefore, this should be an Iterator with the
            // earliest first LogEntry.
            let mut log_iter = match sources.pop() {
                None => break, // No more sources.
                Some((log_iter, _priority)) => log_iter,
            };

            let log_entry = match log_iter.next() {
                Some(log_entry) => log_entry,
                None => continue,
            };

            let enhanced_log_entry = EnhancedLogEntry::new(log_iter.severity, log_entry);
            approximate_total_size += enhanced_log_entry.approximate_size();
            if approximate_total_size > MAX_LOGS_RESPONSE_SIZE {
                break;
            }
            interleaved_logs.push(enhanced_log_entry);

            if log_iter.head.is_some() {
                // This guard is a minor optimization, because earlier in this
                // loop continue handles log_iter being empty.
                let priority = log_iter.priority();
                sources.push(log_iter, priority);
            }
        }

        serde_json::json!({
            "entries": interleaved_logs,
        })
        .to_string()
    }

    fn skip_old_log_entries<'a>(
        &self,
        log_buffer: &'a LogBuffer,
    ) -> impl Iterator<Item = &'a LogEntry> + use<'a> {
        let max_skip_timestamp = self.time;
        log_buffer
            .entries_partition_point(move |log_entry| log_entry.timestamp <= max_skip_timestamp)
    }
}

impl TryFrom<CanisterHttpRequestArgument> for LogsRequest {
    type Error = String;

    fn try_from(
        http_request: CanisterHttpRequestArgument,
    ) -> Result<Self, /* description */ String> {
        // Parse query parameters.
        let query = query_parameters_map(&http_request.url);

        let severity = query
            .get("severity")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "Info".to_string());
        let time = query
            .get("time")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string());

        let mut defects = vec![];

        let severity = match LogSeverity::from_str(&severity) {
            Ok(severity) => severity,
            Err(err) => {
                defects.push(format!(
                    "Invalid value for query parameter `severity` ({severity}): {err}",
                ));
                // Dummy value; won't actually be used, because defects is now nonempty.
                LogSeverity::Info
            }
        };

        let time = match u64::from_str(&time) {
            Ok(time) => time,
            Err(err) => {
                defects.push(format!(
                    "Invalid value for query parameter `time` ({time}): {err}",
                ));
                // Dummy value; won't actually be used, because defects is now nonempty.
                0
            }
        };

        if !defects.is_empty() {
            return Err(format!(
                "Invalid request for the following reason(s):\n  -{}",
                defects.join("\n  -"),
            ));
        }

        Ok(Self { severity, time })
    }
}

/// The "right" way to implement this is to use the url crate, but that causes
/// our WASMs to be inordinately larger.
fn query_parameters_map(url: &str) -> HashMap<String, String> {
    const QUERY_SEPARATOR: &str = "?";
    let mut it = url.split(QUERY_SEPARATOR);
    let _skip = it.next();
    let query_string = it.next().unwrap_or_default();

    let mut result = HashMap::new();
    if query_string.is_empty() {
        return result;
    }

    const PARAMETER_SEPARATOR: &str = "&";
    for chunk in query_string.split(PARAMETER_SEPARATOR) {
        const KEY_VALUE_SEPARATOR: &str = "=";
        let mut split = chunk.splitn(2, KEY_VALUE_SEPARATOR);
        let name = split
            .next()
            .expect("Unable to get head of split (this should be impossible).");
        let value = split.next().unwrap_or_default();
        result.insert(name.to_string(), value.to_string());
    }

    result
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug, serde::Serialize)]
enum LogSeverity {
    Info,
    Error,
}

impl FromStr for LogSeverity {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, /* description */ String> {
        let severity = match name {
            "Info" => Self::Info,
            "Error" => Self::Error,
            _ => return Err(format!("Unknown log severity name: {name}")),
        };

        Ok(severity)
    }
}

impl Display for LogSeverity {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let s = match self {
            Self::Info => "Info",
            Self::Error => "Error",
        };

        write!(formatter, "{s}")
    }
}

struct LogIter<'a, I>
where
    I: Iterator<Item = &'a LogEntry>,
{
    severity: LogSeverity,
    head: Option<&'a LogEntry>,
    tail: I,
}

impl<'a, I> LogIter<'a, I>
where
    I: Iterator<Item = &'a LogEntry>,
{
    fn new(severity: LogSeverity, mut tail: I) -> Self {
        let head = tail.next();
        Self {
            severity,
            head,
            tail,
        }
    }

    /// Based on the timestamp of the head log entry; earlier entries have
    /// higher priority.
    fn priority(&self) -> impl Ord + Debug + use<I> {
        Reverse(
            self.head
                .map(|log_entry| log_entry.timestamp)
                .unwrap_or_default(),
        )
    }
}

impl<'a, I> Iterator for LogIter<'a, I>
where
    I: Iterator<Item = &'a LogEntry>,
{
    type Item = &'a LogEntry;

    fn next(&mut self) -> Option<&'a LogEntry> {
        let result = self.head;
        self.head = self.tail.next();
        result
    }
}

impl<'a, I> Debug for LogIter<'a, I>
where
    I: Iterator<Item = &'a LogEntry>,
{
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter
            .debug_struct("LogIter")
            .field("severity", &self.severity)
            .field("head", &self.head)
            .field("tail", &"...")
            .finish()
    }
}

/// Like LogEntry, but with severity.
#[derive(serde::Serialize)]
struct EnhancedLogEntry<'a> {
    severity: LogSeverity,
    timestamp: u64,
    file: &'static str,
    line: u32,
    message: &'a String,
}

impl<'a> EnhancedLogEntry<'a> {
    fn new(severity: LogSeverity, log_entry: &'a LogEntry) -> Self {
        // If the definition of LogEntry is ever changed, this will need to be
        // updated.
        let LogEntry {
            timestamp,
            file,
            line,
            message,
            ..
        } = log_entry;

        let timestamp = *timestamp;
        let line = *line;

        Self {
            severity,
            timestamp,
            file,
            line,
            message,
        }
    }

    fn approximate_size(&self) -> usize {
        let min = size_of::<LogSeverity>() // severity
            + size_of::<u64>() // timestamp
            + self.file.len()
            + size_of::<u32>() // line
            + self.message.len();

        // 1.33x factor of safety, because JSON serialization has some overhead
        // (because of quotes, spaces, colons, etc.).
        min * 4 / 3
    }
}

mod private {
    #[cfg(target_arch = "wasm32")]
    pub fn timestamp() -> u64 {
        ic_cdk::api::time()
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn timestamp() -> u64 {
        use std::time::SystemTime;

        match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => d.as_nanos() as u64,
            Err(_) => panic!("SystemTime before UNIX EPOCH!"),
        }
    }
}

/// Returns the current time as a number of nanoseconds passed since the Unix
/// epoch.
#[doc(hidden)]
pub fn now() -> u64 {
    private::timestamp()
}
