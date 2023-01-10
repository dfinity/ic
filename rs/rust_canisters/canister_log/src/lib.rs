use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::thread::LocalKey;

/// Declares a new canister log buffer.
#[macro_export]
macro_rules! declare_log_buffer {
    (name = $name:ident, capacity = $cap:expr) => {
        thread_local! {
            pub static $name: std::cell::RefCell<$crate::LogBuffer> =
                std::cell::RefCell::new($crate::LogBuffer::with_capacity($cap));
        }
    };
}

/// Adds a new record to a canister log buffer.
///
/// ```
/// use ic_canister_log::{declare_log_buffer, log};
///
/// // Keep up to 100 last messages.
/// declare_log_buffer!(name = LOG, capacity = 100);
///
/// fn sum_and_log(x: u64, y: u64) -> u64 {
///    let result = x.saturating_add(y);
///    log!(LOG, "{} + {} = {}", x, y, result);
///    result
/// }
/// ```
#[macro_export]
macro_rules! log {
    ($sink:expr, $message:expr $(,$args:expr)* $(,)*) => {{
        use $crate::Sink;
        (&$sink).append($crate::LogEntry {
            timestamp: $crate::now(),
            message: std::format!($message $(,$args)*),
            file: std::file!(),
            line: std::line!(),
        });
    }}
}

pub trait Sink {
    fn append(&self, entry: LogEntry);
}

/// An entry in the canister log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub timestamp: u64,
    pub message: String,
    pub file: &'static str,
    pub line: u32,
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}:{} {}",
            self.timestamp, self.file, self.line, self.message
        )
    }
}

#[derive(Clone)]
pub struct DevNull;

impl Sink for DevNull {
    fn append(&self, _: LogEntry) {}
}

/// A circular buffer for log messages.
pub struct LogBuffer {
    max_capacity: usize,
    entries: VecDeque<LogEntry>,
}

impl LogBuffer {
    /// Creates a new buffer of the specified max capacity.
    pub fn with_capacity(max_capacity: usize) -> Self {
        Self {
            max_capacity,
            entries: VecDeque::with_capacity(max_capacity),
        }
    }

    /// Adds a new entry to the buffer, potentially evicting older entries.
    pub fn append(&mut self, entry: LogEntry) {
        if self.entries.len() >= self.max_capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);
    }

    /// Returns an iterator over entries in the order of their insertion.
    pub fn iter(&self) -> impl Iterator<Item = &LogEntry> {
        self.entries.iter()
    }
}

pub type GlobalBuffer = LocalKey<RefCell<LogBuffer>>;

impl Sink for &'static GlobalBuffer {
    fn append(&self, entry: LogEntry) {
        self.with(|cell| cell.borrow_mut().append(entry))
    }
}

mod private {
    #[cfg(target_arch = "wasm32")]
    #[link(wasm_import_module = "ic0")]
    extern "C" {
        pub fn time() -> u64;
    }

    #[cfg(target_arch = "wasm32")]
    pub fn timestamp() -> u64 {
        unsafe { time() }
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

/// Exports the contents of a buffer as a vector of entries in the order of
/// insertion.
///
/// ```
/// use ic_canister_log::{declare_log_buffer, export, log};
///
/// // Keep up to 100 last messages.
/// declare_log_buffer!(name = LOG, capacity = 100);
///
/// log!(LOG, "Hello, {}!", "world");
/// let entries = export(&LOG);
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].message, "Hello, world!");
/// ```

pub fn export(buf: &'static GlobalBuffer) -> Vec<LogEntry> {
    buf.with(|cell| cell.borrow().iter().cloned().collect())
}
