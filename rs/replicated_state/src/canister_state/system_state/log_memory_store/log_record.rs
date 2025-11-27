use ic_management_canister_types_private::{CanisterLogRecord, FetchCanisterLogsFilter};

/// Serialized log record stored in the data region.
///
/// Unlike `CanisterLogRecord`, it stores the content length explicitly
/// to enable serialization and deserialization of content.
#[derive(Debug, Clone, PartialEq)]
pub struct LogRecord {
    pub idx: u64,
    pub timestamp: u64,
    pub len: u32,
    pub content: Vec<u8>,
}

impl LogRecord {
    pub fn bytes_len(&self) -> usize {
        // IMPORTANT: do not check the content length here, as we can only
        // read the record header without loading the full content,
        // but still need to know the full size of the record.
        8 + 8 + 4 + self.len as usize
    }

    pub fn matches(&self, filter: &FetchCanisterLogsFilter) -> bool {
        match filter {
            FetchCanisterLogsFilter::ByIdx(r) => r.start <= self.idx && self.idx < r.end,
            FetchCanisterLogsFilter::ByTimestampNanos(r) => {
                r.start <= self.timestamp && self.timestamp < r.end
            }
        }
    }
}

impl From<CanisterLogRecord> for LogRecord {
    fn from(record: CanisterLogRecord) -> Self {
        LogRecord {
            idx: record.idx,
            timestamp: record.timestamp_nanos,
            len: record.content.len() as u32,
            content: record.content,
        }
    }
}

impl From<LogRecord> for CanisterLogRecord {
    fn from(record: LogRecord) -> Self {
        CanisterLogRecord {
            idx: record.idx,
            timestamp_nanos: record.timestamp,
            content: record.content,
        }
    }
}
