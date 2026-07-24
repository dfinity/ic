use ic_management_canister_types_private::{CanisterLogRecord, FetchCanisterLogsFilter};

/// Serialized log record stored in the data region.
///
/// Unlike `CanisterLogRecord`, it stores the content length explicitly
/// to enable serialization and deserialization of content.
#[derive(Clone, PartialEq, Debug)]
pub(super) struct LogRecord {
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
        Self::estimate_bytes_len(self.len as usize)
    }

    pub const fn estimate_bytes_len(content_len: usize) -> usize {
        8 + 8 + 4 + content_len
    }

    pub fn matches(&self, filter: &FetchCanisterLogsFilter) -> bool {
        match filter {
            FetchCanisterLogsFilter::ByIdx(r) => r.start <= self.idx && self.idx < r.end,
            FetchCanisterLogsFilter::ByTimestampNanos(r) => {
                r.start <= self.timestamp && self.timestamp < r.end
            }
        }
    }

    /// Returns `true` if this record's filter key is at or beyond the filter
    /// range's (exclusive) end, i.e. the record lies past the requested range.
    ///
    /// Records are scanned in ascending key order (both `idx` and `timestamp`
    /// are expected to be non-decreasing with insertion order), so once a scan reaches a
    /// record for which this holds, no later record can match the filter and the
    /// scan can stop — even if it has not matched anything yet (e.g. a range that
    /// lies entirely below the live records).
    pub fn is_past_range_end(&self, filter: &FetchCanisterLogsFilter) -> bool {
        match filter {
            FetchCanisterLogsFilter::ByIdx(r) => self.idx >= r.end,
            FetchCanisterLogsFilter::ByTimestampNanos(r) => self.timestamp >= r.end,
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
