use ic_management_canister_types_private::FetchCanisterLogsFilter;

/// Represents a single log record stored in the data region.
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

/*
bazel test //rs/replicated_state:replicated_state_test \
  --test_output=streamed \
  --test_arg=--nocapture \
  --test_arg=test_log_record_serialized_size
*/
