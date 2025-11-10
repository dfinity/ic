use super::byte_rw::ByteWriter;
use ic_management_canister_types_private::{CanisterLogRecord, FetchCanisterLogsFilter};

#[derive(Debug, PartialEq)]
pub(crate) struct LogRecord {
    pub idx: u64,
    pub ts_nanos: u64,
    pub len: u32,
    pub content: Vec<u8>,
}

impl LogRecord {
    pub fn bytes_len(&self) -> usize {
        8 + 8 + 4 + self.content.len()
    }

    pub fn matches(&self, filter: &FetchCanisterLogsFilter) -> bool {
        let is_ok = |x: u64, start: u64, end: u64| start <= x && x < end; // [start, end)
        match filter {
            FetchCanisterLogsFilter::ByIdx(r) => is_ok(self.idx, r.start, r.end),
            FetchCanisterLogsFilter::ByTimestampNanos(r) => is_ok(self.ts_nanos, r.start, r.end),
        }
    }

    pub fn to_canister_log_record(&self) -> CanisterLogRecord {
        CanisterLogRecord {
            idx: self.idx,
            timestamp_nanos: self.ts_nanos,
            content: self.content.clone(),
        }
    }
}

impl From<&LogRecord> for Vec<u8> {
    fn from(record: &LogRecord) -> Self {
        let mut bytes = vec![0u8; record.bytes_len()];
        let mut writer = ByteWriter::new(&mut bytes);

        writer.write_u64(record.idx);
        writer.write_u64(record.ts_nanos);
        writer.write_u32(record.len);
        writer.write_bytes(&record.content);

        bytes
    }
}
