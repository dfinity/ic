use super::byte_rw::ByteWriter;

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
