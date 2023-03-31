pub trait Environment {
    // Returns the current time in seconds.
    fn now_timestamp_seconds(&self) -> u64;

    // Sets the certified data.
    fn set_certified_data(&self, data: &[u8]);
}
