use ic_types::xnet::{StreamHeader, StreamIndex};
use std::collections::VecDeque;

/// Builder for StreamHeader objects.  Allows for creation of a default struct
/// and subsequent population of fields with specified values.
pub struct StreamHeaderBuilder(StreamHeader);

impl Default for StreamHeaderBuilder {
    /// Creates a dummy StreamHeader with default values.
    fn default() -> Self {
        Self(StreamHeader {
            begin: StreamIndex::from(0),
            end: StreamIndex::from(0),
            signals_end: StreamIndex::from(0),
            reject_signals: VecDeque::default(),
        })
    }
}

impl StreamHeaderBuilder {
    /// Creates a new `StreamHeaderBuilder`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the `begin` field.
    pub fn begin(mut self, begin: StreamIndex) -> Self {
        self.0.begin = begin;
        self
    }

    /// Sets the `end` field.
    pub fn end(mut self, end: StreamIndex) -> Self {
        self.0.end = end;
        self
    }

    /// Sets the `signals_end` field.
    pub fn signals_end(mut self, signals_end: StreamIndex) -> Self {
        self.0.signals_end = signals_end;
        self
    }

    /// Returns the built `StreamHeader`.
    pub fn build(self) -> StreamHeader {
        self.0
    }
}
