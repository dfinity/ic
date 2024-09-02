use ic_types::xnet::{RejectSignal, StreamFlags, StreamHeader, StreamIndex};
use std::collections::VecDeque;

/// Builder for StreamHeader objects.  Allows for creation of a default struct
/// and subsequent population of fields with specified values.
#[derive(Default)]
pub struct StreamHeaderBuilder {
    begin: StreamIndex,
    end: StreamIndex,
    signals_end: StreamIndex,
    reject_signals: VecDeque<RejectSignal>,
    flags: StreamFlags,
}

impl StreamHeaderBuilder {
    /// Creates a new `StreamHeaderBuilder`.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the `begin` field.
    pub fn begin(mut self, begin: StreamIndex) -> Self {
        self.begin = begin;
        self
    }

    /// Sets the `end` field.
    pub fn end(mut self, end: StreamIndex) -> Self {
        self.end = end;
        self
    }

    /// Sets the `signals_end` field.
    pub fn signals_end(mut self, signals_end: StreamIndex) -> Self {
        self.signals_end = signals_end;
        self
    }

    /// Sets the `reject_signals` field.
    pub fn reject_signals(mut self, reject_signals: VecDeque<RejectSignal>) -> Self {
        self.reject_signals = reject_signals;
        self
    }

    /// Sets the `flags` field.
    pub fn flags(mut self, flags: StreamFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Returns the built `StreamHeader`.
    pub fn build(self) -> StreamHeader {
        StreamHeader::new(
            self.begin,
            self.end,
            self.signals_end,
            self.reject_signals,
            self.flags,
        )
    }
}
