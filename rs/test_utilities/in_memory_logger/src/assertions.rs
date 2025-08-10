//! Fluent assertions for log entries.

use ic_protobuf::log::log_entry::v1::LogEntry;
use slog::Level;

pub struct LogEntriesAssert {
    actual: Vec<LogEntry>,
}

impl LogEntriesAssert {
    pub fn assert_that(actual: Vec<LogEntry>) -> Self {
        Self { actual }
    }

    pub fn has_len(&self, expected_length: usize) -> &Self {
        assert_eq!(
            self.actual.len(),
            expected_length,
            "expected length {}, but got {}",
            expected_length,
            self.actual.len()
        );
        self
    }

    pub fn has_only_one_message_containing(
        &self,
        level: &Level,
        expected_substring: &str,
    ) -> &Self {
        self.has_exactly_n_messages_containing(1, level, expected_substring)
    }

    pub fn has_exactly_n_messages_containing(
        &self,
        expected_number_of_times: usize,
        level: &Level,
        expected_substring: &str,
    ) -> &Self {
        self.has_exactly_n_elements_satisfying(
            expected_number_of_times,
            |entry| entry.level == level.as_str() && entry.message.contains(expected_substring),
            &format!("searching for '{}: {}'", level.as_str(), expected_substring),
        )
    }

    fn has_exactly_n_elements_satisfying<P>(
        &self,
        expected_number_of_times: usize,
        predicate: P,
        explain_predicate: &str,
    ) -> &Self
    where
        P: Fn(&LogEntry) -> bool,
    {
        let satisfying_entries: Vec<_> = self
            .actual
            .iter()
            .filter(|entry| predicate(entry))
            .collect();
        assert_eq!(
            satisfying_entries.len(),
            expected_number_of_times,
            "Expecting exactly {} element(s) to satisfy condition: {}, but got {}.\n\
            Satisfying elements (if any): {:?}.\n\
            Elements searched: {:?}",
            expected_number_of_times,
            explain_predicate,
            satisfying_entries.len(),
            satisfying_entries,
            self.actual
        );
        self
    }
}
