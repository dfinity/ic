use ic_protobuf::log::log_entry::v1::LogEntry;
use ic_types::{PrincipalId, PrincipalIdParseError};
use log_analyzer::*;
use std::str::FromStr;

/// The log_analyzer will enforce properties about 'LogEntryFrom',
/// which couples a LogEntry with the node that emmitted it.
#[derive(Debug)]
pub struct LogEntryFrom {
    from: PrincipalId,
    entry: LogEntry,
}

/// We can enforce a new expectation throughoit all runs of the test
/// framework by adding a property to the 'Analyzer' below.
pub fn analyzer() -> Analyzer<'static, LogEntryFrom> {
    Analyzer::new().add_property("Found ERROR", fml_is_never_error())
}

/// Forbids log messages with 'error' level.
pub fn fml_is_never_error() -> Formula<'static, LogEntryFrom> {
    always(is(|lef: &LogEntryFrom| lef.entry.level != "ERROR"))
}

// From here onwards, its a bunch of auxiliary code that is uninteresting
// for most readers; parses LogEntryFrom and adds some tests for it.

#[derive(Debug)]
pub enum LogEntryFromParseError {
    OnEntry(serde_json::error::Error),
    OnPrincipalId(PrincipalIdParseError),
    NoColon,
}

// When logging on JSON format, the log entries are output in the
// following schema:
//
// > {"log_entry":
// >    {"level":"INFO"
// >    ,"utc_time":"2020-12-04T09:08:39.364Z"
// >    ,"message": "Downloading release package for replica version 0.1.0"
// >    ,...
// >    }
// > }
//
// However, trying to 'Deserialize' the entry above crashes with "no such field
// 'level'", thats because the deserialization expects:
//
// > {"level":"INFO"
// > ,"utc_time":"2020-12-04T09:08:39.364Z"
// > ,"message": "Downloading release package for replica version 0.1.0"
// > ,...
// > }
#[derive(serde::Deserialize)]
struct LogEntryLine {
    log_entry: LogEntry,
}

impl FromStr for LogEntryFrom {
    type Err = LogEntryFromParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let colon = s.find(':').ok_or(LogEntryFromParseError::NoColon)?;
        let s_id = &s[0..colon];
        let s_entry = &s[colon + 1..];

        let from = PrincipalId::from_str(s_id).map_err(LogEntryFromParseError::OnPrincipalId)?;
        let entry = serde_json::from_str::<LogEntryLine>(s_entry)
            .map_err(LogEntryFromParseError::OnEntry)?;
        Ok(LogEntryFrom {
            from,
            entry: entry.log_entry,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ignore]
    #[test]
    fn log_entries_from_from_str() {
        let log_entries = vec![
            r#"3dwph-vnvnt-nvv7a-jncv5-pw3qa-dylnr-mxi4r-2siya-w7y74-c7euw-hae: {"log_entry":{"level":"INFO","utc_time":"2020-12-04T09:08:39.364Z","message": "Downloading release package for replica version 0.1.0","crate_":"nodemanager","module":"release_package_provider","line": 77,"node_id":"","subnet_id":""}}"#,
            r#"wusdn-izour-pkw35-6ggkr-n6e45-or4s7-lrljo-apfsq-go4lp-fuzgs-jqe: {"log_entry":{"level":"WARN","utc_time":"2020-12-07T09:17:57.703Z","message":"starvation detected: BlockMaker has not been invoked for 1.981353401s","crate_":"ic_consensus","module":"orchestrator","line":508,"node_id":"wusdn-izour-pkw35-6ggkr-n6e45-or4s7-lrljo-apfsq-go4lp-fuzgs-jqe","subnet_id":"sj7au-m2b4v-wgg7f-ww7e6-hmpig-gtrju-xuypk-5efbc-xjxgx-nqgbh-7qe"}}"#,
            r#"qzizc-qsr7c-naqad-nfx26-r5u4i-c5sva-7wuej-x323w-e5inz-46tgw-rqe: {"log_entry":{"level":"WARN","utc_time":"2020-12-07T09:17:56.220Z","message":"Could not perform query on canister: IC0301: Canister rwlgt-iiaaa-aaaaa-aaaaa-cai not found","crate_":"ic_http_handler","module":"read","line":261,"node_id":"qzizc-qsr7c-naqad-nfx26-r5u4i-c5sva-7wuej-x323w-e5inz-46tgw-rqe","subnet_id":"sj7au-m2b4v-wgg7f-ww7e6-hmpig-gtrju-xuypk-5efbc-xjxgx-nqgbh-7qe"}}"#,
            r#"iosfi-paqab-t2kqj-3ymjk-n7hgf-5reii-tkbjd-gtc3s-iqqys-xcxip-kqe: {"log_entry":{"level":"INFO","utc_time":"2020-12-07T09:40:07.538Z","message":"No local release package detected for version 0.1.0","crate_":"nodemanager","module":"node_manager","line":236,"node_id":"","subnet_id":""}}"#,
        ];

        assert!(!log_entries
            .into_iter()
            .map(|e| LogEntryFrom::from_str(e))
            .any(|r| r.is_err()));
    }
}
