use std::io;

use chrono::{SecondsFormat, Utc};
use slog::{o, PushFnValue, Record};

use crate::log_fields::{Log, Origin, OriginFile};

/// slog::Drain for elastic common schema
///
/// Messages logged using this drain will automatically have the following
/// fields set:
///
/// - @timestamp
/// - message
/// - log { level: "...", origin: { file: "...", line: .. }}
///
///  Logging is delegated to `slog_json`.
pub struct Drain<W: io::Write> {
    json_drain: slog_json::Json<W>,
}

impl<W> Drain<W>
where
    W: io::Write,
{
    pub fn default(io: W, pretty: bool) -> Drain<W> {
        let builder = slog_json::Json::new(io).set_pretty(pretty);
        let json_drain = builder
            .add_key_value(o!(
                "@timestamp" => PushFnValue(move |_ : &Record, ser| {
                    ser.emit(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true))
                }),
                "message" => PushFnValue(move |record: &Record, ser| {
                    ser.emit(record.msg())
                }),
                "log" => PushFnValue(move |record: &Record, ser| {
                    let log = Log {
                        level: Some(record.level().to_string()),
                        origin: Some(Origin {
                            file: Some(OriginFile {
                                line: Some(record.line()),
                                name: Some(record.file().to_string())
                            }),
                            // When Rust compiler is updated to report function
                            // names and the slog version is updated to include
                            // them in the record this can change.
                            function: None,
                        }),
                        ..Default::default()
                    };

                    ser.emit(log)
                })
            ))
            .build();

        Self { json_drain }
    }
}

impl<W> slog::Drain for Drain<W>
where
    W: io::Write,
{
    type Ok = ();
    type Err = io::Error;

    fn log(
        &self,
        record: &slog::Record,
        values: &slog::OwnedKVList,
    ) -> Result<Self::Ok, Self::Err> {
        self.json_drain.log(record, values)
    }
}
