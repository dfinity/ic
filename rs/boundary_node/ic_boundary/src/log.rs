use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Error;
use serde::ser::{SerializeMap, Serializer as _};
use serde_json::Serializer;
use std::os::unix::net::UnixDatagram;
use tracing::Level;
use tracing_serde::AsSerde;
use tracing_subscriber::{
    filter::LevelFilter,
    fmt::layer,
    layer::{Layer, SubscriberExt},
};

use crate::cli::Cli;

// 1k is an average request log message which is a vast majority of log entries
const LOG_ENTRY_SIZE: usize = 1024;
const JOURNALD_PATH: &str = "/run/systemd/journal/socket";

// Journald protocol helper functions, stolen from tracing-journald crate
fn put_value(buf: &mut Vec<u8>, value: &[u8]) {
    buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
    buf.extend_from_slice(value);
    buf.push(b'\n');
}

fn put_field_wellformed(buf: &mut Vec<u8>, name: &str, value: &[u8]) {
    buf.extend_from_slice(name.as_bytes());
    buf.push(b'\n');
    put_value(buf, value);
}

fn put_priority(buf: &mut Vec<u8>, meta: &tracing::Metadata) {
    put_field_wellformed(
        buf,
        "PRIORITY",
        match *meta.level() {
            Level::ERROR => b"3",
            Level::WARN => b"4",
            Level::INFO => b"5",
            Level::DEBUG => b"6",
            Level::TRACE => b"7",
        },
    );
}

// Prepare the JSON-serialized message from a tracing event
fn event_to_json(event: &tracing::Event) -> Result<Vec<u8>, Error> {
    let mut msg = Vec::with_capacity(LOG_ENTRY_SIZE);
    let mut ser = Serializer::new(&mut msg);
    let mut ser = ser.serialize_map(None)?;

    // Set level/timestamp
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ser.serialize_entry("timestamp", &timestamp)?;
    ser.serialize_entry("level", &event.metadata().level().as_serde())?;

    // Set other fields
    let mut visitor = tracing_serde::SerdeMapVisitor::new(ser);
    event.record(&mut visitor);
    ser = visitor.take_serializer()?;

    // Finish serializing
    ser.end()?;

    Ok(msg)
}

// tracing_subscriber Layer implementation that logs the events to Journald in JSON format
struct JournaldLayer {
    socket: UnixDatagram,
}

impl JournaldLayer {
    fn new() -> Result<Self, Error> {
        let socket = UnixDatagram::unbound()?;
        socket.connect(JOURNALD_PATH)?;
        // Ping journald to check the connection
        socket.send(&[])?;
        Ok(Self { socket })
    }
}

impl<S> tracing_subscriber::layer::Layer<S> for JournaldLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        // Do stuff in closure to simplify error handling
        let send = || -> Result<(), Error> {
            let msg = event_to_json(event)?;

            // Prepare the Journald packet that should fit the message
            // TODO optimize to a single allocation?
            let mut buf = Vec::with_capacity(LOG_ENTRY_SIZE + 64);
            put_priority(&mut buf, event.metadata());
            put_field_wellformed(&mut buf, "MESSAGE", &msg);

            // Send it
            self.socket.send(&buf)?;

            Ok(())
        };

        // We can't really handle any of the errors here, so ignore them
        let _ = send();
    }
}

// Sets up logging
pub fn setup_logging(cli: &Cli) -> Result<(), Error> {
    let level_filter = LevelFilter::from_level(cli.monitoring.max_logging_level);

    let subscriber = tracing_subscriber::registry::Registry::default()
        // Journald
        .with(cli.monitoring.log_journald.then(|| {
            JournaldLayer::new()
                .expect("failed to setup logging to journald")
                .with_filter(level_filter)
        }))
        // Stdout
        .with(
            cli.monitoring
                .log_stdout
                .then(|| layer().json().flatten_event(true).with_filter(level_filter)),
        )
        // Null
        .with(cli.monitoring.log_null.then(|| {
            layer()
                .with_writer(std::io::sink)
                .json()
                .flatten_event(true)
                .with_filter(level_filter)
        }));

    Ok(tracing::subscriber::set_global_default(subscriber)?)
}
