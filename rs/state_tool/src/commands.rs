//! Command implementations.
pub mod cdiff;
pub mod chash;
pub mod convert_ids;
pub mod copy;
pub mod decode;
pub mod import_state;
pub mod list;
pub mod manifest;
pub mod parse_overlay;
pub mod split;
pub mod split_manifest;
mod utils;
pub mod verify_manifest;

/// Creates a logger that writes directly to `stderr`.
fn logger() -> ic_logger::ReplicaLogger {
    use slog::{Drain, slog_o};

    let plain = slog_term::PlainSyncDecorator::new(std::io::stderr());
    slog::Logger::root(
        slog_term::FullFormat::new(plain)
            .build()
            .filter_level(slog::Level::Debug)
            .fuse(),
        slog_o!(),
    )
    .into()
}
