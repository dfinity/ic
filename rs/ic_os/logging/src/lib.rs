use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize tracing, using journald if available and falling back to stderr.
pub fn init_logging() {
    match tracing_journald::layer() {
        Ok(layer) => tracing_subscriber::registry().with(layer).init(),
        Err(_) => tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .init(),
    }
}
