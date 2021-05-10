use slog::{info, Logger};

/// Returns a `Future` that completes when the service should gracefully
/// shutdown. Completion happens if either of `SIGINT` or `SIGTERM` are
/// received.
pub async fn shutdown_signal(log: Logger) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sig_int =
        signal(SignalKind::interrupt()).expect("failed to install SIGINT signal handler");
    let mut sig_term =
        signal(SignalKind::terminate()).expect("failed to install SIGTERM signal handler");

    tokio::select! {
        _ = sig_int.recv() => {
            info!(log, "Caught SIGINT");
        }
        _ = sig_term.recv() => {
            info!(log, "Caught SIGTERM");
        }
    }
}
