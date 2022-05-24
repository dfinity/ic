use slog::{info, Logger};

mod http;
mod hyper;
mod observable_counting_semaphore;
mod unix;

pub use self::{
    http::{receive_body, receive_body_without_timeout, BodyReceiveError},
    hyper::ExecuteOnTokioRuntime,
    observable_counting_semaphore::*,
    unix::{ensure_single_systemd_socket, incoming_from_first_systemd_socket, incoming_from_path},
};

/// Aborts the whole program with a core dump if a single thread panics.
pub fn abort_on_panic() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        default_hook(panic_info);
        std::process::abort();
    }));
}

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
