mod hyper;
mod join_map;
mod unix;

use ic_logger::{ReplicaLogger, info};

pub use self::{
    hyper::ExecuteOnTokioRuntime,
    join_map::JoinMap,
    unix::{incoming_from_nth_systemd_socket, incoming_from_path},
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
pub async fn shutdown_signal(log: ReplicaLogger) {
    use tokio::signal::unix::{SignalKind, signal};
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

/// Recommended way of starting a TCP listener given a socket addr. The function
/// will panic if it cannot start the listener, because the OS error can't be
/// handled by the caller.
pub fn start_tcp_listener(
    local_addr: std::net::SocketAddr,
    runtime_handle: &tokio::runtime::Handle,
) -> tokio::net::TcpListener {
    let _enter = runtime_handle.enter();
    let err_msg = format!("Could not start TCP listener at addr = {local_addr}");
    let socket = if local_addr.is_ipv6() {
        tokio::net::TcpSocket::new_v6().expect(&err_msg)
    } else {
        tokio::net::TcpSocket::new_v4().expect(&err_msg)
    };
    socket.set_reuseaddr(true).expect(&err_msg);
    socket.set_reuseport(true).expect(&err_msg);
    socket.bind(local_addr).expect(&err_msg);
    socket.listen(128).expect(&err_msg)
}
