use vsock_lib::server::{LinuxVsockServer, VsockServer};

use tokio::select;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let vsock_server = LinuxVsockServer::with_port(LinuxVsockServer::DEFAULT_PORT)?;

    println!("Listening for vsock connection.\n");

    let cancellation_token = CancellationToken::new();
    let mut join_handle = tokio::spawn(vsock_server.listen(cancellation_token.clone()));

    let result = select! {
        () = shutdown_signal() => {
            println!("Shutting down VSOCK server...");
            cancellation_token.cancel();
            join_handle.await
        },
        result = &mut join_handle => result,
    };

    match result {
        Err(ref err) if err.is_panic() => {
            println!("VSOCK server panicked: '{err}'")
        }
        _ => {
            println!("VSOCK server shutdown gracefully")
        }
    }

    Ok(result?)
}

pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sig_int =
        signal(SignalKind::interrupt()).expect("failed to install SIGINT signal handler");
    let mut sig_term =
        signal(SignalKind::terminate()).expect("failed to install SIGTERM signal handler");

    tokio::select! {
        _ = sig_int.recv() => {
            println!("Caught SIGINT");
        }
        _ = sig_term.recv() => {
            println!("Caught SIGTERM");
        }
    }
}
