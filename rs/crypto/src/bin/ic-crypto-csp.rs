use clap::Parser;
use ic_config::{Config, ConfigSource};
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_logger::{info, new_replica_logger_from_config};
use ic_metrics::MetricsRegistry;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;

// This corresponds to the name of the file where the sockets are defined, i.e.,
// /ic-os/guestos/rootfs/etc/systemd/system/ic-crypto-csp.socket
const IC_CRYPTO_CSP_SOCKET_FILENAME: &str = "ic-crypto-csp.socket";

#[derive(Parser)]
#[clap(
    name = "Remote CspVault server",
    version = "0.1",
    author = "Internet Computer Developers",
    about = "NOTE: This binary is intended to be started as socket-activated \
               systemd service with a single socket named ic-crypto-csp.socket"
)]
struct Opts {
    /// Sets the replica configuration file
    #[clap(long = "replica-config-file", parse(from_os_str))]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    let opts = Opts::parse();
    let ic_config = get_ic_config(opts.config);

    let sks_dir = ic_config.crypto.crypto_root.as_path();

    ensure_n_named_systemd_sockets(2);
    let systemd_socket_listener = listener_from_first_systemd_socket();

    // The `AsyncGuard` must be kept in scope for asynchronously logged messages to appear in the logs.
    let (logger, _async_log_guard) = new_replica_logger_from_config(&ic_config.csp_vault_logger);

    info!(logger;
        crypto.method_name => "main",
        crypto.description => format!(
            "Starting CspVault server listening at systemd socket '{:?}', with SKS-data in '{}' ...",
            systemd_socket_listener.local_addr().expect("failed to get local socket address"),
            sks_dir.display()
        )
    );

    // We abort the whole program with a core dump if a single thread panics.
    // This way we can capture all the context if a critical error happens.
    abort_on_panic();
    let metrics = CryptoMetrics::new(Some(&MetricsRegistry::global()));
    ic_crypto_internal_csp::run_csp_vault_server(sks_dir, systemd_socket_listener, logger, metrics)
        .await;
}

/// Aborts the whole program with a core dump if a single thread panics.
pub fn abort_on_panic() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        default_hook(panic_info);
        std::process::abort();
    }));
}

fn get_ic_config(replica_config_file: PathBuf) -> Config {
    let tmpdir = tempfile::Builder::new()
        .prefix("ic_config")
        .tempdir()
        .expect("failed to create temporary directory for replica config")
        .path()
        .to_path_buf();

    Config::load_with_tmpdir(ConfigSource::File(replica_config_file), tmpdir)
}

fn ensure_n_named_systemd_sockets(num_expected_sockets: usize) {
    const SYSTEMD_SOCKET_NAMES: &str = "LISTEN_FDNAMES"; // see https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html
    let systemd_socket_names =
        std::env::var(SYSTEMD_SOCKET_NAMES).expect("failed to read systemd socket names");
    let num_sockets = systemd_socket_names
        .split(':')
        .map(|socket_name| {
            if IC_CRYPTO_CSP_SOCKET_FILENAME != socket_name {
                panic!(
                    "Expected to receive {} systemd socket(s) named '{}' but instead got '{}'",
                    num_expected_sockets, IC_CRYPTO_CSP_SOCKET_FILENAME, systemd_socket_names
                );
            }
        })
        .count();
    if num_sockets != num_expected_sockets {
        panic!(
            "Expected to receive {} systemd socket named '{}' but instead got {} ('{}')",
            num_expected_sockets, IC_CRYPTO_CSP_SOCKET_FILENAME, num_sockets, systemd_socket_names
        );
    }
}

fn listener_from_first_systemd_socket() -> tokio::net::UnixListener {
    const SD_LISTEN_FDS_START: i32 = 3; // see https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html

    let std_unix_listener = unsafe {
        // SAFETY: Primitives returned by `FromRawFd::from_raw_fd` have the contract
        // that they are the sole owner of the file descriptor they are wrapping.
        // Because no other function is calling `UnixListener::from_raw_fd` on
        // the first file descriptor provided by systemd, we consider this call safe.
        std::os::unix::net::UnixListener::from_raw_fd(SD_LISTEN_FDS_START)
    };

    // Set non-blocking mode as required by `tokio::net::UnixListener::from_std`.
    std_unix_listener
        .set_nonblocking(true)
        .expect("Failed to make listener non-blocking");

    tokio::net::UnixListener::from_std(std_unix_listener)
        .expect("Failed to convert UnixListener into Tokio equivalent")
}
