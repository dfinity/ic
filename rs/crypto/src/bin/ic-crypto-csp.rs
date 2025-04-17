use clap::Parser;
use ic_adapter_metrics_server::start_metrics_grpc;
use ic_config::{Config, ConfigSource};
use ic_crypto_internal_logmon::metrics::CryptoMetrics;
use ic_http_endpoints_async_utils::incoming_from_nth_systemd_socket;
use ic_logger::{info, new_replica_logger_from_config};
use ic_metrics::MetricsRegistry;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;

// This corresponds to the name of the file where the sockets are defined, i.e.,
// ic-crypto-csp.socket
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
    #[clap(long = "replica-config-file")]
    config: PathBuf,
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .thread_name("Crypto_CSP_Thread".to_string())
        .enable_all()
        .build()
        .expect("should create tokio runtime");

    let opts = Opts::parse();
    let ic_config = get_ic_config(opts.config);

    let sks_dir = ic_config.crypto.crypto_root.as_path();

    ensure_n_named_systemd_sockets(2);
    let systemd_socket_listener = listener_from_first_systemd_socket(rt.handle().clone());

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
    let global_metrics = MetricsRegistry::global();
    let metrics = CryptoMetrics::new(Some(&global_metrics));

    // The file descriptors of the process are:
    //  - 0: stdin,
    //  - 1: stdout,
    //  - 2: stderr,
    //  - 3: the logic communication socket (handled by `listener_from_first_systemd_socket`)
    //  - 4: the metrics socket (handled by `incoming_from_nth_systemd_socket`)
    // The file descriptors from 3 onwards correspond to the order the sockets are described in
    // the systemd configuration file.
    // `incoming_from_nth_systemd_socket` starts from FD(3) if the passed `socket_num` is 1, and
    // for the case of the metrics socket, FD(4) corresponds to `socket_num` = 2.
    // The `incoming_from_nth_systemd_socket` function shall only be called once per socket.
    // Systemd Socket config: ic-crypto-csp.socket
    // Systemd Service config: ic-crypto-csp.service
    {
        const METRICS_SOCKET_NUM: i32 = 2;
        let _enter_guard = rt.handle().enter();
        let stream = unsafe { incoming_from_nth_systemd_socket(METRICS_SOCKET_NUM) };
        start_metrics_grpc(global_metrics, logger.clone(), stream);
    }

    rt.block_on(ic_crypto_internal_csp::run_csp_vault_server(
        sks_dir,
        systemd_socket_listener,
        logger,
        metrics,
    ));
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

fn listener_from_first_systemd_socket(
    rt_handle: tokio::runtime::Handle,
) -> tokio::net::UnixListener {
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

    let _enter_guard = rt_handle.enter();
    tokio::net::UnixListener::from_std(std_unix_listener)
        .expect("Failed to convert UnixListener into Tokio equivalent")
}
