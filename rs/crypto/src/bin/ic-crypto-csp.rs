use clap::{Arg, Command};
use ic_config::{Config, ConfigSource};
use ic_logger::{info, new_replica_logger_from_config};
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;

const IC_CRYPTO_CSP_SOCKET_NAME: &str = "ic-crypto-csp.socket";

#[tokio::main]
async fn main() {
    let flags = Command::new("Remote CspVault server")
        .version("0.1")
        .author("Internet Computer Developers")
        .about(
            format!(
                "NOTE: This binary is intended to be started as socket-activated \
                systemd service with a single socket named {}",
                IC_CRYPTO_CSP_SOCKET_NAME
            )
            .as_str(),
        )
        .arg(
            Arg::new("replica-config-file")
                .long("replica-config-file")
                .value_name("STRING")
                .help("The path to the replica config file (ic.json5)")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    let replica_config_file_flag = flags.value_of("replica-config-file").unwrap();
    let ic_config = get_ic_config(PathBuf::from(replica_config_file_flag));

    let sks_dir = ic_config.crypto.crypto_root.as_path();

    ensure_single_named_systemd_socket(IC_CRYPTO_CSP_SOCKET_NAME);
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

    ic_crypto_internal_csp::run_csp_vault_server(sks_dir, systemd_socket_listener, logger).await;
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

fn ensure_single_named_systemd_socket(socket_name: &str) {
    const SYSTEMD_SOCKET_NAMES: &str = "LISTEN_FDNAMES"; // see https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html
    let systemd_socket_names =
        std::env::var(SYSTEMD_SOCKET_NAMES).expect("failed to read systemd socket names");
    if systemd_socket_names != socket_name {
        panic!(
            "Expected to receive a single systemd socket named '{}' but instead got '{}'",
            socket_name, systemd_socket_names
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
