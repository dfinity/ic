use clap::{App, Arg};
use ic_config::{Config, ConfigSource};
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;

const IC_CRYPTO_CSP_SOCKET_NAME: &str = "ic-crypto-csp.socket";

#[tokio::main]
async fn main() {
    let flags = App::new("Remote CspVault server")
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
            Arg::with_name("replica-config-file")
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

    //////////////////////////////////////////////////////////////////////////////
    // TODO: decide if this sanity check is kept or name is even made configurable
    ensure_single_named_systemd_socket(IC_CRYPTO_CSP_SOCKET_NAME);
    //////////////////////////////////////////////////////////////////////////////
    let systemd_socket_listener = listener_from_first_systemd_socket();

    println!(
        "Starting CspVault server listening at systemd socket '{:?}', with SKS-data in '{}' ...",
        systemd_socket_listener
            .local_addr()
            .expect("failed to get local socket address"),
        sks_dir.display()
    );
    ic_crypto_internal_csp::run_csp_vault_server(sks_dir, systemd_socket_listener).await;
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
