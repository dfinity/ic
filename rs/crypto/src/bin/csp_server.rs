use clap::{App, Arg};
use std::path::Path;

#[tokio::main]
async fn main() {
    let flags = App::new("Remote CspVault server")
        .version("0.1")
        .author("Internet Computer Developers")
        .about("Crypto Service Provider")
        .arg(
            Arg::with_name("socket-path")
                .long("socket-path")
                .value_name("STRING")
                .help("Sets the Unix socket to listen on")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sks-dir")
                .long("sks-dir")
                .value_name("STRING")
                .help("Sets the directory which holds secret key store data.")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    let socket_path = flags.value_of("socket-path").unwrap();
    let sks_dir = flags.value_of("sks-dir").unwrap();
    println!(
        "Starting CspVault server listening at socket {}, with SKS-data in {} ...",
        socket_path, sks_dir
    );
    ic_crypto_internal_csp::run_csp_vault_server(Path::new(sks_dir), Path::new(socket_path)).await;
}
