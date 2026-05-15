use canister_test::{CanisterInstallMode, RemoteTestRuntime, Runtime, Wasm};
use clap::Parser;
use ic_base_types::PrincipalId;
use ic_canister_client::{Agent, HttpClientConfig, Sender};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use std::path::PathBuf;
use std::str::FromStr;
use url::Url;

#[derive(Debug, Parser)]
#[clap(
    name = "ic-canister-install",
    about = "Create a canister at a specified ID and install a WASM onto it.",
    version
)]
struct CliArgs {
    /// URL of the IC replica.
    #[clap(long)]
    url: Url,

    /// Canister ID to create (e.g. um5iw-rqaaa-aaaaq-qaaba-cai).
    #[clap(long)]
    canister_id: String,

    /// Path to the WASM (or .wasm.gz) file to install.
    #[clap(long)]
    wasm: PathBuf,

    /// Hex-encoded raw Candid init argument bytes. If omitted, an empty arg is used.
    #[clap(long)]
    init_arg_hex: Option<String>,

    /// If set, HTTP/2 is used. By default, HTTP/1.1 is used.
    #[clap(long)]
    http2_only: bool,
}

#[tokio::main]
async fn main() {
    let args = CliArgs::try_parse_from(std::env::args())
        .unwrap_or_else(|e| panic!("Illegal arguments: {e}"));

    let specified_id = PrincipalId::from_str(&args.canister_id)
        .unwrap_or_else(|e| panic!("Invalid canister ID '{}': {e}", args.canister_id));

    let init_arg: Vec<u8> = match &args.init_arg_hex {
        Some(hex) => hex::decode(hex)
            .unwrap_or_else(|e| panic!("Invalid --init-arg-hex (not valid hex): {e}")),
        None => vec![],
    };

    let agent = Agent::new_with_http_client_config(
        args.url.clone(),
        Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
        HttpClientConfig {
            http2_only: args.http2_only,
            ..HttpClientConfig::default()
        },
    );

    let runtime = Runtime::Remote(RemoteTestRuntime {
        agent,
        effective_canister_id: REGISTRY_CANISTER_ID.into(),
    });

    let mut canister = runtime
        .create_canister_at_id_max_cycles_with_retries(specified_id)
        .await
        .unwrap_or_else(|e| panic!("Failed to create canister {specified_id}: {e}"));

    let wasm = Wasm::from_file(&args.wasm);
    wasm.install_onto_canister(
        &mut canister,
        CanisterInstallMode::Install,
        Some(init_arg),
        None,
    )
    .await
    .unwrap_or_else(|e| panic!("Failed to install wasm onto {specified_id}: {e}"));

    eprintln!("Installed {} onto {specified_id}", args.wasm.display());
}
