//! Utility to allow to upgrade governance in testnets running a mainnet backup.
//!
//! DEPRECATED: After the ongoing switch to using `ic-replay` to modify the
//! mainnet state in testnets this will be no longer needed.
use clap::Parser;
use ic_agent::{
    agent::http_transport::ReqwestHttpReplicaV2Transport, export::Principal, Agent, AgentError,
};
use ic_identity_hsm::HardwareIdentity;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_utils::call::AsyncCall;
use ic_utils::interfaces::{management_canister::builders::InstallMode, ManagementCanister};
use std::convert::TryFrom;
use std::path::Path;
use std::{
    fs::{metadata, File},
    io::Read,
    path::PathBuf,
};
use url::Url;

/// Command line options for the `governance_upgrader` utility.
#[derive(Parser)]
#[clap(version = "1.0")]
struct Opts {
    #[clap(long)]
    /// The URL of an NNS entry point. That is, the URL of any replica on the
    /// NNS subnet.
    nns_url: Url,

    /// The slot related to the HSM key that shall be used.
    #[clap(long = "slot")]
    hsm_slot: usize,

    /// The id of the key on the HSM that shall be used.
    #[clap(long = "key-id")]
    key_id: String,

    /// The PIN used to unlock the HSM.
    #[clap(long = "pin")]
    pin: String,

    /// The path to the pkcs11 .so file, the path below only works
    /// on macos. The path (at least on macos) can be found by
    /// running "pkcs11-tool --help" on the terminal.
    #[clap(long, default_value = "/Library/OpenSC/lib/opensc-pkcs11.so")]
    pkcs11_so_path: String,

    #[clap(long)]
    wasm: PathBuf,

    #[clap(long)]
    start_only: bool,
}

/// Main method for the `governance_upgrader` utility.
#[tokio::main]
async fn main() {
    let opts: Opts = Opts::parse();

    let path = Path::new(&opts.pkcs11_so_path);
    let pin = opts.pin.clone();
    let identity = HardwareIdentity::new(path, opts.hsm_slot, &opts.key_id, || Ok(pin)).unwrap();

    let agent = Agent::builder()
        .with_transport(ReqwestHttpReplicaV2Transport::create(opts.nns_url.to_string()).unwrap())
        .with_identity(identity)
        .build()
        .unwrap();
    agent
        .fetch_root_key()
        .await
        .expect("Couldn't fetch root key");
    let management_canister = ManagementCanister::create(&agent);

    let governance_canister_id =
        Principal::try_from(GOVERNANCE_CANISTER_ID.get().as_slice()).unwrap();

    if !opts.start_only {
        let wasm_bytes = read_file_fully(&opts.wasm);

        let _stopped: () = management_canister
            .stop_canister(&governance_canister_id)
            .call_and_wait(delay())
            .await
            .expect("canister stopping failed");

        let upgraded: Result<(), AgentError> = management_canister
            .install_code(&governance_canister_id, &wasm_bytes)
            .with_mode(InstallMode::Upgrade)
            .call_and_wait(delay())
            .await;

        eprintln!("The call to install_code returned: {:?}", upgraded);
    }

    let _started: () = management_canister
        .start_canister(&governance_canister_id)
        .call_and_wait(delay())
        .await
        .expect("canister starting failed");
}

/// Read a file fully into a vector.
fn read_file_fully(path: &Path) -> Vec<u8> {
    let mut f = File::open(path).unwrap_or_else(|_| panic!("Value file not found at: {:?}", path));
    let metadata = metadata(path).expect("Unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read_exact(&mut buffer)
        .unwrap_or_else(|_| panic!("Couldn't read the content of {:?}", path));
    buffer
}

/// Forces a call to wait before proceeding.
fn delay() -> garcon::Delay {
    garcon::Delay::builder()
        .throttle(std::time::Duration::from_millis(500))
        .timeout(std::time::Duration::from_secs(60 * 5))
        .build()
}
