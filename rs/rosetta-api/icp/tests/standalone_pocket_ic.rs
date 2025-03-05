use pocket_ic::common::rest::SubnetId;
use pocket_ic::PocketIcBuilder;
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;
use tempfile::TempDir;

/// A place that you can download from or upload to using the `scp` command.
#[derive(Debug)]
struct ScpLocation {
    user: &'static str,
    host: &'static str,
    path: &'static str,
}

impl ScpLocation {
    pub fn to_argument(&self) -> String {
        let Self { user, host, path } = self;

        format!("{}@{}:{}", user, host, path)
    }
}

const NNS_STATE_SOURCE: ScpLocation = ScpLocation {
    user: "dev",
    host: "zh1-pyr07.zh1.dfinity.network",
    path: "/home/dev/nns_state.tar.zst",
};

fn main() {
    let nns_subnet_id: SubnetId = candid::Principal::from_text(
        "tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe",
    )
    .unwrap()
    .into();

    let state_dir = download_and_untar_golden_nns_state_or_panic(NNS_STATE_SOURCE, "nns_state");

    let mut pocket_ic = PocketIcBuilder::new()
        .with_nns_state(nns_subnet_id, state_dir.into_path())
        .build();
    // let mut pocket_ic = PocketIcBuilder::new().with_nns_subnet().build();
    let endpoint = pocket_ic.make_live(None);

    // let ledger_wasm = build_ledger_wasm();
    // let ledger_canister_id = Principal::from(LEDGER_CANISTER_ID);
    // let ledger_canister_id = pocket_ic
    //     .create_canister_with_id(None, None, ledger_canister_id)
    //     .expect("Unable to create the canister in which the Ledger would be installed");
    // pocket_ic.install_canister(
    //     ledger_canister_id,
    //     ledger_wasm.bytes(),
    //     Encode!(&LedgerCanisterInitPayload::builder()
    //         .minting_account(Principal::anonymous().into())
    //         .initial_values(
    //             [(
    //                 Principal::from_slice(&[1]).into(),
    //                 icp_ledger::Tokens::from_tokens(1_000_000_000).unwrap(),
    //             )]
    //             .into()
    //         )
    //         .build()
    //         .unwrap())
    //     .unwrap(),
    //     None,
    // );

    let port = endpoint.port().unwrap();
    let replica_url = format!("http://localhost:{}", port);
    println!("replica_url: {}", replica_url);
    sleep(Duration::from_secs(3600));
}

fn download_and_untar_golden_nns_state_or_panic(
    scp_location: ScpLocation,
    archive_state_dir_name: &str,
) -> TempDir {
    let download_destination = bazel_test_compatible_temp_dir_or_panic();
    let download_destination = download_destination
        .path()
        .join(format!("{}.tar.zst", archive_state_dir_name));
    download_golden_nns_state_or_panic(scp_location, &download_destination);

    let state_dir = bazel_test_compatible_temp_dir_or_panic();
    untar_state_archive_or_panic(
        &download_destination,
        state_dir.path(),
        archive_state_dir_name,
    );
    state_dir
}

/// If available, uses the `TEST_TMPDIR` environment variable, which is set by
/// `bazel test`, and points to where you are allowed to write to disk.
/// Otherwise, this just falls back on vanilla TempDir::new.
fn bazel_test_compatible_temp_dir_or_panic() -> TempDir {
    match std::env::var("TEST_TMPDIR") {
        Ok(dir) => TempDir::new_in(dir).unwrap(),
        Err(_err) => TempDir::new().unwrap(),
    }
}

fn download_golden_nns_state_or_panic(scp_location: ScpLocation, destination: &Path) {
    let source = scp_location.to_argument();
    println!("Downloading {} to {:?} ...", source, destination,);

    // Actually download.
    let scp_out = Command::new("scp")
        .arg("-oUserKnownHostsFile=/dev/null")
        .arg("-oStrictHostKeyChecking=no")
        .arg("-v")
        .arg(source.clone())
        .arg(destination)
        .output()
        .unwrap_or_else(|err| panic!("Could not scp from {:?} because: {:?}!", scp_location, err));

    // Inspect result.
    if !scp_out.status.success() {
        panic!("Could not scp from {}\n{:#?}", source, scp_out,);
    }

    let size = std::fs::metadata(destination)
        .map(|metadata| {
            let len = metadata.len() as f64;
            let len = len / (1 << 30) as f64;
            format!("{:.2} GiB", len)
        })
        .unwrap_or_else(|_err| "???".to_string());

    let destination = destination.to_string_lossy();
    println!("Downloaded {} to {}. size = {}", source, destination, size);
}

fn untar_state_archive_or_panic(source: &Path, destination: &Path, state_dir: &str) {
    println!(
        "Unpacking {} from {:?} to {:?}...",
        state_dir, source, destination
    );

    // TODO: Mathias reports having problems with this (or something similar) on Mac.
    let unpack_destination = bazel_test_compatible_temp_dir_or_panic();
    let unpack_destination = unpack_destination
        .path()
        .to_str()
        .expect("Was trying to convert a Path to a string.");
    let tar_out = Command::new("tar")
        .arg("--extract")
        .arg("--file")
        .arg(source)
        .arg("--directory")
        .arg(unpack_destination)
        .output()
        .unwrap_or_else(|err| panic!("Could not unpack {:?}: {}", source, err));

    if !tar_out.status.success() {
        panic!("Could not unpack {:?}\n{:#?}", source, tar_out);
    }

    // Move $UNTAR_DESTINATION/nns_state/ic_state to final output dir path, StateMachine's so-called
    // state_dir.
    std::fs::rename(
        format!("{}/{}/ic_state", unpack_destination, state_dir),
        destination,
    )
    .unwrap();

    println!("Unpacked {:?} to {:?}", source, destination);
}
