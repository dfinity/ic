use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_config::{execution_environment::Config, subnet_config::SubnetConfig};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_types::NumInstructions;

use std::{ops::RangeInclusive, path::Path, process::Command, str::FromStr};
use std::env;
use tempfile::TempDir;

// TODO: Add support for PocketIc.

pub fn new_state_machine_with_golden_nns_state_or_panic() -> StateMachine {
    // TODO, remove when this is the value set in the normal IC build This is to
    // uncover issues in testing that might affect performance in production.
    // Application subnets have this set to 2 billion.
    const MAX_INSTRUCTIONS_PER_SLICE: NumInstructions = NumInstructions::new(2_000_000_000);

    let state_machine_builder = StateMachineBuilder::new()
        .with_current_time()
        // using the canister ranges of both the NNS and II subnets. Note. The
        // last canister ID in the canister range of the II subnet is omitted so
        // that the canister range of the II subnet is not used for automatic
        // generation of new canister IDs.
        .with_extra_canister_range(RangeInclusive::new(
            CanisterId::from_u64(0x2100000),
            CanisterId::from_u64(0x21FFFFE),
        ));

    let mut subnet_config = SubnetConfig::new(SubnetType::System);
    subnet_config.scheduler_config.max_instructions_per_slice = MAX_INSTRUCTIONS_PER_SLICE;
    let state_machine_builder = state_machine_builder.with_config(Some(StateMachineConfig::new(
        subnet_config,
        Config::default(),
    )));

    let nns_subnet_id = SubnetId::new(
        PrincipalId::from_str("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .unwrap(),
    );
    let state_dir = download_and_untar_golden_nns_state_or_panic();
    let state_machine_builder = state_machine_builder
        .with_state_dir(state_dir)
        // Patch StateMachine. This is a bit of a hack that we need because we
        // are initializing from a state_dir.
        .with_nns_subnet_id(nns_subnet_id)
        .with_subnet_id(nns_subnet_id);

    println!("Building StateMachine...");
    let state_machine = state_machine_builder.build();
    println!("Done building StateMachine...");

    state_machine
}

pub fn download_and_untar_golden_nns_state_or_panic() -> TempDir {
    let download_destination = bazel_test_compatible_temp_dir_or_panic();
    let download_destination = download_destination.path().join("nns_state.tar.zst");
    download_golden_nns_state_or_panic(&download_destination);

    let state_dir = bazel_test_compatible_temp_dir_or_panic();
    untar_state_archive_or_panic(&download_destination, state_dir.path());
    state_dir
}

// Privates

const NNS_STATE_SOURCE: ScpLocation = ScpLocation {
    user: "dev",
    host: "zh1-pyr07.zh1.dfinity.network",
    path: "/home/dev/nns_state.tar.zst",
};

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

fn download_golden_nns_state_or_panic(destination: &Path) {
    let source = NNS_STATE_SOURCE.to_argument();
    println!("Downloading {} to {:?} ...", source, destination,);

    for (key, value) in env::vars() {
        println!("{key}: {value}");
    }

    // Actually download.
    let scp_out = Command::new("scp")
        .arg("-oUserKnownHostsFile=/dev/null")
        .arg("-oStrictHostKeyChecking=no")
        .arg("-v")
        .arg(source.clone())
        .arg(destination)
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "Could not scp from {:?} because: {:?}!",
                NNS_STATE_SOURCE, err
            )
        });

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

fn untar_state_archive_or_panic(source: &Path, destination: &Path) {
    println!("Unpacking {:?} to {:?}...", source, destination);

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
        format!("{}/nns_state/ic_state", unpack_destination),
        destination,
    )
    .unwrap();

    println!("Unpacked {:?} to {:?}", source, destination);
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
