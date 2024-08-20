use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_config::{execution_environment::Config, subnet_config::SubnetConfig};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, StateMachineConfig};
use ic_types::NumInstructions;

use ic_config::flag_status::FlagStatus;
use std::{ops::RangeInclusive, path::Path, process::Command, str::FromStr};
use tempfile::TempDir;
// TODO: Add support for PocketIc.

pub fn new_state_machine_with_golden_fiduciary_state_or_panic() -> StateMachine {
    let fiduciary_subnet_id = SubnetId::new(
        PrincipalId::from_str("pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae")
            .unwrap(),
    );
    let setup_config = SetupConfig {
        archive_state_dir_name: "fiduciary_state",
        extra_canister_range: RangeInclusive::new(
            CanisterId::from_u64(0x2300000),
            CanisterId::from_u64(0x23FFFFE),
        ),
        hypervisor_config: Some(Config {
            rate_limiting_of_instructions: FlagStatus::Disabled,
            ..Config::default()
        }),
        scp_location: FIDUCIARY_STATE_SOURCE,
        subnet_id: fiduciary_subnet_id,
        subnet_type: SubnetType::Application,
    };
    new_state_machine_with_golden_state_or_panic(setup_config)
}

pub fn new_state_machine_with_golden_nns_state_or_panic() -> StateMachine {
    let nns_subnet_id = SubnetId::new(
        PrincipalId::from_str("tdb26-jop6k-aogll-7ltgs-eruif-6kk7m-qpktf-gdiqx-mxtrf-vb5e6-eqe")
            .unwrap(),
    );
    let setup_config = SetupConfig {
        archive_state_dir_name: "nns_state",
        // using the canister ranges of both the NNS and II subnets. Note. The
        // last canister ID in the canister range of the II subnet is omitted so
        // that the canister range of the II subnet is not used for automatic
        // generation of new canister IDs.
        extra_canister_range: RangeInclusive::new(
            CanisterId::from_u64(0x2100000),
            CanisterId::from_u64(0x21FFFFE),
        ),
        hypervisor_config: None,
        scp_location: NNS_STATE_SOURCE,
        subnet_id: nns_subnet_id,
        subnet_type: SubnetType::System,
    };
    new_state_machine_with_golden_state_or_panic(setup_config)
}

pub fn new_state_machine_with_golden_sns_state_or_panic() -> StateMachine {
    let sns_subnet_id = SubnetId::new(
        PrincipalId::from_str("x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae")
            .unwrap(),
    );
    let setup_config = SetupConfig {
        archive_state_dir_name: "sns_state",
        extra_canister_range: RangeInclusive::new(
            CanisterId::from_u64(0x2000000),
            CanisterId::from_u64(0x20FFFFE),
        ),
        hypervisor_config: Some(Config {
            rate_limiting_of_instructions: FlagStatus::Disabled,
            ..Config::default()
        }),
        scp_location: SNS_STATE_SOURCE,
        subnet_id: sns_subnet_id,
        subnet_type: SubnetType::Application,
    };
    new_state_machine_with_golden_state_or_panic(setup_config)
}

fn new_state_machine_with_golden_state_or_panic(setup_config: SetupConfig) -> StateMachine {
    let SetupConfig {
        archive_state_dir_name,
        extra_canister_range,
        hypervisor_config,
        scp_location,
        subnet_id,
        subnet_type,
    } = setup_config;
    // TODO, remove when this is the value set in the normal IC build This is to
    // uncover issues in testing that might affect performance in production.
    // Application subnets have this set to 2 billion.
    const MAX_INSTRUCTIONS_PER_SLICE: NumInstructions = NumInstructions::new(2_000_000_000);

    let state_machine_builder = StateMachineBuilder::new()
        .with_current_time()
        .with_extra_canister_range(extra_canister_range);

    let mut subnet_config = SubnetConfig::new(subnet_type);
    subnet_config.scheduler_config.max_instructions_per_slice = MAX_INSTRUCTIONS_PER_SLICE;
    let state_machine_builder = state_machine_builder.with_config(Some(StateMachineConfig::new(
        subnet_config,
        hypervisor_config.unwrap_or_default(),
    )));

    let state_dir =
        download_and_untar_golden_nns_state_or_panic(scp_location, archive_state_dir_name);
    let state_machine_builder = state_machine_builder
        .with_state_machine_state_dir(Box::new(state_dir))
        // Patch StateMachine. This is a bit of a hack that we need because we
        // are initializing from a state_dir.
        .with_nns_subnet_id(subnet_id)
        .with_subnet_id(subnet_id);

    println!("Building StateMachine...");
    let state_machine = state_machine_builder.build();
    println!("Done building StateMachine...");

    state_machine
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

// Privates

const FIDUCIARY_STATE_SOURCE: ScpLocation = ScpLocation {
    user: "dev",
    host: "zh1-pyr07.zh1.dfinity.network",
    path: "/home/dev/fiduciary_state.tar.zst",
};

const NNS_STATE_SOURCE: ScpLocation = ScpLocation {
    user: "dev",
    host: "zh1-pyr07.zh1.dfinity.network",
    path: "/home/dev/nns_state.tar.zst",
};

const SNS_STATE_SOURCE: ScpLocation = ScpLocation {
    user: "dev",
    host: "zh1-pyr07.zh1.dfinity.network",
    path: "/home/dev/sns_state.tar.zst",
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

struct SetupConfig {
    archive_state_dir_name: &'static str,
    extra_canister_range: RangeInclusive<CanisterId>,
    hypervisor_config: Option<Config>,
    scp_location: ScpLocation,
    subnet_id: SubnetId,
    subnet_type: SubnetType,
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

/// If available, uses the `TEST_TMPDIR` environment variable, which is set by
/// `bazel test`, and points to where you are allowed to write to disk.
/// Otherwise, this just falls back on vanilla TempDir::new.
fn bazel_test_compatible_temp_dir_or_panic() -> TempDir {
    match std::env::var("TEST_TMPDIR") {
        Ok(dir) => TempDir::new_in(dir).unwrap(),
        Err(_err) => TempDir::new().unwrap(),
    }
}
