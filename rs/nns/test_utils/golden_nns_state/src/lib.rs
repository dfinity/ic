use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_config::{execution_environment::Config, subnet_config::SubnetConfig};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    StateMachine, StateMachineBuilder, StateMachineConfig, StateMachineStateDir,
};
use ic_types::NumInstructions;

use ic_config::flag_status::FlagStatus;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
use std::{
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};
use tempfile::TempDir;
// TODO: Add support for PocketIc.

pub fn new_state_machine_with_golden_fiduciary_state_or_panic() -> StateMachine {
    let fiduciary_subnet_id = SubnetId::new(
        PrincipalId::from_str("pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae")
            .unwrap(),
    );
    let routing_table = create_routing_table(0x2300000, 0x23FFFFE, fiduciary_subnet_id);
    let setup_config = SetupConfig {
        archive_state_dir_name: "fiduciary_state",
        routing_table,
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
    // using the canister ranges of both the NNS and II subnets. Note. The
    // last canister ID in the canister range of the II subnet is omitted so
    // that the canister range of the II subnet is not used for automatic
    // generation of new canister IDs.
    let routing_table = create_routing_table(0x2100000, 0x21FFFFE, nns_subnet_id);
    let setup_config = SetupConfig {
        archive_state_dir_name: "nns_state",
        routing_table,
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
    let routing_table = create_routing_table(0x2000000, 0x20FFFFE, sns_subnet_id);
    let setup_config = SetupConfig {
        archive_state_dir_name: "sns_state",
        routing_table,
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
        routing_table,
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
        .with_routing_table(routing_table);

    let mut subnet_config = SubnetConfig::new(subnet_type);
    subnet_config.scheduler_config.max_instructions_per_slice = MAX_INSTRUCTIONS_PER_SLICE;
    let state_machine_builder = state_machine_builder.with_config(Some(StateMachineConfig::new(
        subnet_config,
        hypervisor_config.unwrap_or_default(),
    )));

    let state_dir = maybe_download_golden_nns_state_or_panic(scp_location, archive_state_dir_name);
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

/// A directory for storing the golden state which can be either a temporary directory or a cached
/// directory which can be used across multiple tests.
enum StateDir {
    // A temporary directory that will be deleted after the test is done.
    Temp(TempDir),
    // A directory that will be cached and reused across tests.
    Cache(PathBuf),
}

impl StateMachineStateDir for StateDir {
    fn path(&self) -> PathBuf {
        match self {
            Self::Temp(temp_dir) => temp_dir.path().to_path_buf(),
            Self::Cache(path) => path.clone(),
        }
    }
}

fn maybe_download_golden_nns_state_or_panic(
    scp_location: ScpLocation,
    archive_state_dir_name: &str,
) -> StateDir {
    let maybe_use_cached_state_dir = std::env::var_os("USE_CACHED_STATE_DIR");

    match maybe_use_cached_state_dir {
        Some(cached_state_dir) => {
            let destination = PathBuf::from(cached_state_dir).join(archive_state_dir_name);
            if !destination.exists() {
                std::fs::create_dir(&destination)
                    .unwrap_or_else(|_| panic!("Failed to create directory {destination:?}"));
                download_and_untar_golden_nns_state_or_panic(
                    scp_location,
                    archive_state_dir_name,
                    &destination,
                );
            }
            StateDir::Cache(destination)
        }
        None => {
            let state_dir = bazel_test_compatible_temp_dir_or_panic();
            download_and_untar_golden_nns_state_or_panic(
                scp_location,
                archive_state_dir_name,
                state_dir.path(),
            );
            StateDir::Temp(state_dir)
        }
    }
}

fn download_and_untar_golden_nns_state_or_panic(
    scp_location: ScpLocation,
    archive_state_dir_name: &str,
    destination: &Path,
) {
    let download_destination = bazel_test_compatible_temp_dir_or_panic();
    let download_destination = download_destination
        .path()
        .join(format!("{}.tar.zst", archive_state_dir_name));
    download_golden_nns_state_or_panic(scp_location, &download_destination);
    untar_state_archive_or_panic(&download_destination, destination, archive_state_dir_name);
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
    routing_table: RoutingTable,
    hypervisor_config: Option<Config>,
    scp_location: ScpLocation,
    subnet_id: SubnetId,
    subnet_type: SubnetType,
}

/// Create a routing table for the `StateMachine`, with the provided canister IDs being routed to
/// the local subnet, and all other canister IDs being routed to non-existent subnets. Any leftover
/// responses destined for other subnets will be routed to a stream and will stay there. In
/// particular, they will not cause a panic, causing the test to fail.
fn create_routing_table(
    canister_range_start: u64,
    canister_range_end: u64,
    subnet_id: SubnetId,
) -> RoutingTable {
    let mut routing_table = RoutingTable::new();
    let (first_subnet_id, second_subnet_id) = compute_unique_subnet_ids(subnet_id);
    if canister_range_start > 0 {
        add_canister_range_to_routing_table(
            &mut routing_table,
            first_subnet_id,
            0,
            canister_range_start - 1,
        );
    }
    add_canister_range_to_routing_table(
        &mut routing_table,
        subnet_id,
        canister_range_start,
        canister_range_end,
    );
    if canister_range_end < u64::MAX {
        add_canister_range_to_routing_table(
            &mut routing_table,
            second_subnet_id,
            canister_range_end + 1,
            u64::MAX,
        );
    }
    routing_table
}

fn compute_unique_subnet_ids(subnet_id: SubnetId) -> (SubnetId, SubnetId) {
    let mut candidates = vec![];
    let mut subnet_id_counter = 0u64;
    while candidates.len() < 2 {
        let candidate = SubnetId::from(PrincipalId::new_subnet_test_id(subnet_id_counter));
        if candidate != subnet_id {
            candidates.push(candidate);
        }
        subnet_id_counter += 1;
    }
    (candidates[0], candidates[1])
}

fn add_canister_range_to_routing_table(
    routing_table: &mut RoutingTable,
    subnet_id: SubnetId,
    canister_range_start: u64,
    canister_range_end: u64,
) {
    routing_table
        .insert(
            CanisterIdRange {
                start: CanisterId::from_u64(canister_range_start),
                end: CanisterId::from_u64(canister_range_end),
            },
            subnet_id,
        )
        .expect("should be able to insert canister range into routing table");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_valid_routing_table_with_canister_ids_neither_0_nor_u64_max() {
        let routing_table = create_routing_table(
            0x1000000,
            0x1FFFFFE,
            SubnetId::new(
                PrincipalId::from_str(
                    "x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae",
                )
                .unwrap(),
            ),
        );
        assert_routing_table_size(routing_table, 3);
    }

    #[test]
    fn should_create_valid_routing_table_with_canister_ids_starting_at_0() {
        let routing_table = create_routing_table(
            0x0,
            0x1FFFFFE,
            SubnetId::new(
                PrincipalId::from_str(
                    "x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae",
                )
                .unwrap(),
            ),
        );
        assert_routing_table_size(routing_table, 2);
    }

    #[test]
    fn should_create_valid_routing_table_with_canister_ids_ending_at_u64_max() {
        let routing_table = create_routing_table(
            0x1000000,
            u64::MAX,
            SubnetId::new(
                PrincipalId::from_str(
                    "x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae",
                )
                .unwrap(),
            ),
        );
        assert_routing_table_size(routing_table, 2);
    }

    #[test]
    fn should_create_valid_routing_table_with_canister_ids_starting_at_0_and_ending_at_u64_max() {
        let routing_table = create_routing_table(
            0x0,
            u64::MAX,
            SubnetId::new(
                PrincipalId::from_str(
                    "x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae",
                )
                .unwrap(),
            ),
        );
        assert_routing_table_size(routing_table, 1);
    }

    #[test]
    fn should_create_routing_table_with_distinct_subnets_with_conflicting_subnet_id() {
        let routing_table = create_routing_table(
            0x1000000,
            0x1FFFFFE,
            SubnetId::from(PrincipalId::new_subnet_test_id(0)),
        );
        assert_routing_table_size(routing_table, 3);
    }

    fn assert_routing_table_size(routing_table: RoutingTable, expected_size: usize) {
        let mut num_subnets = 0;
        for _ in routing_table.iter() {
            num_subnets += 1;
        }
        assert_eq!(num_subnets, expected_size);
    }
}
