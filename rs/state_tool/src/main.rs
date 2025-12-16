//! IC State Tool
//!
//! A command-line tool to manage Internet Computer replicated states (decode
//! persisted state files, diff checkpoints, compute partial state hashes and
//! checkpoint manifests, import state trees).

use clap::Parser;
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_state_tool::commands;
use ic_types::{Height, PrincipalId, Time};
use std::{error::Error, path::PathBuf};

/// Supported `state_tool` commands and their arguments.
#[derive(Debug, Parser)]
#[clap(about = "IC state tool", version)]
enum Opt {
    /// Computes diff of canonical trees between checkpoints.
    #[clap(name = "cdiff")]
    CDiff { path_a: PathBuf, path_b: PathBuf },

    /// Computes partial state hash that is used for certification.
    #[clap(name = "chash")]
    CHash {
        /// Path to a checkpoint.
        #[clap(long = "state")]
        path: PathBuf,
    },

    /// Imports replicated state from an external location.
    /// Deprecated: use `copy` instead.
    #[clap(name = "import")]
    ImportState {
        /// Path to the state to import.
        #[clap(long = "state")]
        state: PathBuf,

        /// Path to the replica configuration (ic.json).
        #[clap(long = "config")]
        config: PathBuf,

        /// The height to label the state with.
        #[clap(long = "height", short = 'h')]
        height: u64,
    },

    /// Copies states from one ic_state directory to another including their metadata.
    #[clap(name = "copy")]
    CopyStates {
        /// Path to the source ic_state directory.
        source: PathBuf,
        /// Path to the destination ic_state directory.
        destination: PathBuf,
        /// Heights to copy.
        #[command(flatten)]
        heights: HeightsArgs,
    },

    /// Computes manifest of a checkpoint.
    #[clap(name = "manifest")]
    Manifest {
        /// Path to a checkpoint.
        #[clap(long = "state")]
        path: PathBuf,
    },

    /// Verifies whether the textual representation
    /// of a manifest matches its root hash.
    #[clap(name = "verify_manifest")]
    VerifyManifest {
        /// Path to a manifest.
        #[clap(long = "file")]
        file: PathBuf,
    },

    /// Enumerates persisted states.
    #[clap(name = "list")]
    ListStates {
        /// Path to the replica configuration (ic.json).
        #[clap(long = "config")]
        config: PathBuf,
    },

    /// Displays a pretty-printed debug view of a state file.
    #[clap(name = "decode")]
    Decode {
        /// Path to the file to display.
        #[clap(long = "file")]
        file: PathBuf,
    },

    /// Converts textual principal representation to hex.
    #[clap(name = "canister_id_to_hex")]
    CanisterIdToHex {
        #[clap(long = "canister_id")]
        canister_id: String,
    },

    /// Converts hex principal representation to textual representation.
    #[clap(name = "canister_id_from_hex")]
    CanisterIdFromHex {
        #[clap(long = "canister_id")]
        canister_id: String,
    },

    /// Encodes an array of comma-separated bytes (e.g., [0, 1, 20, ... , 142]) as
    /// a principal.
    #[clap(name = "principal_from_bytes")]
    PrincipalFromBytes {
        #[clap(long = "bytes")]
        bytes: String,
    },

    /// Prunes a replicated state, as part of a subnet split.
    #[clap(name = "split")]
    #[clap(group(
        clap::ArgGroup::new("ranges")
            .required(true)
            .args(&["retain", "drop"]),
    ))]
    Split {
        /// Path to the state layout.
        #[clap(long, required = true)]
        root: PathBuf,
        /// The ID of the subnet being split off.
        #[clap(long, required = true)]
        subnet_id: PrincipalId,
        /// Canister ID ranges to retain (assigned to the subnet in the routing table).
        #[clap(long, num_args(1..))]
        retain: Vec<CanisterIdRange>,
        /// Canister ID ranges to drop (assigned to other subnet in the routing table).
        #[clap(long, num_args(1..))]
        drop: Vec<CanisterIdRange>,
        /// New subnet's batch time (original subnet always retains its batch time).
        ///
        /// If not specified, the new subnet uses the batch time of the original subnet.
        #[clap(long)]
        batch_time_nanos: Option<u64>,
    },

    /// Splits a manifest, to verify the manifests resulting from a subnet split.
    #[clap(name = "split_manifest")]
    SplitManifest {
        /// Path to the manifest dump.
        #[clap(long, required = true)]
        path: PathBuf,
        /// ID of the subnet being split.
        #[clap(long, required = true)]
        from_subnet: PrincipalId,
        /// ID of the new subnet resulting from the split.
        #[clap(long, required = true)]
        to_subnet: PrincipalId,
        /// Type of the original subnet (to also be applied to `to_subnet`).
        #[clap(long, required = true)]
        subnet_type: SubnetType,
        /// Batch time to apply to the state of `to_subnet` (the new subnet).
        #[clap(long, required = true)]
        batch_time_nanos: u64,
        /// Canister ID ranges migrated to the new subnet.
        #[clap(long, required = true, num_args(1..))]
        migrated_ranges: Vec<CanisterIdRange>,
    },

    /// Prints out the index part of an overlay file in human-readable form.
    #[clap(name = "parse_overlay")]
    ParseOverlay {
        /// Path to the manifest dump.
        #[clap(long, required = true)]
        path: PathBuf,
    },

    /// Extracts canister metrics from the replicated state and prints them in CSV format to the
    /// specified file.
    #[clap(name = "canister_metrics")]
    CanisterMetrics {
        /// Path to a checkpoint.
        #[clap(long = "checkpoint")]
        path: PathBuf,

        /// Output path.
        #[clap(long)]
        output: PathBuf,

        /// Type of the subnet.
        #[clap(long, required = true)]
        subnet_type: SubnetType,
    },
}

/// Command line arguments for the `copy` command with eith
#[derive(Debug, Clone, clap::Args)]
#[group(multiple = false)]
struct HeightsArgs {
    /// Copy the latest state only, or none if there are no states in the source.
    ///
    /// Mutually exclusive with `--heights`. If neither is specified, all heights are copied.
    #[clap(long = "latest")]
    latest: bool,
    /// List of heights to copy.
    ///
    /// Heights can be specified as a comma separated list of heights. Optionally, a state can be renamed by specifiying the source and destination height separated by '->'.
    ///
    /// Examples:
    ///     - `--heights 1,2,3` copies states at heights 1, 2, and 3.
    ///     - `--heights 1->2` copies the state at height 1 and renames it to height 2.
    ///
    /// Mutually exclusive with `--latest`. If neither is specified, all heights are copied.
    #[clap(long = "heights", value_parser = parse_height_pair, value_delimiter = ',', verbatim_doc_comment)]
    heights: Option<Vec<(Height, Option<Height>)>>,
}

impl From<HeightsArgs> for commands::copy::Heights {
    fn from(val: HeightsArgs) -> Self {
        if val.latest {
            Self::Latest
        } else if val.heights.is_some() {
            Self::Explicit(val.heights.unwrap().into_iter().collect())
        } else {
            Self::All
        }
    }
}

/// Parser for either a single height or a pair of heights separated by '->'.
/// Used to parse the `--heights` argument of the `copy` command.
fn parse_height_pair(
    s: &str,
) -> Result<(Height, Option<Height>), Box<dyn Error + Send + Sync + 'static>> {
    match s.find("->") {
        Some(pos) => Ok((
            Height::new(s[..pos].parse()?),
            Some(Height::new(s[pos + 2..].parse()?)),
        )),
        None => Ok((Height::new(s.parse()?), None)),
    }
}

fn main() {
    let args = std::env::args().collect();
    main_inner(args);
}

pub(crate) fn main_inner(args: Vec<String>) {
    let opt = Parser::parse_from(args);
    let result = match opt {
        Opt::CDiff { path_a, path_b } => commands::cdiff::do_diff(path_a, path_b),
        Opt::CHash { path } => commands::chash::do_hash(path),
        Opt::ImportState {
            state,
            config,
            height,
        } => commands::import_state::do_import(state, config, height),
        Opt::CopyStates {
            source,
            destination,
            heights,
        } => commands::copy::do_copy(source, destination, heights.into()),
        Opt::Manifest { path } => commands::manifest::do_compute_manifest(path),
        Opt::VerifyManifest { file } => commands::verify_manifest::do_verify_manifest(&file),
        Opt::ListStates { config } => commands::list::do_list(config),
        Opt::Decode { file } => commands::decode::do_decode(file),
        Opt::CanisterIdToHex { canister_id } => {
            commands::convert_ids::do_canister_id_to_hex(canister_id)
        }
        Opt::CanisterIdFromHex { canister_id } => {
            commands::convert_ids::do_canister_id_from_hex(canister_id)
        }
        Opt::PrincipalFromBytes { bytes } => {
            commands::convert_ids::do_principal_from_byte_string(bytes)
        }
        Opt::Split {
            root,
            subnet_id,
            retain,
            drop,
            batch_time_nanos,
        } => commands::split::do_split(
            root,
            subnet_id,
            retain,
            drop,
            batch_time_nanos.map(Time::from_nanos_since_unix_epoch),
        ),
        Opt::SplitManifest {
            path,
            from_subnet,
            to_subnet,
            subnet_type,
            batch_time_nanos,
            migrated_ranges,
        } => commands::split_manifest::do_split_manifest(
            path,
            from_subnet.into(),
            to_subnet.into(),
            subnet_type,
            Time::from_nanos_since_unix_epoch(batch_time_nanos),
            migrated_ranges,
        ),
        Opt::ParseOverlay { path } => commands::parse_overlay::do_parse_overlay(path),
        Opt::CanisterMetrics {
            path,
            output,
            subnet_type,
        } => commands::canister_metrics::get(path, subnet_type, &output),
    };

    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_logger::no_op_logger;
    use ic_metrics::MetricsRegistry;
    use ic_state_layout::StateLayout;
    use ic_state_machine_tests::StateMachineBuilder;
    use tempfile::TempDir;

    #[test]
    fn copy_command_line_test() {
        let env = StateMachineBuilder::new().build();
        env.checkpointed_tick();
        env.state_manager.flush_tip_channel();

        let dst_dir = TempDir::new().unwrap();

        main_inner(vec![
            "state-tool".to_string(),
            "copy".to_string(),
            env.state_manager
                .state_layout()
                .raw_path()
                .display()
                .to_string(),
            dst_dir.path().display().to_string(),
        ]);

        let dst_layout = StateLayout::try_new(
            no_op_logger(),
            dst_dir.path().to_path_buf(),
            &MetricsRegistry::new(),
        )
        .unwrap();

        assert_eq!(
            dst_layout.checkpoint_heights().unwrap(),
            vec![Height::new(1)]
        );
    }

    #[test]
    fn copy_command_line_latest_test() {
        let env = StateMachineBuilder::new()
            .with_remove_old_states(false)
            .build();
        env.checkpointed_tick();
        env.checkpointed_tick();
        env.checkpointed_tick();
        env.state_manager.flush_tip_channel();

        let dst_dir = TempDir::new().unwrap();

        main_inner(vec![
            "state-tool".to_string(),
            "copy".to_string(),
            env.state_manager
                .state_layout()
                .raw_path()
                .display()
                .to_string(),
            dst_dir.path().display().to_string(),
            "--latest".to_string(),
        ]);

        let dst_layout = StateLayout::try_new(
            no_op_logger(),
            dst_dir.path().to_path_buf(),
            &MetricsRegistry::new(),
        )
        .unwrap();

        assert_eq!(
            dst_layout.checkpoint_heights().unwrap(),
            vec![Height::new(3)]
        );
    }

    #[test]
    fn copy_command_line_rename_test() {
        let env = StateMachineBuilder::new().build();
        env.checkpointed_tick();
        env.state_manager.flush_tip_channel();

        let dst_dir = TempDir::new().unwrap();

        main_inner(vec![
            "state-tool".to_string(),
            "copy".to_string(),
            env.state_manager
                .state_layout()
                .raw_path()
                .display()
                .to_string(),
            dst_dir.path().display().to_string(),
            "--heights".to_string(),
            "1->2".to_string(),
        ]);

        let dst_layout = StateLayout::try_new(
            no_op_logger(),
            dst_dir.path().to_path_buf(),
            &MetricsRegistry::new(),
        )
        .unwrap();

        assert_eq!(
            dst_layout.checkpoint_heights().unwrap(),
            vec![Height::new(2)]
        );
    }

    #[test]
    fn copy_command_line_filter_test() {
        let env = StateMachineBuilder::new()
            .with_remove_old_states(false)
            .build();
        env.checkpointed_tick();
        env.checkpointed_tick();
        env.checkpointed_tick();
        env.state_manager.flush_tip_channel();

        let dst_dir = TempDir::new().unwrap();

        main_inner(vec![
            "state-tool".to_string(),
            "copy".to_string(),
            env.state_manager
                .state_layout()
                .raw_path()
                .display()
                .to_string(),
            dst_dir.path().display().to_string(),
            "--heights".to_string(),
            "1,3".to_string(),
        ]);

        let dst_layout = StateLayout::try_new(
            no_op_logger(),
            dst_dir.path().to_path_buf(),
            &MetricsRegistry::new(),
        )
        .unwrap();

        assert_eq!(
            dst_layout.checkpoint_heights().unwrap(),
            vec![Height::new(1), Height::new(3)]
        );
    }
}
