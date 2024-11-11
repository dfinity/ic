//! IC State Tool
//!
//! A command-line tool to manage Internet Computer replicated states (decode
//! persisted state files, diff checkpoints, compute partial state hashes and
//! checkpoint manifests, import state trees).

use clap::Parser;
use ic_registry_routing_table::CanisterIdRange;
use ic_registry_subnet_type::SubnetType;
use ic_state_tool::commands;
use ic_types::{PrincipalId, Time};
use std::path::PathBuf;

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
        #[clap(long, multiple_values(true))]
        retain: Vec<CanisterIdRange>,
        /// Canister ID ranges to drop (assigned to other subnet in the routing table).
        #[clap(long, multiple_values(true))]
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
        #[clap(long, required = true, multiple_values(true))]
        migrated_ranges: Vec<CanisterIdRange>,
    },
}

fn main() {
    let opt = Parser::parse();
    let result = match opt {
        Opt::CDiff { path_a, path_b } => commands::cdiff::do_diff(path_a, path_b),
        Opt::CHash { path } => commands::chash::do_hash(path),
        Opt::ImportState {
            state,
            config,
            height,
        } => commands::import_state::do_import(state, config, height),
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
    };

    if let Err(e) = result {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
