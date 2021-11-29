//! IC State Tool
//!
//! A command-line tool to manage Internet Computer replicated states (decode
//! persisted state files, diff checkpoints, compute partial state hashes and
//! checkpoint manifests, import state trees).

use std::path::PathBuf;
use structopt::StructOpt;

mod commands;

/// Supported `state_tool` commands and their arguments.
#[derive(StructOpt, Debug)]
#[structopt(about = "IC state tool")]
enum Opt {
    /// Computes diff of canonical trees between checkpoints.
    #[structopt(name = "cdiff")]
    CDiff { path_a: PathBuf, path_b: PathBuf },

    /// Computes partial state hash that is used for certification.
    #[structopt(name = "chash")]
    CHash {
        /// Path to a checkpoint.
        #[structopt(long = "state")]
        path: PathBuf,
    },

    /// Imports replicated state from an external location.
    #[structopt(name = "import")]
    ImportState {
        /// Path to the state to import.
        #[structopt(long = "state")]
        state: PathBuf,

        /// Path to the replica configuration (ic.json).
        #[structopt(long = "config")]
        config: PathBuf,

        /// The height to label the state with.
        #[structopt(long = "height", short = "h")]
        height: u64,
    },

    /// Computes manifest of a checkpoint.
    #[structopt(name = "manifest")]
    Manifest {
        /// Path to a checkpoint.
        #[structopt(long = "state")]
        path: PathBuf,
    },

    /// Enumerates persisted states.
    #[structopt(name = "list")]
    ListStates {
        /// Path to the replica configuration (ic.json).
        #[structopt(long = "config")]
        config: PathBuf,
    },

    /// Displays a pretty-printed debug view of a state file.
    #[structopt(name = "decode")]
    Decode {
        /// Path to the file to display.
        #[structopt(long = "file")]
        file: PathBuf,
    },
}

fn main() {
    let opt = Opt::from_args();
    let result = match opt {
        Opt::CDiff { path_a, path_b } => commands::cdiff::do_diff(path_a, path_b),
        Opt::CHash { path } => commands::chash::do_hash(path),
        Opt::ImportState {
            state,
            config,
            height,
        } => commands::import_state::do_import(state, config, height),
        Opt::Manifest { path } => commands::manifest::do_compute_manifest(path),
        Opt::ListStates { config } => commands::list::do_list(config),
        Opt::Decode { file } => commands::decode::do_decode(file),
    };

    if let Err(e) = result {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
