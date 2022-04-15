//! IC State Tool
//!
//! A command-line tool to manage Internet Computer replicated states (decode
//! persisted state files, diff checkpoints, compute partial state hashes and
//! checkpoint manifests, import state trees).

use clap::Parser;
use std::path::PathBuf;

mod commands;

/// Supported `state_tool` commands and their arguments.
#[derive(Parser, Debug)]
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
        Opt::ListStates { config } => commands::list::do_list(config),
        Opt::Decode { file } => commands::decode::do_decode(file),
    };

    if let Err(e) = result {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}
