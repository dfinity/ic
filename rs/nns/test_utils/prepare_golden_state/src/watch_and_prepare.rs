//! Example usage:
//!
//! In one shell:
//!
//! ```
//! bazel run //rs/nns/test_utils/prepare_golden_state:watch_and_prepare --
//! --state-dir-path=/some/directory --state-source=nns
//! ```
//!
//! In another shell:
//!
//! ```
//! bazel test --test_env=USE_EXISTING_STATE_DIR=/some/directory \
//!   --test_env=SSH_AUTH_SOCK \
//!   --test_env=NNS_CANISTER_UPGRADE_SEQUENCE=governance \
//!   --test_output=streamed \
//!   --test_arg=--nocapture \
//!   //rs/nns/integration_tests:upgrade_canisters_with_golden_nns_state
//! ```
//!
//! The test in the second shell can be run multiple times, and as soon as the test starts running,
//! the `StateMachine` will take away the state directory from the first shell and use it for the
//! test, and the first shell will notice that the state directory is gone and start untarring the
//! state again.

use clap::Parser;
use ic_nns_test_utils_prepare_golden_state::{
    StateSource, download_golden_state_or_panic, untar_state_archive_or_panic,
};
use std::{path::PathBuf, str::FromStr, thread::sleep, time::Duration};
use tempfile::TempDir;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    state_dir_path: PathBuf,

    #[clap(long)]
    state_source: String,

    #[clap(long)]
    clean: bool,
}

fn main() {
    let args = Args::parse();
    println!("Args: {args:?}");

    let state_source = StateSource::from_str(&args.state_source).expect("Invalid state source");

    let download_destination = args
        .state_dir_path
        .join(format!("{}.tar.zst", state_source.state_dir_name()));
    let untar_destination = args.state_dir_path.join(state_source.state_dir_name());

    if args.clean {
        println!(
            "The --clean flag is set, removing the existing downloaded state file {} and state directory {} if they exist",
            download_destination.display(),
            untar_destination.display()
        );
        if download_destination.exists() {
            std::fs::remove_file(download_destination.as_path())
                .expect("Failed to remove state file");
            println!(
                "Removed the existing downloaded state file {}",
                download_destination.display()
            );
        }
        if untar_destination.exists() {
            std::fs::remove_dir_all(untar_destination.as_path())
                .expect("Failed to remove state directory");
            println!(
                "Removed the existing state directory {}",
                untar_destination.display()
            );
        }
    }

    if !download_destination.exists() {
        download_golden_state_or_panic(state_source, download_destination.as_path());
    }

    if untar_destination.exists() {
        println!(
            "State directory found at {}, doing nothing for now but will keep monitoring...",
            untar_destination.display()
        );
    }

    loop {
        if untar_destination.exists() {
            sleep(Duration::from_secs(5));
            continue;
        }
        println!(
            "State directory not found at {}, untarring from {}...",
            untar_destination.display(),
            download_destination.display()
        );
        untar_state_archive_or_panic(
            download_destination.as_path(),
            untar_destination.as_path(),
            state_source.state_dir_name(),
            || TempDir::new_in(args.state_dir_path.as_path()).expect("Failed to create temp dir"),
        );
    }
}
