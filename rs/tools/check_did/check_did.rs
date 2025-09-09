use candid_parser::utils::{CandidSource, service_compatible};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} new.did old.did", args[0]);
        std::process::exit(1);
    }

    let new_did_file = PathBuf::from(&args[1]);
    let old_did_file = PathBuf::from(&args[2]);

    if let Err(e) = service_compatible(
        CandidSource::File(&new_did_file),
        CandidSource::File(&old_did_file),
    ) {
        panic!(
            "The new interface at {} is not compatible with the old interface at {}:\n{}",
            new_did_file.display(),
            old_did_file.display(),
            e,
        );
    }
}
