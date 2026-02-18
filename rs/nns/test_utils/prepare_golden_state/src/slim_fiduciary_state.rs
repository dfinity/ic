//! Slims a `fiduciary_state.tar.zst` archive to only the ckETH ledger and index canisters.
//!
//! Usage:
//!   slim_fiduciary_state <input.tar.zst> <output.tar.zst>
//!   slim_fiduciary_state --canister <principal> ... <input.tar.zst> <output.tar.zst>
//!
//! By default keeps only:
//!   - ckETH ledger: ss2fx-dyaaa-aaaar-qacoq-cai
//!   - ckETH index:  s3zol-vqaaa-aaaar-qacpa-cai

use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek};
use std::path::{Path, PathBuf};
use std::str::FromStr;

const FIDUCIARY_STATE_DIR: &str = "fiduciary_state";
const IC_STATE_DIR: &str = "ic_state";
const CHECKPOINTS_DIR: &str = "checkpoints";
const CANISTER_STATES_DIR: &str = "canister_states";
const SNAPSHOTS_DIR: &str = "snapshots";

/// Default ckETH ledger and index canister IDs (principal strings).
const CKETH_LEDGER: &str = "ss2fx-dyaaa-aaaar-qacoq-cai";
const CKETH_INDEX: &str = "s3zol-vqaaa-aaaar-qacpa-cai";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut canister_principals = vec![CKETH_LEDGER.to_string(), CKETH_INDEX.to_string()];
    let mut args = std::env::args().skip(1).peekable();

    while args.peek().map(|a| a == "--canister" || a == "-c").unwrap_or(false) {
        args.next(); // consume --canister
        if let Some(p) = args.next() {
            canister_principals.push(p);
        }
    }

    let input = args
        .next()
        .ok_or("Usage: slim_fiduciary_state [--canister <principal> ...] <input.tar.zst> <output.tar.zst>")?;
    let output = args
        .next()
        .ok_or("Usage: slim_fiduciary_state [--canister <principal> ...] <input.tar.zst> <output.tar.zst>")?;

    let allowlist = build_canister_id_allowlist(&canister_principals)?;
    println!(
        "Keeping {} canister(s): {}",
        allowlist.len(),
        allowlist.join(", ")
    );

    let temp_dir = tempfile::tempdir()?;
    let extract_root = temp_dir.path();

    // Extract input tar.zst
    println!("Extracting {} ...", input);
    extract_tar_zst(Path::new(&input), extract_root)?;

    let state_root = extract_root.join(FIDUCIARY_STATE_DIR).join(IC_STATE_DIR);
    if !state_root.is_dir() {
        return Err(format!(
            "Expected {}/{} inside archive; not found at {}",
            FIDUCIARY_STATE_DIR,
            IC_STATE_DIR,
            state_root.display()
        )
        .into());
    }

    // Remove canister state and snapshot dirs not in allowlist under tip and each checkpoint
    slim_checkpoint_dir(state_root.join("tip"), &allowlist)?;
    let checkpoints = state_root.join(CHECKPOINTS_DIR);
    if checkpoints.is_dir() {
        for entry in fs::read_dir(&checkpoints)? {
            let entry = entry?;
            if entry.path().is_dir() {
                slim_checkpoint_dir(entry.path(), &allowlist)?;
            }
        }
    }

    // Repack fiduciary_state/ into output tar.zst
    println!("Writing {} ...", output);
    create_tar_zst(extract_root.join(FIDUCIARY_STATE_DIR), Path::new(&output))?;

    println!("Done.");
    Ok(())
}

fn build_canister_id_allowlist(principals: &[String]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    use ic_base_types::PrincipalId;
    let mut out = Vec::with_capacity(principals.len());
    for p in principals {
        let principal = PrincipalId::from_str(p)?;
        let bytes = principal.as_slice();
        out.push(hex::encode(bytes));
    }
    Ok(out)
}

fn slim_checkpoint_dir(checkpoint_path: PathBuf, allowlist: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    for subdir in [CANISTER_STATES_DIR, SNAPSHOTS_DIR] {
        let dir = checkpoint_path.join(subdir);
        if !dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("Non-UTF8 directory name")?;
            if !allowlist.contains(&name.to_string()) {
                let path = entry.path();
                println!("Removing {} {}", subdir, name);
                fs::remove_dir_all(&path)?;
            }
        }
    }
    Ok(())
}

fn extract_tar_zst(archive: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let f = File::open(archive)?;
    let mut reader = BufReader::new(f);
    // Detect zst magic
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    reader.seek(std::io::SeekFrom::Start(0))?;
    let decompressed: Box<dyn Read> = if magic == [0x28, 0xb5, 0x2f, 0xfd] {
        Box::new(zstd::stream::read::Decoder::new(reader)?)
    } else {
        Box::new(reader)
    };
    let mut archive = tar::Archive::new(decompressed);
    archive.unpack(dest)?;
    Ok(())
}

fn create_tar_zst(source_dir: PathBuf, out_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let out_file = File::create(out_path)?;
    let writer = BufWriter::new(out_file);
    let encoder = zstd::stream::write::Encoder::new(writer, 3)?;
    let mut tar = tar::Builder::new(encoder);
    let name = source_dir.file_name().unwrap_or_default();
    tar.append_dir_all(name, &source_dir)?;
    tar.finish()?;
    let encoder = tar.into_inner()?;
    encoder.finish()?;
    Ok(())
}
