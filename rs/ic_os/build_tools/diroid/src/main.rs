use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use walkdir::WalkDir;

/// Generate an e2fsdroid fs_config file for a given directory tree
#[derive(Parser)]
struct Args {
    /// Fakeroot statefile, to pull ownership from
    #[arg(long, required = true)]
    fakeroot: PathBuf,
    /// Base directory to scan
    #[arg(long, required = true)]
    input_dir: PathBuf,
    /// Output file
    #[arg(long, required = true)]
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let fakeroot_map = read_fakeroot_state(&args.fakeroot)?;
    let mut output = File::create(args.output)?;

    for entry in WalkDir::new(&args.input_dir) {
        let entry = entry?;

        let metadata = entry.metadata()?;

        // Look the entry up by the inode number that stat(2) reports (st_ino), which is
        // what fakeroot recorded, not by the one readdir(3) reports (d_ino, which is what
        // walkdir's DirEntryExt::ino() returns). The two differ for directories on an
        // overlayfs whose layers are on different filesystems (e.g. a GitHub Actions
        // runner's root filesystem) unless it is mounted with xino=on: there st_ino is
        // an overlay-private number while d_ino is the real inode of the upper layer.
        let ino = metadata.ino();
        let (uid, gid) = match fakeroot_map.get(&ino) {
            Some(v) => v,
            // fakeroot does not track /, so special case this ownership
            None if entry.path() == args.input_dir => &(0, 0),
            None => {
                bail!("fakeroot map does not contain inode: '{}'", ino);
            }
        };

        writeln!(
            &mut output,
            "{} {} {} {:o}",
            entry.path().strip_prefix(&args.input_dir)?.display(),
            uid,
            gid,
            metadata.mode()
        )?;
    }

    Ok(())
}

/// Parse a fakeroot statefile, building a map of inode to uid/gid
fn read_fakeroot_state(path: &PathBuf) -> Result<HashMap<u64, (u32, u32)>> {
    let state = File::open(path)?;

    let mut fakeroot_map = HashMap::new();
    for line in io::BufReader::new(state).lines() {
        let line = line?;

        let fields: Vec<_> = line.split(',').collect();

        let ino = fields.iter().find_map(|v| v.strip_prefix("ino="));
        let uid = fields.iter().find_map(|v| v.strip_prefix("uid="));
        let gid = fields.iter().find_map(|v| v.strip_prefix("gid="));

        let ino = ino.context("fakeroot map invalid, 'ino' not found")?;
        let uid = uid.context("fakeroot map invalid, 'uid' not found")?;
        let gid = gid.context("fakeroot map invalid, 'gid' not found")?;

        fakeroot_map.insert(ino.parse()?, (uid.parse()?, gid.parse()?));
    }

    Ok(fakeroot_map)
}
