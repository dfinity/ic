use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use anyhow::{bail, Result};
use sys_util::{PunchHole, SeekHole, WriteZeroes};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    source: PathBuf,
    #[arg(short, long)]
    target: PathBuf,
    #[arg(short, long, default_value_t = 0)]
    target_seek: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.source == args.target {
        bail!("Source and target must be different");
    }

    let mut source = File::open(args.source.as_path())?;
    let mut target = File::options().write(true).open(args.target.as_path())?;

    target.seek(SeekFrom::Start(args.target_seek))?;
    File::copy()
    std::io::copy(&mut source, &mut target)?;
    Ok(())
    // let mut source_offset = 0;
    // let mut target_offset = 0;
    // if let Some(new_source_offset) = source.seek_data(source_offset)? {
    //     let seek_distance = new_source_offset - source_offset;
    //     source_offset += seek_distance;
    //     target_offset += seek_distance;
    //     target.write_zeroes(seek_distance.try_into()?)?
    // } else {
    //     let remaining_zeros: usize = (source.metadata()?.len() - source_offset).try_into()?;
    //     assert_eq!(target.write_zeroes(remaining_zeros)?, remaining_zeros);
    // }
    //
    // std::io::copy()
    //
    // println!("Source: {:?}", args.source);
    // println!("Target: {:?}", args.target);
    // println!("Target Seek: {}", args.target_seek);
    // // Your copy logic here, using args.source, args.target, and args.target_seek
}
