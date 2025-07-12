use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use std::fs::File;
use tar::Archive;
use tempfile::{tempdir, TempDir};
use zstd::stream::read::Decoder;

use partition_tools::{ext::ExtPartition, Partition};

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    image: PathBuf,
    #[arg(long, default_value_t = 4)]
    index: usize,
    #[arg(long, default_value_t = true)]
    unarchive: bool,
    #[arg(long, default_value = "/guest-os.img.tar.zst")]
    source: PathBuf,
    dest: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let tmpdir = tempdir()?;

    let partition_path = if cli.unarchive {
        // Decompress and open the archive
        decompress_image(&cli.image, &tmpdir)?
    } else {
        cli.image
    };

    // Open the image
    let mut partition = ExtPartition::open(partition_path, Some(cli.index))
        .await
        .expect("Could not open partition");

    partition
        .copy_file_to(&cli.source, &cli.dest)
        .await
        .unwrap();

    Ok(())
}

fn decompress_image(path: &Path, tmpdir: &TempDir) -> Result<PathBuf> {
    let image = File::open(path)?;
    let mut archive = Archive::new(Decoder::new(&image)?);

    // Unpack to a tempdir
    let partition_path = tmpdir.path().join("temp.img");

    let mut entries = archive.entries()?;
    entries
        .next()
        .unwrap_or_else(|| panic!("'{}' contains no files.", path.display()))?
        .unpack(&partition_path)?;

    if entries.next().is_some() {
        panic!("'{}' must contain a single file.", path.display());
    }

    Ok(partition_path)
}
