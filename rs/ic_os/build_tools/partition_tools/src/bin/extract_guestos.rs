use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use std::fs::File;
use tar::Archive;
use tempfile::{TempDir, tempdir};
use zstd::Decoder;

use partition_tools::{Partition, ext::ExtPartition};

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    image: PathBuf,
    #[arg(long, action = clap::ArgAction::SetFalse, default_value_t = true)]
    unarchive: bool,
    dest: PathBuf,
}

const GUESTOS_PATH: &str = "/guest-os.img.tar.zst";
const SETUPOS_DATA_INDEX: u32 = 4;

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
    let mut partition = ExtPartition::open(partition_path, Some(SETUPOS_DATA_INDEX))
        .await
        .expect("Could not open partition");

    partition
        .copy_file_to(Path::new(GUESTOS_PATH), &cli.dest)
        .await
        .unwrap();

    partition.close().await.expect("Could not close partition");

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
