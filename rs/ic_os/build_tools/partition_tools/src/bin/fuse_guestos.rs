use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{ensure, Result};
use clap::Parser;
use std::{fs::File, io, io::Seek};
use tar::Builder;
use tempfile::{tempdir, NamedTempFile, TempDir};
use zstd::Encoder;

use dflate::{add_file_to_archive, scan_file_for_holes};
use partition_tools::gpt;

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    image: PathBuf,
    #[arg(long)]
    update: PathBuf,
    dest: PathBuf,
}

const GUESTOS_BOOT_INDEX: u32 = 4;
const GUESTOS_ROOT_INDEX: u32 = 5;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let tmpdir = tempdir()?;

    // Decompress and open the archive
    let image = decompress_image(&cli.image, &tmpdir)?;

    let merged_image = NamedTempFile::new()?;

    // NOTE: fs::copy does not support sparse files, call out to cp instead.
    Command::new("cp")
        .arg(image)
        .arg(merged_image.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    // Decompress and open the archive
    let (boot, root) = decompress_update(&cli.update, &tmpdir)?;

    write_part(merged_image.path(), &boot, GUESTOS_BOOT_INDEX)?;
    write_part(merged_image.path(), &root, GUESTOS_ROOT_INDEX)?;

    let mut dest = Builder::new(
        Encoder::new(
            File::create(cli.dest)?,
            0, /* use default compression level */
        )?
        .auto_finish(),
    );

    let mut merged_file = File::open(&merged_image)?;
    let state = scan_file_for_holes(&mut merged_file, "disk.img".to_string())?;
    add_file_to_archive(&mut merged_file, &mut dest, state)?;

    Ok(())
}

fn write_part(target: &Path, image: &Path, index: u32) -> Result<()> {
    let mut input = File::open(image)?;
    let image_length = input.metadata()?.len();
    let part_length = gpt::get_partition_length(target, index)?;
    ensure!(
        image_length <= part_length,
        "Image is too large for partition"
    );

    let offset = gpt::get_partition_offset(target, index)?;
    let mut output = File::options().write(true).open(target)?;
    output.seek(io::SeekFrom::Start(offset))?;

    io::copy(&mut input, &mut output)?;

    Ok(())
}

fn decompress_image(path: &Path, tmpdir: &TempDir) -> Result<PathBuf> {
    // NOTE: The tar crate does not currently support extended numeric form
    // for sparse headers, so shell out to tar, for now.
    // https://www.gnu.org/software/tar/manual/html_node/Extensions.html#Extensions
    Command::new("tar")
        .arg("xaf")
        .arg(path)
        .arg("-C")
        .arg(tmpdir.path())
        .arg("disk.img")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    Ok(tmpdir.path().join("disk.img"))
}

fn decompress_update(path: &Path, tmpdir: &TempDir) -> Result<(PathBuf, PathBuf)> {
    // NOTE: The tar crate does not currently support extended numeric form
    // for sparse headers, so shell out to tar, for now.
    // https://www.gnu.org/software/tar/manual/html_node/Extensions.html#Extensions
    Command::new("tar")
        .arg("xaf")
        .arg(path)
        .arg("-C")
        .arg(tmpdir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    Ok((
        tmpdir.path().join("boot.img"),
        tmpdir.path().join("root.img"),
    ))
}
