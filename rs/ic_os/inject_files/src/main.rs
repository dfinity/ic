use std::env;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use tokio::process::Command;

use partition_tools::{
    ext::{ExtPartition, FileContexts},
    Partition,
};

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    index: Option<usize>,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    file_contexts: Option<PathBuf>,
    #[arg(long)]
    prefix: Option<PathBuf>,
    #[arg(long)]
    dflate: PathBuf,
    extra_files: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let temp_dir = PathBuf::from(env::var("ICOS_TEMP_DIR")
        .context("ICOS_TEMP_DIR should be set in BUILD script.")?);
    let temp_file = temp_dir.join("partition.img");

    // TODO: Quick hack to unpack and repack file
    let mut cmd = Command::new("tar");
    let _ = cmd
        .arg("xf")
        .arg(cli.input)
        .arg("-C")
        .arg(temp_dir.as_path())
        .status()
        .await;

    let mut target = ExtPartition::open(temp_file.clone(), cli.index).await?;

    let contexts = cli
        .file_contexts
        .map(|v| {
            let contents = std::fs::read_to_string(v)?;

            FileContexts::new(&contents)
        })
        .transpose()?;

    for file in cli.extra_files {
        let mut components = file.split(':');
        let (source_file, install_target, target_mode) =
            (|| Some((components.next()?, components.next()?, components.next()?)))()
                .ok_or(anyhow!("invalid file format: '{file}'"))?;

        let source_file = Path::new(source_file);
        let install_target = Path::new(install_target);
        let target_mode = usize::from_str_radix(target_mode, 8)?;

        // Include the file type in the mode. Always use "regular file" for now.
        let inode_mode = target_mode | 0x8000;

        let context = contexts
            .as_ref()
            .map(|v| {
                if let Some(prefix) = &cli.prefix {
                    v.lookup_context_with_prefix(install_target, prefix)
                } else {
                    v.lookup_context(install_target)
                }
            })
            .transpose()?;

        target.write_file(source_file, install_target).await?;
        target
            .fixup_metadata(install_target, inode_mode, context)
            .await?;
    }

    // Close data partition
    target.close().await?;

    // TODO: Quick hack to unpack and repack file
    // We use our tool, dflate, to quickly create a sparse, deterministic, tar.
    // If dflate is ever misbehaving, it can be replaced with:
    // tar cf <output> --sort=name --owner=root:0 --group=root:0 --mtime="UTC 1970-01-01 00:00:00" --sparse --hole-detection=raw -C <context_path> <item>
    let temp_tar = temp_dir.join("partition.tar");
    let mut cmd = Command::new(cli.dflate);
    let _ = cmd
        .arg("--input")
        .arg(&temp_file)
        .arg("--output")
        .arg(&temp_tar)
        .status()
        .await;

    let mut cmd = Command::new("zstd");
    let _ = cmd
        .arg("-q")
        .arg("--threads=0")
        .arg(&temp_tar)
        .arg("-o")
        .arg(cli.output)
        .status()
        .await;

    Ok(())
}
