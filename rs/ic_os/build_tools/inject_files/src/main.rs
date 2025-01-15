use std::fs;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::Parser;

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

    fs::copy(cli.input, &cli.output)?;
    fs::set_permissions(&cli.output, Permissions::from_mode(0o600))?;

    // let temp_dir = PathBuf::from(
    //     env::var("ICOS_TMPDIR").context("ICOS_TMPDIR should be set in BUILD script.")?,
    // );
    // let temp_file = temp_dir.join("partition.img");
    let mut target = ExtPartition::open(cli.output.clone(), cli.index)
        .await
        .context(format!(
            "Failed to open partition file {}",
            cli.output.clone().display()
        ))?;

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

        target
            .write_file(source_file, install_target)
            .await
            .context(format!(
                "Could not write file {} to {} in partition file {}",
                source_file.display(),
                install_target.display(),
                cli.output.clone().display(),
            ))?;
        target
            .fixup_metadata(install_target, inode_mode, context)
            .await
            .context(format!(
                "Could not fix up metadata of file {} in partition file {}",
                install_target.display(),
                cli.output.clone().display(),
            ))?;
    }

    // Close data partition
    target.close().await?;

    Ok(())
}
