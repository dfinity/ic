use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Error};
use clap::Parser;
use regex::Regex;
use tempfile::NamedTempFile;
use tokio::fs;

use partition_tools::{ext::ExtPartition, Partition};

const CHECK_DISABLER_CMDLINE_ARGS: &str =
    "ic.setupos.check_hardware=0 ic_setupos.check_network=0 ic.setupos.check_age=0";
const SERVICE_NAME: &str = "setupos-disable-checks";

#[derive(Parser)]
#[command(name = SERVICE_NAME)]
struct Cli {
    #[arg(long, default_value = "disk.img")]
    /// Path to SetupOS disk image; its GRUB boot partition will be modified.
    image_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let extra_boot_args_path = Path::new("/extra_boot_args");
    let extra_boot_args_re = Regex::new(r"EXTRA_BOOT_ARGS=(.*)").unwrap();

    // Open boot file system.
    eprintln!("Opening boot file system {}", cli.image_path.display());
    let mut bootfs = ExtPartition::open(cli.image_path, Some(5)).await?;

    // Overwrite age checks
    eprintln!("Clearing age, hardware and network checks in SetupOS");
    let new_args =
        match extra_boot_args_re.captures(bootfs.read_file(extra_boot_args_path).await?.as_str()) {
            Some(captures) => {
                let existing_args = captures.get(1).unwrap().as_str().trim_matches('"');
                let to_append = " ".to_owned() + CHECK_DISABLER_CMDLINE_ARGS;
                let existing_args_idempotent = existing_args.replace(to_append.as_str(), "");
                existing_args_idempotent.to_owned() + to_append.as_str()
            }
            None => CHECK_DISABLER_CMDLINE_ARGS.to_string(),
        };

    let temp_extra_boot_args = NamedTempFile::new()?;
    fs::write(
        temp_extra_boot_args.path(),
        format!(
            "# This file has been modified by setupos-disable-checks.
EXTRA_BOOT_ARGS=\"{}\"
",
            new_args
        ),
    )
    .await
    .context("failed to write temporary extra boot args")?;
    fs::set_permissions(temp_extra_boot_args.path(), Permissions::from_mode(0o755)).await?;

    bootfs
        .write_file(temp_extra_boot_args.path(), extra_boot_args_path)
        .await?;

    eprintln!("Closing boot file system");
    bootfs.close().await?;

    Ok(())
}
