use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Error};
use clap::Parser;
use tempfile::NamedTempFile;
use tokio::fs;

use partition_tools::{ext::ExtPartition, Partition};

const SERVICE_NAME: &str = "setupos-disable-checks";

#[derive(Parser)]
#[command(name = SERVICE_NAME)]
struct Cli {
    #[arg(long, default_value = "disk.img")]
    image_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Open rootfs partition
    println!("Opening root partition");
    let mut rootfs = ExtPartition::open(cli.image_path, Some(6)).await?;

    // Overwrite age checks
    println!("Clearing SetupOS-age checks");
    let check_setupos_age = NamedTempFile::new()?;
    fs::write(
        check_setupos_age.path(),
        indoc::formatdoc!(
            r#"
                #!/usr/bin/env bash
                echo "Skipping SetupOS-age checks."
            "#
        ),
    )
    .await
    .context("failed to write file")?;
    fs::set_permissions(check_setupos_age.path(), Permissions::from_mode(0o755)).await?;
    rootfs
        .write_file(
            check_setupos_age.path(),
            Path::new("/opt/ic/bin/check-setupos-age.sh"),
        )
        .await?;

    // Overwrite hardware checks
    println!("Clearing hardware checks");
    let hardware = NamedTempFile::new()?;
    fs::write(
        hardware.path(),
        indoc::formatdoc!(
            r#"
                #!/usr/bin/env bash
                echo "Skipping hardware checks."
            "#
        ),
    )
    .await
    .context("failed to write file")?;
    fs::set_permissions(hardware.path(), Permissions::from_mode(0o755)).await?;
    rootfs
        .write_file(hardware.path(), Path::new("/opt/ic/bin/hardware.sh"))
        .await?;

    // Overwrite network checks
    println!("Clearing network checks");
    let network = NamedTempFile::new()?;
    fs::write(
        network.path(),
        indoc::formatdoc!(
            r#"
                #!/usr/bin/env bash
                echo "Skipping network checks."
            "#
        ),
    )
    .await
    .context("failed to write file")?;
    fs::set_permissions(network.path(), Permissions::from_mode(0o755)).await?;
    rootfs
        .write_file(network.path(), Path::new("/opt/ic/bin/network.sh"))
        .await?;

    // Close rootfs partition
    println!("Closing root partition");
    rootfs.close().await?;

    Ok(())
}
