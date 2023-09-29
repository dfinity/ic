use std::path::PathBuf;

use anyhow::{Context, Error};
use clap::Parser;
use loopdev::{create_loop_device, detach_loop_device};
use sysmount::{mount, umount};
use tempfile::tempdir;
use tokio::fs;

mod loopdev;
mod sysmount;

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

    // Create a loop device
    let device_path = create_loop_device(&cli.image_path)
        .await
        .context("failed to create loop device")?;

    let rootfs_partition_path = format!("{device_path}p6");

    // Mount rootfs partition
    let target_dir = tempdir().context("failed to create temporary dir")?;

    mount(
        &rootfs_partition_path,               // source
        &target_dir.path().to_string_lossy(), // target
    )
    .await
    .context("failed to mount partition")?;

    // Overwrite hardware checks
    fs::write(
        target_dir.path().join("opt/ic/bin/hardware.sh"), // path
        indoc::formatdoc!(
            r#"
                #!/usr/bin/env bash
                echo "Skipping hardware checks."
            "#
        ),
    )
    .await
    .context("failed to write file")?;

    // Overwrite network checks
    fs::write(
        target_dir.path().join("opt/ic/bin/network.sh"), // path
        indoc::formatdoc!(
            r#"
                #!/usr/bin/env bash
                echo "Skipping network checks."
            "#
        ),
    )
    .await
    .context("failed to write file")?;

    // Unmount partition
    umount(&target_dir.path().to_string_lossy())
        .await
        .context("failed to unmount partition")?;

    // Detach loop device
    detach_loop_device(&device_path)
        .await
        .context("failed to detach loop device")?;

    Ok(())
}
