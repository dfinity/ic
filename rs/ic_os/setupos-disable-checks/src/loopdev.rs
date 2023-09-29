use std::path::Path;

use anyhow::{anyhow, Context, Error};
use tokio::process::Command;

pub(crate) async fn create_loop_device(image_path: &Path) -> Result<String, Error> {
    let out = Command::new("losetup")
        .args([
            "-P",     // create a partitioned loop device
            "-f",     // find first unused device
            "--show", // print device name after setup
            &image_path.to_string_lossy(),
        ])
        .output()
        .await
        .context("failed to run losetup")?;

    if !out.status.success() {
        return Err(anyhow!(
            "losetup failed: {}",
            String::from_utf8(out.stderr)?
        ));
    }

    Ok(String::from_utf8(out.stdout)?.trim_end().to_string())
}

pub(crate) async fn detach_loop_device(device_path: &str) -> Result<(), Error> {
    let out = Command::new("losetup")
        .args([
            "--detach", // detach one or more devices
            device_path,
        ])
        .output()
        .await
        .context("failed to run losetup")?;

    if !out.status.success() {
        return Err(anyhow!(
            "losetup failed: {}",
            String::from_utf8(out.stderr)?
        ));
    }

    Ok(())
}
