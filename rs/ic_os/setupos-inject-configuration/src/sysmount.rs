use anyhow::{anyhow, Context, Error};
use tokio::process::Command;

pub(crate) async fn mount(src: &str, dst: &str) -> Result<(), Error> {
    let out = Command::new("mount")
        .args([
            src, // source
            dst, // destination
        ])
        .output()
        .await
        .context("failed to run mount")?;

    if !out.status.success() {
        return Err(anyhow!("mount failed: {}", String::from_utf8(out.stderr)?));
    }

    Ok(())
}

pub(crate) async fn umount(dst: &str) -> Result<(), Error> {
    let out = Command::new("umount")
        .args([
            dst, // destination
        ])
        .output()
        .await
        .context("failed to run umount")?;

    if !out.status.success() {
        return Err(anyhow!("umount failed: {}", String::from_utf8(out.stderr)?));
    }

    Ok(())
}
