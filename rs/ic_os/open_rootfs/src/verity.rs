use anyhow::{Context, Result, ensure};
use command_runner::CommandRunner;
use std::path::Path;
use std::process::Command;

const VERITY_HASH_OFFSET: u64 = 10603200512;

/// Execute veritysetup command with the given device and hash
pub fn veritysetup(device: &Path, hash: &str, command_runner: &dyn CommandRunner) -> Result<()> {
    eprintln!(
        "Running veritysetup verify for device {:?} with hash {hash}",
        device
    );
    let verify_output = command_runner
        .output(
            Command::new("veritysetup")
                .arg("verify")
                .arg(device)
                .arg(device)
                .arg(hash)
                .arg("--hash-offset")
                .arg(VERITY_HASH_OFFSET.to_string()),
        )
        .context("Failed to execute veritysetup verify")?;

    ensure!(
        verify_output.status.success(),
        "veritysetup verify failed: {verify_output:?}"
    );

    let open_output = command_runner
        .output(
            Command::new("veritysetup")
                .arg("open")
                .arg(device)
                .arg("vroot")
                .arg(device)
                .arg(hash)
                .arg("--hash-offset")
                .arg(VERITY_HASH_OFFSET.to_string()),
        )
        .context("Failed to execute veritysetup open")?;

    ensure!(
        open_output.status.success(),
        "veritysetup open failed: {open_output:?}"
    );

    Ok(())
}
