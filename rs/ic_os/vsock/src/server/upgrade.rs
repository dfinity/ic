use std::path::Path;
use std::time::Duration;

use super::VsockServerError;
use crate::protocol::{Payload, UpgradeData};

use ic_http_utils::file_downloader::FileDownloader;

const UPGRADE_FILE_PATH: &str = "/tmp/upgrade";
const INSTALL_UPGRADE_FILE_PATH: &str = "/opt/ic/bin/install-upgrade.sh";

pub(crate) async fn upgrade_hostos(
    upgrade_data: &UpgradeData,
) -> Result<Payload, VsockServerError> {
    println!("Starting download from: {}...", upgrade_data.url);
    let file_downloader = FileDownloader::new_with_timeout(None, Duration::from_secs(120));

    file_downloader
        .download_file(
            &upgrade_data.url,
            Path::new(UPGRADE_FILE_PATH),
            Some(upgrade_data.target_hash.to_string()),
        )
        .await?;

    println!("Download completed, starting upgrade installation...");
    let command_output = std::process::Command::new(INSTALL_UPGRADE_FILE_PATH)
        .arg(UPGRADE_FILE_PATH)
        .output()
        .map_err(VsockServerError::io(format!(
            "running command '{INSTALL_UPGRADE_FILE_PATH}'"
        )))?;

    if !command_output.status.success() {
        return Err(VsockServerError::CommandFailed {
            command: INSTALL_UPGRADE_FILE_PATH.to_string(),
            stderr: String::from_utf8_lossy(&command_output.stderr).into_owned(),
        });
    };

    // Schedule a reboot for +1 minute
    let command_output = std::process::Command::new("shutdown")
        .arg("--reboot")
        .output()
        .map_err(VsockServerError::io(
            "running command 'shutdown'".to_string(),
        ))?;

    if !command_output.status.success() {
        return Err(VsockServerError::CommandFailed {
            command: "shutdown".to_string(),
            stderr: String::from_utf8_lossy(&command_output.stderr).into_owned(),
        });
    }

    Ok(Payload::NoPayload)
}

pub(crate) fn start_upgrade_guest_vm() -> Result<Payload, VsockServerError> {
    const GUESTOS_UPGRADER_SERVICE: &str = "upgrade-guestos.service";

    let output = std::process::Command::new("systemctl")
        .arg("restart")
        .arg(GUESTOS_UPGRADER_SERVICE)
        .output()
        .map_err(VsockServerError::io(
            "running command 'systemctl restart'".to_string(),
        ))?;

    if output.status.success() {
        return Ok(Payload::NoPayload);
    }

    // systemctl failed, get status
    let status = std::process::Command::new("journalctl")
        .arg("status")
        .arg(GUESTOS_UPGRADER_SERVICE)
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_else(|_| format!("[Could not get {GUESTOS_UPGRADER_SERVICE} status]"));

    Err(VsockServerError::UpgraderService(status))
}
