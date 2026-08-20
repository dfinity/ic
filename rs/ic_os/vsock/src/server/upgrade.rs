use std::path::Path;
use std::time::Duration;

use super::command_utilities::handle_command_output;
use crate::protocol::{Payload, Response, UpgradeData};

use ic_http_utils::file_downloader::FileDownloader;

use tokio::runtime::Runtime;

const UPGRADE_FILE_PATH: &str = "/tmp/upgrade";
const INSTALL_UPGRADE_FILE_PATH: &str = "/opt/ic/bin/install-upgrade.sh";

pub(crate) fn upgrade_hostos(upgrade_data: &UpgradeData) -> Response {
    println!("Trying to fetch hostOS upgrade file from request: {upgrade_data:?}");

    println!("Starting download from: {}", upgrade_data.url);
    let file_downloader = FileDownloader::new_with_timeout(None, Duration::from_secs(120));

    Runtime::new().map_err(|e| e.to_string()).and_then(|rt| {
        rt.block_on(file_downloader.download_file(
            &upgrade_data.url,
            Path::new(UPGRADE_FILE_PATH),
            Some(upgrade_data.target_hash.to_string()),
        ))
        .map_err(|e| e.to_string())
    })?;

    println!("Download completed, starting upgrade installation...");
    let command_output = std::process::Command::new(INSTALL_UPGRADE_FILE_PATH)
        .arg(UPGRADE_FILE_PATH)
        .output();

    handle_command_output(command_output)?;

    // Schedule a reboot for +1 minute
    let command_output = std::process::Command::new("shutdown")
        .arg("--reboot")
        .output();

    handle_command_output(command_output)
}

pub(crate) fn start_upgrade_guest_vm() -> Response {
    const GUESTOS_UPGRADER_SERVICE: &str = "upgrade-guestos.service";

    match std::process::Command::new("systemctl")
        .arg("restart")
        .arg(GUESTOS_UPGRADER_SERVICE)
        .output()
    {
        Ok(output) if output.status.success() => return Ok(Payload::NoPayload),
        Ok(_) => {} // systemctl failed, fallthrough to error handling below
        Err(err) => return Err(format!("Could not start {GUESTOS_UPGRADER_SERVICE}: {err}")),
    };

    // systemctl failed, get status
    let status = std::process::Command::new("journalctl")
        .arg("status")
        .arg(GUESTOS_UPGRADER_SERVICE)
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_else(|_| format!("[Could not get {GUESTOS_UPGRADER_SERVICE} status]"));

    Err(format!(
        "Could not start {GUESTOS_UPGRADER_SERVICE}, status: {status}"
    ))
}
