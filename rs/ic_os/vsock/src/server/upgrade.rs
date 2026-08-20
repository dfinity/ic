use std::path::Path;
use std::time::Duration;

use super::command_utilities::handle_command_output;
use crate::protocol::{Payload, Response, UpgradeData};

use ic_http_utils::file_downloader::FileDownloader;

// upgrade
const UPGRADE_FILE_PATH: &str = "/tmp/upgrade";
const INSTALL_UPGRADE_FILE_PATH: &str = "/opt/ic/bin/install-upgrade.sh";

async fn create_hostos_upgrade_file(
    upgrade_url: &str,
    file_path: &str,
    target_hash: &str,
) -> Result<(), String> {
    println!("Starting download from: {}", upgrade_url);
    let file_downloader = FileDownloader::new_with_timeout(None, Duration::from_secs(120));

    file_downloader
        .download_file(
            upgrade_url,
            Path::new(file_path),
            Some(target_hash.to_string()),
        )
        .await
        .map_err(|e| e.to_string())
}

fn run_upgrade() -> Response {
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

pub(crate) async fn upgrade_hostos(upgrade_data: &UpgradeData) -> Response {
    println!("Trying to fetch hostOS upgrade file from request: {upgrade_data:?}");

    create_hostos_upgrade_file(
        &upgrade_data.url,
        UPGRADE_FILE_PATH,
        &upgrade_data.target_hash,
    )
    .await?;

    println!("Download completed, starting upgrade installation...");
    run_upgrade()
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
