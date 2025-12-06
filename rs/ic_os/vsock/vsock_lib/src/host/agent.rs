use crate::host::command_utilities::handle_command_output;
use crate::host::hsm::{attach_hsm, detach_hsm};
use crate::protocol::{Command, HostOSVsockVersion, NotifyData, Payload, Response, UpgradeData};
use ic_http_utils::file_downloader::FileDownloader;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::Duration;
use tokio::runtime::Runtime;

pub fn dispatch(command: &Command) -> Response {
    use Command::*;
    match command {
        AttachHSM => attach_hsm(),
        DetachHSM => detach_hsm(),
        Upgrade(upgrade_data) => {
            let rt = Runtime::new().map_err(|e| e.to_string())?;
            rt.block_on(upgrade_hostos(upgrade_data))
        }
        Notify(notify_data) => notify(notify_data),
        GetVsockProtocol => get_hostos_vsock_version(),
        GetHostOSVersion => get_hostos_version(),
        StartUpgradeGuestVM => start_upgrade_guest_vm(),
    }
}

// get_hostos_version
const HOSTOS_VERSION_FILE_PATH: &str = "/opt/ic/share/version.txt";

// upgrade
const UPGRADE_FILE_PATH: &str = "/tmp/upgrade";
const INSTALL_UPGRADE_FILE_PATH: &str = "/opt/ic/bin/install-upgrade.sh";

const VSOCK_VERSION: HostOSVsockVersion = HostOSVsockVersion {
    major: 1,
    minor: 0,
    patch: 0,
};

fn get_hostos_version() -> Response {
    let version = std::fs::read_to_string(HOSTOS_VERSION_FILE_PATH)
        .map_err(|_| "Could not read hostOS version".to_string())?;
    let version = version.trim().to_string();

    Ok(Payload::HostOSVersion(version))
}

// HostOSVsockVersion command used for backwards compatibility
fn get_hostos_vsock_version() -> Response {
    Ok(Payload::HostOSVsockVersion(VSOCK_VERSION))
}

fn is_manual_recovery_running() -> bool {
    match procfs::process::all_processes() {
        Ok(processes) => processes.into_iter().any(|process| {
            process.cmdline().is_ok_and(|args| {
                let cmd = args.join(" ");
                cmd.contains("hostos_tool") && cmd.contains("manual-recovery")
            })
        }),
        Err(_) => false,
    }
}

fn notify(notify_data: &NotifyData) -> Response {
    // Skip logging if manual recovery TUI is running to avoid interfering with the display
    if is_manual_recovery_running() {
        return Ok(Payload::NoPayload);
    }

    let message_output_count = std::cmp::min(notify_data.count, 10);
    let message = notify_data.message.clone();

    for device_path in &["/dev/tty1", "/dev/ttyS0"] {
        let mut terminal_device_file =
            OpenOptions::new()
                .write(true)
                .open(device_path)
                .map_err(|err| {
                    println!(
                        "Error opening terminal device file {}: {}",
                        device_path, err
                    );
                    err.to_string()
                })?;

        let message_clone = message.clone();
        let write_lambda = move || -> Result<(), String> {
            for _ in 0..message_output_count {
                match terminal_device_file.write_all(format!("\n{message_clone}\n").as_bytes()) {
                    Ok(_) => std::thread::sleep(std::time::Duration::from_secs(2)),
                    Err(err) => return Err(err.to_string()),
                }
            }
            Ok(())
        };

        std::thread::spawn(write_lambda);
    }

    Ok(Payload::NoPayload)
}

async fn create_hostos_upgrade_file(
    upgrade_url: &str,
    file_path: &str,
    target_hash: &str,
) -> Result<(), String> {
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

async fn upgrade_hostos(upgrade_data: &UpgradeData) -> Response {
    println!("Trying to fetch hostOS upgrade file from request: {upgrade_data:?}");

    match create_hostos_upgrade_file(
        &upgrade_data.url,
        UPGRADE_FILE_PATH,
        &upgrade_data.target_hash,
    )
    .await
    {
        Ok(_) => {
            eprintln!("Download completed, starting upgrade installation...");
        }
        Err(e) => {
            eprintln!("Download failed: {}", e);
            return Err(e);
        }
    }

    println!("Starting upgrade...");
    run_upgrade()
}

fn start_upgrade_guest_vm() -> Response {
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
