use std::fs::OpenOptions;
use std::io::Write;

use super::VSOCK_VERSION;
use crate::protocol::{NotifyData, Payload, Response};

const HOSTOS_VERSION_FILE_PATH: &str = "/opt/ic/share/version.txt";

pub(crate) fn get_hostos_version() -> Response {
    let version = std::fs::read_to_string(HOSTOS_VERSION_FILE_PATH)
        .map_err(|_| "Could not read hostOS version".to_string())?;
    let version = version.trim().to_string();

    Ok(Payload::HostOSVersion(version))
}

// HostOSVsockVersion command used for backwards compatibility
pub(crate) fn get_hostos_vsock_version() -> Response {
    Ok(Payload::HostOSVsockVersion(VSOCK_VERSION))
}

pub(crate) fn notify(notify_data: &NotifyData) -> Response {
    // Skip logging if manual recovery TUI is running to avoid interfering with the display
    if procfs::process::all_processes().is_ok_and(|processes| {
        processes.flatten().any(|process| {
            process.cmdline().is_ok_and(|args| {
                args.iter().any(|v| v.contains("hostos_tool"))
                    && args.iter().any(|v| v.contains("manual-recovery"))
            })
        })
    }) {
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
