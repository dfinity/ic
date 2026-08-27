use std::fs::OpenOptions;
use std::io::Write;

use super::{VSOCK_VERSION, VsockServerError};
use crate::protocol::{NotifyData, Payload};

use tokio::time::sleep;

const HOSTOS_VERSION_FILE_PATH: &str = "/opt/ic/share/version.txt";

pub(crate) fn get_hostos_version() -> Result<Payload, VsockServerError> {
    let version = std::fs::read_to_string(HOSTOS_VERSION_FILE_PATH)?
        .trim()
        .to_string();

    Ok(Payload::HostOSVersion(version))
}

// HostOSVsockVersion command used for backwards compatibility
pub(crate) fn get_hostos_vsock_version() -> Result<Payload, VsockServerError> {
    Ok(Payload::HostOSVsockVersion(VSOCK_VERSION))
}

pub(crate) async fn notify(notify_data: &NotifyData) -> Result<Payload, VsockServerError> {
    // Echo notify messages to the local GuestOS console so they are visible
    // in cloud environments where the host console is not accessible.
    for path in ["/dev/tty1", "/dev/ttyS0"] {
        if let Ok(mut tty) = OpenOptions::new().write(true).open(path) {
            let _ = writeln!(tty, "\n{}", notify_data.message);
        }
    }

    // Skip logging to host if manual recovery TUI is running to avoid interfering with the display
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
    let mut handles = Vec::new();

    for device_path in &["/dev/tty1", "/dev/ttyS0"] {
        let mut terminal_device_file = OpenOptions::new().write(true).open(device_path)?;

        let message_clone = message.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..message_output_count {
                terminal_device_file.write_all(format!("\n{message_clone}\n").as_bytes())?;
                sleep(std::time::Duration::from_secs(2)).await;
            }

            Ok::<(), VsockServerError>(())
        }));
    }

    for handle in handles {
        handle.await??;
    }

    Ok(Payload::NoPayload)
}
