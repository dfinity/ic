use std::fs::OpenOptions;
use std::io::Write;

use super::{VSOCK_VERSION, VsockServerError};
use crate::protocol::{NotifyData, Payload};

use tokio::time::sleep;
use tokio_util::task::TaskTracker;

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

pub(crate) async fn notify(
    notify_data: &NotifyData,
    tracker: TaskTracker,
) -> Result<Payload, VsockServerError> {
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
    let message_clone = notify_data.message.clone();

    tracker.spawn(async move {
        if let Err(e) = notify_task(message_clone, message_output_count).await {
            println!("notify task failed: {e:#}")
        }
    });

    Ok(Payload::NoPayload)
}

async fn notify_task(message: String, message_output_count: u32) -> Result<(), VsockServerError> {
    for _ in 0..message_output_count {
        for device_path in &["/dev/tty1", "/dev/ttyS0"] {
            let mut terminal_device_file = OpenOptions::new().write(true).open(device_path)?;
            terminal_device_file.write_all(format!("\n{message}\n").as_bytes())?;
        }
        sleep(std::time::Duration::from_secs(2)).await;
    }

    Ok(())
}
