use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

mod command_utilities;
mod hsm;

use crate::protocol::{
    Command, HostOSVsockVersion, NotifyData, Payload, Request, Response, UpgradeData, parse_request,
};
use command_utilities::handle_command_output;
use hsm::{attach_hsm, detach_hsm};

use ic_http_utils::file_downloader::FileDownloader;

use tokio::runtime::Runtime;
use vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

// The first CID available for guests to use. This is used later to enforce
// that only the first guest is able to connect over VSOCK, for now.
const VIR_VSOCK_GUEST_CID_MIN: u32 = 3;
const DEFAULT_PORT: u32 = 19090;

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

/// Runs the vsock server and awaits incoming vsock connections.
pub fn run_server() -> io::Result<()> {
    let vsock_listener: VsockListener = create_vsock_listener()?;

    println!("Listening for vsock connection.\n");

    for stream in vsock_listener.incoming() {
        let mut stream: VsockStream = stream?;
        stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;

        std::thread::spawn(move || -> io::Result<()> { process_connection(&mut stream) });
    }

    Ok(())
}

fn create_vsock_listener() -> io::Result<VsockListener> {
    // Only listen for the first GuestOS VM. Only type4.* nodes will have more
    // than one VM that uses VSOCK. We treat the first GuestOS as the leader in
    // charge of HostOS.
    let addr = VsockAddr::new(VMADDR_CID_ANY, DEFAULT_PORT);
    VsockListener::bind(&addr)
}

fn process_connection(stream: &mut VsockStream) -> io::Result<()> {
    let request = match get_request(stream) {
        Ok(request) => request,
        Err(err) => {
            send_response(stream, &Err(err.to_string()))?;
            return Err(err);
        }
    };
    println!("Received vsock request: {request}");

    if request.guest_cid != VIR_VSOCK_GUEST_CID_MIN {
        let err = io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "A type4 host only accepts VSOCK connections from the first VM.",
        );
        send_response(stream, &Err(err.to_string()))?;
        return Err(err);
    };

    if let Err(err) = verify_sender_cid(stream, request.guest_cid) {
        send_response(stream, &Err(err.to_string()))?;
        return Err(err);
    };

    let response: Response = dispatch(&request.command);

    send_response(stream, &response)
}

fn get_request(stream: &mut VsockStream) -> io::Result<Request> {
    let mut buffer = [0; 4096];
    let bytes_read = stream.read(&mut buffer)?;
    let json_request: String = match std::str::from_utf8(&buffer[..bytes_read]) {
        Ok(json_str_request) => json_str_request.to_string(),
        Err(error) => {
            println!("Error converting bytes to string: {error}");
            return Err(io::Error::new(io::ErrorKind::InvalidData, error));
        }
    };

    parse_request(json_request.as_str()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

// As a sanity check, we request that the sender adds its own CID to the message, and that CID must match the CID in the stream peer address.
// NOTE: The kernel vhost driver also enforces this. Any packet with a forged source is dropped.
fn verify_sender_cid(stream: &mut VsockStream, guest_cid: u32) -> io::Result<()> {
    let peer_address = match stream.peer_addr() {
        Ok(peer_address) => peer_address,
        Err(err) => {
            let error = format!("Error: could not verify the sender_cid. {err}");
            return Err(io::Error::new(io::ErrorKind::InvalidData, error));
        }
    };

    if peer_address.cid() == guest_cid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "The actual sender CID did not match the sender CID in the request object",
        ))
    }
}

fn send_response(stream: &mut VsockStream, response: &Response) -> io::Result<()> {
    let json_response = serde_json::to_string(&response)?;
    stream.write_all(json_response.as_bytes())?;

    Ok(())
}

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
        Ok(processes) => processes.into_iter().filter_map(Result::ok).any(|process| {
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

async fn upgrade_hostos(upgrade_data: &UpgradeData) -> Response {
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
