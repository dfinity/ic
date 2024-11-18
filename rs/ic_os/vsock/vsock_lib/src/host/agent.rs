use crate::host::command_utilities::handle_command_output;
use crate::host::hsm::{attach_hsm, detach_hsm};
use crate::protocol::{Command, HostOSVsockVersion, NotifyData, Payload, Response, UpgradeData};
use sha2::Digest;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

pub fn dispatch(command: &Command) -> Response {
    use Command::*;
    match command {
        AttachHSM => attach_hsm(),
        DetachHSM => detach_hsm(),
        Upgrade(upgrade_data) => upgrade_hostos(upgrade_data),
        Notify(notify_data) => notify(notify_data),
        GetVsockProtocol => get_hostos_vsock_version(),
        GetHostOSVersion => get_hostos_version(),
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

fn notify(notify_data: &NotifyData) -> Response {
    let mut terminal_device_file =
        OpenOptions::new()
            .write(true)
            .open("/dev/tty1")
            .map_err(|err| {
                println!("Error opening terminal device file: {}", err);
                err.to_string()
            })?;

    let message_output_count = std::cmp::min(notify_data.count, 10);
    let message_clone = notify_data.message.clone();

    let write_lambda = move || -> Result<(), String> {
        for _ in 0..message_output_count {
            match terminal_device_file.write_all(format!("\n{}\n", message_clone).as_bytes()) {
                Ok(_) => std::thread::sleep(std::time::Duration::from_secs(2)),
                Err(err) => return Err(err.to_string()),
            }
        }
        Ok(())
    };

    std::thread::spawn(write_lambda);

    Ok(Payload::NoPayload)
}

fn create_hostos_upgrade_file(upgrade_url: &str, file_path: &str) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .build()
        .map_err(|err| format!("Could not build download client: {}", err))?;

    let mut response = client
        .get(upgrade_url)
        .send()
        .map_err(|err| format!("Could not download url: {}", err))?;

    let mut upgrade_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(file_path)
        .map_err(|err| format!("Could not open upgrade file: {}", err))?;

    if let Err(copy_err) = std::io::copy(&mut response, &mut upgrade_file) {
        // Report on file download progress
        match upgrade_file.metadata() {
            Ok(metadata) => println!("Write error, '{}' bytes written", metadata.len()),
            Err(metadata_err) => println!("Could not check file metadata: {}", metadata_err),
        }

        return Err(format!("Could not write upgrade file: {}", copy_err));
    }

    Ok(())
}

fn verify_hash(target_hash: &str) -> Result<bool, String> {
    let mut upgrade_file = File::open(UPGRADE_FILE_PATH)
        .map_err(|err| format!("Error opening upgrade file: {}", err))?;

    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0; 65536];

    loop {
        let bytes_read = upgrade_file
            .read(&mut buffer)
            .map_err(|err| format!("Error reading upgrade file: {}", err))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let computed_hash = format!("{:x}", hasher.finalize());

    if computed_hash == target_hash {
        Ok(true)
    } else {
        Err(format!(
            "Target hash does not equal computed hash.
Target hash: {target_hash}
Computed hash: {computed_hash}"
        ))
    }
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

fn upgrade_hostos(upgrade_data: &UpgradeData) -> Response {
    // Attempt to re-use any previously downloaded upgrades, so long as the
    // hash matches.
    if verify_hash(&upgrade_data.target_hash).is_err() {
        println!("Creating hostos upgrade file...");
        create_hostos_upgrade_file(&upgrade_data.url, UPGRADE_FILE_PATH)?;

        println!("Verifying hostos upgrade file hash...");
        verify_hash(&upgrade_data.target_hash)?;
    }

    println!("Starting upgrade...");
    run_upgrade()
}
