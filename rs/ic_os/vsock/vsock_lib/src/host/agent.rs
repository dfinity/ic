use crate::host::command_utilities::handle_command_output;
use crate::host::hsm::{attach_hsm, detach_hsm};
use crate::protocol::{
    Command, HostOSVsockVersion, NodeIdData, NotifyData, Payload, Response, UpgradeData,
};
use sha2::Digest;
use std::fs::OpenOptions;
use std::io::{Read, Write};

pub fn dispatch(command: &Command) -> Response {
    use Command::*;
    match command {
        AttachHSM => attach_hsm(),
        DetachHSM => detach_hsm(),
        SetNodeId(node_id) => set_node_id(node_id),
        Upgrade(upgrade_data) => upgrade_hostos(upgrade_data),
        Notify(notify_data) => notify(notify_data),
        GetVsockProtocol => get_hostos_vsock_version(),
        GetHostOSVersion => get_hostos_version(),
    }
}

// get_hostos_version
const HOSTOS_VERSION_FILE_PATH: &str = "/opt/ic/share/version.txt";

// set_node_id
const NODE_ID_FILE_PATH: &str = "/boot/config/node-id";
const SETUP_HOSTNAME_FILE_PATH: &str = "/opt/ic/bin/setup-hostname.sh";

// upgrade
const UPGRADE_FILE_PATH: &str = "/tmp/upgrade.tar.gz";
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

fn get_hostos_vsock_version() -> Response {
    Ok(Payload::HostOSVsockVersion(VSOCK_VERSION))
}

fn set_node_id(node_id: &NodeIdData) -> Response {
    let mut node_id_file = match OpenOptions::new().write(true).open(NODE_ID_FILE_PATH) {
        Ok(file) => file,
        Err(err) => {
            println!("Error opening file: {}", err);
            return Err(err.to_string());
        }
    };

    match node_id_file.write_all(node_id.node_id.as_bytes()) {
        Ok(_) => println!("Node ID written to file"),
        Err(err) => println!("Error writing Node ID to file: {}", err),
    }

    let command_output = std::process::Command::new(SETUP_HOSTNAME_FILE_PATH)
        .arg("--type=host")
        .output();

    handle_command_output(command_output)
}

fn notify(notify_data: &NotifyData) -> Response {
    let mut terminal_device_file = match OpenOptions::new().write(true).open("/dev/tty1") {
        Ok(file) => file,
        Err(err) => {
            println!("Error opening file: {}", err);
            return Err(err.to_string());
        }
    };

    let message_output_count = std::cmp::min(notify_data.count, 10);
    let message_clone = notify_data.message.clone();

    let write_lambda = move || -> Result<(), String> {
        println!("Thread spawned");
        for _ in 0..message_output_count {
            match terminal_device_file.write_all(format!("\n{}\n", message_clone).as_bytes()) {
                Ok(_) => std::thread::sleep(std::time::Duration::from_secs(2)),
                Err(err) => return Err(err.to_string()),
            }
        }
        Ok(())
    };

    println!("Spawning thread to write to terminal device file...");
    std::thread::spawn(write_lambda);

    Ok(Payload::NoPayload)
}

fn create_hostos_upgrade_file(upgrade_url: &str) -> Result<(), String> {
    let response =
        reqwest::blocking::get(upgrade_url).map_err(|_| "Could not download url".to_string())?;

    let hostos_upgrade_contents = response
        .bytes()
        .map_err(|_| "Could not read downloaded contents".to_string())?;

    let mut upgrade_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(UPGRADE_FILE_PATH)
        .map_err(|_| "Could not open upgrade file".to_string())?;
    upgrade_file
        .write_all(&hostos_upgrade_contents)
        .map_err(|_| "Could not write to upgrade file".to_string())?;
    upgrade_file
        .flush()
        .map_err(|_| "Could not flush upgrade file".to_string())?;

    Ok(())
}

fn verify_hash(target_hash: &str) -> Result<bool, String> {
    let mut upgrade_file = match std::fs::File::open(UPGRADE_FILE_PATH) {
        Ok(upgrade_file) => upgrade_file,
        Err(err) => return Err(err.to_string()),
    };

    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0; 65536];

    loop {
        let bytes_read = upgrade_file.read(&mut buffer).unwrap();
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

    let command_output = std::process::Command::new("reboot").output();

    handle_command_output(command_output)
}

fn upgrade_hostos(upgrade_data: &UpgradeData) -> Response {
    println!("Creating hostos upgrade file...");
    create_hostos_upgrade_file(&upgrade_data.url)?;

    println!("Verifying hostos upgrade file hash...");
    verify_hash(&upgrade_data.target_hash)?;

    println!("Starting upgrade...");
    run_upgrade()
}

/*
pub mod tests {
    #[test]
    fn create_hostos_upgrade_file_and_verify_hash() {
        use super::*;

        let upgrade_url = std::env::var("URL").unwrap_or_else(|_| "dummy url".to_string());
        let hash = std::env::var("HASH").unwrap_or_else(|_| "dummy hash".to_string());

        create_hostos_upgrade_file(&upgrade_url).unwrap();
        assert!(verify_hash(&hash).unwrap())
    }
}
*/
