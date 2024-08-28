#![cfg(target_os = "linux")]

use clap::{Args, Parser};
use vsock_lib::protocol::{Command, NotifyData, Payload, UpgradeData};
use vsock_lib::send_command;
fn main() -> Result<(), String> {
    let cli = Cli::parse();

    let port = cli.port;
    let command = get_command(cli)?;
    let payload = send_command(command, port)?;

    // Output the values directly
    match payload {
        Payload::HostOSVsockVersion(version) => println!("{}", version),
        Payload::HostOSVersion(version) => println!("{}", version),
        Payload::NoPayload => (),
    }

    Ok(())
}

#[derive(Parser, Debug)]
#[clap(
    version = "1.0.0",
    about = "A CLI for sending vsock commands",
    author = "DFINITY Stiftung (c) 2023"
)]
struct Cli {
    /// Request hostOS to attach the HSM to to the guest VM
    #[clap(long)]
    attach_hsm: bool,

    /// Request hostOS to detach the HSM from the guest VM
    #[clap(long)]
    detach_hsm: bool,

    /// Request hostOS to return its version
    #[clap(long)]
    get_hostos_version: bool,

    /// Set a custom port
    #[clap(long, default_value = "19090")]
    port: u32,

    #[clap(flatten)]
    notify: Notify,

    #[clap(flatten)]
    upgrade: Upgrade,
}

#[derive(Args, Debug)]
struct Notify {
    /// Request HostOS to print to the host terminal a given message COUNT number of times.
    #[clap(long, value_name = "MESSAGE")]
    notify: Option<String>,

    /// The number of times to notify the hostOS of a message
    #[clap(long, value_name = "COUNT", default_value = "1")]
    count: u32,
}

#[derive(Args, Debug)]
struct Upgrade {
    /// Request HostOS to apply the given upgrade
    #[clap(long, value_name = "URL")]
    upgrade: Option<String>,
    /// The target hash for a given upgrade URL
    #[clap(long, value_name = "HASH")]
    hash: Option<String>,
}

fn get_command(cli: Cli) -> Result<Command, String> {
    if cli.attach_hsm {
        Ok(Command::AttachHSM)
    } else if cli.detach_hsm {
        Ok(Command::DetachHSM)
    } else if cli.get_hostos_version {
        Ok(Command::GetHostOSVersion)
    } else if let Some(url) = cli.upgrade.upgrade {
        if let Some(target_hash) = cli.upgrade.hash {
            Ok(Command::Upgrade(UpgradeData { url, target_hash }))
        } else {
            Err("No target hash given for upgrade command".into())
        }
    } else if let Some(message) = cli.notify.notify {
        Ok(Command::Notify(NotifyData {
            message,
            count: cli.notify.count,
        }))
    } else {
        Err("no command matched".into())
    }
}
