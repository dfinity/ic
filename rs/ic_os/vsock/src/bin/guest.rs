use std::fs::OpenOptions;
use std::io::Write;

use vsock_lib::client::{LinuxVsockClient, VsockClient};
use vsock_lib::protocol::{Command as ProtocolCommand, NotifyData, Payload, UpgradeData};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

/// A CLI for sending vsock commands
#[derive(Debug, Parser)]
#[command(version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Set a custom port
    #[arg(long, default_value_t = 19090)]
    port: u32,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Request HostOS to attach the HSM to to the guest VM
    AttachHSM,
    /// Request HostOS to detach the HSM from the guest VM
    DetachHSM,
    /// Request HostOS to return its version
    #[command(name = "get-hostos-version")]
    GetHostOSVersion,
    /// Request HostOS to apply the given upgrade
    Upgrade {
        /// The download URL for a given upgrade
        #[arg(long)]
        url: String,
        /// The target hash for a given upgrade URL
        #[arg(long)]
        hash: String,
    },
    /// Request HostOS to print a given message to the host terminal
    Notify {
        /// The message to print
        message: String,

        /// The number of times to notify with the message
        #[arg(long, default_value_t = 1)]
        count: u32,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let command = match cli.command {
        Command::AttachHSM => ProtocolCommand::AttachHSM,
        Command::DetachHSM => ProtocolCommand::DetachHSM,
        Command::GetHostOSVersion => ProtocolCommand::GetHostOSVersion,
        Command::Upgrade { url, hash } => ProtocolCommand::Upgrade(UpgradeData {
            url,
            target_hash: hash,
        }),
        Command::Notify { message, count } => {
            duplicate_to_guest_console(&message);
            ProtocolCommand::Notify(NotifyData { message, count })
        }
    };

    let response = LinuxVsockClient::with_port(cli.port)
        .send_command(command)
        .context("sending command '{command}'")?;

    // Output the values directly
    match response {
        Ok(Payload::HostOSVsockVersion(version)) => println!("{version}"),
        Ok(Payload::HostOSVersion(version)) => println!("{version}"),
        Err(error) => bail!("Server responded with error: '{error:#}'"),
        _ => (),
    }

    Ok(())
}

/// Echo notify messages to the local GuestOS console so they are visible in
/// cloud environments where the host console is not accessible.
fn duplicate_to_guest_console(message: &str) {
    for path in ["/dev/tty1", "/dev/ttyS0"] {
        if let Ok(mut tty) = OpenOptions::new().write(true).open(path) {
            let _ = writeln!(tty, "\n{}", message);
        }
    }
}
