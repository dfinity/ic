use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Error};
use clap::Parser;
use regex::Regex;
use tempfile::NamedTempFile;
use tokio::fs;

use partition_tools::{ext::ExtPartition, Partition};

const CHECK_DISABLER_CMDLINE_ARGS: [&str; 3] = [
    "ic.setupos.check_hardware",
    "ic.setupos.check_network",
    "ic.setupos.check_age",
];
const CHECK_INSTALL_DISABLER_CMDLINE_ARGS: [&str; 1] = ["ic.setupos.stop_before_installation"];
const SERVICE_NAME: &str = "setupos-disable-checks";

#[derive(Parser)]
#[command(name = SERVICE_NAME)]
struct Cli {
    #[arg(long, default_value = "disk.img")]
    /// Path to SetupOS disk image; its GRUB boot partition will be modified.
    image_path: PathBuf,
    #[arg(long, action)]
    /// If specified, defeats the installation routine altogether.
    defeat_installer: bool,
}

fn remove_argument(cmdline: String, argument: String) -> String {
    let replacements = [
        (argument.to_string() + "=1"),
        (argument.to_string() + "=0"),
        argument,
    ];
    let mut existing_args = cmdline.clone();
    for r in replacements.iter() {
        existing_args = existing_args.replace(r.as_str(), "");
        existing_args = existing_args.replace("  ", " ");
        existing_args = existing_args.trim_matches(' ').to_string();
    }
    existing_args
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let extra_boot_args_path = Path::new("/extra_boot_args");
    let extra_boot_args_re = Regex::new(r"EXTRA_BOOT_ARGS=(.*)").unwrap();

    // Open boot file system.
    eprintln!("Opening boot file system {}", cli.image_path.display());
    let mut bootfs = ExtPartition::open(cli.image_path, Some(5)).await?;

    // Overwrite checks.
    if cli.defeat_installer {
        eprintln!(
            "Defeating installer routine as well as age, hardware and network checks in SetupOS"
        );
    } else {
        eprintln!("Defeating age, hardware and network checks in SetupOS");
    }

    let mut to_append = "".to_string()
        + &CHECK_DISABLER_CMDLINE_ARGS
            .iter()
            .map(|x| x.to_string() + "=0")
            .collect::<Vec<String>>()
            .join(" ");
    if cli.defeat_installer {
        to_append = to_append + " " + CHECK_INSTALL_DISABLER_CMDLINE_ARGS[0];
    }

    let new_args =
        match extra_boot_args_re.captures(bootfs.read_file(extra_boot_args_path).await?.as_str()) {
            Some(captures) => {
                let mut existing_args = captures
                    .get(1)
                    .unwrap()
                    .as_str()
                    .trim_matches('"')
                    .to_string();
                for disabled in CHECK_DISABLER_CMDLINE_ARGS.iter() {
                    existing_args = remove_argument(existing_args, disabled.to_string());
                }
                if cli.defeat_installer {
                    for disabled in CHECK_INSTALL_DISABLER_CMDLINE_ARGS.iter() {
                        existing_args = remove_argument(existing_args, disabled.to_string());
                    }
                }
                existing_args.to_owned() + " " + to_append.as_str()
            }
            None => to_append,
        };

    let temp_extra_boot_args = NamedTempFile::new()?;
    fs::write(
        temp_extra_boot_args.path(),
        format!(
            "# This file has been modified by setupos-disable-checks.
EXTRA_BOOT_ARGS=\"{}\"
",
            new_args
        ),
    )
    .await
    .context("failed to write temporary extra boot args")?;
    fs::set_permissions(temp_extra_boot_args.path(), Permissions::from_mode(0o755)).await?;

    bootfs
        .write_file(temp_extra_boot_args.path(), extra_boot_args_path)
        .await?;

    eprintln!("Closing boot file system");
    bootfs.close().await?;

    Ok(())
}
