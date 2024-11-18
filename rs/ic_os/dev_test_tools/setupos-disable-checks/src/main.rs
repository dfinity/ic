use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Error};
use clap::Parser;
use linux_kernel_command_line::{ImproperlyQuotedValue, KernelCommandLine};
use regex::Regex;
use tempfile::NamedTempFile;
use tokio::fs;

use partition_tools::{ext::ExtPartition, Partition};

const CHECK_DISABLER_CMDLINE_ARGS: [&str; 3] = [
    "ic.setupos.check_hardware",
    "ic.setupos.check_network",
    "ic.setupos.check_age",
];
const CHECK_INSTALL_DISABLER_CMDLINE_ARGS: [&str; 1] = ["ic.setupos.perform_installation"];
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

/// Munge the kernel command line:
/// defeat_setup_checks: if true, defeat the checks; if false, ensure they are active
/// defeat_installer: if true, disable the installer; if false, ensure the installer runs
fn munge(
    input: &str,
    defeat_setup_checks: bool,
    defeat_installer: bool,
) -> Result<String, ImproperlyQuotedValue> {
    let extra_boot_args_re = Regex::new(r"(^|\n)EXTRA_BOOT_ARGS=(.*)(\s+#|\n|$)").unwrap();
    let (left, prevmatch, mut extra_boot_args, postmatch, right) =
        match extra_boot_args_re.captures(input) {
            Some(captures) => {
                let wholematch = captures.get(0).unwrap();
                let prevmatch = captures.get(1).unwrap();
                let thematch = captures.get(2).unwrap();
                let postmatch = captures.get(3).unwrap();
                (
                    wholematch.start(),
                    prevmatch.as_str().to_string(),
                    KernelCommandLine::try_from(thematch.as_str().trim_matches('"'))?,
                    postmatch.as_str().to_string(),
                    wholematch.end(),
                )
            }
            None => (
                input.len(),
                "".to_string(),
                KernelCommandLine::default(),
                "\n".to_string(),
                input.len(),
            ),
        };

    for arg in CHECK_DISABLER_CMDLINE_ARGS.iter() {
        extra_boot_args
            .ensure_single_argument(arg, defeat_setup_checks.then_some("0"))
            .unwrap();
    }
    for arg in CHECK_INSTALL_DISABLER_CMDLINE_ARGS.iter() {
        extra_boot_args
            .ensure_single_argument(arg, defeat_installer.then_some("0"))
            .unwrap();
    }

    let extra_boot_args_str: String = extra_boot_args.into();

    Ok(format!(
        "# This file has been modified by setupos-disable-checks.\n{}{}EXTRA_BOOT_ARGS=\"{}\"{}{}",
        &input[..left],
        prevmatch,
        extra_boot_args_str,
        postmatch,
        &input[right..],
    ))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let extra_boot_args_path = Path::new("/extra_boot_args");

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

    let temp_extra_boot_args = NamedTempFile::new()?;
    fs::write(
        temp_extra_boot_args.path(),
        munge(
            bootfs.read_file(extra_boot_args_path).await?.as_str(),
            true,
            cli.defeat_installer,
        )
        .context(
            "Could not parse the EXTRA_BOOT_ARGS variable in the existing extra_boot_args file",
        )?,
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

#[cfg(test)]
mod tests {
    use crate::munge;

    #[test]
    fn test_munge() {
        let table = [
            (
                "variable gets added when the file does not contain the variable",
                r#"# This file contains nothing.
"#,
                true,
                true,
                r#"# This file has been modified by setupos-disable-checks.
# This file contains nothing.
EXTRA_BOOT_ARGS="ic.setupos.check_hardware=0 ic.setupos.check_network=0 ic.setupos.check_age=0 ic.setupos.perform_installation=0"
"#,
            ),
            (
                "munges the variable successfully when present",
                r#"# Hello hello.
EXTRA_BOOT_ARGS="security=selinux selinux=1 enforcing=0"
# Postfix.
"#,
                true,
                true,
                r#"# This file has been modified by setupos-disable-checks.
# Hello hello.
EXTRA_BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.check_hardware=0 ic.setupos.check_network=0 ic.setupos.check_age=0 ic.setupos.perform_installation=0"
# Postfix.
"#,
            ),
            (
                "munges the variable even at the beginning of the file",
                r#"EXTRA_BOOT_ARGS="security=selinux selinux=1 enforcing=0"
"#,
                true,
                true,
                r#"# This file has been modified by setupos-disable-checks.
EXTRA_BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.check_hardware=0 ic.setupos.check_network=0 ic.setupos.check_age=0 ic.setupos.perform_installation=0"
"#,
            ),
            (
                "variables for defeat installer are set, and checks are prevented from being defeated",
                r#"EXTRA_BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.check_hardware=0"
"#,
                false,
                true,
                r#"# This file has been modified by setupos-disable-checks.
EXTRA_BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.check_hardware ic.setupos.check_network ic.setupos.check_age ic.setupos.perform_installation=0"
"#,
            ),
            (
                "variables for defeat checks are set, and installer is prevented from being defeated",
                r#"EXTRA_BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.check_hardware=0 ic.setupos.check_age"
"#,
                true,
                false,
                r#"# This file has been modified by setupos-disable-checks.
EXTRA_BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.check_hardware=0 ic.setupos.check_age=0 ic.setupos.check_network=0 ic.setupos.perform_installation"
"#,
            ),
        ];
        for (test_name, input, defeat_checks, defeat_installer, expected) in table.into_iter() {
            let result = munge(input, defeat_checks, defeat_installer).unwrap();
            if result != expected {
                panic!(
                    "During test {test_name}:

Input:
[[[{input}]]]

Expected:
[[[{expected}]]]

Actual:
[[[{result}]]]
"
                );
            }
        }
    }
}
