use anyhow::{Context, Error};
use clap::Parser;
use linux_kernel_command_line::{ImproperlyQuotedValue, KernelCommandLine};
use regex::Regex;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tempfile::NamedTempFile;
use tokio::fs;

use partition_tools::{Partition, ext::ExtPartition};

const CHECK_DISABLER_CMDLINE_ARGS: [&str; 3] = [
    "ic.setupos.check_hardware",
    "ic.setupos.check_network",
    "ic.setupos.check_age",
];
const SERVICE_NAME: &str = "setupos-disable-checks";

#[derive(Parser)]
#[command(name = SERVICE_NAME)]
struct Cli {
    #[arg(long, default_value = "disk.img")]
    /// Path to SetupOS disk image; its GRUB boot partition will be modified.
    image_path: PathBuf,
}

/// Munge the kernel command line:
/// defeat_setup_checks: if true, defeat the checks; if false, ensure they are active
fn munge(
    input: &str,
    defeat_setup_checks: bool,
) -> Result<String, ImproperlyQuotedValue> {
    let boot_args_re = Regex::new(r"(^|\n)BOOT_ARGS=(.*)(\s+#|\n|$)").unwrap();
    let (left, prevmatch, mut boot_args, postmatch, right) = match boot_args_re.captures(input) {
        Some(captures) => {
            let wholematch = captures.get(0).unwrap();
            let prevmatch = captures.get(1).unwrap();
            let thematch = captures.get(2).unwrap();
            let postmatch = captures.get(3).unwrap();
            (
                wholematch.start(),
                prevmatch.as_str().to_string(),
                KernelCommandLine::from_str(thematch.as_str().trim().trim_matches('"'))?,
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
        boot_args
            .ensure_single_argument(arg, defeat_setup_checks.then_some("0"))
            .unwrap();
    }

    let boot_args_str: String = boot_args.into();

    Ok(format!(
        "# This file has been modified by setupos-disable-checks.\n{}{}BOOT_ARGS=\"{}\"{}{}",
        &input[..left],
        prevmatch,
        boot_args_str,
        postmatch,
        &input[right..],
    ))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let boot_args_path = Path::new("/boot_args");

    // Open boot file system.
    eprintln!("Opening boot file system {}", cli.image_path.display());
    let mut bootfs = ExtPartition::open(cli.image_path, Some(5)).await?;

    // Overwrite checks.
    eprintln!("Defeating age, hardware and network checks in SetupOS");

    let temp_boot_args = NamedTempFile::new()?;
    fs::write(
        temp_boot_args.path(),
        munge(
            std::str::from_utf8(&bootfs.read_file(boot_args_path).await?)?,
            true,
        )
        .context("Could not parse the BOOT_ARGS variable in the existing boot_args file")?,
    )
    .await
    .context("failed to write temporary boot args")?;
    fs::set_permissions(temp_boot_args.path(), Permissions::from_mode(0o755)).await?;

    bootfs
        .write_file(temp_boot_args.path(), boot_args_path)
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
                r#"# This file has been modified by setupos-disable-checks.
# This file contains nothing.
BOOT_ARGS="ic.setupos.check_hardware=0 ic.setupos.check_network=0 ic.setupos.check_age=0"
"#,
            ),
            (
                "munges the variable successfully when present",
                r#"# Hello hello.
BOOT_ARGS="security=selinux selinux=1 enforcing=0"
# Postfix.
"#,
                true,
                r#"# This file has been modified by setupos-disable-checks.
# Hello hello.
BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.check_hardware=0 ic.setupos.check_network=0 ic.setupos.check_age=0"
# Postfix.
"#,
            ),
            (
                "munges the variable even at the beginning of the file",
                r#"BOOT_ARGS="security=selinux selinux=1 enforcing=0"
"#,
                true,
                r#"# This file has been modified by setupos-disable-checks.
BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.check_hardware=0 ic.setupos.check_network=0 ic.setupos.check_age=0"
"#,
            ),
            (
                "checks are prevented from being defeated",
                r#"BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.check_hardware=0"
"#,
                false,
                r#"# This file has been modified by setupos-disable-checks.
BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.check_hardware ic.setupos.check_network ic.setupos.check_age"
"#,
            ),
            (
                "variables for defeat checks are set",
                r#"BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.check_hardware=0 ic.setupos.check_age"
"#,
                true,
                r#"# This file has been modified by setupos-disable-checks.
BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.check_hardware=0 ic.setupos.check_age=0 ic.setupos.check_network=0"
"#,
            ),
        ];
        for (test_name, input, defeat_checks, expected) in table.into_iter() {
            let result = munge(input, defeat_checks).unwrap();
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
