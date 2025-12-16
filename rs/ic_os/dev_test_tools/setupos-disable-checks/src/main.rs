use anyhow::{Context, Error};
use clap::Parser;
use regex_lite::Regex;
use std::fs;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use partition_tools::{Partition, ext::ExtPartition};

#[derive(Parser)]
#[command(name = "setupos-disable-checks")]
struct Cli {
    #[arg(long, default_value = "disk.img")]
    /// Path to SetupOS disk image; its GRUB boot partition will be modified.
    image_path: PathBuf,

    // TODO: Remove with NODE-1791
    #[arg(long)]
    /// Disable old flags for temporary backwards compatibility
    compat: bool,
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let boot_args_path = Path::new("/boot_args");

    // Open boot file system.
    eprintln!("Opening boot file system {}", cli.image_path.display());
    let mut bootfs = ExtPartition::open(cli.image_path, Some(5))?;

    // Overwrite checks.
    eprintln!("Defeating age, hardware and network checks in SetupOS");

    let temp_boot_args = NamedTempFile::new()?;
    fs::write(
        temp_boot_args.path(),
        process_cmdline(
            std::str::from_utf8(&bootfs.read_file(boot_args_path)?)?,
            cli.compat,
        ),
    )
    .context("failed to write temporary boot args")?;
    fs::set_permissions(temp_boot_args.path(), Permissions::from_mode(0o755))?;

    bootfs
        .write_file(temp_boot_args.path(), boot_args_path)
        .context("failed to write boot args")?;

    eprintln!("Closing boot file system");
    bootfs.close()?;

    Ok(())
}

/// Disable checks from the kernel command line
fn process_cmdline(input: &str, compat: bool) -> String {
    let boot_args_re = Regex::new(r"(^|\n)BOOT_ARGS=(.*)(\s+#|\n|$)").unwrap();

    let left;
    let indent;
    let boot_args;
    let tail;
    let right;
    match boot_args_re.captures(input) {
        Some(captures) => {
            let whole_match = captures.get(0).unwrap();

            left = whole_match.start();
            indent = captures.get(1).unwrap().as_str();
            boot_args = captures.get(2).unwrap().as_str().trim().trim_matches('"');
            tail = captures.get(3).unwrap().as_str();
            right = whole_match.end();
        }
        None => {
            left = input.len();
            indent = "";
            boot_args = "";
            tail = "\n";
            right = input.len();
        }
    };

    let requires_space = !boot_args.is_empty();
    let mut boot_args = format!(
        "{boot_args}{sep}ic.setupos.run_checks=0",
        sep = if requires_space { " " } else { "" }
    );

    // TODO: Remove with NODE-1791
    // Disable old flags for temporary backwards compatibility
    if compat {
        boot_args = format!(
            "{boot_args} ic.setupos.check_hardware=0 ic.setupos.check_network=0 ic.setupos.check_age=0",
        );
    }

    format!(
        "# This file has been modified by setupos-disable-checks.\n{file_start}{indent}BOOT_ARGS=\"{boot_args}\"{tail}{file_end}",
        file_start = &input[..left],
        file_end = &input[right..],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test(input: &str, expected: &str) {
        let result = process_cmdline(input, false);

        assert_eq!(
            expected,
            result,
            "Result does not match expected, given input:\n input: \"{}\"",
            input.escape_debug(),
        );
    }

    #[test]
    /// Variable gets added when the file does not contain the variable
    fn cmdline_created_when_empty() {
        test(
            "# This file contains nothing.\n",
            indoc::indoc! {
                r#"
                    # This file has been modified by setupos-disable-checks.
                    # This file contains nothing.
                    BOOT_ARGS="ic.setupos.run_checks=0"
                "#,
            },
        )
    }

    #[test]
    /// Adds the variable even at the beginning of the file
    fn simple_append() {
        test(
            "BOOT_ARGS=\"security=selinux selinux=1 enforcing=0\"\n",
            indoc::indoc! {
                r#"
                    # This file has been modified by setupos-disable-checks.
                    BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.run_checks=0"
                "#
            },
        )
    }

    #[test]
    /// Adds the variable successfully with contents
    fn append_with_contents() {
        test(
            indoc::indoc! {
                r#"
                    # Hello hello.
                    BOOT_ARGS="security=selinux selinux=1 enforcing=0"
                    # Postfix.
                "#
            },
            indoc::indoc! {
                r#"
                    # This file has been modified by setupos-disable-checks.
                    # Hello hello.
                    BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.run_checks=0"
                    # Postfix.
                "#,
            },
        )
    }
}
