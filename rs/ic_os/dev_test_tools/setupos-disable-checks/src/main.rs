use anyhow::{Context, Error};
use clap::Parser;
use regex::Regex;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use tokio::fs;

use partition_tools::{Partition, ext::ExtPartition};

const SERVICE_NAME: &str = "setupos-disable-checks";

#[derive(Parser)]
#[command(name = SERVICE_NAME)]
struct Cli {
    #[arg(long, default_value = "disk.img")]
    /// Path to SetupOS disk image; its GRUB boot partition will be modified.
    image_path: PathBuf,
}

/// Munge the kernel command line:
fn munge(input: &str) -> String {
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
                thematch.as_str().trim().trim_matches('"').to_string(),
                postmatch.as_str().to_string(),
                wholematch.end(),
            )
        }
        None => (
            input.len(),
            "".to_string(),
            "".to_string(),
            "\n".to_string(),
            input.len(),
        ),
    };

    let requires_space = !boot_args.is_empty();
    boot_args.push_str(&format!(
        "{sep}ic.setupos.run_checks=0",
        sep = if requires_space { " " } else { "" }
    ));

    format!(
        "# This file has been modified by setupos-disable-checks.\n{}{}BOOT_ARGS=\"{}\"{}{}",
        &input[..left],
        prevmatch,
        boot_args,
        postmatch,
        &input[right..],
    )
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
        munge(std::str::from_utf8(
            &bootfs.read_file(boot_args_path).await?,
        )?),
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
                r#"# This file has been modified by setupos-disable-checks.
# This file contains nothing.
BOOT_ARGS="ic.setupos.run_checks=0"
"#,
            ),
            (
                "munges the variable successfully when present",
                r#"# Hello hello.
BOOT_ARGS="security=selinux selinux=1 enforcing=0"
# Postfix.
"#,
                r#"# This file has been modified by setupos-disable-checks.
# Hello hello.
BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.run_checks=0"
# Postfix.
"#,
            ),
            (
                "munges the variable even at the beginning of the file",
                r#"BOOT_ARGS="security=selinux selinux=1 enforcing=0"
"#,
                r#"# This file has been modified by setupos-disable-checks.
BOOT_ARGS="security=selinux selinux=1 enforcing=0 ic.setupos.run_checks=0"
"#,
            ),
        ];
        for (test_name, input, expected) in table.into_iter() {
            let result = munge(input);
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
