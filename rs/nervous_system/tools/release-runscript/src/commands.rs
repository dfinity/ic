use crate::utils::input_yes_or_no;
use anyhow::Result;
use itertools::Itertools;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub(crate) fn run_script(
    script: PathBuf,
    args: &[&str],
    cwd: &PathBuf,
) -> Result<std::process::Output> {
    loop {
        let output = Command::new(&script).args(args).current_dir(cwd).output()?;

        if output.status.success() {
            return Ok(output);
        } else {
            let command_str = format!(
                "{} {}",
                script.display(),
                args.iter().map(|s| format!("\"{s}\"")).join(" ")
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Script failed: {stderr}");
            eprintln!("Failed to run command: {command_str}");
            if input_yes_or_no("Do you want to try again?", true)? {
                continue;
            } else {
                return Err(anyhow::anyhow!("{}\n{}", stdout, stderr)
                    .context(format!("Failed to run command: {command_str}")));
            }
        }
    }
}

pub(crate) fn run_script_in_current_process(
    script: PathBuf,
    args: &[&str],
    cwd: &PathBuf,
) -> Result<std::process::Output> {
    loop {
        let output = Command::new(&script)
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()?;

        if output.status.success() {
            return Ok(output);
        } else {
            let command_str = format!(
                "{} {}",
                script.display(),
                args.iter().map(|s| format!("\"{s}\"")).join(" ")
            );
            // we can't read stdout or stderr here because it's piped to the current process
            eprintln!("Script failed :(");
            eprintln!("Failed to run command: {command_str}");
            if input_yes_or_no("Do you want to try again?", true)? {
                continue;
            } else {
                return Err(anyhow::anyhow!("Failed to run command: {}", command_str));
            }
        }
    }
}
