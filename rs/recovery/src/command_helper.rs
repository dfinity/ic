//! Various helper methods enabling execution and piping of system commands.
use crate::error::{RecoveryError, RecoveryResult};
use std::convert::TryInto;
use std::process::Command;
use std::process::Stdio;

/// Execute ALL given commands in a blocking manner by creating pipes between
/// them. Execution will fail if ANY [Command] fails. Optionally return the
/// output of the last command if it exists and execution was successful.
pub fn pipe_all(cmds: &mut [Command]) -> RecoveryResult<Option<String>> {
    for i in 1..cmds.len() {
        let (l, r) = cmds.split_at_mut(i);
        pipe(&mut l[i - 1], &mut r[0])?;
    }
    if let Some(cmd) = cmds.last_mut() {
        return exec_cmd(cmd);
    }
    Ok(None)
}

/// Create a pipe between commands by executing the FIRST [Command] blockingly
/// and, if successful, set its output as the input of the second [Command]
/// WITHOUT executing it.
pub fn pipe(a: &mut Command, b: &mut Command) -> RecoveryResult<()> {
    let mut cmd_a = a
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| RecoveryError::cmd_error(a, format!("Could not spawn: {:?}", e)))?;

    let b_stdin: Stdio = cmd_a
        .stdout
        .take()
        .ok_or_else(|| {
            RecoveryError::cmd_error(a, "Could not create pipe: stdout is None".to_string())
        })?
        .try_into()
        .map_err(|e| RecoveryError::cmd_error(a, format!("Could not create pipe: {:?}", e)))?;

    b.stdin(b_stdin).stdout(Stdio::piped());

    let output = cmd_a.wait_with_output();
    let output = output
        .map_err(|e| RecoveryError::cmd_error(a, format!("Failed to execute command: {:?}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr)
            .map_err(|e| RecoveryError::cmd_error(a, format!("Could not get stderr: {:?}", e)))?;
        return Err(RecoveryError::cmd_error(a, stderr));
    }

    Ok(())
}

/// Execute the given system [Command] in a blocking manner. Optionally return
/// the commands output if it exists and execution was successful.
pub fn exec_cmd(command: &mut Command) -> RecoveryResult<Option<String>> {
    let output = command
        .output()
        .map_err(|e| RecoveryError::cmd_error(command, format!("Could not execute: {:?}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr).map_err(|e| {
            RecoveryError::cmd_error(command, format!("Could not get stderr: {:?}", e))
        })?;
        return Err(RecoveryError::cmd_error(command, stderr));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| RecoveryError::cmd_error(command, format!("Could not get stdout: {:?}", e)))?;

    Ok(Some(stdout).filter(|s| !s.is_empty()))
}
