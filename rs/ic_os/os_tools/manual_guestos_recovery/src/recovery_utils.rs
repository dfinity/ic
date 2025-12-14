use std::process::Command;

pub const RECOVERY_LAUNCHER_PATH: &str = "/opt/ic/bin/guestos-recovery-launcher.sh";

/// Represents a constructed recovery command.
/// Can be converted to a local Command object (for safe execution)
/// or a shell string (for remote execution via SSH).
pub struct RecoveryUpgraderCommand {
    args: Vec<String>,
}

impl RecoveryUpgraderCommand {
    pub fn to_command(&self) -> Command {
        let mut cmd = Command::new("sudo");
        cmd.arg(RECOVERY_LAUNCHER_PATH).args(&self.args);
        cmd
    }

    pub fn to_shell_string(&self) -> String {
        let escaped_args: Vec<String> = self
            .args
            .iter()
            .map(|arg| shell_escape::escape(arg.as_str().into()).to_string())
            .collect();
        format!("sudo {RECOVERY_LAUNCHER_PATH} {}", escaped_args.join(" "))
    }
}

pub fn build_recovery_upgrader_command(
    version: &str,
    version_hash: &str,
    recovery_hash: &str,
) -> RecoveryUpgraderCommand {
    let args = vec![
        format!("version={version}"),
        format!("version-hash={version_hash}"),
        format!("recovery-hash={recovery_hash}"),
    ];
    RecoveryUpgraderCommand { args }
}
