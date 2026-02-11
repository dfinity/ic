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

pub fn build_recovery_upgrader_command(mode: &str, args: &[String]) -> RecoveryUpgraderCommand {
    let mut full_args = Vec::with_capacity(args.len() + 1);
    full_args.push(format!("mode={mode}"));
    full_args.extend_from_slice(args);
    RecoveryUpgraderCommand { args: full_args }
}

pub fn build_recovery_upgrader_prep_command(
    version: &str,
    recovery_hash_prefix: &str,
) -> RecoveryUpgraderCommand {
    build_recovery_upgrader_command(
        "prep",
        &[
            format!("version={version}"),
            format!("recovery-hash-prefix={recovery_hash_prefix}"),
        ],
    )
}

pub fn build_recovery_upgrader_install_command() -> RecoveryUpgraderCommand {
    build_recovery_upgrader_command("install", &[])
}

/// Convenience helper to perform a single-shot run (prep + install) without TUI confirmation.
pub fn build_recovery_upgrader_run_command(
    version: &str,
    recovery_hash_prefix: &str,
) -> RecoveryUpgraderCommand {
    build_recovery_upgrader_command(
        "run",
        &[
            format!("version={version}"),
            format!("recovery-hash-prefix={recovery_hash_prefix}"),
        ],
    )
}
