use grub::BootAlternative;
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

fn maybe_add_wipe_var_partition(args: &mut Vec<String>, wipe_var_partition: bool) {
    if wipe_var_partition {
        args.push("wipe-var-partition".to_string());
    }
}

pub fn build_recovery_upgrader_prep_command(
    version: &str,
    target_boot_alternative: BootAlternative,
    recovery_hash_prefix: &str,
    wipe_var_partition: bool,
) -> RecoveryUpgraderCommand {
    let mut args = vec![
        format!("version={version}"),
        format!("target-boot-alternative={target_boot_alternative}"),
        format!("recovery-hash-prefix={recovery_hash_prefix}"),
    ];
    maybe_add_wipe_var_partition(&mut args, wipe_var_partition);
    build_recovery_upgrader_command("prep", &args)
}

pub fn build_recovery_upgrader_install_command(
    wipe_var_partition: bool,
) -> RecoveryUpgraderCommand {
    let mut args = Vec::new();
    maybe_add_wipe_var_partition(&mut args, wipe_var_partition);
    build_recovery_upgrader_command("install", &args)
}

/// Convenience helper to perform a single-shot run (prep + install) without TUI confirmation.
pub fn build_recovery_upgrader_run_command(
    version: &str,
    recovery_hash_prefix: &str,
    target_boot_alternative: &str,
    wipe_var_partition: bool,
) -> RecoveryUpgraderCommand {
    let mut args = vec![
        format!("version={version}"),
        format!("recovery-hash-prefix={recovery_hash_prefix}"),
        format!("target-boot-alternative={target_boot_alternative}"),
    ];
    maybe_add_wipe_var_partition(&mut args, wipe_var_partition);
    build_recovery_upgrader_command("run", &args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prep_command_includes_target_boot_alternative_and_empty_recovery_hash_prefix() {
        let command = build_recovery_upgrader_prep_command("aabbcc", BootAlternative::B, "", false);

        let shell = command.to_shell_string();
        assert!(shell.contains("mode=prep"));
        assert!(shell.contains("version=aabbcc"));
        assert!(shell.contains("target-boot-alternative=B"));
        assert!(shell.contains("recovery-hash-prefix="));
    }

    #[test]
    fn prep_command_includes_recovery_hash_prefix_when_enabled() {
        let command =
            build_recovery_upgrader_prep_command("aabbcc", BootAlternative::A, "123abc", true);

        let shell = command.to_shell_string();
        assert!(shell.contains("mode=prep"));
        assert!(shell.contains("version=aabbcc"));
        assert!(shell.contains("target-boot-alternative=A"));
        assert!(shell.contains("recovery-hash-prefix=123abc"));
        assert!(shell.contains("wipe-var-partition"));
    }

    #[test]
    fn install_command_includes_wipe_var_partition_flag_when_requested() {
        let command = build_recovery_upgrader_install_command(true);

        let shell = command.to_shell_string();
        assert!(shell.contains("mode=install"));
        assert!(shell.contains("wipe-var-partition"));
    }

    #[test]
    fn run_command_includes_wipe_var_partition_flag_when_requested() {
        let command = build_recovery_upgrader_run_command("aabbcc", "123abc", "B", true);

        let shell = command.to_shell_string();
        assert!(shell.contains("mode=run"));
        assert!(shell.contains("recovery-hash-prefix=123abc"));
        assert!(shell.contains("target-boot-alternative=B"));
        assert!(shell.contains("wipe-var-partition"));
    }
}
