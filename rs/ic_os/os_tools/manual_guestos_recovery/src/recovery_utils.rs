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
        let escaped_args: Vec<String> = self.args.iter().map(|arg| shell_escape(arg)).collect();
        format!("sudo {RECOVERY_LAUNCHER_PATH} {}", escaped_args.join(" "))
    }
}

/// Escapes `arg` for use as a single word in a POSIX shell command line.
///
/// Arguments consisting only of `[A-Za-z0-9_=/,.+-]` are returned unchanged; anything else
/// (including the empty string) is wrapped in single quotes, with embedded `'` (and `!`, which
/// is special in interactive bash history expansion) written as `'\''` / `'\!'`.
fn shell_escape(arg: &str) -> String {
    fn is_safe(ch: char) -> bool {
        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '=' | '/' | ',' | '.' | '+')
    }

    if !arg.is_empty() && arg.chars().all(is_safe) {
        return arg.to_string();
    }

    let mut escaped = String::with_capacity(arg.len() + 2);
    escaped.push('\'');
    for ch in arg.chars() {
        match ch {
            '\'' | '!' => {
                escaped.push_str("'\\");
                escaped.push(ch);
                escaped.push('\'');
            }
            _ => escaped.push(ch),
        }
    }
    escaped.push('\'');
    escaped
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
    fn shell_escape_leaves_safe_arguments_untouched() {
        let safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+";
        assert_eq!(shell_escape(safe), safe);
        assert_eq!(shell_escape("mode=prep"), "mode=prep");
        assert_eq!(shell_escape("/opt/ic/bin/x.sh"), "/opt/ic/bin/x.sh");
    }

    #[test]
    fn shell_escape_quotes_unsafe_arguments() {
        assert_eq!(shell_escape(""), "''");
        assert_eq!(shell_escape("a b"), "'a b'");
        assert_eq!(shell_escape("a:b@c"), "'a:b@c'");
        assert_eq!(shell_escape("$HOME"), "'$HOME'");
        assert_eq!(shell_escape("it's"), r"'it'\''s'");
        assert_eq!(shell_escape("wow!"), r"'wow'\!''");
        assert_eq!(shell_escape("`rm -rf /`"), "'`rm -rf /`'");
        assert_eq!(shell_escape("a;b|c&d"), "'a;b|c&d'");
    }

    #[test]
    fn shell_string_escapes_arguments() {
        let command = build_recovery_upgrader_command("prep", &["version=a b".to_string()]);
        assert_eq!(
            command.to_shell_string(),
            format!("sudo {RECOVERY_LAUNCHER_PATH} mode=prep 'version=a b'")
        );
    }

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
