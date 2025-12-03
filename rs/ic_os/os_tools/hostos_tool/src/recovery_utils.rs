pub fn build_recovery_upgrader_command(
    version: &str,
    version_hash: &str,
    recovery_hash: &str,
) -> String {
    format!(
        "sudo /opt/ic/bin/guestos-recovery-launcher.sh version={version} version-hash={version_hash} recovery-hash={recovery_hash}"
    )
}
