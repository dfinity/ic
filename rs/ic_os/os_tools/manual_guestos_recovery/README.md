# manual_guestos_recovery

Interactive TUI for operator-driven GuestOS recovery on HostOS.

## How it works
- Presents a small ratatui-based form that collects a target version and,
  depending on the recovery mode, a recovery hash prefix.
- Supports two recovery modes:
  - **NNS mode**: collects a version and a 6-character recovery hash prefix.
  - **TEE mode**: collects only a version (the recovery hash prefix is not
    needed because TEE mode verifies the version hash rather than a separate
    recovery artifact).
- Lets the operator choose the target boot alternative (current or opposite
  slot) and optionally request a `var` partition wipe.
- Validates the operator input before starting any recovery action.
- Builds the underlying prep/install commands in `recovery_utils.rs`, passing
  `target-boot-alternative`, `recovery-hash-prefix`, and `wipe-var-partition`
  through to the recovery launcher.
- Streams subprocess output back into the UI so the operator can follow the
  recovery progress and failures.

This crate is launched by `hostos_tool manual-recovery`.
