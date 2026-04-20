# manual_guestos_recovery

Interactive TUI for operator-driven GuestOS recovery on HostOS.

## How it works
- Presents a small ratatui-based form that collects a target version and
  recovery hash prefix.
- Validates the operator input before starting any recovery action.
- Builds the underlying prep/install commands in `recovery_utils.rs`.
- Streams subprocess output back into the UI so the operator can follow the
  recovery progress and failures.

This crate is launched by `hostos_tool manual-recovery`.
