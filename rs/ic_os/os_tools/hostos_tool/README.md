# hostos_tool

HostOS operational CLI for network setup, metrics, manual recovery, and GuestOS
A/B control.

## How it works
- Generates deterministic HostOS/GuestOS MAC and IPv6 values from the HostOS
  config.
- Writes systemd-networkd configuration for HostOS.
- Exports the hardware-generation metric used by node monitoring.
- Launches the manual recovery TUI.
- Reads and updates the active GuestOS boot alternative through the `grub`
  crate.

If you are changing boot-alternative behavior, read `guestos_alternative.rs` in
addition to the CLI in `src/main.rs`.
