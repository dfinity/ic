# grub

Small library for reading, updating, and atomically writing the `grubenv` block
used by IC-OS GuestOS A/B boot management.

## Role in the boot flow
`grubenv` is the persistent handoff between HostOS decisions and GuestOS A/B
boot behavior. Even though HostOS now performs direct kernel boot, it still uses
the same `boot_alternative` and `boot_cycle` state to decide which GuestOS slot
to launch and whether the node is in a rollback-sensitive first-boot phase.

## Boot-cycle transitions
- `install -> stable`
- `first_boot -> failsafe_check`
- `failsafe_check -> switch to the opposite boot alternative and mark it
  stable`

Semantically, `install` is only for the first boot in the machine's lifetime
after initial installation. `first_boot` is the post-upgrade probation state for
the selected GuestOS slot before it is considered stable.

That promotion to `stable` is done by the GuestOS which after successful boot confirms
the boot explicitly (via the `manageboot.sh confirm` flow), which writes
`boot_cycle=stable` back to `grubenv`.

This state machine is intentionally **not idempotent**: reading and refreshing
`grubenv` advances recovery state, so callers must avoid repeating the refresh
logic.

One subtle but important consequence is that callers should only persist a
refreshed `grubenv` once they know which boot path they will actually use.
`guest_vm_runner` follows this rule: it computes the refreshed state first, but
only writes it out after it has confirmed that direct boot can proceed.

## Defaults
If `grubenv` does not exist yet, the effective defaults are boot alternative `A`
and boot cycle `stable`. This matches the first-boot behavior of a newly
installed system.

## Where it is used
- `hostos_tool` to inspect or swap the active GuestOS alternative.
- `guest_vm_runner` to decide which GuestOS boot partition to launch and to
  advance the boot-cycle state machine.

HostOS owns this state because it performs the direct kernel boot via QEMU. The
kernel, initrd, and kernel command line depend on the selected GuestOS boot
alternative, so HostOS must know and manage the active alternative before it can
launch GuestOS correctly.

`hostos_tool guestos-alternative swap` is the manual override: it sets a new
target boot alternative and marks the next boot as `first_boot`, which means
the selected slot is still unconfirmed and can still fall back if that boot is
not later confirmed.
