# GuestOS Recovery

This directory contains the manual GuestOS recovery path used when the normal
GuestOS update flow cannot make progress, for example during NNS/subnet
recovery.

The recovery flow has two phases that intentionally span HostOS and GuestOS.

## Recovery flow

1. An operator triggers `guestos-recovery-upgrader` from the HostOS limited
   console.
2. HostOS downloads/stages the requested GuestOS update image plus the recovery
   artifact, verifies hashes, and writes the update into the inactive GuestOS
   slot.
3. HostOS sets `grubenv` to boot that slot with `boot_cycle=first_boot`, just
   like a normal GuestOS upgrade would.
4. HostOS restarts GuestOS.
5. The recovered GuestOS boots and `guestos-recovery-engine` downloads/applies
   the recovery payload (registry local store, CUP, etc.).
6. After that, the machine is back in the normal GuestOS lifecycle, including
   the usual boot confirmation / rollback behavior.

This is important: manual recovery is not a separate permanent boot mode. It
re-enters the same A/B boot-state machine as a regular GuestOS upgrade.

## `guestos-recovery-upgrader`

`guestos-recovery-upgrader.sh` runs on HostOS. It is a lightweight/manual
upgrade path that:

- stages artifacts for node operator confirmation,
- writes the new GuestOS boot/root images into the inactive slot,
- wipes the target `var` header so the recovered GuestOS can reinitialize it,
- updates `grubenv` to boot that slot as `first_boot`.

Because it writes `first_boot`, the recovered slot is still probationary until
GuestOS later confirms it as stable.

## `guestos-recovery-engine`

The recovered GuestOS image starts the `guestos-recovery-engine` service. That
service completes the logical recovery by downloading and applying the recovery
artifact inside GuestOS itself.

The recovery engine does not choose the slot or mutate the A/B boot state
directly; HostOS already did that when it prepared the recovered GuestOS boot.
