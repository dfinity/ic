# guest_vm_runner

HostOS service that prepares and launches the GuestOS virtual machine.

## Launch flow
1. Read HostOS config and decide whether to launch the normal GuestOS or the
   temporary Upgrade VM.
2. Resolve the GuestOS slot to boot from `grubenv`.
3. Prepare direct boot artifacts from that slot when available.
4. Build the libvirt domain definition and start the VM.
5. Watch the serial log for explicit boot success/failure markers.

Separately, a newly upgraded slot only becomes `stable` when GuestOS later runs
`manageboot.sh confirm` and writes that acknowledgement back
to `grubenv`.

## Boot selection and `grubenv`
HostOS owns boot selection because it is the layer that launches GuestOS through
QEMU. In direct-boot mode HostOS must pass the kernel, initrd, and kernel
command line itself, and those inputs depend on the chosen boot alternative.

Only the **default** GuestOS VM refreshes `grubenv` according to the boot-cycle
state machine. The **Upgrade VM** intentionally does not mutate `grubenv`; it
boots from the opposite slot only to stage and validate the new release without
changing the primary boot decision underneath the active node.

## Direct boot vs legacy GRUB boot
Direct boot is the preferred path because it makes the kernel, initrd, and root
hash part of the SEV launch measurement.

The fallback from direct boot to older GRUB-based boot behavior exists only for
compatibility with older GuestOS images. It is expected to disappear once all
supported GuestOS images provide the modern direct-boot artifacts.

Because refreshing `grubenv` is not idempotent, direct-boot preparation defers
writing any refreshed state until it has confirmed that the required direct-boot
artifacts are present. If the crate has to fall back to legacy GRUB boot, it
must not consume a boot-cycle transition prematurely.

## Resource model
The Upgrade VM is intentionally low‑resource because the old GuestOS continues
to run concurrently. CPU and memory allocated to the Upgrade VM are
unavailable to the active GuestOS, so the temporary VM is kept as small as practical.

Hugepages are only used when confidential computing is disabled. In the SEV path
this optimization is intentionally off because the current Linux/kernel stack in
this configuration does not support the hugepage setup needed for encrypted
guest memory.

## Upgrade VM disk mapping
Only the persistent data partition is snapshot-protected for the Upgrade VM.
The EFI/grub/config partitions are not expected to change, while the boot, root,
and var partitions are private to the new deployment anyway. Protecting the data
partition is the critical part: if anything else breaks during the temporary
Upgrade VM run, the node can still recover as long as the persistent data stays
intact.

This fits the rollback model as well: the old GuestOS should remain able to keep
serving or resume serving with access to the shared data if HostOS switches the
boot alternative back.