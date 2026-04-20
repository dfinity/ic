# open_rootfs

Boot-time helper that opens the GuestOS root filesystem with dm-verity.

## How it works
- Reads the base `root_hash` from the kernel cmdline (`/proc/cmdline`).
- Tries to open the root device with `veritysetup` using that hash.
- If that fails on a SEV node, it attempts the recovery path: verify an
  alternative GuestOS proposal and extract the recovery rootfs hash.
- Recovery verification uses SEV guest firmware attestation helpers before
  trusting that fallback hash.
- On non-SEV nodes, there is no recovery path here: failure to open with the
  base `root_hash` remains a failure.

## Recovery trust model
On SEV nodes, the fallback recovery rootfs hash comes from an NNS proposal.
`open_rootfs` cryptographically verifies that proposal before trusting the
recovery hash, so the trust anchor is a signed NNS proposal.

The key constraint is that recovery must preserve the original SEV launch
measurement so the node can still derive the same disk-sealing keys. In practice
that means the recovery flow keeps the original kernel, initrd, and kernel
command line, while allowing an NNS-approved alternative rootfs to be mounted
after the proposal has been verified.

## When recovery is used
This path exists only on SEV nodes, and only for the rare case where the normal
GuestOS encoded in the current measurement cannot boot successfully. In that
situation the node falls back to a recovery OS rather than trusting the broken
local rootfs.

This is emergency behavior, not a normal upgrade mechanism. The recovery image
is intended to be community-approved, targeted, and rare.

The core logic lives in `run()`, which is designed to be testable by injecting
the SEV firmware provider, command runner, and partition provider.
