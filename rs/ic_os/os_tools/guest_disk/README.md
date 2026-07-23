# guest_disk

Handles formatting and opening the encrypted GuestOS `var` and `store`
partitions.

## Data model
- `var` is per-GuestOS-slot mutable state.
- `store` is shared persistent state that must survive upgrades.
- In TEE mode, `store` is the partition that needs explicit key migration during
  upgrade because its key continuity matters across GuestOS versions.
- `store` uses a **detached LUKS2 header** (persisted at
  `DEFAULT_STORE_LUKS_HEADER_PATH`, `/var/store_luks_header.bin`) so the 
  non-encrypted *store* header is itself stored on the encrypted var partition. 
  This provides some protection against tampering with the header.

Outside TEE mode the crate falls back to a persisted random key instead of a
measurement-derived one.

Only the sensitive data partitions are encrypted. The `var` partitions contain
mutable GuestOS state and the shared `store` partition contains persistent node
data, so both need confidentiality protection. The boot/root/config partitions
are not treated as confidential in the same way, and the root partition's
integrity is enforced separately via the measured `root_hash` + dm-verity flow
(see `open_rootfs`).

## SEV key derivation invariant
When SEV-based encryption is used, the effective disk passphrase comes from a
hardware-derived sealing key plus per-device derivation. In practice this means
the key material is tied to the node's CPU identity, the GuestOS launch
measurement, and the target device path. This ensures that:
- `var` and `store` never derive the same key,
- the two A/B `var` partitions never derive the same key,
- the same GuestOS release on two different machines still derives different
  keys,
- each encrypted device has its own separate passphrase even when the VM
  measurement is otherwise the same.

## Rollback and key migration
During an upgrade, the new GuestOS eventually adds its own derived passphrase to
the shared `store` partition's detached LUKS header without removing the
previous one. Keeping both passphrases is intentional: if the node rolls back to
the previous GuestOS slot, the old GuestOS can still derive its original
passphrase and regain access to the shared data.

The intended steady state is exactly two retained passphrases:
one for the current GuestOS and one for the previous version.

This is enforced actively: after a successful migration, the crate prunes other
store keyslots and leaves only the current and previous passphrases.
