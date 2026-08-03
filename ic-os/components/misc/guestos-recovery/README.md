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


## `guestos-recovery-upgrader`

`guestos-recovery-upgrader.sh` runs on HostOS. It is a lightweight/manual
upgrade path that:

- stages artifacts for node operator confirmation,
- writes the new GuestOS boot/root images into the selected target slot
  (`target-boot-alternative=A|B`),
- optionally wipes the target `var` partition header (when `wipe-var-partition`
  is passed) so the recovered GuestOS can reinitialize it,
- updates `grubenv` to boot that slot as `first_boot`.

The launcher accepts `mode=<install|prep|run>`. In `install` mode only
`target-boot-alternative` and `wipe-var-partition` are relevant; in `prep`/`run`
mode a `version` and `target-boot-alternative` are required and
`recovery-hash-prefix` is optional (it may be omitted or empty in TEE mode,
where no recovery artifact is needed).

Because it writes `first_boot`, the recovered slot is still probationary until
GuestOS later confirms it as stable.

## `guestos-recovery-engine`

The recovered GuestOS image starts the `guestos-recovery-engine` service. That
service completes the logical recovery by downloading and applying the recovery
artifact inside GuestOS itself.

The recovery engine does not choose the slot or mutate the A/B boot state
directly; HostOS already did that when it prepared the recovered GuestOS boot.

### How the recovery engine is activated in the GuestOS

The `guestos-recovery-engine.service` systemd unit is installed in recovery
GuestOS images.

The activation chain is:

1. **HostOS writes the recovery hash.** Near the end of
   `guestos-recovery-upgrader.sh`, the operator-supplied recovery-hash-prefix
   is written to `/run/config/guestos_recovery_hash` on HostOS, and then
   `guestos.service` is restarted.

2. **HostOS embeds the hash into the GuestOS config.** When HostOS generates
   the GuestOS config (`generate_guestos_config()` in the config tool), it
   reads `/run/config/guestos_recovery_hash`. If the file exists and is
   non-empty, the hash prefix is placed into `recovery_config.recovery_hash`
   in the `GuestOSConfig` JSON. The file is then **deleted** to ensure
   one-time use — a subsequent normal boot will not see a recovery hash.

3. **GuestOS boots and the service starts.** The
   `guestos-recovery-engine.service` unit starts as part of
   `multi-user.target`.

4. **The engine script reads the config.** `guestos-recovery-engine.sh` calls
   `get_config_value '.recovery_config.recovery_hash'`.
   - If the value is **present**, it downloads `recovery.tar.zst` from
     `https://download.dfinity.systems/recovery/<hash_prefix>/recovery.tar.zst`
     (falling back to `download.dfinity.network`), verifies the SHA-256 hash
     prefix, extracts the archive, and applies the registry local store and
     CUP to their target paths under `/var/lib/ic/data/`.
   - If the value is **absent** (normal boot, no recovery), the script exits
     with an error. Because the service is `Type=oneshot` with no hard
     dependency from `ic-replica.service`, this does not block the normal
     GuestOS boot.
