# Guest Upgrade (SEV-SNP Disk Encryption Key Exchange)

This crate implements the disk encryption key exchange that occurs during
GuestOS upgrades when SEV-SNP is enabled. Because the store partition's
encryption key is derived from the SEV launch measurement, a new GuestOS
version (with a different measurement) cannot derive the old key. This crate
transfers the key and the detached Store LUKS header from the old VM to the
new one over a mutually attested channel.

The launch measurement captures the GuestOS launch inputs, including the kernel,
initrd, and kernel command line. Since the kernel command line also carries the
expected rootfs hash, even a root filesystem change results in a different
measurement and therefore a different sealing key.

## Upgrade flow
The key exchange involves two GuestOS VMs running simultaneously on the same
physical host:

- **Server**: the currently active GuestOS, typically started by orchestrator.
- **Client**: the temporary Upgrade VM launched by HostOS from the other boot alternative.

The flow is:
1. HostOS launches the low-resource Upgrade VM.
2. The Upgrade VM and the active GuestOS mutually attest over TLS.
3. The active GuestOS shares the current `store` key and the detached Store
   LUKS header only if the Upgrade VM proves it is an approved GuestOS running
   on the same physical host.
4. The Upgrade VM stores the previous key and the Store LUKS header in its
   private `var` partition and shuts down.
5. After reboot into the new default GuestOS, that VM uses the previous key to
   reopen `store`, adds its own new passphrase, and deletes the temporary previous-key file.

The Upgrade VM is intentionally low‑resource because the old GuestOS continues
to run concurrently. CPU and memory allocated to the Upgrade VM are
unavailable to the active GuestOS, so the temporary VM is kept as small as practical.

HostOS is responsible for launching the Upgrade VM, but it is not trusted to
vouch for what software is actually running there or whether disk key material
should be released. That is precisely why this flow relies on the trusted
execution environment: the trust decision stays inside GuestOS and is based on
registry-published measurements plus direct attestation of the peer VM, not on
host claims.


```
┌─────────────────────────────────────────────────────────┐
│ HostOS                                                  │
│                                                         │
│  ┌──────────────────────┐   ┌────────────────────────┐  │
│  │ Active GuestOS       │   │ Upgrade VM (new)       │  │
│  │                      │   │                        │  │
│  │  Orchestrator        │   │  guest_upgrade_client   │  │
│  │    │                 │   │    │                    │  │
│  │    ▼                 │   │    │                    │  │
│  │  guest_upgrade_server│◄──┼────┘                    │  │
│  │    │                 │   │                        │  │
│  │    │ derive_key()    │   │  writes key + LUKS     │  │
│  │    │ from SEV        │   │  header to /var/       │  │
│  │    │ measurement     │   │  alternative_store.*   │  │
│  │    ▼                 │   │                        │  │
│  │  sends key + ───────►│───┼──► receives key +      │  │
│  │  LUKS header         │   │  LUKS header           │  │
│  └──────────────────────┘   └────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Mutual Attestation Protocol

Both VMs attest to each other over TLS using SEV-SNP attestation reports:

1. Both sides generate ephemeral self-signed TLS certificates.
2. Both TLS public keys are hashed together and used as the attestation report's custom data field.
3. Each side generates an SEV-SNP attestation report with this custom data.
4. Each side verifies the other's report against three properties:
   - **Measurement** matches the elected (approved) launch measurements from the
     registry.
   - **Custom data** matches the expected TLS key binding, proving that both
     ends of the TLS channel are the TEEs that generated the reports and
     preventing replay or MITM attacks.
   - **Chip ID** matches the local report's chip ID, proving that both VMs are
     running on the same physical host/CPU rather than on two different nodes.

This means the active GuestOS does not have to trust HostOS to correctly report
which image it launched, or even to behave honestly in general. The whole point
of the TEE is to keep those trust decisions anchored in attested GuestOS launch
state rather than in the host. The old GuestOS verifies the new GuestOS
directly before releasing any shared-disk secret.

## Why the client sometimes skips transfer
Sometimes the Upgrade VM can already open the store partition (using the
detached LUKS header and either the previous key or its own derived key) without
fetching a key from the active GuestOS. The most common reason is that the same
Upgrade VM was started more than once and already has the necessary key material
from an earlier run. In that case the client short-circuits the transfer and
only reports success so the server-side flow can complete cleanly.

There can also be rarer cases, such as some downgrade paths, where the Upgrade
VM can already open the store with its own derived key.

## Previous-key and LUKS-header lifecycle
The Upgrade VM does **not** add its own derived passphrase to the LUKS header
while the old GuestOS is still running, because two VMs writing to the same disk
state in parallel could corrupt it. Instead, the Upgrade VM stores the previous
key and a detached copy of the Store LUKS header in its private `var` partition.
After reboot, when that VM becomes the default GuestOS, it uses the previous key
together with the detached LUKS header to open `store`, adds its own passphrase,
and then deletes the temporary previous-key file.

After this migration step, both the previous and new passphrases remain present
in the LUKS header. This is intentional and supports rollback: if the new
GuestOS later fails to boot, HostOS can switch `boot_alternative` back to the
previous slot and the old GuestOS can still derive its old passphrase and reopen
the shared `store` partition.

The intended steady state is to retain exactly two `store` passphrases: one for
the current GuestOS and one for the previous version.

## Rollback model
The upgrade flow is designed so the node can return to the previous GuestOS
either immediately after a failed upgrade attempt or later if the new version
turns out to be bad in practice. Preserving the previous boot alternative and
keeping the old `store` passphrase valid are both part of that rollback story.

## Sequence
The registry is the source of truth for approved GuestOS measurements. During
release/upgrade rollout, the expected measurement is published ahead of time, so
the old GuestOS can verify that the Upgrade VM is running an approved release
before releasing any disk key material.

See `ic-os/docs/Upgrades.adoc` for the full upgrade sequence including the
HostOS and orchestrator steps that surround this key exchange.
