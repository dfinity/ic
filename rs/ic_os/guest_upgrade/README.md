# Guest Upgrade (SEV-SNP Disk Encryption Key Exchange)

This crate implements the disk encryption key exchange that occurs during GuestOS upgrades when SEV-SNP is enabled. Because the store partition's encryption key is derived from the SEV launch measurement, a new GuestOS version (with a different measurement) cannot derive the old key. This crate transfers the key from the old VM to the new one over a mutually attested channel.

## Architecture

The key exchange involves two GuestOS VMs running simultaneously on the same physical host:

- **Server** (active GuestOS): Hosted by the orchestrator. Derives the disk encryption key from its own SEV measurement and sends it to the client.
- **Client** (upgrade VM): A temporary GuestOS VM launched by the HostOS with the new image. Connects to the server, receives the key, writes it to disk, and shuts down.

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
│  │    │ derive_key()    │   │  writes key to         │  │
│  │    │ from SEV        │   │  /var/alternative_      │  │
│  │    │ measurement     │   │  store.keyfile          │  │
│  │    ▼                 │   │                        │  │
│  │  sends key ─────────►│───┼──► receives key         │  │
│  └──────────────────────┘   └────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Mutual Attestation Protocol

Both VMs attest to each other over TLS using SEV-SNP attestation reports:

1. Both sides generate ephemeral self-signed TLS certificates.
2. Both TLS public keys are hashed together and used as the attestation report's custom data field.
3. Each side generates an SEV-SNP attestation report with this custom data.
4. Each side verifies the other's report against three properties:
   - **Measurement** matches approved launch measurements from the registry.
   - **Custom data** matches the expected TLS key binding (prevents MITM/replay).
   - **Chip ID** matches the local report's chip ID (proves same physical CPU).

## Sequence

See `ic-os/docs/Upgrades.adoc` for the full upgrade sequence including the HostOS and orchestrator steps that surround this key exchange.
