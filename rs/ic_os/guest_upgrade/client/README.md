# guest_upgrade_client

Client side of the GuestOS upgrade disk-encryption key exchange.

## How it works
- Runs inside the temporary Upgrade GuestOS VM.
- Reads the peer VM address from `GuestOSConfig` and connects to the running
  GuestOS over mutually-attested TLS.
- If the new VM can already open the store partition with its own SEV-derived
  key, it skips transfer and only signals success. The most common reason is
  that the same Upgrade VM was started multiple times and already has the
  necessary key material from an earlier run. Rarer cases, such as some
  downgrade paths, can also trigger this fallback.
- Otherwise it sends its attestation package, verifies the server's attestation
  against blessed measurements and matching custom data, then writes the
  received key to the previous-key path.

The previous-key file is temporary upgrade state: the Upgrade VM writes it to
its private `var` partition, then after reboot the new default GuestOS uses it
once to update the LUKS header and deletes it after the new passphrase has been
added successfully.