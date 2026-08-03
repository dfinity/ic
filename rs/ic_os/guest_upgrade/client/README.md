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
  against the elected launch measurements and matching custom data, then
  persists the received key and Store LUKS header.

The received artifacts are temporary: the Upgrade VM writes the
previous key and the detached Store LUKS header to its private `var` partition.
After reboot the new default GuestOS uses the
previous key and detached header once to update the LUKS header and deletes the
temporary previous-key file after the new passphrase has been added successfully.