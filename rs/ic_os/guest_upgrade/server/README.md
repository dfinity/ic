# guest_upgrade_server

Server side of the GuestOS upgrade disk-encryption key exchange.

## How it works
- Runs in the currently active GuestOS, typically under orchestrator control.
- Starts a gRPC service with an ephemeral self-signed certificate.
- Verifies the Upgrade VM's attestation against the Upgrade GuestOS's expected
  launch measurement from the NNS Registry.
- Asks HostOS over vsock to start the Upgrade VM, then waits for the client to
  connect and report success or failure.
- On success, derives or loads the current store key and returns it to the
  Upgrade VM over the attested channel.

The attestation checks are intentionally strict: the peer must present a blessed
measurement, matching custom data bound to both TLS public keys, and the same
chip ID so the exchange is guaranteed to stay on the same physical host.

The main implementation lives in `service.rs`, while `orchestrator.rs` wires the
crate into the production startup path.
