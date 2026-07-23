# remote_attestation_server

gRPC service that returns a GuestOS SEV attestation package to remote callers.

## How it works
- Listens on `remote_attestation_shared::DEFAULT_PORT`.
- Accepts optional 32-byte caller-supplied custom data.
- Wraps that custom data in the `RawRemoteAttestation` namespace and asks the
  SEV guest firmware to produce an attestation package. The namespace is a
  domain-separation mechanism: it prevents a caller from obtaining an
  attestation report for one code path and replaying it into another protocol
  that interprets the same raw custom-data bytes differently.
- If SEV is not active, the service still starts but returns `Unavailable` for
  attestation requests so clients get a fast, reliable answer instead of timing
  out.

At startup the service loads `GuestOSConfig` so it can obtain the trusted
execution environment certificate chain required to build verifiable packages.

## Primary use case
This service exists mainly for remote monitoring of nodes. It allows external
checkers to verify that a node is running the expected software in a trusted
execution environment and has not been tampered with.

More generally, the attestation package gives a verifier evidence about both the
TEE itself and the launched GuestOS configuration. The measurement can be
compared against approved GuestOS releases, while the certificate chain proves
that the report came from genuine SEV-SNP hardware.