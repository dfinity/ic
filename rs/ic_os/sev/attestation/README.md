# attestation

SEV-SNP attestation verification library shared by IC-OS and canister-side
attestation flows.

## How it works
- Parses an attestation package into an attestation report plus certificate
  chain.
- Verifies the report signature and certificate chain.
- Verifies policy-specific properties such as blessed measurement, custom data,
  and chip identity.
- Exposes a fluent verification flow through the parsed package types.

The launch measurement is the core identity signal being verified: it is the
cryptographic fingerprint of how the VM was initialized, including the launch
artifacts and configuration metadata. IC-OS relies on this to bind trust to a
specific approved GuestOS release.

## Layout
- `src/attestation_package.rs`: parsing and verification entry points.
- `src/custom_data.rs`: typed namespacing for custom-data payloads.
- `src/proto_gen/`: generated protobuf bindings.

## Generation of Rust files

To regenerate the protobuf Rust files, run:

```bash
REGENERATE=1 cargo test -p attestation --test check_generated_files
```

Commit the changes.
