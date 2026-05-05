SEV Attestation
===============

SEV-SNP attestation verification library. Parses and validates attestation packages (report + certificate chain), verifying measurements, signatures, custom data, and chip identity. Used by both the canister and OS-level attestation flows.

Folder structure:

- `proto/` contains protobuf message definitions;
- `src/proto_gen/` contains Rust code generated from protobuf messages;
- `src/` contains the main library code.

Generation of Rust files
------------------------

To regenerate the protobuf Rust files, run:

```bash
REGENERATE=1 cargo test -p attestation --test check_generated_files
```

Commit the changes.
