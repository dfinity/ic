SEV Attestation
===============

This crate provides types and utilities for SEV-SNP attestation.

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
