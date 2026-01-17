SEV Attestation
===============

This crate provides types and utilities for SEV-SNP attestation.

Folder structure:

- `proto/` contains protobuf message definitions;
- `src/proto_gen/` contains Rust code generated from protobuf messages;
- `src/` contains the main library code.

Generation of Rust files
------------------------

From the repository root, run:

```bash
bazel build //rs/ic_os/sev/attestation:build_script
cp bazel-bin/rs/ic_os/sev/attestation/build_script.out_dir/attestation.rs rs/ic_os/sev/attestation/src/proto_gen/
```

Commit the changes.
