The Internet Computer Protocol Buffers
======================================

This folder contains protobuf messages used by the Replica.

Folder structure:

- `def/` contains protobuf message definitions;
- `gen/` contains Rust code generated from protobuf messages;
- `src/` exports generated protobuf Rust structs;
- `generator/` controls code generation (i.e. transforms `def/` => `gen/`).

Generation of Rust files
------------------------

Run `bazel run generator` inside this directory, commit the changes.
