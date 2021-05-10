This folder contains protobuf messages used by the Replica.

Folder structure:

- `def/` contains protobuf message definitions;
- `gen/` contains rust code generated from protobuf messages;
- `src/` exports generated protobuf Rust structs;
- `build.rs` controls code generation (i.e. transforms def/ => gen/).

## Generation of Rust files

Run `cargo build` inside this directory. Note that the generated files are git-ignored.
