# BuildBuddy Protocol Buffer Definitions

These `.proto` files are vendored from the [BuildBuddy](https://github.com/buildbuddy-io/buildbuddy) repository.

## Source

Downloaded from: https://github.com/buildbuddy-io/buildbuddy/tree/master/proto

## Usage

These proto files are compiled at build time by Bazel into Python modules (`*_pb2.py`). The proto files are stored in this repository and compiled using Bazel's `proto_library` and `py_proto_library` rules defined in [ci/githubstats/BUILD.bazel](../BUILD.bazel). When `query.py` needs to call BuildBuddy's API, it imports the pre-compiled `target_pb2` module.

## Build

The proto files are automatically compiled when you build the query tool:

```bash
bazel build //ci/githubstats:query
```

The generated `*_pb2.py` files are created in the `bazel-bin/` directory as part of the build process.

## Requirements

No runtime dependencies on `protoc` are needed. The `protobuf` Python package is required and listed in `/ic/requirements.in` for using the compiled proto modules.

## Updating

To update these proto files to a newer version:

```bash
cd ci/githubstats/buildbuddy_proto
curl -sL https://raw.githubusercontent.com/buildbuddy-io/buildbuddy/master/proto/target.proto -o target.proto
# Update other proto files as needed
```

After updating, rebuild the target to recompile the protos.

Note: `timestamp.proto` and `duration.proto` are not included as they are standard Google protobuf types imported from `@protobuf//src/google/protobuf`.
