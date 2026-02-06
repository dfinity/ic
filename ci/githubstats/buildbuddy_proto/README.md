# BuildBuddy Protocol Buffer Definitions

These `.proto` files are vendored from the [BuildBuddy](https://github.com/buildbuddy-io/buildbuddy) repository.

## Source

Downloaded from: https://github.com/buildbuddy-io/buildbuddy/tree/master/proto

## Usage

These proto files are compiled at runtime by `query.py` using `protoc`. The proto files are stored in this repository and included as data files in the Bazel build. When `query.py` needs to call BuildBuddy's API, it compiles the proto files on-demand and imports the generated Python modules.

**Why runtime compilation?** BuildBuddy's proto files have complex external dependencies (googleapis, google/rpc, etc.) that would require significant Bazel configuration to compile statically. Runtime compilation keeps the setup simple while still using BuildBuddy's official proto definitions.

## Requirements

The `protobuf` Python package is required and listed in `/ic/requirements.in`. The `protoc` compiler must be available in the PATH.

## Updating

To update these proto files to a newer version:

```bash
cd ci/githubstats/buildbuddy_proto
curl -sL https://raw.githubusercontent.com/buildbuddy-io/buildbuddy/master/proto/target.proto -o target.proto
# Update other proto files as needed
```

After updating, rebuild the target to recompile the protos.

Note: `timestamp.proto` and `duration.proto` are not included as they are standard Google protobuf types imported from `@protobuf//src/google/protobuf`.
