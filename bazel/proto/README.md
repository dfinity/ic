To update the protos
1. Copy the relevant protos from https://github.com/buildbuddy-io/buildbuddy/tree/master/proto
1. Edit the import fields to prefix the import paths with `bazel/` e.g. `proto/foo.proto` -> `bazel/proto/foo.proto`

The source of truth for these protobufs files lives in the Bazel repo: https://github.com/bazelbuild/bazel

Unfortunately, it's difficult to either vendor or reference directly from the third party sources.
1. In the Bazel repo, the Java protobuf definitions are marked public, but their proto_library are private. 
1. The Buildbuddry repo includes targets to generate typescript protos, a dependency we don't want to include into our workspace.
1. Furthermore, Gazelle does not seem to know how to import and generate build files for those protobufs definitions.
