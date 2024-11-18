# Bazel configuration

This directory contains some bazelrc fragments that are used in different scenarios. The fragments
can be used like this:

```
bazel build --noworkspace_rc --bazelrc <fragment> --bazelrc <fragment>
```

The default `.bazelrc` loads all fragments. See the individual fragments for more information.
