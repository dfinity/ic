# diroid

`diroid` generates an `e2fsdroid` `fs_config` file for a directory tree.

## How it works
- Walks the target directory tree and emits the metadata format expected by
  `e2fsdroid`.
- Merges ownership and mode information from the filesystem plus the optional
  fakeroot state file.
- Produces deterministic image-build input so Android-style filesystem tooling
  can recreate the intended metadata inside generated images.

This crate is a build-time utility; it is not part of the runtime IC-OS system.
