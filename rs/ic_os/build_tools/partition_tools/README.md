# partition_tools

Helpers for manipulating IC-OS disk images and partitions during image build and
image-mutation workflows.

## How it works
- `ext` exposes ext4-backed partition helpers used to read and write files in
  boot/data partitions inside a disk image.
- `fat` provides the same style of API for FAT partitions such as the config
  partition.
- `gpt` and `partition` provide partition selection and low-level GPT access.
- The `extract_guestos` binary is a small image-extraction utility built on top
  of the library.

This crate is used by tools such as `setupos-image-config` and
`setupos-disable-checks` that need to patch images without booting them.
