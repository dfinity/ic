# ic_device

Linux device and partition abstraction layer used by several IC-OS image and
boot-time tools.

## How it works
- `device_mapping` provides RAII wrappers around loop devices and device-mapper
  constructs such as linear mappings and snapshots.
- `mount` provides GPT-aware partition discovery and mounting by UUID or label.
- `io` contains lower-level Linux I/O helpers shared by the higher-level APIs.

This crate keeps low-level disk plumbing in one place so tools like
`open_rootfs` and `guest_vm_runner` do not need to implement device-mapper and
partition handling.
