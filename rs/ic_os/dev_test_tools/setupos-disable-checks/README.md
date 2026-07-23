# setupos-disable-checks

Developer utility that patches a SetupOS disk image so boot-time validation
checks are disabled.

## How it works
- Opens the SetupOS boot partition from the image using `partition_tools`.
- Reads the `BOOT_ARGS` entry from `/boot_args`.
- Uses `linux_kernel_command_line` to disable SetupOS checks with `ic.setupos.run_checks=0`.
- Writes the modified file back into the image.

This is intentionally a dev/test-only tool because it weakens SetupOS safety
checks.
