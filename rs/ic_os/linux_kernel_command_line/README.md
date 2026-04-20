# linux_kernel_command_line

Library for parsing and safely rewriting Linux kernel command line strings.

## How it works
- Parses a command line into a structured representation that preserves quoting
  semantics.
- Supports common mutations such as `add_argument`, `remove_argument`, and
  `ensure_single_argument`.
- Serializes back to a command line string while rejecting values that cannot be
  represented safely.

This crate is used when tooling needs to patch boot arguments without relying on
fragile string concatenation.
