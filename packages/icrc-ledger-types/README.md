# ICRC Ledger Types

This package defines types for interacting with the [DFINITY](https://dfinity.org/) implementation of the
[ICRC-1](https://github.com/dfinity/ICRC-1/tree/2e693e153dfa2afd9242cdbd82a8cd688fcfc4e5/standards/ICRC-1),
[ICRC-2](https://github.com/dfinity/ICRC-1/tree/2e693e153dfa2afd9242cdbd82a8cd688fcfc4e5/standards/ICRC-2), and
[ICRC-3](https://github.com/dfinity/ICRC-1/tree/2e693e153dfa2afd9242cdbd82a8cd688fcfc4e5/standards/ICRC-3) fungible
token standards.

## Features

With the default feature, or with the `storable` feature explicitly enabled, the library includes
`impl Storable for Account`, and a dependency on `ic-stable-structures`. To remove this dependency,
use the `no_storable` feature. This allows users of this library to independently choose the version of
`ic-stable-structures` to depend on (if any).
