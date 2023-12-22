# rs/fuzzers

A collection of fuzzers for external dependencies used in the IC stack. When adding fuzzers for a new external crate, follow the following directory structure.

```
├── bitcoin
│   ├── BUILD.bazel
│   └── fuzz_targets
│       ├── deserialize_bitcoin_block.rs
│       ├── deserialize_bitcoin_raw_network_message.rs
│       └── deserialize_bitcoin_transaction.rs
└── candid
    ├── BUILD.bazel
    └── fuzz_targets
        ├── candid_parser.rs
        └── candid_type_decoder.rs
```