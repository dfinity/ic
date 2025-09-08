//! This test is run as an integration test so that it runs as it's own process.
//! This is required to use /proc to count open file descriptors without
//! interference from other tests running in the same process.

use std::fs::read_dir;

use ic_config::embedders::Config;
use ic_embedders::{CompilationCacheBuilder, WasmtimeEmbedder, wasm_utils::compile};
use ic_logger::no_op_logger;
use ic_wasm_types::{BinaryEncodedWasm, CanisterModule};

fn count_open_fds() -> usize {
    read_dir("/proc/self/fd").unwrap().count()
}

/// With a limit of 1000 entries in the cache we expect it to have about 2000
/// open file descriptors when full.
#[test]
fn check_file_descriptors() {
    const COUNT: usize = 1_000;

    let cache = CompilationCacheBuilder::new()
        .with_max_entries(COUNT)
        .build();

    let serialized = compile(
        &WasmtimeEmbedder::new(Config::default(), no_op_logger()),
        &BinaryEncodedWasm::new(wat::parse_str("(module)").unwrap()),
    )
    .1
    .unwrap()
    .1;

    // Insert 1000 entries to the cache.
    for i in 0..1_000_u64 {
        cache.insert_ok(
            &CanisterModule::new(i.to_le_bytes().to_vec()),
            serialized.clone(),
        );
    }
    let open_fds = count_open_fds();
    // We should have at least 2 file descriptors open per entry.
    assert!(
        open_fds > 1000,
        "Number of open file descriptors {open_fds} is less than the expected 100."
    );
    // We should not have more than 2000 open file descriptors (with some wiggle room).
    assert!(
        open_fds < 2000 + 5,
        "Number of open file descriptors {open_fds} is greater than the expected 2000 + epsilon."
    );

    // Insert 1000 new entries to the cache.
    for i in 1_000..2_000_u64 {
        cache.insert_ok(
            &CanisterModule::new(i.to_le_bytes().to_vec()),
            serialized.clone(),
        );
    }
    let open_fds = count_open_fds();
    // We should not have more than 2000 open file descriptors (with some wiggle room).
    assert!(
        open_fds < 2000 + 5,
        "Number of open file descriptors {open_fds} is greater than the expected 2000 + epsilon."
    );
}
