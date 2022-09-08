use crate::log::{InitError, Log, WriteError};
use crate::vec_mem::VectorMemory;
use crate::{Memory, RestrictedMemory, WASM_PAGE_SIZE};

#[test]
fn test_log_construct() {
    let log = Log::new(VectorMemory::default(), VectorMemory::default());

    assert_eq!(log.len(), 0);
    assert_eq!(log.log_size_bytes(), 0);
    assert_eq!(log.index_size_bytes(), 40);
    let (index_memory, data_memory) = log.forget();

    let log = Log::init(index_memory, data_memory).expect("failed to init log");
    assert_eq!(log.len(), 0);
    assert_eq!(log.log_size_bytes(), 0);
    assert_eq!(log.index_size_bytes(), 40);
}

#[test]
fn test_new_overwrites() {
    let log = Log::new(VectorMemory::default(), VectorMemory::default());
    log.append(b"DEADBEEF").expect("failed to append entry");

    assert_eq!(log.len(), 1);

    let (index_memory, data_memory) = log.forget();
    let log = Log::new(index_memory, data_memory);
    assert_eq!(log.len(), 0);
}

#[test]
fn test_log_init_empty() {
    let log =
        Log::init(VectorMemory::default(), VectorMemory::default()).expect("failed to init log");

    assert_eq!(log.len(), 0);
    assert_eq!(log.log_size_bytes(), 0);
    assert_eq!(log.index_size_bytes(), 40);
}

#[test]
fn test_log_init_with_different_data_magic() {
    let mem = VectorMemory::default();
    assert_eq!(mem.grow(1), 0);
    mem.write(0, b"WAS");
    let log = Log::init(VectorMemory::default(), mem).expect("failed to init log");
    assert_eq!(log.len(), 0);
}

#[test]
fn test_log_init_with_different_index_magic() {
    let index_mem = VectorMemory::default();
    assert_eq!(index_mem.grow(1), 0);
    index_mem.write(0, b"WAS");
    let data_mem = VectorMemory::default();
    assert_eq!(data_mem.grow(1), 0);
    data_mem.write(0, b"GLD\x01");
    assert_eq!(
        Log::init(index_mem, data_mem).map(|_| ()).unwrap_err(),
        InitError::InvalidIndex
    );
}

#[test]
fn test_log_load_bad_index_version() {
    let index_memory = VectorMemory::default();
    assert_eq!(index_memory.grow(1), 0);
    index_memory.write(0, b"GLI\x02");

    let data_memory = VectorMemory::default();
    assert_eq!(data_memory.grow(1), 0);
    data_memory.write(0, b"GLD\x01");
    assert_eq!(
        Log::init(index_memory, data_memory)
            .map(|_| ())
            .unwrap_err(),
        InitError::IncompatibleIndexVersion {
            last_supported_version: 1,
            decoded_version: 2
        },
    );
}

#[test]
fn test_log_load_bad_data_version() {
    let mem = VectorMemory::default();
    assert_eq!(mem.grow(1), 0);
    mem.write(0, b"GLD\x02");

    assert_eq!(
        Log::init(VectorMemory::default(), mem)
            .map(|_| ())
            .unwrap_err(),
        InitError::IncompatibleDataVersion {
            last_supported_version: 1,
            decoded_version: 2
        },
    );
}

#[test]
fn test_log_append() {
    let log = Log::new(VectorMemory::default(), VectorMemory::default());
    let idx1 = log.append(b"DEADBEEF").expect("failed to append entry");
    let idx2 = log.append(b"FEEDBAD").expect("failed to append entry");

    assert_eq!(idx1, 0);
    assert_eq!(idx2, 1);
    assert_eq!(log.len(), 2);
    assert_eq!(log.get(idx1).unwrap(), b"DEADBEEF".to_vec());
    assert_eq!(log.get(idx2).unwrap(), b"FEEDBAD".to_vec());
}

#[test]
fn test_log_append_persistence() {
    let log = Log::new(VectorMemory::default(), VectorMemory::default());
    let idx = log.append(b"DEADBEEF").expect("failed to append entry");

    let (index_memory, data_memory) = log.forget();

    let log = Log::init(index_memory, data_memory).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log.get(idx).unwrap(), b"DEADBEEF".to_vec());
    assert_eq!(log.log_size_bytes(), b"DEADBEEF".len());
    assert_eq!(log.index_size_bytes(), 48); // header (32) + num entries (8) + 1 index entry (8)
    assert_eq!(log.data_size_bytes(), 40); // header (32) + 1 entry (8)
    assert_eq!(log.get(5), None);
    assert_eq!(log.get(usize::MAX), None);
}

#[test]
fn test_append_data_out_of_memory() {
    let log = Log::new(
        VectorMemory::default(),
        RestrictedMemory::new(VectorMemory::default(), 0..1),
    );

    assert_eq!(Ok(0), log.append(b"small entry that fits into one page"));
    assert_eq!(Ok(1), log.append(b"another small entry"));
    assert_eq!(
        Err(WriteError::GrowFailed {
            current_size: 1,
            delta: 1
        }),
        log.append(&[1; WASM_PAGE_SIZE as usize])
    );
    assert_eq!(2, log.len());
}

#[test]
fn test_append_index_out_of_memory() {
    let log = Log::new(
        RestrictedMemory::new(VectorMemory::default(), 0..1),
        VectorMemory::default(),
    );

    for _ in 0..8_187 {
        log.append(b"log").expect("failed to append entry");
    }
    assert_eq!(
        Err(WriteError::GrowFailed {
            current_size: 1,
            delta: 1
        }),
        log.append(b"log")
    );
    assert_eq!(8_187, log.len());
}

#[test]
fn test_index_grow() {
    let log = Log::new(VectorMemory::default(), VectorMemory::default());
    for _ in 0..8_188 {
        log.append(b"log").expect("failed to append entry");
    }
    assert_eq!(log.index_size_bytes(), 65_544); // more than WASM_PAGE_SIZE
    let (index_memory, _) = log.forget();
    assert_eq!(index_memory.size(), 2)
}
