use crate::log::{InitError, Log, WriteError};
use crate::vec_mem::VectorMemory;
use crate::{Memory, RestrictedMemory, WASM_PAGE_SIZE};

#[test]
fn test_log_construct() {
    let log = Log::new(VectorMemory::default(), 5);

    assert_eq!(log.len(), 0);
    assert_eq!(log.size_bytes(), 0);
    assert_eq!(log.max_len(), 5);

    let mem = log.forget();

    let log = Log::init(mem, 500).expect("failed to init log");
    assert_eq!(log.len(), 0);
    assert_eq!(log.size_bytes(), 0);
    assert_eq!(log.max_len(), 5);
}

#[test]
fn test_new_overwrites() {
    let log = Log::new(VectorMemory::default(), 5);
    log.append(b"DEADBEEF").expect("failed to append entry");

    assert_eq!(log.len(), 1);
    assert_eq!(log.max_len(), 5);

    let log = Log::new(log.forget(), 500);
    assert_eq!(log.len(), 0);
    assert_eq!(log.max_len(), 500);
}

#[test]
fn test_log_init_with_different_magic() {
    let mem = VectorMemory::default();
    assert_eq!(mem.grow(1), 0);
    mem.write(0, b"WAS");
    let log = Log::init(mem, 5).expect("failed to init log");
    assert_eq!(log.len(), 0);
    assert_eq!(log.max_len(), 5);
}

#[test]
fn test_log_load_bad_version() {
    let mem = VectorMemory::default();
    assert_eq!(mem.grow(1), 0);
    mem.write(0, b"SLG\x02");

    assert_eq!(
        Log::init(mem, 5).map(|_| ()).unwrap_err(),
        InitError::IncompatibleVersion {
            last_supported_version: 1,
            decoded_version: 2
        },
    );
}

#[test]
fn test_log_append() {
    let log = Log::new(VectorMemory::default(), 5);
    let idx = log.append(b"DEADBEEF").expect("failed to append entry");

    assert_eq!(idx, 0);
    assert_eq!(log.len(), 1);
    assert_eq!(log.get(idx).unwrap(), b"DEADBEEF".to_vec());
}

#[test]
fn test_log_append_persistence() {
    let log = Log::new(VectorMemory::default(), 5);
    let idx = log.append(b"DEADBEEF").expect("failed to append entry");

    let mem = log.forget();

    let log = Log::init(mem, 10).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log.max_len(), 5);
    assert_eq!(log.get(idx).unwrap(), b"DEADBEEF".to_vec());
    assert_eq!(log.size_bytes(), b"DEADBEEF".len());
    assert_eq!(log.get(5), None);
    assert_eq!(log.get(u32::MAX as usize), None);
    assert_eq!(log.get(u32::MAX as usize + 1), None);
}

#[test]
fn test_log_append_limit() {
    let log = Log::new(VectorMemory::default(), 5);

    let mut total_size = 0;
    for i in 0..5 {
        let entry = vec![i as u8; 10];
        assert_eq!(i, log.append(&entry).unwrap());
        assert_eq!(log.len(), i + 1);
        total_size += entry.len();
        assert_eq!(log.size_bytes(), total_size);
    }

    assert_eq!(
        Err(WriteError::IndexFull { max_entries: 5 }),
        log.append(b"does not fit")
    );

    assert_eq!(log.len(), 5);
}

#[test]
fn test_append_out_of_memory() {
    let log = Log::new(RestrictedMemory::new(VectorMemory::default(), 0..1), 100);

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
