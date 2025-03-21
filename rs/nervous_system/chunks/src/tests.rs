use super::*;
use std::{cell::RefCell, rc::Rc};

#[test]
fn test_chunks() {
    let size = 5_000_000;

    let original_monolithic_blob = (0..size).map(|i| (13 * i + 42) as u8).collect::<Vec<_>>();

    let memory = Rc::new(RefCell::new(Vec::<u8>::new()));
    let mut chunks = Chunks::init(memory);

    let keys = chunks.upsert_monolithic_blob(original_monolithic_blob.clone());

    // The expected value is based on the chunk size being a little bit less
    // that 2e6.
    assert_eq!(keys.len(), 3, "{:#?}", keys);

    let reconstituted_monolithic_blob = keys
        .iter()
        .flat_map(|key| chunks.get_chunk(key).unwrap())
        .collect::<Vec<u8>>();
    // We do not compare blobs directly (i.e. using assert_eq), because the
    // panic message would be very spammy.
    assert_eq!(
        reconstituted_monolithic_blob.len(),
        original_monolithic_blob.len()
    );
    const SLICE_SIZE: usize = 25;
    assert_eq!(
        &reconstituted_monolithic_blob[..SLICE_SIZE],
        &original_monolithic_blob[..SLICE_SIZE],
    );
    assert_eq!(
        reconstituted_monolithic_blob[size - SLICE_SIZE..size],
        original_monolithic_blob[size - SLICE_SIZE..size],
    );
    assert!(reconstituted_monolithic_blob == original_monolithic_blob);
}
