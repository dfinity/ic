use crate::numeric::BlockNumber;
use crate::state::eth_logs_scraping::BlockRangeInclusive;
use proptest::{prelude::any, prop_assume, proptest};

#[test]
fn should_be_non_overlapping() {
    let range = BlockRangeInclusive::from(1..=100_u32);

    let mut chunks = range.into_chunks(23);

    assert_eq!(chunks.next(), Some(BlockRangeInclusive::from(1..=23_u32)));
    assert_eq!(chunks.next(), Some(BlockRangeInclusive::from(24..=46_u32)));
    assert_eq!(chunks.next(), Some(BlockRangeInclusive::from(47..=69_u32)));
    assert_eq!(chunks.next(), Some(BlockRangeInclusive::from(70..=92_u32)));
    assert_eq!(chunks.next(), Some(BlockRangeInclusive::from(93..=100_u32)));
    assert_eq!(chunks.next(), None);
}

#[test]
fn should_be_one_by_one() {
    let range = BlockRangeInclusive::from(0..=4_u32);

    let mut chunks = range.into_chunks(1);

    assert_eq!(chunks.next(), Some(BlockRangeInclusive::from(0..=0_u32)));
    assert_eq!(chunks.next(), Some(BlockRangeInclusive::from(1..=1_u32)));
    assert_eq!(chunks.next(), Some(BlockRangeInclusive::from(2..=2_u32)));
    assert_eq!(chunks.next(), Some(BlockRangeInclusive::from(3..=3_u32)));
    assert_eq!(chunks.next(), Some(BlockRangeInclusive::from(4..=4_u32)));
    assert_eq!(chunks.next(), None);
}

#[test]
fn should_be_one_iteration() {
    for block in [BlockNumber::ZERO, BlockNumber::ONE, BlockNumber::MAX] {
        let singleton_range = BlockRangeInclusive::new(block, block);
        let mut chunks = singleton_range.clone().into_chunks(1);
        assert_eq!(chunks.next(), Some(singleton_range));
        assert_eq!(chunks.next(), None);
    }
}

proptest! {
    #[test]
    fn should_be_empty(chunk_size in any::<u16>()) {
        prop_assume!(chunk_size > 0);
        let empty_range = BlockRangeInclusive::new(BlockNumber::MAX, BlockNumber::ZERO);
        let mut chunks = empty_range.into_chunks(chunk_size);
        assert_eq!(chunks.next(), None);
    }
}
