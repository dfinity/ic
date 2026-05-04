use crate::numeric::BlockNumber;
use std::fmt::{Debug, Display};
use std::ops::RangeInclusive;

#[derive(Clone, PartialEq, Eq)]
pub struct BlockRangeInclusive(RangeInclusive<BlockNumber>);

impl BlockRangeInclusive {
    pub fn new(start: BlockNumber, end: BlockNumber) -> Self {
        Self(RangeInclusive::new(start, end))
    }

    /// Destructures the `BlockRangeInclusive` into (lower bound, upper (inclusive) bound).
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_cketh_minter::numeric::{BlockNumber, BlockRangeInclusive};
    ///
    /// let start = BlockNumber::from(1_u8);
    /// let end = BlockNumber::from(5_u8);
    /// let block_range = BlockRangeInclusive::new(start, end);
    ///
    /// assert_eq!(block_range.into_inner(), (start, end));
    /// ```
    pub fn into_inner(self) -> (BlockNumber, BlockNumber) {
        self.0.into_inner()
    }

    /// Partition a block range into two non-overlapping ranges at the given block number.
    ///
    /// Returns a pair of optional block ranges as follows:
    /// 1. `(Some([start, mid - 1]), Some([mid, end]))` if `start < mid <= end`, meaning that the left partition does *not* include `mid`.
    /// 2. `(None, self)` if `mid <= start`
    /// 3. `(self, None)` if `mid > end`
    ///
    /// # Examples
    /// ```
    /// use ic_cketh_minter::numeric::BlockRangeInclusive;
    ///
    /// let block_range = BlockRangeInclusive::from(1..=5_u32);
    ///
    /// let (left, right) = block_range.clone().partition_at_checked(0_u32);
    /// assert_eq!(left, None);
    /// assert_eq!(right, Some(block_range.clone()));
    ///
    /// let (left, right) = block_range.clone().partition_at_checked(1_u32);
    /// assert_eq!(left, None);
    /// assert_eq!(right, Some(block_range.clone()));
    ///
    /// let (left, right) = block_range.clone().partition_at_checked(2_u32);
    /// assert_eq!(left, Some(BlockRangeInclusive::from(1..=1_u32)));
    /// assert_eq!(right, Some(BlockRangeInclusive::from(2..=5_u32)));
    ///
    /// let (left, right) = block_range.clone().partition_at_checked(3_u32);
    /// assert_eq!(left, Some(BlockRangeInclusive::from(1..=2_u32)));
    /// assert_eq!(right, Some(BlockRangeInclusive::from(3..=5_u32)));
    ///
    /// let (left, right) = block_range.clone().partition_at_checked(4_u32);
    /// assert_eq!(left, Some(BlockRangeInclusive::from(1..=3_u32)));
    /// assert_eq!(right, Some(BlockRangeInclusive::from(4..=5_u32)));
    ///
    /// let (left, right) = block_range.clone().partition_at_checked(5_u32);
    /// assert_eq!(left, Some(BlockRangeInclusive::from(1..=4_u32)));
    /// assert_eq!(right, Some(BlockRangeInclusive::from(5..=5_u32)));
    ///
    /// let (left, right) = block_range.clone().partition_at_checked(6_u32);
    /// assert_eq!(left, Some(block_range.clone()));
    /// assert_eq!(right, None);
    /// ```
    pub fn partition_at_checked<T: Into<BlockNumber>>(
        self,
        mid: T,
    ) -> (Option<BlockRangeInclusive>, Option<BlockRangeInclusive>) {
        let mid = mid.into();
        if &mid <= self.as_ref().start() {
            (None, Some(self))
        } else if &mid > self.as_ref().end() {
            (Some(self), None)
        } else {
            //0 <= start < mid <= end
            let (start, end) = self.0.into_inner();
            let left = BlockRangeInclusive::new(
                start,
                mid.checked_decrement()
                    .expect("BUG: mid is strictly positive"),
            );
            let right = BlockRangeInclusive::new(mid, end);
            (Some(left), Some(right))
        }
    }

    /// Partition a block range into two non-overlapping ranges at the midpoint,
    /// which is included in the first partition.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_cketh_minter::numeric::BlockRangeInclusive;
    ///
    /// let block_range = BlockRangeInclusive::from(1..=1_u8);
    /// let (left, right) = block_range.clone().partition_into_halves();
    /// assert_eq!(left, Some(block_range));
    /// assert_eq!(right, None);
    ///
    /// let block_range = BlockRangeInclusive::from(1..=2_u8);
    /// let (left, right) = block_range.partition_into_halves();
    /// assert_eq!(left, Some(BlockRangeInclusive::from(1..=1_u8)));
    /// assert_eq!(right, Some(BlockRangeInclusive::from(2..=2_u8)));
    ///
    /// let block_range = BlockRangeInclusive::from(1..=3_u8);
    /// let (left, right) = block_range.partition_into_halves();
    /// assert_eq!(left, Some(BlockRangeInclusive::from(1..=2_u8)));
    /// assert_eq!(right, Some(BlockRangeInclusive::from(3..=3_u8)));
    ///
    /// let block_range = BlockRangeInclusive::from(1..=4_u8);
    /// let (left, right) = block_range.partition_into_halves();
    /// assert_eq!(left, Some(BlockRangeInclusive::from(1..=2_u8)));
    /// assert_eq!(right, Some(BlockRangeInclusive::from(3..=4_u8)));
    /// ```
    ///
    pub fn partition_into_halves(
        self,
    ) -> (Option<BlockRangeInclusive>, Option<BlockRangeInclusive>) {
        if self.as_ref().start() >= self.as_ref().end() {
            return (Some(self), None);
        }
        // start < end <= BlockNumber::MAX
        let mid = self
            .as_ref()
            .start()
            .checked_add(
                self.as_ref()
                    .end()
                    .checked_sub(*self.as_ref().start())
                    .expect("unreachable: end > start")
                    .div_by_two(),
            )
            // mid == end - (delta - delta/2) < end,
            // where delta = end - start > 0
            .expect("unreachable: mid < end")
            .checked_increment()
            .expect("unreachable: mid <= end");
        self.partition_at_checked(mid)
    }

    /// Join two block ranges into a single range that spans both ranges.
    ///
    /// The two block ranges need not be adjacent or non-overlapping.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_cketh_minter::numeric::BlockRangeInclusive;
    ///
    /// let lower_range = BlockRangeInclusive::from(1..=3_u8);
    /// let upper_range = BlockRangeInclusive::from(4..=5_u8);
    /// assert_eq!(lower_range.clone().join_with(upper_range.clone()), BlockRangeInclusive::from(1..=5_u8));
    /// assert_eq!(upper_range.join_with(lower_range), BlockRangeInclusive::from(1..=5_u8));
    ///
    /// let lower_range = BlockRangeInclusive::from(1..=3_u8);
    /// let upper_range = BlockRangeInclusive::from(5..=10_u8);
    /// assert_eq!(lower_range.join_with(upper_range), BlockRangeInclusive::from(1..=10_u8));
    /// ```
    pub fn join_with(self, other: BlockRangeInclusive) -> BlockRangeInclusive {
        let (start, end) = self.0.into_inner();
        let (other_start, other_end) = other.0.into_inner();
        BlockRangeInclusive::new(start.min(other_start), end.max(other_end))
    }
}

impl Display for BlockRangeInclusive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..={}", self.0.start(), self.0.end())
    }
}

impl Debug for BlockRangeInclusive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl<T: Into<BlockNumber>> From<RangeInclusive<T>> for BlockRangeInclusive {
    fn from(value: RangeInclusive<T>) -> Self {
        let (start, end) = value.into_inner();
        Self(RangeInclusive::new(start.into(), end.into()))
    }
}

impl AsRef<RangeInclusive<BlockNumber>> for BlockRangeInclusive {
    fn as_ref(&self) -> &RangeInclusive<BlockNumber> {
        &self.0
    }
}

impl BlockRangeInclusive {
    pub fn into_chunks(self, chunk_size: u16) -> BlockRangeChunks {
        assert_ne!(chunk_size, 0, "chunk size must be non-zero");
        BlockRangeChunks::new(self, chunk_size)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockRangeChunks {
    range: BlockRangeInclusive,
    chunk_size: u16,
    exhausted: bool,
}

impl BlockRangeChunks {
    pub fn new(range: BlockRangeInclusive, chunk_size: u16) -> Self {
        Self {
            range,
            chunk_size,
            exhausted: false,
        }
    }
}

impl Iterator for BlockRangeChunks {
    type Item = BlockRangeInclusive;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted {
            return None;
        }
        if self.range.as_ref().is_empty() {
            self.exhausted = true;
            return None;
        }
        // start <= mid
        let mid = self
            .range
            .as_ref()
            .start()
            .checked_add(BlockNumber::from(self.chunk_size))
            .unwrap_or(BlockNumber::MAX);
        match self.range.clone().partition_at_checked(mid) {
            // start < mid <= end
            (Some(left), Some(right)) => {
                self.range = right;
                Some(left)
            }
            (Some(left), None) => {
                // start <= end < mid
                self.exhausted = true;
                Some(left)
            }
            (None, Some(right)) => {
                // mid <= start <= end,
                // but since chunk_size > 0,
                // this is only possible if start == mid == end == BlockNumber::MAX.
                self.exhausted = true;
                Some(right)
            }
            (None, None) => {
                unreachable!("BUG: partition_at_checked should not return (None, None)")
            }
        }
    }
}
