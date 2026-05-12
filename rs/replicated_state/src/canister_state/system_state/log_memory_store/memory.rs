use std::ops::{Add, Mul, Rem, Sub};

/// `MemoryAddress` is an absolute address in the log memory store PageMap.
///
/// It is used to read/write data from/to the memory store.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Debug)]
pub(super) struct MemoryAddress(u64);
const _: () = assert!(std::mem::size_of::<MemoryAddress>() == 8);

impl MemoryAddress {
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    pub const fn get(&self) -> u64 {
        self.0
    }

    pub const fn add_size(&self, size: MemorySize) -> Self {
        Self(self.0 + size.0)
    }
}

// address + position = address
impl Add<MemoryPosition> for MemoryAddress {
    type Output = Self;
    fn add(self, rhs: MemoryPosition) -> Self {
        Self(self.0 + rhs.0)
    }
}

// address + size = address
impl Add<MemorySize> for MemoryAddress {
    type Output = Self;
    fn add(self, rhs: MemorySize) -> Self {
        Self(self.0 + rhs.0)
    }
}

/// `MemoryPosition` represents a position in the data region of the log memory store.
///
/// It is used to manage the head and tail positions of the circular buffer where log records are stored.
/// Belongs in the range of [0, data_capacity), and wraps around when it reaches the end of the data region.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Debug)]
pub(super) struct MemoryPosition(u64);
const _: () = assert!(std::mem::size_of::<MemoryPosition>() == 8);

impl MemoryPosition {
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    pub const fn get(&self) -> u64 {
        self.0
    }
}

// position + size = position
impl Add<MemorySize> for MemoryPosition {
    type Output = Self;
    fn add(self, rhs: MemorySize) -> Self {
        Self(self.0 + rhs.0)
    }
}

// position % size = position
impl Rem<MemorySize> for MemoryPosition {
    type Output = Self;
    fn rem(self, rhs: MemorySize) -> Self {
        Self(self.0 % rhs.0)
    }
}

/// `MemorySize` represents the size of a memory region in the log memory store.
///
/// It is used to manage the capacity and size of the data region in the memory store,
/// where log records are stored in a circular buffer manner.
#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Debug)]
pub(super) struct MemorySize(u64);
const _: () = assert!(std::mem::size_of::<MemorySize>() == 8);

impl MemorySize {
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    pub const fn get(&self) -> u64 {
        self.0
    }

    pub const fn saturating_add(&self, other: MemorySize) -> MemorySize {
        MemorySize::new(self.0.saturating_add(other.0))
    }

    pub const fn saturating_sub(&self, other: MemorySize) -> MemorySize {
        MemorySize::new(self.0.saturating_sub(other.0))
    }
}

// size + size = size
impl Add<MemorySize> for MemorySize {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

// size - size = size
impl Sub<MemorySize> for MemorySize {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0)
    }
}

// k * size = size
impl Mul<MemorySize> for u64 {
    type Output = MemorySize;
    fn mul(self, rhs: MemorySize) -> MemorySize {
        MemorySize(self * rhs.0)
    }
}
