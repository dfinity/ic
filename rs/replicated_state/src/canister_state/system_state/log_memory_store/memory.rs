use core::ops::{Add, Rem, Sub};

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct MemoryAddress(u64);

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct MemoryPosition(u64);

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub(crate) struct MemorySize(u64);

impl MemoryAddress {
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    pub const fn get(self) -> usize {
        self.0 as usize
    }

    pub const fn add_size(self, size: MemorySize) -> MemoryAddress {
        MemoryAddress(self.0 + size.0)
    }

    pub fn to_size(self) -> MemorySize {
        MemorySize(self.0)
    }
}

impl MemoryPosition {
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn saturating_sub(self, rhs: MemorySize) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl MemorySize {
    pub const fn new(v: u64) -> Self {
        Self(v)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    pub fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }

    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl From<u64> for MemoryAddress {
    fn from(v: u64) -> Self {
        MemoryAddress(v)
    }
}

impl From<MemoryAddress> for u64 {
    fn from(v: MemoryAddress) -> Self {
        v.0
    }
}

impl From<u64> for MemoryPosition {
    fn from(v: u64) -> Self {
        MemoryPosition(v)
    }
}

impl From<MemoryPosition> for u64 {
    fn from(v: MemoryPosition) -> Self {
        v.0
    }
}

impl From<u64> for MemorySize {
    fn from(v: u64) -> Self {
        MemorySize(v)
    }
}

impl From<MemorySize> for u64 {
    fn from(v: MemorySize) -> Self {
        v.0
    }
}

// addr + pos = addr
impl Add<MemoryPosition> for MemoryAddress {
    type Output = MemoryAddress;

    fn add(self, rhs: MemoryPosition) -> MemoryAddress {
        MemoryAddress(self.0 + rhs.0)
    }
}

// addr + size = addr
impl Add<MemorySize> for MemoryAddress {
    type Output = MemoryAddress;

    fn add(self, rhs: MemorySize) -> MemoryAddress {
        MemoryAddress(self.0 + rhs.0)
    }
}

// pos + size = pos
impl Add<MemorySize> for MemoryPosition {
    type Output = MemoryPosition;

    fn add(self, rhs: MemorySize) -> MemoryPosition {
        MemoryPosition(self.0 + rhs.0)
    }
}

// size - pos = size
impl Sub<MemoryPosition> for MemorySize {
    type Output = MemorySize;

    fn sub(self, rhs: MemoryPosition) -> MemorySize {
        MemorySize(self.0 - rhs.0)
    }
}

// (pos + size) % size = pos
impl Rem<MemorySize> for MemoryPosition {
    type Output = MemoryPosition;

    fn rem(self, rhs: MemorySize) -> MemoryPosition {
        MemoryPosition((self.0 + rhs.0) % rhs.0)
    }
}
