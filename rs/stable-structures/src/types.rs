use core::ops::{Add, AddAssign, Mul, Sub};

pub const NULL: Address = Address(0);

#[repr(packed)]
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd)]
pub struct Address(u64);

impl From<u64> for Address {
    fn from(addr: u64) -> Self {
        Self(addr)
    }
}

impl Address {
    pub fn get(&self) -> u64 {
        self.0
    }
}

impl Add<Bytes> for Address {
    type Output = Self;

    fn add(self, offset: Bytes) -> Self {
        Self(self.0 + offset.0)
    }
}

impl Sub<Bytes> for Address {
    type Output = Self;

    fn sub(self, offset: Bytes) -> Self {
        Self(self.0 - offset.0)
    }
}

impl AddAssign<Bytes> for Address {
    fn add_assign(&mut self, other: Bytes) {
        *self = Self(self.0 + other.0);
    }
}

#[repr(packed)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Bytes(u64);

impl From<u64> for Bytes {
    fn from(bytes: u64) -> Self {
        Self(bytes)
    }
}

// We don't implement the `From<usize>` trait as it's
// not needed and will conflict with the `From<u64>` trait.
#[allow(clippy::from_over_into)]
impl Into<usize> for Bytes {
    fn into(self) -> usize {
        self.0 as usize
    }
}

impl Add<Bytes> for Bytes {
    type Output = Self;

    fn add(self, bytes: Bytes) -> Self {
        Self(self.0 + bytes.0)
    }
}

impl Mul<Bytes> for Bytes {
    type Output = Self;

    fn mul(self, bytes: Bytes) -> Self {
        Self(self.0 * bytes.0)
    }
}

impl Mul<u64> for Bytes {
    type Output = Self;

    fn mul(self, num: u64) -> Self {
        Self(self.0 * num)
    }
}
