use serde::Serialize;
use std::{fmt, ops::Add};

/// Represents the content length of an http request. The ContentLength is
/// a scalar value that represents the number of bytes (octets) in the
/// payload of the request. This does not include header sizes.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct ContentLength(u64);

impl ContentLength {
    /// Returns a zero lengths content length
    pub fn zero() -> ContentLength {
        ContentLength(0)
    }

    /// Creates a new content length from a number of bytes
    pub fn new(bytes: u64) -> ContentLength {
        ContentLength(bytes)
    }

    /// Returns the bytes associated with the content length
    pub fn bytes(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for ContentLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const GIGS: u64 = 1024 * 1024 * 1024;
        const MEGS: u64 = 1024 * 1024;
        const KILO: u64 = 1024;

        if self.0 > GIGS {
            write!(f, "{:0.2} GB", self.0 as f64 / GIGS as f64)?;
        } else if self.0 > MEGS {
            write!(f, "{:0.2} MB", self.0 as f64 / MEGS as f64)?;
        } else if self.0 > KILO {
            write!(f, "{:0.2} KB", self.0 as f64 / KILO as f64)?;
        } else {
            write!(f, "{} B", self.0)?;
        }
        Ok(())
    }
}

impl Add for ContentLength {
    type Output = ContentLength;

    fn add(self, rhs: ContentLength) -> ContentLength {
        ContentLength(self.0 + rhs.0)
    }
}

impl<'a> Add for &'a ContentLength {
    type Output = ContentLength;

    fn add(self, rhs: &ContentLength) -> ContentLength {
        ContentLength(self.0 + rhs.0)
    }
}

impl<'a> Add<&'a ContentLength> for ContentLength {
    type Output = ContentLength;

    fn add(self, rhs: &ContentLength) -> ContentLength {
        ContentLength(self.0 + rhs.0)
    }
}

impl<'a> Add<ContentLength> for &'a ContentLength {
    type Output = ContentLength;

    fn add(self, rhs: ContentLength) -> ContentLength {
        ContentLength(self.0 + rhs.0)
    }
}
