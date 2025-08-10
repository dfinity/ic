//! Constructors and conversion from/to other types
use super::*;

impl PublicCoefficients {
    ///////////////
    // Constructors

    /// Returns the empty vector
    pub fn zero() -> Self {
        Self {
            coefficients: vec![],
        }
    }
}
