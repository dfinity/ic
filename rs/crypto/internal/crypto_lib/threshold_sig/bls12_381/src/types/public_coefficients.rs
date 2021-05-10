//! Public counterpart to a polynomial.

use crate::types::PublicKey;

mod advanced_ops;
#[cfg(test)]
mod arbitrary;
mod constructors;
pub mod conversions;
mod ops;
#[cfg(test)]
pub mod tests;

/// Given a polynomial with secret coefficients <a0, ..., ak> the public
/// coefficients are the public keys <A0, ..., Ak> corresponding to those secret
/// keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicCoefficients {
    pub coefficients: Vec<PublicKey>,
}
