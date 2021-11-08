//! Polynomials over `Scalar`.
//!
//! Note: This file is largely based on https://github.com/poanetwork/threshold_crypto/blob/master/src/poly.rs

use bls12_381::Scalar;
use ff::Field;
use rand_core::RngCore;
use std::iter;
use zeroize::Zeroize;

// Methods:
mod advanced_ops;
mod common_traits;
mod constructors;
mod ops;

#[cfg(test)]
pub mod arbitrary;
#[cfg(test)]
mod tests;

/// A univariate polynomial
/// Note: The polynomial terms are: coefficients[i] * x^i
///       E.g. 3 + 2x + x^2 - x^4 is encoded as:
///       Polynomial{ coefficients: [3,2,1,0,-1] }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    pub coefficients: Vec<Scalar>,
}
