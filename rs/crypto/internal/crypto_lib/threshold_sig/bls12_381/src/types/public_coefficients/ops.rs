//! Standard Rust operations on PublicCoefficients

use super::*;
use group::CurveProjective;
use pairing::bls12_381::Fr;
use pairing::bls12_381::G2;
use std::borrow::Borrow;
use std::iter::Sum;
use std::ops;

impl<B: Borrow<PublicCoefficients>> Sum<B> for PublicCoefficients {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = B>,
    {
        iter.fold(PublicCoefficients::zero(), |a, b| a + b)
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl<B: Borrow<PublicCoefficients>> ops::AddAssign<B> for PublicCoefficients {
    fn add_assign(&mut self, rhs: B) {
        let len = self.coefficients.len();
        let rhs_len = rhs.borrow().coefficients.len();
        if rhs_len > len {
            self.coefficients.resize(rhs_len, PublicKey(G2::zero()));
        }
        for (self_c, rhs_c) in self.coefficients.iter_mut().zip(&rhs.borrow().coefficients) {
            self_c.0.add_assign(&rhs_c.0);
        }
        self.remove_zeros();
    }
}

impl<B: Borrow<PublicCoefficients>> ops::Add<B> for PublicCoefficients {
    type Output = Self;

    fn add(mut self, rhs: B) -> Self {
        self += rhs;
        self
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl ops::MulAssign<Fr> for PublicCoefficients {
    fn mul_assign(&mut self, rhs: Fr) {
        for self_c in self.coefficients.iter_mut() {
            self_c.0.mul_assign(rhs);
        }
        self.remove_zeros();
    }
}

impl ops::Mul<Fr> for PublicCoefficients {
    type Output = Self;

    fn mul(mut self, rhs: Fr) -> Self {
        self *= rhs;
        self
    }
}
