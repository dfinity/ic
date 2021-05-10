//! Standard arithmetic operations such as addition

use super::common_traits::zeroize_fr;
use super::*;
use ff::Field;
use std::borrow::Borrow;
use std::iter::Sum;
use std::ops;

#[cfg(test)]
mod tests;

impl<B: Borrow<Polynomial>> Sum<B> for Polynomial {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = B>,
    {
        iter.fold(Polynomial::zero(), |a, b| a + b)
    }
}

impl<B: Borrow<Polynomial>> ops::AddAssign<B> for Polynomial {
    fn add_assign(&mut self, rhs: B) {
        let len = self.coefficients.len();
        let rhs_len = rhs.borrow().coefficients.len();
        if rhs_len > len {
            self.coefficients.resize(rhs_len, Fr::zero());
        }
        for (self_c, rhs_c) in self.coefficients.iter_mut().zip(&rhs.borrow().coefficients) {
            Field::add_assign(self_c, rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Polynomial>> ops::Add<B> for &'a Polynomial {
    type Output = Polynomial;

    fn add(self, rhs: B) -> Polynomial {
        (*self).clone() + rhs
    }
}

impl<B: Borrow<Polynomial>> ops::Add<B> for Polynomial {
    type Output = Polynomial;

    fn add(mut self, rhs: B) -> Polynomial {
        self += rhs;
        self
    }
}

impl<'a> ops::Add<Fr> for Polynomial {
    type Output = Polynomial;

    fn add(mut self, rhs: Fr) -> Self::Output {
        if !rhs.is_zero() {
            if self.is_zero() {
                self.coefficients.push(rhs);
            } else {
                self.coefficients[0].add_assign(&rhs);
                self.remove_zeros();
            }
        }
        self
    }
}

impl<B: Borrow<Polynomial>> ops::SubAssign<B> for Polynomial {
    fn sub_assign(&mut self, rhs: B) {
        let len = self.coefficients.len();
        let rhs_len = rhs.borrow().coefficients.len();
        if rhs_len > len {
            self.coefficients.resize(rhs_len, Fr::zero());
        }
        for (self_c, rhs_c) in self.coefficients.iter_mut().zip(&rhs.borrow().coefficients) {
            Field::sub_assign(self_c, rhs_c);
        }
        self.remove_zeros();
    }
}

impl<'a, B: Borrow<Polynomial>> ops::Sub<B> for &'a Polynomial {
    type Output = Polynomial;

    fn sub(self, rhs: B) -> Polynomial {
        (*self).clone() - rhs
    }
}

impl<B: Borrow<Polynomial>> ops::Sub<B> for Polynomial {
    type Output = Polynomial;

    fn sub(mut self, rhs: B) -> Polynomial {
        self -= rhs;
        self
    }
}

// Clippy thinks using `+` in a `Sub` implementation is suspicious.
#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a> ops::Sub<Fr> for Polynomial {
    type Output = Polynomial;

    fn sub(self, mut rhs: Fr) -> Self::Output {
        rhs.negate();
        self + rhs
    }
}

// Clippy thinks using any `+` and `-` in a `Mul` implementation is suspicious.
#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a, B: Borrow<Polynomial>> ops::Mul<B> for &'a Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: B) -> Self::Output {
        let rhs = rhs.borrow();
        if rhs.is_zero() || self.is_zero() {
            return Polynomial::zero();
        }
        let n_coeffs = self.coefficients.len() + rhs.coefficients.len() - 1;
        let mut coeffs = vec![Fr::zero(); n_coeffs];
        let mut tmp = Fr::zero();
        for (i, ca) in self.coefficients.iter().enumerate() {
            for (j, cb) in rhs.coefficients.iter().enumerate() {
                tmp = *ca;
                tmp.mul_assign(cb);
                coeffs[i + j].add_assign(&tmp);
            }
        }
        zeroize_fr(&mut tmp);
        Polynomial::from(coeffs)
    }
}

impl<B: Borrow<Polynomial>> ops::Mul<B> for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: B) -> Self::Output {
        &self * rhs
    }
}

impl<B: Borrow<Self>> ops::MulAssign<B> for Polynomial {
    fn mul_assign(&mut self, rhs: B) {
        *self = &*self * rhs;
    }
}

impl ops::MulAssign<Fr> for Polynomial {
    fn mul_assign(&mut self, rhs: Fr) {
        if rhs.is_zero() {
            self.zeroize();
            self.coefficients.clear();
        } else {
            for c in &mut self.coefficients {
                Field::mul_assign(c, &rhs);
            }
        }
    }
}

impl<'a> ops::Mul<&'a Fr> for Polynomial {
    type Output = Polynomial;

    fn mul(mut self, rhs: &Fr) -> Self::Output {
        if rhs.is_zero() {
            self.zeroize();
            self.coefficients.clear();
        } else {
            self.coefficients.iter_mut().for_each(|c| c.mul_assign(rhs));
        }
        self
    }
}

impl ops::Mul<Fr> for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Fr) -> Self::Output {
        let rhs = &rhs;
        self * rhs
    }
}

impl<'a> ops::Mul<&'a Fr> for &'a Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: &Fr) -> Self::Output {
        (*self).clone() * rhs
    }
}

impl<'a> ops::Mul<Fr> for &'a Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Fr) -> Self::Output {
        (*self).clone() * rhs
    }
}
