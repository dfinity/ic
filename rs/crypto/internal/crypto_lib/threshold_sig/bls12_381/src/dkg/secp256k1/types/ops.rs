use super::*;
use libsecp256k1::curve::Scalar;
use libsecp256k1::ECMULT_CONTEXT;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg};

#[cfg(test)]
mod tests;

/// Public * Secret
///
/// Multiplies a curve point (self) by a scalar (other).
impl MulAssign<&EphemeralSecretKey> for EphemeralPublicKey {
    fn mul_assign(&mut self, other: &EphemeralSecretKey) {
        if !self.is_infinity() {
            let point = self.0;
            ECMULT_CONTEXT.ecmult(&mut self.0, &point, &other.0, &Scalar::from_int(0));
        }
    }
}
impl Mul<&EphemeralSecretKey> for EphemeralPublicKey {
    type Output = EphemeralPublicKey;
    fn mul(mut self, other: &EphemeralSecretKey) -> EphemeralPublicKey {
        self *= other;
        self
    }
}
impl Mul<EphemeralSecretKey> for EphemeralPublicKey {
    type Output = EphemeralPublicKey;
    fn mul(self, other: EphemeralSecretKey) -> EphemeralPublicKey {
        self * &other
    }
}

/// Public + Secret
///
/// Adds to a curve point (self) the product of the base point G and a scalar
/// (other).
impl AddAssign<&EphemeralSecretKey> for EphemeralPublicKey {
    fn add_assign(&mut self, other: &EphemeralSecretKey) {
        if self.is_infinity() {
            self.0 = EphemeralPublicKey::from(other).0;
        } else {
            let point = self.0;
            ECMULT_CONTEXT.ecmult(&mut self.0, &point, &Scalar::from_int(1), &other.0);
        }
    }
}
impl Add<&EphemeralSecretKey> for EphemeralPublicKey {
    type Output = EphemeralPublicKey;
    fn add(mut self, other: &EphemeralSecretKey) -> EphemeralPublicKey {
        self += other;
        self
    }
}
impl Add<EphemeralSecretKey> for EphemeralPublicKey {
    type Output = EphemeralPublicKey;
    fn add(self, other: EphemeralSecretKey) -> EphemeralPublicKey {
        self + &other
    }
}

// Public + Public
impl AddAssign<&EphemeralPublicKey> for EphemeralPublicKey {
    fn add_assign(&mut self, other: &EphemeralPublicKey) {
        self.0 = self.0.add_var(&other.0, None);
    }
}
impl Add<&EphemeralPublicKey> for EphemeralPublicKey {
    type Output = EphemeralPublicKey;
    fn add(mut self, other: &EphemeralPublicKey) -> EphemeralPublicKey {
        self += other;
        self
    }
}
impl Add<EphemeralPublicKey> for EphemeralPublicKey {
    type Output = EphemeralPublicKey;
    fn add(self, other: EphemeralPublicKey) -> EphemeralPublicKey {
        self + &other
    }
}

/// -Secret
///
/// Negates a scalar.
impl Neg for EphemeralSecretKey {
    type Output = EphemeralSecretKey;
    fn neg(self) -> EphemeralSecretKey {
        EphemeralSecretKey(-self.0)
    }
}

/// Secret * Secret
///
/// Multiples two scalars.
impl MulAssign<&EphemeralSecretKey> for EphemeralSecretKey {
    fn mul_assign(&mut self, other: &EphemeralSecretKey) {
        self.0 *= &other.0;
    }
}
impl Mul<&EphemeralSecretKey> for EphemeralSecretKey {
    type Output = EphemeralSecretKey;
    fn mul(mut self, other: &EphemeralSecretKey) -> EphemeralSecretKey {
        self *= other;
        self
    }
}
impl Mul<EphemeralSecretKey> for EphemeralSecretKey {
    type Output = EphemeralSecretKey;
    fn mul(self, other: EphemeralSecretKey) -> EphemeralSecretKey {
        self * &other
    }
}

/// Secret + Secret
///
/// Adds two scalars.
impl AddAssign<&EphemeralSecretKey> for EphemeralSecretKey {
    fn add_assign(&mut self, other: &EphemeralSecretKey) {
        self.0 += &other.0;
    }
}
impl Add<&EphemeralSecretKey> for EphemeralSecretKey {
    type Output = EphemeralSecretKey;
    fn add(mut self, other: &EphemeralSecretKey) -> EphemeralSecretKey {
        self += other;
        self
    }
}
impl Add<EphemeralSecretKey> for EphemeralSecretKey {
    type Output = EphemeralSecretKey;
    fn add(self, other: EphemeralSecretKey) -> EphemeralSecretKey {
        self + &other
    }
}
