use crate::{ThresholdEcdsaError, ThresholdEcdsaResult};
use std::fmt;
use zeroize::Zeroize;

const LIMBS: usize = 256 / 64;

/// The P-256 prime
///
/// See FIPS 186-4 [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf]
/// section D.1.2.3
const MODULUS: FieldElement = FieldElement::from_u64x4(
    0xFFFFFFFF00000001,
    0x0000000000000000,
    0x00000000FFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
);

/// The P-256 "A" parameter is -3
///
/// See FIPS 186-4 [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf]
/// section D.1.2
const CURVE_A: FieldElement = FieldElement::from_u64x4(
    0xFFFFFFFF00000001,
    0x0000000000000000,
    0x00000000FFFFFFFF,
    0xFFFFFFFFFFFFFFFC,
);

/// The P-256 "B" parameter is randomly generated
///
/// See FIPS 186-4 [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf]
/// section D.1.2.3
const CURVE_B: FieldElement = FieldElement::from_u64x4(
    0x5AC635D8AA3A93E7,
    0xB3EBBD55769886BC,
    0x651D06B0CC53B0F6,
    0x3BCE3C3E27D2604B,
);

/// The constant `Z=-10` in the simplified SWU map specified in
// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-12.html#name-suites-for-nist-p-256
const SSWU_Z: FieldElement = FieldElement::from_u64x4(
    0xFFFFFFFF00000001,
    0x0000000000000000,
    0x00000000FFFFFFFF,
    0xFFFFFFFFFFFFFFF5,
);

/// The constant `C2` is the square root of `-Z` see
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-12.html#appendix-F.2.1.2
const SSWU_C2: FieldElement = FieldElement::from_u64x4(
    0xDA538E3BE1D89B99,
    0xC978FC675180AAB2,
    0x7B8D1FF84C55D5B6,
    0x2CCD3427E433C47F,
);

const MODULUS_MINUS_2: [u64; LIMBS] = [
    0xFFFFFFFF00000001,
    0x0000000000000000,
    0x00000000FFFFFFFF,
    0xFFFFFFFFFFFFFFFD,
];

const MODULUS_PLUS_1_OVER_4: [u64; LIMBS] = [
    0x3FFFFFFFC0000000,
    0x4000000000000000,
    0x0000000040000000,
    0x0000000000000000,
];

const MODULUS_MINUS_3_OVER_4: [u64; LIMBS] = [
    0x3FFFFFFFC0000000,
    0x4000000000000000,
    0x000000003FFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// Montgomery param (-p)^-1 mod 2^64
const P_DASH: u64 = 1;

/// MONTY_R = 2^256 mod p
const MONTY_R: FieldElement = FieldElement::from_u64x4(
    0x00000000FFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFF00000000,
    0x0000000000000001,
);

/// MONTY_R^2 = 2^512 mod p
const MONTY_R2: FieldElement = FieldElement::from_u64x4(
    0x00000004FFFFFFFD,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFBFFFFFFFF,
    0x0000000000000003,
);

/// MONTY_R^3 = 2^768 mod p
const MONTY_R3: FieldElement = FieldElement::from_u64x4(
    0x0000001800000001,
    0x00000005fffffffc,
    0xffffffedfffffff7,
    0xfffffffd0000000a,
);

crate::fe::utils::define_field_element!(LIMBS);

impl FieldElement {
    /// Initialize from 4 u64 (private constructor)
    ///
    /// This function uses a reverse convention from the internal ordering,
    /// because it is used for creating the constants and it is nicer for
    /// those to read "in order".
    const fn from_u64x4(v0: u64, v1: u64, v2: u64, v3: u64) -> Self {
        Self::from_limbs([v3, v2, v1, v0])
    }

    /// Return one (in Montgomery form)
    pub fn one() -> Self {
        MONTY_R
    }

    /// Return A (in Montgomery form)
    pub fn a() -> Self {
        CURVE_A.mul(&MONTY_R2)
    }

    /// Return B (in Montgomery form)
    pub fn b() -> Self {
        CURVE_B.mul(&MONTY_R2)
    }

    /// Return A' (in Montgomery form)
    pub fn sswu_a() -> Self {
        // P256 SSWU uses the normal curve
        Self::a()
    }

    /// Return B' (in Montgomery form)
    pub fn sswu_b() -> Self {
        // P256 SSWU uses the normal curve
        Self::b()
    }

    /// Return SSWU Z (in Montgomery form)
    pub fn sswu_z() -> Self {
        SSWU_Z.mul(&MONTY_R2)
    }

    /// Return SSWU C2 (in Montgomery form)
    pub fn sswu_c2() -> Self {
        SSWU_C2.mul(&MONTY_R2)
    }

    pub fn progenitor(&self) -> Self {
        self.pow_vartime(&MODULUS_MINUS_3_OVER_4)
    }

    /// Return the square root of self mod p, or zero if no square root exists.
    pub fn sqrt(&self) -> Self {
        // For p == 3 (mod 4) square root can be computed using x^(p+1)/4
        // See I.1 of draft-irtf-cfrg-hash-to-curve-12

        let sqrt = self.pow_vartime(&MODULUS_PLUS_1_OVER_4);

        // Check that the result is valid before returning
        if sqrt.square().ct_eq(self) {
            return sqrt;
        }

        Self::zero()
    }
}
