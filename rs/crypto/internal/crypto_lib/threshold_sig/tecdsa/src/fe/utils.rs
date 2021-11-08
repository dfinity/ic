// First disable some Clippy warnings
//
// The "needless" range loops are much easier to understand than
// what clippy prefers, and more closely match the usual notation
// used for such operations.
//
// The "single_component_path_imports" allow is due to a bug in Clippy:
// https://github.com/rust-lang/rust-clippy/issues/7106

#![allow(clippy::needless_range_loop)]
#![allow(clippy::single_component_path_imports)]

use std::convert::TryInto;

#[inline]
pub(crate) fn add_limb(x: u64, y: u64, carry: &mut u64) -> u64 {
    let z = (x as u128) + (y as u128) + (*carry as u128);
    *carry = (z >> 64) as u64;
    z as u64
}

#[inline]
pub(crate) fn sub_limb(x: u64, y: u64, borrow: &mut u64) -> u64 {
    let ret = (x as u128).wrapping_sub((y as u128) + ((*borrow & 1) as u128));
    *borrow = (ret >> 64) as u64;
    ret as u64
}

#[inline]
pub(crate) fn mul_add(x: u64, y: u64, z: u64, carry: &mut u64) -> u64 {
    let ret = ((x as u128) * (y as u128)) + (z as u128) + (*carry as u128);
    *carry = (ret >> 64) as u64;
    ret as u64
}

#[inline]
pub(crate) fn read_limbs<const LIMBS: usize>(src: &[u8]) -> [u64; LIMBS] {
    let mut limbs = [0u64; LIMBS];

    for i in 0..LIMBS {
        limbs[LIMBS - 1 - i] = u64::from_be_bytes(src[i * 8..(i + 1) * 8].try_into().unwrap());
    }

    limbs
}

#[inline]
pub(crate) fn mod_sub<const LIMBS: usize>(
    l: &[u64],
    r: &[u64; LIMBS],
    modulus: &[u64; LIMBS],
) -> [u64; LIMBS] {
    let mut borrow = 0;
    let mut w = [0u64; LIMBS];
    for i in 0..LIMBS {
        w[i] = sub_limb(l[i], r[i], &mut borrow);
    }

    for i in LIMBS..l.len() {
        let _ = sub_limb(l[i], 0, &mut borrow);
    }

    // Use borrow as a mask to conditionally add
    let mut carry = 0;
    for i in 0..LIMBS {
        w[i] = add_limb(w[i], modulus[i] & borrow, &mut carry);
    }

    w
}

#[inline]
pub(crate) fn monty_redc<const LIMBS: usize, const Z_LIMBS: usize>(
    z_in: &[u64],
    modulus: &[u64; LIMBS],
    p_dash: u64,
) -> [u64; LIMBS] {
    let mut z = [0u64; Z_LIMBS];
    z[0..z_in.len()].copy_from_slice(z_in);

    for i in 0..LIMBS {
        let y = u64::wrapping_mul(z[i], p_dash);

        let mut carry = 0;
        for j in 0..LIMBS {
            z[i + j] = mul_add(modulus[j], y, z[i + j], &mut carry);
        }

        for j in LIMBS + i..2 * LIMBS + 1 {
            z[j] = add_limb(z[j], 0, &mut carry);
        }
    }

    mod_sub(&z[LIMBS..], modulus, modulus)
}

macro_rules! define_field_element {
    ( $limbs: expr) => {
        /// A field element
        ///
        /// The limbs are stored in little-endian order, ie limbs[0]
        /// cooresponds to the low bits of the integer.
        #[derive(Copy, Clone, Zeroize)]
        pub struct FieldElement {
            limbs: [u64; $limbs],
        }

        impl PartialEq for FieldElement {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq(other)
            }
        }

        impl Eq for FieldElement {}

        impl fmt::Debug for FieldElement {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "FieldElement(0x{}", hex::encode(self.as_bytes()))
            }
        }

        impl Default for FieldElement {
            fn default() -> Self {
                FieldElement::zero()
            }
        }

        impl FieldElement {
            /// Initialize from [u64; $limbs] (private constructor)
            const fn from_limbs(limbs: [u64; $limbs]) -> Self {
                Self { limbs }
            }

            /// Return zero (in Montgomery form)
            pub fn zero() -> Self {
                Self::from_limbs([0u64; $limbs])
            }

            /// Parse the given byte array as a field element.
            ///
            /// Return Err if the byte array does not represeent an integer in [0,p)
            pub fn from_bytes(bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
                if bytes.len() != 8 * $limbs {
                    return Err(ThresholdEcdsaError::InvalidFieldElement);
                }

                let limbs = super::utils::read_limbs::<$limbs>(bytes);

                // If lhs < rhs then lhs - rhs will underflow; if it doesn't then lhs >= rhs
                let mut borrow = 0;
                for i in 0..$limbs {
                    let _ = super::utils::sub_limb(limbs[i], MODULUS.limbs[i], &mut borrow);
                }

                let is_gte = borrow == 0;

                if is_gte {
                    return Err(ThresholdEcdsaError::InvalidFieldElement);
                }

                // Multiply by R2 to convert into Montgomery form
                Ok(Self::from_limbs(limbs).mul(&MONTY_R2))
            }

            pub fn from_bytes_wide(bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
                const WIDE_BYTES_LEN: usize = 2 * 8 * $limbs;

                if bytes.len() > WIDE_BYTES_LEN {
                    return Err(ThresholdEcdsaError::InvalidFieldElement);
                }

                let mut wide_bytes = [0u8; WIDE_BYTES_LEN];
                wide_bytes[WIDE_BYTES_LEN - bytes.len()..].copy_from_slice(bytes);
                let limbs = super::utils::read_limbs::<{ 2 * $limbs }>(&wide_bytes);

                // First reduce then mul by R3 to convert to Montgomery form
                Ok(Self::redc(&limbs).mul(&MONTY_R3))
            }

            /// Return the encoding of this field element
            pub fn as_bytes(&self) -> Vec<u8> {
                // Convert from Montgomery form
                let value = Self::redc(&self.limbs);
                let mut ret = vec![0u8; 8 * $limbs];
                for i in 0..$limbs {
                    ret[8 * i..(8 * i + 8)]
                        .copy_from_slice(&value.limbs[$limbs - 1 - i].to_be_bytes());
                }
                ret
            }

            /// Return true if and only if self is equal to zero
            pub fn is_zero(&self) -> bool {
                self.ct_eq(&Self::zero())
            }

            /// If assign is true then set self to other
            pub fn ct_assign(&mut self, other: &Self, assign: bool) {
                use subtle::ConditionallySelectable;

                let choice = subtle::Choice::from(assign as u8);
                for i in 0..$limbs {
                    self.limbs[i] =
                        u64::conditional_select(&self.limbs[i], &other.limbs[i], choice);
                }
            }

            fn ct_eq(&self, other: &Self) -> bool {
                let mut cmp = 0;

                for i in 0..$limbs {
                    cmp |= self.limbs[i] ^ other.limbs[i];
                }

                cmp == 0
            }

            /// Return self + rhs mod p
            pub fn add(&self, rhs: &Self) -> Self {
                let mut sum = [0u64; $limbs + 1];
                let mut carry = 0;
                for i in 0..$limbs {
                    sum[i] = super::utils::add_limb(self.limbs[i], rhs.limbs[i], &mut carry);
                }
                sum[$limbs] = carry;

                // Attempt to subtract the modulus, to ensure the result is in the field.
                Self::mod_sub(&sum, MODULUS.limbs)
            }

            /// Return self - rhs mod p
            pub fn subtract(&self, rhs: &Self) -> Self {
                Self::mod_sub(&self.limbs, rhs.limbs)
            }

            fn mod_sub(l: &[u64], r: [u64; $limbs]) -> Self {
                let w = super::utils::mod_sub(l, &r, &MODULUS.limbs);
                Self::from_limbs(w)
            }

            fn redc(z: &[u64]) -> Self {
                Self::from_limbs(super::utils::monty_redc::<$limbs, { 2 * $limbs + 1 }>(
                    z,
                    &MODULUS.limbs,
                    P_DASH,
                ))
            }

            /// Return self * rhs mod p
            pub fn mul(&self, rhs: &Self) -> Self {
                let mut product = [0u64; 2 * $limbs];

                for i in 0..$limbs {
                    let mut carry = 0;

                    for j in 0..$limbs {
                        product[i + j] = super::utils::mul_add(
                            self.limbs[i],
                            rhs.limbs[j],
                            product[i + j],
                            &mut carry,
                        );
                    }

                    product[i + $limbs] = carry;
                }

                Self::redc(&product)
            }

            /// Return self * self mod p
            pub fn square(&self) -> Self {
                self.mul(self)
            }

            /// Return `self^power`
            ///
            /// Variable time with respect to the exponent, which should only be a
            /// constant.
            fn pow_vartime(&self, power: &[u64; $limbs]) -> Self {
                let mut z = Self::one();
                for i in 0..$limbs {
                    for b in (0..64).rev() {
                        z = z.square();

                        if ((power[i] >> b) & 1) == 1 {
                            z = z.mul(self);
                        }
                    }
                }
                z
            }

            /// Return the multiplicative inverse of self, if self is non-zero, or else
            /// zero
            pub fn invert(&self) -> Self {
                // Since p is prime we can just use Fermat's little theorem to compute
                // an inverse. The only case that fails is self == 0 in which case we
                // return 0 which is never a valid multiplicative inverse.
                self.pow_vartime(&MODULUS_MINUS_2)
            }
        }
    };
}

pub(crate) use define_field_element;
