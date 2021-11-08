//! Test utilities

use bls12_381::{G2Projective, Scalar};

/// Convert an unsigned number into the corresponding field element.  This is so
/// that we can make tests on Scalar that are easily understandable to humans by
/// using the integer equivalents.
///
/// This makes no assumptions about the field representation, so construction is
/// only through the trait API.  This is because, in this context, correctness
/// not speed is the primary goal.
pub fn uint_to_fr(num: u32) -> Scalar {
    let mut num = num;
    let mut power = Scalar::one();
    let mut ans = Scalar::zero();
    while num != 0 {
        if (num & 1) != 0 {
            ans += power;
        }
        power = power.double();
        num >>= 1;
    }
    ans
}

/// Test mapping to Scalar of first N integers.
#[test]
fn uint_to_fr_is_correct() {
    let mut fr = Scalar::zero();
    for i in 0..10 {
        assert_eq!(
            fr,
            uint_to_fr(i),
            "Conversion from integers to Scalar failed for {}",
            i
        );
        fr += Scalar::one();
    }
}

/// Convert a signed integer into the corresponding field element
pub fn int_to_fr(num: i32) -> Scalar {
    if num >= 0 {
        uint_to_fr(num as u32)
    } else {
        let mut ans = Scalar::zero();
        ans -= &uint_to_fr((-num) as u32);
        ans
    }
}

/// Test mapping to Scalar of -N..N.
#[test]
fn int_to_fr_is_correct() {
    let mut positive = Scalar::zero();
    let mut negative = Scalar::zero();
    for i in 0..10 {
        assert_eq!(
            positive,
            int_to_fr(i),
            "Conversion from integers to Scalar failed for {}",
            i
        );
        assert_eq!(
            negative,
            int_to_fr(-i),
            "Conversion from integers to Scalar failed for {}",
            i
        );
        positive += &Scalar::one();
        negative -= &Scalar::one();
    }
}

#[test]
fn uint_to_fr_arithmetic_is_correct() {
    let mut fr = uint_to_fr(5);
    fr += &uint_to_fr(34);
    assert_eq!(fr, uint_to_fr(39));
}

/// Get G2Projective elements by primitive double and add.
// TODO(DFN-1240): Write our own unit tests for all the pairing library
// functions to make sure that their implementation is correct and that the
// operations are what we expect them to be.
pub fn uint_to_g2(num: u32) -> G2Projective {
    let mut num = num;
    let mut power = G2Projective::generator();
    let mut ans = G2Projective::identity();
    while num != 0 {
        if (num & 1) != 0 {
            ans += &power;
        }
        power = power.double();
        num >>= 1;
    }
    ans
}

/// Test mapping to G2Projective of first N integers.
#[test]
fn uint_to_g2_is_correct() {
    let mut g2 = G2Projective::identity();
    for i in 0..10 {
        assert_eq!(
            g2,
            uint_to_g2(i),
            "Conversion from integers to Scalar failed for {}",
            i
        );
        g2 += &G2Projective::generator();
    }
}

#[test]
fn uint_to_g2_arithmetic_is_correct() {
    let mut g2 = uint_to_g2(5);
    g2 += &uint_to_g2(34);
    assert_eq!(g2, uint_to_g2(39));
}
