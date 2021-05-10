//! Test utilities

use ff::Field;
use group::CurveProjective;
use pairing::bls12_381::{Fr, G2};

/// Convert an unsigned number into the corresponding field element.  This is so
/// that we can make tests on Fr that are easily understandable to humans by
/// using the integer equivalents.
///
/// This makes no assumptions about the field representation, so construction is
/// only through the trait API.  This is because, in this context, correctness
/// not speed is the primary goal.
pub fn uint_to_fr(num: u32) -> Fr {
    let mut num = num;
    let mut power = Fr::one();
    let mut ans = Fr::zero();
    while num != 0 {
        if (num & 1) != 0 {
            ans.add_assign(&power);
        }
        power.double();
        num >>= 1;
    }
    ans
}

/// Test mapping to Fr of first N integers.
#[test]
fn uint_to_fr_is_correct() {
    let mut fr = Fr::zero();
    for i in 0..10 {
        assert_eq!(
            fr,
            uint_to_fr(i),
            "Conversion from integers to Fr failed for {}",
            i
        );
        fr.add_assign(&Fr::one());
    }
}

/// Convert a signed integer into the corresponding field element
pub fn int_to_fr(num: i32) -> Fr {
    if num >= 0 {
        uint_to_fr(num as u32)
    } else {
        let mut ans = Fr::zero();
        ans.sub_assign(&uint_to_fr((-num) as u32));
        ans
    }
}

/// Test mapping to Fr of -N..N.
#[test]
fn int_to_fr_is_correct() {
    let mut positive = Fr::zero();
    let mut negative = Fr::zero();
    for i in 0..10 {
        assert_eq!(
            positive,
            int_to_fr(i),
            "Conversion from integers to Fr failed for {}",
            i
        );
        assert_eq!(
            negative,
            int_to_fr(-i),
            "Conversion from integers to Fr failed for {}",
            i
        );
        positive.add_assign(&Fr::one());
        negative.sub_assign(&Fr::one());
    }
}

#[test]
fn uint_to_fr_arithmetic_is_correct() {
    let mut fr = uint_to_fr(5);
    fr.add_assign(&uint_to_fr(34));
    assert_eq!(fr, uint_to_fr(39));
}

/// Get G2 elements by primitive double and add.
// TODO(DFN-1240): Write our own unit tests for all the pairing library
// functions to make sure that their implementation is correct and that the
// operations are what we expect them to be.
pub fn uint_to_g2(num: u32) -> G2 {
    let mut num = num;
    let mut power = G2::one();
    let mut ans = G2::zero();
    while num != 0 {
        if (num & 1) != 0 {
            ans.add_assign(&power);
        }
        power.double();
        num >>= 1;
    }
    ans
}

/// Test mapping to G2 of first N integers.
#[test]
fn uint_to_g2_is_correct() {
    let mut g2 = G2::zero();
    for i in 0..10 {
        assert_eq!(
            g2,
            uint_to_g2(i),
            "Conversion from integers to Fr failed for {}",
            i
        );
        g2.add_assign(&G2::one());
    }
}

#[test]
fn uint_to_g2_arithmetic_is_correct() {
    let mut g2 = uint_to_g2(5);
    g2.add_assign(&uint_to_g2(34));
    assert_eq!(g2, uint_to_g2(39));
}
