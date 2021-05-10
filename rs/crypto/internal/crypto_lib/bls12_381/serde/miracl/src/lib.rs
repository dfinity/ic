//! Conversion between MIRACL representations of BLS12-381 values and the
//! standard representation.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used)]

#[cfg(test)]
mod tests;

pub use ic_crypto_internal_types::curves::bls12_381::{
    Fr as FrBytes, G1 as G1Bytes, G2 as G2Bytes,
};
use miracl_core::bls12381::{
    big::BIG, big::MODBYTES as BIG_SIZE, ecp::ECP, ecp2::ECP2, fp::FP, fp2::FP2, rom::CURVE_ORDER,
};
use std::cmp::Ordering;

/// Serializes a MIRACL `Fr` (i.e. `BIG`) to a standard, library-independent
/// form.
///
/// Note: MIRACL represents `Fr` as a `BIG`, which is a larger data type than
/// `FrBytes`.
///
/// # References
/// * The `G1Bytes` documentation includes a description of the format.
///
/// # Panics
/// * If the leading bytes of `big` are *not* `0`
pub fn miracl_fr_to_bytes(big: &BIG) -> FrBytes {
    let mut big = BIG::new_big(big);
    big.rmod(&BIG::new_ints(&CURVE_ORDER));
    let mut miracl_buffer = [0u8; BIG_SIZE];
    big.tobytes(&mut miracl_buffer);
    const FR_DATA_START: usize = BIG_SIZE - FrBytes::SIZE;
    assert_eq!(
        [0u8; FR_DATA_START][..],
        miracl_buffer[0..FR_DATA_START],
        "Fr is small compared with BIG; the leading bytes should be zero and the data should be in the remaining bytes."
    );
    let mut buffer = [0u8; FrBytes::SIZE];
    buffer.copy_from_slice(&miracl_buffer[FR_DATA_START..]);
    FrBytes(buffer)
}

/// Parses an `Fr` in a standard, library-independent form to a MIRACL `BIG`.
///
/// # Errors
/// * `Err(())` if `bytes` encodes a `BIG` that's greater than the BLS12_381
///   curve order.
pub fn miracl_fr_from_bytes(bytes: &[u8; FrBytes::SIZE]) -> Result<BIG, ()> {
    let mut buffer = [0u8; BIG_SIZE];
    buffer[BIG_SIZE - FrBytes::SIZE..].copy_from_slice(bytes);
    let result = BIG::frombytes(&buffer[..]);
    if BIG::comp(&result, &BIG::new_ints(&CURVE_ORDER)) >= 0 {
        Err(())
    } else {
        Ok(result)
    }
}

/// Serializes a MIRACL `G1` (i.e. `ECP`) to a standard, library-independent
/// form.
///
/// # References
/// * The `G1Bytes` documentation includes a description of the format.
/// * [MIRACL](https://github.com/miracl/core/blob/master/rust/ecp.rs) - see
///   `tobytes(..)`
pub fn miracl_g1_to_bytes(ecp: &ECP) -> G1Bytes {
    let mut buffer = [0u8; G1Bytes::SIZE];
    let affine_ecp = {
        // The conversion to affine is used when getting x and when getting the sign.
        // For efficiency we do this once; the later conversions become trivial.
        let mut miracl_point = ECP::new();
        miracl_point.copy(ecp);
        miracl_point.affine();
        miracl_point
    };
    affine_ecp.getpx().redc().tobytes(&mut buffer);
    buffer[G1Bytes::FLAG_BYTE_OFFSET] |= G1Bytes::COMPRESSED_FLAG;
    if affine_ecp.is_infinity() {
        buffer[G1Bytes::FLAG_BYTE_OFFSET] |= G1Bytes::INFINITY_FLAG
    } else if islarger_fp(&mut affine_ecp.getpy()) == Ordering::Greater {
        buffer[G1Bytes::FLAG_BYTE_OFFSET] |= G1Bytes::SIGN_FLAG;
    }
    G1Bytes(buffer)
}

/// Parses a `G1` in a standard, library-independent form to a MIRACL `ECP`.
///
/// Note: This does NOT verify that the parsed value is actually in `G1`.
///
/// Errors:
/// * `Err(())` if
///   - The point is encoded in UNCOMPRESSED form
///   - The point's x-coordinate is non-canonical (i.e. greater than the field
///     modulus)
///   - The point's x-coordinate is infinity, but the INFINITY flag is *not* set
///   - The INFINITY flag is set, but the encoded x-coordinate is *not*
///     all-zeroes
fn miracl_g1_from_bytes_unchecked(bytes: &[u8; G1Bytes::SIZE]) -> Result<ECP, ()> {
    if (bytes[G1Bytes::FLAG_BYTE_OFFSET] & G1Bytes::COMPRESSED_FLAG) == 0 {
        return Err(());
    }
    let infinity_bit = bytes[G1Bytes::FLAG_BYTE_OFFSET] & G1Bytes::INFINITY_FLAG;
    let sign_bit = bytes[G1Bytes::FLAG_BYTE_OFFSET] & G1Bytes::SIGN_FLAG;
    let mut other_bits = [0u8; 48];
    other_bits.copy_from_slice(&bytes[..]);
    other_bits[G1Bytes::FLAG_BYTE_OFFSET] &= G1Bytes::NON_FLAG_BITS;
    if infinity_bit == 0 {
        let x_coordinate = BIG::frombytes(&other_bits);
        use miracl_core::bls12381::rom;
        if BIG::comp(&x_coordinate, &BIG::new_ints(&rom::MODULUS)) >= 0 {
            return Err(());
        }
        let sign_bit: isize = if sign_bit == 0 { 0 } else { 1 };
        let mut ecp = ECP::new_big(&x_coordinate);
        if ecp.is_infinity() {
            return Err(());
        }
        ecp.affine();
        let x = ecp.getx();
        let y = choose_sign_fp(
            ecp.getpy(),
            if sign_bit != 0 {
                Ordering::Greater
            } else {
                Ordering::Less
            },
        )
        .redc();
        Ok(ECP::new_bigs(&x, &y))
    } else {
        if sign_bit != 0 || !other_bits.iter().all(|b| *b == 0) {
            return Err(());
        };
        let mut ecp = ECP::new();
        ecp.inf();
        Ok(ecp)
    }
}

/// Parses a `G1` in a standard, library-independent form to a MIRACL `ECP`.
///
/// Also verifies that the point is in the correct prime order subgroup.
///
/// # Errors
/// * `Err(())` if
///   - The point is *not* in the correct prime order subgroup.
///   - The point is encoded in UNCOMPRESSED form
///   - The point's x-coordinate is non-canonical (i.e. greater than the field
///     modulus)
///   - The point's x-coordinate is infinity, but the INFINITY flag is *not* set
///   - The INFINITY flag is set, but the encoded x-coordinate is *not*
///     all-zeroes
pub fn miracl_g1_from_bytes(bytes: &[u8; G1Bytes::SIZE]) -> Result<ECP, ()> {
    let ans = miracl_g1_from_bytes_unchecked(bytes)?;
    {
        // Verify that the point has the expected degree:
        let spec_p = BIG::new_ints(&CURVE_ORDER);
        if !ans.mul(&spec_p).is_infinity() {
            return Err(());
        }
    }
    Ok(ans)
}

/// Serializes a MIRACL `G2` (i.e. `ECP2`) to a standard, library-independent
/// form.
///
/// # References
/// * The `G2Bytes` documentation includes a description of the format.
/// * [MIRACL](https://github.com/miracl/core/blob/master/rust/ecp2.rs) - see
///   `tobytes(..)`
pub fn miracl_g2_to_bytes(ecp2: &ECP2) -> G2Bytes {
    let mut buffer = [0u8; G2Bytes::SIZE];
    let affine_ecp2 = {
        // The conversion to affine is used when getting x and when getting the sign.
        // For efficiency we do this once; the later conversions become trivial.
        let mut miracl_point = ECP2::new();
        miracl_point.copy(ecp2);
        miracl_point.affine();
        miracl_point
    };
    let mut x = affine_ecp2.getpx();
    x.getA()
        .redc()
        .tobytes(&mut buffer[G2Bytes::X0_BYTES_OFFSET..]);
    x.getB()
        .redc()
        .tobytes(&mut buffer[G2Bytes::X1_BYTES_OFFSET..]);
    buffer[G2Bytes::FLAG_BYTE_OFFSET] |= G2Bytes::COMPRESSED_FLAG;
    if affine_ecp2.is_infinity() {
        buffer[G2Bytes::FLAG_BYTE_OFFSET] |= G2Bytes::INFINITY_FLAG
    } else if islarger_fp2(&mut affine_ecp2.gety()) == Ordering::Greater {
        buffer[G2Bytes::FLAG_BYTE_OFFSET] |= G2Bytes::SIGN_FLAG;
    }
    G2Bytes(buffer)
}

/// Parses a `G2` in a standard, library-independent form to a MIRACL `ECP2`.
///
/// Note: This does NOT verify that the parsed value is actually in `G2`.
///
/// Errors:
/// * `Err(())` if
///   - The point is encoded in UNCOMPRESSED form
///   - Either sub-component of the point's x-coordinate is non-canonical (i.e.
///     greater than the field modulus)
///   - The point's x-coordinate is infinity, but the INFINITY flag is *not* set
///   - The INFINITY flag is set, but the encoded x-coordinate is *not*
///     all-zeroes
fn miracl_g2_from_bytes_unchecked(bytes: &[u8; G2Bytes::SIZE]) -> Result<ECP2, ()> {
    if (bytes[G2Bytes::FLAG_BYTE_OFFSET] & G2Bytes::COMPRESSED_FLAG) == 0 {
        return Err(());
    }
    let infinity_bit = bytes[G2Bytes::FLAG_BYTE_OFFSET] & G2Bytes::INFINITY_FLAG;
    let sign_bit = bytes[G2Bytes::FLAG_BYTE_OFFSET] & G2Bytes::SIGN_FLAG;
    let mut other_bits = [0u8; 96];
    other_bits.copy_from_slice(&bytes[..]);
    other_bits[G2Bytes::FLAG_BYTE_OFFSET] &= G2Bytes::NON_FLAG_BITS;

    if infinity_bit == 0 {
        let x_coordinate = {
            use miracl_core::bls12381::rom;
            let field_order = BIG::new_ints(&rom::MODULUS);
            let x1 = BIG::frombytearray(&other_bits, G2Bytes::X1_BYTES_OFFSET);
            if BIG::comp(&x1, &field_order) >= 0 {
                return Err(());
            }
            let x0 = BIG::frombytearray(&other_bits, G2Bytes::X0_BYTES_OFFSET);
            if BIG::comp(&x0, &field_order) >= 0 {
                return Err(());
            }
            FP2::new_bigs(&x0, &x1)
        };
        let sign_bit: isize = if sign_bit == 0 { 0 } else { 1 };
        let mut ecp2 = ECP2::new_fp2(&x_coordinate, 0);
        ecp2.affine();
        let x = ecp2.getx();
        if ecp2.is_infinity() {
            return Err(());
        }
        let y = choose_sign_fp2(
            ecp2.getpy(),
            if sign_bit != 0 {
                Ordering::Greater
            } else {
                Ordering::Less
            },
        );
        Ok(ECP2::new_fp2s(&x, &y))
    } else {
        if sign_bit != 0 || !other_bits.iter().all(|b| *b == 0) {
            return Err(());
        };
        let mut ecp2 = ECP2::new();
        ecp2.inf();
        Ok(ecp2)
    }
}

/// Parses a `G2` in a standard, library-independent form to a MIRACL `ECP2`.
///
/// Also verifies that the point is in the correct prime order subgroup.
///
/// Errors:
/// * `Err(())` if
///   - The point is *not* in the correct prime order subgroup.
///   - The point is encoded in UNCOMPRESSED form
///   - Either sub-component of the point's x-coordinate is non-canonical (i.e.
///     greater than the field modulus)
///   - The point's x-coordinate is infinity, but the INFINITY flag is *not* set
///   - The INFINITY flag is set, but the encoded x-coordinate is *not*
///     all-zeroes
pub fn miracl_g2_from_bytes(bytes: &[u8; G2Bytes::SIZE]) -> Result<ECP2, ()> {
    let ans = miracl_g2_from_bytes_unchecked(bytes)?;
    {
        // Verify that the point has the expected degree:
        let spec_p = BIG::new_ints(&CURVE_ORDER);
        if !ans.mul(&spec_p).is_infinity() {
            return Err(());
        }
    }
    Ok(ans)
}

/// Converts MIRACL's comparison return value to the standard Rust cmp return
/// value.
fn isize_to_ordering(ordering: isize) -> Ordering {
    match ordering {
        x if x < 0 => Ordering::Less,
        0 => Ordering::Equal,
        _ => Ordering::Greater,
    }
}

/// Compares y with -y mod p.
///
/// Note: "sign" in the spec is defined in terms of lexicographic ordering.
/// Note: There are several definitions of "sign" in various codebases; please
/// beware of using another definition.
fn islarger_fp(fp: &mut FP) -> Ordering {
    // This is what pairing does:
    let minus_fp = neg_fp(fp);
    cmp_fp(fp, &minus_fp)
}
fn neg_fp(fp: &FP) -> FP {
    let mut minus_fp = FP::new();
    minus_fp.zero();
    minus_fp.sub(&fp);
    minus_fp
}
fn cmp_fp(left: &FP, right: &FP) -> Ordering {
    isize_to_ordering(BIG::comp(&left.redc(), &right.redc()))
}
/// Return y or -y depending on whether the greater is wanted.
fn choose_sign_fp(fp: FP, greater: Ordering) -> FP {
    let minus_fp = neg_fp(&fp);
    if cmp_fp(&fp, &minus_fp) == greater {
        fp
    } else {
        minus_fp
    }
}

/// Compares y with -y mod p.
///
/// Note: This is now in miracl but not published yet.
fn islarger_fp2(fp2: &mut FP2) -> Ordering {
    let mut minus_fp2 = neg_fp2(fp2);
    cmp_fp2(fp2, &mut minus_fp2)
}
fn cmp_fp2(left: &mut FP2, right: &mut FP2) -> Ordering {
    let cmpa = BIG::comp(&left.geta(), &right.geta());
    let cmpb = BIG::comp(&left.getb(), &right.getb());
    if cmpb == 0 {
        isize_to_ordering(cmpa)
    } else {
        isize_to_ordering(cmpb)
    }
}

fn neg_fp2(fp2: &FP2) -> FP2 {
    let mut minus_fp2 = FP2::new();
    minus_fp2.zero();
    minus_fp2.sub(&fp2);
    minus_fp2
}

/// Return y or -y depending on whether the greater is wanted.
fn choose_sign_fp2(mut fp2: FP2, greater: Ordering) -> FP2 {
    let mut minus_fp2 = neg_fp2(&fp2);
    if cmp_fp2(&mut fp2, &mut minus_fp2) == greater {
        fp2
    } else {
        minus_fp2
    }
}
