use crate::fe::EccFieldElement;
use crate::group::{EccCurveType, EccPoint, EccScalar};
use crate::{ThresholdEcdsaError, ThresholdEcdsaResult};
use hex_literal::hex;

/// Conditional move matching draft-irtf-cfrg-hash-to-curve-12 notation
///
/// CMOV(a, b, c): If c is False, CMOV returns a, otherwise it returns b.
fn cmov(
    a: &EccFieldElement,
    b: &EccFieldElement,
    c: bool,
) -> ThresholdEcdsaResult<EccFieldElement> {
    let mut r = *a;
    r.ct_assign(b, c)?;
    Ok(r)
}

fn sqrt_ratio(
    u: &EccFieldElement,
    v: &EccFieldElement,
) -> ThresholdEcdsaResult<(bool, EccFieldElement)> {
    if u.curve_type() != v.curve_type() {
        return Err(ThresholdEcdsaError::CurveMismatch);
    }

    // By the construction of tv6 in sswu this cannot occur, but check just to
    // be safe as otherwise the output of this function is not well defined.
    if v.is_zero() {
        return Err(ThresholdEcdsaError::InvalidArguments(
            "sqrt_ratio v == 0".to_string(),
        ));
    }

    let curve_type = u.curve_type();

    if curve_type == EccCurveType::P256 || curve_type == EccCurveType::K256 {
        // Fast codepath for curves where p == 3 (mod 4)
        // See https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-12.html#appendix-F.2.1.2
        let c2 = EccFieldElement::sswu_c2(curve_type);

        let tv1 = v.square()?;
        let tv2 = u.mul(v)?;
        let tv1 = tv1.mul(&tv2)?;
        let y1 = tv1.progenitor(); // see https://eprint.iacr.org/2020/1497.pdf
        let y1 = y1.mul(&tv2)?;
        let y2 = y1.mul(&c2)?;
        let tv3 = y1.square()?;
        let tv3 = tv3.mul(v)?;
        let is_qr = tv3 == *u;
        let y = cmov(&y2, &y1, is_qr)?;
        Ok((is_qr, y))
    } else {
        // Generic but slower codepath for other primes
        let z = EccFieldElement::sswu_z(curve_type);
        let vinv = v.invert();
        let uov = u.mul(&vinv)?;
        let sqrt_uov = uov.sqrt();
        let uov_is_qr = !sqrt_uov.is_zero();
        let z_uov = z.mul(&uov)?;
        let sqrt_z_uov = z_uov.sqrt();
        Ok((uov_is_qr, cmov(&sqrt_z_uov, &sqrt_uov, uov_is_qr)?))
    }
}

/// Simplified Shallue-van de Woestijne-Ulas method
///
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-12.html#name-simplified-swu-method
#[allow(clippy::many_single_char_names)]
fn sswu(u: &EccFieldElement) -> ThresholdEcdsaResult<(EccFieldElement, EccFieldElement)> {
    let curve = u.curve_type();

    let a = EccFieldElement::sswu_a(curve);
    let b = EccFieldElement::sswu_b(curve);
    let z = EccFieldElement::sswu_z(curve);
    let one = EccFieldElement::one(curve);

    let tv1 = z.mul(&u.square()?)?;
    let mut tv2 = tv1.square()?;
    tv2 = tv2.add(&tv1)?;
    let mut tv3 = tv2.add(&one)?;
    tv3 = tv3.mul(&b)?;
    let mut tv4 = cmov(&z, &tv2.negate()?, !tv2.is_zero())?;
    tv4 = tv4.mul(&a)?;
    tv2 = tv3.square()?;
    let mut tv6 = tv4.square()?;
    let mut tv5 = tv6.mul(&a)?;
    tv2 = tv2.add(&tv5)?;
    tv2 = tv2.mul(&tv3)?;
    tv6 = tv6.mul(&tv4)?;
    tv5 = tv6.mul(&b)?;
    tv2 = tv2.add(&tv5)?;

    let mut x = tv1.mul(&tv3)?;

    let (is_gx1_square, y1) = sqrt_ratio(&tv2, &tv6)?;

    let mut y = tv1.mul(u)?;
    y = y.mul(&y1)?;
    x = cmov(&x, &tv3, is_gx1_square)?;
    y = cmov(&y, &y1, is_gx1_square)?;
    let e1 = u.sign() == y.sign();
    y = cmov(&y.negate()?, &y, e1)?;
    x = x.mul(&tv4.invert())?;

    Ok((x, y))
}

fn map_to_curve(fe: &EccFieldElement) -> ThresholdEcdsaResult<EccPoint> {
    let (x, y) = sswu(fe)?;

    if fe.curve_type() == EccCurveType::K256 {
        let (x, y) = sswu_isogeny_secp256k1(&x, &y)?;
        EccPoint::from_field_elems(&x, &y)
    } else {
        EccPoint::from_field_elems(&x, &y)
    }
}

fn hash_to_field(
    count: usize,
    curve: EccCurveType,
    input: &[u8],
    domain_separator: &[u8],
) -> ThresholdEcdsaResult<Vec<EccFieldElement>> {
    let p_bits = curve.field_bits();
    let security_level = curve.security_level();

    let field_len = (p_bits + security_level + 7) / 8; // "L" in spec
    let len_in_bytes = count * field_len;

    let uniform_bytes = crate::xmd::expand_message_xmd(input, domain_separator, len_in_bytes);

    let mut out = Vec::with_capacity(count);

    for i in 0..count {
        let fe = EccFieldElement::from_bytes_wide(
            curve,
            &uniform_bytes[i * field_len..(i + 1) * field_len],
        )?;
        out.push(fe);
    }

    Ok(out)
}

pub(crate) fn hash_to_scalar(
    count: usize,
    curve: EccCurveType,
    input: &[u8],
    domain_separator: &[u8],
) -> ThresholdEcdsaResult<Vec<EccScalar>> {
    let s_bits = curve.scalar_bits();
    let security_level = curve.security_level();

    let field_len = (s_bits + security_level + 7) / 8; // "L" in spec
    let len_in_bytes = count * field_len;

    let uniform_bytes = crate::xmd::expand_message_xmd(input, domain_separator, len_in_bytes);

    let mut out = Vec::with_capacity(count);

    for i in 0..count {
        let s =
            EccScalar::from_bytes_wide(curve, &uniform_bytes[i * field_len..(i + 1) * field_len])?;
        out.push(s);
    }

    Ok(out)
}

/// Hash to curve random oracle variant
///
/// This implementation only supports prime order curves with
/// extension degree equal to 1. It would require extension to
/// support other curves such as BLS12-381
pub fn hash2curve_ro(
    curve: EccCurveType,
    input: &[u8],
    domain_separator: &[u8],
) -> ThresholdEcdsaResult<EccPoint> {
    let u = hash_to_field(2, curve, input, domain_separator)?;

    let q0 = map_to_curve(&u[0])?;
    let q1 = map_to_curve(&u[1])?;

    let r = q0.add_points(&q1)?;
    // for a curve without prime order, we would clear the cofactor here
    Ok(r)
}

/// Return x**2 + x*c1 + c2
#[inline(always)]
fn x2_xc1_c2(
    x: &EccFieldElement,
    c1: &EccFieldElement,
    c2: &EccFieldElement,
) -> ThresholdEcdsaResult<EccFieldElement> {
    x.mul(&x.add(c1)?)?.add(c2)
}

#[inline(always)]
fn x3_x2c1_xc2_c3(
    x: &EccFieldElement,
    c1: &EccFieldElement,
    c2: &EccFieldElement,
    c3: &EccFieldElement,
) -> ThresholdEcdsaResult<EccFieldElement> {
    x.mul(&x2_xc1_c2(x, c1, c2)?)?.add(c3)
}

/// Return x**3 * c1 + x**2 * c2 + x * c3 + c4
#[inline(always)]
fn x3c1_x2c2_xc3_c4(
    x: &EccFieldElement,
    c1: &EccFieldElement,
    c2: &EccFieldElement,
    c3: &EccFieldElement,
    c4: &EccFieldElement,
) -> ThresholdEcdsaResult<EccFieldElement> {
    x.mul(&x.mul(&x.mul(c1)?.add(c2)?)?.add(c3)?)?.add(c4)
}

lazy_static::lazy_static! {

    /// The constants that define the isogeny mapping for secp256k1
    static ref K256_C : [EccFieldElement; 13] = {
        let fb = |bs| EccFieldElement::from_bytes(EccCurveType::K256, bs).expect("Constant was invalid");
        [fb(&hex!("8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA88C")),
         fb(&hex!("534C328D23F234E6E2A413DECA25CAECE4506144037C40314ECBD0B53D9DD262")),
         fb(&hex!("07D3D4C80BC321D5B9F315CEA7FD44C5D595D2FC0BF63B92DFFF1044F17C6581")),
         fb(&hex!("8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA8C7")),
         fb(&hex!("EDADC6F64383DC1DF7C4B2D51B54225406D36B641F5E41BBC52A56612A8C6D14")),
         fb(&hex!("D35771193D94918A9CA34CCBB7B640DD86CD409542F8487D9FE6B745781EB49B")),
         fb(&hex!("2F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F38E38D84")),
         fb(&hex!("29A6194691F91A73715209EF6512E576722830A201BE2018A765E85A9ECEE931")),
         fb(&hex!("C75E0C32D5CB7C0FA9D0A54B12A0A6D5647AB046D686DA6FDFFC90FC201D71A3")),
         fb(&hex!("4BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684B8E38E23C")),
         fb(&hex!("6484AA716545CA2CF3A70C3FA8FE337E0A3D21162F0D6299A7BF8192BFD2A76F")),
         fb(&hex!("7A06534BB8BDB49FD5E9E6632722C2989467C1BFC8E8D978DFB425D2685C2573")),
         fb(&hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFF93B")),
        ]
    };
}

///Returns (x,y) where:
/// * x = x_num / x_den, where
///     * x_num = C0 * x'^3 + C1 * x'^2 + C2 * x' + C3
///     * x_den = x'^2 + C4 * x' + C5
/// * y = y' * y_num / y_den, where
///    * y_num = C6 * x'^3 + C7 * x'^2 + C8 * x' + C9
///    * y_den = x'^3 + C10 * x'^2 + C11 * x' + C12
///
/// where Ci refers to the constants in the variable K256_C[i]
fn sswu_isogeny_secp256k1(
    x: &EccFieldElement,
    y: &EccFieldElement,
) -> ThresholdEcdsaResult<(EccFieldElement, EccFieldElement)> {
    let xnum = x3c1_x2c2_xc3_c4(x, &K256_C[0], &K256_C[1], &K256_C[2], &K256_C[3])?;

    let xden = x2_xc1_c2(x, &K256_C[4], &K256_C[5])?;

    let ynum = x3c1_x2c2_xc3_c4(x, &K256_C[6], &K256_C[7], &K256_C[8], &K256_C[9])?;

    let yden = x3_x2c1_xc2_c3(x, &K256_C[10], &K256_C[11], &K256_C[12])?;

    // We could avoid an inversion with projective points:
    //   (X, Y, Z) = (xnum * yden, ynum * xden, xden * yden).
    // The EccPoint API insists on affine coordinates, so we must invert.
    //
    // We can perform both inversions in one step, using what is
    // usually called Montgomery's trick:
    //
    //   To compute x^-1 and y^-1 compute z=(x*y)^-1
    //   Then z*y = x^-1 and z*x = y^-1
    let inv = xden.mul(&yden)?.invert();

    let k256_x = xnum.mul(&inv.mul(&yden)?)?;
    let k256_y = y.mul(&ynum.mul(&inv.mul(&xden)?)?)?;

    Ok((k256_x, k256_y))
}
