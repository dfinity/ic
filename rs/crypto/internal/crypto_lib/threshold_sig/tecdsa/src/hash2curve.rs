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
    let mut r = a.clone();
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
    let z = EccFieldElement::sswu_z(curve_type);
    let vinv = v.invert();
    let uov = u.mul(&vinv)?;
    let sqrt_uov = uov.sqrt();
    let uov_is_qr = !sqrt_uov.is_zero();
    let z_uov = z.mul(&uov)?;
    let sqrt_z_uov = z_uov.sqrt();
    Ok((uov_is_qr, cmov(&sqrt_z_uov, &sqrt_uov, uov_is_qr)?))
}

/// Simplified Shallue-van de Woestijne-Ulas method
///
/// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-12.html#name-simplified-swu-method
#[allow(clippy::many_single_char_names)]
fn sswu(u: &EccFieldElement) -> ThresholdEcdsaResult<EccPoint> {
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

    EccPoint::from_field_elems(&x, &y)
}

fn map_to_curve(fe: &EccFieldElement) -> ThresholdEcdsaResult<EccPoint> {
    match fe.curve_type() {
        EccCurveType::P256 => sswu(fe),
        EccCurveType::K256 => sswu_isogeny_secp256k1(fe),
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

fn sswu_isogeny_secp256k1(h: &EccFieldElement) -> ThresholdEcdsaResult<EccPoint> {
    let curve = EccCurveType::K256;
    let fb = |bs| EccFieldElement::from_bytes(curve, bs);
    let one = EccFieldElement::one(curve);
    let sswu_a = EccFieldElement::sswu_a(curve);
    let sswu_b = EccFieldElement::sswu_b(curve);
    let sswu_z = EccFieldElement::sswu_z(curve);
    // We add underscores to some names to work around Clippy warnings.
    let t_ = sswu_z.mul(&h.square()?)?;
    let tt1 = (t_.add(&one)?).mul(&t_)?;
    let d_ = tt1.mul(&sswu_a)?;
    let x2 = (tt1.add(&one)?).mul(&sswu_b)?.negate()?;
    let d2 = d_.square()?;
    let gx1 = x2
        .mul(&x2.square()?.add(&d2.mul(&sswu_a)?)?)?
        .add(&d2.mul(&d_.mul(&sswu_b)?)?)?;
    let w = gx1.mul(&d_)?;
    // Compute the 'progenitor' of w. https://eprint.iacr.org/2020/1497.pdf
    // For secp256k1 it is w^((p-3)/4).
    let mut wpg = one;
    for i in (0..254).rev() {
        wpg = wpg.square()?;
        // In binary, p is 256 1-bits except for 0-bits at positions 4 6 7 8 9 32.
        // The exponent is (p-3)/4, so we subtract 2 from each position.
        // (We could save many multiplications with a better addition chain.)
        if i >= 8 && i != 30 || i <= 3 && i != 2 {
            wpg = wpg.mul(&w)?;
        }
    }
    let wpg2 = wpg.square()?;
    // w*wpg^2 = w^((p-1)/2) tests quadratic reciprocity (Legendre symbol).
    // As p is odd, the parity of (-1) is 0, and we use sign() instead of is_one().
    let cond = w.mul(&wpg2)?.sign() != 1;
    // w*wpg^4 = w^(p-2) is the inverse of w.
    // Multiplying this by gx1 recovers the inverse of d.
    let dinv = wpg2.square()?.mul(&w)?.mul(&gx1)?;
    let dinv2 = dinv.square()?;
    let x = cmov(&x2, &x2.mul(&t_)?, cond)?.mul(&dinv)?;
    // The progenitor of sswu_z, namely (-11)^((p-3)/4).
    let zpg = fb(&hex!(
        "CCE8E9E8813FFE30F4D5B4640A39CD8BBBFDCA45C23F508ECDC813789E8624AA"
    ))?;
    // Square root of w or w*sswu_z.
    let rt = cmov(&w, &w.mul(&sswu_z)?, cond)?.mul(&cmov(&wpg, &wpg.mul(&zpg)?, cond)?)?;
    let y1 = cmov(&dinv2, &dinv2.mul(h)?.mul(&t_)?, cond)?;
    let y2 = y1.mul(&cmov(&rt, &rt.negate()?, rt.sign() == 1)?)?;
    let y = cmov(&y2, &y2.negate()?, y2.sign() != h.sign())?;
    let xnum = &x
        .mul(
            &x.mul(
                &x.mul(&fb(&hex!(
                    "8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA88C"
                ))?)?
                .add(&fb(&hex!(
                    "534C328D23F234E6E2A413DECA25CAECE4506144037C40314ECBD0B53D9DD262"
                ))?)?,
            )?
            .add(&fb(&hex!(
                "07D3D4C80BC321D5B9F315CEA7FD44C5D595D2FC0BF63B92DFFF1044F17C6581"
            ))?)?,
        )?
        .add(&fb(&hex!(
            "8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA8C7"
        ))?)?;

    let xden = x
        .mul(&x.add(&fb(&hex!(
            "EDADC6F64383DC1DF7C4B2D51B54225406D36B641F5E41BBC52A56612A8C6D14"
        ))?)?)?
        .add(&fb(&hex!(
            "D35771193D94918A9CA34CCBB7B640DD86CD409542F8487D9FE6B745781EB49B"
        ))?)?;

    let ynum = &y.mul(
        &x.mul(
            &x.mul(
                &x.mul(&fb(&hex!(
                    "2F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F38E38D84"
                ))?)?
                .add(&fb(&hex!(
                    "29A6194691F91A73715209EF6512E576722830A201BE2018A765E85A9ECEE931"
                ))?)?,
            )?
            .add(&fb(&hex!(
                "C75E0C32D5CB7C0FA9D0A54B12A0A6D5647AB046D686DA6FDFFC90FC201D71A3"
            ))?)?,
        )?
        .add(&fb(&hex!(
            "4BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684B8E38E23C"
        ))?)?,
    )?;

    let yden = &x
        .mul(
            &x.mul(&x.add(&fb(&hex!(
                "6484AA716545CA2CF3A70C3FA8FE337E0A3D21162F0D6299A7BF8192BFD2A76F"
            ))?)?)?
            .add(&fb(&hex!(
                "7A06534BB8BDB49FD5E9E6632722C2989467C1BFC8E8D978DFB425D2685C2573"
            ))?)?,
        )?
        .add(&fb(&hex!(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFF93B"
        ))?)?;
    // We could avoid an inversion with projective points:
    //   (X, Y, Z) = (xnum * yden, ynum * xden, xden * yden).
    // The EccPoint API insists on affine coordinates, so we must invert.
    let inv = xden.mul(yden)?.invert();
    EccPoint::from_field_elems(&xnum.mul(&yden.mul(&inv)?)?, &ynum.mul(&xden.mul(&inv)?)?)
}
