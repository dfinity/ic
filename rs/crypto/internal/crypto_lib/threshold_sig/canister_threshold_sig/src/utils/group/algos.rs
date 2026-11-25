macro_rules! declare_sswu_p_3_mod_4_map_to_curve_impl {
    ($fn_name:ident, $fe:ident, $pt:ident, $map_to_curve:ident) => {
        fn $fn_name(input: &[u8], dst: &[u8]) -> $pt {
            fn hash_to_fe(input: &[u8], dst: &[u8]) -> ($fe, $fe) {
                const P_BITS: usize = $fe::BYTES * 8;
                const SECURITY_LEVEL: usize = P_BITS / 2;

                const FIELD_BYTES: usize = (P_BITS + SECURITY_LEVEL).div_ceil(8); // "L" in spec
                const XMD_BYTES: usize = 2 * FIELD_BYTES;
                const WIDE_BYTES_OFFSET: usize = 2 * $fe::BYTES - FIELD_BYTES;

                let u =
                    ic_crypto_internal_seed::xmd::<XMD_BYTES, ic_crypto_sha2::Sha256>(input, dst);

                fn extended_u(u: &[u8]) -> [u8; 2 * $fe::BYTES] {
                    let mut ext_u = [0_u8; 2 * $fe::BYTES];
                    ext_u[WIDE_BYTES_OFFSET..].copy_from_slice(&u);
                    ext_u
                }

                let u0 = $fe::from_bytes_wide_exact(&extended_u(&u[..FIELD_BYTES]));
                let u1 = $fe::from_bytes_wide_exact(&extended_u(&u[FIELD_BYTES..]));

                (u0, u1)
            }

            /// SSWU (Simplified Shallue-van de Woestijne-Ulas)
            ///
            /// This is a mapping from u to (x,y) where u is an arbitrary
            /// field element and (x,y) is a valid elliptic curve point.
            ///
            /// See RFC 9380 section 6.6.2 <https://www.rfc-editor.org/rfc/rfc9380.html#section-6.6.2>
            /// for details.
            fn sswu(u: &$fe) -> ($fe, $fe) {
                // Specialized version for p == 3 (mod 4)
                //
                // If in the future we needed to support SSWU with curves where
                // p == 1 (mod 4) we could use the generalized version instead
                fn sqrt_ratio(u: &$fe, v: &$fe) -> (subtle::Choice, $fe) {
                    let c2 = $fe::sswu_c2();

                    let tv1 = v.square();
                    let tv2 = u.mul(v);
                    let tv1 = tv1.mul(&tv2);
                    let y1 = tv1.progenitor(); // see https://eprint.iacr.org/2020/1497.pdf
                    let y1 = y1.mul(&tv2);
                    let y2 = y1.mul(&c2);
                    let tv3 = y1.square();
                    let tv3 = tv3.mul(v);
                    let is_qr = tv3.ct_eq(u);
                    let y = $fe::cmov(&y2, &y1, is_qr);
                    (is_qr, y)
                }

                let a = $fe::sswu_a();
                let b = $fe::sswu_b();
                let z = $fe::sswu_z();
                let one = $fe::one();

                let tv1 = z.mul(&u.square());
                let mut tv2 = tv1.square();
                tv2 = tv2.add(&tv1);
                let mut tv3 = tv2.add(&one);
                tv3 = tv3.mul(&b);
                let mut tv4 = $fe::cmov(&z, &tv2.negate(), !tv2.is_zero());
                tv4 = tv4.mul(&a);
                tv2 = tv3.square();
                let mut tv6 = tv4.square();
                let mut tv5 = tv6.mul(&a);
                tv2 = tv2.add(&tv5);
                tv2 = tv2.mul(&tv3);
                tv6 = tv6.mul(&tv4);
                tv5 = tv6.mul(&b);
                tv2 = tv2.add(&tv5);

                let mut x = tv1.mul(&tv3);

                let (is_gx1_square, y1) = sqrt_ratio(&tv2, &tv6);

                let mut y = tv1.mul(u);
                y = y.mul(&y1);
                x = $fe::cmov(&x, &tv3, is_gx1_square);
                y = $fe::cmov(&y, &y1, is_gx1_square);
                // Same as u.sign() == y.sign() but hopefully less problematic re constant-time
                let e1 = subtle::Choice::from(u.sign() ^ y.sign() ^ 1);
                y = $fe::cmov(&y.negate(), &y, e1);
                x = x.mul(&tv4.invert());

                (x, y)
            }

            let (u0, u1) = hash_to_fe(input, dst);

            let q0 = $map_to_curve(&sswu(&u0));
            let q1 = $map_to_curve(&sswu(&u1));

            q0.add(&q1)
        }
    };
}

pub(crate) use declare_sswu_p_3_mod_4_map_to_curve_impl;
