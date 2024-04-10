macro_rules! declare_mul_by_g_impl {
    ($tbl_typ:ident, $projective:ty, $scalar:ty) => {
        /// Structure for precomputed multiplication p*x
        ///
        /// It works by precomputing a table containing the powers of p
        /// which allows the online phase of the scalar multiplication
        /// to be effected using only additions.
        ///
        /// As the precomputation phase is expensive this is only worth using
        /// for points which are multiplied many times (typically the standard
        /// group generators).
        pub struct $tbl_typ {
            table: Vec<$projective>,
        }

        impl $tbl_typ {
            /// The number of bits we examine in each scalar per iteration
            const WINDOW_BITS: usize = 3;
            // 2^w elements minus one (since one table element is always the identity)
            const TABLE_ELEM_PER_WINDOW: usize = (1 << Self::WINDOW_BITS) - 1;

            pub fn new(p: &$projective) -> Self {
                type Window = crate::WindowInfo<{ <$tbl_typ>::WINDOW_BITS }>;
                const WINDOWS: usize = Window::number_of_windows_for_bits(<$scalar>::BITS);

                let mut table = Vec::with_capacity(Self::TABLE_ELEM_PER_WINDOW * WINDOWS);

                let mut accum = p.clone();

                for _ in 0..WINDOWS {
                    let x1 = accum;
                    let x2 = x1.double();
                    let x3 = x2.add(&x1);
                    let x4 = x2.double();
                    let x5 = x4.add(&x1);
                    let x6 = x3.double();
                    let x7 = x6.add(&x1);
                    let x8 = x4.double();

                    table.push(x1);
                    table.push(x2);
                    table.push(x3);
                    table.push(x4);
                    table.push(x5);
                    table.push(x6);
                    table.push(x7);

                    accum = x8;
                }

                Self { table }
            }

            pub fn mul(&self, x: &$scalar) -> $projective {
                type Window = crate::WindowInfo<{ <$tbl_typ>::WINDOW_BITS }>;
                const WINDOWS: usize = Window::number_of_windows_for_bits(<$scalar>::BITS);

                assert_eq!(self.table.len(), WINDOWS * Self::TABLE_ELEM_PER_WINDOW);

                let s = x.to_bytes();

                let mut accum = <$projective>::identity();

                for i in 0..WINDOWS {
                    let tbl_i = &self.table
                        [Self::TABLE_ELEM_PER_WINDOW * i..(Self::TABLE_ELEM_PER_WINDOW * (i + 1))];
                    let w = Window::extract(&s, WINDOWS - 1 - i) as usize;
                    accum = accum.add(&<$projective>::ct_select(tbl_i, w));
                }

                accum
            }
        }
    };
}

pub(crate) use declare_mul_by_g_impl;

// declare the impl for the mul2 table struct
macro_rules! declare_mul2_table_impl {
    ($tbl_typ:ident, $projective:ty, $scalar:ty) => {
        /// Structure for precomputed multiplication g*x+h*y
        ///
        /// It works by precomputing a series of table, each of which
        /// consists of a linear combination of (a multiple of) g and h;
        /// each table is used for only a single window.
        ///
        /// We use a 2 bit window, so in each iteration examine 4 bits of
        /// scalar (2 from x and 2 from y).
        ///
        /// At each iteration we select a single element from the table. If
        /// all the bits of x and y are zero then the element is always the
        /// identity, which is omitted from each table to save space.
        ///
        /// The first 15 elements are:
        ///  [g, 2*g, 3*g, h, g + h, 2*g + h, 3*g + h, 2*h, g + 2*h, 2*g + 2*h, 3*g + 2*h, 3*h, g + 3*h, 2*g + 3*h, 3*g + 3*h]
        ///
        /// The next 15 elements are the same except replace g with 4*g, and h
        /// by 4*h:
        ///  [4*g, 8*g, 12*g, 4*h, 4*g + 4*h, ...]
        ///
        /// And so on. During the online part of the algorithm, we examine two
        /// bits of x and two bits of y, and choose one of the table elements,
        /// adding it to our accumulator.
        ///
        /// This approach is only competitive if g and h are very long lived;
        /// the precomputation step is quite expensive. It is intended for use
        /// with the standard generators, which are known at compile time.

        pub struct $tbl_typ {
            table: Vec<$projective>,
        }

        impl $tbl_typ {
            /// The number of bits we examine in each scalar per iteration
            const WINDOW_BITS: usize = 2;
            /// The value of 2^WINDOW_BITS
            const WINDOW_ELEM: usize = 1 << Self::WINDOW_BITS;
            // 2^(2*w) elements minus one (since it is always the identity)
            const TABLE_ELEM_PER_BIT: usize = (1 << (2 * Self::WINDOW_BITS)) - 1;

            // Total number of elements in the table
            const TABLE_SIZE: usize = Self::TABLE_ELEM_PER_BIT * <$scalar>::BITS;

            // The number of windows (of WINDOW_BITS size) required to examine every
            // bit of a scalar of this curve.
            const WINDOWS: usize = (<$scalar>::BITS + Self::WINDOW_BITS - 1) / Self::WINDOW_BITS;

            pub fn for_standard_generators() -> Self {
                let g = <$projective>::generator();
                let h = <$projective>::generator_h();
                Self::new(g, h)
            }

            pub fn new(mut x: $projective, mut y: $projective) -> Self {
                let mut table = Vec::with_capacity(Self::TABLE_SIZE);

                for _ in 0..<$scalar>::BITS {
                    let x2 = x.double();
                    let x3 = x2.add(&x);
                    let x4 = x2.double();

                    let y2 = y.double();
                    let y3 = y2.add(&y);
                    let y4 = y2.double();

                    let x_w = [&x, &x2, &x3];
                    let y_w = [&y, &y2, &y3];

                    // compute linear combinations of x/y ignoring the case of i == 0
                    // as that is always the identity
                    for i in 1..1 + Self::TABLE_ELEM_PER_BIT {
                        let x_i = i % Self::WINDOW_ELEM;
                        let y_i = i / Self::WINDOW_ELEM;

                        let x_pt = if x_i > 0 { Some(x_w[x_i - 1]) } else { None };
                        let y_pt = if y_i > 0 { Some(y_w[y_i - 1]) } else { None };

                        // Avoid a point addition unless we have to combine two points:
                        let accum = match (x_pt, y_pt) {
                            (Some(x), Some(y)) => x.add(y),
                            (Some(x), None) => x.clone(),
                            (None, Some(y)) => y.clone(),
                            (None, None) => unreachable!("At least one bit is set in the index"),
                        };

                        table.push(accum);
                    }

                    x = x4;
                    y = y4;
                }

                Self { table }
            }

            /// Computes g*a + h*b where g and h are the points specified during construction
            pub fn mul2(&self, a: &$scalar, b: &$scalar) -> $projective {
                let s1 = a.to_bytes();
                let s2 = b.to_bytes();

                let mut accum = <$projective>::identity();

                for i in 0..Self::WINDOWS {
                    let tbl_i = &self.table
                        [Self::TABLE_ELEM_PER_BIT * i..Self::TABLE_ELEM_PER_BIT * (i + 1)];

                    let w1 = Self::extract(&s1, Self::WINDOWS - 1 - i);
                    let w2 = Self::extract(&s2, Self::WINDOWS - 1 - i);

                    let w = w1 + (w2 << Self::WINDOW_BITS);

                    accum = accum.add(&<$projective>::ct_select(tbl_i, w));
                }

                accum
            }

            // Return the i'th 2-bit window of scalar
            #[inline(always)]
            fn extract(scalar: &[u8], i: usize) -> usize {
                let b = scalar[i / 4];
                let shift = 6 - 2 * (i % 4);
                ((b >> shift) % 4) as usize
            }
        }
    };
}

pub(crate) use declare_mul2_table_impl;

macro_rules! declare_sswu_p_3_mod_4_map_to_curve_impl {
    ($fn_name:ident, $fe:ident, $pt:ident, $map_to_curve:ident) => {
        fn $fn_name(input: &[u8], dst: &[u8]) -> $pt {
            fn hash_to_fe(input: &[u8], dst: &[u8]) -> ($fe, $fe) {
                const P_BITS: usize = $fe::BYTES * 8;
                const SECURITY_LEVEL: usize = P_BITS / 2;

                const FIELD_LEN: usize = (P_BITS + SECURITY_LEVEL + 7) / 8; // "L" in spec
                const LEN_IN_BYTES: usize = 2 * FIELD_LEN;
                const WIDE_BYTES_OFFSET: usize = 2 * $fe::BYTES - FIELD_LEN;

                // Compile time assertion that XMD can output the requested bytes
                const _: () = assert!(LEN_IN_BYTES <= 8160, "XMD output is sufficient");

                // XMD only fails if the requested output is too long, but we already checked
                // at compile time that the output length is within range.
                let u = ic_crypto_internal_seed::xmd::expand_message_xmd(input, dst, LEN_IN_BYTES)
                    .expect("XMD unexpected failed");

                fn extended_u(u: &[u8]) -> [u8; 2 * $fe::BYTES] {
                    let mut ext_u = [0u8; 2 * $fe::BYTES];
                    ext_u[WIDE_BYTES_OFFSET..].copy_from_slice(&u);
                    ext_u
                }

                let u0 = $fe::from_bytes_wide_exact(&extended_u(&u[..FIELD_LEN]));
                let u1 = $fe::from_bytes_wide_exact(&extended_u(&u[FIELD_LEN..]));

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
