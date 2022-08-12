use ic_crypto_internal_bls12_381_type::*;
use ic_crypto_internal_types::curves::test_vectors::bls12_381 as test_vectors;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::Digest;

fn scalar_test_encoding(scalar: Scalar, expected_value: &'static str) {
    assert_eq!(hex::encode(scalar.serialize()), expected_value);

    let decoded = Scalar::deserialize(&hex::decode(expected_value).expect("Invalid hex"))
        .expect("Invalid encoding");

    assert_eq!(decoded, scalar);
}

fn g1_test_encoding(pt: G1Affine, expected_value: &'static str) {
    assert_eq!(hex::encode(pt.serialize()), expected_value);

    let decoded = G1Affine::deserialize(&hex::decode(expected_value).expect("Invalid hex"))
        .expect("Invalid encoding");

    assert_eq!(decoded, pt);
}

fn g2_test_encoding(pt: G2Affine, expected_value: &'static str) {
    assert_eq!(hex::encode(pt.serialize()), expected_value);

    let decoded = G2Affine::deserialize(&hex::decode(expected_value).expect("Invalid hex"))
        .expect("Invalid encoding");

    assert_eq!(decoded, pt);
}

fn seeded_rng() -> ChaCha20Rng {
    let mut thread_rng = rand::thread_rng();
    let seed = thread_rng.gen::<u64>();
    println!("RNG seed {}", seed);
    ChaCha20Rng::seed_from_u64(seed)
}

#[test]
fn scalar_legacy_random_generates_expected_values() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    scalar_test_encoding(
        Scalar::legacy_random_generation(&mut rng),
        "54ee2937b4dfc1905ccaf277a60b5e53c7ea791f6b9bdadd7e84e7f458d4d0a4",
    );
}

#[test]
fn scalar_miracl_random_generates_expected_values() {
    let seed = hex::decode("4e42f768bab72a9248a43c439a330b94e3d39595c627eb603fff8ff84b7a9914")
        .expect("valid");
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed.try_into().expect("Invalid size"));

    scalar_test_encoding(
        Scalar::miracl_random(&mut rng),
        "0ab77cf4d9338f6bfdcd9541574bf1211e8b552743426917e405739c029407aa",
    );

    let seed = hex::decode("8844d58a75db49c9df827e21085ea9d46f0a14e2bc6edaab27aeb640f88c313a")
        .expect("valid");
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed.try_into().expect("Invalid size"));

    scalar_test_encoding(
        Scalar::miracl_random(&mut rng),
        "583912964c0e5c35604b073bf5fe37c4a17f7dc3cd597481116ff9f4c544b2f3",
    );
}

#[test]
fn scalar_legacy_hash_to_fr_generates_expected_values() {
    fn sha256(input: &[u8]) -> [u8; 32] {
        sha2::Sha256::digest(input).into()
    }

    scalar_test_encoding(
        Scalar::legacy_hash_to_fr(sha256(b"A test input")),
        "630fcb163218d5cd34f3ee5dc68bdbeda20975a54e08b130f3457afc6728d1d5",
    );

    scalar_test_encoding(
        Scalar::legacy_hash_to_fr(sha256(b"A second unrelated test input")),
        "699ed6764b14e1ae3ff73686399084f4fbbd51b972f85c49e4ef0954b36921af",
    );
}

#[test]
fn scalar_random_generates_expected_values() {
    let seed = 802;

    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    assert_eq!(
        hex::encode(bytes),
        "b257761dbdaf0bcb97fb808f7b95ed1ec1974557af790021ff073ee14811b3d9"
    );

    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    scalar_test_encoding(
        Scalar::random(&mut rng),
        "3257761dbdaf0bcb97fb808f7b95ed1ec1974557af790021ff073ee14811b3d9",
    );
}

#[test]
fn scalar_zero_generates_expected_values() {
    scalar_test_encoding(
        Scalar::zero(),
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn scalar_one_generates_expected_values() {
    scalar_test_encoding(
        Scalar::one(),
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
}

#[test]
fn scalar_two_generates_expected_values() {
    scalar_test_encoding(
        Scalar::one() + Scalar::one(),
        "0000000000000000000000000000000000000000000000000000000000000002",
    );
}

#[test]
fn test_scalar_comparison() {
    let zero = Scalar::zero();
    let one = Scalar::one();

    assert!(zero < one);
    assert!(one > zero);

    assert!(zero <= zero);
    assert!(zero >= zero);

    assert!(one <= one);
    assert!(one >= one);

    let mut rng = seeded_rng();

    for _ in 0..300 {
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);

        assert_eq!(a.serialize().cmp(&b.serialize()), a.cmp(&b));
        assert_eq!(b.serialize().cmp(&a.serialize()), b.cmp(&a));

        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
        assert_eq!(b.cmp(&b), std::cmp::Ordering::Equal);
    }

    for _ in 0..300 {
        let a = Scalar::from_u32(rng.gen::<u32>());
        let b = Scalar::from_u32(rng.gen::<u32>());

        assert_eq!(a.serialize().cmp(&b.serialize()), a.cmp(&b));
        assert_eq!(b.serialize().cmp(&a.serialize()), b.cmp(&a));

        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
        assert_eq!(b.cmp(&b), std::cmp::Ordering::Equal);
    }
}

#[test]
fn test_scalar_from_integer_type() {
    let mut rng = seeded_rng();

    assert_eq!(Scalar::zero(), Scalar::from_i32(0));
    assert_eq!(Scalar::zero(), Scalar::from_u32(0));
    assert_eq!(Scalar::zero(), Scalar::from_u64(0));

    assert_eq!(Scalar::one(), Scalar::from_i32(1));
    assert_eq!(Scalar::one(), Scalar::from_u32(1));
    assert_eq!(Scalar::one(), Scalar::from_u64(1));

    // check overflow handling (i32::MIN.abs() is greater than i32::MAX)
    assert_eq!(
        Scalar::from_i32(i32::MIN).neg(),
        Scalar::from_i32(i32::MAX) + Scalar::one()
    );

    for _ in 0..30 {
        let r = rng.gen::<u32>();
        assert_eq!(Scalar::from_u32(r), Scalar::from_u64(r as u64));

        let bytes = Scalar::from_u32(r).serialize();
        let mut expected = [0u8; 32];
        expected[28..].copy_from_slice(&r.to_be_bytes());
        assert_eq!(bytes, expected);
    }

    for _ in 0..30 {
        let r = rng.gen::<i32>();

        let s = Scalar::from_i32(r);

        if r < 0 {
            assert_eq!(s.neg(), Scalar::from_u32((-r) as u32));
        } else {
            assert_eq!(s, Scalar::from_u32(r as u32));
        }
    }
}

#[test]
fn test_scalar_is_zero() {
    assert!(Scalar::zero().is_zero());
    assert!(!Scalar::one().is_zero());
}

#[test]
fn test_scalar_addition() {
    let mut rng = seeded_rng();

    for _ in 0..30 {
        let s1 = Scalar::random(&mut rng);
        let s2 = Scalar::random(&mut rng);

        let s3 = s1 + s2;

        let mut s4 = s3;
        assert_eq!(s4, s3);
        s4 -= s2;
        assert_eq!(s4, s1);
        s4 += s2;
        assert_eq!(s4, s3);
        s4 -= s1;
        assert_eq!(s4, s2);
    }
}

#[test]
fn test_scalar_neg() {
    let mut rng = seeded_rng();

    for _ in 0..30 {
        let scalar = Scalar::random(&mut rng);
        let nscalar = scalar.neg();
        assert_eq!(scalar + nscalar, Scalar::zero());
    }
}

#[test]
fn test_scalar_inverse() {
    let mut rng = seeded_rng();

    assert_eq!(Scalar::zero().inverse(), None);
    assert_eq!(Scalar::one().inverse(), Some(Scalar::one()));

    for _ in 0..30 {
        let scalar = Scalar::random(&mut rng);

        match scalar.inverse() {
            None => assert!(scalar.is_zero()),
            Some(inv) => {
                assert_eq!(scalar * inv, Scalar::one())
            }
        }
    }
}

#[test]
fn test_impl_debugs() {
    assert_eq!(
        format!("{:?}", Scalar::one().neg()),
        "Scalar(73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000)"
    );

    assert_eq!(format!("{:?}", G1Affine::generator()),
               "G1Affine(97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb)");
    assert_eq!(format!("{:?}", G2Affine::generator()),
               "G2Affine(93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8)");
}

#[test]
fn test_gt_generator_is_expected_value() {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    assert_eq!(Gt::pairing(&g1, &g2), Gt::generator());
}

#[test]
fn test_pairing_bilinearity() {
    let mut rng = seeded_rng();

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    for _ in 0..3 {
        let s1 = Scalar::random(&mut rng);
        let s2 = Scalar::random(&mut rng);
        let s3 = Scalar::random(&mut rng);

        let mul_123 = Gt::pairing(&(g1 * s1).into(), &(g2 * s2).into()) * s3;
        let mul_132 = Gt::pairing(&(g1 * s1).into(), &(g2 * s3).into()) * s2;
        let mul_213 = Gt::pairing(&(g1 * s2).into(), &(g2 * s1).into()) * s3;
        let mul_231 = Gt::pairing(&(g1 * s2).into(), &(g2 * s3).into()) * s1;
        let mul_312 = Gt::pairing(&(g1 * s3).into(), &(g2 * s1).into()) * s2;
        let mul_321 = Gt::pairing(&(g1 * s3).into(), &(g2 * s2).into()) * s1;

        let mul_gt = ((Gt::generator() * s1) * s2) * s3;

        assert_eq!(mul_123, mul_gt);
        assert_eq!(mul_132, mul_gt);
        assert_eq!(mul_213, mul_gt);
        assert_eq!(mul_231, mul_gt);
        assert_eq!(mul_312, mul_gt);
        assert_eq!(mul_321, mul_gt);
    }
}

#[test]
fn test_g1_addition() {
    let mut rng = seeded_rng();

    let g = G1Affine::generator();

    for _ in 0..30 {
        let s0 = Scalar::random(&mut rng);
        let s1 = Scalar::random(&mut rng);
        let s2 = s0 - s1;

        let gs0 = g * s0;
        let gs1 = g * s1;
        let gs2 = g * s2;
        assert_eq!(gs0, gs1 + gs2);
        assert_eq!(gs0 - gs1, gs2);
        assert_eq!(gs0 - gs2, gs1);
    }
}

#[test]
fn test_g2_addition() {
    let mut rng = seeded_rng();

    let g = G2Affine::generator();

    for _ in 0..30 {
        let s0 = Scalar::random(&mut rng);
        let s1 = Scalar::random(&mut rng);
        let s2 = s0 - s1;

        let gs0 = g * s0;
        let gs1 = g * s1;
        let gs2 = g * s2;
        assert_eq!(gs0, gs1 + gs2);
        assert_eq!(gs0 - gs1, gs2);
        assert_eq!(gs0 - gs2, gs1);
    }
}

#[test]
fn test_gt_addition() {
    let mut rng = seeded_rng();

    let g = Gt::generator();

    for _ in 0..30 {
        let s0 = Scalar::random(&mut rng);
        let s1 = Scalar::random(&mut rng);
        let s2 = s0 - s1;

        let gs0 = g * s0;
        let gs1 = g * s1;
        let gs2 = g * s2;
        assert_eq!(gs0, gs1 + gs2);
        assert_eq!(gs0 - gs1, gs2);
        assert_eq!(gs0 - gs2, gs1);
    }
}

#[test]
fn test_g1_generator_is_expected_value() {
    /*
    The generators of G1 and and G2 are computed by finding the
    lexicographically smallest valid x-coordinate, and its
    lexicographically smallest y-coordinate and scaling it by the
    cofactor such that the result is not the point at infinity.

    For G1 x = 4
    */
    let g1_cofactor = Scalar::deserialize(
        &hex::decode("00000000000000000000000000000000396c8c005555e1568c00aaab0000aaab").unwrap(),
    )
    .unwrap();

    fn x4() -> [u8; 48] {
        let mut x4 = [0u8; 48];
        x4[0] = 0x80; // set compressed bit
        x4[47] = 4;
        x4
    }

    let x4 = G1Affine::deserialize_unchecked(&x4()).unwrap();

    let g1 = x4 * g1_cofactor;

    assert_eq!(g1, G1Projective::generator());
    assert_eq!(G1Affine::from(g1), G1Affine::generator());

    assert_eq!(hex::encode(G1Affine::generator().serialize()),
               "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
}

#[test]
fn test_g2_generator_is_expected_value() {
    assert_eq!(hex::encode(G2Affine::generator().serialize()),
               "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8");
}

#[test]
fn test_identity_is_identity() {
    assert!(G1Affine::identity().is_identity());
    assert!(G1Projective::identity().is_identity());
    assert!(G2Affine::identity().is_identity());
    assert!(G2Projective::identity().is_identity());
    assert!(Gt::identity().is_identity());

    let s = Scalar::from_u64(9);

    assert!((G1Affine::identity() * s).is_identity());
    assert!((G1Projective::identity() * s).is_identity());
    assert!((G2Affine::identity() * s).is_identity());
    assert!((G2Projective::identity() * s).is_identity());
    assert!((Gt::identity() * s).is_identity());
}

#[test]
fn test_point_neg() {
    assert_eq!(G1Affine::identity(), G1Affine::identity().neg());
    assert_eq!(G1Projective::identity(), G1Projective::identity().neg());
    assert_eq!(G2Affine::identity(), G2Affine::identity().neg());
    assert_eq!(G2Projective::identity(), G2Projective::identity().neg());

    let pt_pos = G1Projective::generator() * Scalar::from_u32(42);
    let pt_neg = G1Projective::generator() * Scalar::from_i32(-42);

    assert_eq!(pt_pos.neg(), pt_neg);
    assert_eq!(pt_neg.neg(), pt_pos);
    assert!((pt_pos + pt_neg).is_identity());

    let pt_pos = G2Projective::generator() * Scalar::from_u32(42);
    let pt_neg = G2Projective::generator() * Scalar::from_i32(-42);

    assert_eq!(pt_pos.neg(), pt_neg);
    assert_eq!(pt_neg.neg(), pt_pos);
    assert!((pt_pos + pt_neg).is_identity());
}

#[test]
fn test_multipairing() {
    let g1 = G1Affine::generator();
    let g1n = G1Affine::generator().neg();
    let g2p = G2Prepared::generator();
    let g2pn = G2Prepared::neg_generator();

    assert_eq!(Gt::multipairing(&[]), Gt::identity());

    assert_eq!(Gt::multipairing(&[(&g1, &g2p)]), Gt::generator());

    assert_eq!(Gt::multipairing(&[(&g1n, &g2pn)]), Gt::generator());

    assert_eq!(Gt::multipairing(&[(&g1, &g2pn)]), Gt::generator().neg());

    assert_eq!(Gt::multipairing(&[(&g1n, &g2p)]), Gt::generator().neg());

    let mut rng = seeded_rng();

    for _ in 0..5 {
        let a = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let c = Scalar::random(&mut rng);

        let g1a = G1Affine::from(G1Projective::generator() * a);
        let g1b = G1Affine::from(G1Projective::generator() * b);
        let g1c = G1Affine::from(G1Projective::generator() * c);

        let g2a = G2Prepared::from(G2Projective::generator() * a);
        let g2b = G2Prepared::from(G2Projective::generator() * b);
        let g2c = G2Prepared::from(G2Projective::generator() * c);

        let g2 = G2Prepared::generator();

        assert_eq!(
            Gt::multipairing(&[(&g1a, &g2), (&g1b, &g2), (&g1c, &g2)]),
            Gt::multipairing(&[(&g1, &g2a), (&g1, &g2b), (&g1, &g2c)]),
        );
    }
}

#[test]
fn test_g1_is_torsion_free() {
    let mut rng = seeded_rng();

    for _ in 0..30 {
        let mut buf = [0u8; G1Affine::BYTES];
        rng.fill_bytes(&mut buf);

        let pt_c = G1Affine::deserialize(&buf);
        let pt_u = G1Affine::deserialize_unchecked(&buf);

        match (pt_c, pt_u) {
            (Ok(pt_c), Ok(pt_u)) => {
                assert_eq!(pt_c, pt_u);
                assert!(pt_c.is_torsion_free());
            }

            (Err(_), Ok(pt_u)) => {
                // we always use compressed format so as a consequence it's not
                // actually possible to create a point that is not on the curve.
                // so if deserialize rejected it is because we are not in the subgroup:
                assert!(!pt_u.is_torsion_free());
            }
            (Ok(_), Err(_)) => {
                // this should never happen
                panic!("deserialize accepted but deserialize_unchecked did not");
            }
            (Err(_), Err(_)) => {
                // was so invalid that even deserialize_unchecked didn't like it
            }
        }
    }
}

#[test]
fn test_g2_is_torsion_free() {
    let mut rng = seeded_rng();

    for _ in 0..30 {
        let mut buf = [0u8; G2Affine::BYTES];
        rng.fill_bytes(&mut buf);

        let pt_c = G2Affine::deserialize(&buf);
        let pt_u = G2Affine::deserialize_unchecked(&buf);

        match (pt_c, pt_u) {
            (Ok(pt_c), Ok(pt_u)) => {
                assert_eq!(pt_c, pt_u);
                assert!(pt_c.is_torsion_free());
            }

            (Err(_), Ok(pt_u)) => {
                // we always use compressed format so as a consequence it's not
                // actually possible to create a point that is not on the curve.
                // so if deserialize rejected it is because we are not in the subgroup:
                assert!(!pt_u.is_torsion_free());
            }
            (Ok(_), Err(_)) => {
                // this should never happen
                panic!("deserialize accepted but deserialize_unchecked did not");
            }
            (Err(_), Err(_)) => {
                // was so invalid that even deserialize_unchecked didn't like it
            }
        }
    }
}

fn g1_from_u64(i: &u64) -> G1Projective {
    G1Projective::generator() * Scalar::from_u64(*i)
}

fn g2_from_u64(i: &u64) -> G2Projective {
    G2Projective::generator() * Scalar::from_u64(*i)
}

fn gt_from_u64(i: &u64) -> Gt {
    Gt::generator() * Scalar::from_u64(*i)
}

#[test]
fn test_sum_g1() {
    let mut rng = seeded_rng();

    for t in 1..20 {
        let inputs: Vec<u64> = (0..t).map(|_| rng.gen::<u32>() as u64).collect();
        let g1_elements: Vec<G1Projective> = inputs.iter().map(g1_from_u64).collect();
        assert_eq!(
            g1_from_u64(&inputs.iter().sum()),
            G1Projective::sum(&g1_elements)
        )
    }
}

#[test]
fn test_sum_g2() {
    let mut rng = seeded_rng();

    for t in 1..20 {
        let inputs: Vec<u64> = (0..t).map(|_| rng.gen::<u32>() as u64).collect();
        let g2_elements: Vec<G2Projective> = inputs.iter().map(g2_from_u64).collect();
        assert_eq!(
            g2_from_u64(&inputs.iter().sum()),
            G2Projective::sum(&g2_elements)
        )
    }
}

#[test]
fn test_mul_g1() {
    let mut rng = seeded_rng();

    for _ in 1..20 {
        let lhs = rng.gen::<u32>() as u64;
        let rhs = rng.gen::<u32>() as u64;
        let integer_prod = lhs * rhs;
        let g1_prod = g1_from_u64(&lhs) * Scalar::from_u64(rhs);
        assert_eq!(g1_from_u64(&integer_prod), g1_prod);
    }
}

#[test]
fn test_mul_g2() {
    let mut rng = seeded_rng();

    for _ in 1..20 {
        let lhs = rng.gen::<u32>() as u64;
        let rhs = rng.gen::<u32>() as u64;
        let integer_prod = lhs * rhs;
        let g2_prod = g2_from_u64(&lhs) * Scalar::from_u64(rhs);
        assert_eq!(g2_from_u64(&integer_prod), g2_prod);
    }
}

#[test]
fn test_mul_gt() {
    let mut rng = seeded_rng();

    for _ in 1..20 {
        let lhs = rng.gen::<u32>() as u64;
        let rhs = rng.gen::<u32>() as u64;
        let integer_prod = lhs * rhs;
        let gt_prod = gt_from_u64(&lhs) * Scalar::from_u64(rhs);
        assert_eq!(gt_from_u64(&integer_prod), gt_prod);
    }
}

#[test]
fn test_scalar_serialization_round_trips() {
    let mut rng = seeded_rng();

    for _ in 1..30 {
        let s_orig = Scalar::random(&mut rng);
        let s_bits = s_orig.serialize();

        let s_d = Scalar::deserialize(&s_bits).expect("Invalid serialization");
        assert_eq!(s_orig, s_d);
        assert_eq!(s_d.serialize(), s_bits);

        let s_du = Scalar::deserialize_unchecked(s_bits);
        assert_eq!(s_orig, s_du);
        assert_eq!(s_du.serialize(), s_bits);
    }
}

#[test]
fn test_g1_serialization_round_trips() {
    let mut rng = seeded_rng();

    for _ in 1..30 {
        let g1_orig = G1Projective::hash(b"domain_sep", &rng.gen::<[u8; 32]>());
        let g1_bits = g1_orig.serialize();

        let g1_d = G1Projective::deserialize(&g1_bits).expect("Invalid serialization");
        assert_eq!(g1_orig, g1_d);
        assert_eq!(g1_d.serialize(), g1_bits);

        let g1_du = G1Projective::deserialize_unchecked(&g1_bits).expect("Invalid serialization");
        assert_eq!(g1_orig, g1_du);
        assert_eq!(g1_du.serialize(), g1_bits);
    }
}

#[test]
fn test_g2_serialization_round_trips() {
    let mut rng = seeded_rng();

    for _ in 1..30 {
        let g2_orig = G2Projective::hash(b"domain_sep", &rng.gen::<[u8; 32]>());
        let g2_bits = g2_orig.serialize();

        let g2_d = G2Projective::deserialize(&g2_bits).expect("Invalid serialization");
        assert_eq!(g2_orig, g2_d);
        assert_eq!(g2_d.serialize(), g2_bits);

        let g2_du = G2Projective::deserialize_unchecked(&g2_bits).expect("Invalid serialization");
        assert_eq!(g2_orig, g2_du);
        assert_eq!(g2_du.serialize(), g2_bits);
    }
}

#[test]
fn test_g1_test_vectors() {
    g1_test_encoding(G1Affine::identity(), test_vectors::g1::INFINITY);
    g1_test_encoding(G1Affine::generator(), test_vectors::g1::GENERATOR);

    let g = G1Affine::generator();

    for (i, expected) in test_vectors::g1::POSITIVE_NUMBERS.iter().enumerate() {
        let s = Scalar::from_u64((i + 1) as u64);
        g1_test_encoding((g * s).into(), expected);
    }

    for (i, expected) in test_vectors::g1::NEGATIVE_NUMBERS.iter().enumerate() {
        let s = Scalar::from_u64((i + 1) as u64).neg();
        g1_test_encoding((g * s).into(), expected);
    }

    for (i, expected) in test_vectors::g1::POWERS_OF_2.iter().enumerate() {
        let s = Scalar::from_u64(1 << i);
        g1_test_encoding((g * s).into(), expected);
    }
}

#[test]
fn test_g2_test_vectors() {
    g2_test_encoding(G2Affine::identity(), test_vectors::g2::INFINITY);
    g2_test_encoding(G2Affine::generator(), test_vectors::g2::GENERATOR);

    let g = G2Affine::generator();

    for (i, expected) in test_vectors::g2::POSITIVE_NUMBERS.iter().enumerate() {
        let s = Scalar::from_u64((i + 1) as u64);
        g2_test_encoding((g * s).into(), expected);
    }

    for (i, expected) in test_vectors::g2::NEGATIVE_NUMBERS.iter().enumerate() {
        let s = Scalar::from_u64((i + 1) as u64).neg();
        g2_test_encoding((g * s).into(), expected);
    }

    for (i, expected) in test_vectors::g2::POWERS_OF_2.iter().enumerate() {
        let s = Scalar::from_u64(1 << i);
        g2_test_encoding((g * s).into(), expected);
    }
}

fn biased_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    let coin = rng.gen::<u8>();

    if coin < 10 {
        Scalar::zero()
    } else if coin < 20 {
        Scalar::one()
    } else if coin < 30 {
        Scalar::one().neg()
    } else {
        Scalar::random(rng)
    }
}

fn biased_g1<R: RngCore + CryptoRng>(rng: &mut R) -> G1Projective {
    let coin = rng.gen::<u8>();

    if coin < 10 {
        G1Projective::identity()
    } else if coin < 20 {
        G1Projective::generator()
    } else if coin < 30 {
        G1Projective::generator().neg()
    } else {
        G1Projective::hash(b"random-g1-for-testing", &rng.gen::<[u8; 32]>())
    }
}

#[test]
fn test_g1_mul2() {
    let mut rng = seeded_rng();

    let g = G1Projective::generator();
    let zero = Scalar::zero();
    let one = Scalar::one();

    assert_eq!(
        G1Projective::mul2(&g, &zero, &g, &zero),
        G1Projective::identity()
    );
    assert_eq!(G1Projective::mul2(&g, &one, &g, &zero), g);
    assert_eq!(G1Projective::mul2(&g, &zero, &g, &one), g);

    for _ in 0..1000 {
        let s1 = biased_scalar(&mut rng);
        let s2 = biased_scalar(&mut rng);

        let p1 = biased_g1(&mut rng);
        let p2 = biased_g1(&mut rng);

        let reference = p1 * s1 + p2 * s2;

        assert_eq!(G1Projective::mul2(&p1, &s1, &p2, &s2), reference);
        assert_eq!(G1Projective::mul2(&p2, &s2, &p1, &s1), reference);
    }
}

#[test]
fn test_g1_muln() {
    let mut rng = seeded_rng();

    assert_eq!(G1Projective::muln_vartime(&[]), G1Projective::identity());

    for t in 1..100 {
        let mut terms = Vec::with_capacity(t);

        for _ in 0..t {
            terms.push((biased_g1(&mut rng), biased_scalar(&mut rng)));
        }

        let mut reference_val = G1Projective::identity();
        for (p, s) in &terms {
            reference_val += *p * *s;
        }

        let computed = G1Projective::muln_vartime(&terms);

        assert_eq!(computed, reference_val);
    }
}

#[test]
fn test_verify_bls_signature() {
    let mut rng = seeded_rng();

    let sk = Scalar::random(&mut rng);
    let pk = G2Affine::from(G2Affine::generator() * sk);
    let message = G1Affine::hash(b"bls_signature", &rng.gen::<[u8; 32]>());
    let signature = G1Affine::from(message * sk);

    assert!(verify_bls_signature(&signature, &pk, &message));
    assert!(!verify_bls_signature(&message, &pk, &signature));
}

#[test]
fn test_hash_to_g1_matches_draft() {
    /*
    These are the test vectors from draft-irtf-cfrg-hash-to-curve-16 section J.9.1

    The draft expresses the output in affine coordinates (x,y) while the
    BLS12-381 only exposes a compressed representation. In the BLS12-381
    compressed format the initial bit is set, as well the lowest bit of the
    leading byte may be set depending on the "sign" of y

    For example the first test (for input "") in J.9.1 has
       P.x     = 0529....79a1
    while we have as the entire point encoding
                 8529....79a1
    (because the "sign" of the y coordinate happens to be 0 for this case)
    */

    let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

    g1_test_encoding(
        G1Affine::hash(&dst[..], b""),
        "852926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1"
    );

    g1_test_encoding(
        G1Affine::hash(&dst[..], b"abc"),
        "83567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903"
    );

    g1_test_encoding(
        G1Affine::hash(&dst[..], b"abcdef0123456789"),
        "91e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
    );

    g1_test_encoding(
        G1Affine::hash(&dst[..], format!("q128_{}", "q".repeat(128)).as_bytes()),
        "b5f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488",
    );

    g1_test_encoding(
        G1Affine::hash(&dst[..], format!("a512_{}", "a".repeat(512)).as_bytes()),
        "882aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe",
    );
}

#[test]
fn test_hash_to_g2_matches_draft() {
    /*
    These are the test vectors from draft-irtf-cfrg-hash-to-curve-16 section J.9.1

    As described in the test_hash_to_g1_matches_draft test, these are expressed
    in compressed form, unlike the draft which uses uncompressed representation.

    The draft uses P.x = <a> + I * <b> where <a> and <b> are field elements.
    However the serialization of G2 orders as <b> || <a> instead.
    */

    let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

    g2_test_encoding(
        G2Affine::hash(&dst[..], b""),
        "a5cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a"
    );

    g2_test_encoding(
        G2Affine::hash(&dst[..], b"abc"),
        "939cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd802c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6"
    );

    g2_test_encoding(
        G2Affine::hash(&dst[..], b"abcdef0123456789"),
        "990d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0"
    );

    g2_test_encoding(
        G2Affine::hash(&dst[..], format!("q128_{}", "q".repeat(128)).as_bytes()),
        "8934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb9119a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da"
    );

    g2_test_encoding(
        G2Affine::hash(&dst[..], format!("a512_{}", "a".repeat(512)).as_bytes()),
        "91fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d0156901a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534"
    );
}
