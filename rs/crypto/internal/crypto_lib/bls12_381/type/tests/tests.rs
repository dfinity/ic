use ic_crypto_internal_bls12_381_type::*;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use itertools::izip;
use paste::paste;
use rand::seq::IteratorRandom;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

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

#[test]
fn scalar_miracl_random_generates_expected_values() {
    let seed = hex::decode("4e42f768bab72a9248a43c439a330b94e3d39595c627eb603fff8ff84b7a9914")
        .expect("valid");
    let rng = &mut rand_chacha::ChaCha20Rng::from_seed(seed.try_into().expect("Invalid size"));

    scalar_test_encoding(
        Scalar::miracl_random(rng),
        "0ab77cf4d9338f6bfdcd9541574bf1211e8b552743426917e405739c029407aa",
    );

    let seed = hex::decode("8844d58a75db49c9df827e21085ea9d46f0a14e2bc6edaab27aeb640f88c313a")
        .expect("valid");
    let rng = &mut rand_chacha::ChaCha20Rng::from_seed(seed.try_into().expect("Invalid size"));

    scalar_test_encoding(
        Scalar::miracl_random(rng),
        "583912964c0e5c35604b073bf5fe37c4a17f7dc3cd597481116ff9f4c544b2f3",
    );
}

#[test]
fn scalar_random_is_stable() {
    let seed = 802;

    let rng = &mut ChaCha20Rng::seed_from_u64(seed);
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    assert_eq!(
        hex::encode(bytes),
        "b257761dbdaf0bcb97fb808f7b95ed1ec1974557af790021ff073ee14811b3d9"
    );

    let rng = &mut ChaCha20Rng::seed_from_u64(seed);
    scalar_test_encoding(
        Scalar::random(rng),
        "3257761dbdaf0bcb97fb808f7b95ed1ec1974557af790021ff073ee14811b3d9",
    );
}

#[test]
fn scalar_batch_random_is_stable() {
    let seed = 802;

    let rng = &mut ChaCha20Rng::seed_from_u64(seed);
    let random = Scalar::batch_random(rng, 2);
    assert_eq!(random.len(), 2);
    scalar_test_encoding(
        random[0].clone(),
        "3257761dbdaf0bcb97fb808f7b95ed1ec1974557af790021ff073ee14811b3d9",
    );
    scalar_test_encoding(
        random[1].clone(),
        "388f4601a393e81ef4964593283d317ddd7bfd88fb89fd7a7e4fb3a1ffee335a",
    );
}

#[test]
fn test_scalar_batch_random_generates_unique_values() {
    let rng = &mut reproducible_rng();

    fn assert_no_duplicates(scalars: &[Scalar]) {
        let mut uniq = std::collections::BTreeSet::new();
        for s in scalars {
            assert!(uniq.insert(s));
        }
    }

    for i in 0..100 {
        let random = Scalar::batch_random(rng, i);
        assert_eq!(random.len(), i);

        /*
        In a strict sense this test might fail. However the odds of it
        doing so if everything is working as expected are well under
        2^-250 so in practice it failing would indicate some problem in
        the code.
         */
        assert_no_duplicates(&random);
    }
}

#[test]
fn test_polynomial_random_is_stable() {
    let seed = [1u8; 32];
    let rng = &mut ChaCha20Rng::from_seed(seed);
    let poly = Polynomial::random(3, rng);

    assert_eq!(
        hex::encode(poly.coeff(0).serialize()),
        "023f37203a2476c42566a61cc55c3ca875dbb4cc41c0deb789f8e7bf88183638",
    );
    assert_eq!(
        hex::encode(poly.coeff(1).serialize()),
        "1ecc3686b60ee3b84b6c7d321d70d5c06e9dac63a4d0a79d731b17c0d04d030d",
    );
    assert_eq!(
        hex::encode(poly.coeff(2).serialize()),
        "01274dd1ee5216c204fb698daea45b52e98b6f0fdd046dcc3a86bb079e36f024",
    );
}

#[test]
fn test_polynomial_addition() {
    let rng = &mut reproducible_rng();

    for coeff_x in 0..32 {
        for coeff_y in 0..32 {
            let x = Polynomial::random(coeff_x, rng);
            let y = Polynomial::random(coeff_y, rng);

            let z = &x + &y;

            assert_eq!(z.degree(), std::cmp::max(x.degree(), y.degree()));

            for i in 0..z.degree() {
                assert_eq!(*z.coeff(i), x.coeff(i) + y.coeff(i));
            }
        }
    }
}

#[test]
fn test_polynomial_evaluation() {
    let rng = &mut reproducible_rng();

    for coeff in 0..32 {
        let p = Polynomial::random(coeff, rng);
        // Check that f(0) will always just equal the constant term:
        assert_eq!(p.evaluate_at(&Scalar::zero()), *p.coeff(0));

        // Check that f(1) will equal the sum of the various coefficients:
        assert_eq!(
            p.evaluate_at(&Scalar::one()),
            p.coefficients()
                .iter()
                .fold(Scalar::zero(), |acc, s| acc + s)
        );

        // Compute f(r) for some random r then check it:
        let r = Scalar::random(rng);
        let pr = p.evaluate_at(&r);

        assert_eq!(
            pr,
            p.coefficients()
                .iter()
                .rev()
                .fold(Scalar::zero(), |acc, s| acc * &r + s)
        );
    }
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
fn scalar_neg_one_generates_expected_values() {
    // This value is the BLS12-381 group order, minus 1
    scalar_test_encoding(
        Scalar::one().neg(),
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000",
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

    let rng = &mut reproducible_rng();

    for _ in 0..300 {
        let a = Scalar::random(rng);
        let b = Scalar::random(rng);

        assert_eq!(a.serialize().cmp(&b.serialize()), a.cmp(&b));
        assert_eq!(b.serialize().cmp(&a.serialize()), b.cmp(&a));

        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
        assert_eq!(b.cmp(&b), std::cmp::Ordering::Equal);
    }

    for _ in 0..300 {
        let a = Scalar::from_u32(rng.r#gen::<u32>());
        let b = Scalar::from_u32(rng.r#gen::<u32>());

        assert_eq!(a.serialize().cmp(&b.serialize()), a.cmp(&b));
        assert_eq!(b.serialize().cmp(&a.serialize()), b.cmp(&a));

        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
        assert_eq!(b.cmp(&b), std::cmp::Ordering::Equal);
    }
}

#[test]
fn test_scalar_from_integer_type() {
    let rng = &mut reproducible_rng();

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
        let r = rng.r#gen::<u32>();
        assert_eq!(Scalar::from_u32(r), Scalar::from_u64(r as u64));

        let bytes = Scalar::from_u32(r).serialize();
        let mut expected = [0u8; 32];
        expected[28..].copy_from_slice(&r.to_be_bytes());
        assert_eq!(bytes, expected);
    }

    for _ in 0..30 {
        let r = rng.r#gen::<i32>();

        let s = Scalar::from_i32(r);

        if r < 0 {
            assert_eq!(s.neg(), Scalar::from_u32((-r) as u32));
        } else {
            assert_eq!(s, Scalar::from_u32(r as u32));
        }
    }
}

#[test]
fn test_scalar_small_random() {
    let rng = &mut reproducible_rng();

    for bit_size in 1..32 {
        let n = u64::MAX >> (64 - bit_size);
        assert_eq!(bit_size, 64 - n.leading_zeros());
        let s = Scalar::random_within_range(rng, n);
        assert!(s < Scalar::from_u64(n));
    }

    for n in 1..1024 {
        let s = Scalar::random_within_range(rng, n);
        assert!(s < Scalar::from_u64(n));
    }

    let range = 1039; // small prime

    /*
    This upper bound is arbitrary and as the test is probabilistic it
    might occasionally fail. However over 10000 iterations the largest
    number of attempts required was range*15, so using range*30 if the
    test fails it probably does indicate a problem.
    */
    let max_attempts = range * 30;

    let mut seen = std::collections::HashSet::new();

    for _ in 0..max_attempts {
        let s = Scalar::random_within_range(rng, range);
        assert!(s < Scalar::from_u64(range));
        seen.insert(s.serialize());

        if seen.len() == range as usize {
            break;
        }
    }

    assert_eq!(seen.len(), range as usize);
}

#[test]
fn test_scalar_is_zero() {
    assert!(Scalar::zero().is_zero());
    assert!(!Scalar::one().is_zero());
}

#[test]
fn test_scalar_addition() {
    let rng = &mut reproducible_rng();

    for _ in 0..30 {
        let s1 = Scalar::random(rng);
        let s2 = Scalar::random(rng);

        let s3 = &s1 + &s2;

        let mut s4 = s3.clone();
        assert_eq!(s4, s3);
        s4 -= &s2;
        assert_eq!(s4, s1);
        s4 += &s2;
        assert_eq!(s4, s3);
        s4 -= &s1;
        assert_eq!(s4, s2);
    }
}

#[test]
fn test_scalar_neg() {
    let rng = &mut reproducible_rng();

    for _ in 0..30 {
        let scalar = Scalar::random(rng);
        let nscalar = scalar.neg();
        assert_eq!(scalar + nscalar, Scalar::zero());
    }
}

#[test]
fn test_scalar_inverse() {
    let rng = &mut reproducible_rng();

    assert_eq!(Scalar::zero().inverse(), None);
    assert_eq!(Scalar::one().inverse(), Some(Scalar::one()));

    for _ in 0..30 {
        let scalar = Scalar::random(rng);

        match scalar.inverse() {
            None => assert!(scalar.is_zero()),
            Some(inv) => {
                assert_eq!(scalar * inv, Scalar::one())
            }
        }
    }
}

#[test]
fn test_scalar_batch_inverse() {
    let rng = &mut reproducible_rng();

    for cnt in 1..30 {
        let scalars = (0..cnt).map(|_| Scalar::random(rng)).collect::<Vec<_>>();

        assert_eq!(scalars.len(), cnt);
        if let Some(inv) = Scalar::batch_inverse_vartime(&scalars) {
            for i in 0..cnt {
                assert_eq!(&scalars[i] * &inv[i], Scalar::one());
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

    assert_eq!(
        format!("{:?}", G1Affine::generator()),
        "G1Affine(97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb)"
    );
    assert_eq!(
        format!("{:?}", G2Affine::generator()),
        "G2Affine(93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8)"
    );
}

#[test]
fn test_gt_generator_is_expected_value() {
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    assert_eq!(Gt::pairing(g1, g2), *Gt::generator());
}

#[test]
fn test_gt_hash_has_no_collisions_in_range() {
    let mut seen = std::collections::HashSet::new();

    let mut x = Gt::identity();
    for _ in 0..=0xFFFF {
        let hash = x.short_hash_for_linear_search();
        assert!(seen.insert(hash));
        x += Gt::generator();
    }
}

#[test]
fn test_gt_mul_u16_is_correct() {
    let rng = &mut reproducible_rng();

    // We could do an exhaustive search here but because Gt standard
    // mul is so slow it takes several minutes to complete. So instead
    // just perform some random trials.

    for _ in 0..500 {
        let i = rng.r#gen::<u16>();
        let fast = Gt::g_mul_u16(i);
        let refv = Gt::generator() * Scalar::from_usize(i as usize);
        assert_eq!(fast, refv);
    }
}

#[test]
#[ignore]
fn test_gt_mul_u16_is_correct_exhaustive_test() {
    // This takes several minutes to run in debug mode

    let mut accum = Gt::identity();
    for x in 0..=0xffff {
        let fast = Gt::g_mul_u16(x);
        assert_eq!(fast, accum);

        accum += Gt::generator();
    }
}

#[test]
fn test_pairing_bilinearity() {
    let rng = &mut reproducible_rng();

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    for _ in 0..3 {
        let s1 = Scalar::random(rng);
        let s2 = Scalar::random(rng);
        let s3 = Scalar::random(rng);

        let mul_123 = Gt::pairing(&(g1 * &s1).into(), &(g2 * &s2).into()) * &s3;
        let mul_132 = Gt::pairing(&(g1 * &s1).into(), &(g2 * &s3).into()) * &s2;
        let mul_213 = Gt::pairing(&(g1 * &s2).into(), &(g2 * &s1).into()) * &s3;
        let mul_231 = Gt::pairing(&(g1 * &s2).into(), &(g2 * &s3).into()) * &s1;
        let mul_312 = Gt::pairing(&(g1 * &s3).into(), &(g2 * &s1).into()) * &s2;
        let mul_321 = Gt::pairing(&(g1 * &s3).into(), &(g2 * &s2).into()) * &s1;

        let mul_gt = ((Gt::generator() * &s1) * &s2) * &s3;

        assert_eq!(mul_123, mul_gt);
        assert_eq!(mul_132, mul_gt);
        assert_eq!(mul_213, mul_gt);
        assert_eq!(mul_231, mul_gt);
        assert_eq!(mul_312, mul_gt);
        assert_eq!(mul_321, mul_gt);

        // test that the tag is identical no matter how the Gt was derived
        assert_eq!(mul_123.tag(), mul_gt.tag());
        assert_eq!(mul_132.tag(), mul_gt.tag());
        assert_eq!(mul_213.tag(), mul_gt.tag());
        assert_eq!(mul_231.tag(), mul_gt.tag());
        assert_eq!(mul_312.tag(), mul_gt.tag());
        assert_eq!(mul_321.tag(), mul_gt.tag());
    }
}

#[test]
fn test_gt_tag_is_expected_value() {
    fn hash_of_tag(g: &Gt) -> String {
        let mut sha = Sha256::default();
        sha.update(g.tag());
        hex::encode(sha.finalize().as_slice())
    }

    // The SHA-256 of the encodings of g*1, g*2, g*3, ...
    let expected = [
        "300e47c99502f3af33ad2080847d528cabd90365a90ab98bc174565c27928591",
        "067894e43096b5a855549fd6d19955d3922f402680ca82cb02ebc545f65779a7",
        "aad5ac496dd4b1ea2a6353051e81950185d56882c75664792ab71164820d386d",
        "557219d7adf954d8438411808e20ba5834c286e9a80e0d22e47a37c543282e6e",
        "621f31153ec9fafd2d0547620f76b6d0c5935d3fe920ca27adcf6afa5501941c",
        "e9e1a6e7029556364ca875f9582ebdf8dcc0db1c6f3312341292ebc0df17baa3",
        "f93ac623ee1dc6d057070f8f19c069565fc60708431175d5053b88004106648a",
        "c8a6cc7acc0b87a957fdb2d999108db57c71c53a81804dad951de9f34d6c1da4",
        "0f650545765993b34996e5adf1ef3dd4c835e7b23926e15fd569ef07a36f5ab9",
        "d446409bee1f57b697be2d71979ce6e57e54fa6cc9d7899304c0862f83bc95a8",
        "9b526347ba5a9b440c22c164c1f62ab18ae1c32f63c42d6efa3819b53b21c37f",
        "e44e2a3d236f34decd4d6a4f6f958dfdb98cdda8b0f8e2b7809609c2b0bf89b7",
        "2c74b687d7f06e8ef3473463393b16128f4ec1c3e5b30aa1b297305717ef9984",
        "789aad7bcc07c3053908a8de556ab1512cd3e3a89e9b23b63d383543235b7a11",
        "140ff2aa98b9fc1e25900b1af0c74e242f603919b72910a52f3f6e41b6ce363e",
        "2d7e7b7b420f6b01d0c0c822ba5dd03006f95529a702ebbd48f2c0bcb512871b",
        "06a291618e610ea18dcc57202f6e917576997731e3b6e24db593aa9c0ed672d4",
        "2a8c95c256fcfc3a5d003ec04d13366138421870b3b28c2dd3ed8ffa2f4a759a",
        "12b826c18cda8414f0efb3a909fadde1909a11eb2de944837f9b0137efa1251a",
        "3ee907fa77740c5631ed321c5b5a941af5592cf33efc1b3ee6c2674b21fc9194",
        "37fc0038857c81a431bd361d6610441125353c8ce3b17484cf512626652bb456",
        "ce79a21dbd31218b153b9c3e0e8fa9340bc36f92e3319aae88d3f0587b49dafa",
        "14669f024da5757b913976dcf8b6eed5d2a35d5d5863ad5df7241cdaa33d4a44",
        "d778f3e6645e45554ac27cb243b959427fa8786446065113ab76154a784d5d56",
        "f7f098948e4bc9f31a5cd9a927f41a07bc225e3da130692acf99888d4a5ed606",
        "ca027cc487f092de0e30fde26c2297f12bff759b9a59004df2dd737a84eb17df",
        "0c683f5bc078cff9a1cdf4016bb5461e6b298a7ffb51e9fc7dde1e21b923ead8",
        "71cb0152efdf758280de68aa539e69dbf46ec3d72a738339485a56350f41e8cc",
        "06af9830dcab4047081894519019b04fecfb8395aff845ba96bc1e712606e636",
        "6b638b23cbe45d4ea3d478cc1399ffecfe3f215f391d01610db26d1f2b39f356",
        "739262709aa4c7b628d66e702836c1dc12d3df9a4e36cb3171f0d8eedf4ad0f4",
        "a52e01b0c4776ed83790961c18264e1e1db3e275e176fa321c4e42e8010aedb8",
        "c6bd4a052f1cbbf3eacc0ff28c0c62045fa8aca7ad1b83db1dd3a6bdbf322e6d",
    ];

    let mut g = Gt::identity();

    for h in expected {
        g += Gt::generator();
        assert_eq!(hash_of_tag(&g), h);
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

    assert_eq!(g1, *G1Projective::generator());
    assert_eq!(G1Affine::from(g1), *G1Affine::generator());

    assert_eq!(
        hex::encode(G1Affine::generator().serialize()),
        "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
    );
}

#[test]
fn test_g2_generator_is_expected_value() {
    assert_eq!(
        hex::encode(G2Affine::generator().serialize()),
        "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
    );
}

#[test]
fn test_identity_is_identity() {
    assert!(G1Affine::identity().is_identity());
    assert!(G1Projective::identity().is_identity());
    assert!(G2Affine::identity().is_identity());
    assert!(G2Projective::identity().is_identity());
    assert!(Gt::identity().is_identity());

    let s = Scalar::from_u64(9);

    assert!((G1Affine::identity() * &s).is_identity());
    assert!((G1Projective::identity() * &s).is_identity());
    assert!((G2Affine::identity() * &s).is_identity());
    assert!((G2Projective::identity() * &s).is_identity());
    assert!((Gt::identity() * &s).is_identity());
}

#[test]
fn test_multipairing() {
    let g1 = G1Affine::generator();
    let g1n = G1Affine::generator().neg();
    let g2p = G2Prepared::generator();
    let g2pn = G2Prepared::neg_generator();

    assert_eq!(Gt::multipairing(&[]), Gt::identity());

    assert_eq!(Gt::multipairing(&[(g1, g2p)]), *Gt::generator());

    assert_eq!(Gt::multipairing(&[(&g1n, g2pn)]), *Gt::generator());

    assert_eq!(Gt::multipairing(&[(g1, g2pn)]), Gt::generator().neg());

    assert_eq!(Gt::multipairing(&[(&g1n, g2p)]), Gt::generator().neg());

    let rng = &mut reproducible_rng();

    for _ in 0..5 {
        let a = Scalar::random(rng);
        let b = Scalar::random(rng);
        let c = Scalar::random(rng);

        let g1a = G1Affine::from(G1Affine::generator() * &a);
        let g1b = G1Affine::from(G1Affine::generator() * &b);
        let g1c = G1Affine::from(G1Affine::generator() * &c);

        let g2a = G2Prepared::from(G2Affine::generator() * &a);
        let g2b = G2Prepared::from(G2Affine::generator() * &b);
        let g2c = G2Prepared::from(G2Affine::generator() * &c);

        let g2 = G2Prepared::generator();

        assert_eq!(
            Gt::multipairing(&[(&g1a, g2), (&g1b, g2), (&g1c, g2)]),
            Gt::multipairing(&[(g1, &g2a), (g1, &g2b), (g1, &g2c)]),
        );
    }
}

#[test]
fn test_g1_deserialize_rejects_infinity_bit_with_nonzero_x() {
    let g1 = G1Affine::generator();

    let mut g1_bytes = g1.serialize();
    // set the infinity bit
    g1_bytes[0] |= 1 << 6;

    assert!(G1Affine::deserialize(&g1_bytes).is_err());
    assert!(G1Affine::deserialize_unchecked(&g1_bytes).is_err());
}

#[test]
fn test_g2_deserialize_rejects_infinity_bit_with_nonzero_x() {
    let g2 = G2Affine::generator();

    let mut g2_bytes = g2.serialize();
    // set the infinity bit
    g2_bytes[0] |= 1 << 6;

    assert!(G2Affine::deserialize(&g2_bytes).is_err());
    assert!(G2Affine::deserialize_unchecked(&g2_bytes).is_err());
    assert!(G2Affine::deserialize_cached(&g2_bytes).is_err());
}

#[test]
fn test_g1_deserialize_rejects_out_of_range_x_value() {
    // This point has an x coordinate equal to the size of the G1 field
    let g1_x_eq_mod =
        hex::decode("9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab").unwrap();

    assert!(G1Affine::deserialize_unchecked(&g1_x_eq_mod).is_err());

    // This point has an x coordinate equal to the size of the G1 field + 2
    let g1_x_eq_mod =
        hex::decode("9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaad").unwrap();

    assert!(G1Affine::deserialize_unchecked(&g1_x_eq_mod).is_err());

    // This point has an x coordinate equal 2 (smallest valid x coordinate)
    let g1_x_eq_mod =
        hex::decode("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002").unwrap();

    assert!(G1Affine::deserialize(&g1_x_eq_mod).is_err());
}

#[test]
fn test_g2_deserialize_rejects_out_of_range_x_value() {
    let invalid_x0 =
        hex::decode("9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

    assert!(G2Affine::deserialize_unchecked(&invalid_x0).is_err());
    assert!(G2Affine::deserialize_cached(&invalid_x0).is_err());

    let invalid_x1 =
        hex::decode("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab").unwrap();

    assert!(G2Affine::deserialize_unchecked(&invalid_x1).is_err());
    assert!(G2Affine::deserialize_cached(&invalid_x1).is_err());
}

#[test]
fn test_scalar_serialization_round_trips() {
    let rng = &mut reproducible_rng();

    for _ in 1..30 {
        let s_orig = Scalar::random(rng);
        let s_bits = s_orig.serialize();

        let s_d = Scalar::deserialize(&s_bits).expect("Invalid serialization");
        assert_eq!(s_orig, s_d);
        assert_eq!(s_d.serialize(), s_bits);

        let s_du = Scalar::deserialize_unchecked(&s_bits);
        assert_eq!(s_orig, s_du);
        assert_eq!(s_du.serialize(), s_bits);
    }
}

#[test]
fn test_g1_test_vectors() {
    /// The chosen generator for the G1 group.
    ///
    /// Note: This matches `x=0x17f1d3..` in the spec, with flag bits added to the
    /// first byte.
    const GENERATOR: &str = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    /// The additive identity, also known as zero.
    const INFINITY: &str = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    /// Powers of 2: `g1_generator * {1, 2, 4, 8, ...}`
    const POWERS_OF_2: &[&str] = &[
        GENERATOR,
        "a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "ac9b60d5afcbd5663a8a44b7c5a02f19e9a77ab0a35bd65809bb5c67ec582c897feb04decc694b13e08587f3ff9b5b60",
        "a85ae765588126f5e860d019c0e26235f567a9c0c0b2d8ff30f3e8d436b1082596e5e7462d20f5be3764fd473e57f9cf",
        "a73eb991aa22cdb794da6fcde55a427f0a4df5a4a70de23a988b5e5fc8c4d844f66d990273267a54dd21579b7ba6a086",
        "a72841987e4f219d54f2b6a9eac5fe6e78704644753c3579e776a3691bc123743f8c63770ed0f72a71e9e964dbf58f43",
    ];
    /// Positive numbers: `g1_generator * {1,2,3,4,...}`
    const POSITIVE_NUMBERS: &[&str] = &[
        GENERATOR,
        "a572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "89ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224",
        "ac9b60d5afcbd5663a8a44b7c5a02f19e9a77ab0a35bd65809bb5c67ec582c897feb04decc694b13e08587f3ff9b5b60",
        "b0e7791fb972fe014159aa33a98622da3cdc98ff707965e536d8636b5fcc5ac7a91a8c46e59a00dca575af0f18fb13dc",
    ];
    /// Negative numbers: `g1_generator * {-1, -2, -3, -4, ...}`
    const NEGATIVE_NUMBERS: &[&str] = &[
        "b7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        "8572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e",
        "a9ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e5224",
        "8c9b60d5afcbd5663a8a44b7c5a02f19e9a77ab0a35bd65809bb5c67ec582c897feb04decc694b13e08587f3ff9b5b60",
        "90e7791fb972fe014159aa33a98622da3cdc98ff707965e536d8636b5fcc5ac7a91a8c46e59a00dca575af0f18fb13dc",
    ];

    let g = G1Affine::generator();
    let identity = G1Affine::identity();

    g1_test_encoding(identity.clone(), INFINITY);
    g1_test_encoding(g.clone(), GENERATOR);

    assert_eq!(identity, G1Affine::from(G1Projective::identity()));
    assert_eq!(g, &G1Affine::from(G1Projective::generator()));

    for (i, expected) in POSITIVE_NUMBERS.iter().enumerate() {
        let s = Scalar::from_u64((i + 1) as u64);
        g1_test_encoding((g * s).into(), expected);
    }

    for (i, expected) in NEGATIVE_NUMBERS.iter().enumerate() {
        let s = Scalar::from_u64((i + 1) as u64).neg();
        g1_test_encoding((g * s).into(), expected);
    }

    for (i, expected) in POWERS_OF_2.iter().enumerate() {
        let s = Scalar::from_u64(1 << i);
        g1_test_encoding((g * s).into(), expected);
    }
}

#[test]
fn test_g2_test_vectors() {
    /// The chosen generator for the G2 group.
    ///
    /// Note: This matches `x'_1 || x'_0` in the spec, with flag bits added to the
    /// first byte.
    const GENERATOR: &str = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
    /// The additive identity, also known as zero.
    const INFINITY: &str = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    /// Powers of 2: `g2_generator * [1, 2, 4, 8, ..., 256]`
    const POWERS_OF_2: &[&str] = &[
        GENERATOR,
        "aa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053",
        "870227d3f13684fdb7ce31b8065ba3acb35f7bde6fe2ddfefa359f8b35d08a9ab9537b43e24f4ffb720b5a0bda2a82f20e7a30979a8853a077454eb63b8dcee75f106221b262886bb8e01b0abb043368da82f60899cc1412e33e4120195fc557",
        "92be651a5fa620340d418834526d37a8c932652345400b4cd9d43c8f41c080f41a6d9558118ebeab9d4268bb73e850e102142a58bae275564a6d63cb6bd6266ca66bef07a6ab8ca37b9d0ba2d4effbccfd89c169649f7d0e8a3eb006846579ad",
        "a70401d9bba01c0445e0a682406b099f21d16d9c348cc97156769084055ca328a145c134b8c8b58f019d62882b2965de1800ecc167bb714100f31e7610cd3fd010ca299b394c01b1a89afd11b051e92989f6336db5e6d3212f6b04673526d839",
        "ac1bcdf2034a7d577355b280f431cf2bf2cb5e955915904766a52d57b3aca6e8c4c96af35382e0c63687f4a77724012b0f22d7c4d43cbb513893e53e6cf995c70e4f5fa7c5b6f167838b217825d3d2dadab5f07764ef69d346f2dc97c231a3f6",
        "b6480241fab3ca8ec408219988d8dce6180dbed76fd5e9b84fdb42d73759ea991f179a40566038c1ec6cbbd2d16745390254b59e8676796a65a52610b9c88e366f9dbf7fdbdd5983a4e0b691a3c310f8eb5d2bc1177833bdfa1c1b42cacb953f",
        "afc5f85e7adc6cea5b3792af7c9fa9d3acc465e3785f40654292be3a09dfd2f266bc765fcfe8da55e948c2312ec571d211f6a8f78fa020f9ea41dc9c2b54e1037c77f59dcb9058a1f7ff95a0102d30b7ad18e0ada1dee28bc05183abf87cdb1e",
        "82f7f6cc00b080cb3a7f8976c44d1987fd36a8334db831be269c6f6144c392b54bb934313d5fc832ec41d2f9a4b7ea910412f6b2e37effc7e16d566d6f831572411d130eee4c15d82aa29e44cb4db9b5eb8c08b0ae158cde970d9d29ba368780",
    ];
    /// Positive numbers: `g2_generator * [1, 2, 3, ..., 9]`
    const POSITIVE_NUMBERS: &[&str] = &[
        GENERATOR,
        "aa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053",
        "89380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae",
        "870227d3f13684fdb7ce31b8065ba3acb35f7bde6fe2ddfefa359f8b35d08a9ab9537b43e24f4ffb720b5a0bda2a82f20e7a30979a8853a077454eb63b8dcee75f106221b262886bb8e01b0abb043368da82f60899cc1412e33e4120195fc557",
        "80fb837804dba8213329db46608b6c121d973363c1234a86dd183baff112709cf97096c5e9a1a770ee9d7dc641a894d60411a5de6730ffece671a9f21d65028cc0f1102378de124562cb1ff49db6f004fcd14d683024b0548eff3d1468df2688",
        "83f4b4e761936d90fd5f55f99087138a07a69755ad4a46e4dd1c2cfe6d11371e1cc033111a0595e3bba98d0f538db45119e384121b7d70927c49e6d044fd8517c36bc6ed2813a8956dd64f049869e8a77f7e46930240e6984abe26fa6a89658f",
        "8d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c",
        "92be651a5fa620340d418834526d37a8c932652345400b4cd9d43c8f41c080f41a6d9558118ebeab9d4268bb73e850e102142a58bae275564a6d63cb6bd6266ca66bef07a6ab8ca37b9d0ba2d4effbccfd89c169649f7d0e8a3eb006846579ad",
        "ac48e0d4f9404ae0a7f10774c55a9e838bb09d3bae85b5eaa6b16b0f4dc2354368117f3799c37f3f7126d8b54d3f8393018405e4b67f957b6465ead9f5afc47832d45643dc3aa03af7314c6cf980fa23dd3bb8db3358693ad06011f6a6b1a5ff",
    ];
    /// Negative numbers: `g2_generator * [-1, -2, -3, ..., -9]`
    const NEGATIVE_NUMBERS: &[&str] = &[
        "b3e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
        "8a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053",
        "a9380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae",
        "a70227d3f13684fdb7ce31b8065ba3acb35f7bde6fe2ddfefa359f8b35d08a9ab9537b43e24f4ffb720b5a0bda2a82f20e7a30979a8853a077454eb63b8dcee75f106221b262886bb8e01b0abb043368da82f60899cc1412e33e4120195fc557",
        "a0fb837804dba8213329db46608b6c121d973363c1234a86dd183baff112709cf97096c5e9a1a770ee9d7dc641a894d60411a5de6730ffece671a9f21d65028cc0f1102378de124562cb1ff49db6f004fcd14d683024b0548eff3d1468df2688",
        "a3f4b4e761936d90fd5f55f99087138a07a69755ad4a46e4dd1c2cfe6d11371e1cc033111a0595e3bba98d0f538db45119e384121b7d70927c49e6d044fd8517c36bc6ed2813a8956dd64f049869e8a77f7e46930240e6984abe26fa6a89658f",
        "ad0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c",
        "b2be651a5fa620340d418834526d37a8c932652345400b4cd9d43c8f41c080f41a6d9558118ebeab9d4268bb73e850e102142a58bae275564a6d63cb6bd6266ca66bef07a6ab8ca37b9d0ba2d4effbccfd89c169649f7d0e8a3eb006846579ad",
        "8c48e0d4f9404ae0a7f10774c55a9e838bb09d3bae85b5eaa6b16b0f4dc2354368117f3799c37f3f7126d8b54d3f8393018405e4b67f957b6465ead9f5afc47832d45643dc3aa03af7314c6cf980fa23dd3bb8db3358693ad06011f6a6b1a5ff",
    ];

    let g = G2Affine::generator();
    let identity = G2Affine::identity();

    g2_test_encoding(identity.clone(), INFINITY);
    g2_test_encoding(g.clone(), GENERATOR);

    assert_eq!(identity, G2Affine::from(G2Projective::identity()));
    assert_eq!(g, &G2Affine::from(G2Projective::generator()));

    for (i, expected) in POSITIVE_NUMBERS.iter().enumerate() {
        let s = Scalar::from_u64((i + 1) as u64);
        g2_test_encoding((g * s).into(), expected);
    }

    for (i, expected) in NEGATIVE_NUMBERS.iter().enumerate() {
        let s = Scalar::from_u64((i + 1) as u64).neg();
        g2_test_encoding((g * s).into(), expected);
    }

    for (i, expected) in POWERS_OF_2.iter().enumerate() {
        let s = Scalar::from_u64(1 << i);
        g2_test_encoding((g * s).into(), expected);
    }
}

#[test]
fn test_scalar_muln() {
    use BiasedValue;

    let rng = &mut reproducible_rng();

    assert_eq!(Scalar::muln_vartime(&[], &[]), Scalar::zero());

    for t in 1..100 {
        let mut lhs = Vec::with_capacity(t);
        let mut rhs = Vec::with_capacity(t);

        for _ in 0..t {
            lhs.push(Scalar::biased(rng));
            rhs.push(Scalar::biased(rng));
        }

        let mut reference_val = Scalar::zero();
        for i in 0..t {
            reference_val += &lhs[i] * &rhs[i];
        }

        let computed = Scalar::muln_vartime(&lhs, &rhs);

        assert_eq!(computed, reference_val);
    }
}

#[test]
fn test_g1_augmented_hash_test_vectors() {
    /*
     * No source for test vectors for the G1 augmented hash could be located. These
     * values were generated by zkcrypto/bls12_381
     */
    let test_vectors = [
        (
            "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "ce900db33cb4f6bc3db0b3ce0c462e78",
            "816c73d8098a07f0584d2e5a9a13abd98fe0536b86e921bebaa953577a03300453764e88b6383e442e10a7fed0de37f0",
        ),
        (
            "864ed23497b7c6bf4b95f981f6a8ebc5de6e303ad90e1dad71a1a8b7676912bfeaa7a3b61eeabf2a5d728ec298c268fb18ab9f32c0ee43d99bc4901eb8d3815cd1a8cef6591931dd706f212691bba1ad3490e0fa2e7c593d978e920566486066",
            "a7eed036705827efec713b65533b9b10",
            "9900f2cd31147dda4400ba954849eba5785730d62010b38a0ebaabf93281f49d8b24eb839493b9563ed8a422e2de3337",
        ),
        (
            "8ac83f419f09283c558cb9630ceeb887de1c646cb249ae9e5a5777699127d9044b37a8a34de665b98aa6ff3954cefc270f15e4e7fc38f2c317b726326c01a7fd679c6bcfa14bf0575b971e14705ef3d874281360586d86fb5ced64a568eb7c6c",
            "8be4fa4a80dcaa0621cfe00face73486",
            "ade977d871dcb7ff69ec2a154ff9b0aff750ea3872057bf0721ae0c3fd7a086e5086793dd72256d993acc630c5dba61d",
        ),
        (
            "a43ac20c81f7c3a88a49913bc9dc11c736088af78715a438f1e72d6a006f2a90761c0b5f0cb9ae1e5828d6e7abde5b7a058f75435777ea0bdf0d52e9c03b11f6a0683351cd9b8d28e8657b3fb2ac1f24087bada88b7c5168a0a1468d52cf5842",
            "6bdf244fded974ef5833df52b70db200",
            "a19250e0e4fe6b1ef839c3f3edab385f56e9d991566f3bc19a250df09b087b695e39d59c05dc5a58921afe17e57823cb",
        ),
        (
            "8d73306394bbc5646a195507ac6424ea852a8f8e5928ab8dd108d6d9fdecce9e0b22204209fd16ccefde1d6f1b73ca1718950972a2b74f2a0aac0ee4d9d72dd2102726ba047405d0377dc8f714e563f99e37a9ee3b31263b002793fc206e5771",
            "b1f88617c75b527152977ac506b8d46f",
            "a9b3056b47b56613445def1729ea323ec883dd856ac36f2eefb56ad7c40353c19f9f23f0bafaa5a65322c4cc7437e5f2",
        ),
        (
            "980cf164639279acee275350c22686ab48e2eb6e79eca03ca409b4c160e72530a42eef3668bc8d997b7b103515d902610ff7bf3a1793c3445b24006c863fbdf1713652fbab371a1813037a1c2ab35804ec1973aafd6ee51b4602143e10685bb0",
            "2d5ba3c198d8728c64ccd660353561fe",
            "b23869d704e064f8a60870b3aaa2d3a81a2e2f965504aa9d64f60a945e4ed1d872ea9736f202a5029926a80450f9872d",
        ),
        (
            "832e3b180d3ca7f787327b5d615804b7e883f911ddda48da42e58e45d779f0788d9cd563f4d4b65ed2573b5a50641efe1873bca56f0836c156b3e82787a18881b9f8c7aa130e67b28c2762bbc1c8d19506b91150ecdedbccce8e07da6e74c014",
            "6a86af2c8226707d25bfa649cb9223ec",
            "8e775d6c996f1c8f9902d8f19193694f387c6e453eea4ade39f541c484c15f3a8e47f0d2fbd98f1f590aaa04e3dcd41a",
        ),
        (
            "95f90c37e583863c6e7d8e17f64dda7ecf56b3568c5558362ebdb39b6b9304fabc4ef91efc92e0932abc9d87b44a3fdd08d6f23cc0f547ef35cdf975c5eb2b37c00095b5e818587cd08ae9ee4fe76b6de5fc07a79c046ef68d6fbde8db3631b6",
            "042259be774dc136482d40f3587103f8",
            "99c74b44d6e1092173e62358faa7d388cc15d5bcbffa17511d30fb2699b4d2dc58d33ed346fa4fec317da4d51f7cd8d8",
        ),
        (
            "85fcc79dbcd6ad60b2ceb7d2759fd3a165c1a4cfc9a3813e32eb9a4e13148d3b74cfc18331eb82a0ec82f5947dec5f2d16e517fefedc0123e36f93ca758ff9b23810a692e80ecc40ca97edb76d210fe037339c4fb2e4151ccb9721f91cd124d3",
            "10d4bd96176d6368c45349277369909c",
            "a76b58c80a52efcd1c91ece11b13b60b21d533713f689721b4ca6bedb214a124b3619ee41ad73c255d72590e25d44631",
        ),
        (
            "999986ca521874abf02735b50647f9890cf194214cbaaa6f9f6fb6ac924e397699227c5ac15ce6574d7b989ebaa17fb4103d7403ada1e927fadc413c4e0aa4286e29572261628c708e90c89e8825679ef6c977e5290e83c9b96af7251a4e1c75",
            "6936ad26ab5ca7c291287827e3388e55",
            "a420355356cb7d91af6be049123e93212340d601f068ab99d62f568a63255e2f6991d6b4f5a2cafc92669a925ce17783",
        ),
        (
            "8a02185f6a780cae9264a3cb6e811122faa01c50d9cb2b359cc7bbb8de2527aed3f8048f289de6d4d2d8d7eeafb8d08804be0d1a26e8f4a573d8fc87ebc8475beefbfa4f0221493f80b51e75bcd3c6403a2e872601cc5c33ce1c9938d2264de5",
            "33f280df9b7638f9b4785524961c0af6",
            "8abb3a215edabeee131d6ab3e2f6666b39636d177b103e9aea73c33d672cd37959aefe9c88a3fc1aaa179bc63f5ba503",
        ),
    ];

    for (g2, data, g1) in &test_vectors {
        let g2 = G2Affine::deserialize(&hex::decode(g2).expect("Invalid hex")).expect("Invalid G2");
        let data = hex::decode(data).expect("Invalid hex");

        let computed_g1 = G1Affine::augmented_hash(&g2, &data);

        assert_eq!(hex::encode(computed_g1.serialize()), *g1);
    }
}

#[test]
fn test_verify_bls_signature() {
    let rng = &mut reproducible_rng();

    let sk = Scalar::random(rng);
    let pk = G2Affine::from(G2Affine::generator() * &sk);
    let message = G1Affine::hash(b"bls_signature", &rng.r#gen::<[u8; 32]>());
    let signature = G1Affine::from(&message * &sk);

    assert!(verify_bls_signature(&signature, &pk, &message));
    assert!(!verify_bls_signature(&message, &pk, &signature));
}

fn with_random_duplicates(
    n: usize,
    rng: &mut (impl Rng + CryptoRng),
    sigs: &[G1Affine],
    pks: &[G2Affine],
    msgs: &[G1Affine],
) -> (Vec<G1Affine>, Vec<G2Affine>, Vec<G1Affine>) {
    let mut result_sigs = sigs.to_vec();
    let mut result_pks = pks.to_vec();
    let mut result_msgs = msgs.to_vec();
    for _ in 0..n {
        let in_index = rng.gen_range(0..sigs.len());
        let out_index = rng.gen_range(0..result_sigs.len() + 1);
        result_sigs.insert(out_index, sigs[in_index].clone());
        result_pks.insert(out_index, pks[in_index].clone());
        result_msgs.insert(out_index, msgs[in_index].clone());
    }

    (result_sigs, result_pks, result_msgs)
}

fn with_random_new_msgs_signed_by_existing_keys(
    n: usize,
    rng: &mut (impl Rng + CryptoRng),
    sks: &[Scalar],
    sigs: &[G1Affine],
    pks: &[G2Affine],
    msgs: &[G1Affine],
) -> (Vec<G1Affine>, Vec<G2Affine>, Vec<G1Affine>) {
    let mut result_sigs = sigs.to_vec();
    let mut result_pks = pks.to_vec();
    let mut result_msgs = msgs.to_vec();
    for _ in 0..n {
        let in_index = rng.gen_range(0..sigs.len());
        let out_index = rng.gen_range(0..result_sigs.len() + 1);

        let rand_new_msg = G1Affine::hash(b"bls_signature", &rng.r#gen::<[u8; 32]>());

        let rand_selected_pk = pks[in_index].clone();
        let rand_selected_sk = sks[in_index].clone();

        let new_sig = G1Affine::from(&rand_new_msg * rand_selected_sk);

        result_sigs.insert(out_index, new_sig);
        result_pks.insert(out_index, rand_selected_pk);
        result_msgs.insert(out_index, rand_new_msg);
    }

    (result_sigs, result_pks, result_msgs)
}

fn with_random_sigs_of_existing_messages_signed_by_existing_signers(
    n: usize,
    rng: &mut (impl Rng + CryptoRng),
    sks: &[Scalar],
    sigs: &[G1Affine],
    pks: &[G2Affine],
    msgs: &[G1Affine],
) -> (Vec<G1Affine>, Vec<G2Affine>, Vec<G1Affine>) {
    let mut result_sigs = sigs.to_vec();
    let mut result_pks = pks.to_vec();
    let mut result_msgs = msgs.to_vec();
    for _ in 0..n {
        let msg_index = rng.gen_range(0..sigs.len());
        let signer_index = rng.gen_range(0..sigs.len());

        let out_index = rng.gen_range(0..result_sigs.len() + 1);

        let rand_selected_pk = pks[signer_index].clone();
        let rand_selected_sk = sks[signer_index].clone();
        let rand_selected_msg = msgs[msg_index].clone();

        let new_sig = G1Affine::from(&rand_selected_msg * rand_selected_sk);

        result_sigs.insert(out_index, new_sig);
        result_pks.insert(out_index, rand_selected_pk);
        result_msgs.insert(out_index, rand_selected_msg);
    }

    (result_sigs, result_pks, result_msgs)
}

const NUM_DUPLICATES: usize = 10;

macro_rules! generic_test_verify_bls_signature_batch {
    ($batch_verification_function:ident) => {
        let rng = &mut reproducible_rng();

        for num_inputs in [1, 2, 4, 8, 16, 32, 100] {
            let sks: Vec<_> = (0..num_inputs).map(|_| Scalar::random(rng)).collect();
            let pks: Vec<_> = sks
                .iter()
                .map(|sk| G2Affine::from(G2Affine::generator() * sk))
                .collect();
            let msgs: Vec<_> = (0..num_inputs)
                .map(|_| G1Affine::hash(b"bls_signature", &rng.r#gen::<[u8; 32]>()))
                .collect();
            let sigs: Vec<_> = sks
                .iter()
                .zip(msgs.iter())
                .map(|(sk, msg)| G1Affine::from(msg * sk))
                .collect();

            for i in 0..num_inputs {
                assert!(verify_bls_signature(&sigs[i], &pks[i], &msgs[i]));
                // swapped sigs/msgs must not work
                assert!(!verify_bls_signature(&msgs[i], &pks[i], &sigs[i]));
            }

            assert!($batch_verification_function(
                &izip!(sigs.iter(), pks.iter(), msgs.iter()).collect::<Vec<_>>()[..],
                rng
            ));

            // swapped sigs/msgs must not work
            assert!(!$batch_verification_function(
                &izip!(msgs.iter(), pks.iter(), sigs.iter()).collect::<Vec<_>>()[..],
                rng
            ));

            if num_inputs > 1 {
                // swapped single sigs must not work
                let mut cloned_sigs = sigs.clone();
                cloned_sigs.swap(0, 1);
                assert!(!$batch_verification_function(
                    &izip!(cloned_sigs.iter(), pks.iter(), msgs.iter()).collect::<Vec<_>>()[..],
                    rng
                ));

                // swapped single msgs must not work
                let mut cloned_msgs = msgs.clone();
                cloned_msgs.swap(0, 1);

                assert!(!$batch_verification_function(
                    &izip!(sigs.iter(), pks.iter(), cloned_msgs.iter()).collect::<Vec<_>>()[..],
                    rng
                ));

                // swapped single pks must not work
                let mut cloned_pks = pks.clone();
                cloned_pks.swap(0, 1);

                assert!(!$batch_verification_function(
                    &izip!(sigs.iter(), cloned_pks.iter(), msgs.iter()).collect::<Vec<_>>()[..],
                    rng
                ));
            }

            let (sigs_w_dups, pks_w_dups, msgs_w_dups) =
                with_random_duplicates(NUM_DUPLICATES, rng, &sigs, &pks, &msgs);

            assert!($batch_verification_function(
                &izip!(sigs_w_dups.iter(), pks_w_dups.iter(), msgs_w_dups.iter())
                    .collect::<Vec<_>>()[..],
                rng
            ));

            let (sigs_w_new_msgs, pks_w_new_msgs, msgs_w_new_msgs) =
                with_random_new_msgs_signed_by_existing_keys(
                    NUM_DUPLICATES,
                    rng,
                    &sks,
                    &sigs,
                    &pks,
                    &msgs,
                );

            assert!($batch_verification_function(
                &izip!(
                    sigs_w_new_msgs.iter(),
                    pks_w_new_msgs.iter(),
                    msgs_w_new_msgs.iter()
                )
                .collect::<Vec<_>>()[..],
                rng
            ));

            // corrupt each signature sequentially for not too large batches
            if sigs_w_new_msgs.len() < 50 {
                for i in 0..sigs_w_new_msgs.len() {
                    let sigs_w_new_msgs: Vec<_> = sigs_w_new_msgs
                        .iter()
                        .enumerate()
                        .map(|(j, sig)| {
                            if j == i {
                                // corrupt signature i
                                G1Affine::hash(b"bls_signature", &rng.r#gen::<[u8; 32]>())
                            } else {
                                sig.clone()
                            }
                        })
                        .collect();
                    assert!(!$batch_verification_function(
                        &izip!(
                            sigs_w_new_msgs.iter(),
                            pks_w_new_msgs.iter(),
                            msgs_w_new_msgs.iter()
                        )
                        .collect::<Vec<_>>()[..],
                        rng
                    ));
                }
            }

            let (sigs_w_dup_msgs, pks_w_dup_msgs, msgs_w_dup_msgs) =
                with_random_sigs_of_existing_messages_signed_by_existing_signers(
                    NUM_DUPLICATES,
                    rng,
                    &sks,
                    &sigs,
                    &pks,
                    &msgs,
                );

            assert!($batch_verification_function(
                &izip!(
                    sigs_w_dup_msgs.iter(),
                    pks_w_dup_msgs.iter(),
                    msgs_w_dup_msgs.iter()
                )
                .collect::<Vec<_>>()[..],
                rng
            ));
        }
    };
}

#[test]
fn test_verify_bls_signature_batch_with_distinct_msgs_and_sigs() {
    generic_test_verify_bls_signature_batch!(verify_bls_signature_batch_distinct);
}

#[test]
fn test_verify_bls_signature_mixed_batch() {
    generic_test_verify_bls_signature_batch!(verify_bls_signature_batch);
}

#[test]
fn test_verify_bls_signature_batch_with_same_msg() {
    let rng = &mut reproducible_rng();

    for num_inputs in [1, 2, 4, 8, 16, 32, 100] {
        let sks: Vec<_> = (0..num_inputs).map(|_| Scalar::random(rng)).collect();
        let pks: Vec<_> = sks
            .iter()
            .map(|sk| G2Affine::from(G2Affine::generator() * sk))
            .collect();
        let msg = G1Affine::hash(b"bls_signature", &rng.r#gen::<[u8; 32]>());
        let sigs: Vec<_> = sks.iter().map(|sk| G1Affine::from(&msg * sk)).collect();

        for i in 0..num_inputs {
            assert!(verify_bls_signature(&sigs[i], &pks[i], &msg));
            assert!(!verify_bls_signature(&msg, &pks[i], &sigs[i]));
        }

        assert!(verify_bls_signature_batch_same_msg(
            &sigs.iter().zip(pks.iter()).collect::<Vec<_>>()[..],
            &msg,
            rng
        ));

        // the "all-distinct" batched method should also work
        assert!(verify_bls_signature_batch_distinct(
            &sigs
                .iter()
                .zip(pks.iter())
                .map(|(sig, pk)| (sig, pk, &msg))
                .collect::<Vec<_>>()[..],
            rng
        ));

        assert!(!verify_bls_signature_batch_same_msg(
            &sigs.iter().zip(pks.iter()).collect::<Vec<_>>()[..],
            &G1Affine::hash(b"bls_signature", &rng.r#gen::<[u8; 32]>()),
            rng
        ));

        // swapped single sigs/pks must not work
        if num_inputs > 1 {
            let mut cloned_sigs = sigs.clone();
            cloned_sigs.swap(0, 1);

            assert!(!verify_bls_signature_batch_same_msg(
                &cloned_sigs.iter().zip(pks.iter()).collect::<Vec<_>>()[..],
                &msg,
                rng
            ));

            let mut cloned_pks = pks.clone();
            cloned_pks.swap(0, 1);

            assert!(!verify_bls_signature_batch_same_msg(
                &sigs.iter().zip(cloned_pks.iter()).collect::<Vec<_>>()[..],
                &msg,
                rng
            ));
        }

        let (sigs_w_dups, pks_w_dups, _msgs_w_dups) = with_random_duplicates(
            NUM_DUPLICATES,
            rng,
            &sigs,
            &pks,
            &vec![msg.clone(); pks.len()][..],
        );

        assert!(verify_bls_signature_batch_same_msg(
            &sigs_w_dups
                .iter()
                .zip(pks_w_dups.iter())
                .collect::<Vec<_>>()[..],
            &msg,
            rng
        ));
    }
}

#[test]
fn test_verify_bls_signature_batch_with_same_pk() {
    let rng = &mut reproducible_rng();

    for num_inputs in [1, 2, 4, 8, 16, 32, 100] {
        let sk = Scalar::random(rng);
        let pk = G2Affine::from(G2Affine::generator() * &sk);
        let msgs: Vec<_> = (0..num_inputs)
            .map(|_| G1Affine::hash(b"bls_signature", &rng.r#gen::<[u8; 32]>()))
            .collect();
        let sigs: Vec<_> = msgs.iter().map(|msg| G1Affine::from(msg * &sk)).collect();

        for i in 0..num_inputs {
            assert!(verify_bls_signature(&sigs[i], &pk, &msgs[i]));
            assert!(!verify_bls_signature(&msgs[i], &pk, &sigs[i]));
        }

        assert!(verify_bls_signature_batch_same_pk(
            &sigs.iter().zip(msgs.iter()).collect::<Vec<_>>()[..],
            &pk,
            rng
        ));

        // the "all-distinct" batched method should also work
        assert!(verify_bls_signature_batch_distinct(
            &sigs
                .iter()
                .zip(msgs.iter())
                .map(|(sig, msg)| (sig, &pk, msg))
                .collect::<Vec<_>>()[..],
            rng
        ));

        assert!(!verify_bls_signature_batch_same_pk(
            &sigs.iter().zip(msgs.iter()).collect::<Vec<_>>()[..],
            &G2Affine::from(G2Affine::generator() * &Scalar::random(rng)),
            rng
        ));

        // swapped single sigs/msgs must not work
        if num_inputs > 1 {
            let mut cloned_sigs = sigs.clone();
            cloned_sigs.swap(0, 1);

            assert!(!verify_bls_signature_batch_same_pk(
                &cloned_sigs.iter().zip(msgs.iter()).collect::<Vec<_>>()[..],
                &pk,
                rng
            ));

            let mut cloned_msgs = msgs.clone();
            cloned_msgs.swap(0, 1);

            assert!(!verify_bls_signature_batch_same_pk(
                &sigs.iter().zip(cloned_msgs.iter()).collect::<Vec<_>>()[..],
                &pk,
                rng
            ));
        }

        let (sigs_w_dups, _pks_w_dups, msgs_w_dups) = with_random_duplicates(
            NUM_DUPLICATES,
            rng,
            &sigs[..],
            &vec![pk.clone(); msgs.len()][..],
            &msgs[..],
        );

        assert!(verify_bls_signature_batch_same_pk(
            &sigs_w_dups
                .iter()
                .zip(msgs_w_dups.iter())
                .collect::<Vec<_>>()[..],
            &pk,
            rng
        ));
    }
}

#[test]
fn test_hash_to_scalar_matches_known_values() {
    // I was not able to locate any official test vectors for BLS12-381 hash_to_scalar
    // so these were just generated using ic_bls12_381 itself.

    let dst = b"QUUX-V01-CS02-with-BLS12381SCALAR_XMD:SHA-256_SSWU_RO_";

    scalar_test_encoding(
        Scalar::hash(&dst[..], b""),
        "3b3fdf74b194c0a0f683d67a312a4e72d663d74b8478dc7b56be41e0ce11caa1",
    );

    scalar_test_encoding(
        Scalar::hash(&dst[..], b"abc"),
        "47e7a8839695a3df27f202cf71e295a8554b47cef75c1e316b1865317720e188",
    );

    scalar_test_encoding(
        Scalar::hash(&dst[..], b"abcdef0123456789"),
        "3dff572f262e702f2ee8fb79b70e3225f5ee543a389eea2e58eec7b2bfd6afeb",
    );

    scalar_test_encoding(
        Scalar::hash(&dst[..], format!("q128_{}", "q".repeat(128)).as_bytes()),
        "2874c0e7814fcf42a5f63258417d4be8ea0465ff7352691493d0eca2dd5a9729",
    );

    scalar_test_encoding(
        Scalar::hash(&dst[..], format!("a512_{}", "a".repeat(512)).as_bytes()),
        "3cf6864b1a81fba0798c370f6daf9c23a838f9dbb96ea3a3a1145899ddf259b4",
    );
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
        "852926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
    );

    g1_test_encoding(
        G1Affine::hash(&dst[..], b"abc"),
        "83567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
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
        "a5cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
    );

    g2_test_encoding(
        G2Affine::hash(&dst[..], b"abc"),
        "939cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd802c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
    );

    g2_test_encoding(
        G2Affine::hash(&dst[..], b"abcdef0123456789"),
        "990d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0",
    );

    g2_test_encoding(
        G2Affine::hash(&dst[..], format!("q128_{}", "q".repeat(128)).as_bytes()),
        "8934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb9119a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da",
    );

    g2_test_encoding(
        G2Affine::hash(&dst[..], format!("a512_{}", "a".repeat(512)).as_bytes()),
        "91fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d0156901a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534",
    );
}

fn random_node_indexes<R: rand::Rng>(
    rng: &mut R,
    count: usize,
) -> std::collections::BTreeSet<NodeIndex> {
    let mut set = std::collections::BTreeSet::new();

    while set.len() != count {
        let r = rng.r#gen::<NodeIndex>();
        set.insert(r);
    }

    set
}

#[test]
fn should_g1_interpolation_at_zero_work() -> Result<(), InterpolationError> {
    let rng = &mut reproducible_rng();

    for num_coefficients in 1..30 {
        let poly = Polynomial::random(num_coefficients, rng);

        let sk = poly.coeff(0);
        let pk = G1Affine::from(G1Affine::generator() * sk);

        let node_ids = random_node_indexes(rng, num_coefficients);
        let mut node_shares = Vec::with_capacity(num_coefficients);

        for r in &node_ids {
            let p_r = poly.evaluate_at(&Scalar::from_node_index(*r));
            let g_p_r = G1Affine::from(G1Affine::generator() * &p_r);
            node_shares.push(g_p_r);
        }

        let coefficients = LagrangeCoefficients::at_zero(&NodeIndices::from_set(&node_ids));
        let g0 = coefficients.interpolate_g1(&node_shares)?;
        assert_eq!(g0, pk);
    }

    Ok(())
}

#[test]
fn should_g2_interpolation_at_zero_work() -> Result<(), InterpolationError> {
    let rng = &mut reproducible_rng();

    for num_coefficients in 1..30 {
        let poly = Polynomial::random(num_coefficients, rng);

        let sk = poly.coeff(0);
        let pk = G2Affine::from(G2Affine::generator() * sk);

        let node_ids = random_node_indexes(rng, num_coefficients);
        let mut node_shares = Vec::with_capacity(num_coefficients);

        for r in &node_ids {
            let p_r = poly.evaluate_at(&Scalar::from_node_index(*r));
            let g_p_r = G2Affine::from(G2Affine::generator() * &p_r);
            node_shares.push(g_p_r);
        }

        let coefficients = LagrangeCoefficients::at_zero(&NodeIndices::from_set(&node_ids));
        let g0 = coefficients.interpolate_g2(&node_shares)?;
        assert_eq!(g0, pk);
    }

    Ok(())
}

/// Verify that x_for_index(i) == i+1 (in the field).
#[test]
fn test_scalar_from_node_index_returns_correct_value() {
    // First N values:
    let mut x = Scalar::one();
    for i in 0..100 {
        assert_eq!(Scalar::from_node_index(i), x);
        x += Scalar::one();
    }
    // Binary 0, 1, 11, 111, ... all the way up to the maximum NodeIndex.
    // The corresponding x values are binary 1, 10, 100, ... and the last value is
    // one greater than the maximum NodeIndex.

    let two = Scalar::from_u64(2);
    let mut x = Scalar::one();
    let mut i: NodeIndex = 0;
    loop {
        assert_eq!(Scalar::from_node_index(i), x);
        if i == NodeIndex::MAX {
            break;
        }
        i = i * 2 + 1;
        x *= &two;
    }
}

/// A trait generating "biased" values
///
/// This trait is used to generate inputs which may trigger corner
/// cases in multiplication routines, especially when combined in
/// multi-input multiplications (mul2, muln)
///
/// The exact nature of the bias is unspecified
trait BiasedValue {
    type Output;
    fn biased<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Output;
}

impl BiasedValue for Scalar {
    type Output = Scalar;
    fn biased<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Output {
        let coin = rng.r#gen::<u8>();

        // With ~4% probability each use -1, 0, or 1. Otherwise random
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
}

impl BiasedValue for G1Projective {
    type Output = G1Projective;
    fn biased<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Output {
        let coin = rng.r#gen::<u8>();

        // With ~4% probability each use identity, g, or -g. Otherwise random
        if coin < 10 {
            Self::identity()
        } else if coin < 20 {
            Self::generator().clone()
        } else if coin < 30 {
            Self::generator().neg()
        } else {
            Self::hash(b"random-g1-val-for-testing", &rng.r#gen::<[u8; 32]>())
        }
    }
}

impl BiasedValue for G2Projective {
    type Output = G2Projective;
    fn biased<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Output {
        let coin = rng.r#gen::<u8>();

        // With ~4% probability each use identity, g, or -g. Otherwise random
        if coin < 10 {
            Self::identity()
        } else if coin < 20 {
            Self::generator().clone()
        } else if coin < 30 {
            Self::generator().neg()
        } else {
            Self::hash(b"random-g2-val-for-testing", &rng.r#gen::<[u8; 32]>())
        }
    }
}

macro_rules! test_point_operation {

    // Top level dispatch: iterate over the groups and reinvoke
    // with the individual group identifier
    ( $test_name:ident, [$( $group:ident ),+], $block:block ) => {
        $(
            test_point_operation!{$test_name, $group, $block}
        )*
    };

    // Match on the specific group identifier provided by the top level
    // dispatch arm, and then reinvoke again, specifying the related types.
    ( $test_name:ident, g1, $block:block ) => {
        test_point_operation!($test_name, $block, g1, G1Affine, G1Projective);
    };
    ( $test_name:ident, g2, $block:block ) => {
        test_point_operation!($test_name, $block, g2, G2Affine, G2Projective);
    };
    ( $test_name:ident, gt, $block:block ) => {
        test_point_operation!($test_name, $block, gt, Gt, Gt);
    };

    // With all parameters known at this point, finally generate the #[test]
    ( $test_name:ident, $block:block, $group_id:ident, $affine:ty, $projective:ty ) => {
        paste! { #[test] fn [<test_ $group_id _ $test_name>]() {
            #[allow(dead_code)]
            type Affine = $affine;
            #[allow(dead_code)]
            type Projective = $projective;

            #[allow(unused_imports)]
            use BiasedValue;

            $block
        }
        }
    };
}

test_point_operation!(serialization_round_trip, [g1, g2], {
    let rng = &mut reproducible_rng();

    for _ in 1..30 {
        let orig = Projective::hash(b"serialization-round-trip-test", &rng.r#gen::<[u8; 32]>());
        let bits = orig.serialize();

        let d = Projective::deserialize(&bits).expect("Invalid serialization");
        assert_eq!(orig, d);
        assert_eq!(d.serialize(), bits);

        let du = Projective::deserialize_unchecked(&bits).expect("Invalid serialization");
        assert_eq!(orig, du);
        assert_eq!(du.serialize(), bits);
    }
});

test_point_operation!(is_torsion_free, [g1, g2], {
    let rng = &mut reproducible_rng();

    for _ in 0..30 {
        let mut buf = [0u8; Affine::BYTES];
        rng.fill_bytes(&mut buf);

        let pt_c = Affine::deserialize(&buf);
        let pt_u = Affine::deserialize_unchecked(&buf);

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
});

test_point_operation!(negation, [g1, g2, gt], {
    assert_eq!(Affine::identity(), Affine::identity().neg());
    assert_eq!(Projective::identity(), Projective::identity().neg());

    let rng = &mut reproducible_rng();

    let s = Scalar::random(rng);

    let pt_pos = Affine::generator() * &s;
    let pt_neg = Affine::generator() * s.neg();

    assert_eq!(pt_pos.neg(), pt_neg);
    assert_eq!(pt_neg.neg(), pt_pos);
    assert!((pt_pos + pt_neg).is_identity());
});

test_point_operation!(addition, [g1, g2, gt], {
    let rng = &mut reproducible_rng();

    let g = Affine::generator();

    for _ in 0..1000 {
        let s0 = Scalar::random(rng);
        let s1 = Scalar::random(rng);
        let s2 = &s0 - &s1;

        let gs0 = g * &s0;
        let gs1 = g * &s1;
        let gs2 = g * &s2;
        assert_eq!(gs0, &gs1 + &gs2);
        assert_eq!(gs1, &gs0 - &gs2);
        assert_eq!(gs2, &gs0 - &gs1);
    }
});

test_point_operation!(sum, [g1, g2], {
    let rng = &mut reproducible_rng();

    let pt = Affine::generator();

    for t in 1..20 {
        let mut inputs = Vec::with_capacity(t);
        let mut elements = Vec::with_capacity(t);
        for _ in 0..t {
            let r = rng.r#gen::<u32>() as u64;
            inputs.push(r);
            elements.push(pt * Scalar::from_u64(r));
        }

        assert_eq!(
            pt * Scalar::from_u64(inputs.iter().sum()),
            Projective::sum(&elements)
        )
    }
});

test_point_operation!(multiply, [g1, g2, gt], {
    let rng = &mut reproducible_rng();

    let pt = Affine::generator();

    for _ in 1..300 {
        let lhs = rng.r#gen::<u32>() as u64;
        let rhs = rng.r#gen::<u32>() as u64;
        let integer_prod = lhs * rhs;
        let product = (pt * Scalar::from_u64(lhs)) * Scalar::from_u64(rhs);

        assert_eq!(pt * Scalar::from_u64(integer_prod), product);
    }
});

test_point_operation!(mul_with_precompute, [g1, g2], {
    let rng = &mut reproducible_rng();

    let g = Affine::hash(b"random-point-for-mul-precompute", &rng.r#gen::<[u8; 32]>());

    let mut g_with_precompute = g.clone();
    g_with_precompute.precompute();

    let assert_same_result = |s: Scalar| {
        let no_precomp = &g * &s;
        let with_precomp = &g_with_precompute * &s;
        assert_eq!(no_precomp, with_precomp);
    };

    assert_same_result(Scalar::zero());
    assert_same_result(Scalar::one());
    assert_same_result(Scalar::one().neg());
    for _ in 0..1000 {
        assert_same_result(Scalar::random(rng));
    }
});

test_point_operation!(batch_mul, [g1, g2], {
    let rng = &mut reproducible_rng();

    let pt = Affine::hash(b"ic-crypto-batch-mul-test", &rng.r#gen::<[u8; 32]>());

    for i in 0..20 {
        let scalars = Scalar::batch_random(rng, i);
        assert_eq!(scalars.len(), i);

        let batch = Affine::batch_mul(&pt, &scalars);
        assert_eq!(batch.len(), scalars.len());

        for j in 0..i {
            assert_eq!(batch[j], Affine::from(&pt * &scalars[j]));
        }
    }
});

test_point_operation!(mul2, [g1, g2], {
    let rng = &mut reproducible_rng();

    let g = Projective::generator();
    let zero = Scalar::zero();
    let one = Scalar::one();

    assert_eq!(Projective::mul2(g, &zero, g, &zero), Projective::identity());
    assert_eq!(Projective::mul2(g, &one, g, &zero), *g);
    assert_eq!(Projective::mul2(g, &zero, g, &one), *g);

    for _ in 0..1000 {
        let s1 = Scalar::biased(rng);
        let s2 = Scalar::biased(rng);

        let p1 = Projective::biased(rng);
        let p2 = Projective::biased(rng);

        let reference = &p1 * &s1 + &p2 * &s2;

        assert_eq!(Projective::mul2(&p1, &s1, &p2, &s2), reference);
        assert_eq!(Projective::mul2(&p2, &s2, &p1, &s1), reference);
    }
});

test_point_operation!(muln_sparse, [g1, g2], {
    let rng = &mut reproducible_rng();

    assert_eq!(
        Projective::muln_affine_sparse_vartime(&[]),
        Projective::identity()
    );

    fn gen_rand_subset(k: usize, n: usize, rng: &mut (impl Rng + CryptoRng)) -> Vec<usize> {
        (0..n)
            .collect::<Vec<usize>>()
            .iter()
            .choose_multiple(rng, k)
            .into_iter()
            .cloned()
            .collect()
    }

    fn gen_rand_sparse_scalar(k: usize, rng: &mut (impl Rng + CryptoRng)) -> Scalar {
        let set_bit = |bytes: &mut [u8], i: usize| {
            bytes[Scalar::BYTES - i / 8 - 1] |= 1 << (i % 8);
        };

        const SCALAR_FLOORED_BIT_LENGTH: usize = 254;

        let mut scalar = [0u8; Scalar::BYTES];
        for i in gen_rand_subset(k, SCALAR_FLOORED_BIT_LENGTH, rng) {
            set_bit(&mut scalar, i);
        }
        Scalar::deserialize(&scalar).unwrap()
    }

    // test sparse scalars
    for hamming_weight in [1, 2, 3, 5, 10, 15, 20, 100] {
        for num_inputs in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 30, 40, 50, 100] {
            let points: Vec<Affine> = (0..num_inputs)
                .map(|_| Projective::biased(rng).to_affine())
                .collect();
            let scalars: Vec<Scalar> = (0..num_inputs)
                .map(|_| gen_rand_sparse_scalar(hamming_weight, rng))
                .collect();

            let reference_val = points
                .iter()
                .zip(scalars.iter())
                .fold(Projective::identity(), |accum, (p, s)| accum + p * s);

            let computed = Projective::muln_affine_sparse_vartime(
                &points.iter().zip(scalars.iter()).collect::<Vec<_>>()[..],
            );
            assert_eq!(computed, reference_val);
        }
    }

    // non-sparse scalars must also work, although slower
    for t in 1..20 {
        let mut points = Vec::with_capacity(t);
        let mut scalars = Vec::with_capacity(t);
        for _ in 0..t {
            points.push(Projective::biased(rng).to_affine());
            scalars.push(Scalar::biased(rng));
        }

        let reference_val = points
            .iter()
            .zip(scalars.iter())
            .fold(Projective::identity(), |accum, (p, s)| accum + p * s);

        let computed = Projective::muln_affine_sparse_vartime(
            &points.iter().zip(scalars.iter()).collect::<Vec<_>>()[..],
        );
        assert_eq!(computed, reference_val);
    }
});

test_point_operation!(muln, [g1, g2], {
    let rng = &mut reproducible_rng();

    assert_eq!(Projective::muln_vartime(&[], &[]), Projective::identity());

    for t in 1..100 {
        let mut points = Vec::with_capacity(t);
        let mut scalars = Vec::with_capacity(t);

        for _ in 0..t {
            points.push(Projective::biased(rng));
            scalars.push(Scalar::biased(rng));
        }

        let reference_val = points
            .iter()
            .zip(scalars.iter())
            .fold(Projective::identity(), |accum, (p, s)| accum + p * s);

        let computed = Projective::muln_vartime(&points[..], &scalars[..]);

        assert_eq!(computed, reference_val);
    }
});

test_point_operation!(muln_affine, [g1, g2], {
    let rng = &mut reproducible_rng();

    assert_eq!(
        Projective::muln_affine_vartime(&[], &[]),
        Projective::identity()
    );

    for t in 1..100 {
        let mut points = Vec::with_capacity(t);
        let mut scalars = Vec::with_capacity(t);

        for _ in 0..t {
            points.push(Projective::biased(rng));
            scalars.push(Scalar::biased(rng));
        }

        let points = Projective::batch_normalize(&points);

        let reference_val = points
            .iter()
            .zip(scalars.iter())
            .fold(Projective::identity(), |accum, (p, s)| accum + p * s);

        let computed = Projective::muln_affine_vartime(&points[..], &scalars[..]);

        assert_eq!(computed, reference_val);
    }
});

test_point_operation!(batch_normalize, [g1, g2], {
    let rng = &mut reproducible_rng();

    let g = Affine::generator();

    for i in 0..100 {
        let inputs = (0..i).map(|_| g * Scalar::random(rng)).collect::<Vec<_>>();

        let batch_converted = Projective::batch_normalize(&inputs);

        assert_eq!(inputs.len(), batch_converted.len());

        for j in 0..i {
            assert_eq!(inputs[j].to_affine(), batch_converted[j]);
        }
    }
});
