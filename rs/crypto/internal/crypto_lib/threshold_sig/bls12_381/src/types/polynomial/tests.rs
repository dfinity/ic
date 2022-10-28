//! Polynomial tests
use super::*;

mod basic_functionality {
    use super::*;
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test]
    fn test_polynomial_from_rng_produces_same_poly_from_same_seed() {
        let seed = [1u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let poly = Polynomial::random(3, &mut rng);

        assert_eq!(
            hex::encode(poly.coefficients[0].serialize()),
            "023f37203a2476c42566a61cc55c3ca875dbb4cc41c0deb789f8e7bf88183638",
        );
        assert_eq!(
            hex::encode(poly.coefficients[1].serialize()),
            "1ecc3686b60ee3b84b6c7d321d70d5c06e9dac63a4d0a79d731b17c0d04d030d",
        );
        assert_eq!(
            hex::encode(poly.coefficients[2].serialize()),
            "01274dd1ee5216c204fb698daea45b52e98b6f0fdd046dcc3a86bb079e36f024",
        );
    }

    // Slow tests
    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 4,
            .. ProptestConfig::default()
        })]

        #[test]
        fn polynomial_from_rng_works(seed: [u8; 32], length in 0usize..200) {
            let mut rng = ChaChaRng::from_seed(seed);
            Polynomial::random(length, &mut rng);
        }

        // Shamir's Secret Sharing Scheme
        #[test]
        fn shamir_secret_sharing_scheme(
            secret in arbitrary::fr(),
            mut poly in arbitrary::poly()
               .prop_filter("poly must have at least one coefficient", |p| !p.coefficients.is_empty()),
            shareholders in proptest::collection::vec(arbitrary::fr(), 1..300)
        ) {
            poly.coefficients[0] = secret.clone();
            let shares: Vec<(Scalar,Scalar)> = shareholders.iter().map(|x| (x.clone(), poly.evaluate_at(x))).collect();
            if shares.len() >= poly.coefficients.len() {
                assert_eq!(Polynomial::interpolate(&shares[0..poly.coefficients.len()]).coefficients[0], secret);
            } else {
                assert_ne!(Polynomial::interpolate(&shares).coefficients[0], secret);
            }
        }
    }
}
