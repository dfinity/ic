//! Polynomial tests
use super::*;

mod basic_functionality {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

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
            poly.coefficients[0] = secret;
            let shares: Vec<(Fr,Fr)> = shareholders.iter().map(|x| (*x, poly.evaluate_at(x))).collect();
            if shares.len() >= poly.coefficients.len() {
                assert_eq!(Polynomial::interpolate(&shares[0..poly.coefficients.len()]).coefficients[0], secret);
            } else {
                assert_ne!(Polynomial::interpolate(&shares).coefficients[0], secret);
            }
        }
    }
}
