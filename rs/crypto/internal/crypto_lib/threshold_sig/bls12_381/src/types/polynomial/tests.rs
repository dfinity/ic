//! Polynomial tests
use super::*;

mod basic_functionality {
    use super::*;
    use ic_crypto_internal_bls12381_common::fr_to_bytes;
    use pairing::bls12_381::FrRepr;
    use proptest::prelude::*;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    #[test]
    fn test_polynomial_from_rng_produces_same_poly_from_same_seed() {
        let seed = [1u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let poly = Polynomial::random(3, &mut rng);

        assert_eq!(
            hex::encode(fr_to_bytes(&FrRepr::from(poly.coefficients[0]))),
            "1610358dd042ebf85b72e7529e97e899f22e8a28c34874baf245ed8b2b86e779"
        );
        assert_eq!(
            hex::encode(fr_to_bytes(&FrRepr::from(poly.coefficients[1]))),
            "4427ceb3e6bed8feb9f0d6f1a82838f3b499b63027b9368793ee5e5b494e889e"
        );
        assert_eq!(
            hex::encode(fr_to_bytes(&FrRepr::from(poly.coefficients[2]))),
            "5201bc3088e41597c91cfbaf54e2e563b557599884262081520cb6a877fdce27"
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
