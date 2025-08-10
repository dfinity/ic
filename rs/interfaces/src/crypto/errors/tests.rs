mod error_reproducibility {
    use crate::crypto::ErrorReproducibility;
    use ic_crypto_internal_csp_proptest_utils::arb_crypto_error;
    use proptest::proptest;

    proptest! {
        #[test]
        fn should_not_panic(error in arb_crypto_error()) {
            let _should_not_panic = error.is_reproducible();
        }
    }
}
