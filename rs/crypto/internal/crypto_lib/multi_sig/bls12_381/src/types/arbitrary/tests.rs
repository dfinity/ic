//! Check that the arbitrary traits work.
//! The standalone methods are all guaranteed to be used or to show build
//! warnings.  Not so the trait implementations.

use super::*;

proptest! {
        #![proptest_config(ProptestConfig {
            cases: 5,
            .. ProptestConfig::default()
        })]

    #[test]
    fn arbitrary_public_key_bytes_works(_public_key_bytes: PublicKeyBytes) {}

    #[test]
    fn arbitrary_individual_signature_bytes_works(_individual_signature_bytes: IndividualSignatureBytes) {}

    #[test]
    fn arbitrary_pop_bytes_works(_pop_bytes: PopBytes) {}

    #[test]
    fn arbitrary_combined_signature_bytes_works(_combined_signature_bytes: CombinedSignatureBytes) {}
}
