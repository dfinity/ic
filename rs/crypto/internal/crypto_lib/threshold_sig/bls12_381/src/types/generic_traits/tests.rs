//! Check that the generic traits work.
//! The standalone methods are all guaranteed to be used or to show build
//! warnings.  Not so the trait implementations.

use super::*;
use crate::types::arbitrary::threshold_sig_public_key_bytes;
use proptest::prelude::*;

proptest! {
        #![proptest_config(ProptestConfig {
            cases: 1,
            .. ProptestConfig::default()
        })]

    #[test]
    fn debug_trait_on_public_key_bytes_works(public_key_bytes in threshold_sig_public_key_bytes()) { format!("{:?}", public_key_bytes) }

    #[test]
    fn debug_trait_on_individual_signature_bytes_works(individual_signature_bytes: IndividualSignatureBytes) {  format!("{:?}", individual_signature_bytes) }

    #[test]
    fn debug_trait_on_combined_signature_bytes_works(combined_signature_bytes: CombinedSignatureBytes) {  format!("{:?}", combined_signature_bytes) }

    #[test]
    fn debug_should_redact_secretkey_bytes(secret_key_bytes: SecretKeyBytes) {
        let debug_str = format!("{:?}", secret_key_bytes);
        let raw_str = String::from(secret_key_bytes);
        assert!(!debug_str.contains(&raw_str));
        assert_eq!(debug_str, "REDACTED");
    }

    #[test]
    fn equality_holds_for_public_key_bytes(public_key_bytes in threshold_sig_public_key_bytes()) {
      assert_eq!(public_key_bytes, public_key_bytes);
    }

    #[test]
    fn equality_fails_for_public_key_bytes(public_key_bytes in threshold_sig_public_key_bytes()) {
      let mut different_bytes = public_key_bytes;
      different_bytes.0[0] ^= 0xff;
      assert_ne!(public_key_bytes, different_bytes);
    }

    #[test]
    fn equality_holds_for_individual_signature_bytes(individual_signature_bytes: IndividualSignatureBytes) {
      assert_eq!(individual_signature_bytes, individual_signature_bytes);
    }

    #[test]
    fn equality_fails_for_individual_signature_bytes(individual_signature_bytes: IndividualSignatureBytes) {
      let mut different_bytes = individual_signature_bytes;
      different_bytes.0[0] ^= 0xff;
      assert_ne!(individual_signature_bytes, different_bytes);
    }
}
