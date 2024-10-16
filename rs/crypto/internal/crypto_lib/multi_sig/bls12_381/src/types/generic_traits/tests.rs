//! Check that the generic traits work.
//! The standalone methods are all guaranteed to be used or to show build
//! warnings.  Not so the trait implementations.

use super::*;
use proptest::prelude::*;

proptest! {
        #![proptest_config(ProptestConfig {
            cases: 1,
            .. ProptestConfig::default()
        })]

    #[test]
    fn debug_trait_on_public_key_bytes_works(public_key_bytes: PublicKeyBytes) { let _ = format!("{:?}", public_key_bytes); }

    #[test]
    fn debug_trait_on_individual_signature_bytes_works(individual_signature_bytes: IndividualSignatureBytes) { let _ = format!("{:?}", individual_signature_bytes); }

    #[test]
    fn debug_trait_on_pop_bytes_works(pop_bytes: PopBytes) { let _ = format!("{:?}", pop_bytes); }

    #[test]
    fn debug_trait_on_combined_signature_bytes_works(combined_signature_bytes: CombinedSignatureBytes) { let _ = format!("{:?}", combined_signature_bytes); }

    #[test]
    fn debug_should_redact_secretkey_bytes(secret_key_bytes: SecretKeyBytes) {
        let debug_str = format!("{:?}", secret_key_bytes);
        let raw_str = base64::encode(secret_key_bytes.0.expose_secret());
        assert!(!debug_str.contains(&raw_str));
        assert_eq!(debug_str, "REDACTED");
    }

    #[test]
    fn equality_fails_for_public_key_bytes(public_key_bytes: PublicKeyBytes) {
      let mut different_bytes = public_key_bytes;
      different_bytes.0[0] ^= 0xff;
      assert_ne!(public_key_bytes, different_bytes);
    }

    #[test]
    fn equality_fails_for_individual_signature_bytes(individual_signature_bytes: IndividualSignatureBytes) {
      let mut different_bytes = individual_signature_bytes;
      different_bytes.0[0] ^= 0xff;
      assert_ne!(individual_signature_bytes, different_bytes);
    }

    #[test]
    fn equality_fails_for_pop_bytes(pop_bytes: PopBytes) {
      let mut different_bytes = pop_bytes;
      different_bytes.0[0] ^= 0xff;
      assert_ne!(pop_bytes, different_bytes);
    }
}
