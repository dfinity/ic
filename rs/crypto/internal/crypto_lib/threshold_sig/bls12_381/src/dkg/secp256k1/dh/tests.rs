use super::*;
use crate::types::arbitrary::secret_key;
use ic_crypto_internal_csp_test_utils::arbitrary::arbitrary_ephemeral_public_key_bytes;
use ic_types_test_utils::arbitrary as arbitrary_types;
use proptest::prelude::*;

proptest! {
    #[test]
    fn encrypted_decrypts(
       dkg_id in arbitrary_types::dkg_id(),
       dealer_public_key in arbitrary_ephemeral_public_key_bytes(),
       receiver_public_key in arbitrary_ephemeral_public_key_bytes(),
       diffie_hellman in arbitrary_ephemeral_public_key_bytes(),
       secret_share in secret_key(),
    ){
        let encrypted = encrypt_share(dkg_id, dealer_public_key, receiver_public_key, diffie_hellman, secret_share);
        let decrypted = decrypt_share(dkg_id, dealer_public_key, receiver_public_key, diffie_hellman, encrypted);
        assert_eq!(secret_share, decrypted);
    }
}
