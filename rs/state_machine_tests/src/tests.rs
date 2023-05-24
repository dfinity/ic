use ic_crypto_ecdsa_secp256k1::{PrivateKey, PublicKey};
use ic_crypto_extended_bip32::{DerivationIndex, DerivationPath};
use proptest::{collection::vec as pvec, prelude::*, prop_assert, proptest};

proptest! {
    #[test]
    fn test_derivation_prop(
        derivation_path_bytes in pvec(pvec(any::<u8>(), 1..10), 1..10),
        message_hash in pvec(any::<u8>(), 32),
        chain_code in pvec(any::<u8>(), 32)
    ) {
        let private_key_bytes =
            hex::decode("fb7d1f5b82336bb65b82bf4f27776da4db71c1ef632c6a7c171c0cbfa2ea4920").unwrap();

        let ecdsa_secret_key: PrivateKey =
            PrivateKey::deserialize_sec1(private_key_bytes.as_slice()).unwrap();

        let signature = crate::sign_message_with_derived_key(&ecdsa_secret_key, &message_hash, &derivation_path_bytes, &chain_code);

        let public_key = ecdsa_secret_key.public_key();

        let derivation_path = DerivationPath::new(
            derivation_path_bytes
                .into_iter()
                .map(DerivationIndex)
                .collect(),
        );
        let derived_public_key_bytes = derivation_path
            .public_key_derivation(&public_key.serialize_sec1(true), &chain_code)
            .expect("couldn't derive ecdsa public key");
        let derived_public_key = PublicKey::deserialize_sec1(&derived_public_key_bytes.derived_public_key)
            .expect("couldn't deserialize sec1");
        prop_assert!(derived_public_key.verify_signature(&message_hash, &signature));
    }
}
