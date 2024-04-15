use ic_crypto_ecdsa_secp256k1::{PrivateKey, PublicKey};
use ic_crypto_extended_bip32::{DerivationIndex, DerivationPath};
use proptest::{collection::vec as pvec, prelude::*, prop_assert, proptest};

proptest! {
    #[test]
    fn test_derivation_prop(
        derivation_path_bytes in pvec(pvec(any::<u8>(), 1..10), 1..10),
        message_hash in pvec(any::<u8>(), 32),
    ) {
        const CHAIN_CODE: &[u8] = &[0; 32];
        let private_key_bytes =
            hex::decode("fb7d1f5b82336bb65b82bf4f27776da4db71c1ef632c6a7c171c0cbfa2ea4920").unwrap();

        let ecdsa_secret_key: PrivateKey =
            PrivateKey::deserialize_sec1(private_key_bytes.as_slice()).unwrap();
            let derivation_path = DerivationPath::new(
                derivation_path_bytes
                    .into_iter()
                    .map(DerivationIndex)
                    .collect(),
            );

        let signature = crate::sign_prehashed_message_with_derived_key(&ecdsa_secret_key, &message_hash, derivation_path.clone());

        let public_key = ecdsa_secret_key.public_key();

        let derived_public_key_bytes = derivation_path
            .public_key_derivation(&public_key.serialize_sec1(true), CHAIN_CODE)
            .expect("couldn't derive ecdsa public key");
        let derived_public_key = PublicKey::deserialize_sec1(&derived_public_key_bytes.derived_public_key)
            .expect("couldn't deserialize sec1");

        prop_assert!(derived_public_key.verify_signature_prehashed(&message_hash, &signature));
    }
}

#[test]
fn check_derived_signature() {
    const PUBLIC_KEY: [u8; 33] = [
        3, 127, 201, 44, 246, 255, 171, 193, 248, 139, 250, 124, 121, 72, 201, 158, 63, 60, 212,
        165, 56, 242, 52, 7, 67, 152, 180, 154, 67, 37, 77, 92, 151,
    ];
    const SIGNATURE: [u8; 64] = [
        178, 122, 242, 90, 8, 232, 120, 54, 167, 120, 172, 40, 88, 253, 252, 255, 31, 111, 58, 13,
        67, 49, 55, 130, 200, 29, 5, 202, 52, 184, 2, 113, 120, 2, 107, 57, 154, 50, 211, 215, 171,
        171, 98, 83, 136, 163, 197, 127, 101, 28, 102, 161, 130, 235, 127, 139, 26, 88, 217, 174,
        247, 84, 114, 86,
    ];
    const DIGEST: [u8; 32] = [
        101, 150, 83, 30, 137, 183, 4, 198, 179, 132, 194, 110, 159, 39, 111, 77, 90, 238, 166,
        150, 169, 24, 252, 246, 26, 57, 121, 75, 54, 74, 38, 28,
    ];
    const DERIVATION_PATH: [[u8; 10]; 1] = [[0, 0, 0, 0, 0, 0, 0, 0, 1, 1]];

    let derivation_path = DerivationPath::new(
        DERIVATION_PATH
            .to_vec()
            .iter()
            .map(|path| DerivationIndex(path.to_vec()))
            .collect::<Vec<_>>(),
    );

    let private_key_bytes =
        hex::decode("fb7d1f5b82336bb65b82bf4f27776da4db71c1ef632c6a7c171c0cbfa2ea4920").unwrap();

    let ecdsa_secret_key: PrivateKey =
        PrivateKey::deserialize_sec1(private_key_bytes.as_slice()).unwrap();

    let signature =
        crate::sign_prehashed_message_with_derived_key(&ecdsa_secret_key, &DIGEST, derivation_path);

    assert_eq!(signature, SIGNATURE);

    let derived_public_key =
        PublicKey::deserialize_sec1(&PUBLIC_KEY).expect("couldn't deserialize sec1");
    assert!(derived_public_key.verify_signature_prehashed(&DIGEST, &signature));
}

#[test]
fn public_derivation_path() {
    use ic_types::crypto::canister_threshold_sig::ExtendedDerivationPath;
    use ic_types::crypto::canister_threshold_sig::MasterPublicKey;
    use ic_types::crypto::AlgorithmId;
    use ic_types::PrincipalId;

    let private_key_bytes =
        hex::decode("fb7d1f5b82336bb65b82bf4f27776da4db71c1ef632c6a7c171c0cbfa2ea4920").unwrap();

    let ecdsa_secret_key: PrivateKey =
        PrivateKey::deserialize_sec1(private_key_bytes.as_slice()).unwrap();

    let master_public_key = MasterPublicKey {
        algorithm_id: AlgorithmId::EcdsaSecp256k1,
        public_key: ecdsa_secret_key.public_key().serialize_sec1(true),
    };

    let caller = PrincipalId::new_user_test_id(1);

    let extended_derivation_path = ExtendedDerivationPath {
        caller,
        derivation_path: vec![],
    };

    let derivation_path = DerivationPath::new(
        std::iter::once(caller.as_slice().to_vec())
            .map(DerivationIndex)
            .collect::<Vec<_>>(),
    );

    let derived_public_key_bytes = derivation_path
        .public_key_derivation(
            &ecdsa_secret_key.public_key().serialize_sec1(true),
            &[0; 32],
        )
        .expect("couldn't derive ecdsa public key");

    assert_eq!(
        ic_crypto_tecdsa::derive_threshold_public_key(
            &master_public_key,
            &extended_derivation_path
        )
        .expect("failed to derive tecdsa key")
        .public_key,
        derived_public_key_bytes.derived_public_key
    );
}
