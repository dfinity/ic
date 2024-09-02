use ic_crypto_secp256k1::{DerivationIndex, DerivationPath, PrivateKey, PublicKey};
use proptest::{collection::vec as pvec, prelude::*, prop_assert, proptest};

proptest! {
    #[test]
    fn test_derivation_prop(
        derivation_path_bytes in pvec(pvec(any::<u8>(), 1..10), 1..10),
        message_hash in pvec(any::<u8>(), 32),
    ) {
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

        let derived_secret_key = ecdsa_secret_key.derive_subkey(&derivation_path).0;
        let signature = derived_secret_key.sign_message_with_ecdsa(&message_hash);

        let derived_public_key = derived_secret_key.public_key();
        prop_assert!(derived_public_key.verify_ecdsa_signature(&message_hash, &signature));
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

    let derived_key = ecdsa_secret_key.derive_subkey(&derivation_path).0;

    let signature = derived_key.sign_digest_with_ecdsa(&DIGEST);
    assert_eq!(signature, SIGNATURE);

    let derived_public_key =
        PublicKey::deserialize_sec1(&PUBLIC_KEY).expect("couldn't deserialize sec1");
    assert!(derived_public_key.verify_signature_prehashed(&DIGEST, &signature));
}

#[test]
fn public_derivation_path() {
    use ic_types::PrincipalId;

    let private_key_bytes =
        hex::decode("fb7d1f5b82336bb65b82bf4f27776da4db71c1ef632c6a7c171c0cbfa2ea4920").unwrap();

    let ecdsa_secret_key: PrivateKey =
        PrivateKey::deserialize_sec1(private_key_bytes.as_slice()).unwrap();

    let caller = PrincipalId::new_user_test_id(1);

    let path = DerivationPath::from_canister_id_and_path(caller.as_slice(), &[]);

    let derived_key = ecdsa_secret_key
        .public_key()
        .derive_subkey(&path)
        .0
        .serialize_sec1(true);

    assert_eq!(
        hex::encode(&derived_key),
        "03fda02786d72d691d807a10a3de60522b664472ec2f06a704cc34ebe2fc26724c"
    );
}
