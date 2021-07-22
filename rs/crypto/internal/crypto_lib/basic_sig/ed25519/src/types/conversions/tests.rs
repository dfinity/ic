mod secretkeybytes {
    use crate::api::keypair_from_rng;
    use crate::types::SecretKeyBytes;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use std::time::SystemTime;

    #[test]
    fn should_deserialize_from_backwards_compat() {
        // This was generated from a version of this codebase
        // from *before* the change to use SecretArray.
        // This test is to ensure the previous keys still deserialize correctly.
        let old = vec![
            88, 32, 120, 72, 181, 215, 17, 188, 152, 131, 153, 99, 23, 163, 249, 201, 2, 105, 213,
            103, 113, 0, 93, 84, 10, 25, 24, 73, 57, 201, 232, 208, 219, 42,
        ];
        let maybe_new_sk = serde_cbor::from_slice::<SecretKeyBytes>(&old);
        assert!(maybe_new_sk.is_ok());
    }

    #[test]
    fn should_deserialize_from_serialized() {
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("failed to convert current time to Unix");
        let mut csprng = ChaCha20Rng::seed_from_u64(seed.as_secs());

        let (sk, _pk) = keypair_from_rng(&mut csprng);

        let serialized = serde_cbor::to_vec(&sk).expect("failed to serialize SecretKeyBytes");
        println!("Serialized: {:?}", serialized);

        let deserialized = serde_cbor::from_slice::<SecretKeyBytes>(&serialized)
            .expect("failed to deserialize SecretKeyBytes");

        assert_eq!(sk, deserialized);
    }
}
