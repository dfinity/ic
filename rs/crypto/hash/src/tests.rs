mod crypto_hash_tests {
    use super::super::*;
    use ic_crypto_sha::{DomainSeparationContext, Sha256};
    use ic_interfaces::crypto::{CryptoHashDomain, CryptoHashableTestDummy};
    use std::hash::Hash;

    const TEST_INPUT: &[u8; 445] = b"Lorem ipsum dolor sit amet, consectetur \
        adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut \
        enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea \
        commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum \
        dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in \
        culpa qui officia deserunt mollit anim id est laborum.";

    const EXPECTED_HASH: &str = "af323a768af7ebcf6a08caee5dfefc8562316df3754238aa916870795640c963";

    #[test]
    fn should_produce_correct_crypto_hash() {
        let struct_to_hash = CryptoHashableTestDummy(TEST_INPUT.to_vec());

        let crypto_hash = crypto_hash(&struct_to_hash);

        assert_eq!(crypto_hash.get_ref().0.len(), 256 / 8);
        assert_eq!(crypto_hash.get_ref().0, hex::decode(EXPECTED_HASH).unwrap());
    }

    #[test]
    fn crypto_hash_dependent_on_domain_and_bytes_from_hash_trait() {
        let struct_to_hash = CryptoHashableTestDummy(vec![1, 2, 3]);
        let hash_trait_bytes = bytes_fed_to_hasher_when_hashing_with_hash_trait(&struct_to_hash);
        let mut hash =
            Sha256::new_with_context(&DomainSeparationContext::new(struct_to_hash.domain()));
        hash.write(&hash_trait_bytes);
        let expected_hash_incl_domain_and_bytes_from_hash_trait =
            CryptoHash(hash.finish().to_vec());

        let crypto_hash = crypto_hash(&struct_to_hash);

        assert_eq!(
            crypto_hash.get(),
            expected_hash_incl_domain_and_bytes_from_hash_trait
        );

        fn bytes_fed_to_hasher_when_hashing_with_hash_trait<T: Hash>(
            hashable_struct: &T,
        ) -> Vec<u8> {
            let mut hasher_spy = SpyHasher::new();
            hashable_struct.hash(&mut hasher_spy);
            return hasher_spy.hashed_bytes;

            struct SpyHasher {
                hashed_bytes: Vec<u8>,
            }

            impl SpyHasher {
                fn new() -> Self {
                    SpyHasher {
                        hashed_bytes: Vec::new(),
                    }
                }
            }

            impl std::hash::Hasher for SpyHasher {
                fn finish(&self) -> u64 {
                    unimplemented!()
                }

                fn write(&mut self, bytes: &[u8]) {
                    self.hashed_bytes.extend_from_slice(bytes)
                }
            }
        }
    }
}
