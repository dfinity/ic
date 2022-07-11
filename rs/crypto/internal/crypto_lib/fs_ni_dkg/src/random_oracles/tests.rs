use super::*;
use miracl_core::bls12381::big::BIG;

struct StructToBeHashed {
    point: ECP,
    string: String,
    integer: usize,
    scalar: BIG,
    bytes: Vec<u8>,
}

impl From<&StructToBeHashed> for HashableMap {
    fn from(some_struct: &StructToBeHashed) -> Self {
        let mut map = HashableMap::new();
        map.insert("point".to_string(), Box::new(some_struct.point.to_owned()));
        map.insert(
            "string".to_string(),
            Box::new(some_struct.string.to_owned()),
        );
        map.insert(
            "integer".to_string(),
            Box::new(some_struct.integer.to_owned()),
        );
        map.insert(
            "scalar".to_string(),
            Box::new(some_struct.scalar.to_owned()),
        );
        map.insert("bytes".to_string(), Box::new(some_struct.bytes.to_owned()));
        map
    }
}

impl UniqueHash for StructToBeHashed {
    fn unique_hash(&self) -> [u8; 32] {
        let mut map = HashedMap::new();
        map.insert_hashed("point", &self.point);
        map.insert_hashed("string", &self.string);
        map.insert_hashed("integer", &self.integer);
        map.insert_hashed("scalar", &self.scalar);
        map.insert_hashed("bytes", &self.bytes);
        map.unique_hash()
    }
}

mod unique_hashing {
    use super::*;

    #[test]
    fn should_hash_strings_correctly() {
        // UniqueHash of the string "This is a string" using domain separator
        // "ic-random-oracle-string".
        const STRING_HASH_HEX: &str =
            "87f7f36651ed7a2d776576a004e1e0f172cc0680e0cb83edfec73840a2c31107";

        let string = String::from("This is a string");
        let hash = string.unique_hash();

        assert_eq!(
            hash.to_vec(),
            hex::decode(STRING_HASH_HEX).expect("It should decode")
        );
    }

    #[test]
    fn should_hash_empty_strings() {
        let string = String::from("");
        let hash = string.unique_hash();

        assert_eq!(
            hash.to_vec(),
            new_hasher_with_domain(DOMAIN_RO_STRING).finish()
        );
    }

    #[test]
    fn should_hash_integers_correctly() {
        // UniqueHash of the integer 42 using domain separator
        // "ic-random-oracle-integer".
        const INTEGER_HASH_HEX: &str =
            "f0496c68b3a9652a454e53dc157f70567e49232df7ae2b0bc95d0e28a41abe1a";

        let int = 42usize;
        let hash = int.unique_hash();

        assert_eq!(
            hash.to_vec(),
            hex::decode(INTEGER_HASH_HEX).expect("It should decode")
        );
    }

    #[test]
    fn should_hash_empty_byte_vector() {
        let bytes: Vec<u8> = Vec::new();
        let hash = bytes.unique_hash();

        assert_eq!(
            hash.to_vec(),
            new_hasher_with_domain(DOMAIN_RO_BYTE_ARRAY).finish()
        );
    }

    #[test]
    fn should_hash_byte_vectors_correctly() {
        // UniqueHash of the bytes [1u8, 2u8, 3u8, 4u8] using domain separator
        // "ic-random-oracle-byte-array".
        const BYTES_HASH_HEX: &str =
            "1dad75ea20c2f7f58939a1f905148f3554bf24c14528ff6cd0527dffbd10e431";

        let bytes = vec![1u8, 2u8, 3u8, 4u8];
        let hash = bytes.unique_hash();

        assert_eq!(
            hash.to_vec(),
            hex::decode(BYTES_HASH_HEX).expect("It should decode")
        );
    }

    #[test]
    fn should_hash_scalars_correctly() {
        // UniqueHash of the generator of the scalar 1_000_000 using domain separator
        // "ic-random-oracle-bls12381-scalar".
        const SCALAR_HASH_HEX: &str =
            "715a3ba63746ea8ff3d76fecad523406e29c3fdcf97c0cfe526199af1465f9ae";

        let point = BIG::new_int(1_000_000);
        let hash = point.unique_hash();

        assert_eq!(
            hash.to_vec(),
            hex::decode(SCALAR_HASH_HEX).expect("It should decode")
        );
    }

    #[test]
    fn should_hash_ecp_points_correctly() {
        // UniqueHash of the generator of G1 of BLS12_381 using domain separator
        // "ic-random-oracle-bls12381-g1".
        const ECP_POINT_HASH_HEX: &str =
            "39335810030283da83504357ac5ef1e53d13343cc854df984f4b451934ef0f05";

        let point = ECP::generator();
        let hash = point.unique_hash();

        assert_eq!(
            hash.to_vec(),
            hex::decode(ECP_POINT_HASH_HEX).expect("It should decode")
        );
    }

    #[test]
    fn should_hash_ecp2_points_correctly() {
        // UniqueHash of the generator of G2 of BLS12_381 using domain separator
        // "ic-random-oracle-bls12381-g2".
        const ECP2_POINT_HASH_HEX: &str =
            "9f0811beced7640b5dc6b4c08676bb4897b2d6171bf13b4738ab14a252c66057";

        let point = ECP2::generator();
        let hash = point.unique_hash();

        assert_eq!(
            hash.to_vec(),
            hex::decode(ECP2_POINT_HASH_HEX).expect("It should decode")
        );
    }

    #[test]
    fn should_hash_empty_vectors() {
        let point: Vec<ECP> = Vec::new();
        let hash = point.unique_hash();

        assert_eq!(
            hash.to_vec(),
            new_hasher_with_domain(DOMAIN_RO_VECTOR).finish()
        );
    }

    #[test]
    fn should_hash_vectors_of_points() {
        let point = ECP::generator();
        let other_point = ECP::generator().mul(&BIG::new_int(42));

        let vec = vec![point, other_point];
        let _hash = vec.unique_hash();
    }

    #[test]
    fn should_hash_vectors_of_vectors_of_points() {
        let point = ECP::generator();
        let other_point = ECP::generator();

        let vec_in = vec![point, other_point];
        let vec_out = vec![vec_in; 3];

        let _hash = vec_out.unique_hash();
    }

    #[test]
    fn should_hash_vectors_of_hashable_structs() {
        let string = String::from("This is a string");
        let point1 = ECP::generator().mul(&BIG::new_int(17));
        let point2 = ECP::generator().mul(&BIG::new_int(13));
        let hashable_struct = StructToBeHashed {
            point: ECP::generator(),
            string: "some string".to_string(),
            integer: 4usize,
            scalar: BIG::new_int(36),
            bytes: vec![1, 2, 3, 4],
        };
        let vec_in = vec![point1, point2];
        let mut vec_out: Vec<&dyn UniqueHash> = Vec::new();
        let hashed_map = hashable_struct.unique_hash().to_vec();
        let hashable_map = HashableMap::from(&hashable_struct);
        vec_out.push(&vec_in);
        vec_out.push(&string);
        vec_out.push(&hashed_map);
        vec_out.push(&hashable_map);
        let _hash = vec_out.unique_hash();
    }

    #[test]
    fn should_hash_structs_with_domain() {
        let hashable_struct = StructToBeHashed {
            point: ECP::generator(),
            string: "some string".to_string(),
            integer: 4usize,
            scalar: BIG::new_int(36),
            bytes: vec![1, 2, 3, 4],
        };

        let hash = hashable_struct.unique_hash();

        let mut map = HashableMap::new();
        map.insert("point".to_string(), Box::new(hashable_struct.point));
        map.insert("string".to_string(), Box::new(hashable_struct.string));
        map.insert("integer".to_string(), Box::new(hashable_struct.integer));
        map.insert("scalar".to_string(), Box::new(hashable_struct.scalar));
        map.insert("bytes".to_string(), Box::new(hashable_struct.bytes));

        assert_eq!(hash, map.unique_hash());
    }
}

mod random_oracles {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_hash_to_g1_against_draft_vectors() {
        let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

        assert_eq!(
            hex::encode(miracl_g1_to_bytes(&hash_to_miracl_ecp(&dst[..], b""))),
            "852926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1"
        );

        assert_eq!(
            hex::encode(miracl_g1_to_bytes(&hash_to_miracl_ecp(&dst[..], b"abc"))),
            "83567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903"
        );

        assert_eq!(
            hex::encode(miracl_g1_to_bytes(&hash_to_miracl_ecp(&dst[..], b"abcdef0123456789"))),
            "91e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
        );

        assert_eq!(
            hex::encode(miracl_g1_to_bytes(&hash_to_miracl_ecp(&dst[..], format!("q128_{}", "q".repeat(128)).as_bytes()))),
            "b5f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac488",
        );

        assert_eq!(
            hex::encode(miracl_g1_to_bytes(&hash_to_miracl_ecp(&dst[..], format!("a512_{}", "a".repeat(512)).as_bytes()))),
            "882aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe",
        );
    }

    proptest! {
        #[test]
        fn should_return_distinct_hashes_on_different_domains(domain_1: String, domain_2: String) {
            prop_assume!(domain_1.len()<100);
            prop_assume!(domain_2.len()<100);
            prop_assume!(domain_1!=domain_2);

            let hashable_struct = StructToBeHashed {
                point: ECP::generator(),
                string: "some string".to_string(),
                integer: 4usize,
                scalar: BIG::new_int(36),
                bytes: vec![1, 2, 3, 4],
            };
            let hash_1 = random_oracle(&domain_1, &hashable_struct);
            let hash_2 = random_oracle(&domain_2, &hashable_struct);
            assert_ne!(hash_1, hash_2);
        }

        #[test]
        fn should_return_distinct_scalars_on_different_domains(domain_1: String, domain_2: String) {
            prop_assume!(domain_1.len()<100);
            prop_assume!(domain_2.len()<100);
            prop_assume!(domain_1!=domain_2);

            let hashable_struct = StructToBeHashed {
                point: ECP::generator(),
                string: "some string".to_string(),
                integer: 4usize,
                scalar: BIG::new_int(36),
                bytes: vec![1, 2, 3, 4],
            };
            let hash_1 = random_oracle_to_scalar(&domain_1, &hashable_struct);
            let hash_2 = random_oracle_to_scalar(&domain_2, &hashable_struct);
            let result = BIG::comp(&hash_1, &hash_2);
            assert_ne!(result, 0);
        }

        #[test]
        fn should_return_distinct_ecp_points_on_different_domains(domain_1: String, domain_2: String) {
            prop_assume!(domain_1.len()<100);
            prop_assume!(domain_2.len()<100);
            prop_assume!(domain_1!=domain_2);

            let hashable_struct = StructToBeHashed {
                point: ECP::generator(),
                string: "some string".to_string(),
                integer: 4usize,
                scalar: BIG::new_int(36),
                bytes: vec![1, 2, 3, 4],
            };
            let hash_1 = random_oracle_to_miracl_ecp(&domain_1, &hashable_struct);
            let hash_2 = random_oracle_to_miracl_ecp(&domain_2, &hashable_struct);
            assert!(!hash_1.equals(&hash_2));
        }
    }
}
