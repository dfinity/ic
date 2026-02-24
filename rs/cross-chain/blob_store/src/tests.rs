mod hash {
    use crate::Hash;

    const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn should_parse_hash_from_hex_string_with_or_without_prefix() {
        let hash: Hash = HELLO_SHA256.parse().unwrap();
        assert_eq!(hash, Hash::sha256(b"hello"));

        let prefixed = format!("0x{HELLO_SHA256}");
        let parsed_prefixed: Hash = prefixed.parse().unwrap();
        assert_eq!(parsed_prefixed, hash);
    }

    #[test]
    fn hash_display_roundtrips() {
        let hash = Hash::sha256(b"hello");
        let reparsed: Hash = hash.to_string().parse().unwrap();
        assert_eq!(hash, reparsed);
    }

    #[test]
    fn should_not_parse() {
        assert!("not-valid-hex".parse::<Hash>().is_err());
        // too short
        assert!("2cf24dba5fb0".parse::<Hash>().is_err());
        // too long
        assert!(format!("aa{HELLO_SHA256}").parse::<Hash>().is_err());
    }
}
