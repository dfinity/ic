mod ck_token_symbol {
    use crate::erc20::CkTokenSymbol;
    use assert_matches::assert_matches;
    use proptest::proptest;
    use std::str::FromStr;

    #[test]
    fn should_parse_supported_token() {
        for supported_token in [
            "ckETH",
            "ckUSDC",
            "ckUSDT",
            "ckSepoliaETH",
            "ckSepoliaUSDC",
            "ckSepoliaUSDT",
        ] {
            assert_eq!(
                CkTokenSymbol::from_str(supported_token),
                Ok(CkTokenSymbol(supported_token.to_string()))
            );
        }
    }

    #[test]
    fn should_error_when_symbol_invalid() {
        assert_matches!(CkTokenSymbol::from_str(""), Err(_));
        assert_matches!(CkTokenSymbol::from_str("USDC"), Err(_));
        assert_matches!(CkTokenSymbol::from_str("ckUSDC❤"), Err(_));
    }

    proptest! {
        #[test]
        fn should_error_when_symbol_too_long(symbol in ".{21,}") {
            assert_matches!(
                CkTokenSymbol::from_str(&symbol),
                Err(_)
            );
        }
    }
}
