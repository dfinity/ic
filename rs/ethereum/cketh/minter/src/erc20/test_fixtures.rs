use crate::erc20::CkTokenSymbol;
use proptest::prelude::Strategy;
use std::str::FromStr;

pub fn arb_ck_token_symbol() -> impl Strategy<Value = CkTokenSymbol> {
    "ck[0-9A-Za-z_]{0,18}".prop_map(|token_symbol| CkTokenSymbol::from_str(&token_symbol).unwrap())
}
