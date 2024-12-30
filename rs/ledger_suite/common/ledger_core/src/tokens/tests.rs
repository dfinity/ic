use crate::tokens::Tokens;
use ic_stable_structures::Storable;
use proptest::prelude::{any, prop_assert_eq, proptest};

#[test]
fn tokens_serialization() {
    proptest!(|(e8s in any::<u64>())| {
        let tokens = Tokens { e8s };
        let new_tokens = Tokens::from_bytes(tokens.to_bytes());
        prop_assert_eq!(new_tokens, tokens);
    })
}
