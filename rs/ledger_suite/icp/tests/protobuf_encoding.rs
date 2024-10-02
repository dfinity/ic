use dfn_protobuf::ToProto;
use ic_ledger_hash_of::HashOf;
use icp_ledger::{AccountIdentifier, Block, Memo, Operation, TimeStamp, Tokens, Transaction};
use proptest::array::{uniform28, uniform32};
use proptest::collection::vec as pvec;
use proptest::prelude::*;
use serde_bytes::ByteBuf;

prop_compose! {
    fn arb_tokens()(amount in any::<u64>()) -> Tokens {
        Tokens::from_e8s(amount)
    }
}

prop_compose! {
    fn arb_ts()(ts in any::<u64>()) -> TimeStamp {
        TimeStamp::from_nanos_since_unix_epoch(ts)
    }
}

prop_compose! {
    fn arb_account_id()(
        hash in uniform28(any::<u8>())
    ) -> AccountIdentifier {
        AccountIdentifier { hash }
    }
}

prop_compose! {
    fn arb_mint()(
        to in arb_account_id(),
        amount in arb_tokens(),
    ) -> Operation {
        Operation::Mint { to, amount }
    }
}

prop_compose! {
    fn arb_burn()(
        from in arb_account_id(),
        amount in arb_tokens(),
    ) -> Operation {
        Operation::Burn { from, amount, spender: None }
    }
}

prop_compose! {
    fn arb_transfer()(
        from in arb_account_id(),
        to in arb_account_id(),
        amount in arb_tokens(),
        fee in 0..100_000u64,
    ) -> Operation {
        Operation::Transfer {
            from, to, amount, spender: None, fee: Tokens::from_e8s(fee)
        }
    }
}

prop_compose! {
    fn arb_approve()(
        from in arb_account_id(),
        spender in arb_account_id(),
        allowance in arb_tokens(),
        expires_at in proptest::option::of(arb_ts()),
        fee in 0..100_000u64,
        expected_allowance in arb_tokens(),
    ) -> Operation {
        Operation::Approve {
            from,
            spender,
            allowance,
            expected_allowance: Some(expected_allowance),
            expires_at,
            fee: Tokens::from_e8s(fee)
        }
    }
}

prop_compose! {
    fn arb_transfer_from()(
        from in arb_account_id(),
        to in arb_account_id(),
        spender in arb_account_id(),
        amount in arb_tokens(),
        fee in 0..100_000u64,
    ) -> Operation {
        Operation::Transfer {
            from, to, spender: Some(spender), amount, fee: Tokens::from_e8s(fee)
        }
    }
}

fn arb_op() -> BoxedStrategy<Operation> {
    prop_oneof![
        arb_mint(),
        arb_burn(),
        arb_transfer(),
        arb_approve(),
        arb_transfer_from(),
    ]
    .boxed()
}

prop_compose! {
    fn arb_tx()(
        operation in arb_op(),
        memo in any::<u64>(),
        created_at_time in proptest::option::of(arb_ts()),
        icrc1_memo in proptest::option::of(pvec(any::<u8>(), 0..=32)),
    ) -> Transaction {
        Transaction {
            operation,
            memo: Memo(memo),
            created_at_time,
            icrc1_memo: icrc1_memo.map(ByteBuf::from),
        }
    }
}

prop_compose! {
    fn arb_block()(
        phash in proptest::option::of(uniform32(any::<u8>())),
        transaction in arb_tx(),
        timestamp in arb_ts(),
    ) -> Block {
        Block {
            parent_hash: phash.map(HashOf::new),
            transaction,
            timestamp,
        }
    }
}

proptest! {
    #[test]
    fn test_proto_roundtrip(b in arb_block()) {
        let original = b.clone();
        let proto = b.into_proto();
        prop_assert_eq!(Block::from_proto(proto).unwrap(), original);
    }
}
