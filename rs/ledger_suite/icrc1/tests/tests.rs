use ic_icrc1::blocks::{
    encoded_block_to_generic_block, generic_block_to_encoded_block,
    generic_transaction_from_generic_block,
};
use ic_icrc1::{Block, Transaction, hash};
use ic_icrc1_test_utils::{arb_amount, arb_block, arb_small_amount, blocks_strategy};
use ic_icrc1_tokens_u64::U64;
use ic_icrc1_tokens_u256::U256;
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_ledger_core::Tokens;
use ic_ledger_core::block::BlockType;
use ic_ledger_core::tokens::TokensType;
use ic_ledger_hash_of::HashOf;
use ic_ledger_suite_state_machine_tests::arb_fee_collector_block;
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use proptest::prelude::*;

fn arb_u256() -> impl Strategy<Value = U256> {
    (any::<u128>(), any::<u128>()).prop_map(|(hi, lo)| U256::from_words(hi, lo))
}

fn large_u128_amount() -> impl Strategy<Value = U256> {
    (u64::MAX as u128 + 1..u128::MAX).prop_map(|lo| U256::from_words(0, lo))
}

fn large_u256_amount() -> impl Strategy<Value = U256> {
    (1u128..).prop_map(|lo| U256::from_words(u128::MAX, lo))
}

fn check_block_conversion<T: TokensType>(block: Block<T>) -> Result<(), TestCaseError> {
    // for any possible block, assert that the conversion
    // block->encoded_block->generic_block->encoded_block->block
    // returns the original block
    let generic_block = encoded_block_to_generic_block(&block.clone().encode());
    let encoded_block = generic_block_to_encoded_block(generic_block.clone()).unwrap();
    prop_assert_eq!(
        &generic_block,
        &encoded_block_to_generic_block(&encoded_block)
    );
    prop_assert_eq!(&block, &Block::<T>::decode(encoded_block.clone()).unwrap());
    prop_assert_eq!(
        block.clone(),
        Block::<T>::try_from(generic_block.clone()).unwrap()
    );
    prop_assert_eq!(
        Transaction::<T>::try_from(generic_block.clone()).unwrap(),
        block.transaction.clone()
    );
    prop_assert_eq!(
        generic_block.hash().to_vec(),
        Block::<T>::block_hash(&encoded_block).as_slice().to_vec()
    );
    Ok(())
}

fn check_tx_hash<T: TokensType>(block: Block<T>) -> Result<(), TestCaseError> {
    // Convert the encoded block into bytes, to ciborium::value::Value and then to GenericBlock;
    let generic_block = encoded_block_to_generic_block(&block.clone().encode());

    //Convert generic block to generic transaction
    let generic_transaction = generic_transaction_from_generic_block(generic_block).unwrap();

    //Check that the hash of the generic transaction and the transaction object are the same
    prop_assert_eq!(
        generic_transaction.hash().to_vec(),
        <Transaction<T> as LedgerTransaction>::hash(&block.transaction)
            .as_slice()
            .to_vec()
    );

    Ok(())
}

fn check_block_hash<T: TokensType>(block: Block<T>) -> Result<(), TestCaseError> {
    // Convert the encoded block into bytes, to ciborium::value::Value and then to GenericBlock;
    let generic_block = encoded_block_to_generic_block(&block.clone().encode());

    let encoded_block_hash = hash::hash_cbor(block.encode().as_slice())
        .map(HashOf::<T>::new)
        .unwrap();
    let generic_block_hash = generic_block.hash().to_vec();

    //Check that the hash of the generic block and the encoded block are the same
    prop_assert_eq!(encoded_block_hash.as_slice(), &generic_block_hash);

    Ok(())
}

#[test_strategy::proptest]
fn test_generic_block_to_encoded_block_conversion(
    #[strategy(blocks_strategy(arb_small_amount()))] block: Block<U64>,
) {
    check_block_conversion::<U64>(block)?;
}

#[test_strategy::proptest]
fn test_generic_block_to_encoded_block_conversion_u128(
    #[strategy(blocks_strategy(large_u128_amount()))] block: Block<U256>,
) {
    check_block_conversion::<U256>(block)?;
}

#[test_strategy::proptest]
fn test_generic_block_to_encoded_block_conversion_u256(
    #[strategy(blocks_strategy(large_u256_amount()))] block: Block<U256>,
) {
    check_block_conversion::<U256>(block)?;
}

#[test_strategy::proptest]
fn test_generic_transaction_hash(
    #[strategy(blocks_strategy(arb_small_amount()))] block: Block<U64>,
) {
    check_tx_hash::<U64>(block)?;
}

#[test_strategy::proptest]
fn test_generic_transaction_hash_u256(#[strategy(blocks_strategy(arb_u256()))] block: Block<U256>) {
    check_tx_hash::<U256>(block)?;
}

#[test_strategy::proptest]
fn test_generic_block_and_encoded_block_hash_parity(
    #[strategy(blocks_strategy(arb_u256()))] block: Block<U256>,
) {
    check_block_hash::<U256>(block)?;
}

#[test_strategy::proptest]
fn test_generic_block_and_encoded_block_hash_parity_u64(
    #[strategy(blocks_strategy(arb_amount()))] block: Block<U64>,
) {
    check_block_hash::<U64>(block)?;
}

#[test_strategy::proptest]
fn test_generic_block_and_encoded_block_hash_parity_u128(
    #[strategy(blocks_strategy(large_u128_amount()))] block: Block<U256>,
) {
    check_block_hash::<U256>(block)?;
}

#[test_strategy::proptest]
fn test_generic_block_and_encoded_block_hash_parity_u256(
    #[strategy(blocks_strategy(large_u256_amount()))] block: Block<U256>,
) {
    check_block_hash::<U256>(block)?;
}

#[test_strategy::proptest]
fn test_encoding_decoding_block_u64(#[strategy(arb_block(arb_token, 32))] block: Block<Tokens>) {
    let mut bytes = vec![];
    ciborium::into_writer(&block, &mut bytes).unwrap();
    let decoded: Block<Tokens> = ciborium::from_reader(&bytes[..]).unwrap();
    prop_assert_eq!(block, decoded);
}

fn arb_token() -> impl Strategy<Value = Tokens> {
    any::<u64>().prop_map(Tokens::from_e8s)
}

#[test_strategy::proptest]
fn test_encoding_decoding_block_u256(
    #[strategy(arb_block(arb_token_u256, 32))] block: Block<U256>,
) {
    let mut bytes = vec![];
    ciborium::into_writer(&block, &mut bytes).unwrap();
    let decoded: Block<U256> = ciborium::from_reader(&bytes[..]).unwrap();
    prop_assert_eq!(block, decoded);
}

fn arb_token_u256() -> impl Strategy<Value = U256> {
    (any::<u128>(), any::<u128>()).prop_map(|(hi, lo)| U256::from_words(hi, lo))
}

#[test_strategy::proptest]
fn test_encoding_decoding_fee_collector_block_u64(
    #[strategy(arb_fee_collector_block::<U64>())] original_block: ICRC3Value,
) {
    let encoded_block = generic_block_to_encoded_block(original_block.clone().into())
        .expect("failed to decode generic block");
    let decoded_block =
        Block::<U64>::decode(encoded_block.clone()).expect("failed to decode encoded block");
    let decoded_value = encoded_block_to_generic_block(&decoded_block.clone().encode());
    prop_assert_eq!(original_block.clone().hash(), decoded_value.hash());
}

#[test_strategy::proptest]
fn test_encoding_decoding_fee_collector_block_u256(
    #[strategy(arb_fee_collector_block::<U256>())] original_block: ICRC3Value,
) {
    let encoded_block = generic_block_to_encoded_block(original_block.clone().into())
        .expect("failed to decode generic block");
    let decoded_block =
        Block::<U256>::decode(encoded_block.clone()).expect("failed to decode encoded block");
    let decoded_value = encoded_block_to_generic_block(&decoded_block.clone().encode());
    prop_assert_eq!(original_block.clone().hash(), decoded_value.hash());
}

mod block_encoding_stability {
    use ic_base_types::PrincipalId;
    use ic_icrc1::blocks::generic_block_to_encoded_block;
    use ic_icrc1_test_utils::icrc3::BlockBuilder;
    use ic_ledger_core::Tokens;
    use icrc_ledger_types::icrc::generic_value::ICRC3Value;
    use icrc_ledger_types::icrc1::account::Account;

    #[test]
    fn test_approve_block() {
        const EXPECTED_BLOCK: &str = "d9d9f7a3657068617368582022222222222222222222222222222222222222222222222222222222222222226274731a68686767627478a463616d741b00009911991199116466726f6d824a0500000000000000fe0158201717171717171717171717171717171717171717171717171717171717171717626f7067617070726f7665677370656e646572824a0600000000000000fe0158207171717171717171717171717171717171717171717171717171717171717171";

        let account1 = Account {
            owner: PrincipalId::new_user_test_id(5).0,
            subaccount: Some([0x17u8; 32]),
        };
        let account2 = Account {
            owner: PrincipalId::new_user_test_id(6).0,
            subaccount: Some([0x71u8; 32]),
        };
        let builder = BlockBuilder::<Tokens>::new(2, 0x68686767)
            .with_parent_hash(vec![0x22u8; 32])
            .approve(account1, account2, Tokens::from_e8s(0x991199119911u64));
        assert_block_encoding(builder.build(), EXPECTED_BLOCK);
    }

    #[test]
    fn test_burn_block() {
        const EXPECTED_BLOCK: &str = "d9d9f7a365706861736858201b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b6274731a58585757627478a363616d741b00004411441144116466726f6d824a0d00000000000000fe0158205151515151515151515151515151515151515151515151515151515151515151626f70646275726e";

        let account = Account {
            owner: PrincipalId::new_user_test_id(13).0,
            subaccount: Some([0x51u8; 32]),
        };
        let builder = BlockBuilder::<Tokens>::new(3, 0x58585757)
            .with_parent_hash(vec![27u8; 32])
            .burn(account, Tokens::from_e8s(0x441144114411u64));

        assert_block_encoding(builder.build(), EXPECTED_BLOCK);
    }

    #[test]
    fn test_fee_collector_block() {
        const EXPECTED_BLOCK: &str = "d9d9f7a465627479706569313037666565636f6c657068617368582043434343434343434343434343434343434343434343434343434343434343436274731a00bc614e627478a46663616c6c65724a0200000000000000fe016d6665655f636f6c6c6563746f72824a0100000000000000fe0158202525252525252525252525252525252525252525252525252525252525252525626f70743130377365745f6665655f636f6c6c6563746f726274731a0154cbf7";

        let account = Account {
            owner: PrincipalId::new_user_test_id(1).0,
            subaccount: Some([37u8; 32]),
        };
        let builder = BlockBuilder::<Tokens>::new(1, 12345678)
            .with_btype("107feecol".to_string())
            .with_parent_hash(vec![67u8; 32])
            .fee_collector(
                Some(account),
                Some(PrincipalId::new_user_test_id(2).0),
                Some(22334455u64),
                Some("107set_fee_collector".to_string()),
            );
        assert_block_encoding(builder.build(), EXPECTED_BLOCK);
    }

    #[test]
    fn test_mint_block() {
        const EXPECTED_BLOCK: &str = "d9d9f7a365706861736858202b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b6274731a041813af627478a363616d741b000000e89312b744626f70646d696e7462746f824a0100000000000000fe0158202525252525252525252525252525252525252525252525252525252525252525";

        let account = Account {
            owner: PrincipalId::new_user_test_id(1).0,
            subaccount: Some([37u8; 32]),
        };
        let builder = BlockBuilder::<Tokens>::new(2, 68686767)
            .with_parent_hash(vec![43u8; 32])
            .mint(account, Tokens::from_e8s(998899889988u64));

        assert_block_encoding(builder.build(), EXPECTED_BLOCK);
    }

    #[test]
    fn test_transfer_block() {
        const EXPECTED_BLOCK: &str = "d9d9f7a36570686173685820b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b86274731a10102020627478a463616d741a552155216466726f6d824a0700000000000000fe0158202626262626262626262626262626262626262626262626262626262626262626626f70647866657262746f824a0800000000000000fe0158203838383838383838383838383838383838383838383838383838383838383838";

        let account1 = Account {
            owner: PrincipalId::new_user_test_id(7).0,
            subaccount: Some([0x26u8; 32]),
        };
        let account2 = Account {
            owner: PrincipalId::new_user_test_id(8).0,
            subaccount: Some([0x38u8; 32]),
        };
        let builder = BlockBuilder::<Tokens>::new(7, 0x10102020)
            .with_parent_hash(vec![0xb8u8; 32])
            .transfer(account1, account2, Tokens::from_e8s(0x55215521u64));
        assert_block_encoding(builder.build(), EXPECTED_BLOCK);
    }

    #[test]
    fn test_transfer_from_block() {
        const EXPECTED_BLOCK: &str = "d9d9f7a36570686173685820a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a66274731a31313131627478a563616d741a733773376466726f6d824a0700000000000000fe0158202626262626262626262626262626262626262626262626262626262626262626626f706478666572677370656e646572824a0900000000000000fe015820474747474747474747474747474747474747474747474747474747474747474762746f824a0800000000000000fe0158203838383838383838383838383838383838383838383838383838383838383838";

        let account1 = Account {
            owner: PrincipalId::new_user_test_id(7).0,
            subaccount: Some([0x26u8; 32]),
        };
        let account2 = Account {
            owner: PrincipalId::new_user_test_id(8).0,
            subaccount: Some([0x38u8; 32]),
        };
        let account3 = Account {
            owner: PrincipalId::new_user_test_id(9).0,
            subaccount: Some([0x47u8; 32]),
        };
        let builder = BlockBuilder::<Tokens>::new(7, 0x31313131)
            .with_parent_hash(vec![0xa6u8; 32])
            .transfer(account1, account2, Tokens::from_e8s(0x73377337u64))
            .with_spender(account3);
        assert_block_encoding(builder.build(), EXPECTED_BLOCK);
    }

    #[track_caller]
    fn assert_block_encoding(block: ICRC3Value, expected: &str) {
        let encoded_block = generic_block_to_encoded_block(block.clone().into())
            .expect("failed to decode generic block");
        let block_hex_bytes = hex::encode(encoded_block.as_slice());

        assert_eq!(
            expected, block_hex_bytes,
            "mismatch for expected block encoding:\n  {}\nvs actual block encoding:\n  {}\nfor block:\n{}",
            expected, block_hex_bytes, block
        );
    }
}
