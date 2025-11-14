use candid::Principal;
use ic_icrc1::blocks::{
    encoded_block_to_generic_block, generic_block_to_encoded_block,
    generic_transaction_from_generic_block,
};
use ic_icrc1::{Block, Transaction, hash};
use ic_icrc1_test_utils::icrc3::BlockBuilder;
use ic_icrc1_test_utils::{arb_account, arb_amount, arb_block, arb_small_amount, blocks_strategy};
use ic_icrc1_tokens_u64::U64;
use ic_icrc1_tokens_u256::U256;
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_ledger_core::Tokens;
use ic_ledger_core::block::BlockType;
use ic_ledger_core::tokens::TokensType;
use ic_ledger_hash_of::HashOf;
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

pub fn arb_fee_collector_block<Tokens>() -> impl Strategy<Value = ICRC3Value>
where
    Tokens: TokensType,
{
    (
        any::<u64>(),
        any::<u64>(),
        any::<Option<[u8; 32]>>(),
        proptest::option::of(arb_account()),
        proptest::option::of(proptest::collection::vec(any::<u8>(), 28)),
        any::<Option<u64>>(),
    )
        .prop_map(
            |(block_id, block_ts, parent_hash, fee_collector, caller, tx_ts)| {
                let caller = caller.map(|mut c| {
                    c.push(0x00);
                    Principal::try_from_slice(&c[..]).unwrap()
                });
                let builder = BlockBuilder::<Tokens>::new(block_id, block_ts)
                    .with_btype("107feecol".to_string());
                let builder = match parent_hash {
                    Some(parent_hash) => builder.with_parent_hash(parent_hash.to_vec()),
                    None => builder,
                };
                builder.fee_collector(fee_collector, caller, tx_ts).build()
            },
        )
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
