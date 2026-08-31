use crate::deposit_address::DepositAddress;
use crate::eth_logs::encode_principal;
use crate::sweeper_contract::{SweepItem, encode_sweep_erc20_batch};
use crate::tx::TransactionSignature;
use candid::Principal;
use ethnum::u256;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;

const SIGNATURE: &str =
    "sweepErc20Batch((address,bytes32,bytes32,bytes32,bytes32,uint8)[],address[])";

#[test]
fn should_call_the_function_the_delegate_exposes() {
    let (items, tokens) = sweep();

    let data = encode_sweep_erc20_batch(&items, &tokens);

    assert_eq!(
        &data[..4],
        &ic_sha3::Keccak256::hash(SIGNATURE.as_bytes())[..4]
    );
}

#[test]
fn should_encode_a_batch_sweep() {
    use ethers_core::abi::{Token, encode};

    let (items, tokens) = sweep();

    let data = encode_sweep_erc20_batch(&items, &tokens);

    let expected_arguments = encode(&[
        Token::Array(
            items
                .iter()
                .map(|item| {
                    Token::Tuple(vec![
                        Token::Address(item.deposit.as_address().into_bytes().into()),
                        Token::FixedBytes(encode_principal(&item.account.owner).to_vec()),
                        Token::FixedBytes(item.account.effective_subaccount().to_vec()),
                        Token::FixedBytes(item.attestation.r.to_be_bytes().to_vec()),
                        Token::FixedBytes(item.attestation.s.to_be_bytes().to_vec()),
                        Token::Uint((27 + u8::from(item.attestation.signature_y_parity)).into()),
                    ])
                })
                .collect(),
        ),
        Token::Array(
            tokens
                .iter()
                .map(|token| Token::Address(token.into_bytes().into()))
                .collect(),
        ),
    ]);

    assert_eq!(&data[4..], expected_arguments.as_slice());
}

#[test]
fn should_place_the_tokens_right_after_the_items() {
    let (items, tokens) = sweep();
    for count in 0..=items.len() {
        let items = &items[..count];

        let data = encode_sweep_erc20_batch(items, &tokens);

        assert_eq!(head_word(&data, 0), 64);
        let tokens_offset = head_word(&data, 1);
        assert_eq!(tokens_offset, 64 + 32 + items.len() * 6 * 32);
        assert_eq!(
            &data[4 + tokens_offset..4 + tokens_offset + 32],
            &word(tokens.len())
        );
        assert_eq!(
            data.len(),
            4 + 64 + 32 + items.len() * 6 * 32 + 32 + tokens.len() * 32
        );
    }
}

#[test]
fn should_encode_an_empty_batch() {
    let data = encode_sweep_erc20_batch(&[], &[]);

    assert_eq!(data.len(), 4 + 64 + 32 + 32);
    assert_eq!(&data[4 + 64..4 + 96], &word(0));
    assert_eq!(&data[4 + 96..], &word(0));
}

fn sweep() -> (Vec<SweepItem>, Vec<Address>) {
    (
        vec![
            SweepItem {
                deposit: DepositAddress::new(Address::new([0x11; 20])),
                account: Account {
                    owner: Principal::from_slice(&[1, 2, 3, 4]),
                    subaccount: Some([42; 32]),
                },
                attestation: TransactionSignature {
                    r: u256::from_be_bytes([0xaa; 32]),
                    s: u256::from_be_bytes([0xbb; 32]),
                    signature_y_parity: false,
                },
            },
            SweepItem {
                deposit: DepositAddress::new(Address::new([0x22; 20])),
                account: Account {
                    owner: Principal::from_slice(&[5, 6, 7]),
                    subaccount: None,
                },
                attestation: TransactionSignature {
                    r: u256::from_be_bytes([0xcc; 32]),
                    s: u256::from_be_bytes([0xdd; 32]),
                    signature_y_parity: true,
                },
            },
        ],
        vec![Address::new([0x33; 20]), Address::new([0x44; 20])],
    )
}

/// The `index`-th 32-byte word of the ABI head, i.e. right after the selector.
fn head_word(data: &[u8], index: usize) -> usize {
    let word = <[u8; 32]>::try_from(&data[4 + index * 32..4 + (index + 1) * 32]).unwrap();
    let (high, low) = word.split_at(24);
    assert!(high.iter().all(|byte| *byte == 0), "offset out of range");
    usize::try_from(u64::from_be_bytes(<[u8; 8]>::try_from(low).unwrap())).unwrap()
}

fn word(value: usize) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[32 - size_of::<usize>()..].copy_from_slice(&value.to_be_bytes());
    bytes
}
