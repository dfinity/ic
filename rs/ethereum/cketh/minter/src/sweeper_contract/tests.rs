use crate::deposit_address::DepositAddress;
use crate::sweeper_contract::{SweepItem, encode_sweep_erc20_batch};
use crate::tx::TransactionSignature;
use candid::Principal;
use ethnum::u256;
use ic_ethereum_types::Address;
use icrc_ledger_types::icrc1::account::Account;

// Encoded independently of this crate, from the ABI specification, for the two items and two tokens
// `sweep()` builds below: selector, then the two head offsets (0x40 and 0x1e0), the inline
// `SweepItem[]` and the `address[]`.
const GOLDEN: &str = "3a7ce054\
000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001e0\
0000000000000000000000000000000000000000000000000000000000000002\
000000000000000000000000111111111111111111111111111111111111111104010203040000000000000000000000000000000000000000000000000000002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000000000000000000000000000000000000000000000000000000000001b\
000000000000000000000000222222222222222222222222222222222222222203050607000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd000000000000000000000000000000000000000000000000000000000000001c\
0000000000000000000000000000000000000000000000000000000000000002\
00000000000000000000000033333333333333333333333333333333333333330000000000000000000000004444444444444444444444444444444444444444";

#[test]
fn should_encode_a_batch_sweep() {
    let (items, tokens) = sweep();

    assert_eq!(
        hex::encode(encode_sweep_erc20_batch(&items, &tokens)),
        GOLDEN
    );
}

#[test]
fn should_place_the_tokens_right_after_the_items() {
    for count in 0..4_usize {
        let (items, tokens) = sweep();
        let items = &items[..count.min(items.len())];

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
