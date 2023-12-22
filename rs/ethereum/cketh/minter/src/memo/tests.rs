mod decode_memo {
    use crate::cbor::tests::check_roundtrip;
    use crate::eth_rpc::Hash;
    use crate::memo::{Address, ReceivedEthEvent};
    use crate::memo::{BurnMemo, MintMemo};
    use crate::numeric::{BlockNumber, LedgerBurnIndex, LogIndex, Wei};
    use crate::state::transactions::ReimbursementRequest;
    use candid::Principal;
    use icrc_ledger_types::icrc1::transfer::Memo;
    use proptest::array::{uniform20, uniform32};
    use proptest::prelude::*;
    use std::str::FromStr;

    fn arb_hash() -> impl Strategy<Value = Hash> {
        uniform32(any::<u8>()).prop_map(Hash)
    }

    fn arb_address() -> impl Strategy<Value = Address> {
        uniform20(any::<u8>()).prop_map(Address::new)
    }

    proptest! {
        #[test]
        fn mint_convert_memo_round_trip(
            tx_hash in arb_hash(),
            from_address in arb_address(),
            log_index in any::<u8>(),
        ) {
            check_roundtrip(&MintMemo::Convert {
                from_address,
                log_index: LogIndex::from(log_index),
                tx_hash,
            })?;
        }

        #[test]
        fn mint_reimburse_memo_round_trip(
            tx_hash in arb_hash(),
            withdrawal_id in any::<u64>(),
        ) {
            check_roundtrip(&MintMemo::Reimburse {
                withdrawal_id,
                tx_hash,
            })?;
        }

        #[test]
        fn burn_memo_round_trip(
            to_address in arb_address(),
        ) {
            check_roundtrip(&BurnMemo::Convert {
                to_address
            })?;
        }
    }

    #[test]
    fn encode_mint_convert_memo_is_stable() {
        let transaction_hash: Hash =
            "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3"
                .parse()
                .unwrap();
        let from_address: crate::address::Address = "0xdd2851cdd40ae6536831558dd46db62fac7a844d"
            .parse()
            .unwrap();
        let event = ReceivedEthEvent {
            transaction_hash,
            block_number: BlockNumber::new(3974279),
            log_index: LogIndex::from(39_u8),
            from_address,
            value: Wei::from(10_000_000_000_000_000_u128),
            principal: Principal::from_str("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap(),
        };
        let memo: Memo = event.into();

        assert_eq!(
            memo.0,
            [
                130, 0, 131, 84, 221, 40, 81, 205, 212, 10, 230, 83, 104, 49, 85, 141, 212, 109,
                182, 47, 172, 122, 132, 77, 88, 32, 112, 95, 130, 104, 97, 200, 2, 180, 7, 132, 62,
                153, 175, 152, 108, 253, 232, 116, 155, 102, 158, 94, 10, 90, 21, 15, 67, 80, 188,
                170, 155, 195, 24, 39,
            ]
        );
    }

    #[test]
    fn encode_mint_reimburse_memo_is_stable() {
        let transaction_hash: Hash =
            "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3"
                .parse()
                .unwrap();
        let reimbursment_request = ReimbursementRequest {
            withdrawal_id: LedgerBurnIndex::from(1234_u64),
            reimbursed_amount: Wei::from(100_u64),
            to: Principal::anonymous(),
            to_subaccount: None,
            transaction_hash: Some(transaction_hash),
        };
        let memo: Memo = reimbursment_request.into();

        assert_eq!(
            memo.0,
            [
                130, 1, 130, 25, 4, 210, 88, 32, 112, 95, 130, 104, 97, 200, 2, 180, 7, 132, 62,
                153, 175, 152, 108, 253, 232, 116, 155, 102, 158, 94, 10, 90, 21, 15, 67, 80, 188,
                170, 155, 195,
            ]
        );
    }

    #[test]
    fn encode_burn_memo_is_stable() {
        let memo = Memo::from(BurnMemo::Convert {
            to_address: "0xdd2851cdd40ae6536831558dd46db62fac7a844d"
                .parse()
                .unwrap(),
        });

        assert_eq!(
            memo.0,
            [
                130, 0, 129, 84, 221, 40, 81, 205, 212, 10, 230, 83, 104, 49, 85, 141, 212, 109,
                182, 47, 172, 122, 132, 77,
            ]
        );
    }
}
