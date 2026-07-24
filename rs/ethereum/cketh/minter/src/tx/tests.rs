use crate::tx::{GasFeeEstimate, TransactionPrice};
use proptest::strategy::Strategy;

mod estimate_transaction_price {
    use crate::numeric::WeiPerGas;
    use crate::tx::{GasFeeEstimate, TransactionFeeEstimationError, estimate_transaction_fee};
    use assert_matches::assert_matches;
    use evm_rpc_types::{FeeHistory, Nat256};
    use proptest::collection::vec;
    use proptest::prelude::any;
    use proptest::{prop_assert_eq, proptest};
    use std::cmp::max;

    proptest! {
        #[test]
        fn should_estimate_transaction_price(
            base_fee_per_gas in vec(any::<u64>(), 6),
            reward in vec(any::<u64>(), 5)
        ) {
            let expected_base_fee_per_gas = base_fee_per_gas[5];
            let expected_max_priority_fee_per_gas = {
                let mut sorted_reward = reward.clone();
                sorted_reward.sort();
                let median = sorted_reward[2];
                max(median, 1_500_000_000_u64)
            };
            let fee_history = fee_history(base_fee_per_gas, reward);

            let result = estimate_transaction_fee(&fee_history);

            prop_assert_eq!(
                result,
                Ok(GasFeeEstimate {
                    base_fee_per_gas: WeiPerGas::from(expected_base_fee_per_gas),
                    max_priority_fee_per_gas: WeiPerGas::from(expected_max_priority_fee_per_gas),
                })
            )
        }
    }

    #[test]
    fn should_fail_when_base_fee_per_gas_overflows() {
        let fee_history = fee_history(
            vec![
                WeiPerGas::ZERO,
                WeiPerGas::ZERO,
                WeiPerGas::ZERO,
                WeiPerGas::ZERO,
                WeiPerGas::ZERO,
                WeiPerGas::MAX,
            ],
            vec![0_u8, 0, 0, 0, 0],
        );

        let result = estimate_transaction_fee(&fee_history);

        assert_matches!(result, Err(TransactionFeeEstimationError::Overflow(_)));
    }

    #[test]
    fn should_fail_when_max_priority_fee_per_gas_overflows() {
        let fee_history = fee_history(vec![0_u8, 0, 0, 0, 0, 1], [WeiPerGas::MAX; 5].to_vec());
        let result = estimate_transaction_fee(&fee_history);
        assert_matches!(result, Err(TransactionFeeEstimationError::Overflow(_)));
    }

    fn fee_history<U: Into<Nat256>, V: Into<Nat256>>(
        base_fee_per_gas: Vec<U>,
        reward: Vec<V>,
    ) -> FeeHistory {
        assert_eq!(
            base_fee_per_gas.len(),
            reward.len() + 1,
            "base_fee_per_gas must contain a value for the next block"
        );
        let default_gas_used_ratio = vec![1.; reward.len()];
        FeeHistory {
            oldest_block: 0x10f73fc_u32.into(),
            base_fee_per_gas: base_fee_per_gas.into_iter().map(|x| x.into()).collect(),
            gas_used_ratio: default_gas_used_ratio,
            reward: reward.into_iter().map(|x| vec![x.into()]).collect(),
        }
    }
}

mod resubmit_transaction_price {
    use crate::numeric::WeiPerGas;
    use crate::tx::GasFeeEstimate;
    use crate::tx::tests::{arb_gas_fee_estimate, arb_transaction_price};
    use proptest::{prop_assert, prop_assert_eq, proptest};

    proptest! {
        #[test]
        fn should_be_the_same_when_base_fee_per_gas_covered(initial_price in arb_transaction_price()) {
            let max_base_fee_per_gas = initial_price
                .max_fee_per_gas
                .checked_sub(initial_price.max_priority_fee_per_gas)
                .expect("BUG: max fee per gas should be greater or equal than max priority fee per gas");
            let mut base_fee_per_gas = max_base_fee_per_gas;
            while base_fee_per_gas > WeiPerGas::ZERO {
                let new_gas_fee = GasFeeEstimate {
                    base_fee_per_gas,
                    max_priority_fee_per_gas: initial_price.max_priority_fee_per_gas,
                };

                let updated_price = initial_price
                    .clone()
                    .resubmit_transaction_price(new_gas_fee);

                prop_assert_eq!(&updated_price, &initial_price);

                base_fee_per_gas = base_fee_per_gas.div_by_two();
            }
        }
    }

    proptest! {
        #[test]
        fn should_increase_by_at_least_10_percent_when_base_fee_not_covered(initial_price in arb_transaction_price()) {
            let max_base_fee_per_gas = initial_price
                .max_fee_per_gas
                .checked_sub(initial_price.max_priority_fee_per_gas)
                .expect(
                    "BUG: max fee per gas should be greater or equal than max priority fee per gas",
                );
            let mut base_fee_per_gas = max_base_fee_per_gas
                .checked_add(WeiPerGas::ONE)
                .unwrap_or(WeiPerGas::MAX);
            while base_fee_per_gas < WeiPerGas::MAX {
                let new_gas_fee = GasFeeEstimate {
                    base_fee_per_gas,
                    max_priority_fee_per_gas: initial_price.max_priority_fee_per_gas,
                };

                let updated_price = initial_price
                    .clone()
                    .resubmit_transaction_price(new_gas_fee);
                let max_priority_fee_per_gas_diff = updated_price.max_priority_fee_per_gas.checked_sub(initial_price.max_priority_fee_per_gas).expect("updated max priority fee per gas should be greater than original");

                prop_assert_eq!(updated_price.gas_limit, initial_price.gas_limit);
                prop_assert!(updated_price.max_fee_per_gas >= initial_price.max_fee_per_gas);
                prop_assert_eq!(max_priority_fee_per_gas_diff, initial_price.max_priority_fee_per_gas.checked_div_ceil(10_u8).unwrap());

                base_fee_per_gas = base_fee_per_gas.checked_mul(2_u8).unwrap_or(WeiPerGas::MAX);
            }
        }
    }

    proptest! {
        #[test]
        fn should_always_increase_or_be_the_same(initial_price in arb_transaction_price(), new_gas_fee in arb_gas_fee_estimate()) {
            let updated_price = initial_price
                .clone()
                .resubmit_transaction_price(new_gas_fee);

            prop_assert_eq!(updated_price.gas_limit, initial_price.gas_limit);
            prop_assert!(updated_price.max_fee_per_gas >= initial_price.max_fee_per_gas);
            prop_assert!(updated_price.max_priority_fee_per_gas >= initial_price.max_priority_fee_per_gas);
        }
    }
}

#[test]
fn should_cbor_encoding_be_stable() {
    use crate::numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas};
    use crate::tx::{
        AccessList, Eip1559TransactionRequest, SignedEip1559TransactionRequest,
        TransactionSignature,
    };
    use ethnum::u256;
    use ic_ethereum_types::Address;
    use std::str::FromStr;

    // see https://sepolia.etherscan.io/getRawTx?tx=0x66a9a218ea720ac6d2c9e56f7e44836c1541c186b7627bda220857ce34e2df7f
    let signature = TransactionSignature {
        signature_y_parity: true,
        r: u256::from_str_hex("0x7d097b81dc8bf5ad313f8d6656146d4723d0e6bb3fb35f1a709e6a3d4426c0f3")
            .unwrap(),
        s: u256::from_str_hex("0x4f8a618d959e7d96e19156f0f5f2ed321b34e2004a0c8fdb7f02bc7d08b74441")
            .unwrap(),
    };
    let transaction = Eip1559TransactionRequest {
        chain_id: 11155111,
        nonce: TransactionNonce::from(6_u8),
        max_priority_fee_per_gas: WeiPerGas::new(0x59682f00),
        max_fee_per_gas: WeiPerGas::new(0x598653cd),
        gas_limit: GasAmount::new(56_511),
        destination: Address::from_str("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34").unwrap(),
        amount: Wei::new(1_000_000_000_000_000),
        data: hex::decode(
            "b214faa51d882d15b09f8e81e29606305f5fefc5eff3e2309620a3557ecae39d62020000",
        )
        .unwrap(),
        access_list: AccessList::new(),
    };
    let signed_tx = SignedEip1559TransactionRequest::from((transaction, signature));
    let mut encoded_signed_tx: Vec<u8> = Vec::new();

    minicbor::encode(&signed_tx, &mut encoded_signed_tx).unwrap();

    assert_eq!(
        encoded_signed_tx,
        [
            130, 137, 26, 0, 170, 54, 167, 6, 26, 89, 104, 47, 0, 26, 89, 134, 83, 205, 25, 220,
            191, 84, 180, 75, 94, 117, 106, 137, 71, 117, 252, 50, 237, 223, 51, 20, 187, 27, 25,
            68, 220, 52, 27, 0, 3, 141, 126, 164, 198, 128, 0, 88, 36, 178, 20, 250, 165, 29, 136,
            45, 21, 176, 159, 142, 129, 226, 150, 6, 48, 95, 95, 239, 197, 239, 243, 226, 48, 150,
            32, 163, 85, 126, 202, 227, 157, 98, 2, 0, 0, 128, 131, 245, 194, 88, 32, 125, 9, 123,
            129, 220, 139, 245, 173, 49, 63, 141, 102, 86, 20, 109, 71, 35, 208, 230, 187, 63, 179,
            95, 26, 112, 158, 106, 61, 68, 38, 192, 243, 194, 88, 32, 79, 138, 97, 141, 149, 158,
            125, 150, 225, 145, 86, 240, 245, 242, 237, 50, 27, 52, 226, 0, 74, 12, 143, 219, 127,
            2, 188, 125, 8, 183, 68, 65
        ]
    );

    let decoded_signed_tx: SignedEip1559TransactionRequest =
        minicbor::decode(&encoded_signed_tx).unwrap();

    assert_eq!(decoded_signed_tx, signed_tx);
}

mod eip7702 {
    use crate::numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas};
    use crate::tx::{
        AccessList, Authorization, Eip7702TransactionRequest, SignedAuthorization,
        SignedEip7702TransactionRequest, TransactionSignature,
    };
    use ethnum::u256;
    use ic_ethereum_types::Address;
    use std::str::FromStr;

    // Published test vector from the trust-wallet/wallet-core EIP-7702 test suite:
    // https://github.com/trustwallet/wallet-core/blob/83823464a621115cf7c06c86079a2597fe46e55b/rust/tw_evm/src/transaction/transaction_eip7702.rs
    #[test]
    fn should_encode_type_0x04_transaction() {
        assert_eq!(
            sample_signed_transaction().raw_transaction_hex_string(),
            "0x04f8c0380102030494010101010101010101010101010101010101010105821234c0f85cf85a069402020202020202020202020202020202020202020280a042556c4f2a3f4e4e639cca524d1da70e60881417d4643e5382ed110a52719eafa0172f591a2a763d0bd6b13d042d8c5eb66e87f129c9dc77ada66b6041012db2b380a0d93fc9ae934d4f72db91cb149e7e84b50ca83b5a8a7b873b0fdb009546e3af47a0786bfaf31af61eea6471dbb1bec7d94f73fb90887e4f04d0e9b85676c47ab02a"
        );
    }

    // Published test vector from the alloy-rs EIP-7702 test suite:
    // https://github.com/alloy-rs/alloy/blob/main/crates/eips/src/eip7702.rs (alloy-eip7702 auth_list.rs)
    #[test]
    fn should_encode_signed_authorization_tuple() {
        use rlp::Encodable;

        let authorization = SignedAuthorization {
            chain_id: 1,
            delegate: Address::from_str("0x0000000000000000000000000000000000000006").unwrap(),
            nonce: TransactionNonce::from(1_u8),
            y_parity: false,
            r: u256::from_str_hex(
                "0x48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353",
            )
            .unwrap(),
            s: u256::from_str_hex(
                "0xefffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804",
            )
            .unwrap(),
        };

        assert_eq!(
            hex::encode(authorization.rlp_bytes()),
            "f85a019400000000000000000000000000000000000000060180a048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804"
        );
    }

    // The signature hash of an authorization is keccak256(0x05 || rlp([chain_id, delegate, nonce])).
    // Expected values are cross-checked against an independent RLP + Keccak256 reference that
    // reproduces the published alloy-rs and trust-wallet authorization tuples above.
    #[test]
    fn should_compute_authorization_signature_hash() {
        let alloy = Authorization {
            chain_id: 1,
            delegate: Address::from_str("0x0000000000000000000000000000000000000006").unwrap(),
            nonce: TransactionNonce::from(1_u8),
        };
        assert_eq!(
            hex::encode(alloy.hash().0),
            "16559694155c9c6e69d5c2c665f9118beae5baaded2f2466926f4900a36b12de"
        );

        let trust_wallet = Authorization {
            chain_id: 6,
            delegate: Address::from_str("0x0202020202020202020202020202020202020202").unwrap(),
            nonce: TransactionNonce::from(2_u8),
        };
        assert_eq!(
            hex::encode(trust_wallet.hash().0),
            "92e45641ec1a2c72deca9dbbf759fe6831b9edd8a500f530bc1039a9e5d78a3c"
        );
    }

    // Round-trip: sign the authorization signature hash with a known key, determine the recovery
    // id (y_parity) with the same recovery machinery used for EIP-1559 signatures, then recover the
    // authority address from the resulting `[y_parity, r, s]` and check it matches the signer.
    // The key pair is the published EIP-155 example key:
    // private key 0x4646...46 -> address 0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F.
    #[test]
    fn should_recover_authority_from_signed_authorization() {
        use crate::address::ecdsa_public_key_to_address;
        use ethers_core::types::{
            H256, RecoveryMessage, Signature as EthSignature, U256 as EthU256,
        };
        use ic_secp256k1::PrivateKey;

        let private_key = PrivateKey::deserialize_sec1(&[0x46_u8; 32]).unwrap();
        let public_key = private_key.public_key();
        let authority = ecdsa_public_key_to_address(&public_key);
        assert_eq!(
            authority,
            Address::from_str("0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F").unwrap()
        );

        let authorization = Authorization {
            chain_id: 1,
            delegate: Address::from_str("0x0000000000000000000000000000000000000006").unwrap(),
            nonce: TransactionNonce::from(1_u8),
        };
        let hash = authorization.hash();
        let signature = private_key.sign_digest_with_ecdsa(&hash.0);
        let recovery_id = public_key
            .try_recovery_from_digest(&hash.0, &signature)
            .unwrap();
        assert!(!recovery_id.is_x_reduced());

        let (r_bytes, s_bytes) = super::super::split_in_two(signature);
        let tuple = SignedAuthorization {
            chain_id: authorization.chain_id,
            delegate: authorization.delegate,
            nonce: authorization.nonce,
            y_parity: recovery_id.is_y_odd(),
            r: u256::from_be_bytes(r_bytes),
            s: u256::from_be_bytes(s_bytes),
        };

        let recovered = EthSignature {
            r: EthU256::from_big_endian(&r_bytes),
            s: EthU256::from_big_endian(&s_bytes),
            v: 27 + tuple.y_parity as u64,
        }
        .recover(RecoveryMessage::Hash(H256(hash.0)))
        .unwrap();

        assert_eq!(recovered.as_bytes(), authority.as_ref());
    }

    // Known-answer recovery vector reproducing the viem recoverAuthorizationAddress fixture: the
    // anvil account 0 key signs the authorization { chain_id: 1, delegate: wagmi test contract,
    // nonce: 0 } and recovers to that account's address. All values are pinned to viem commit
    // 349eb2eae6a84d0a7ea9e73b81b51f3fe2f17df8:
    // - fixture: test/src/utils/authorization/recoverAuthorizationAddress.test.ts (imports the
    //   constants below; the literal values are not inlined there)
    // - accounts[0].privateKey 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    //   and accounts[0].address 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266: test/src/constants.ts L1-6
    // - wagmiContractConfig.address 0xFBA3912Ca04dd458c843e2EE08967fC04f3579c2: test/src/abis.ts L1252-1253
    #[test]
    fn should_recover_viem_authority_from_signed_authorization() {
        use crate::address::ecdsa_public_key_to_address;
        use ethers_core::types::{
            H256, RecoveryMessage, Signature as EthSignature, U256 as EthU256,
        };
        use ic_secp256k1::PrivateKey;

        let private_key = PrivateKey::deserialize_sec1(
            &hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap(),
        )
        .unwrap();
        let public_key = private_key.public_key();
        let authority = ecdsa_public_key_to_address(&public_key);
        assert_eq!(
            authority,
            Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap()
        );

        let authorization = Authorization {
            chain_id: 1,
            delegate: Address::from_str("0xFBA3912Ca04dd458c843e2EE08967fC04f3579c2").unwrap(),
            nonce: TransactionNonce::from(0_u8),
        };
        let hash = authorization.hash();
        let signature = private_key.sign_digest_with_ecdsa(&hash.0);
        let recovery_id = public_key
            .try_recovery_from_digest(&hash.0, &signature)
            .unwrap();
        assert!(!recovery_id.is_x_reduced());

        let (r_bytes, s_bytes) = super::super::split_in_two(signature);
        let recovered = EthSignature {
            r: EthU256::from_big_endian(&r_bytes),
            s: EthU256::from_big_endian(&s_bytes),
            v: 27 + recovery_id.is_y_odd() as u64,
        }
        .recover(RecoveryMessage::Hash(H256(hash.0)))
        .unwrap();

        assert_eq!(recovered.as_bytes(), authority.as_ref());
    }

    fn sample_signed_transaction() -> SignedEip7702TransactionRequest {
        let authorization = SignedAuthorization {
            chain_id: 6,
            delegate: Address::from_str("0x0202020202020202020202020202020202020202").unwrap(),
            nonce: TransactionNonce::from(2_u8),
            y_parity: false,
            r: u256::from_str_hex(
                "0x42556c4f2a3f4e4e639cca524d1da70e60881417d4643e5382ed110a52719eaf",
            )
            .unwrap(),
            s: u256::from_str_hex(
                "0x172f591a2a763d0bd6b13d042d8c5eb66e87f129c9dc77ada66b6041012db2b3",
            )
            .unwrap(),
        };
        let transaction = Eip7702TransactionRequest {
            chain_id: 56,
            nonce: TransactionNonce::from(1_u8),
            max_priority_fee_per_gas: WeiPerGas::new(2),
            max_fee_per_gas: WeiPerGas::new(3),
            gas_limit: GasAmount::new(4),
            destination: Address::from_str("0x0101010101010101010101010101010101010101").unwrap(),
            amount: Wei::new(5),
            data: hex::decode("1234").unwrap(),
            access_list: AccessList::new(),
            authorization_list: vec![authorization],
        };
        let signature = TransactionSignature {
            signature_y_parity: false,
            r: u256::from_str_hex(
                "0xd93fc9ae934d4f72db91cb149e7e84b50ca83b5a8a7b873b0fdb009546e3af47",
            )
            .unwrap(),
            s: u256::from_str_hex(
                "0x786bfaf31af61eea6471dbb1bec7d94f73fb90887e4f04d0e9b85676c47ab02a",
            )
            .unwrap(),
        };
        SignedEip7702TransactionRequest::from((transaction, signature))
    }

    #[test]
    fn should_cbor_encoding_of_signed_eip7702_transaction_be_stable() {
        let signed_tx = sample_signed_transaction();
        let mut encoded: Vec<u8> = Vec::new();
        minicbor::encode(&signed_tx, &mut encoded).unwrap();

        assert_eq!(
            encoded,
            [
                130, 138, 24, 56, 1, 2, 3, 4, 84, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 5, 66, 18, 52, 128, 129, 134, 6, 84, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 244, 194, 88, 32, 66, 85, 108, 79, 42, 63, 78, 78,
                99, 156, 202, 82, 77, 29, 167, 14, 96, 136, 20, 23, 212, 100, 62, 83, 130, 237, 17,
                10, 82, 113, 158, 175, 194, 88, 32, 23, 47, 89, 26, 42, 118, 61, 11, 214, 177, 61,
                4, 45, 140, 94, 182, 110, 135, 241, 41, 201, 220, 119, 173, 166, 107, 96, 65, 1,
                45, 178, 179, 131, 244, 194, 88, 32, 217, 63, 201, 174, 147, 77, 79, 114, 219, 145,
                203, 20, 158, 126, 132, 181, 12, 168, 59, 90, 138, 123, 135, 59, 15, 219, 0, 149,
                70, 227, 175, 71, 194, 88, 32, 120, 107, 250, 243, 26, 246, 30, 234, 100, 113, 219,
                177, 190, 199, 217, 79, 115, 251, 144, 136, 126, 79, 4, 208, 233, 184, 86, 118,
                196, 122, 176, 42
            ]
        );

        let decoded: SignedEip7702TransactionRequest = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded, signed_tx);
    }

    #[test]
    fn should_cbor_encoding_of_signed_authorization_be_stable() {
        let authorization = sample_signed_transaction().transaction().authorization_list[0].clone();
        let mut encoded: Vec<u8> = Vec::new();
        minicbor::encode(&authorization, &mut encoded).unwrap();

        assert_eq!(
            encoded,
            [
                134, 6, 84, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 244,
                194, 88, 32, 66, 85, 108, 79, 42, 63, 78, 78, 99, 156, 202, 82, 77, 29, 167, 14,
                96, 136, 20, 23, 212, 100, 62, 83, 130, 237, 17, 10, 82, 113, 158, 175, 194, 88,
                32, 23, 47, 89, 26, 42, 118, 61, 11, 214, 177, 61, 4, 45, 140, 94, 182, 110, 135,
                241, 41, 201, 220, 119, 173, 166, 107, 96, 65, 1, 45, 178, 179
            ]
        );

        let decoded: SignedAuthorization = minicbor::decode(&encoded).unwrap();
        assert_eq!(decoded, authorization);
    }
}

fn arb_transaction_price() -> impl Strategy<Value = TransactionPrice> {
    use crate::numeric::WeiPerGas;
    use crate::test_fixtures::arb::arb_checked_amount_of;
    use proptest::prelude::any;
    (arb_checked_amount_of(), any::<u128>(), any::<u128>()).prop_map(
        |(gas_limit, delta_to_max_fee_per_gas, max_priority_fee_per_gas)| TransactionPrice {
            gas_limit,
            // max_fee_per_gas is always greater or equal to max_priority_fee_per_gas
            max_fee_per_gas: WeiPerGas::from(max_priority_fee_per_gas)
                .checked_add(WeiPerGas::from(delta_to_max_fee_per_gas))
                .expect("BUG: addition of 2 u128 should not overflow a u256"),
            max_priority_fee_per_gas: WeiPerGas::from(max_priority_fee_per_gas),
        },
    )
}

fn arb_gas_fee_estimate() -> impl Strategy<Value = GasFeeEstimate> {
    use crate::numeric::WeiPerGas;
    use proptest::prelude::any;
    (any::<u64>(), any::<u64>()).prop_map(|(base_fee_per_gas, max_priority_fee_per_gas)| {
        GasFeeEstimate {
            base_fee_per_gas: WeiPerGas::from(base_fee_per_gas),
            max_priority_fee_per_gas: WeiPerGas::from(max_priority_fee_per_gas),
        }
    })
}
