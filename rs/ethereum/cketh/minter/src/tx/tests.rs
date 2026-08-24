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
    use crate::checked_amount::CheckedAmountOf;
    use crate::numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas};
    use crate::tx::{
        AccessList, AccessListItem, Authorization, Eip7702TransactionRequest, SignedAuthorization,
        SignedEip7702TransactionRequest, StorageKey, TransactionSignature,
    };
    use ethnum::u256;
    use ic_ethereum_types::Address;
    use rlp::Encodable;
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
        use alloy_primitives::{B256, Signature};
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

        let recovered = Signature::from_scalars_and_parity(
            B256::from(r_bytes),
            B256::from(s_bytes),
            tuple.y_parity,
        )
        .recover_address_from_prehash(&B256::from(hash.0))
        .unwrap();

        assert_eq!(recovered.as_slice(), authority.as_ref());
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
        use alloy_primitives::{B256, Signature};
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
        let recovered = Signature::from_scalars_and_parity(
            B256::from(r_bytes),
            B256::from(s_bytes),
            recovery_id.is_y_odd(),
        )
        .recover_address_from_prehash(&B256::from(hash.0))
        .unwrap();

        assert_eq!(recovered.as_slice(), authority.as_ref());
    }

    /// Cross-checks the minter's hand-rolled EIP-7702 encoding against `alloy`, which encodes the
    /// same transaction independently: the payload to sign, the broadcast payload of the signed
    /// transaction, and the hash the transaction is referenced by. `ethers-core` was archived
    /// before EIP-7702 and could not check any of this.
    #[test]
    fn should_encode_the_same_transaction_as_alloy() {
        use alloy_consensus::SignableTransaction;
        use alloy_eips::eip2718::Encodable2718;

        for signed_tx in [
            sample_signed_transaction(),
            sample_signed_transaction_with_access_list(),
        ] {
            let alloy_tx = to_alloy_transaction(signed_tx.transaction());
            assert_eq!(
                prefix_with_transaction_type(
                    crate::tx::SignableTransaction::transaction_type(signed_tx.transaction()),
                    signed_tx.transaction().rlp_bytes().to_vec()
                ),
                alloy_tx.encoded_for_signing()
            );

            let alloy_signed = alloy_tx.into_signed(to_alloy_signature(signed_tx.signature()));
            assert_eq!(
                signed_tx.raw_transaction_bytes(),
                alloy_signed.encoded_2718()
            );
            assert_eq!(signed_tx.hash().0, alloy_signed.hash().0);
        }
    }

    fn to_alloy_transaction(transaction: &Eip7702TransactionRequest) -> alloy_consensus::TxEip7702 {
        alloy_consensus::TxEip7702 {
            chain_id: transaction.chain_id,
            nonce: to_u64(transaction.nonce),
            gas_limit: to_u64(transaction.gas_limit),
            max_fee_per_gas: to_u128(transaction.max_fee_per_gas),
            max_priority_fee_per_gas: to_u128(transaction.max_priority_fee_per_gas),
            to: alloy_primitives::Address::from(transaction.destination.into_bytes()),
            value: alloy_primitives::U256::from_be_bytes(transaction.amount.to_be_bytes()),
            access_list: alloy_eips::eip2930::AccessList(
                transaction
                    .access_list
                    .0
                    .iter()
                    .map(|item| alloy_eips::eip2930::AccessListItem {
                        address: alloy_primitives::Address::from(item.address.into_bytes()),
                        storage_keys: item
                            .storage_keys
                            .iter()
                            .map(|key| alloy_primitives::B256::from(key.0))
                            .collect(),
                    })
                    .collect(),
            ),
            authorization_list: transaction
                .authorization_list
                .iter()
                .map(to_alloy_authorization)
                .collect(),
            input: alloy_primitives::Bytes::copy_from_slice(&transaction.data),
        }
    }

    fn to_alloy_authorization(
        authorization: &SignedAuthorization,
    ) -> alloy_eips::eip7702::SignedAuthorization {
        alloy_eips::eip7702::SignedAuthorization::new_unchecked(
            alloy_eips::eip7702::Authorization {
                chain_id: alloy_primitives::U256::from(authorization.chain_id),
                address: alloy_primitives::Address::from(authorization.delegate.into_bytes()),
                nonce: to_u64(authorization.nonce),
            },
            u8::from(authorization.y_parity),
            alloy_primitives::U256::from_be_bytes(authorization.r.to_be_bytes()),
            alloy_primitives::U256::from_be_bytes(authorization.s.to_be_bytes()),
        )
    }

    fn to_alloy_signature(signature: &TransactionSignature) -> alloy_primitives::Signature {
        alloy_primitives::Signature::new(
            alloy_primitives::U256::from_be_bytes(signature.r.to_be_bytes()),
            alloy_primitives::U256::from_be_bytes(signature.s.to_be_bytes()),
            signature.signature_y_parity,
        )
    }

    fn to_u64<Unit>(amount: CheckedAmountOf<Unit>) -> u64 {
        alloy_primitives::U256::from_be_bytes(amount.to_be_bytes()).to::<u64>()
    }

    fn to_u128<Unit>(amount: CheckedAmountOf<Unit>) -> u128 {
        alloy_primitives::U256::from_be_bytes(amount.to_be_bytes()).to::<u128>()
    }

    fn prefix_with_transaction_type(transaction_type: u8, rlp: Vec<u8>) -> Vec<u8> {
        let mut prefixed = rlp;
        prefixed.insert(0, transaction_type);
        prefixed
    }

    /// The sample transaction carries an empty access list, so decoding it exercises neither the
    /// nested storage keys nor the address inside an access-list item.
    fn sample_signed_transaction_with_access_list() -> SignedEip7702TransactionRequest {
        let signed_tx = sample_signed_transaction();
        let transaction = Eip7702TransactionRequest {
            access_list: AccessList(vec![AccessListItem {
                address: Address::from_str("0x0303030303030303030303030303030303030303").unwrap(),
                storage_keys: vec![StorageKey([0x11; 32]), StorageKey([0x22; 32])],
            }]),
            ..signed_tx.transaction().clone()
        };
        SignedEip7702TransactionRequest::from((transaction, sample_transaction_signature()))
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
        SignedEip7702TransactionRequest::from((transaction, sample_transaction_signature()))
    }

    fn sample_transaction_signature() -> TransactionSignature {
        TransactionSignature {
            signature_y_parity: false,
            r: u256::from_str_hex(
                "0xd93fc9ae934d4f72db91cb149e7e84b50ca83b5a8a7b873b0fdb009546e3af47",
            )
            .unwrap(),
            s: u256::from_str_hex(
                "0x786bfaf31af61eea6471dbb1bec7d94f73fb90887e4f04d0e9b85676c47ab02a",
            )
            .unwrap(),
        }
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

mod sweep {
    use crate::numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas};
    use crate::tx::{
        AccessList, DelegatingSweep, Eip1559TransactionRequest, Eip7702TransactionRequest,
        SignableTransaction, SignedAuthorization, SignedEip1559TransactionRequest,
        SignedEip7702TransactionRequest, SignedSweepTransaction, SweepTransaction,
        TransactionSignature,
    };
    use assert_matches::assert_matches;
    use ethnum::u256;
    use ic_ethereum_types::Address;
    use std::str::FromStr;

    const EIP1559_TX_ID: u8 = 2;
    const SET_CODE_TX_ID: u8 = 4;

    #[test]
    fn should_sign_a_plain_sweep_as_its_eip1559_transaction() {
        let transaction = sweep_transaction();
        let sweep = SweepTransaction::new(transaction.clone(), vec![]);

        assert_eq!(sweep.transaction_type(), EIP1559_TX_ID);
        assert_eq!(sweep.authorizations(), &[]);
        assert_eq!(sweep.hash(), transaction.hash());
        assert_eq!(
            SignedSweepTransaction::from((sweep, signature())).raw_transaction_hex_string(),
            SignedEip1559TransactionRequest::from((transaction, signature()))
                .raw_transaction_hex_string()
        );
    }

    #[test]
    fn should_sign_a_delegating_sweep_as_its_eip7702_transaction() {
        let sweep = SweepTransaction::new(sweep_transaction(), vec![authorization()]);
        let SweepTransaction::Eip7702(transaction) = sweep.clone() else {
            panic!("BUG: a sweep with an authorization must be a type-0x04 transaction");
        };

        assert_eq!(sweep.transaction_type(), SET_CODE_TX_ID);
        assert_eq!(sweep.authorizations(), &[authorization()]);
        let transaction = transaction.transaction().clone();
        assert_eq!(sweep.hash(), transaction.hash());
        assert_eq!(
            SignedSweepTransaction::from((sweep, signature())).raw_transaction_hex_string(),
            SignedEip7702TransactionRequest::from((transaction, signature()))
                .raw_transaction_hex_string()
        );
    }

    #[test]
    fn should_cbor_encoding_of_sweep_transaction_be_stable() {
        let expected: [(SweepTransaction, Vec<u8>); 2] = [
            (
                SweepTransaction::new(sweep_transaction(), vec![]),
                vec![
                    130, 0, 129, 137, 26, 0, 170, 54, 167, 6, 26, 89, 104, 47, 0, 26, 89, 134, 83,
                    205, 26, 0, 1, 134, 160, 84, 180, 75, 94, 117, 106, 137, 71, 117, 252, 50, 237,
                    223, 51, 20, 187, 27, 25, 68, 220, 52, 0, 66, 18, 52, 128,
                ],
            ),
            (
                SweepTransaction::new(sweep_transaction(), vec![authorization()]),
                vec![
                    130, 1, 129, 138, 26, 0, 170, 54, 167, 6, 26, 89, 104, 47, 0, 26, 89, 134, 83,
                    205, 26, 0, 1, 134, 160, 84, 180, 75, 94, 117, 106, 137, 71, 117, 252, 50, 237,
                    223, 51, 20, 187, 27, 25, 68, 220, 52, 0, 66, 18, 52, 128, 129, 134, 26, 0,
                    170, 54, 167, 84, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    0, 244, 194, 88, 32, 66, 85, 108, 79, 42, 63, 78, 78, 99, 156, 202, 82, 77, 29,
                    167, 14, 96, 136, 20, 23, 212, 100, 62, 83, 130, 237, 17, 10, 82, 113, 158,
                    175, 194, 88, 32, 23, 47, 89, 26, 42, 118, 61, 11, 214, 177, 61, 4, 45, 140,
                    94, 182, 110, 135, 241, 41, 201, 220, 119, 173, 166, 107, 96, 65, 1, 45, 178,
                    179,
                ],
            ),
        ];
        for (sweep, expected_encoding) in expected {
            let mut encoded: Vec<u8> = Vec::new();
            minicbor::encode(&sweep, &mut encoded).unwrap();

            assert_eq!(encoded, expected_encoding);

            let decoded: SweepTransaction = minicbor::decode(&encoded).unwrap();
            assert_eq!(decoded, sweep);
        }
    }

    #[test]
    fn should_refuse_a_delegating_sweep_that_installs_nothing() {
        let SweepTransaction::Eip7702(sweep) =
            SweepTransaction::new(sweep_transaction(), vec![authorization()])
        else {
            panic!("BUG: a sweep with an authorization must be a type-0x04 transaction");
        };

        assert_eq!(
            DelegatingSweep::new(Eip7702TransactionRequest {
                authorization_list: vec![],
                ..sweep.transaction().clone()
            }),
            None
        );
    }

    #[test]
    fn should_refuse_to_decode_a_delegating_sweep_that_installs_nothing() {
        let SweepTransaction::Eip7702(sweep) =
            SweepTransaction::new(sweep_transaction(), vec![authorization()])
        else {
            panic!("BUG: a sweep with an authorization must be a type-0x04 transaction");
        };
        let empty = Eip7702TransactionRequest {
            authorization_list: vec![],
            ..sweep.transaction().clone()
        };
        let encoded = minicbor::to_vec(&empty).unwrap();

        assert_matches!(
            minicbor::decode::<DelegatingSweep>(&encoded),
            Err(e) if e.to_string().contains("empty authorization list")
        );
        assert_eq!(
            minicbor::decode::<DelegatingSweep>(&minicbor::to_vec(sweep.transaction()).unwrap())
                .unwrap(),
            sweep
        );
    }

    #[test]
    #[should_panic(expected = "BUG: authorization for another chain")]
    fn should_trap_on_an_authorization_for_another_chain() {
        let other_chain = SignedAuthorization {
            chain_id: sweep_transaction().chain_id + 1,
            ..authorization()
        };

        let _ = SweepTransaction::new(sweep_transaction(), vec![other_chain]);
    }

    #[test]
    fn should_accept_an_authorization_valid_on_every_chain() {
        let any_chain = SignedAuthorization {
            chain_id: 0,
            ..authorization()
        };

        let sweep = SweepTransaction::new(sweep_transaction(), vec![any_chain.clone()]);

        assert_eq!(sweep.transaction_type(), SET_CODE_TX_ID);
        assert_eq!(sweep.authorizations(), &[any_chain]);
    }

    fn sweep_transaction() -> Eip1559TransactionRequest {
        Eip1559TransactionRequest {
            chain_id: 11155111,
            nonce: TransactionNonce::from(6_u8),
            max_priority_fee_per_gas: WeiPerGas::new(0x59682f00),
            max_fee_per_gas: WeiPerGas::new(0x598653cd),
            gas_limit: GasAmount::new(100_000),
            destination: Address::from_str("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34").unwrap(),
            amount: Wei::ZERO,
            data: hex::decode("1234").unwrap(),
            access_list: AccessList::new(),
        }
    }

    fn authorization() -> SignedAuthorization {
        SignedAuthorization {
            chain_id: 11155111,
            delegate: Address::from_str("0x0202020202020202020202020202020202020202").unwrap(),
            nonce: TransactionNonce::ZERO,
            y_parity: false,
            r: u256::from_str_hex(
                "0x42556c4f2a3f4e4e639cca524d1da70e60881417d4643e5382ed110a52719eaf",
            )
            .unwrap(),
            s: u256::from_str_hex(
                "0x172f591a2a763d0bd6b13d042d8c5eb66e87f129c9dc77ada66b6041012db2b3",
            )
            .unwrap(),
        }
    }

    fn signature() -> TransactionSignature {
        TransactionSignature {
            signature_y_parity: true,
            r: u256::from_str_hex(
                "0x7d097b81dc8bf5ad313f8d6656146d4723d0e6bb3fb35f1a709e6a3d4426c0f3",
            )
            .unwrap(),
            s: u256::from_str_hex(
                "0x4f8a618d959e7d96e19156f0f5f2ed321b34e2004a0c8fdb7f02bc7d08b74441",
            )
            .unwrap(),
        }
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

mod sign_digest {
    use crate::eth_rpc::Hash;
    use crate::test_fixtures::mock::MockCanisterRuntime;
    use crate::test_fixtures::{init_state, initial_state};
    use crate::tx::{TransactionSignature, sign_digest, split_in_two};
    use ethnum::u256;
    use ic_cdk_management_canister::EcdsaPublicKeyResult;
    use ic_secp256k1::PrivateKey;

    #[tokio::test]
    async fn should_sign_digest_through_the_runtime() {
        let private_key = PrivateKey::deserialize_sec1(&[0x46_u8; 32]).unwrap();
        let digest = Hash([0x11_u8; 32]);
        let signature = private_key.sign_digest_with_ecdsa(&digest.0);
        let public_key = EcdsaPublicKeyResult {
            public_key: private_key.public_key().serialize_sec1(true),
            chain_code: vec![0_u8; 32],
        };
        init_state(initial_state());
        let mut runtime = MockCanisterRuntime::new();
        runtime
            .expect_ecdsa_public_key()
            .times(1)
            .return_once(move |_, _| Ok(public_key));
        runtime
            .expect_sign_with_ecdsa()
            .times(1)
            .return_once(move |_, _, _| Ok(signature));

        let signed = sign_digest(&digest, &[], &runtime).await.unwrap();

        let (r_bytes, s_bytes) = split_in_two(signature);
        let recovery_id = private_key
            .public_key()
            .try_recovery_from_digest(&digest.0, &signature)
            .unwrap();
        assert_eq!(
            signed,
            TransactionSignature {
                signature_y_parity: recovery_id.is_y_odd(),
                r: u256::from_be_bytes(r_bytes),
                s: u256::from_be_bytes(s_bytes),
            }
        );
    }
}
