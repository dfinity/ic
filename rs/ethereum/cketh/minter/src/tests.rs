use crate::address::ecdsa_public_key_to_address;
use crate::{EVM_RPC_ID_PRODUCTION, EVM_RPC_ID_STAGING};

#[test]
fn test_evm_rpc_id_mainnet_value() {
    assert_eq!(
        EVM_RPC_ID_PRODUCTION.to_string(),
        "7hfb6-caaaa-aaaar-qadga-cai"
    );
}

#[test]
fn test_evm_rpc_id_staging_value() {
    assert_eq!(
        EVM_RPC_ID_STAGING.to_string(),
        "xhcuo-6yaaa-aaaar-qacqq-cai"
    );
}

mod eth_get_logs {
    use evm_rpc_types::{Hex, Hex20, Hex32};
    use std::str::FromStr;

    #[test]
    fn deserialize_get_logs() {
        use evm_rpc_types::LogEntry;

        let logs: Vec<LogEntry> = serde_json::from_str(r#"[
 {
    "address": "0x7e41257f7b5c3dd3313ef02b1f4c864fe95bec2b",
    "topics": [
      "0x2a2607d40f4a6feb97c36e0efd57e0aa3e42e0332af4fceb78f21b7dffcbd657"
    ],
    "data": "0x00000000000000000000000055654e7405fcb336386ea8f36954a211b2cda764000000000000000000000000000000000000000000000000002386f26fc100000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000003f62327071372d71677a7a692d74623564622d72357363692d637736736c2d6e646f756c2d666f7435742d347a7732702d657a6677692d74616a32792d76716500",
    "blockNumber": 3843316,
    "transactionHash": "0x5618f72c485bd98a3df58d900eabe9e24bfaa972a6fe5227e02233fad2db1154",
    "transactionIndex": 6,
    "blockHash": "0x908e6b84d26d71421bfaa08e7966e0afcef3883a28a53a0a7a31104caf1e94c2",
    "logIndex": 8,
    "removed": false
  }]"#).unwrap();
        assert_eq!(
            logs,
            vec![LogEntry {
                address: Hex20::from_str("0x7e41257f7b5c3dd3313ef02b1f4c864fe95bec2b").unwrap(),
                topics: vec![
                   Hex32::from_str("0x2a2607d40f4a6feb97c36e0efd57e0aa3e42e0332af4fceb78f21b7dffcbd657").unwrap(),
                ],
                data: Hex::from_str("0x00000000000000000000000055654e7405fcb336386ea8f36954a211b2cda764000000000000000000000000000000000000000000000000002386f26fc100000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000003f62327071372d71677a7a692d74623564622d72357363692d637736736c2d6e646f756c2d666f7435742d347a7732702d657a6677692d74616a32792d76716500").unwrap(),
                block_number: Some(0x3aa4f4_u32.into()),
                transaction_hash: Some(Hex32::from_str("0x5618f72c485bd98a3df58d900eabe9e24bfaa972a6fe5227e02233fad2db1154").unwrap()),
                transaction_index: Some(0x06_u8.into()),
                block_hash: Some(Hex32::from_str("0x908e6b84d26d71421bfaa08e7966e0afcef3883a28a53a0a7a31104caf1e94c2").unwrap()),
                log_index: Some(0x08_u8.into()),
                removed: false,
            }]
        );
    }
}

#[test]
fn address_from_pubkey() {
    use ic_secp256k1::PublicKey;

    // Examples come from https://mycrypto.tools/sample_ethaddresses.html
    const EXAMPLES: &[(&str, &str)] = &[
        (
            "04e68acfc0253a10620dff706b0a1b1f1f5833ea3beb3bde2250d5f271f3563606672ebc45e0b7ea2e816ecb70ca03137b1c9476eec63d4632e990020b7b6fba39",
            "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1",
        ),
        (
            "04bbe06c9dd095cdf0aded667ea17621e8c1fdcd36ffe112a9c94e47aa6be1406a666e1001cf0067d0f9a541043dfc5438ead7be3ecbcdc328b67d8f966bceea63",
            "0x721B68fA152a930F3df71F54aC1ce7ed3ac5f867",
        ),
    ];
    for (pk_bytes, address) in EXAMPLES {
        let sec1_bytes = hex::decode(pk_bytes).unwrap();
        let pk = PublicKey::deserialize_sec1(&sec1_bytes).unwrap();
        assert_eq!(&ecdsa_public_key_to_address(&pk).to_string(), address);
    }
}

mod rlp_encoding {
    use crate::numeric::{GasAmount, TransactionNonce, Wei, WeiPerGas};
    use crate::tx::{
        AccessList, Eip1559Signature, Eip1559TransactionRequest, SignedEip1559TransactionRequest,
    };
    use ethnum::u256;
    use ic_ethereum_types::Address;
    use rlp::Encodable;
    use std::str::FromStr;

    const SEPOLIA_TEST_CHAIN_ID: u64 = 11155111;

    #[test]
    fn test_rlp_encoding() {
        use crate::tx::{AccessList, Eip1559TransactionRequest};
        use ethers_core::abi::ethereum_types::H160;
        use ethers_core::types::Signature as EthersCoreSignature;
        use ethers_core::types::transaction::eip1559::Eip1559TransactionRequest as EthersCoreEip1559TransactionRequest;
        use ethers_core::types::transaction::eip2930::AccessList as EthersCoreAccessList;
        use ethers_core::types::{Bytes, U256};
        use ethnum::u256;

        let address_bytes: [u8; 20] = [
            180, 75, 94, 117, 106, 137, 71, 117, 252, 50, 237, 223, 51, 20, 187, 27, 25, 68, 220,
            52,
        ];

        let ethers_core_tx = EthersCoreEip1559TransactionRequest {
            from: None,
            to: Some(ethers_core::types::NameOrAddress::Address(H160::from(
                address_bytes,
            ))),
            gas: Some(1.into()),
            value: Some(2.into()),
            data: Some(Bytes::new()),
            nonce: Some(0.into()),
            access_list: EthersCoreAccessList::from(vec![]),
            max_priority_fee_per_gas: Some(3.into()),
            max_fee_per_gas: Some(4.into()),
            chain_id: Some(1.into()),
        };
        let minter_tx = Eip1559TransactionRequest {
            chain_id: 1,
            destination: Address::new(address_bytes),
            nonce: 0_u64.into(),
            gas_limit: 1_u32.into(),
            max_fee_per_gas: 4_u64.into(),
            amount: 2_u64.into(),
            data: vec![],
            access_list: AccessList::new(),
            max_priority_fee_per_gas: 3_u64.into(),
        };
        assert_eq!(
            minter_tx.rlp_bytes().to_vec(),
            ethers_core_tx.rlp().to_vec()
        );

        let signature = Eip1559Signature {
            signature_y_parity: true,
            r: u256::from_str_radix(
                "b92224ecdb5295f3b889059621909c6b7a2308ccd0e5f13812409d80706b13cd",
                16,
            )
            .unwrap(),
            s: u256::from_str_radix(
                "0bec9da278e6388a9d6934c911684234e16db1610c2227545c7b192db277c4b1",
                16,
            )
            .unwrap(),
        };

        assert_eq!(
            SignedEip1559TransactionRequest::from((minter_tx, signature))
                .rlp_bytes()
                .to_vec(),
            ethers_core_tx
                .rlp_signed(&EthersCoreSignature {
                    v: 1,
                    r: U256::from_str_radix(
                        "b92224ecdb5295f3b889059621909c6b7a2308ccd0e5f13812409d80706b13cd",
                        16
                    )
                    .unwrap(),
                    s: U256::from_str_radix(
                        "0bec9da278e6388a9d6934c911684234e16db1610c2227545c7b192db277c4b1",
                        16
                    )
                    .unwrap(),
                })
                .to_vec()
        );
    }

    #[test]
    fn should_compute_correct_rlp_encoding_of_signed_transaction() {
        // see https://sepolia.etherscan.io/getRawTx?tx=0x66a9a218ea720ac6d2c9e56f7e44836c1541c186b7627bda220857ce34e2df7f
        let signature = Eip1559Signature {
            signature_y_parity: true,
            r: u256::from_str_hex(
                "0x7d097b81dc8bf5ad313f8d6656146d4723d0e6bb3fb35f1a709e6a3d4426c0f3",
            )
            .unwrap(),
            s: u256::from_str_hex(
                "0x4f8a618d959e7d96e19156f0f5f2ed321b34e2004a0c8fdb7f02bc7d08b74441",
            )
            .unwrap(),
        };
        let transaction = Eip1559TransactionRequest {
            chain_id: SEPOLIA_TEST_CHAIN_ID,
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
        let tx_hash = transaction.hash();
        assert_eq!(
            tx_hash.to_string(),
            "0x2d9e6453d9864cff7453ca35dcab86be744c641ba4891c2fe9aeaa2f767b9758"
        );

        let signed_transaction = SignedEip1559TransactionRequest::from((transaction, signature));
        assert_eq!(
            signed_transaction.raw_transaction_hex_string(),
            "0x02f89883aa36a7068459682f0084598653cd82dcbf94b44b5e756a894775fc32eddf3314bb1b1944dc3487038d7ea4c68000a4b214faa51d882d15b09f8e81e29606305f5fefc5eff3e2309620a3557ecae39d62020000c001a07d097b81dc8bf5ad313f8d6656146d4723d0e6bb3fb35f1a709e6a3d4426c0f3a04f8a618d959e7d96e19156f0f5f2ed321b34e2004a0c8fdb7f02bc7d08b74441"
        );
        assert_eq!(
            signed_transaction.hash().to_string(),
            "0x66a9a218ea720ac6d2c9e56f7e44836c1541c186b7627bda220857ce34e2df7f"
        );
    }
}
