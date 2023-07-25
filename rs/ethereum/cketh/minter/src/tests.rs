use crate::address::Address;
use std::str::FromStr;

#[test]
fn deserialize_block_spec() {
    use crate::eth_rpc::*;

    assert_eq!(
        BlockSpec::Number(Quantity::new(0xffff)),
        serde_json::from_str("\"0xffff\"").unwrap()
    );
    assert_eq!(
        BlockSpec::Tag(BlockTag::Earliest),
        serde_json::from_str("\"earliest\"").unwrap()
    );
    assert_eq!(
        BlockSpec::Tag(BlockTag::Finalized),
        serde_json::from_str("\"finalized\"").unwrap()
    );
    assert_eq!(
        BlockSpec::Tag(BlockTag::Pending),
        serde_json::from_str("\"pending\"").unwrap()
    );
}

#[test]
fn deserialize_json_reply() {
    use crate::eth_rpc::*;
    let reply: JsonRpcReply<String> =
        serde_json::from_str(r#"{"id":2,"jsonrpc":"2.0","result":"0x1639e49bba16280000"}"#)
            .unwrap();
    assert_eq!(
        reply.result,
        JsonRpcResult::Result("0x1639e49bba16280000".to_string())
    );

    let reply: JsonRpcReply<String> =
        serde_json::from_str(r#"{"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params: invalid username"}, "id": 1}"#)
            .unwrap();
    assert_eq!(
        reply.result,
        JsonRpcResult::Error {
            code: -32602,
            message: "Invalid params: invalid username".to_string(),
        }
    );
}

#[test]
fn deserialize_get_logs() {
    use crate::eth_rpc::*;

    fn hash_from_hex(s: &str) -> Hash {
        Hash(hex::decode(s).unwrap().try_into().unwrap())
    }

    let logs: Vec<LogEntry> = serde_json::from_str(r#"[
 {
    "address": "0x7e41257f7b5c3dd3313ef02b1f4c864fe95bec2b",
    "topics": [
      "0x2a2607d40f4a6feb97c36e0efd57e0aa3e42e0332af4fceb78f21b7dffcbd657"
    ],
    "data": "0x00000000000000000000000055654e7405fcb336386ea8f36954a211b2cda764000000000000000000000000000000000000000000000000002386f26fc100000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000003f62327071372d71677a7a692d74623564622d72357363692d637736736c2d6e646f756c2d666f7435742d347a7732702d657a6677692d74616a32792d76716500",
    "blockNumber": "0x3aa4f4",
    "transactionHash": "0x5618f72c485bd98a3df58d900eabe9e24bfaa972a6fe5227e02233fad2db1154",
    "transactionIndex": "0x6",
    "blockHash": "0x908e6b84d26d71421bfaa08e7966e0afcef3883a28a53a0a7a31104caf1e94c2",
    "logIndex": "0x8",
    "removed": false
  }]"#).unwrap();
    assert_eq!(
        logs,
        vec![LogEntry {
            address: Address::from_str("0x7e41257f7b5c3dd3313ef02b1f4c864fe95bec2b").unwrap(),
            topics: vec![
                Data(hex::decode("2a2607d40f4a6feb97c36e0efd57e0aa3e42e0332af4fceb78f21b7dffcbd657").unwrap()),
            ],
            data: Data(hex::decode("00000000000000000000000055654e7405fcb336386ea8f36954a211b2cda764000000000000000000000000000000000000000000000000002386f26fc100000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000003f62327071372d71677a7a692d74623564622d72357363692d637736736c2d6e646f756c2d666f7435742d347a7732702d657a6677692d74616a32792d76716500").unwrap()),
            block_number: Some(Quantity::new(0x3aa4f4)),
            transaction_hash: Some(hash_from_hex("5618f72c485bd98a3df58d900eabe9e24bfaa972a6fe5227e02233fad2db1154")),
            transaction_index: Some(Quantity::new(0x06)),
            block_hash: Some(hash_from_hex("908e6b84d26d71421bfaa08e7966e0afcef3883a28a53a0a7a31104caf1e94c2")),
            log_index: Some(Quantity::new(0x08)),
            removed: false,
        }]
    );
}

#[test]
fn address_from_pubkey() {
    use ic_crypto_ecdsa_secp256k1::PublicKey;

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
        assert_eq!(&Address::from_pubkey(&pk).to_string(), address);
    }
}

// See https://eips.ethereum.org/EIPS/eip-55#test-cases
#[test]
fn address_display() {
    use crate::address::*;

    const EXAMPLES: &[&str] = &[
        // All caps
        "0x52908400098527886E0F7030069857D2E4169EE7",
        "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
        // All Lower
        "0xde709f2102306220921060314715629080e2fb77",
        "0x27b1fdb04752bbc536007a920d24acb045561c26",
        // Normal
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];
    for example in EXAMPLES {
        let addr = Address::from_str(example).unwrap();
        assert_eq!(&addr.to_string(), example);
    }
}
