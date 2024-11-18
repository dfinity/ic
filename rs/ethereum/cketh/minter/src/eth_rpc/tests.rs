use super::*;
use std::str::FromStr;

fn check_response_normalization<O: HttpResponsePayload>(left: &str, right: &str) {
    fn add_envelope(reply: &str) -> Vec<u8> {
        format!("{{\"jsonrpc\": \"2.0\", \"id\": 1, \"result\": {}}}", reply).into_bytes()
    }

    let mut left = add_envelope(left);
    let mut right = add_envelope(right);
    let maybe_transform = O::response_transform();
    if let Some(transform) = maybe_transform {
        transform.apply(&mut left);
        transform.apply(&mut right);
    }
    let left_string = String::from_utf8(left).unwrap();
    let right_string = String::from_utf8(right).unwrap();
    assert_eq!(left_string, right_string);
}

#[test]
fn fee_history_normalization() {
    check_response_normalization::<FeeHistory>(
        r#"{
        "baseFeePerGas": [
            "0x729d3f3b3",
            "0x766e503ea",
            "0x75b51b620",
            "0x74094f2b4",
            "0x716724f03",
            "0x73b467f76"
        ],
        "gasUsedRatio": [
            0.6332004,
            0.47556506666666665,
            0.4432122666666667,
            0.4092196,
            0.5811903
        ],
        "oldestBlock": "0x10f73fc",
        "reward": [
            [
                "0x5f5e100",
                "0x5f5e100",
                "0x68e7780"
            ],
            [
                "0x55d4a80",
                "0x5f5e100",
                "0x5f5e100"
            ],
            [
                "0x5f5e100",
                "0x5f5e100",
                "0x5f5e100"
            ],
            [
                "0x5f5e100",
                "0x5f5e100",
                "0x5f5e100"
            ],
            [
                "0x5f5e100",
                "0x5f5e100",
                "0x180789e0"
            ]
        ]
    }"#,
        r#"{
        "gasUsedRatio": [
            0.6332004,
            0.47556506666666665,
            0.4432122666666667,
            0.4092196,
            0.5811903
        ],
        "baseFeePerGas": [
            "0x729d3f3b3",
            "0x766e503ea",
            "0x75b51b620",
            "0x74094f2b4",
            "0x716724f03",
            "0x73b467f76"
        ],
        "reward": [
            [
                "0x5f5e100",
                "0x5f5e100",
                "0x68e7780"
            ],
            [
                "0x55d4a80",
                "0x5f5e100",
                "0x5f5e100"
            ],
            [
                "0x5f5e100",
                "0x5f5e100",
                "0x5f5e100"
            ],
            [
                "0x5f5e100",
                "0x5f5e100",
                "0x5f5e100"
            ],
            [
                "0x5f5e100",
                "0x5f5e100",
                "0x180789e0"
            ]
        ],
        "oldestBlock": "0x10f73fc"
    }"#,
    )
}

#[test]
fn block_normalization() {
    check_response_normalization::<Block>(
        r#"{
        "number": "0x10eb3c6",
        "hash": "0x85db6d6ad071d127795df4c5f1b04863629d7c2832c89550aa2771bf81c40c85",
        "transactions": [
            "0x3829ea8f4312fc3c69fea37003cbe43f7745c616bc3fd5bff8fef99e35bad75b"
        ],
        "difficulty": "0x0",
        "extraData": "0x6275696c64657230783639",
        "gasLimit": "0x1c9c380",
        "gasUsed": "0xd447a0",
        "logsBloom": "0xcdb111024104125e7188052bbd09fb21d8b08419130094a16401d7a6b605df8060b5f29682d5e7b072303f06c3299750de01e29aea01e9b75e70c4cd752f6d60381244097518a92c5974c28b8389202aa12a738008641e05ed45d5f498668eb47a12ed8a2a62dd03a75d39f938e17c4fa3f7066c30001d45f20a3cdd008854222a3cff6e860cf993c26d9521834e77aea0c5209109435088ec85fd4703107cacfee407e909b1b1a72a1957d19b9e440484061401a11260ea906b9326ae5a92e8591e74b6008062532f8c842037b0ac8480e51222268d72d68efac0226815e0cc3f58600c3be8a0f80e853eefa3216baa850f779a99fc87d60421384150a3a483",
        "miner": "0x690b9a9e9aa1c9db991c7721a92d351db4fac990",
        "mixHash": "0x4dd122a99169327413ec6533fd70a9a9a9cbfad627d356d9b1dc67a47f61b936",
        "nonce": "0x0000000000000000",
        "parentHash": "0xeb080e615e8d1583a5e5cbe3daaed23cf408ae64da2c7352691e00b6e1ffdf89",
        "receiptsRoot": "0xb07ebab433f52fd6dc24297a7804a40578ae0201060aa5938a5a57f4a3a05e03",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "size": "0x29ade",
        "stateRoot": "0x675aa943df0011c3b47038b8365db65ce2d41fcdf3e4bcfb2076f1dfd2dabca4",
        "timestamp": "0x64ba5557",
        "totalDifficulty": "0xc70d815d562d3cfa955",
        "transactionsRoot": "0x42bdb666db19f89d6b6d16e125c49bd15143e062665e00287da5fda10e0d95c0",
        "uncles": [],
        "baseFeePerGas": "0x4b85a0fcd",
        "withdrawalsRoot": "0xedaa8043cdce8101ef827863eb0d808277d200a7a0ee77961934bd235dcb82c6",
        "withdrawals": [
            {
                "address": "0x80b2886b8ef418cce2564ad16ffec4bfbff13787",
                "amount": "0xdbdc02",
                "index": "0xac512e",
                "validatorIndex": "0x932ef"
            }
        ]
    }"#,
        r#"{
        "hash": "0x85db6d6ad071d127795df4c5f1b04863629d7c2832c89550aa2771bf81c40c85",
        "number": "0x10eb3c6",
        "transactions": [
            "0x3829ea8f4312fc3c69fea37003cbe43f7745c616bc3fd5bff8fef99e35bad75b"
        ],
        "extraData": "0x6275696c64657230783639",
        "difficulty": "0x0",
        "gasUsed": "0xd447a0",
        "gasLimit": "0x1c9c380",
        "logsBloom": "0xcdb111024104125e7188052bbd09fb21d8b08419130094a16401d7a6b605df8060b5f29682d5e7b072303f06c3299750de01e29aea01e9b75e70c4cd752f6d60381244097518a92c5974c28b8389202aa12a738008641e05ed45d5f498668eb47a12ed8a2a62dd03a75d39f938e17c4fa3f7066c30001d45f20a3cdd008854222a3cff6e860cf993c26d9521834e77aea0c5209109435088ec85fd4703107cacfee407e909b1b1a72a1957d19b9e440484061401a11260ea906b9326ae5a92e8591e74b6008062532f8c842037b0ac8480e51222268d72d68efac0226815e0cc3f58600c3be8a0f80e853eefa3216baa850f779a99fc87d60421384150a3a483",
        "mixHash": "0x4dd122a99169327413ec6533fd70a9a9a9cbfad627d356d9b1dc67a47f61b936",
        "miner": "0x690b9a9e9aa1c9db991c7721a92d351db4fac990",
        "parentHash": "0xeb080e615e8d1583a5e5cbe3daaed23cf408ae64da2c7352691e00b6e1ffdf89",
        "nonce": "0x0000000000000000",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "receiptsRoot": "0xb07ebab433f52fd6dc24297a7804a40578ae0201060aa5938a5a57f4a3a05e03",
        "stateRoot": "0x675aa943df0011c3b47038b8365db65ce2d41fcdf3e4bcfb2076f1dfd2dabca4",
        "size": "0x29ade",
        "timestamp": "0x64ba5557",
        "transactionsRoot": "0x42bdb666db19f89d6b6d16e125c49bd15143e062665e00287da5fda10e0d95c0",
        "totalDifficulty": "0xc70d815d562d3cfa955",
        "baseFeePerGas": "0x4b85a0fcd",
        "uncles": [],
        "withdrawals": [
            {
                "address": "0x80b2886b8ef418cce2564ad16ffec4bfbff13787",
                "amount": "0xdbdc02",
                "index": "0xac512e",
                "validatorIndex": "0x932ef"
            }
        ],
        "withdrawalsRoot": "0xedaa8043cdce8101ef827863eb0d808277d200a7a0ee77961934bd235dcb82c6"
    }"#,
    )
}

#[test]
fn eth_get_logs_normalization() {
    check_response_normalization::<Vec<LogEntry>>(
        r#"[
        {
            "removed": false,
            "blockHash": "0x8436209a391f7bc076123616ecb229602124eb6c1007f5eae84df8e098885d3c",
            "blockNumber": "0x3ca487",
            "data": "0x000000000000000000000000000000000000000000000000002386f26fc10000",
            "logIndex": "0x27",
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x000000000000000000000000dd2851cdd40ae6536831558dd46db62fac7a844d",
                "0x09efcdab00000000000100000000000000000000000000000000000000000000"
            ],
            "transactionHash": "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3",
            "transactionIndex": "0x22"
        },
        {
            "transactionHash": "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2",
            "logIndex": "0x1d",
            "blockHash": "0x4205f2436ee7a90aa87a88ae6914ec6860971360995f463602a40803bff98f4d",
            "blockNumber": "0x3c6f2f",
            "data": "0x000000000000000000000000000000000000000000000000002386f26fc10000",
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "removed": false,
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x000000000000000000000000dd2851cdd40ae6536831558dd46db62fac7a844d",
                "0x0000000000000000000000000000000000000000000000000000000000000000"
            ],
            "transactionIndex": "0x1f"
        }
    ]"#,
        r#"[
        {
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "blockHash": "0x4205f2436ee7a90aa87a88ae6914ec6860971360995f463602a40803bff98f4d",
            "blockNumber": "0x3c6f2f",
            "data": "0x000000000000000000000000000000000000000000000000002386f26fc10000",
            "logIndex": "0x1d",
            "removed": false,
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x000000000000000000000000dd2851cdd40ae6536831558dd46db62fac7a844d",
                "0x0000000000000000000000000000000000000000000000000000000000000000"
            ],
            "transactionHash": "0xf1ac37d920fa57d9caeebc7136fea591191250309ffca95ae0e8a7739de89cc2",
            "transactionIndex": "0x1f"
        },
        {
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "blockHash": "0x8436209a391f7bc076123616ecb229602124eb6c1007f5eae84df8e098885d3c",
            "blockNumber": "0x3ca487",
            "data": "0x000000000000000000000000000000000000000000000000002386f26fc10000",
            "logIndex": "0x27",
            "removed": false,
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x000000000000000000000000dd2851cdd40ae6536831558dd46db62fac7a844d",
                "0x09efcdab00000000000100000000000000000000000000000000000000000000"
            ],
            "transactionHash": "0x705f826861c802b407843e99af986cfde8749b669e5e0a5a150f4350bcaa9bc3",
            "transactionIndex": "0x22"
        }
    ]"#,
    );
}

#[test]
fn eth_get_logs_order_normalization() {
    use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
    use rand::prelude::SliceRandom;
    const LOGS: &str = r#"[
        {
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x000000000000000000000000dd4f158536c7f8c07736d04b7cc805f8d59b241a",
                "0x1d5ad0eae83b042ac243598bde6c4eea3e5dff125e2e2057476a3010e4020000"
            ],
            "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "blockNumber": "0x3f50c8",
            "transactionHash": "0xcf36dcf9e4b42954b35e9b7deb20f3c1c481c3ec9d66b538a58b6838d5fdc0cc",
            "transactionIndex": "0x5",
            "blockHash": "0x9ee5966f424dcae471daa0d669354a5fc1b7387303b5a623e615d1bf1540e6ad",
            "logIndex": "0x10",
            "removed": false
        },
        {
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x000000000000000000000000dd4f158536c7f8c07736d04b7cc805f8d59b241a",
                "0x1d882d15b09f8e81e29606305f5fefc5eff3e2309620a3557ecae39d62020000"
            ],
            "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "blockNumber": "0x3f50c8",
            "transactionHash": "0xcf36dcf9e4b42954b35e9b7deb20f3c1c481c3ec9d66b538a58b6838d5fdc0cc",
            "transactionIndex": "0x5",
            "blockHash": "0x9ee5966f424dcae471daa0d669354a5fc1b7387303b5a623e615d1bf1540e6ad",
            "logIndex": "0x11",
            "removed": false
        },
        {
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x000000000000000000000000dd4f158536c7f8c07736d04b7cc805f8d59b241a",
                "0x1d5ad0eae83b042ac243598bde6c4eea3e5dff125e2e2057476a3010e4020000"
            ],
            "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "blockNumber": "0x3f50f5",
            "transactionHash": "0x17a1b0272352607d36cddf6ad8e5883ddef5ba8235a4cf6ed2b4924b8d702756",
            "transactionIndex": "0xa",
            "blockHash": "0xd9daa1bea7a56809fd88a6d14bdd21820a5e9565bf75f307c413bf47b86e649f",
            "logIndex": "0x10",
            "removed": false
        },
        {
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x000000000000000000000000dd4f158536c7f8c07736d04b7cc805f8d59b241a",
                "0x1d882d15b09f8e81e29606305f5fefc5eff3e2309620a3557ecae39d62020000"
            ],
            "data": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "blockNumber": "0x3f50f5",
            "transactionHash": "0x17a1b0272352607d36cddf6ad8e5883ddef5ba8235a4cf6ed2b4924b8d702756",
            "transactionIndex": "0xa",
            "blockHash": "0xd9daa1bea7a56809fd88a6d14bdd21820a5e9565bf75f307c413bf47b86e649f",
            "logIndex": "0x11",
            "removed": false
        },
        {
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x000000000000000000000000dd4f158536c7f8c07736d04b7cc805f8d59b241a",
                "0x1d5ad0eae83b042ac243598bde6c4eea3e5dff125e2e2057476a3010e4020000"
            ],
            "data": "0x000000000000000000000000000000000000000000000000002386f26fc10000",
            "blockNumber": "0x3f50f5",
            "transactionHash": "0x19a258899d3943d114f62d749521d1a3d3d88f0c9b3e2b45b9cd0c4c66fcda68",
            "transactionIndex": "0xc",
            "blockHash": "0xd9daa1bea7a56809fd88a6d14bdd21820a5e9565bf75f307c413bf47b86e649f",
            "logIndex": "0x13",
            "removed": false
        },
        {
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x000000000000000000000000dd4f158536c7f8c07736d04b7cc805f8d59b241a",
                "0x1d882d15b09f8e81e29606305f5fefc5eff3e2309620a3557ecae39d62020000"
            ],
            "data": "0x000000000000000000000000000000000000000000000000002386f26fc10000",
            "blockNumber": "0x3f50f5",
            "transactionHash": "0x19a258899d3943d114f62d749521d1a3d3d88f0c9b3e2b45b9cd0c4c66fcda68",
            "transactionIndex": "0xc",
            "blockHash": "0xd9daa1bea7a56809fd88a6d14bdd21820a5e9565bf75f307c413bf47b86e649f",
            "logIndex": "0x14",
            "removed": false
        }
    ]"#;
    let rng = &mut reproducible_rng();
    let original_logs: Vec<LogEntry> = serde_json::from_str(LOGS).unwrap();
    assert!(original_logs.len() > 1);
    let suffled_logs = {
        let mut logs = original_logs.clone();
        logs.shuffle(rng);
        logs
    };

    check_response_normalization::<Vec<LogEntry>>(
        &serde_json::to_string(&original_logs).unwrap(),
        &serde_json::to_string(&suffled_logs).unwrap(),
    )
}

#[test]
fn should_deserialize_event_data_from_str() {
    let data = "0x0000000000000000000000000000000000000000000000000163474a06d41ff6";
    let parsed_data = Data::from_str(data);
    let expected_data = Data(vec![
        0_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 99, 71, 74,
        6, 212, 31, 246,
    ]);

    assert_eq!(parsed_data, Ok(expected_data));
}

#[test]
fn transaction_receipt_normalization() {
    check_response_normalization::<TransactionReceipt>(
        r#"{
        "type": "0x2",
        "blockHash": "0x82005d2f17b251900968f01b0ed482cb49b7e1d797342bc504904d442b64dbe4",
        "transactionHash": "0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d",
        "logs": [],
        "contractAddress": null,
        "effectiveGasPrice": "0xfefbee3e",
        "cumulativeGasUsed": "0x8b2e10",
        "from": "0x1789f79e95324a47c5fd6693071188e82e9a3558",
        "gasUsed": "0x5208",
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "status": "0x1",
        "to": "0xdd2851cdd40ae6536831558dd46db62fac7a844d",
        "transactionIndex": "0x32",
        "blockNumber": "0x4132ec"
    }"#,
        r#"{
        "transactionHash": "0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d",
        "blockHash": "0x82005d2f17b251900968f01b0ed482cb49b7e1d797342bc504904d442b64dbe4",
        "blockNumber": "0x4132ec",
        "logs": [],
        "contractAddress": null,
        "effectiveGasPrice": "0xfefbee3e",
        "cumulativeGasUsed": "0x8b2e10",
        "from": "0x1789f79e95324a47c5fd6693071188e82e9a3558",
        "gasUsed": "0x5208",
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "status": "0x1",
        "to": "0xdd2851cdd40ae6536831558dd46db62fac7a844d",
        "transactionIndex": "0x32",
        "type": "0x2"
    }"#,
    );
}

#[test]
fn http_metrics_should_aggregate_retry_counts() {
    use super::metrics::HttpMetrics;

    let mut metrics = HttpMetrics::default();

    for count in [0, 1, 2, 3, 0, 0, 2, 5, 100, 200, 300] {
        metrics.observe_retry_count("eth_test".to_string(), count);
    }

    for count in [0, 1, 2, 3] {
        metrics.observe_retry_count("eth_test2".to_string(), count);
    }

    assert_eq!(3, metrics.count_retries_in_bucket("eth_test", 0));
    assert_eq!(1, metrics.count_retries_in_bucket("eth_test", 1));
    assert_eq!(2, metrics.count_retries_in_bucket("eth_test", 2));
    assert_eq!(1, metrics.count_retries_in_bucket("eth_test", 3));
    assert_eq!(0, metrics.count_retries_in_bucket("eth_test", 4));
    assert_eq!(1, metrics.count_retries_in_bucket("eth_test", 5));
    assert_eq!(1, metrics.count_retries_in_bucket("eth_test", 5));
    assert_eq!(3, metrics.count_retries_in_bucket("eth_test", 100));
    assert_eq!(3, metrics.count_retries_in_bucket("eth_test", 200));
    assert_eq!(3, metrics.count_retries_in_bucket("eth_test", 300));
    assert_eq!(3, metrics.count_retries_in_bucket("eth_test", usize::MAX));

    assert_eq!(1, metrics.count_retries_in_bucket("eth_test2", 0));
    assert_eq!(1, metrics.count_retries_in_bucket("eth_test2", 1));
    assert_eq!(1, metrics.count_retries_in_bucket("eth_test2", 2));
    assert_eq!(1, metrics.count_retries_in_bucket("eth_test2", 3));
    assert_eq!(0, metrics.count_retries_in_bucket("eth_test2", 100));

    assert_eq!(0, metrics.count_retries_in_bucket("eth_unknown", 0));

    let mut encoder = ic_metrics_encoder::MetricsEncoder::new(Vec::new(), 12346789);
    metrics.encode(&mut encoder).unwrap();
    let bytes = encoder.into_inner();
    let metrics_text = String::from_utf8(bytes).unwrap();

    assert_eq!(
        metrics_text.trim(),
        r#"
# HELP cketh_eth_rpc_call_retry_count The number of ETH RPC call retries by method.
# TYPE cketh_eth_rpc_call_retry_count histogram
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="0"} 3 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="1"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="2"} 6 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="3"} 7 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="4"} 7 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="5"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="6"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="7"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="8"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="9"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="10"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="11"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="12"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="13"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="14"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="15"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="16"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="17"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="18"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="19"} 8 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test",le="+Inf"} 11 12346789
cketh_eth_rpc_call_retry_count_sum{method="eth_test"} 613 12346789
cketh_eth_rpc_call_retry_count_count{method="eth_test"} 11 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="0"} 1 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="1"} 2 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="2"} 3 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="3"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="4"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="5"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="6"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="7"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="8"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="9"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="10"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="11"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="12"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="13"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="14"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="15"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="16"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="17"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="18"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="19"} 4 12346789
cketh_eth_rpc_call_retry_count_bucket{method="eth_test2",le="+Inf"} 4 12346789
cketh_eth_rpc_call_retry_count_sum{method="eth_test2"} 6 12346789
cketh_eth_rpc_call_retry_count_count{method="eth_test2"} 4 12346789
"#
        .trim()
    );
}

#[test]
fn check_get_logs_param_single_topic_serialization() {
    let topic =
        &hex_literal::hex!("257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435");
    let p = GetLogsParam {
        from_block: BlockNumber::new(1200).into(),
        to_block: BlockNumber::new(1301).into(),
        address: vec![Address::from_str("0x80b2886b8ef418cce2564ad16ffec4bfbff13787").unwrap()],
        topics: vec![FixedSizeData(*topic).into()],
    };
    assert_eq!(
        serde_json::to_value(p).unwrap(),
        serde_json::json!({
            "fromBlock":"0x4b0",
            "toBlock":"0x515",
            "address":["0x80b2886b8ef418cce2564ad16ffec4bfbff13787"],
            "topics":["0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435"]
        })
    );
}

#[test]
fn check_get_logs_param_multiple_topics_serialization() {
    let topic =
        &hex_literal::hex!("257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435");
    let p = GetLogsParam {
        from_block: BlockNumber::new(1200).into(),
        to_block: BlockNumber::new(1301).into(),
        address: vec![Address::from_str("0x80b2886b8ef418cce2564ad16ffec4bfbff13787").unwrap()],
        topics: vec![
            FixedSizeData(*topic).into(),
            vec![
                FixedSizeData(
                    (&Address::from_str("0x1c7d4b196cb0c7b01d743fbc6116a902379c7238").unwrap())
                        .into(),
                ),
                FixedSizeData(
                    (&Address::from_str("0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34").unwrap())
                        .into(),
                ),
            ]
            .into(),
        ],
    };
    assert_eq!(
        serde_json::to_value(p).unwrap(),
        serde_json::json!({
            "fromBlock":"0x4b0",
            "toBlock":"0x515",
            "address":["0x80b2886b8ef418cce2564ad16ffec4bfbff13787"],
            "topics":[
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                [
                "0x0000000000000000000000001c7d4b196cb0c7b01d743fbc6116a902379c7238",
                "0x000000000000000000000000b44b5e756a894775fc32eddf3314bb1b1944dc34"
                ]
            ]
        })
    );
}
