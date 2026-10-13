use crate::flow::DepositCkEthParams;
use crate::response::{
    block_response, default_erc20_signed_eip_1559_transaction, default_signed_eip_1559_transaction,
    empty_logs, encode_transaction, fee_history, fee_history_json_value, hash_transaction,
    send_raw_transaction_response, transaction_receipt,
};
use crate::{
    DEFAULT_BLOCK_NUMBER, DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION,
    DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE, DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH,
    DEFAULT_WITHDRAWAL_TRANSACTION, DEFAULT_WITHDRAWAL_TRANSACTION_HASH,
};
use evm_rpc_types::{FeeHistory, Nat256};
use ic_cketh_minter::numeric::{GasAmount, Wei};
use ic_cketh_minter::tx::estimate_transaction_fee;
use serde_json::json;

#[test]
fn should_use_meaningful_constants() {
    let (default_tx, default_sig) = default_signed_eip_1559_transaction();
    assert_eq!(
        encode_transaction(default_tx.clone(), default_sig),
        DEFAULT_WITHDRAWAL_TRANSACTION
    );
    assert_eq!(
        format!("{:?}", hash_transaction(default_tx, default_sig)),
        DEFAULT_WITHDRAWAL_TRANSACTION_HASH
    );

    let (default_tx, default_sig) = default_erc20_signed_eip_1559_transaction();
    assert_eq!(
        encode_transaction(default_tx.clone(), default_sig),
        DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION
    );
    assert_eq!(
        format!("{:?}", hash_transaction(default_tx, default_sig)),
        DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH
    );
}

#[test]
fn should_have_meaningful_ckerc20_withdrawal_transaction_fee() {
    fn convert_fee_history(fee_history: alloy_rpc_types_eth::FeeHistory) -> FeeHistory {
        FeeHistory {
            oldest_block: Nat256::from(fee_history.oldest_block),
            base_fee_per_gas: fee_history
                .base_fee_per_gas
                .into_iter()
                .map(Nat256::from)
                .collect(),
            gas_used_ratio: fee_history.gas_used_ratio,
            reward: fee_history
                .reward
                .unwrap_or_default()
                .into_iter()
                .map(|rewards| rewards.into_iter().map(Nat256::from).collect())
                .collect(),
        }
    }

    let fee_history_core: alloy_rpc_types_eth::FeeHistory =
        serde_json::from_value(fee_history_json_value()).unwrap();
    let fee_history = convert_fee_history(fee_history_core);

    let ckerc20_tx_price = estimate_transaction_fee(&fee_history).map(|gas_fee| {
        gas_fee
            .to_price(GasAmount::new(65_000))
            .max_transaction_fee()
    });

    assert_eq!(
        ckerc20_tx_price,
        Ok(Wei::from(DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE))
    );
}

/// The mocked EVM RPC serves these fixtures as the literal HTTP body the EVM RPC canister parses,
/// and the minter compares `max_response_bytes` against that body's length, so their serialization
/// is part of what the tests assert rather than an implementation detail of whichever library
/// produces it.
#[test]
fn should_serialize_the_mocked_responses_as_the_evm_rpc_expects() {
    assert_eq!(
        serde_json::to_value(block_response(DEFAULT_BLOCK_NUMBER)).unwrap(),
        json!({
            "baseFeePerGas": "0x3e4f64de7",
            "difficulty": "0x0",
            "extraData": "0x",
            "gasLimit": "0x0",
            "gasUsed": "0x0",
            "hash": "0x82005d2f17b251900968f01b0ed482cb49b7e1d797342bc504904d442b64dbe4",
            "logsBloom": "0x93ab55f727ed7f7f7ffa47b6e520df221dce71f165d0f470a71d051cfd36ab0ad4015725f16938bb3798fb4fc58fd3d95e23a8689ba06ae3ce16ffba95afbedcfece0dcdce2f1e7f6eb6573a92c5a8feadec65bd2655296a5ff07ecee9ae5b2abfddd7b2877ed3f5ac7bf4d95061bd5d6f8e37fb87995ea0904d58d6d8cbb86f9fef7af0364e834154dbb74a2ff7c6355a43ac1d73d9bcf9f5a9ed756492fffdfbffd1e7ffdf7f274e36fbc4e9e3bdf9e56fdad089dd582fd7e5fc733fcc63753762f4f7c49dbffeb5a196ae6a3fddd749f1f26effedd1df23ad5d23b9d2fc2f19ffa5513504a53155d477f1f155b966ddadfa195b4c6bdafb9df97ff065debf",
            "miner": "0x1f9090aae28b8a3dceadf281b0f12828e676c326",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "nonce": "0x0000000000000000",
            "number": "0x4132ec",
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "size": "0x19eea",
            "stateRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "timestamp": "0x0",
            "totalDifficulty": "0xc70d815d562d3cfa955",
            "transactions": [],
            "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            "uncles": []
        })
    );
    assert_eq!(
        serde_json::to_value(transaction_receipt(
            DEFAULT_WITHDRAWAL_TRANSACTION_HASH.to_string()
        ))
        .unwrap(),
        json!({
            "blockHash": "0x82005d2f17b251900968f01b0ed482cb49b7e1d797342bc504904d442b64dbe4",
            "blockNumber": "0x4132ec",
            "contractAddress": null,
            "cumulativeGasUsed": "0x8b2e10",
            "effectiveGasPrice": "0xfefbee3e",
            "from": "0x1789f79e95324a47c5fd6693071188e82e9a3558",
            "gasUsed": "0x5208",
            "logs": [],
            "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "status": "0x1",
            "to": "0x221e931fbfcb9bd54ddd26ce6f5e29e98add01c0",
            "transactionHash": "0xa31221e733b030eb72eeb6973593a4d920c2c3391433429eed3c16b8f4f3ba7a",
            "transactionIndex": "0x32",
            "type": "0x2"
        })
    );
    assert_eq!(
        serde_json::to_value(fee_history()).unwrap(),
        json!({
            "baseFeePerGas": [
                "0x39fc781e8",
                "0x3ab9a6343",
                "0x3a07c507e",
                "0x39814c872",
                "0x391ea51f7",
                "0x3aae23831"
            ],
            "gasUsedRatio": [
                0.0,
                0.22033613333333332,
                0.8598215666666666,
                0.5756615333333334,
                0.3254294
            ],
            "oldestBlock": "0x1134b57",
            "reward": [
                [
                    "0x25ed41c"
                ],
                [
                    "0x0"
                ],
                [
                    "0x0"
                ],
                [
                    "0x479ace"
                ],
                [
                    "0x0"
                ]
            ]
        })
    );
    assert_eq!(
        serde_json::to_value(DepositCkEthParams::default().to_log_entry()).unwrap(),
        json!({
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "blockHash": "0x79cfe76d69337dae199e32c2b6b3d7c2668bfe71a05f303f95385e70031b9ef8",
            "blockNumber": "0x9",
            "data": "0x0000000000000000000000000000000000000000000000000163474a06d41ff6",
            "logIndex": "0x24",
            "removed": false,
            "topics": [
                "0x257e057bb61920d8d0ed2cb7b720ac7f9c513cd1110bc9fa543079154f45f435",
                "0x00000000000000000000000055654e7405fcb336386ea8f36954a211b2cda764",
                "0x0a01f79d0000000000fe01000000000000000000000000000000000000000000"
            ],
            "transactionHash": "0xcfa48c44dc89d18a898a42b4a5b02b6847a3c2019507d5571a481751c7a2f353",
            "transactionIndex": "0x33"
        })
    );
    assert_eq!(
        serde_json::to_value(send_raw_transaction_response()).unwrap(),
        json!("0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d")
    );
    assert_eq!(serde_json::to_value(empty_logs()).unwrap(), json!([]));
}
