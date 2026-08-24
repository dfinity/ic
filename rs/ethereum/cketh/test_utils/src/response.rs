use crate::{
    DEFAULT_BLOCK_HASH, DEFAULT_BLOCK_NUMBER, DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS,
    EFFECTIVE_GAS_PRICE, GAS_USED, MINTER_ADDRESS, USDC_ERC20_CONTRACT_ADDRESS,
};
use serde_json::{Value, json};
use std::str::FromStr;

pub fn empty_logs() -> Vec<alloy_rpc_types_eth::Log> {
    vec![]
}

/// Encode a deployless balance-batcher `eth_call` response: the `balances` as a flat
/// concatenation of 32-byte words, exactly what the batcher's `RETURN` yields — one word per
/// scanned `(address, token)` pair, in call order.
///
/// Encoded as a flat list of `Uint` tokens (not `Token::Array`, which would prepend an ABI
/// offset+length header the batcher does not emit).
pub fn balance_scan_response(balances: &[u128]) -> String {
    use ethers_core::abi::{Token, encode};
    use ethers_core::types::U256;
    let words = encode(
        &balances
            .iter()
            .map(|&balance| Token::Uint(U256::from(balance)))
            .collect::<Vec<_>>(),
    );
    format!("0x{}", hex::encode(words))
}

pub fn multi_logs_for_single_transaction<Entry: Clone + Into<alloy_rpc_types_eth::Log>>(
    log_entry: Entry,
    num_logs: usize,
) -> Vec<alloy_rpc_types_eth::Log> {
    let mut logs = Vec::with_capacity(num_logs);
    for log_index in 0..num_logs {
        let mut log = log_entry.clone().into();
        log.log_index = Some(log_index as u64);
        logs.push(log);
    }
    logs
}

pub fn send_raw_transaction_response() -> alloy_primitives::TxHash {
    "0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d"
        .parse()
        .unwrap()
}

pub fn block_response(block_number: u64) -> alloy_rpc_types_eth::Block {
    use alloy_primitives::U256;

    alloy_rpc_types_eth::Block {
        header: alloy_rpc_types_eth::Header {
            hash: DEFAULT_BLOCK_HASH.parse().unwrap(),
            inner: alloy_consensus::Header {
                number: block_number,
                base_fee_per_gas: Some(0x3e4f64de7),
                logs_bloom: "0x93ab55f727ed7f7f7ffa47b6e520df221dce71f165d0f470a71d051cfd36ab0ad4015725f16938bb3798fb4fc58fd3d95e23a8689ba06ae3ce16ffba95afbedcfece0dcdce2f1e7f6eb6573a92c5a8feadec65bd2655296a5ff07ecee9ae5b2abfddd7b2877ed3f5ac7bf4d95061bd5d6f8e37fb87995ea0904d58d6d8cbb86f9fef7af0364e834154dbb74a2ff7c6355a43ac1d73d9bcf9f5a9ed756492fffdfbffd1e7ffdf7f274e36fbc4e9e3bdf9e56fdad089dd582fd7e5fc733fcc63753762f4f7c49dbffeb5a196ae6a3fddd749f1f26effedd1df23ad5d23b9d2fc2f19ffa5513504a53155d477f1f155b966ddadfa195b4c6bdafb9df97ff065debf".parse().unwrap(),
                beneficiary: "0x1f9090aae28b8a3dceadf281b0f12828e676c326".parse().unwrap(),
                ..Default::default()
            },
            total_difficulty: Some(U256::from(0xc70d815d562d3cfa955_u128)),
            size: Some(U256::from(0x19eea)),
        },
        ..Default::default()
    }
}

pub fn transaction_receipt(transaction_hash: String) -> alloy_rpc_types_eth::TransactionReceipt {
    let json_value = json!({
        "blockHash": DEFAULT_BLOCK_HASH,
        "blockNumber": format!("{:#x}", DEFAULT_BLOCK_NUMBER),
        "contractAddress": null,
        "cumulativeGasUsed": "0x8b2e10",
        "effectiveGasPrice": format!("{:#x}", EFFECTIVE_GAS_PRICE),
        "from": "0x1789f79e95324a47c5fd6693071188e82e9a3558",
        "gasUsed": format!("{:#x}", GAS_USED),
        "logs": [],
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "status": format!("{:#x}", 1_u8),
        "to": "0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0",
        "transactionHash": transaction_hash,
        "transactionIndex": "0x32",
        "type": "0x2"
    });
    serde_json::from_value(json_value).expect("BUG: invalid transaction receipt")
}

pub fn transaction_count_response(count: u32) -> String {
    format!("{count:#x}")
}

pub fn fee_history() -> alloy_rpc_types_eth::FeeHistory {
    let json_value = fee_history_json_value();
    serde_json::from_value(json_value).expect("BUG: invalid fee history")
}

pub fn fee_history_json_value() -> Value {
    json!({
        "oldestBlock": "0x1134b57",
        "reward": [
            ["0x25ed41c"],
            ["0x0"],
            ["0x0"],
            ["0x479ace"],
            ["0x0"]
        ],
        "baseFeePerGas": [
            "0x39fc781e8",
            "0x3ab9a6343",
            "0x3a07c507e",
            "0x39814c872",
            "0x391ea51f7",
            "0x3aae23831"
        ],
        "gasUsedRatio": [
            0,
            0.22033613333333332,
            0.8598215666666666,
            0.5756615333333334,
            0.3254294
        ]
    })
}

pub fn default_signed_eip_1559_transaction()
-> (alloy_consensus::TxEip1559, alloy_primitives::Signature) {
    let tx = alloy_consensus::TxEip1559 {
        chain_id: 1,
        nonce: 0,
        gas_limit: 21_000,
        max_fee_per_gas: 33_003_708_258,
        max_priority_fee_per_gas: 1_500_000_000,
        to: alloy_primitives::TxKind::Call(DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS.parse().unwrap()),
        value: alloy_primitives::U256::from(99_306_922_126_581_990_u64),
        access_list: Default::default(),
        input: alloy_primitives::Bytes::new(),
    };
    let sig = alloy_primitives::Signature::new(
        alloy_primitives::U256::from_str(
            "78378320896144165623306772901883835881146801392437857873186382435197931981331",
        )
        .unwrap(),
        alloy_primitives::U256::from_str(
            "11573774696968647626294885286453366440757932248598190533848223153778081228091",
        )
        .unwrap(),
        true,
    );
    (tx, sig)
}

pub fn default_erc20_signed_eip_1559_transaction()
-> (alloy_consensus::TxEip1559, alloy_primitives::Signature) {
    let tx = alloy_consensus::TxEip1559 {
        chain_id: 1,
        nonce: 0,
        gas_limit: 65_000,
        max_fee_per_gas: 33_003_708_258,
        max_priority_fee_per_gas: 1_500_000_000,
        to: alloy_primitives::TxKind::Call(USDC_ERC20_CONTRACT_ADDRESS.parse().unwrap()),
        value: alloy_primitives::U256::ZERO,
        access_list: Default::default(),
        input: alloy_primitives::Bytes::from_str("0xa9059cbb000000000000000000000000221e931fbfcb9bd54ddd26ce6f5e29e98add01c000000000000000000000000000000000000000000000000000000000001e8480").unwrap(),
    };
    let sig = alloy_primitives::Signature::from_scalars_and_parity(
        "0xda4f476ede0aaf7da633371a938d5e2525a65a23699b55761779871a313f8cb3"
            .parse()
            .unwrap(),
        "0x45833d409eba50e3e9b145d04ea294ee791c14465503818f8b325a881938ddc1"
            .parse()
            .unwrap(),
        false,
    );
    (tx, sig)
}

pub fn minter_address() -> alloy_primitives::Address {
    MINTER_ADDRESS.parse().unwrap()
}

pub fn encode_transaction(
    tx: alloy_consensus::TxEip1559,
    sig: alloy_primitives::Signature,
) -> String {
    use alloy_eips::eip2718::Encodable2718;
    format!(
        "0x{}",
        hex::encode(sign_transaction(tx, sig).encoded_2718())
    )
}

/// Decodes the payload a signed EIP-1559 transaction is broadcast as, so that a transaction the
/// minter built and signed itself can be checked against an independent decoder.
///
/// # Panics
/// * if `tx` is not the payload of a signed EIP-1559 transaction.
pub fn decode_transaction(tx: &str) -> alloy_consensus::Signed<alloy_consensus::TxEip1559> {
    use alloy_consensus::TxEnvelope;
    use alloy_eips::eip2718::Decodable2718;

    let raw_bytes =
        hex::decode(tx.trim_start_matches("0x")).expect("BUG: transaction is not hex-encoded");
    match TxEnvelope::decode_2718(&mut raw_bytes.as_slice())
        .expect("BUG: failed to deserialize sent ETH transaction")
    {
        TxEnvelope::Eip1559(signed) => signed,
        transaction => panic!("BUG: unexpected sent ETH transaction type {transaction:?}"),
    }
}

pub fn hash_transaction(
    tx: alloy_consensus::TxEip1559,
    sig: alloy_primitives::Signature,
) -> alloy_primitives::TxHash {
    *sign_transaction(tx, sig).hash()
}

fn sign_transaction(
    tx: alloy_consensus::TxEip1559,
    sig: alloy_primitives::Signature,
) -> alloy_consensus::Signed<alloy_consensus::TxEip1559> {
    use alloy_consensus::SignableTransaction;
    tx.into_signed(sig)
}
