use crate::{
    DEFAULT_BLOCK_HASH, DEFAULT_BLOCK_NUMBER, DEFAULT_DEPOSIT_BLOCK_NUMBER,
    DEFAULT_DEPOSIT_LOG_INDEX, DEFAULT_ERC20_DEPOSIT_LOG_INDEX,
    DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS, EFFECTIVE_GAS_PRICE, GAS_USED, HEADER_SIZE_LIMIT,
    MINTER_ADDRESS, RECEIVED_ERC20_EVENT_TOPIC, RECEIVED_ETH_EVENT_TOPIC,
    USDC_ERC20_CONTRACT_ADDRESS,
};
use ethers_core::abi::AbiDecode;
use ethers_core::utils::rlp;
use ic_ethereum_types::Address;
use serde_json::{json, Value};
use std::str::FromStr;

#[derive(Clone)]
pub struct EthLogEntry {
    pub encoded_principal: String,
    pub amount: u64,
    pub from_address: Address,
    pub transaction_hash: String,
}

impl From<EthLogEntry> for ethers_core::types::Log {
    fn from(log_entry: EthLogEntry) -> Self {
        let amount_hex = format!("0x{:0>64x}", log_entry.amount);
        let topics = vec![
            RECEIVED_ETH_EVENT_TOPIC.to_string(),
            format!(
                "0x000000000000000000000000{}",
                hex::encode(log_entry.from_address.as_ref())
            ),
            log_entry.encoded_principal,
        ];

        let json_value = json!({
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "blockHash": "0x79cfe76d69337dae199e32c2b6b3d7c2668bfe71a05f303f95385e70031b9ef8",
            "blockNumber": format!("0x{:x}", DEFAULT_DEPOSIT_BLOCK_NUMBER),
            "data": amount_hex,
            "logIndex": format!("0x{:x}", DEFAULT_DEPOSIT_LOG_INDEX),
            "removed": false,
            "topics": topics,
            "transactionHash": log_entry.transaction_hash,
            "transactionIndex": "0x33"
        });
        serde_json::from_value(json_value).expect("BUG: invalid log entry")
    }
}

pub struct Erc20LogEntry {
    pub encoded_principal: String,
    pub amount: u64,
    pub from_address: Address,
    pub transaction_hash: String,
    pub erc20_contract_address: Address,
}

impl From<Erc20LogEntry> for ethers_core::types::Log {
    fn from(log_entry: Erc20LogEntry) -> Self {
        let amount_hex = format!("0x{:0>64x}", log_entry.amount);
        let topics = vec![
            RECEIVED_ERC20_EVENT_TOPIC.to_string(),
            format!(
                "0x000000000000000000000000{}",
                hex::encode(log_entry.erc20_contract_address.as_ref()),
            ),
            format!(
                "0x000000000000000000000000{}",
                hex::encode(log_entry.from_address.as_ref())
            ),
            log_entry.encoded_principal,
        ];

        let json_value = json!({
            "address": "0xb44b5e756a894775fc32eddf3314bb1b1944dc34",
            "blockHash": "0x79cfe76d69337dae199e32c2b6b3d7c2668bfe71a05f303f95385e70031b9ef8",
            "blockNumber": format!("0x{:x}", DEFAULT_DEPOSIT_BLOCK_NUMBER),
            "data": amount_hex,
            "logIndex": format!("0x{:x}", DEFAULT_ERC20_DEPOSIT_LOG_INDEX),
            "removed": false,
            "topics": topics,
            "transactionHash": log_entry.transaction_hash,
            "transactionIndex": "0x33"
        });
        serde_json::from_value(json_value).expect("BUG: invalid log entry")
    }
}

pub fn empty_logs() -> Vec<ethers_core::types::Log> {
    vec![]
}

pub fn multi_logs_for_single_transaction(
    log_entry: EthLogEntry,
    num_logs: usize,
) -> Vec<ethers_core::types::Log> {
    let mut logs = Vec::with_capacity(num_logs);
    for log_index in 0..num_logs {
        let mut log = ethers_core::types::Log::from(log_entry.clone());
        log.log_index = Some(log_index.into());
        logs.push(log);
    }
    logs
}

pub fn all_eth_get_logs_response_size_estimates() -> Vec<u64> {
    vec![
        100 + HEADER_SIZE_LIMIT,
        2048 + HEADER_SIZE_LIMIT,
        4096 + HEADER_SIZE_LIMIT,
        8192 + HEADER_SIZE_LIMIT,
        16_384 + HEADER_SIZE_LIMIT,
        32_768 + HEADER_SIZE_LIMIT,
        65_536 + HEADER_SIZE_LIMIT,
        131_072 + HEADER_SIZE_LIMIT,
        262_144 + HEADER_SIZE_LIMIT,
        524_288 + HEADER_SIZE_LIMIT,
        1_048_576 + HEADER_SIZE_LIMIT,
        2_000_000,
    ]
}

pub fn send_raw_transaction_response() -> ethers_core::types::TxHash {
    ethers_core::types::TxHash::decode_hex(
        "0x0e59bd032b9b22aca5e2784e4cf114783512db00988c716cf17a1cc755a0a93d",
    )
    .unwrap()
}

pub fn block_response(block_number: u64) -> ethers_core::types::Block<ethers_core::types::TxHash> {
    ethers_core::types::Block::<ethers_core::types::TxHash> {
        number: Some(block_number.into()),
        base_fee_per_gas: Some(0x3e4f64de7_u64.into()),
        ..Default::default()
    }
}

pub fn transaction_receipt(transaction_hash: String) -> ethers_core::types::TransactionReceipt {
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
    format!("{:#x}", count)
}

pub fn fee_history() -> ethers_core::types::FeeHistory {
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

pub fn default_signed_eip_1559_transaction() -> (
    ethers_core::types::Eip1559TransactionRequest,
    ethers_core::types::Signature,
) {
    let tx = ethers_core::types::Eip1559TransactionRequest::new()
        .from(minter_address())
        .to(DEFAULT_WITHDRAWAL_DESTINATION_ADDRESS
            .parse::<ethers_core::types::NameOrAddress>()
            .unwrap())
        .nonce(0_u64)
        .value(99_306_922_126_581_990_u64)
        .gas(21_000_u64)
        .max_priority_fee_per_gas(1_500_000_000_u64)
        .max_fee_per_gas(33_003_708_258_u64)
        .chain_id(1_u64);
    let sig = ethers_core::types::Signature {
        r: ethers_core::types::U256::from_dec_str(
            "80728915039673634151963281987194499535727562641034879173530654129915839382129",
        )
        .unwrap(),
        s: ethers_core::types::U256::from_dec_str(
            "54281815563936592133007646348951747532427232100340298742740287107883437683286",
        )
        .unwrap(),
        v: 1,
    };
    (tx, sig)
}

pub fn default_erc20_signed_eip_1559_transaction() -> (
    ethers_core::types::Eip1559TransactionRequest,
    ethers_core::types::Signature,
) {
    let tx = ethers_core::types::Eip1559TransactionRequest::new()
        .from(minter_address())
        .to(USDC_ERC20_CONTRACT_ADDRESS
            .parse::<ethers_core::types::NameOrAddress>()
            .unwrap())
        .nonce(0_u64)
        .value(0_u64)
        .gas(65_000_u64)
        .data(hex::decode(&"0xa9059cbb000000000000000000000000221e931fbfcb9bd54ddd26ce6f5e29e98add01c000000000000000000000000000000000000000000000000000000000001e8480"[2..]).unwrap())
        .max_priority_fee_per_gas(1_500_000_000_u64)
        .max_fee_per_gas(33_003_708_258_u64)
        .chain_id(1_u64);
    let sig = ethers_core::types::Signature {
        r: ethers_core::types::U256::from_str_radix(
            "bb694aec6175b489523a55d5fce39452368e97096d4afa2cdcc35cf2d805152f",
            16,
        )
        .unwrap(),
        s: ethers_core::types::U256::from_str_radix(
            "0112b26a028af84dd397d23549844efdaf761d90cdcfdbe6c3608239648a85a3",
            16,
        )
        .unwrap(),
        v: 0,
    };
    (tx, sig)
}

fn minter_address() -> [u8; 20] {
    ethers_core::types::Bytes::from_str(MINTER_ADDRESS)
        .unwrap()
        .to_vec()
        .try_into()
        .unwrap()
}

pub fn encode_transaction(
    tx: ethers_core::types::Eip1559TransactionRequest,
    sig: ethers_core::types::Signature,
) -> String {
    ethers_core::types::transaction::eip2718::TypedTransaction::Eip1559(tx)
        .rlp_signed(&sig)
        .to_string()
}

pub fn decode_transaction(
    tx: &str,
) -> (
    ethers_core::types::Eip1559TransactionRequest,
    ethers_core::types::Signature,
) {
    use ethers_core::types::transaction::eip2718::TypedTransaction;

    TypedTransaction::decode_signed(&rlp::Rlp::new(
        &ethers_core::types::Bytes::from_str(tx).unwrap(),
    ))
    .map(|(tx, sig)| match tx {
        TypedTransaction::Eip1559(eip1559_tx) => (eip1559_tx, sig),
        _ => panic!("BUG: unexpected sent ETH transaction type {:?}", tx),
    })
    .expect("BUG: failed to deserialize sent ETH transaction")
}

pub fn hash_transaction(
    tx: ethers_core::types::Eip1559TransactionRequest,
    sig: ethers_core::types::Signature,
) -> ethers_core::types::TxHash {
    ethers_core::types::transaction::eip2718::TypedTransaction::Eip1559(tx).hash(&sig)
}
