use crate::response::{
    default_erc20_signed_eip_1559_transaction, default_signed_eip_1559_transaction,
    encode_transaction, fee_history_json_value, hash_transaction,
};
use crate::{
    DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION, DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE,
    DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH, DEFAULT_WITHDRAWAL_TRANSACTION,
    DEFAULT_WITHDRAWAL_TRANSACTION_HASH,
};
use evm_rpc_types::{FeeHistory, Nat256};
use ic_cketh_minter::numeric::{GasAmount, Wei};
use ic_cketh_minter::tx::estimate_transaction_fee;

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
    fn convert_fee_history(fee_history: ethers_core::types::FeeHistory) -> FeeHistory {
        let mut bytes = [0u8; 32];
        fee_history.oldest_block.to_big_endian(&mut bytes);
        let oldest_block: Nat256 = Nat256::from_be_bytes(bytes);

        let base_fee_per_gas = fee_history
            .base_fee_per_gas
            .into_iter()
            .map(|val| {
                let mut bytes = [0u8; 32];
                val.to_big_endian(&mut bytes);
                Nat256::from_be_bytes(bytes)
            })
            .collect();

        let reward = fee_history
            .reward
            .into_iter()
            .map(|inner_vec| {
                inner_vec
                    .into_iter()
                    .map(|val| {
                        let mut bytes = [0u8; 32];
                        val.to_big_endian(&mut bytes);
                        Nat256::from_be_bytes(bytes)
                    })
                    .collect()
            })
            .collect();

        FeeHistory {
            oldest_block,
            base_fee_per_gas,
            gas_used_ratio: fee_history.gas_used_ratio,
            reward,
        }
    }

    let fee_history_core: ethers_core::types::FeeHistory =
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
