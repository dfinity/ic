use crate::response::{
    default_erc20_signed_eip_1559_transaction, default_signed_eip_1559_transaction,
    encode_transaction, fee_history_json_value, hash_transaction,
};
use crate::{
    DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION, DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_FEE,
    DEFAULT_CKERC20_WITHDRAWAL_TRANSACTION_HASH, DEFAULT_WITHDRAWAL_TRANSACTION,
    DEFAULT_WITHDRAWAL_TRANSACTION_HASH,
};
use ic_cketh_minter::eth_rpc::FeeHistory;
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
    let fee_history: FeeHistory = serde_json::from_value(fee_history_json_value()).unwrap();
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
