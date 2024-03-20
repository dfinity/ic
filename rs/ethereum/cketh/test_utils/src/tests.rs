use crate::response::{default_signed_eip_1559_transaction, encode_transaction, hash_transaction};
use crate::{DEFAULT_WITHDRAWAL_TRANSACTION, DEFAULT_WITHDRAWAL_TRANSACTION_HASH};

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
}
