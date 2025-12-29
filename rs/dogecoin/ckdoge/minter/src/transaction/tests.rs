use crate::test_fixtures::mock::MockCanisterRuntime;
use crate::transaction::DogecoinTransactionSigner;
use ic_ckbtc_minter::ECDSAPublicKey;
use ic_ckbtc_minter::tx::UnsignedTransaction;

#[tokio::test]
async fn should_be_noop_when_no_transactions() {
    let runtime = MockCanisterRuntime::new();
    let signer = signer();
    let result = signer
        .sign_transaction(
            UnsignedTransaction {
                inputs: vec![],
                outputs: vec![],
                lock_time: 0,
            },
            vec![],
            &runtime,
        )
        .await
        .unwrap();

    let transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(result.as_ref()).unwrap();

    assert_eq!(
        transaction,
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    );
}

fn signer() -> DogecoinTransactionSigner {
    DogecoinTransactionSigner::new(
        "key_1".to_string(),
        ECDSAPublicKey {
            public_key: vec![],
            chain_code: vec![],
        },
    )
}
