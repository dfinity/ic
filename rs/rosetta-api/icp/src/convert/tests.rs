use super::*;
use crate::models::amount::signed_amount;
use crate::models::operation::OperationType;
use crate::models::OperationIdentifier;
use crate::request_types::Stake;
use crate::DEFAULT_TOKEN_SYMBOL;
use icp_ledger::AccountIdentifier;
use icp_ledger::Operation as LedgerOperation;

struct OperationBuilder(Operation);
impl OperationBuilder {
    fn new(idx: u64, _type: OperationType) -> Self {
        Self(Operation {
            operation_identifier: OperationIdentifier::new(idx),
            type_: _type.to_string(),
            status: None,
            account: None,
            amount: None,
            coin_change: None,
            metadata: None,
            related_operations: None,
        })
    }

    fn account(self, account: AccountIdentifier) -> Self {
        Self(Operation {
            account: Some(to_model_account_identifier(&account)),
            ..self.0
        })
    }

    fn amount(self, amount: i128) -> Self {
        Self(Operation {
            amount: Some(signed_amount(amount, DEFAULT_TOKEN_SYMBOL)),
            ..self.0
        })
    }

    fn neuron_index(self, neuron_index: u64) -> Self {
        let mut metadata = self.0.metadata.unwrap_or_default();
        metadata.insert(
            "neuron_index".to_owned(),
            serde_json::to_value(neuron_index).unwrap(),
        );
        Self(Operation {
            metadata: Some(metadata),
            ..self.0
        })
    }

    fn build(self) -> Operation {
        self.0
    }
}

fn test_account(n: u64) -> AccountIdentifier {
    let mut hash = [0u8; 28];
    hash[0..8].copy_from_slice(&n.to_be_bytes());
    AccountIdentifier { hash }
}

#[test]
fn test_transfer_requests_to_operations() {
    assert_eq!(
        Request::requests_to_operations(
            &[Request::Transfer(LedgerOperation::Transfer {
                from: test_account(1),
                to: test_account(2),
                spender: None,
                amount: Tokens::from_e8s(100),
                fee: Tokens::from_e8s(10),
            })],
            DEFAULT_TOKEN_SYMBOL
        ),
        Ok(vec![
            OperationBuilder::new(0, OperationType::Transaction)
                .account(test_account(1))
                .amount(-100)
                .build(),
            OperationBuilder::new(1, OperationType::Transaction)
                .account(test_account(2))
                .amount(100)
                .build(),
            OperationBuilder::new(2, OperationType::Fee)
                .account(test_account(1))
                .amount(-10)
                .build(),
        ])
    );
}

#[test]
fn test_transfer_and_stake_requests_to_operations() {
    assert_eq!(
        Request::requests_to_operations(
            &[
                Request::Transfer(LedgerOperation::Transfer {
                    from: test_account(1),
                    to: test_account(2),
                    spender: None,
                    amount: Tokens::from_e8s(100),
                    fee: Tokens::from_e8s(10),
                }),
                Request::Stake(Stake {
                    account: test_account(2),
                    neuron_index: 1,
                })
            ],
            DEFAULT_TOKEN_SYMBOL
        ),
        Ok(vec![
            OperationBuilder::new(0, OperationType::Transaction)
                .account(test_account(1))
                .amount(-100)
                .build(),
            OperationBuilder::new(1, OperationType::Transaction)
                .account(test_account(2))
                .amount(100)
                .build(),
            OperationBuilder::new(2, OperationType::Fee)
                .account(test_account(1))
                .amount(-10)
                .build(),
            OperationBuilder::new(3, OperationType::Stake)
                .account(test_account(2))
                .neuron_index(1)
                .build(),
        ])
    );
}

#[test]
fn test_can_handle_multiple_transfers() {
    assert_eq!(
        Request::requests_to_operations(
            &[
                Request::Transfer(LedgerOperation::Transfer {
                    from: test_account(1),
                    to: test_account(2),
                    spender: None,
                    amount: Tokens::from_e8s(100),
                    fee: Tokens::from_e8s(10),
                }),
                Request::Transfer(LedgerOperation::Transfer {
                    from: test_account(3),
                    to: test_account(4),
                    spender: None,
                    amount: Tokens::from_e8s(200),
                    fee: Tokens::from_e8s(20),
                }),
            ],
            DEFAULT_TOKEN_SYMBOL
        ),
        Ok(vec![
            OperationBuilder::new(0, OperationType::Transaction)
                .account(test_account(1))
                .amount(-100)
                .build(),
            OperationBuilder::new(1, OperationType::Transaction)
                .account(test_account(2))
                .amount(100)
                .build(),
            OperationBuilder::new(2, OperationType::Fee)
                .account(test_account(1))
                .amount(-10)
                .build(),
            OperationBuilder::new(3, OperationType::Transaction)
                .account(test_account(3))
                .amount(-200)
                .build(),
            OperationBuilder::new(4, OperationType::Transaction)
                .account(test_account(4))
                .amount(200)
                .build(),
            OperationBuilder::new(5, OperationType::Fee)
                .account(test_account(3))
                .amount(-20)
                .build(),
        ])
    );
}

#[test]
fn account_identifier_decode_test() {
    // a good address
    AccountIdentifier::from_hex("42a3eb61d549dc9fe6429ce2361ec60a569b8befe43eb15a3fc5c88516711bc5")
        .unwrap();
    // too long
    AccountIdentifier::from_hex(
        "42a3eb61d549dc9fe6429ce2361ec60a569b8befe43eb15a3fc5c88516711bc50",
    )
    .unwrap_err();
    // invalid character
    AccountIdentifier::from_hex("42a3eb61d549dc9fe6429ce2361ec60a569b8befe43eb15a3fc5c88516711bcz")
        .unwrap_err();
    AccountIdentifier::from_hex("42a3eb61d549dc9fe6429ce2361ec6Oa569b8befe43eb15a3fc5c88516711bc5")
        .unwrap_err();
    // too short
    AccountIdentifier::from_hex("42a3eb61d549dc9fe6429ce2361ec60a569b8befe43eb15a3fc5c88516711bc")
        .unwrap_err();
    AccountIdentifier::from_hex("abcd").unwrap_err();
    // wrong crc
    AccountIdentifier::from_hex("32a3eb61d549dc9fe6429ce2361ec60a569b8befe43eb15a3fc5c88516711bc5")
        .unwrap_err();
    // 0x not allowed
    AccountIdentifier::from_hex(
        "0x42a3eb61d549dc9fe6429ce2361ec60a569b8befe43eb15a3fc5c88516711bc5",
    )
    .unwrap_err();
}
