use super::*;
use crate::DEFAULT_TOKEN_SYMBOL;
use crate::convert::from_account_or_account_identifier;
use crate::models::OperationIdentifier;
use crate::models::amount::signed_amount;
use crate::models::operation::OperationType;
use crate::request_types::Stake;
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

    fn neuron_controller(self, controller: Option<PublicKeyOrPrincipal>) -> Self {
        let mut metadata = self.0.metadata.unwrap_or_default();
        metadata.insert(
            "controller".to_owned(),
            serde_json::to_value(controller).unwrap(),
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
                .neuron_controller(None)
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

#[test]
fn from_account_ai_to_ai_test() {
    // Both None - OK
    assert_eq!(from_account_or_account_identifier(None, None), Ok(None));

    let account = Account {
        owner: PrincipalId::new_user_test_id(1).0,
        subaccount: None,
    };

    let to_nns_account = |account: Account| ic_nns_governance_api::Account {
        owner: Some(PrincipalId(account.owner)),
        subaccount: account.subaccount.map(|s| s.to_vec()),
    };

    let account_id = AccountIdentifier::from(account);

    // Both Some - Error
    let error =
        from_account_or_account_identifier(Some(to_nns_account(account)), Some(account_id.into()))
            .unwrap_err();
    assert_eq!(
        error,
        ApiError::invalid_request("Cannot specify both account and account_identifier")
    );

    // Only AccountIdentifier
    let result = from_account_or_account_identifier(None, Some(account_id.into()))
        .unwrap()
        .expect("should return an account identifier");
    assert_eq!(result, account_id);

    // Incorrect account id
    let incorrect_ai = icp_ledger::protobuf::AccountIdentifier { hash: vec![1u8; 2] };
    let error = from_account_or_account_identifier(None, Some(incorrect_ai)).unwrap_err();
    assert_eq!(
        error,
        ApiError::invalid_request(
            "Could not parse recipient account identifier: Received an invalid AccountIdentifier with length 2 bytes instead of the expected 28 or 32."
        )
    );

    // Only Account, no subaccount
    let result = from_account_or_account_identifier(Some(to_nns_account(account)), None)
        .unwrap()
        .expect("should return an account identifier");
    assert_eq!(result, account_id);

    // Only Account, with subaccount
    let account = Account {
        owner: PrincipalId::new_user_test_id(1).0,
        subaccount: Some([2u8; 32]),
    };
    let result = from_account_or_account_identifier(Some(to_nns_account(account)), None)
        .unwrap()
        .expect("should return an account identifier");
    assert_eq!(result, AccountIdentifier::from(account));

    // Account without owner - Error
    let no_owner = ic_nns_governance_api::Account {
        owner: None,
        subaccount: None,
    };
    let error = from_account_or_account_identifier(Some(no_owner), None).unwrap_err();
    assert_eq!(
        error,
        ApiError::invalid_request("Invalid Account, the owner needs to be specified")
    );

    // Incorrect subaccount length - Error
    let incorrect_sub = ic_nns_governance_api::Account {
        owner: Some(PrincipalId::new_user_test_id(1)),
        subaccount: Some(vec![1u8; 2]),
    };
    let error = from_account_or_account_identifier(Some(incorrect_sub), None).unwrap_err();
    assert_eq!(
        error,
        ApiError::invalid_request("Invalid subaccount length: 2, should be 32")
    );
}
